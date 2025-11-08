package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ProcNetDev    = "/proc/net/dev"
	SysfsNetPath  = "/sys/class/net"
	MinInterval   = 1
	MaxInterval   = 3600
	DefaultUnits  = "binary"
	HistorySize   = 60
	CleanupAge    = time.Hour
)

var (
	InfoLog  = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	ErrorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
)

type MonitorConfig struct {
	Interval      float64
	CacheTTL      float64
	MaxInterfaces int
	ShowLoopback  bool
	ShowInactive  bool
	Precision     int
	CounterBits   int
	Units         string
	ShowProcesses bool
}

type InterfaceTraffic struct {
	Name       string
	RxBytes    int64
	TxBytes    int64
	RxPackets  int64
	TxPackets  int64
	RxErrs     int64
	TxErrs     int64
	RxDrop     int64
	TxDrop     int64
	Mtu        *int
	State      string
	IPv4Addr   *string
	IPv6Addrs  []string
	Speed      *int
	Duplex     *string
}

func (it *InterfaceTraffic) IsActive() bool {
	return it.RxBytes > 0 || it.TxBytes > 0 || it.RxPackets > 0 || it.TxPackets > 0
}

func (it *InterfaceTraffic) IsUp() bool {
	return it.State == "up"
}

func (it *InterfaceTraffic) TotalBytes() int64 {
	return it.RxBytes + it.TxBytes
}

func (it *InterfaceTraffic) TotalPackets() int64 {
	return it.RxPackets + it.TxPackets
}

type RateSample struct {
	RxRate float64
	TxRate float64
	Time   time.Time
}

type NetworkMonitor struct {
	mu             sync.RWMutex
	config         MonitorConfig
	ipv6Cache      map[string][]string
	ipv6CacheTime  time.Time
	mtuCache       map[string]*int
	stateCache     map[string]string
	speedCache     map[string]*int
	duplexCache    map[string]*string
	interfaceCache []string
	cacheTime      time.Time
	prevTraffic    map[string]InterfaceTraffic
	rateHistory    map[string][]RateSample
	lastCleanup    time.Time
}

var Colors = struct {
	Reset   string
	Grey    string
	Sepia   string
	Red     string
	Green   string
	Yellow  string
	Blue    string
	Cyan    string
	Magenta string
}{
	Reset:   "\033[0m",
	Grey:    "\033[38;5;250m",
	Sepia:   "\033[38;5;130m",
	Red:     "\033[31m",
	Green:   "\033[32m",
	Yellow:  "\033[33m",
	Blue:    "\033[34m",
	Cyan:    "\033[36m",
	Magenta: "\033[35m",
}

func disableColors() {
	Colors.Reset = ""
	Colors.Grey = ""
	Colors.Sepia = ""
	Colors.Red = ""
	Colors.Green = ""
	Colors.Yellow = ""
	Colors.Blue = ""
	Colors.Cyan = ""
	Colors.Magenta = ""
}

func NewNetworkMonitor(config MonitorConfig) *NetworkMonitor {
	return &NetworkMonitor{
		config:      config,
		ipv6Cache:   make(map[string][]string),
		mtuCache:    make(map[string]*int),
		stateCache:  make(map[string]string),
		speedCache:  make(map[string]*int),
		duplexCache: make(map[string]*string),
		prevTraffic: make(map[string]InterfaceTraffic),
		rateHistory: make(map[string][]RateSample),
		lastCleanup: time.Now(),
	}
}

func validateConfig(config *MonitorConfig) error {
	if config.Interval < MinInterval || config.Interval > MaxInterval {
		return fmt.Errorf("interval must be between %d and %d", MinInterval, MaxInterval)
	}
	if config.MaxInterfaces <= 0 || config.MaxInterfaces > 10000 {
		return fmt.Errorf("max interfaces must be between 1 and 10000")
	}
	if config.Units != "binary" && config.Units != "decimal" {
		return fmt.Errorf("units must be 'binary' or 'decimal'")
	}
	if config.CacheTTL <= 0 {
		config.CacheTTL = 5.0
	}
	if config.CounterBits <= 0 {
		config.CounterBits = 64
	}
	return nil
}

func (nm *NetworkMonitor) getDivisor() int64 {
	if nm.config.Units == "decimal" {
		return 1000
	}
	return 1024
}

func (nm *NetworkMonitor) getUnits() []string {
	if nm.config.Units == "decimal" {
		return []string{"B", "KB", "MB", "GB", "TB"}
	}
	return []string{"B", "KiB", "MiB", "GiB", "TiB"}
}

func (nm *NetworkMonitor) formatBytes(size int64) string {
	divisor := nm.getDivisor()
	units := nm.getUnits()
	
	readable := float64(size)
	unitIdx := 0
	
	for readable >= float64(divisor) && unitIdx < len(units)-1 {
		readable /= float64(divisor)
		unitIdx++
	}
	
	if unitIdx == 0 {
		return fmt.Sprintf("%.0f%s", readable, units[unitIdx])
	} else if readable < 10 {
		return fmt.Sprintf("%.2f%s", readable, units[unitIdx])
	}
	return fmt.Sprintf("%.1f%s", readable, units[unitIdx])
}

func (nm *NetworkMonitor) formatRatePrecise(bytesPerSec float64) string {
	if bytesPerSec < 0 {
		return "0B/s"
	}
	
	divisor := float64(nm.getDivisor())
	units := nm.getUnits()
	
	readable := bytesPerSec
	unitIdx := 0
	
	for readable >= divisor && unitIdx < len(units)-1 {
		readable /= divisor
		unitIdx++
	}
	
	if unitIdx == 0 {
		return fmt.Sprintf("%.0f%s/s", readable, units[unitIdx])
	} else if readable < 10 {
		return fmt.Sprintf("%.2f%s/s", readable, units[unitIdx])
	}
	return fmt.Sprintf("%.1f%s/s", readable, units[unitIdx])
}

func (nm *NetworkMonitor) safeInterfaceName(name string) bool {
	matched, _ := regexp.MatchString("^[a-zA-Z0-9-_.:]+$", name)
	return matched
}

func (nm *NetworkMonitor) safeReadSysfsFile(interfaceName, filename string) ([]byte, error) {
	if !nm.safeInterfaceName(interfaceName) || !nm.safeInterfaceName(filename) {
		return nil, fmt.Errorf("invalid interface or filename")
	}
	
	safePath := filepath.Clean(filepath.Join(SysfsNetPath, interfaceName, filename))
	if !strings.HasPrefix(safePath, SysfsNetPath) {
		return nil, fmt.Errorf("path traversal attempt detected")
	}
	
	return os.ReadFile(safePath)
}

func (nm *NetworkMonitor) readInterfaceState(interfaceName string) string {
	data, err := nm.safeReadSysfsFile(interfaceName, "operstate")
	if err != nil {
		return "unknown"
	}
	
	return strings.TrimSpace(string(data))
}

func (nm *NetworkMonitor) getInterfaceState(interfaceName string) string {
	nm.mu.RLock()
	if state, exists := nm.stateCache[interfaceName]; exists {
		nm.mu.RUnlock()
		return state
	}
	nm.mu.RUnlock()
	
	state := nm.readInterfaceState(interfaceName)
	
	nm.mu.Lock()
	nm.stateCache[interfaceName] = state
	nm.mu.Unlock()
	
	return state
}

func (nm *NetworkMonitor) getInterfaceSpeed(interfaceName string) *int {
	nm.mu.RLock()
	if speed, exists := nm.speedCache[interfaceName]; exists {
		nm.mu.RUnlock()
		return speed
	}
	nm.mu.RUnlock()
	
	data, err := nm.safeReadSysfsFile(interfaceName, "speed")
	if err != nil {
		nm.mu.Lock()
		nm.speedCache[interfaceName] = nil
		nm.mu.Unlock()
		return nil
	}
	
	speedStr := strings.TrimSpace(string(data))
	speed, err := strconv.Atoi(speedStr)
	if err != nil {
		nm.mu.Lock()
		nm.speedCache[interfaceName] = nil
		nm.mu.Unlock()
		return nil
	}
	
	nm.mu.Lock()
	nm.speedCache[interfaceName] = &speed
	nm.mu.Unlock()
	
	return &speed
}

func (nm *NetworkMonitor) getInterfaceDuplex(interfaceName string) *string {
	nm.mu.RLock()
	if duplex, exists := nm.duplexCache[interfaceName]; exists {
		nm.mu.RUnlock()
		return duplex
	}
	nm.mu.RUnlock()
	
	data, err := nm.safeReadSysfsFile(interfaceName, "duplex")
	if err != nil {
		nm.mu.Lock()
		nm.duplexCache[interfaceName] = nil
		nm.mu.Unlock()
		return nil
	}
	
	duplex := strings.TrimSpace(string(data))
	
	nm.mu.Lock()
	nm.duplexCache[interfaceName] = &duplex
	nm.mu.Unlock()
	
	return &duplex
}

func (nm *NetworkMonitor) getAvailableInterfaces() []string {
	nm.mu.RLock()
	now := time.Now()
	if nm.interfaceCache != nil && now.Sub(nm.cacheTime).Seconds() < nm.config.CacheTTL {
		cache := nm.interfaceCache
		nm.mu.RUnlock()
		return cache
	}
	nm.mu.RUnlock()
	
	files, err := os.ReadDir(SysfsNetPath)
	if err != nil {
		return []string{}
	}
	
	var interfaces []string
	for _, file := range files {
		iface := file.Name()
		
		if !nm.safeInterfaceName(iface) {
			continue
		}
		
		if !nm.config.ShowLoopback && iface == "lo" {
			continue
		}
		
		operstate := nm.getInterfaceState(iface)
		if operstate == "down" && !nm.config.ShowInactive {
			continue
		}
		
		interfaces = append(interfaces, iface)
	}
	
	sort.Strings(interfaces)
	
	nm.mu.Lock()
	nm.interfaceCache = interfaces
	nm.cacheTime = now
	nm.mu.Unlock()
	
	return interfaces
}

func (nm *NetworkMonitor) validateInterfaces(requestedIfaces []string) []string {
	available := nm.getAvailableInterfaces()
	if len(requestedIfaces) == 0 {
		return available
	}
	
	var validIfaces []string
	var invalidIfaces []string
	
	for _, iface := range requestedIfaces {
		found := false
		for _, avail := range available {
			if iface == avail {
				found = true
				validIfaces = append(validIfaces, iface)
				break
			}
		}
		if !found {
			invalidIfaces = append(invalidIfaces, iface)
		}
	}
	
	if len(invalidIfaces) > 0 {
		ErrorLog.Printf("Invalid interfaces: %v", invalidIfaces)
	}
	
	return validIfaces
}

func (nm *NetworkMonitor) getMTUCached(interfaceName string) *int {
	nm.mu.RLock()
	if mtu, exists := nm.mtuCache[interfaceName]; exists {
		nm.mu.RUnlock()
		return mtu
	}
	nm.mu.RUnlock()
	
	data, err := nm.safeReadSysfsFile(interfaceName, "mtu")
	if err != nil {
		nm.mu.Lock()
		nm.mtuCache[interfaceName] = nil
		nm.mu.Unlock()
		return nil
	}
	
	mtuStr := strings.TrimSpace(string(data))
	mtu, err := strconv.Atoi(mtuStr)
	if err != nil {
		nm.mu.Lock()
		nm.mtuCache[interfaceName] = nil
		nm.mu.Unlock()
		return nil
	}
	
	nm.mu.Lock()
	nm.mtuCache[interfaceName] = &mtu
	nm.mu.Unlock()
	
	return &mtu
}

func (nm *NetworkMonitor) getIPv4Info(interfaceName string) *string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	
	for _, iface := range ifaces {
		if iface.Name != interfaceName {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.To4() != nil {
					ones, _ := ipNet.Mask.Size()
					info := fmt.Sprintf("%s/%d", ipNet.IP.String(), ones)
					return &info
				}
			}
		}
	}
	
	return nil
}

func (nm *NetworkMonitor) getAllIPv6InfoCached() map[string][]string {
	nm.mu.RLock()
	now := time.Now()
	if nm.ipv6Cache != nil && now.Sub(nm.ipv6CacheTime).Seconds() < nm.config.CacheTTL {
		cache := nm.ipv6Cache
		nm.mu.RUnlock()
		return cache
	}
	nm.mu.RUnlock()
	
	ipv6Map := make(map[string][]string)
	
	ifaces, err := net.Interfaces()
	if err != nil {
		return ipv6Map
	}
	
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.To16() != nil && ipNet.IP.To4() == nil {
					ones, _ := ipNet.Mask.Size()
					scope := "global"
					if ipNet.IP.IsLinkLocalUnicast() {
						scope = "link"
					}
					info := fmt.Sprintf("%s/%d (%s)", ipNet.IP.String(), ones, scope)
					ipv6Map[iface.Name] = append(ipv6Map[iface.Name], info)
				}
			}
		}
	}
	
	nm.mu.Lock()
	nm.ipv6Cache = ipv6Map
	nm.ipv6CacheTime = now
	nm.mu.Unlock()
	
	return ipv6Map
}

func (nm *NetworkMonitor) getInterfaceAddrs(interfaceName string) map[string][]string {
	addrs := map[string][]string{
		"ipv4": {},
		"ipv6": {},
	}
	
	ipv4 := nm.getIPv4Info(interfaceName)
	if ipv4 != nil {
		addrs["ipv4"] = append(addrs["ipv4"], *ipv4)
	}
	
	ipv6Map := nm.getAllIPv6InfoCached()
	if ipv6Addrs, exists := ipv6Map[interfaceName]; exists {
		addrs["ipv6"] = append(addrs["ipv6"], ipv6Addrs...)
	}
	
	return addrs
}

func (nm *NetworkMonitor) formatAddrsString(addrs map[string][]string) string {
	var parts []string
	
	if len(addrs["ipv4"]) > 0 {
		parts = append(parts, fmt.Sprintf("IPv4: %s", strings.Join(addrs["ipv4"], ", ")))
	}
	
	if len(addrs["ipv6"]) > 0 {
		ipv6Display := addrs["ipv6"]
		if len(ipv6Display) > 2 {
			ipv6Display = append(ipv6Display[:2], fmt.Sprintf("... (+%d more)", len(addrs["ipv6"])-2))
		}
		parts = append(parts, fmt.Sprintf("IPv6: %s", strings.Join(ipv6Display, ", ")))
	}
	
	if len(parts) > 0 {
		return strings.Join(parts, "; ")
	}
	return "No addresses"
}

func (nm *NetworkMonitor) calculateRate(current, previous int64, interval float64) float64 {
	if interval <= 0 {
		return 0.0
	}
	
	var diff int64
	if current >= previous {
		diff = current - previous
	} else {
		maxValue := int64(1<<uint(nm.config.CounterBits) - 1)
		if maxValue < 0 {
			maxValue = math.MaxInt64
		}
		diff = (maxValue - previous) + current + 1
	}
	
	return float64(diff) / interval
}

func (nm *NetworkMonitor) updateRateHistory(interfaceName string, rxRate, txRate float64) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	if _, exists := nm.rateHistory[interfaceName]; !exists {
		nm.rateHistory[interfaceName] = make([]RateSample, 0, HistorySize)
	}
	
	nm.rateHistory[interfaceName] = append(nm.rateHistory[interfaceName], RateSample{
		RxRate: rxRate,
		TxRate: txRate,
		Time:   time.Now(),
	})
	
	if len(nm.rateHistory[interfaceName]) > HistorySize {
		nm.rateHistory[interfaceName] = nm.rateHistory[interfaceName][1:]
	}
}

func (nm *NetworkMonitor) getAvgRates(interfaceName string) (float64, float64) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	samples, exists := nm.rateHistory[interfaceName]
	if !exists || len(samples) == 0 {
		return 0.0, 0.0
	}
	
	var totalRx, totalTx float64
	for _, sample := range samples {
		totalRx += sample.RxRate
		totalTx += sample.TxRate
	}
	
	return totalRx / float64(len(samples)), totalTx / float64(len(samples))
}

func (nm *NetworkMonitor) cleanupStaleData() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-CleanupAge)
	
	for iface, samples := range nm.rateHistory {
		if len(samples) > 0 && samples[len(samples)-1].Time.Before(cutoff) {
			delete(nm.rateHistory, iface)
			delete(nm.prevTraffic, iface)
			delete(nm.stateCache, iface)
			delete(nm.speedCache, iface)
			delete(nm.duplexCache, iface)
			delete(nm.mtuCache, iface)
		}
	}
	
	if len(nm.stateCache) > 1000 {
		nm.stateCache = make(map[string]string)
	}
	if len(nm.speedCache) > 1000 {
		nm.speedCache = make(map[string]*int)
	}
	if len(nm.duplexCache) > 1000 {
		nm.duplexCache = make(map[string]*string)
	}
	if len(nm.mtuCache) > 1000 {
		nm.mtuCache = make(map[string]*int)
	}
	
	nm.lastCleanup = now
}

func (nm *NetworkMonitor) readProcNetDev() ([]byte, error) {
	file, err := os.Open(ProcNetDev)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	return io.ReadAll(io.LimitReader(file, 65536))
}

func (nm *NetworkMonitor) parseNetDevLine(line string, validIfaces []string) (string, InterfaceTraffic, error) {
	parts := strings.Fields(line)
	if len(parts) < 17 {
		return "", InterfaceTraffic{}, fmt.Errorf("insufficient fields")
	}
	
	iface := strings.TrimSuffix(parts[0], ":")
	if !nm.safeInterfaceName(iface) {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid interface name")
	}
	
	if len(validIfaces) > 0 {
		found := false
		for _, validIface := range validIfaces {
			if iface == validIface {
				found = true
				break
			}
		}
		if !found {
			return "", InterfaceTraffic{}, fmt.Errorf("interface not in filter")
		}
	}
	
	var traffic InterfaceTraffic
	traffic.Name = iface
	
	var parseErr error
	traffic.RxBytes, parseErr = strconv.ParseInt(parts[1], 10, 64)
	if parseErr != nil {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid rx_bytes: %v", parseErr)
	}
	
	traffic.RxPackets, parseErr = strconv.ParseInt(parts[2], 10, 64)
	if parseErr != nil {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid rx_packets: %v", parseErr)
	}
	
	traffic.RxErrs, parseErr = strconv.ParseInt(parts[3], 10, 64)
	if parseErr != nil {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid rx_errs: %v", parseErr)
	}
	
	traffic.RxDrop, parseErr = strconv.ParseInt(parts[4], 10, 64)
	if parseErr != nil {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid rx_drop: %v", parseErr)
	}
	
	traffic.TxBytes, parseErr = strconv.ParseInt(parts[9], 10, 64)
	if parseErr != nil {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid tx_bytes: %v", parseErr)
	}
	
	traffic.TxPackets, parseErr = strconv.ParseInt(parts[10], 10, 64)
	if parseErr != nil {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid tx_packets: %v", parseErr)
	}
	
	traffic.TxErrs, parseErr = strconv.ParseInt(parts[11], 10, 64)
	if parseErr != nil {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid tx_errs: %v", parseErr)
	}
	
	traffic.TxDrop, parseErr = strconv.ParseInt(parts[12], 10, 64)
	if parseErr != nil {
		return "", InterfaceTraffic{}, fmt.Errorf("invalid tx_drop: %v", parseErr)
	}
	
	return iface, traffic, nil
}

func parseProcNetDev(monitor *NetworkMonitor, filterIfaces []string) map[string]InterfaceTraffic {
	stats := make(map[string]InterfaceTraffic)
	
	data, err := monitor.readProcNetDev()
	if err != nil {
		ErrorLog.Printf("Error reading %s: %v", ProcNetDev, err)
		return stats
	}
	
	lines := strings.Split(string(data), "\n")
	validIfaces := monitor.validateInterfaces(filterIfaces)
	
	for i, line := range lines {
		if i < 2 || strings.TrimSpace(line) == "" {
			continue
		}
		
		iface, traffic, err := monitor.parseNetDevLine(line, validIfaces)
		if err != nil {
			continue
		}
		
		if !monitor.config.ShowInactive && traffic.RxBytes == 0 && traffic.TxBytes == 0 {
			continue
		}
		
		state := monitor.getInterfaceState(iface)
		addrs := monitor.getInterfaceAddrs(iface)
		mtu := monitor.getMTUCached(iface)
		speed := monitor.getInterfaceSpeed(iface)
		duplex := monitor.getInterfaceDuplex(iface)
		
		var ipv4Addr *string
		if len(addrs["ipv4"]) > 0 {
			ipv4Addr = &addrs["ipv4"][0]
		}
		
		traffic.State = state
		traffic.Mtu = mtu
		traffic.IPv4Addr = ipv4Addr
		traffic.IPv6Addrs = addrs["ipv6"]
		traffic.Speed = speed
		traffic.Duplex = duplex
		
		stats[iface] = traffic
		
		if len(stats) >= monitor.config.MaxInterfaces {
			break
		}
	}
	
	return stats
}

func displayNetworkInfo(monitor *NetworkMonitor, filterIfaces []string) {
	fmt.Printf("%sNetwork Interface Information:%s\n", Colors.Blue, Colors.Reset)
	validIfaces := monitor.validateInterfaces(filterIfaces)
	
	if len(validIfaces) == 0 {
		fmt.Printf("%sNo interfaces found.%s\n", Colors.Grey, Colors.Reset)
		return
	}
	
	for _, iface := range validIfaces {
		state := monitor.getInterfaceState(iface)
		stateColor := Colors.Green
		if state != "up" {
			stateColor = Colors.Red
		}
		mtu := monitor.getMTUCached(iface)
		addrs := monitor.getInterfaceAddrs(iface)
		speed := monitor.getInterfaceSpeed(iface)
		duplex := monitor.getInterfaceDuplex(iface)
		
		fmt.Printf("\n%s%s%s [%s%s%s]\n", Colors.Sepia, iface, Colors.Reset, stateColor, state, Colors.Reset)
		
		if speed != nil {
			duplexStr := ""
			if duplex != nil {
				duplexStr = fmt.Sprintf(", %s", *duplex)
			}
			fmt.Printf("  Speed: %d Mbps%s\n", *speed, duplexStr)
		}
		
		if mtu != nil {
			fmt.Printf("  MTU: %d\n", *mtu)
		}
		
		fmt.Printf("  Addresses: %s\n", monitor.formatAddrsString(addrs))
	}
}

func displayTrafficStats(monitor *NetworkMonitor, filterIfaces []string) {
	stats := parseProcNetDev(monitor, filterIfaces)
	if len(stats) == 0 {
		fmt.Printf("%sNo traffic statistics available.%s\n", Colors.Grey, Colors.Reset)
		return
	}
	
	fmt.Printf("%s\nTraffic Statistics:%s\n", Colors.Blue, Colors.Reset)
	
	statsSlice := make([]InterfaceTraffic, 0, len(stats))
	for _, traffic := range stats {
		statsSlice = append(statsSlice, traffic)
	}
	
	sort.Slice(statsSlice, func(i, j int) bool {
		return statsSlice[i].TotalBytes() > statsSlice[j].TotalBytes()
	})
	
	for _, traffic := range statsSlice {
		stateColor := Colors.Green
		if !traffic.IsUp() {
			stateColor = Colors.Red
		}
		
		speedInfo := ""
		if traffic.Speed != nil {
			speedInfo = fmt.Sprintf(" (%d Mbps)", *traffic.Speed)
		}
		
		fmt.Printf("\n%s%-12s%s [%s%s%s]%s\n", 
			Colors.Sepia, traffic.Name, Colors.Reset, 
			stateColor, traffic.State, Colors.Reset, speedInfo)
		
		fmt.Printf("  RX: %s%-12s%s %s(%d pkts, %d errs, %d drop)%s\n",
			Colors.Green, monitor.formatBytes(traffic.RxBytes), Colors.Reset,
			Colors.Grey, traffic.RxPackets, traffic.RxErrs, traffic.RxDrop, Colors.Reset)
		
		fmt.Printf("  TX: %s%-12s%s %s(%d pkts, %d errs, %d drop)%s\n",
			Colors.Yellow, monitor.formatBytes(traffic.TxBytes), Colors.Reset,
			Colors.Grey, traffic.TxPackets, traffic.TxErrs, traffic.TxDrop, Colors.Reset)
		
		if traffic.IsActive() {
			total := monitor.formatBytes(traffic.TotalBytes())
			fmt.Printf("  Total: %s%s%s (%d total packets)\n",
				Colors.Cyan, total, Colors.Reset, traffic.TotalPackets())
		}
	}
}

func clearScreen() {
	fmt.Print("\033[H\033[J")
}

func setupSignalHandler() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	
	go func() {
		<-sigCh
		cancel()
		<-sigCh
		os.Exit(1)
	}()
	
	return ctx, cancel
}

func (nm *NetworkMonitor) buildInterfaceLine(iface string, traffic InterfaceTraffic, prevTraffic InterfaceTraffic) string {
	var sb strings.Builder
	
	stateColor := Colors.Green
	if !traffic.IsUp() {
		stateColor = Colors.Red
	}
	
	speedInfo := ""
	if traffic.Speed != nil {
		speedInfo = fmt.Sprintf(" (%d Mbps)", *traffic.Speed)
	}
	
	sb.WriteString(fmt.Sprintf("%s%-12s%s [%s%s%s]%s", 
		Colors.Sepia, iface, Colors.Reset, 
		stateColor, traffic.State, Colors.Reset, speedInfo))
	
	if prevTraffic.Name != "" {
		rxRate := nm.calculateRate(traffic.RxBytes, prevTraffic.RxBytes, nm.config.Interval)
		txRate := nm.calculateRate(traffic.TxBytes, prevTraffic.TxBytes, nm.config.Interval)
		avgRx, avgTx := nm.getAvgRates(iface)
		
		sb.WriteString(fmt.Sprintf(" RX %s%-12s%s", Colors.Green, nm.formatRatePrecise(rxRate), Colors.Reset))
		sb.WriteString(fmt.Sprintf(" TX %s%-12s%s", Colors.Yellow, nm.formatRatePrecise(txRate), Colors.Reset))
		sb.WriteString(fmt.Sprintf(" Avg: %sRX%s TX%s%s", Colors.Cyan, 
			nm.formatRatePrecise(avgRx), 
			nm.formatRatePrecise(avgTx), Colors.Reset))
	} else {
		sb.WriteString(fmt.Sprintf(" RX %s%-12s%s", Colors.Green, nm.formatBytes(traffic.RxBytes), Colors.Reset))
		sb.WriteString(fmt.Sprintf(" TX %s%-12s%s", Colors.Yellow, nm.formatBytes(traffic.TxBytes), Colors.Reset))
		sb.WriteString(fmt.Sprintf(" %s(initial)%s", Colors.Grey, Colors.Reset))
	}
	
	return sb.String()
}

func (nm *NetworkMonitor) updateDisplay(filterIfaces []string, updateCount int, startTime time.Time) {
	clearScreen()
	currentTime := time.Now()
	elapsedTotal := currentTime.Sub(startTime).Seconds()
	
	fmt.Printf("%sLive Network Traffic Monitor%s\n", Colors.Blue, Colors.Reset)
	fmt.Printf("%sInterval: %.1fs | Uptime: %.0fs | Updates: %d%s\n\n", 
		Colors.Grey, nm.config.Interval, elapsedTotal, updateCount, Colors.Reset)
	
	currStats := parseProcNetDev(nm, filterIfaces)
	
	for iface, now := range currStats {
		if prev, exists := nm.prevTraffic[iface]; exists {
			rxRate := nm.calculateRate(now.RxBytes, prev.RxBytes, nm.config.Interval)
			txRate := nm.calculateRate(now.TxBytes, prev.TxBytes, nm.config.Interval)
			nm.updateRateHistory(iface, rxRate, txRate)
		}
	}
	
	statsSlice := make([]struct {
		Name    string
		Traffic InterfaceTraffic
	}, 0, len(currStats))
	
	for iface, traffic := range currStats {
		statsSlice = append(statsSlice, struct {
			Name    string
			Traffic InterfaceTraffic
		}{iface, traffic})
	}
	
	sort.Slice(statsSlice, func(i, j int) bool {
		avgRxI, _ := nm.getAvgRates(statsSlice[i].Name)
		avgRxJ, _ := nm.getAvgRates(statsSlice[j].Name)
		return avgRxI > avgRxJ
	})
	
	for _, item := range statsSlice {
		line := nm.buildInterfaceLine(item.Name, item.Traffic, nm.prevTraffic[item.Name])
		fmt.Println(line)
	}
	
	if len(currStats) == 0 {
		fmt.Printf("%sNo active interfaces to monitor.%s\n", Colors.Grey, Colors.Reset)
	}
	
	activeCount := 0
	var totalRx, totalTx int64
	for _, traffic := range currStats {
		if traffic.IsActive() {
			activeCount++
		}
		totalRx += traffic.RxBytes
		totalTx += traffic.TxBytes
	}
	
	fmt.Printf("\n%s[Ctrl+C to stop] | Interfaces: %d (active: %d) | Total: RX%s TX%s | %s%s\n",
		Colors.Grey, len(currStats), activeCount, 
		nm.formatBytes(totalRx), nm.formatBytes(totalTx),
		time.Now().Format("15:04:05"), Colors.Reset)
	
	nm.prevTraffic = currStats
}

func watchModeImproved(monitor *NetworkMonitor, filterIfaces []string, interval float64) {
	ctx, cancel := setupSignalHandler()
	defer cancel()
	
	monitor.config.Interval = interval
	
	ticker := time.NewTicker(time.Duration(interval * float64(time.Second)))
	defer ticker.Stop()
	
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()
	
	startTime := time.Now()
	updateCount := 0
	
	InfoLog.Printf("Watching TCP connections (refresh every %.1fs)", interval)
	InfoLog.Printf("Started at: %s", startTime.Format("2006-01-02 15:04:05"))
	
	for {
		select {
		case <-ctx.Done():
			monitor.cleanupStaleData()
			InfoLog.Printf("Monitoring stopped after %d updates", updateCount)
			return
		case <-cleanupTicker.C:
			monitor.cleanupStaleData()
		case <-ticker.C:
			monitor.updateDisplay(filterIfaces, updateCount, startTime)
			updateCount++
		}
	}
}

func outputJSON(monitor *NetworkMonitor, filterIfaces []string) {
	stats := parseProcNetDev(monitor, filterIfaces)
	
	payload := make(map[string]interface{})
	for iface, traffic := range stats {
		payload[iface] = map[string]interface{}{
			"rx_bytes":      traffic.RxBytes,
			"tx_bytes":      traffic.TxBytes,
			"rx_packets":    traffic.RxPackets,
			"tx_packets":    traffic.TxPackets,
			"rx_errs":       traffic.RxErrs,
			"tx_errs":       traffic.TxErrs,
			"rx_drop":       traffic.RxDrop,
			"tx_drop":       traffic.TxDrop,
			"mtu":           traffic.Mtu,
			"state":         traffic.State,
			"ipv4_addr":     traffic.IPv4Addr,
			"ipv6_addrs":    traffic.IPv6Addrs,
			"speed":         traffic.Speed,
			"duplex":        traffic.Duplex,
			"is_active":     traffic.IsActive(),
			"is_up":         traffic.IsUp(),
			"total_bytes":   traffic.TotalBytes(),
			"total_packets": traffic.TotalPackets(),
		}
	}
	
	jsonData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		ErrorLog.Printf("Error generating JSON: %v", err)
		return
	}
	
	fmt.Println(string(jsonData))
}

func main() {
	var (
		interfaces    = flag.String("i", "", "Comma-separated list of interfaces to monitor")
		watch         = flag.Float64("w", 0, "Watch mode with refresh interval (0 for default 1s)")
		jsonOutput    = flag.Bool("json", false, "Produce JSON output")
		noColor       = flag.Bool("no-color", false, "Disable ANSI colors")
		showInactive  = flag.Bool("show-inactive", false, "Show inactive interfaces")
		hideLoopback  = flag.Bool("hide-loopback", false, "Hide loopback interface")
		interval      = flag.Float64("interval", 1.0, "Polling interval in seconds")
		cacheTTL      = flag.Float64("cache-ttl", 5.0, "Cache TTL in seconds")
		maxInterfaces = flag.Int("max-interfaces", 100, "Maximum interfaces to display")
		units         = flag.String("units", "binary", "Display units (binary|decimal)")
	)
	
	flag.Parse()
	
	if _, err := os.Stat("/proc/net/dev"); os.IsNotExist(err) {
		ErrorLog.Println("This tool only works on Linux systems")
		os.Exit(1)
	}
	
	if *noColor {
		disableColors()
	}
	
	config := MonitorConfig{
		Interval:      *interval,
		CacheTTL:      *cacheTTL,
		MaxInterfaces: *maxInterfaces,
		ShowLoopback:  !*hideLoopback,
		ShowInactive:  *showInactive,
		Precision:     1,
		CounterBits:   64,
		Units:         *units,
		ShowProcesses: false,
	}
	
	if err := validateConfig(&config); err != nil {
		ErrorLog.Printf("Configuration error: %v", err)
		os.Exit(1)
	}
	
	monitor := NewNetworkMonitor(config)
	
	var filterIfaces []string
	if *interfaces != "" {
		filterIfaces = strings.Split(*interfaces, ",")
	}
	
	if *jsonOutput {
		outputJSON(monitor, filterIfaces)
	} else if *watch != 0 {
		watchInterval := *watch
		if watchInterval == 0 {
			watchInterval = 1.0
		}
		watchModeImproved(monitor, filterIfaces, watchInterval)
	} else {
		displayNetworkInfo(monitor, filterIfaces)
		displayTrafficStats(monitor, filterIfaces)
	}
}
