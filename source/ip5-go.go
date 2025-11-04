package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Constants
const (
	ProcNetDev    = "/proc/net/dev"
	SysfsNetPath  = "/sys/class/net"
	MinInterval   = 1
	MaxInterval   = 3600
	DefaultUnits  = "binary"
	HistorySize   = 60
)

// Configuration
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

// Interface Traffic Data
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

// Network Monitor
type NetworkMonitor struct {
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
}

type RateSample struct {
	RxRate float64
	TxRate float64
	Time   time.Time
}

// Colors for terminal output
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
	}
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

func (nm *NetworkMonitor) getInterfaceState(interfaceName string) string {
	if state, exists := nm.stateCache[interfaceName]; exists {
		return state
	}
	
	statePath := filepath.Join(SysfsNetPath, interfaceName, "operstate")
	data, err := ioutil.ReadFile(statePath)
	if err != nil {
		nm.stateCache[interfaceName] = "unknown"
		return "unknown"
	}
	
	state := strings.TrimSpace(string(data))
	nm.stateCache[interfaceName] = state
	return state
}

func (nm *NetworkMonitor) getInterfaceSpeed(interfaceName string) *int {
	if speed, exists := nm.speedCache[interfaceName]; exists {
		return speed
	}
	
	speedPath := filepath.Join(SysfsNetPath, interfaceName, "speed")
	data, err := ioutil.ReadFile(speedPath)
	if err != nil {
		nm.speedCache[interfaceName] = nil
		return nil
	}
	
	speedStr := strings.TrimSpace(string(data))
	speed, err := strconv.Atoi(speedStr)
	if err != nil {
		nm.speedCache[interfaceName] = nil
		return nil
	}
	
	nm.speedCache[interfaceName] = &speed
	return &speed
}

func (nm *NetworkMonitor) getInterfaceDuplex(interfaceName string) *string {
	if duplex, exists := nm.duplexCache[interfaceName]; exists {
		return duplex
	}
	
	duplexPath := filepath.Join(SysfsNetPath, interfaceName, "duplex")
	data, err := ioutil.ReadFile(duplexPath)
	if err != nil {
		nm.duplexCache[interfaceName] = nil
		return nil
	}
	
	duplex := strings.TrimSpace(string(data))
	nm.duplexCache[interfaceName] = &duplex
	return &duplex
}

func (nm *NetworkMonitor) getAvailableInterfaces() []string {
	now := time.Now()
	if nm.interfaceCache != nil && now.Sub(nm.cacheTime).Seconds() < nm.config.CacheTTL {
		return nm.interfaceCache
	}
	
	files, err := ioutil.ReadDir(SysfsNetPath)
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
		
		// Check if interface is actually available
		operstate := nm.getInterfaceState(iface)
		if operstate == "down" && !nm.config.ShowInactive {
			continue
		}
		
		interfaces = append(interfaces, iface)
	}
	
	sort.Strings(interfaces)
	nm.interfaceCache = interfaces
	nm.cacheTime = now
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
		fmt.Fprintf(os.Stderr, "%sWarning: Invalid interfaces: %v%s\n", Colors.Red, invalidIfaces, Colors.Reset)
	}
	
	return validIfaces
}

func (nm *NetworkMonitor) getMTUCached(interfaceName string) *int {
	if mtu, exists := nm.mtuCache[interfaceName]; exists {
		return mtu
	}
	
	mtuPath := filepath.Join(SysfsNetPath, interfaceName, "mtu")
	data, err := ioutil.ReadFile(mtuPath)
	if err != nil {
		nm.mtuCache[interfaceName] = nil
		return nil
	}
	
	mtuStr := strings.TrimSpace(string(data))
	mtu, err := strconv.Atoi(mtuStr)
	if err != nil {
		nm.mtuCache[interfaceName] = nil
		return nil
	}
	
	nm.mtuCache[interfaceName] = &mtu
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
	now := time.Now()
	if nm.ipv6Cache != nil && now.Sub(nm.ipv6CacheTime).Seconds() < nm.config.CacheTTL {
		return nm.ipv6Cache
	}
	
	ipv6Map := make(map[string][]string)
	
	// Use net.Interfaces for IPv6 addresses
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
	
	nm.ipv6Cache = ipv6Map
	nm.ipv6CacheTime = now
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
		// Show first 2 IPv6 addresses to avoid cluttering
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
	if current >= previous {
		return float64(current-previous) / interval
	}
	
	// Fixed: Use proper bit shifting with integer
	maxCount := float64(int64(1)<<uint(nm.config.CounterBits) - 1)
	return (maxCount - float64(previous) + float64(current) + 1) / interval
}

func (nm *NetworkMonitor) updateRateHistory(interfaceName string, rxRate, txRate float64) {
	if _, exists := nm.rateHistory[interfaceName]; !exists {
		nm.rateHistory[interfaceName] = make([]RateSample, 0, HistorySize)
	}
	
	nm.rateHistory[interfaceName] = append(nm.rateHistory[interfaceName], RateSample{
		RxRate: rxRate,
		TxRate: txRate,
		Time:   time.Now(),
	})
	
	// Keep only last 60 data points
	if len(nm.rateHistory[interfaceName]) > HistorySize {
		nm.rateHistory[interfaceName] = nm.rateHistory[interfaceName][1:]
	}
}

func (nm *NetworkMonitor) getAvgRates(interfaceName string) (float64, float64) {
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

func parseProcNetDev(monitor *NetworkMonitor, filterIfaces []string) map[string]InterfaceTraffic {
	stats := make(map[string]InterfaceTraffic)
	
	data, err := ioutil.ReadFile(ProcNetDev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError: %s does not exist%s\n", Colors.Red, ProcNetDev, Colors.Reset)
		return stats
	}
	
	lines := strings.Split(string(data), "\n")
	validIfaces := monitor.validateInterfaces(filterIfaces)
	
	for i, line := range lines {
		if i < 2 || strings.TrimSpace(line) == "" {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) < 17 {
			continue
		}
		
		iface := strings.TrimSuffix(parts[0], ":")
		
		if len(validIfaces) > 0 {
			found := false
			for _, validIface := range validIfaces {
				if iface == validIface {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		// Parse statistics
		rxBytes, _ := strconv.ParseInt(parts[1], 10, 64)
		rxPackets, _ := strconv.ParseInt(parts[2], 10, 64)
		rxErrs, _ := strconv.ParseInt(parts[3], 10, 64)
		rxDrop, _ := strconv.ParseInt(parts[4], 10, 64)
		txBytes, _ := strconv.ParseInt(parts[9], 10, 64)
		txPackets, _ := strconv.ParseInt(parts[10], 10, 64)
		txErrs, _ := strconv.ParseInt(parts[11], 10, 64)
		txDrop, _ := strconv.ParseInt(parts[12], 10, 64)
		
		if !monitor.config.ShowInactive && rxBytes == 0 && txBytes == 0 {
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
		
		traffic := InterfaceTraffic{
			Name:      iface,
			RxBytes:   rxBytes,
			TxBytes:   txBytes,
			RxPackets: rxPackets,
			TxPackets: txPackets,
			RxErrs:    rxErrs,
			TxErrs:    txErrs,
			RxDrop:    rxDrop,
			TxDrop:    txDrop,
			Mtu:       mtu,
			State:     state,
			IPv4Addr:  ipv4Addr,
			IPv6Addrs: addrs["ipv6"],
			Speed:     speed,
			Duplex:    duplex,
		}
		
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
	
	// Convert to slice for sorting
	statsSlice := make([]InterfaceTraffic, 0, len(stats))
	for _, traffic := range stats {
		statsSlice = append(statsSlice, traffic)
	}
	
	// Sort by total traffic
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

func watchModeImproved(monitor *NetworkMonitor, filterIfaces []string, interval float64) {
	prevStats := make(map[string]InterfaceTraffic)
	startTime := time.Now()
	updateCount := 0
	
	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	
	fmt.Printf("Watching TCP connections (refresh every %.1fs). Press Ctrl+C to stop.\n", interval)
	fmt.Printf("Started at: %s\n\n", startTime.Format("2006-01-02 15:04:05"))
	
	for {
		select {
		case <-sigCh:
			fmt.Printf("\n%sMonitoring stopped after %d updates.%s\n", Colors.Red, updateCount, Colors.Reset)
			return
		default:
			clearScreen()
			currentTime := time.Now()
			elapsedTotal := currentTime.Sub(startTime).Seconds()
			
			fmt.Printf("%sLive Network Traffic Monitor%s\n", Colors.Blue, Colors.Reset)
			fmt.Printf("%sInterval: %.1fs | Uptime: %.0fs | Updates: %d%s\n\n", 
				Colors.Grey, interval, elapsedTotal, updateCount, Colors.Reset)
			
			currStats := parseProcNetDev(monitor, filterIfaces)
			
			// Calculate rates and update history
			for iface, now := range currStats {
				if prev, exists := prevStats[iface]; exists {
					rxRate := monitor.calculateRate(now.RxBytes, prev.RxBytes, interval)
					txRate := monitor.calculateRate(now.TxBytes, prev.TxBytes, interval)
					monitor.updateRateHistory(iface, rxRate, txRate)
				}
			}
			
			// Convert to slice for sorting by RX rate
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
			
			// Sort by average RX rate
			sort.Slice(statsSlice, func(i, j int) bool {
				avgRxI, _ := monitor.getAvgRates(statsSlice[i].Name)
				avgRxJ, _ := monitor.getAvgRates(statsSlice[j].Name)
				return avgRxI > avgRxJ
			})
			
			for _, item := range statsSlice {
				iface := item.Name
				now := item.Traffic
				
				stateColor := Colors.Green
				if !now.IsUp() {
					stateColor = Colors.Red
				}
				
				speedInfo := ""
				if now.Speed != nil {
					speedInfo = fmt.Sprintf(" (%d Mbps)", *now.Speed)
				}
				
				lineParts := []string{
					fmt.Sprintf("%s%-12s%s [%s%s%s]%s", 
						Colors.Sepia, iface, Colors.Reset, 
						stateColor, now.State, Colors.Reset, speedInfo),
				}
				
				if prev, exists := prevStats[iface]; exists {
					rxRate := monitor.calculateRate(now.RxBytes, prev.RxBytes, interval)
					txRate := monitor.calculateRate(now.TxBytes, prev.TxBytes, interval)
					avgRx, avgTx := monitor.getAvgRates(iface)
					
					lineParts = append(lineParts,
						fmt.Sprintf("RX %s%-12s%s", Colors.Green, monitor.formatRatePrecise(rxRate), Colors.Reset),
						fmt.Sprintf("TX %s%-12s%s", Colors.Yellow, monitor.formatRatePrecise(txRate), Colors.Reset),
						fmt.Sprintf("Avg: %sRX%s TX%s%s", Colors.Cyan, 
							monitor.formatRatePrecise(avgRx), 
							monitor.formatRatePrecise(avgTx), Colors.Reset),
					)
				} else {
					lineParts = append(lineParts,
						fmt.Sprintf("RX %s%-12s%s", Colors.Green, monitor.formatBytes(now.RxBytes), Colors.Reset),
						fmt.Sprintf("TX %s%-12s%s", Colors.Yellow, monitor.formatBytes(now.TxBytes), Colors.Reset),
						fmt.Sprintf("%s(initial)%s", Colors.Grey, Colors.Reset),
					)
				}
				
				fmt.Println(strings.Join(lineParts, " "))
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
				monitor.formatBytes(totalRx), monitor.formatBytes(totalTx),
				time.Now().Format("15:04:05"), Colors.Reset)
			
			prevStats = currStats
			updateCount++
			
			time.Sleep(time.Duration(interval * float64(time.Second)))
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
		fmt.Fprintf(os.Stderr, "%sError generating JSON: %v%s\n", Colors.Red, err, Colors.Reset)
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
	
	// Platform check
	if _, err := os.Stat("/proc/net/dev"); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "%sError: This tool only works on Linux systems%s\n", Colors.Red, Colors.Reset)
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
