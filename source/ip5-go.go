package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorGrey   = "\033[38;5;245m"
	colorBlue   = "\033[34m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	clearScreen = "\033[H\033[J"
)

type ifaceStats struct {
	name      string
	rxBytes   uint64
	txBytes   uint64
	rxPackets uint64
	txPackets uint64
	rxErrs    uint64
	txErrs    uint64
}

func getInterfaceIPs() map[string][]string {
	ips := make(map[string][]string)
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var ipList []string
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					ipList = append(ipList, ipNet.IP.String())
				}
			}
		}
		if len(ipList) > 0 {
			ips[iface.Name] = ipList
		}
	}
	return ips
}

func parseProcNetDev() (map[string]*ifaceStats, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stats := make(map[string]*ifaceStats)
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 65536)
	sc.Buffer(buf, 1048576)

	for i := 0; sc.Scan(); i++ {
		if i < 2 {
			continue
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		p := strings.Fields(line)
		if len(p) < 12 {
			continue
		}
		iface := strings.TrimSuffix(p[0], ":")
		s := &ifaceStats{name: iface}
		fmt.Sscanf(p[1], "%d", &s.rxBytes)
		fmt.Sscanf(p[2], "%d", &s.rxPackets)
		fmt.Sscanf(p[3], "%d", &s.rxErrs)
		fmt.Sscanf(p[9], "%d", &s.txBytes)
		fmt.Sscanf(p[10], "%d", &s.txPackets)
		fmt.Sscanf(p[11], "%d", &s.txErrs)
		stats[iface] = s
	}
	return stats, sc.Err()
}

func formatBytes(b uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	val := float64(b)
	for val >= 1024 && i < len(units)-1 {
		val /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%s", val, units[i])
}

func formatRate(rate float64) string {
	units := []string{"B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"}
	i := 0
	val := rate
	for val >= 1024 && i < len(units)-1 {
		val /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%s", val, units[i])
}

func header() {
	fmt.Print(clearScreen)
	fmt.Printf("%sNetwork Interface Monitor%s\n", colorBlue, colorReset)
	fmt.Printf("%sMonitoring interface statistics...%s\n\n", colorGrey, colorReset)
}

func delta(prev, curr map[string]*ifaceStats, interval float64) {
	ipMap := getInterfaceIPs()
	
	for name, now := range curr {
		pr, ok := prev[name]
		if !ok {
			continue
		}

		var rxDelta, txDelta uint64
		
		if now.rxBytes >= pr.rxBytes {
			rxDelta = now.rxBytes - pr.rxBytes
		} else {
			rxDelta = (^uint64(0) - pr.rxBytes) + now.rxBytes + 1
		}
		
		if now.txBytes >= pr.txBytes {
			txDelta = now.txBytes - pr.txBytes
		} else {
			txDelta = (^uint64(0) - pr.txBytes) + now.txBytes + 1
		}

		rxRate := float64(rxDelta) / interval
		txRate := float64(txDelta) / interval

		ips := ipMap[name]
		ipInfo := ""
		if len(ips) > 0 {
			ipInfo = fmt.Sprintf(" [%s]", strings.Join(ips, ", "))
		}

		fmt.Printf("%s%10s%s%s :: RX %s%-12s%s TX %s%-12s%s\n",
			colorBlue, name, colorReset, ipInfo,
			colorGreen, formatRate(rxRate), colorReset,
			colorYellow, formatRate(txRate), colorReset)
	}
	fmt.Println()
	fmt.Printf("%s[ctrl+c to stop]%s\n", colorGrey, colorReset)
}

func watch(interval float64) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	prev, err := parseProcNetDev()
	if err != nil {
		fmt.Printf("%sfailed to read /proc/net/dev: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	header()

	for {
		select {
		case <-time.After(time.Duration(interval * float64(time.Second))):
			curr, err := parseProcNetDev()
			if err != nil {
				fmt.Printf("%sread error: %v%s\n", colorRed, err, colorReset)
				continue
			}
			header()
			delta(prev, curr, interval)
			prev = curr

		case <-sigChan:
			fmt.Printf("\n%sExiting...%s\n", colorGrey, colorReset)
			return
		}
	}
}

func main() {
	watchMode := flag.Bool("watch", false, "Enable live monitoring mode")
	interval := flag.Float64("interval", 1.0, "Polling interval in seconds")
	flag.Parse()

	if *interval <= 0 {
		fmt.Printf("%sInterval must be positive%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	if !*watchMode {
		header()
		stats, err := parseProcNetDev()
		if err != nil {
			fmt.Printf("%s%s%s\n", colorRed, err.Error(), colorReset)
			os.Exit(1)
		}
		ipMap := getInterfaceIPs()
		
		for _, s := range stats {
			ips := ipMap[s.name]
			ipInfo := ""
			if len(ips) > 0 {
				ipInfo = fmt.Sprintf(" - %s%s%s", colorGrey, strings.Join(ips, ", "), colorReset)
			}
			
			fmt.Printf("%s%s%s%s\n", colorBlue, s.name, colorReset, ipInfo)
			fmt.Printf("    RX: %s%s%s (%d pkts, %d errs)\n",
				colorGreen, formatBytes(s.rxBytes), colorReset, s.rxPackets, s.rxErrs)
			fmt.Printf("    TX: %s%s%s (%d pkts, %d errs)\n\n",
				colorYellow, formatBytes(s.txBytes), colorReset, s.txPackets, s.txErrs)
		}
		fmt.Printf("%sInvoke with --watch for live view.%s\n", colorGrey, colorReset)
		return
	}
	watch(*interval)
}
