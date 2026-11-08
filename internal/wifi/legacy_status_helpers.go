package wifi

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"hostberry/internal/utils"
)

func firstWirelessIface() string {
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		return "wlan0"
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ": ", 3)
		if len(parts) < 2 {
			continue
		}
		iface := strings.TrimSpace(parts[1])
		if idx := strings.Index(iface, "@"); idx >= 0 {
			iface = iface[:idx]
		}
		if (strings.HasPrefix(iface, "wlan") || strings.HasPrefix(iface, "wl")) && validateInterfaceName(iface) == nil {
			return iface
		}
	}
	return "wlan0"
}

func anyWirelessInterfaceUp() bool {
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, ": wlan") && strings.Contains(lower, "state up") {
			return true
		}
	}
	return false
}

func readInterfaceFile(iface, name string) string {
	if validateInterfaceName(iface) != nil {
		return ""
	}
	data, err := os.ReadFile("/sys/class/net/" + iface + "/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func wpaCliStatus(iface string) ([]byte, error) {
	if validateInterfaceName(iface) != nil {
		return nil, exec.ErrNotFound
	}
	return utils.ExecCommand(fmt.Sprintf("wpa_cli -i %s status", iface)).CombinedOutput()
}

func iwDevLink(iface string) ([]byte, error) {
	if validateInterfaceName(iface) != nil {
		return nil, exec.ErrNotFound
	}
	return utils.ExecCommand(fmt.Sprintf("iw dev %s link", iface)).CombinedOutput()
}

func iwStationDump(iface string) ([]byte, error) {
	if validateInterfaceName(iface) != nil {
		return nil, exec.ErrNotFound
	}
	return utils.ExecCommand(fmt.Sprintf("iw dev %s station dump", iface)).CombinedOutput()
}

// ifaceIPv4 delega en utils.IPv4OnInterface (argv, sin shell).
func ifaceIPv4(iface string) string {
	return utils.IPv4OnInterface(iface)
}

func dhcpClientRunningForIface(iface string) bool {
	if validateInterfaceName(iface) != nil {
		return false
	}
	for _, proc := range []string{"dhclient", "udhcpc"} {
		out, err := exec.Command("pgrep", "-a", proc).Output()
		if err != nil {
			continue
		}
		if strings.Contains(string(out), iface) {
			return true
		}
	}
	return false
}

func startDHCPForIface(iface string) {
	if validateInterfaceName(iface) != nil {
		return
	}
	if out, err := utils.ExecCommand(fmt.Sprintf("dhclient -v %s", iface)).CombinedOutput(); err == nil || len(out) > 0 {
		return
	}
	_, _ = utils.ExecCommand(fmt.Sprintf("udhcpc -i %s -q -n", iface)).CombinedOutput()
}

func wirelessProcLine(iface string) string {
	if validateInterfaceName(iface) != nil {
		return ""
	}
	data, err := os.ReadFile("/proc/net/wireless")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, iface+":") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func nmcliFirstWifiDevice() string {
	out, err := exec.Command("nmcli", "-t", "-f", "DEVICE,TYPE", "dev", "status").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 2 && strings.EqualFold(strings.TrimSpace(fields[1]), "wifi") {
			device := strings.TrimSpace(fields[0])
			if validateInterfaceName(device) == nil {
				return device
			}
		}
	}
	return ""
}

func defaultRouteIface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				iface := strings.TrimSpace(fields[i+1])
				if validateInterfaceName(iface) == nil {
					return iface
				}
			}
		}
	}
	return ""
}

func iwconfigOutput(iface string) string {
	if validateInterfaceName(iface) != nil {
		return ""
	}
	out, err := utils.ExecCommand(fmt.Sprintf("iwconfig %s", iface)).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}
