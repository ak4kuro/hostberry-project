package network

import (
	"os"
	"os/exec"
	"strings"
	"time"

	"hostberry/internal/i18n"
	"hostberry/internal/utils"
	"hostberry/internal/validators"
)

func listInterfaceNames() ([]string, error) {
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ": ", 3)
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if idx := strings.Index(name, "@"); idx >= 0 {
			name = name[:idx]
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func readTrimmedFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func ipLinkShow(iface string, useSudo bool) (string, error) {
	// El flag useSudo queda obsoleto: privileged-exec decide la vía según euid.
	return utils.ExecuteArgvNoCache([]string{"ip", "link", "show", iface}, 10*time.Second)
}

func ipAddrShow(iface string, useSudo bool) (string, error) {
	return utils.ExecuteArgvNoCache([]string{"ip", "addr", "show", iface}, 10*time.Second)
}

func parseLinkState(output string) string {
	for _, field := range strings.Fields(output) {
		if field == "state" {
			continue
		}
	}
	parts := strings.Fields(output)
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "state" {
			return strings.ToLower(strings.TrimSpace(parts[i+1]))
		}
	}
	return ""
}

func parseFirstIPv4FromIPAddr(output string) (string, string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "inet ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		parts := strings.SplitN(fields[1], "/", 2)
		ip := strings.TrimSpace(parts[0])
		mask := ""
		if len(parts) == 2 {
			mask = strings.TrimSpace(parts[1])
		}
		return ip, mask
	}
	return "", ""
}

func parseFirstIPv4FromIfconfig(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "inet ") {
			continue
		}
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "inet" {
				return strings.TrimPrefix(strings.TrimSpace(fields[i+1]), "addr:")
			}
		}
	}
	return ""
}

func firstHostnameIP() string {
	out, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(fields[0])
}

func processOutputContainsIface(processName, iface string) bool {
	out, err := exec.Command("pgrep", "-a", processName).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), iface)
}

func parseWPAState(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "wpa_state=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "wpa_state="))
		}
	}
	return ""
}

func getWPAState(iface string) string {
	if validators.ValidateIfaceName(iface) != nil {
		return ""
	}
	out, err := utils.ExecuteArgvNoCache([]string{"wpa_cli", "-i", iface, "status"}, 8*time.Second)
	if err != nil {
		return ""
	}
	return parseWPAState(out)
}

func parseDefaultGateway(routeOutput, iface string) string {
	for _, line := range strings.Split(routeOutput, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		var via, dev string
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "via" {
				via = fields[i+1]
			}
			if fields[i] == "dev" {
				dev = fields[i+1]
			}
		}
		if via == "" {
			continue
		}
		if iface == "" || dev == iface {
			return via
		}
	}
	return ""
}

func getNetworkInterfaces() map[string]interface{} {
	result := make(map[string]interface{})
	interfaces := []map[string]interface{}{}

	lines, err := listInterfaceNames()
	if err != nil {
		i18n.LogTf("logs.network_interfaces_error", err)
		result["interfaces"] = interfaces
		result["success"] = true
		result["count"] = 0
		return result
	}

	i18n.LogTf("logs.network_interfaces_found", lines)

	for _, ifaceName := range lines {
		ifaceName = strings.TrimSpace(ifaceName)
		if ifaceName == "" || ifaceName == "lo" {
			continue
		}
		if validators.ValidateIfaceName(ifaceName) != nil {
			i18n.LogTf("logs.network_interface_skip", ifaceName)
			continue
		}

		if _, ifaceCheckErr := ipLinkShow(ifaceName, false); ifaceCheckErr != nil {
			i18n.LogTf("logs.network_interface_skip", ifaceName)
			continue
		}

		i18n.LogTf("logs.network_interface_processing", ifaceName)

		iface := map[string]interface{}{
			"name":  ifaceName,
			"ip":    "N/A",
			"mac":   "N/A",
			"state": "unknown",
		}

		state := readTrimmedFile("/sys/class/net/" + ifaceName + "/operstate")
		if state == "" {
			if linkOut, err := ipLinkShow(ifaceName, false); err == nil {
				state = parseLinkState(linkOut)
			}
		}
		if state != "" {
			iface["state"] = state
		}

		if ifaceName == "ap0" {
			i18n.LogTf("logs.network_ap0_found", iface["state"])
			if iface["state"] == "down" || iface["state"] == "unknown" {
				i18n.LogT("logs.network_ap0_down")
				if _, activateErr := utils.ExecuteArgvNoCache([]string{"ip", "link", "set", "ap0", "up"}, 10*time.Second); activateErr == nil {
					time.Sleep(500 * time.Millisecond)
					newState := readTrimmedFile("/sys/class/net/ap0/operstate")
					if newState != "" {
						iface["state"] = newState
						i18n.LogTf("logs.network_ap0_activated", newState)
					}
				}
			}
		}

		if strings.HasPrefix(ifaceName, "wlan") {
			if wpaState := getWPAState(ifaceName); wpaState != "" {
				iface["wpa_state"] = wpaState
				if wpaState == "COMPLETED" {
					iface["state"] = "up"
				} else if wpaState == "ASSOCIATING" || wpaState == "ASSOCIATED" || wpaState == "4WAY_HANDSHAKE" || wpaState == "GROUP_HANDSHAKE" {
					iface["state"] = "connecting"
				} else {
					iface["state"] = "down"
				}
			}
		}

		if ipOut, err := ipAddrShow(ifaceName, false); err == nil {
			ipLine, mask := parseFirstIPv4FromIPAddr(ipOut)
			if ipLine != "" {
				iface["ip"] = ipLine
				if mask != "" {
					iface["netmask"] = mask
				}
			}
		}

		if iface["ip"] == "N/A" || iface["ip"] == "" {
			if ipOutSudo, err := ipAddrShow(ifaceName, true); err == nil {
				ipLineSudo, mask := parseFirstIPv4FromIPAddr(ipOutSudo)
				if ipLineSudo != "" {
					iface["ip"] = ipLineSudo
					if mask != "" {
						iface["netmask"] = mask
					}
				}
			}
		}

		if iface["ip"] == "N/A" || iface["ip"] == "" {
			ifconfigCmd := exec.Command("ifconfig", ifaceName)
			if ifconfigOut, err := ifconfigCmd.Output(); err == nil {
				ifconfigLine := parseFirstIPv4FromIfconfig(string(ifconfigOut))
				if ifconfigLine != "" {
					iface["ip"] = ifconfigLine
				}
			}
		}

		if iface["ip"] == "N/A" || iface["ip"] == "" {
			hostnameIP := firstHostnameIP()
			if hostnameIP != "" && validators.ValidateIP(hostnameIP) == nil {
				if ipOut, err := ipAddrShow(ifaceName, false); err == nil && strings.Contains(ipOut, hostnameIP) {
					iface["ip"] = hostnameIP
				}
			}
		}

		if (iface["state"] == "up" || iface["state"] == "connected" || iface["state"] == "connecting") && (iface["ip"] == "N/A" || iface["ip"] == "") {
			if processOutputContainsIface("dhclient", ifaceName) || processOutputContainsIface("udhcpc", ifaceName) {
				iface["ip"] = "Obtaining IP..."
			}
		}

		if strings.HasPrefix(ifaceName, "wlan") {
			if wpaState, hasWpaState := iface["wpa_state"]; hasWpaState && wpaState == "COMPLETED" {
				if iface["ip"] == "N/A" || iface["ip"] == "" || iface["ip"] == "Obtaining IP..." {
					iface["connected"] = false
					iface["state"] = "connecting"
				} else {
					iface["connected"] = true
					iface["state"] = "connected"
				}
			} else if wpaState, hasWpaState := iface["wpa_state"]; hasWpaState && (wpaState == "ASSOCIATING" || wpaState == "ASSOCIATED" || wpaState == "4WAY_HANDSHAKE" || wpaState == "GROUP_HANDSHAKE") {
				iface["connected"] = false
				iface["state"] = "connecting"
			} else {
				iface["connected"] = false
				if iface["state"] != "down" {
					iface["state"] = "down"
				}
			}
		} else {
			if iface["ip"] != "N/A" && iface["ip"] != "" && iface["ip"] != "Obtaining IP..." {
				iface["connected"] = true
				if iface["state"] == "up" {
					iface["state"] = "connected"
				}
			} else {
				iface["connected"] = false
			}
		}

		if mac := readTrimmedFile("/sys/class/net/" + ifaceName + "/address"); mac != "" {
			iface["mac"] = mac
		}

		if iface["connected"] == true && iface["ip"] != "N/A" {
			if routeOut, err := exec.Command("ip", "route").Output(); err == nil {
				if gateway := parseDefaultGateway(string(routeOut), ifaceName); gateway != "" {
					iface["gateway"] = gateway
				}
			}
			if iface["gateway"] == nil || iface["gateway"] == "" {
				if defaultGatewayOut, err := exec.Command("ip", "route").Output(); err == nil {
					if defaultGateway := parseDefaultGateway(string(defaultGatewayOut), ""); defaultGateway != "" {
						iface["gateway"] = defaultGateway
					}
				}
			}
		} else {
			iface["gateway"] = "N/A"
		}

		interfaces = append(interfaces, iface)
	}

	result["interfaces"] = interfaces
	result["success"] = true
	result["count"] = len(interfaces)

	return result
}

func getNetworkStatus() map[string]interface{} {
	result := make(map[string]interface{})

	if gatewayOut, err := exec.Command("ip", "route").Output(); err == nil {
		gateway := parseDefaultGateway(string(gatewayOut), "")
		if gateway != "" {
			result["gateway"] = gateway
		} else {
			result["gateway"] = "N/A"
		}
	} else {
		result["gateway"] = "N/A"
	}

	if dnsOut, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		dnsServers := strings.Split(strings.TrimSpace(string(dnsOut)), "\n")
		dnsList := []string{}
		for _, dns := range dnsServers {
			dns = strings.TrimSpace(dns)
			if strings.HasPrefix(dns, "nameserver ") {
				fields := strings.Fields(dns)
				if len(fields) >= 2 && fields[1] != "" {
					dnsList = append(dnsList, fields[1])
				}
			}
		}
		if len(dnsList) > 0 {
			result["dns"] = dnsList
		} else {
			result["dns"] = []string{"N/A"}
		}
	} else {
		result["dns"] = []string{"N/A"}
	}

	if hostname, err := exec.Command("hostname").Output(); err == nil {
		result["hostname"] = strings.TrimSpace(string(hostname))
	} else {
		result["hostname"] = "unknown"
	}

	return result
}

// ---- Exportados para el paquete principal ----

func GetNetworkInterfaces() map[string]interface{} { return getNetworkInterfaces() }
func GetNetworkStatus() map[string]interface{}     { return getNetworkStatus() }
