package wifi

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/utils"
)

func wifiRuntimeStatusHandler(c *fiber.Ctx) error {
	var enabled bool = false
	var hardBlocked bool = false
	var softBlocked bool = false

	wifiOutStr, err := utils.ExecuteArgv("nmcli", "-t", "-f", "WIFI", "g")
	if err == nil {
		wifiState := strings.ToLower(strings.TrimSpace(wifiOutStr))
		if strings.Contains(wifiState, "enabled") || strings.Contains(wifiState, "on") {
			enabled = true
		} else if strings.Contains(wifiState, "disabled") || strings.Contains(wifiState, "off") {
			enabled = false
		}
	}

	rfkillOutStr, _ := utils.ExecuteArgv("rfkill", "list", "wifi")
	rfkillStr := strings.ToLower(rfkillOutStr)
	if strings.Contains(rfkillStr, "hard blocked: yes") {
		hardBlocked = true
		enabled = false
	} else if strings.Contains(rfkillStr, "soft blocked: yes") {
		softBlocked = true
		enabled = false
	} else {
		// `iwconfig | grep -i wlan | head -1` → primera línea wlan en Go.
		iwOutStr, _ := utils.ExecuteArgv("iwconfig")
		var iwFirstWlan string
		for _, line := range strings.Split(iwOutStr, "\n") {
			if strings.Contains(strings.ToLower(line), "wlan") {
				iwFirstWlan = line
				break
			}
		}
		if iwFirstWlan != "" {
			// Segunda consulta del pipeline original: ¿la primera línea wlan
			// contiene "unassociated"?
			if !strings.Contains(strings.ToLower(iwFirstWlan), "unassociated") {
				enabled = true
			}
		} else {
			if anyWirelessInterfaceUp() {
				enabled = true
			}
		}
	}

	ssid := ""
	connected := false
	iface := "wlan0"

	iface = firstWirelessIface()

	wpaStatusOut, wpaErr := wpaCliStatus(iface)
	if wpaErr == nil && len(wpaStatusOut) > 0 {
		wpaStatus := string(wpaStatusOut)
		for _, line := range strings.Split(wpaStatus, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ssid=") {
				ssid = strings.TrimPrefix(line, "ssid=")
				if ssid != "" {
					if strings.Contains(wpaStatus, "wpa_state=COMPLETED") {
						connected = true
					}
				}
				break
			}
		}
	}

	if !connected || ssid == "" {
		iwLinkOut, iwErr := iwDevLink(iface)
		if iwErr == nil && len(iwLinkOut) > 0 {
			iwLink := string(iwLinkOut)
			for _, line := range strings.Split(iwLink, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Connected to ") {
					connected = true
				} else if strings.Contains(line, "SSID:") {
					ssid = strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
					if ssid != "" {
						connected = true
					}
				}
			}
		}
	}

	if !connected || ssid == "" {
		// `iwconfig | grep -i essid | grep -v 'off/any' | head -1` → parseo en Go.
		iwOutStr, _ := utils.ExecuteArgv("iwconfig")
		var essidLine string
		for _, line := range strings.Split(iwOutStr, "\n") {
			if strings.Contains(strings.ToLower(line), "essid") && !strings.Contains(line, "off/any") {
				essidLine = line
				break
			}
		}
		iwStr := essidLine
		if strings.Contains(iwStr, "ESSID:") {
			parts := strings.Split(iwStr, "ESSID:")
			if len(parts) > 1 {
				ssid = strings.TrimSpace(strings.Trim(parts[1], "\""))
				if ssid != "" && ssid != "off/any" {
					connected = true
				}
			}
		}
	}

	reallyConnected := false
	if connected && ssid != "" {
		// Verificar si wpa_state es COMPLETED (autenticado)
		wpaStateCompleted := false
		if wpaErr == nil && len(wpaStatusOut) > 0 {
			wpaStatus := string(wpaStatusOut)
			if strings.Contains(wpaStatus, "wpa_state=COMPLETED") {
				wpaStateCompleted = true
			}
		}

		ip := ifaceIPv4(iface)
		if ip != "" || wpaStateCompleted {
			if ip != "" && ip != "N/A" && !strings.HasPrefix(ip, "169.254") {
				reallyConnected = true
				log.Printf("WiFi realmente conectado: SSID=%s, IP=%s", ssid, ip)
			} else {
				// Si wpa_state es COMPLETED, considerar conectado aunque no tenga IP aún
				if wpaStateCompleted {
					reallyConnected = true
					log.Printf("WiFi autenticado (wpa_state=COMPLETED) pero sin IP aún: SSID=%s", ssid)
					// Intentar obtener IP si no hay proceso DHCP corriendo
					if !dhcpClientRunningForIface(iface) {
						log.Printf("Iniciando DHCP para obtener IP...")
						startDHCPForIface(iface)
					} else {
						log.Printf("WiFi está obteniendo IP (DHCP en proceso)")
					}
				} else {
					log.Printf("WiFi tiene SSID pero no está completamente autenticado: SSID=%s, IP=%s", ssid, ip)
				}
			}
		} else if wpaStateCompleted {
			// Si wpa_state es COMPLETED pero no se pudo verificar IP, considerar conectado
			reallyConnected = true
			log.Printf("WiFi autenticado (wpa_state=COMPLETED): SSID=%s", ssid)
		}
	}

	var connectionInfo fiber.Map = nil
	if reallyConnected && ssid != "" {
		connectionInfo = fiber.Map{
			"ssid": ssid,
		}

		iface := firstWirelessIface()

		wpaStatusOut, wpaErr := wpaCliStatus(iface)
		if wpaErr == nil && len(wpaStatusOut) > 0 {
			wpaStatus := string(wpaStatusOut)
			log.Printf("wpa_cli status output for %s: %s", iface, wpaStatus)
			for _, line := range strings.Split(wpaStatus, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "signal=") {
					signalStr := strings.TrimPrefix(line, "signal=")
					signalStr = strings.TrimSpace(signalStr)
					if signalStr != "" && signalStr != "0" {
						if signalInt, err := strconv.Atoi(signalStr); err == nil && signalInt != 0 {
							if signalInt > 0 {
								signalInt = -signalInt
							}
							if signalInt >= -100 && signalInt <= -30 {
								signalStr = strconv.Itoa(signalInt)
								connectionInfo["signal"] = signalStr
								log.Printf("Found signal from wpa_cli: %s dBm", signalStr)
							} else {
								log.Printf("Signal out of range from wpa_cli: %d dBm (ignoring)", signalInt)
							}
						}
					}
				} else if strings.HasPrefix(line, "key_mgmt=") {
					keyMgmt := strings.TrimPrefix(line, "key_mgmt=")
					keyMgmt = strings.TrimSpace(keyMgmt)
					if keyMgmt != "" {
						keyMgmtUpper := strings.ToUpper(keyMgmt)
						if strings.Contains(keyMgmtUpper, "WPA3") || strings.Contains(keyMgmtUpper, "SAE") {
							connectionInfo["security"] = "WPA3"
						} else if strings.Contains(keyMgmtUpper, "WPA2") || strings.Contains(keyMgmtUpper, "WPA-PSK") || strings.Contains(keyMgmtUpper, "WPA") {
							connectionInfo["security"] = "WPA2"
						} else if strings.Contains(keyMgmtUpper, "NONE") || keyMgmtUpper == "" {
							connectionInfo["security"] = "Open"
						} else {
							if strings.Contains(keyMgmtUpper, "PSK") {
								connectionInfo["security"] = "WPA2"
							} else {
								connectionInfo["security"] = keyMgmt
							}
						}
						log.Printf("Found security from wpa_cli: %s (key_mgmt=%s)", connectionInfo["security"], keyMgmt)
					}
				} else if strings.HasPrefix(line, "wpa=") {
					wpaStr := strings.TrimPrefix(line, "wpa=")
					wpaStr = strings.TrimSpace(wpaStr)
					if wpaStr == "2" && (connectionInfo["security"] == nil || connectionInfo["security"] == "") {
						connectionInfo["security"] = "WPA2"
						log.Printf("Found security from wpa_cli wpa field: WPA2")
					} else if wpaStr == "1" && (connectionInfo["security"] == nil || connectionInfo["security"] == "") {
						connectionInfo["security"] = "WPA"
						log.Printf("Found security from wpa_cli wpa field: WPA")
					}
				} else if strings.HasPrefix(line, "freq=") {
					freqStr := strings.TrimPrefix(line, "freq=")
					freqStr = strings.TrimSpace(freqStr)
					if freq, err := strconv.Atoi(freqStr); err == nil && freq > 0 {
						var channel int
						if freq >= 2412 && freq <= 2484 {
							channel = (freq-2412)/5 + 1
						} else if freq >= 5000 && freq <= 5825 {
							channel = (freq - 5000) / 5
						} else if freq >= 5955 && freq <= 7115 {
							channel = (freq - 5955) / 5
						}
						if channel > 0 {
							connectionInfo["channel"] = strconv.Itoa(channel)
							log.Printf("Found channel from wpa_cli: %d (from freq %d MHz)", channel, freq)
						} else {
							log.Printf("Could not convert freq %d to channel", freq)
						}
					}
				}
			}
		} else {
			log.Printf("wpa_cli failed or returned empty for %s: %v", iface, wpaErr)
		}

		if connectionInfo["signal"] == nil || connectionInfo["signal"] == "" || connectionInfo["signal"] == "0" ||
			connectionInfo["channel"] == nil || connectionInfo["channel"] == "" ||
			connectionInfo["security"] == nil || connectionInfo["security"] == "" {
			log.Printf("Getting additional info from iw for interface %s", iface)
			iwLinkOut, iwErr := iwDevLink(iface)
			if iwErr == nil && len(iwLinkOut) > 0 {
				iwLink := string(iwLinkOut)
				log.Printf("iw link output for %s: %s", iface, iwLink)
				for _, line := range strings.Split(iwLink, "\n") {
					line = strings.TrimSpace(line)
					if (connectionInfo["signal"] == nil || connectionInfo["signal"] == "" || connectionInfo["signal"] == "0") && strings.Contains(strings.ToLower(line), "signal") {
						parts := strings.Fields(line)
						for i, part := range parts {
							partLower := strings.ToLower(part)
							if (partLower == "signal:" || partLower == "signal") && i+1 < len(parts) {
								signalStr := strings.TrimSpace(parts[i+1])
								signalStr = strings.TrimSuffix(signalStr, "dBm")
								signalStr = strings.TrimSpace(signalStr)
								if signalStr != "" && signalStr != "0" {
									if signalInt, err := strconv.Atoi(signalStr); err == nil && signalInt != 0 {
										if signalInt > 0 {
											signalInt = -signalInt
										}
										if signalInt >= -100 && signalInt <= -30 {
											signalStr = strconv.Itoa(signalInt)
											connectionInfo["signal"] = signalStr
											log.Printf("Found signal from iw: %s dBm", signalStr)
										}
									} else {
										re := regexp.MustCompile(`-?\d+`)
										matches := re.FindString(signalStr)
										if matches != "" {
											if signalInt, err := strconv.Atoi(matches); err == nil {
												if signalInt > 0 {
													signalInt = -signalInt
												}
												if signalInt >= -100 && signalInt <= -30 {
													connectionInfo["signal"] = strconv.Itoa(signalInt)
													log.Printf("Found signal from iw (parsed): %d dBm", signalInt)
												}
											}
										}
									}
								}
								break
							}
						}
					}
					if (connectionInfo["channel"] == nil || connectionInfo["channel"] == "") && strings.Contains(line, "freq:") {
						parts := strings.Fields(line)
						for i, part := range parts {
							if part == "freq:" && i+1 < len(parts) {
								freqStr := strings.TrimSpace(parts[i+1])
								if freq, err := strconv.Atoi(freqStr); err == nil && freq > 0 {
									var channel int
									if freq >= 2412 && freq <= 2484 {
										channel = (freq-2412)/5 + 1
									} else if freq >= 5000 && freq <= 5825 {
										channel = (freq - 5000) / 5
									} else if freq >= 5955 && freq <= 7115 {
										channel = (freq - 5955) / 5
									}
									if channel > 0 {
										connectionInfo["channel"] = strconv.Itoa(channel)
										log.Printf("Found channel from iw: %d (from freq %d)", channel, freq)
									}
								}
								break
							}
						}
					}
					if connectionInfo["security"] == nil || connectionInfo["security"] == "" {
						if strings.Contains(line, "WPA3") || strings.Contains(line, "SAE") {
							connectionInfo["security"] = "WPA3"
							log.Printf("Found security from iw: WPA3")
						} else if strings.Contains(line, "WPA2") || strings.Contains(line, "WPA") {
							connectionInfo["security"] = "WPA2"
							log.Printf("Found security from iw: WPA2")
						}
					}
				}
			} else {
				log.Printf("iw link command failed or returned empty: %v, output: %s", iwErr, string(iwLinkOut))
			}
		}

		if connectionInfo["signal"] == nil || connectionInfo["signal"] == "" || connectionInfo["signal"] == "0" {
			log.Printf("Trying /proc/net/wireless for signal on %s", iface)
			wirelessLine := wirelessProcLine(iface)
			if wirelessLine != "" {
				log.Printf("/proc/net/wireless output: %s", wirelessLine)
				parts := strings.Fields(wirelessLine)
				if len(parts) >= 3 {
					if signalLevel, err := strconv.Atoi(strings.TrimSuffix(parts[2], ".")); err == nil && signalLevel > 0 {
						signalDbm := signalLevel / 10
						if signalDbm > 0 {
							connectionInfo["signal"] = fmt.Sprintf("-%d", signalDbm)
							log.Printf("Found signal from /proc/net/wireless: -%d dBm", signalDbm)
						}
					}
				}
			}
		}

		if (connectionInfo["signal"] == nil || connectionInfo["signal"] == "" || connectionInfo["signal"] == "0") ||
			(connectionInfo["channel"] == nil || connectionInfo["channel"] == "") {
			log.Printf("Trying iwconfig as last resort for interface %s", iface)
			iwconfigStr := iwconfigOutput(iface)
			if iwconfigStr != "" {
				log.Printf("iwconfig output: %s", iwconfigStr)
				if connectionInfo["signal"] == nil || connectionInfo["signal"] == "" || connectionInfo["signal"] == "0" {
					if strings.Contains(iwconfigStr, "Signal level=") {
						parts := strings.Split(iwconfigStr, "Signal level=")
						if len(parts) > 1 {
							fields := strings.Fields(parts[1])
							if len(fields) == 0 {
								// parts[1] vacío o solo espacios, evitar panic
							} else {
								signalPart := fields[0]
								signalStr := strings.TrimSpace(signalPart)
								signalStr = strings.TrimSuffix(signalStr, "dBm")
								signalStr = strings.TrimSpace(signalStr)
								if signalStr != "" && signalStr != "0" {
									connectionInfo["signal"] = signalStr
									log.Printf("Found signal from iwconfig: %s", signalStr)
								}
							}
						}
					}
				}
				if connectionInfo["channel"] == nil || connectionInfo["channel"] == "" {
					if strings.Contains(iwconfigStr, "Channel:") {
						parts := strings.Split(iwconfigStr, "Channel:")
						if len(parts) > 1 {
							channelFields := strings.Fields(parts[1])
							if len(channelFields) > 0 {
								channelStr := strings.TrimSpace(channelFields[0])
								if channelStr != "" {
									connectionInfo["channel"] = channelStr
									log.Printf("Found channel from iwconfig: %s", channelStr)
								}
							}
						}
					}
				}
			}
		}

		if (connectionInfo["signal"] == nil || connectionInfo["signal"] == "" || connectionInfo["signal"] == "0") ||
			(connectionInfo["channel"] == nil || connectionInfo["channel"] == "") {
			log.Printf("Trying iw dev %s station dump as additional method", iface)
			iwStationOut, iwStationErr := iwStationDump(iface)
			if iwStationErr == nil && len(iwStationOut) > 0 {
				iwStationStr := string(iwStationOut)
				log.Printf("iw station dump output: %s", iwStationStr)
				if connectionInfo["signal"] == nil || connectionInfo["signal"] == "" || connectionInfo["signal"] == "0" {
					lines := strings.Split(iwStationStr, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if strings.Contains(strings.ToLower(line), "signal") {
							re := regexp.MustCompile(`-?\d+`)
							matches := re.FindAllString(line, -1)
							for _, match := range matches {
								if signalInt, err := strconv.Atoi(match); err == nil {
									if signalInt > 0 {
										signalInt = -signalInt
									}
									if signalInt >= -100 && signalInt <= -30 {
										connectionInfo["signal"] = strconv.Itoa(signalInt)
										log.Printf("Found signal from iw station dump: %d dBm", signalInt)
										break
									}
								}
							}
						}
					}
				}
			}
		}

		if connectionInfo["signal"] == nil || connectionInfo["signal"] == "" || connectionInfo["signal"] == "0" {
			log.Printf("Warning: Could not determine signal strength for %s after all methods", iface)
			delete(connectionInfo, "signal")
		}
		if connectionInfo["channel"] == nil || connectionInfo["channel"] == "" {
			log.Printf("Warning: Could not determine channel for %s after all methods", iface)
			delete(connectionInfo, "channel")
		}
		if connectionInfo["security"] == nil || connectionInfo["security"] == "" {
			log.Printf("Warning: Could not determine security for %s, defaulting to WPA2", iface)
			connectionInfo["security"] = "WPA2" // Valor por defecto común
		}

		if iface != "" {
			if ipStr := ifaceIPv4(iface); ipStr != "" {
				connectionInfo["ip"] = ipStr
			}

			if macStr := readInterfaceFile(iface, "address"); macStr != "" {
				connectionInfo["mac"] = macStr
			}

			if speedStr := readInterfaceFile(iface, "speed"); speedStr != "" && speedStr != "-1" {
				connectionInfo["speed"] = speedStr + " Mbps"
			}
		}
	}

	if !connected && enabled {
		if iface := nmcliFirstWifiDevice(); iface != "" {
			if connectionInfo == nil {
				connectionInfo = fiber.Map{}
			}
			if macStr := readInterfaceFile(iface, "address"); macStr != "" {
				connectionInfo["mac"] = macStr
			}
		}
	}

	// connection_type: "wifi" | "ethernet" | "" para el wizard
	connectionType := ""
	if reallyConnected && ssid != "" {
		connectionType = "wifi"
	} else {
		if ifaceName := defaultRouteIface(); ifaceName != "" && (strings.HasPrefix(ifaceName, "eth") || strings.HasPrefix(ifaceName, "enp") || strings.HasPrefix(ifaceName, "eno") || strings.HasPrefix(ifaceName, "ens")) {
			connectionType = "ethernet"
		}
	}

	return c.JSON(fiber.Map{
		"enabled":            enabled,
		"connected":          reallyConnected,
		"current_connection": ssid,
		"ssid":               ssid,
		"connection_type":    connectionType,
		"hard_blocked":       hardBlocked,
		"soft_blocked":       softBlocked,
		"connection_info":    connectionInfo,
	})
}
