package hostapd

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/constants"
	"hostberry/internal/utils"
	"hostberry/internal/validators"
	"hostberry/internal/wifi"
)

// executeArgv ejecuta un comando como argv (sin shell) delegando en
// internal/utils, que aplica la lógica de sudo/privileged-exec.
func executeArgv(args ...string) (string, error) {
	return utils.ExecuteArgv(args...)
}

// detectPhyName detecta el nombre phy80211 de una interfaz WiFi usando tres
// métodos: sysfs, `iw dev <iface> info` y `iw list`. Sin pipelines shell.
func detectPhyName(phyInterface string) string {
	if b, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/phy80211/name", phyInterface)); err == nil {
		if name := strings.TrimSpace(string(b)); name != "" {
			return name
		}
	}
	if iwOut, err := executeArgv("iw", "dev", phyInterface, "info"); err == nil {
		for _, line := range strings.Split(iwOut, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "wiphy" {
				return fields[1]
			}
		}
	}
	if listOut, err := executeArgv("iw", "list"); err == nil {
		for _, line := range strings.Split(listOut, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "Wiphy" {
				return fields[1]
			}
		}
	}
	return ""
}

// strconvAtoiSafe wrapper para el paquete main -> internal/utils.
func strconvAtoiSafe(s string) (int, error) {
	return utils.StrconvAtoiSafe(s)
}

func processRunning(procName string) bool {
	return exec.Command("pgrep", procName).Run() == nil
}

func firstIPv4FromIPAddrShow(iface string) string {
	out, err := exec.Command("ip", "addr", "show", iface).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strings.TrimSpace(strings.SplitN(fields[1], "/", 2)[0])
			}
		}
	}
	return ""
}

func lastNLines(s string, n int) []string {
	s = strings.TrimSpace(s)
	if s == "" || n <= 0 {
		return []string{}
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

func firstNLines(s string, n int) []string {
	s = strings.TrimSpace(s)
	if s == "" || n <= 0 {
		return []string{}
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return lines
	}
	return lines[:n]
}

func HostapdAccessPointsHandler(c *fiber.Ctx) error {
	var aps []fiber.Map

	configPath := "/etc/hostapd/hostapd.conf"
	config := make(map[string]string)

	if configContent, err := os.ReadFile(configPath); err == nil {
		lines := strings.Split(string(configContent), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				config[key] = value
			}
		}
	}

	interfaceName := sanitizeIfaceOrDefault(config["interface"], "ap0")
	hostapdActive := hostapdProcessOrUnitActive()
	hostapdTransmitting := false

	if hostapdActive {
		if info, err := iwDevInfo(interfaceName); err == nil && iwDevInfoShowsAP(info) {
			hostapdTransmitting = true
		}
		if !hostapdTransmitting && hostapdCliStatusEnabled(interfaceName) {
			hostapdTransmitting = true
		}
	}

	if hostapdActive || len(config) > 0 {
		ssid := config["ssid"]
		if ssid == "" {
			ssid = "hostberry" // Valor por defecto (red + portal cautivo)
		}

		channel := config["channel"]
		if channel == "" {
			channel = "6" // Valor por defecto
		}

		security := "WPA2"
		if config["auth_algs"] == "0" {
			security = "Open"
		} else if strings.Contains(config["wpa_key_mgmt"], "SHA256") {
			security = "WPA3"
		} else if config["wpa"] == "2" {
			security = "WPA2"
		}

		clientsCount := 0
		if hostapdActive {
			clientsCount = hostapdCliCountStations(interfaceName)
		}

		actuallyActive := hostapdActive && hostapdTransmitting

		aps = append(aps, fiber.Map{
			"name":      interfaceName,
			"ssid":      ssid,
			"interface": interfaceName,
			"channel":   channel,
			"security":  security,
			"enabled":   actuallyActive, // Solo true si realmente está transmitiendo
			"active":    actuallyActive, // Solo true si realmente está transmitiendo
			"status": func() string {
				if actuallyActive {
					return "active"
				} else if hostapdActive {
					return "error" // Servicio corriendo pero no transmite
				}
				return "inactive"
			}(),
			"transmitting":    hostapdTransmitting, // Nuevo campo para diagnóstico
			"service_running": hostapdActive,       // Servicio corriendo (pero puede no transmitir)
			"clients_count":   clientsCount,
		})
	}

	return c.JSON(aps)
}

func HostapdClientsHandler(c *fiber.Ctx) error {
	var clients []fiber.Map

	if !hostapdProcessOrUnitActive() {
		return c.JSON(clients)
	}

	iface := ifaceFromHostapdConf("/etc/hostapd/hostapd.conf", "ap0")
	out, err := hostapdCli(iface, "all_sta")
	if err != nil || strings.TrimSpace(out) == "" {
		return c.JSON(clients)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasPrefix(line, "sta=") {
			mac := strings.TrimPrefix(line, "sta=")
			clients = append(clients, fiber.Map{
				"mac_address": mac,
				"ip_address":  "-",
				"signal":      "-",
				"uptime":      "-",
			})
		}
	}

	return c.JSON(clients)
}

func HostapdCreateAp0Handler(c *fiber.Ctx) error {
	phyInterface := "wlan0"
	if linkOut, err := executeArgv("ip", "link"); err == nil {
		for _, line := range strings.Split(linkOut, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasPrefix(fields[1], "wlan") {
				phyInterface = strings.TrimSuffix(fields[1], ":")
				break
			}
		}
	}
	phyInterface = sanitizeIfaceOrDefault(phyInterface, "wlan0")

	log.Printf("Creating ap0 interface from %s", phyInterface)

	ap0Exists := false
	if out, err := executeArgv("ip", "link", "show", "ap0"); err == nil && strings.TrimSpace(out) != "" {
		ap0Exists = true
		log.Printf("Interface ap0 already exists")
		return c.JSON(fiber.Map{
			"success": true,
			"message": "Interface ap0 already exists",
			"exists":  true,
		})
	}

	_, _ = executeArgv("ip", "link", "set", phyInterface, "up")
	time.Sleep(500 * time.Millisecond)

	phyName := detectPhyName(phyInterface)

	if phyName == "" {
		phyName = "phy0"
		log.Printf("Warning: Could not detect phy name, using default: %s", phyName)
	}

	if err := validators.ValidatePhyName(phyName); err != nil {
		return respondValidatorError(c, err)
	}

	log.Printf("Detected phy name: %s for interface %s", phyName, phyInterface)

	delOut, _ := executeArgv("iw", "dev", "ap0", "del")
	if delOut != "" {
		log.Printf("Removed existing ap0 interface (if it existed): %s", strings.TrimSpace(delOut))
	}
	time.Sleep(1 * time.Second)

	log.Printf("Executing: iw phy %s interface add ap0 type __ap", phyName)
	createOut, createErr := executeArgv("iw", "phy", phyName, "interface", "add", "ap0", "type", "__ap")
	if createOut != "" {
		log.Printf("Command output: %s", strings.TrimSpace(createOut))
	}

	if createErr != nil {
		log.Printf("Error creating ap0 with phy %s: %s", phyName, strings.TrimSpace(createOut))
		log.Printf("Trying alternative method: using interface %s directly...", phyInterface)

		log.Printf("Executing: iw dev %s interface add ap0 type __ap", phyInterface)
		createOut2, createErr2 := executeArgv("iw", "dev", phyInterface, "interface", "add", "ap0", "type", "__ap")
		if createOut2 != "" {
			log.Printf("Method 1 output: %s", strings.TrimSpace(createOut2))
		}

		if createErr2 != nil {
			log.Printf("Error with alternative method: %s", strings.TrimSpace(createOut2))
			return c.Status(500).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("Failed to create ap0 interface: %s", strings.TrimSpace(createOut2)),
			})
		} else {
			log.Printf("Successfully created ap0 interface using alternative method (from %s)", phyInterface)
			ap0Exists = true
		}
	} else {
		log.Printf("Successfully created ap0 interface using phy %s", phyName)
		ap0Exists = true
	}

	if ap0Exists {
		time.Sleep(2 * time.Second)

		verified := false
		for i := 0; i < 5; i++ {
			verifyOut, verifyErr := executeArgv("ip", "link", "show", "ap0")
			if verifyErr == nil && strings.TrimSpace(verifyOut) != "" {
				log.Printf("Interface ap0 verified successfully (attempt %d)", i+1)
				verified = true
				break
			}

			if i < 4 {
				log.Printf("Verification attempt %d failed, retrying...", i+1)
				time.Sleep(1 * time.Second)
			}
		}

		if !verified {
			log.Printf("ERROR: Interface ap0 was NOT created successfully after all attempts")
			return c.Status(500).JSON(fiber.Map{
				"success": false,
				"error":   "Failed to verify ap0 interface creation. Please check WiFi hardware and drivers.",
			})
		} else {
			log.Printf("SUCCESS: Interface ap0 created and verified")
			_, _ = executeArgv("ip", "link", "set", "ap0", "up")
			return c.JSON(fiber.Map{
				"success": true,
				"message": "Interface ap0 created successfully",
				"exists":  true,
			})
		}
	}

	return c.Status(500).JSON(fiber.Map{
		"success": false,
		"error":   "Failed to create ap0 interface",
	})
}

func HostapdToggleHandler(c *fiber.Ctx) error {
	log.Printf("HostAPD toggle request received")

	isActive := hostapdProcessOrUnitActive()
	hostapdStatus := "inactive"
	if isActive {
		hostapdStatus = "active"
	}

	log.Printf("Current HostAPD status: %s (isActive: %v)", hostapdStatus, isActive)

	var cmdArgs []string
	var enableArgs []string
	var action string

	if isActive {
		action = "disable"
		_, _ = executeArgv("systemctl", "stop", "dnsmasq")
		cmdArgs = []string{"systemctl", "stop", "hostapd"}
		enableArgs = []string{"systemctl", "disable", "hostapd"}

	} else {
		action = "enable"

		configPath := "/etc/hostapd/hostapd.conf"
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			log.Printf("HostAPD configuration file not found: %s", configPath)
			return c.Status(400).JSON(fiber.Map{
				"error":          "HostAPD configuration not found. Please configure HostAPD first using the configuration form below.",
				"success":        false,
				"config_missing": true,
				"config_path":    configPath,
			})
		}

		configContent, err := os.ReadFile(configPath)
		if err != nil || len(configContent) == 0 {
			log.Printf("HostAPD configuration file is empty or unreadable: %s", configPath)
			return c.Status(400).JSON(fiber.Map{
				"error":          "HostAPD configuration file is empty or invalid. Please configure HostAPD first using the configuration form below.",
				"success":        false,
				"config_missing": true,
				"config_path":    configPath,
			})
		}

		ap0Exists := false
		if out, err := executeArgv("ip", "link", "show", "ap0"); err == nil && strings.TrimSpace(out) != "" {
			ap0Exists = true
			log.Printf("Interface ap0 already exists")
		} else {
			log.Printf("Interface ap0 does not exist, creating it...")
			phyInterface := ifaceFromHostapdConf(configPath, "wlan0")

			_, _ = executeArgv("ip", "link", "set", phyInterface, "up")
			time.Sleep(500 * time.Millisecond)

			phyName := detectPhyName(phyInterface)

			if phyName == "" {
				phyName = "phy0"
				log.Printf("Warning: Could not detect phy name, using default: %s", phyName)
			}

			if err := validators.ValidatePhyName(phyName); err != nil {
				log.Printf("phy name inválido tras detección: %v", err)
				phyName = "phy0"
			}

			log.Printf("Creating ap0 interface using phy %s from interface %s...", phyName, phyInterface)

			_, _ = executeArgv("iw", "dev", "ap0", "del")
			time.Sleep(1 * time.Second)

			log.Printf("Executing: iw phy %s interface add ap0 type __ap", phyName)
			createOut, createErr := executeArgv("iw", "phy", phyName, "interface", "add", "ap0", "type", "__ap")
			if createErr != nil {
				log.Printf("Warning: Could not create ap0 interface with phy %s: %s", phyName, strings.TrimSpace(createOut))
				log.Printf("Executing: iw dev %s interface add ap0 type __ap", phyInterface)
				createOut2, createErr2 := executeArgv("iw", "dev", phyInterface, "interface", "add", "ap0", "type", "__ap")
				if createErr2 != nil {
					log.Printf("Warning: Alternative method also failed: %s", strings.TrimSpace(createOut2))
				} else {
					log.Printf("Successfully created ap0 interface using alternative method (from %s)", phyInterface)
					ap0Exists = true
				}
			} else {
				log.Printf("Successfully created ap0 interface using phy %s", phyName)
				ap0Exists = true
			}

			if ap0Exists {
				verifyOut, verifyErr := executeArgv("ip", "link", "show", "ap0")
				if verifyErr == nil && strings.TrimSpace(verifyOut) != "" {
					log.Printf("Interface ap0 verified: %s", strings.TrimSpace(verifyOut))
					_, _ = executeArgv("ip", "link", "set", "ap0", "up")
					log.Printf("Activated ap0 interface")
				} else {
					log.Printf("Warning: ap0 was created but verification failed")
				}
			}
		}

		maskedStatus := systemctlIsEnabled("hostapd")
		if strings.Contains(maskedStatus, "masked") {
			log.Printf("HostAPD service is masked, unmasking...")
			_, _ = executeArgv("systemctl", "unmask", "hostapd")
		}

		configLines := strings.Split(string(configContent), "\n")
		var interfaceName, gatewayIP string
		for _, line := range configLines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "interface=") {
				interfaceName = strings.TrimSpace(strings.TrimPrefix(line, "interface="))
			}
		}

		if interfaceName != "" && validators.ValidateIfaceName(interfaceName) != nil {
			log.Printf("HostAPD config: nombre de interfaz inválido: %q", interfaceName)
			return c.Status(400).JSON(fiber.Map{
				"error":          "HostAPD: valor 'interface' en la configuración no es un nombre de interfaz válido.",
				"success":        false,
				"config_missing": true,
				"config_path":    configPath,
			})
		}

		if interfaceName == "" {
			log.Printf("HostAPD configuration file missing interface setting: %s", configPath)
			return c.Status(400).JSON(fiber.Map{
				"error":          "HostAPD configuration file is missing required 'interface' setting. Please configure HostAPD first using the configuration form below.",
				"success":        false,
				"config_missing": true,
				"config_path":    configPath,
			})
		}

		if interfaceName != "" {
			gatewayIP = "192.168.4.1"

			currentIP := firstIPv4FromIPAddrShow(interfaceName)

			if currentIP == "" {
				log.Printf("Configuring IP %s on interface %s", gatewayIP, interfaceName)
				if out, err := executeArgv("ip", "addr", "add", gatewayIP+"/24", "dev", interfaceName); err != nil {
					if out2, err2 := executeArgv("ip", "addr", "replace", gatewayIP+"/24", "dev", interfaceName); err2 != nil {
						log.Printf("Warning: Error setting IP on interface: %s", strings.TrimSpace(out+out2))
					}
				}

				if out2, err := executeArgv("ip", "link", "set", interfaceName, "up"); err != nil {
					log.Printf("Warning: Error bringing interface up: %s", strings.TrimSpace(out2))
				}
			}
		}

		_, _ = executeArgv("systemctl", "unmask", "hostapd")
		_, _ = executeArgv("systemctl", "unmask", "dnsmasq")

		_, _ = executeArgv("systemctl", "daemon-reload")

		enableArgs = []string{"systemctl", "enable", "hostapd"}
		_, _ = executeArgv("systemctl", "enable", "dnsmasq")

		_, _ = executeArgv("chmod", "644", configPath)

		cmdArgs = []string{"systemctl", "start", "hostapd"}
		_, _ = executeArgv("systemctl", "start", "dnsmasq")
	}

	log.Printf("Action: %s, Command: %s", action, strings.Join(cmdArgs, " "))

	if len(enableArgs) > 0 {
		if out, err := executeArgv(enableArgs...); err != nil {
			log.Printf("Warning: Error enabling/disabling hostapd: %s", strings.TrimSpace(out))
		} else {
			log.Printf("Enable/disable command executed successfully: %s", strings.TrimSpace(out))
		}
	}

	out, err := executeArgv(cmdArgs...)
	if err != nil {
		log.Printf("Error executing %s command: %s", action, strings.TrimSpace(out))

		var errorDetails string
		if action == "enable" {
			journalOut, _ := utils.ExecuteArgvNoCache([]string{"journalctl", "-u", "hostapd", "-n", "20", "--no-pager"}, 10*time.Second)
			journalLogs := strings.TrimSpace(journalOut)
			journalLogs = strings.Join(lastNLines(journalLogs, 10), "\n")
			if journalLogs != "" {
				lines := strings.Split(journalLogs, "\n")
				errorLines := []string{}
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && (strings.Contains(strings.ToLower(line), "error") ||
						strings.Contains(strings.ToLower(line), "failed") ||
						strings.Contains(strings.ToLower(line), "fail")) {
						errorLines = append(errorLines, line)
					}
				}
				if len(errorLines) > 0 {
					errorDetails = fmt.Sprintf(" Recent errors: %s", strings.Join(errorLines, "; "))
				} else {
					errorDetails = fmt.Sprintf(" Last logs: %s", strings.Join(lines[len(lines)-3:], "; "))
				}
			} else {
				statusOut, _ := utils.ExecuteArgvNoCache([]string{"systemctl", "status", "hostapd", "--no-pager"}, 10*time.Second)
				statusInfo := strings.TrimSpace(statusOut)
				statusInfo = strings.Join(firstNLines(statusInfo, 15), "\n")
				if statusInfo != "" {
					errorDetails = fmt.Sprintf(" Service status: %s", statusInfo)
				}
			}
		}

		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Failed to %s hostapd: %s%s", action, strings.TrimSpace(out), errorDetails),
			"success": false,
		})
	}

	log.Printf("HostAPD %s command executed. Output: %s", action, strings.TrimSpace(out))

	if action == "enable" {
		time.Sleep(1500 * time.Millisecond) // Más tiempo para que hostapd inicie
	} else {
		time.Sleep(500 * time.Millisecond)
	}

	actuallyActive := hostapdProcessOrUnitActive()
	hostapdStatus2 := "inactive"
	if actuallyActive {
		hostapdStatus2 = "active"
	}

	if action == "enable" && !actuallyActive {
		log.Printf("HostAPD failed to start. Checking logs...")
		enabledStatus := systemctlIsEnabled("hostapd")

		journalOut, _ := utils.ExecuteArgvNoCache([]string{"journalctl", "-u", "hostapd", "-n", "15", "--no-pager"}, 10*time.Second)
		journalLogs := strings.TrimSpace(journalOut)
		journalLogs = strings.Join(lastNLines(journalLogs, 8), "\n")

		statusOut, _ := utils.ExecuteArgvNoCache([]string{"systemctl", "status", "hostapd", "--no-pager"}, 10*time.Second)
		statusInfo := strings.TrimSpace(statusOut)
		statusInfo = strings.Join(firstNLines(statusInfo, 20), "\n")

		var errorMsg string
		if journalLogs != "" {
			lines := strings.Split(journalLogs, "\n")
			errorLines := []string{}
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					lowerLine := strings.ToLower(line)
					if strings.Contains(lowerLine, "error") || strings.Contains(lowerLine, "failed") ||
						strings.Contains(lowerLine, "fail") || strings.Contains(lowerLine, "cannot") {
						errorLines = append(errorLines, line)
					}
				}
			}
			if len(errorLines) > 0 {
				maxLines := 3
				if len(errorLines) < maxLines {
					maxLines = len(errorLines)
				}
				errorMsg = strings.Join(errorLines[:maxLines], "; ")
			} else if len(lines) > 0 {
				maxLines := 3
				if len(lines) < maxLines {
					maxLines = len(lines)
				}
				errorMsg = strings.Join(lines[len(lines)-maxLines:], "; ")
			}
		}

		if errorMsg == "" && statusInfo != "" {
			statusLines := strings.Split(statusInfo, "\n")
			for _, line := range statusLines {
				if strings.Contains(strings.ToLower(line), "active:") ||
					strings.Contains(strings.ToLower(line), "failed") ||
					strings.Contains(strings.ToLower(line), "error") {
					errorMsg = strings.TrimSpace(line)
					break
				}
			}
		}

		if errorMsg != "" {
			return c.Status(500).JSON(fiber.Map{
				"error":   fmt.Sprintf("Failed to enable HostAPD. Service status: %s (enabled: %s). %s", hostapdStatus2, enabledStatus, errorMsg),
				"success": false,
				"status":  hostapdStatus2,
				"enabled": false,
			})
		} else {
			return c.Status(500).JSON(fiber.Map{
				"error":   fmt.Sprintf("Failed to enable HostAPD. Service status: %s (enabled: %s). Check configuration and logs.", hostapdStatus2, enabledStatus),
				"success": false,
				"status":  hostapdStatus2,
				"enabled": false,
			})
		}
	}

	log.Printf("HostAPD status after %s: %s (actuallyActive: %v)", action, hostapdStatus2, actuallyActive)

	return c.JSON(fiber.Map{
		"success": true,
		"output":  strings.TrimSpace(out),
		"enabled": actuallyActive,
		"action":  action,
		"status":  hostapdStatus2,
	})
}

func HostapdRestartHandler(c *fiber.Ctx) error {
	out1, err1 := executeArgv("systemctl", "stop", "hostapd")

	time.Sleep(500 * time.Millisecond)

	out2, err2 := executeArgv("systemctl", "start", "hostapd")

	if err1 != nil || err2 != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Error reiniciando HostAPD",
			"stop":    strings.TrimSpace(out1),
			"start":   strings.TrimSpace(out2),
			"stopOk":  err1 == nil,
			"startOk": err2 == nil,
			"success": false,
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"output":  "HostAPD restarted successfully",
	})
}

func HostapdDiagnosticsHandler(c *fiber.Ctx) error {
	diagnostics := make(map[string]interface{})

	systemctlActive := systemctlIsActive("hostapd")
	systemctlStatus := "inactive"
	if systemctlActive {
		systemctlStatus = "active"
	}
	pgrepStatus := "inactive"
	if processRunning("hostapd") {
		pgrepStatus = "active"
	}

	serviceRunning := systemctlStatus == "active" || pgrepStatus == "active"
	diagnostics["service_running"] = serviceRunning
	diagnostics["systemctl_status"] = systemctlStatus
	diagnostics["process_running"] = pgrepStatus == "active"

	interfaceName := "wlan0"
	configPath := "/etc/hostapd/hostapd.conf"
	if configContent, err := os.ReadFile(configPath); err == nil {
		lines := strings.Split(string(configContent), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "interface=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					interfaceName = strings.TrimSpace(parts[1])
					// `hostapd.conf` es local y puede no estar en formato "seguro";
					// validamos antes de interpolar en comandos.
					if validators.ValidateIfaceName(interfaceName) != nil {
						interfaceName = "wlan0"
					}
					break
				}
			}
		}
	}
	diagnostics["interface"] = interfaceName

	// Detectar modo AP: `iw dev <iface> info` (type AP) o iwconfig (mode:master).
	iwStatus := ""
	if iwOut, err := executeArgv("iw", "dev", interfaceName, "info"); err == nil {
		if strings.Contains(strings.ToLower(iwOut), "type ap") {
			iwStatus = iwOut
		}
	}
	if iwStatus == "" {
		if iwcOut, err := executeArgv("iwconfig", interfaceName); err == nil {
			if strings.Contains(strings.ToLower(iwcOut), "mode:master") {
				iwStatus = iwcOut
			}
		}
	}
	transmitting := iwStatus != ""

	if !transmitting && serviceRunning {
		if cliOut, err := executeArgv("hostapd_cli", "-i", interfaceName, "status"); err == nil {
			if strings.Contains(strings.ToLower(cliOut), "state=enabled") {
				transmitting = true
			}
		}
	}

	diagnostics["transmitting"] = transmitting
	diagnostics["interface_in_ap_mode"] = iwStatus != ""

	journalOut, _ := utils.ExecuteArgvNoCache([]string{"journalctl", "-u", "hostapd", "-n", "50", "--no-pager"}, 10*time.Second)
	journalLogs := journalOut
	journalLogs = strings.Join(lastNLines(journalLogs, 30), "\n")
	diagnostics["recent_logs"] = journalLogs

	errors := []string{}
	journalLower := strings.ToLower(journalLogs)
	if strings.Contains(journalLower, "could not configure driver") {
		errors = append(errors, "Driver configuration error")
	}
	if strings.Contains(journalLower, "nl80211: could not") {
		errors = append(errors, "nl80211 driver error")
	}
	if strings.Contains(journalLower, "interface") && strings.Contains(journalLower, "not found") {
		errors = append(errors, "Interface not found")
	}
	if strings.Contains(journalLower, "failed to initialize") {
		errors = append(errors, "Initialization failed")
	}
	if strings.Contains(journalLower, "could not set channel") {
		errors = append(errors, "Channel configuration error")
	}

	diagnostics["errors"] = errors
	diagnostics["has_errors"] = len(errors) > 0

	interfaceUp := false
	if ipOut, err := executeArgv("ip", "addr", "show", interfaceName); err == nil {
		interfaceUp = strings.Contains(strings.ToLower(ipOut), "state up")
	}
	diagnostics["interface_up"] = interfaceUp

	dnsmasqActive := systemctlIsActive("dnsmasq")
	diagnostics["dnsmasq_running"] = dnsmasqActive

	diagnostics["status"] = func() string {
		if !serviceRunning {
			return "service_stopped"
		}
		if !transmitting {
			return "service_running_not_transmitting"
		}
		return "ok"
	}()

	return c.JSON(diagnostics)
}

func HostapdGetConfigHandler(c *fiber.Ctx) error {
	configPath := "/etc/hostapd/hostapd.conf"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return c.JSON(fiber.Map{
			"success": false,
			"error":   "Configuration file not found",
			"config":  nil,
		})
	}

	configContent, err := os.ReadFile(configPath)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   fmt.Sprintf("Error reading config file: %v", err),
			"config":  nil,
		})
	}

	config := make(map[string]string)
	lines := strings.Split(string(configContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			config[key] = value
		}
	}

	interfaceForDisplay := config["interface"]
	if interfaceForDisplay == "ap0" {
		interfaceForDisplay = "wlan0"
	}

	result := fiber.Map{
		"success": true,
		"config": fiber.Map{
			"interface": interfaceForDisplay, // Mostrar interfaz física al usuario
			"ssid":      config["ssid"],
			"channel":   config["channel"],
			// No devolvemos el PSK / password: es un secreto en /etc/hostapd/hostapd.conf
			// y no debe exfiltrarse por la API (aunque el panel tenga auth).
		},
	}

	if config["auth_algs"] == "0" {
		result["config"].(fiber.Map)["security"] = "open"
	} else if strings.Contains(config["wpa_key_mgmt"], "SHA256") {
		result["config"].(fiber.Map)["security"] = "wpa3"
	} else if config["wpa"] == "2" {
		result["config"].(fiber.Map)["security"] = "wpa2"
	} else {
		result["config"].(fiber.Map)["security"] = "wpa2" // Por defecto
	}

	dnsmasqPath := "/etc/dnsmasq.conf"
	if dnsmasqContent, err := os.ReadFile(dnsmasqPath); err == nil {
		dnsmasqLines := strings.Split(string(dnsmasqContent), "\n")
		for _, line := range dnsmasqLines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "dhcp-option=3,") {
				gateway := strings.TrimPrefix(line, "dhcp-option=3,")
				result["config"].(fiber.Map)["gateway"] = gateway
			} else if strings.HasPrefix(line, "dhcp-range=") {
				rangeStr := strings.TrimPrefix(line, "dhcp-range=")
				parts := strings.Split(rangeStr, ",")
				if len(parts) >= 2 {
					result["config"].(fiber.Map)["dhcp_range_start"] = parts[0]
					result["config"].(fiber.Map)["dhcp_range_end"] = parts[1]
					if len(parts) >= 4 {
						result["config"].(fiber.Map)["lease_time"] = parts[3]
					}
				}
			}
		}
	}

	configMap := result["config"].(fiber.Map)
	if configMap["gateway"] == nil || configMap["gateway"] == "" {
		configMap["gateway"] = "192.168.4.1"
	}
	if configMap["dhcp_range_start"] == nil || configMap["dhcp_range_start"] == "" {
		configMap["dhcp_range_start"] = "192.168.4.2"
	}
	if configMap["dhcp_range_end"] == nil || configMap["dhcp_range_end"] == "" {
		configMap["dhcp_range_end"] = "192.168.4.254"
	}
	if configMap["lease_time"] == nil || configMap["lease_time"] == "" {
		configMap["lease_time"] = "12h"
	}
	if configMap["channel"] == nil || configMap["channel"] == "" {
		configMap["channel"] = "6"
	}

	countryCode := config["country_code"]
	if countryCode == "" {
		countryCode = config["country"] // Algunas configuraciones usan "country" en lugar de "country_code"
	}
	if countryCode == "" {
		countryCode = constants.DefaultCountryCode
	}
	configMap["country"] = countryCode

	return c.JSON(result)
}

func HostapdConfigHandler(c *fiber.Ctx) error {
	var req HostapdConfigBody

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   "Invalid request body",
			"success": false,
		})
	}

	if req.Interface == "" || req.SSID == "" {
		return c.Status(400).JSON(fiber.Map{
			"error":   "Missing required fields: interface, ssid",
			"success": false,
		})
	}

	if err := validateWiFiChannel(req.Channel); err != nil {
		return respondValidatorError(c, err)
	}

	if req.Gateway == "" {
		req.Gateway = "192.168.4.1"
	}
	if req.DHCPRangeStart == "" {
		req.DHCPRangeStart = "192.168.4.2"
	}
	if req.DHCPRangeEnd == "" {
		req.DHCPRangeEnd = "192.168.4.254"
	}
	if req.LeaseTime == "" {
		req.LeaseTime = "12h"
	}
	if req.Country == "" {
		req.Country = constants.DefaultCountryCode
	}

	req.Country = strings.ToUpper(strings.TrimSpace(req.Country))
	if len(req.Country) != 2 {
		req.Country = "US"
	}

	if req.Security != "wpa2" && req.Security != "wpa3" && req.Security != "open" {
		req.Security = "wpa2"
	}

	if err := validateHostapdPOST(&req); err != nil {
		return respondValidatorError(c, err)
	}

	apInterface := "ap0"
	phyInterface := req.Interface // wlan0 o la interfaz física

	log.Printf("Configuring AP+STA mode: creating virtual interface %s from %s", apInterface, phyInterface)

	_, _ = executeArgv("ip", "link", "set", phyInterface, "up")
	time.Sleep(500 * time.Millisecond)

	phyName := detectPhyName(phyInterface)

	if phyName == "" {
		if strings.HasPrefix(phyInterface, "wlan") {
			if numStr := strings.TrimPrefix(phyInterface, "wlan"); numStr != "" {
				phyName = "phy" + numStr
				log.Printf("Trying phy name based on interface number: %s", phyName)
			}
		}
	}

	if phyName == "" {
		phyName = "phy0"
		log.Printf("Warning: Could not detect phy name, using default: %s", phyName)
	}

	if err := validators.ValidatePhyName(phyName); err != nil {
		return respondValidatorError(c, err)
	}

	log.Printf("Detected phy name: %s for interface %s", phyName, phyInterface)

	macAddress := ""
	if b, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", phyInterface)); err == nil {
		macAddress = strings.TrimSpace(string(b))
	}
	if macAddress == "" {
		log.Printf("Warning: Could not get MAC address for %s", phyInterface)
		macAddress = "00:00:00:00:00:00" // Valor por defecto
	}

	log.Printf("Using phy: %s (MAC: %s) for virtual interface creation from %s", phyName, macAddress, phyInterface)

	if apInterface == "ap0" {
		log.Printf("Creating udev rule for automatic ap0 interface creation (TheWalrus method - Raspberry Pi 3 B+)")
		udevRulePath := "/etc/udev/rules.d/70-persistent-net.rules"

		hasAp0 := false
		// Si el archivo no existe o no contiene la regla, grep devuelve error => no existe.
		if err := exec.Command("grep", "-q", "ap0", udevRulePath).Run(); err == nil {
			hasAp0 = true
		}
		if !hasAp0 {
			udevRuleContent := fmt.Sprintf(`# Regla para crear interfaz virtual ap0 automáticamente (método TheWalrus - Raspberry Pi 3 B+)
SUBSYSTEM=="ieee80211", ACTION=="add|change", ATTR{macaddress}=="%s", KERNEL=="%s", \
RUN+="/sbin/iw phy %s interface add ap0 type __ap", \
RUN+="/bin/ip link set ap0 address %s"
`, macAddress, phyName, phyName, macAddress)

			udevTmpF, udevTmpErr := os.CreateTemp("", "hostberry-udev-*")
			if udevTmpErr == nil {
				tmpUdevFile := udevTmpF.Name()
				udevTmpF.Close()
				defer os.Remove(tmpUdevFile)
				if err := os.WriteFile(tmpUdevFile, []byte(udevRuleContent), 0644); err == nil {
					if _, err := os.Stat(udevRulePath); err == nil {
						existingContent, _ := os.ReadFile(udevRulePath)
						combinedContent := string(existingContent) + "\n" + udevRuleContent
						os.WriteFile(tmpUdevFile, []byte(combinedContent), 0644)
					}
					if _, err := executeArgv("cp", tmpUdevFile, udevRulePath); err == nil {
						_, _ = executeArgv("chmod", "644", udevRulePath)
					}
					os.Remove(tmpUdevFile)
					log.Printf("Created udev rule for automatic ap0 creation (TheWalrus method - Raspberry Pi 3 B+)")
					_, _ = executeArgv("udevadm", "control", "--reload-rules")
					_, _ = executeArgv("udevadm", "trigger")
				} else {
					log.Printf("Warning: Could not create udev rule: %v", err)
				}
			}
		} else {
			log.Printf("udev rule for ap0 already exists")
		}
	}

	apExists := false
	checkOut, checkErr := executeArgv("ip", "link", "show", apInterface)
	if checkErr == nil && strings.TrimSpace(checkOut) != "" {
		apExists = true
		log.Printf("Interface %s already exists, reusing it", apInterface)
		_, _ = executeArgv("ip", "link", "set", apInterface, "up")
	}

	if !apExists {
		log.Printf("Interface %s does not exist, creating it...", apInterface)

		delOut, delErr := executeArgv("iw", "dev", apInterface, "del")
		if delErr == nil {
			log.Printf("Removed existing %s interface (if it existed): %s", apInterface, strings.TrimSpace(delOut))
		}
		time.Sleep(1 * time.Second)

		log.Printf("Creating virtual interface %s using phy %s...", apInterface, phyName)

		phyCheckOut, phyExistsErr := executeArgv("iw", "phy", phyName, "info")
		if phyExistsErr != nil || strings.TrimSpace(phyCheckOut) == "" {
			log.Printf("Warning: phy %s may not exist, output: %s", phyName, strings.TrimSpace(phyCheckOut))
		} else {
			log.Printf("phy %s exists and is accessible", phyName)
		}

		if !strings.Contains(strings.ToLower(phyCheckOut), "ap") {
			log.Printf("Warning: phy %s may not support AP mode, but attempting anyway", phyName)
		} else {
			log.Printf("phy %s supports AP mode", phyName)
		}

		iwInfoOut, _ := executeArgv("iw", "dev", phyInterface, "info")
		if strings.Contains(iwInfoOut, "type AP") {
			log.Printf("Warning: Physical interface %s is in AP mode, changing to managed first", phyInterface)
			_, _ = executeArgv("iw", "dev", phyInterface, "set", "type", "managed")
			time.Sleep(1 * time.Second)
		}

		_, _ = executeArgv("ip", "link", "set", phyInterface, "up")
		time.Sleep(500 * time.Millisecond)

		log.Printf("Executing: iw phy %s interface add %s type __ap", phyName, apInterface)
		createOut, createErr := executeArgv("iw", "phy", phyName, "interface", "add", apInterface, "type", "__ap")
		if createOut != "" {
			log.Printf("Command output: %s", strings.TrimSpace(createOut))
		}

		if createErr != nil {
			log.Printf("Error creating virtual interface %s with phy %s: %s", apInterface, phyName, strings.TrimSpace(createOut))
			log.Printf("Error details: %v", createErr)
			log.Printf("Trying alternative method 1: using interface %s directly...", phyInterface)

			log.Printf("Executing: iw dev %s interface add %s type __ap", phyInterface, apInterface)
			createOut2, createErr2 := executeArgv("iw", "dev", phyInterface, "interface", "add", apInterface, "type", "__ap")
			if createOut2 != "" {
				log.Printf("Method 1 output: %s", strings.TrimSpace(createOut2))
			}

			if createErr2 != nil {
				log.Printf("Error with alternative method 1: %s", strings.TrimSpace(createOut2))
				log.Printf("Trying alternative method 2: using iw phy without sudo...")

				log.Printf("Executing: iw phy %s interface add %s type __ap", phyName, apInterface)
				createOut3, createErr3 := executeArgv("iw", "phy", phyName, "interface", "add", apInterface, "type", "__ap")
				if createOut3 != "" {
					log.Printf("Method 2 output: %s", strings.TrimSpace(createOut3))
				}

				if createErr3 != nil {
					log.Printf("Error with alternative method 2: %s", strings.TrimSpace(createOut3))
					log.Printf("Trying alternative method 3: using mac80211_hwsim if available...")

					altPhys := []string{}
					if phyListOut, _ := executeArgv("iw", "phy"); phyListOut != "" {
						for _, line := range strings.Split(phyListOut, "\n") {
							fields := strings.Fields(line)
							if len(fields) >= 2 && fields[0] == "Wiphy" {
								altPhys = append(altPhys, fields[1])
							}
						}
					}
					log.Printf("Available phys: %s", strings.Join(altPhys, ", "))
					altPhyName := ""
					for _, p := range altPhys {
						if p != phyName {
							altPhyName = p
							break
						}
					}
					if altPhyName != "" {
						log.Printf("Trying with alternative phy: %s", altPhyName)
						log.Printf("Executing: iw phy %s interface add %s type __ap", altPhyName, apInterface)
						createOut4, createErr4 := executeArgv("iw", "phy", altPhyName, "interface", "add", apInterface, "type", "__ap")
						if createOut4 != "" {
							log.Printf("Method 3 output: %s", strings.TrimSpace(createOut4))
						}
						if createErr4 == nil {
							log.Printf("Successfully created interface %s using alternative phy %s", apInterface, altPhyName)
							apExists = true
							phyName = altPhyName // Actualizar phyName para uso posterior
						} else {
							log.Printf("Error with alternative phy: %s", strings.TrimSpace(createOut4))
							apInterface = phyInterface
							log.Printf("Falling back to using physical interface %s directly (non-concurrent mode)", apInterface)
						}
					} else {
						apInterface = phyInterface
						log.Printf("Falling back to using physical interface %s directly (non-concurrent mode)", apInterface)
					}
				} else {
					log.Printf("Successfully created interface %s using method 2 (without sudo)", apInterface)
					apExists = true
				}
			} else {
				log.Printf("Successfully created interface %s using alternative method 1 (from %s)", apInterface, phyInterface)
				apExists = true
			}
		} else {
			log.Printf("Successfully created interface %s using phy %s", apInterface, phyName)
			apExists = true
		}

		if apExists && apInterface == "ap0" {
			time.Sleep(2 * time.Second)

			verified := false
			for i := 0; i < 5; i++ {
				if verifyOut, verifyErr := executeArgv("ip", "link", "show", apInterface); verifyErr == nil && strings.TrimSpace(verifyOut) != "" {
					log.Printf("Interface %s verified successfully with ip link (attempt %d)", apInterface, i+1)
					verified = true
					break
				}

				if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", apInterface)); err == nil {
					log.Printf("Interface %s verified successfully with sysfs (attempt %d)", apInterface, i+1)
					verified = true
					break
				}

				if iwDevOut, _ := executeArgv("iw", "dev"); strings.Contains(iwDevOut, "Interface "+apInterface) {
					log.Printf("Interface %s verified successfully with iw dev (attempt %d)", apInterface, i+1)
					verified = true
					break
				}

				if i < 4 {
					log.Printf("Verification attempt %d failed, retrying...", i+1)
					time.Sleep(1 * time.Second)
				}
			}

			if !verified {
				log.Printf("ERROR: Interface %s was NOT created successfully after all attempts", apInterface)
				log.Printf("Diagnostics:")
				log.Printf("  - phy name: %s", phyName)
				log.Printf("  - physical interface: %s", phyInterface)
				log.Printf("  - MAC address: %s", macAddress)

				log.Printf("Attempting manual creation as last resort...")
				manualOut, _ := executeArgv("iw", "phy", phyName, "interface", "add", apInterface, "type", "__ap")
				time.Sleep(1 * time.Second)
				if linkOut, _ := executeArgv("ip", "link", "show", apInterface); linkOut != "" {
					manualOut += "\n" + linkOut
				}
				log.Printf("Manual creation result: %s", strings.TrimSpace(manualOut))
			} else {
				log.Printf("SUCCESS: Interface %s created and verified", apInterface)
			}
		}
	}

	// `ip addr add` falla si la dirección ya existe; `replace` la actualiza.
	if out, err := executeArgv("ip", "addr", "add", req.Gateway+"/24", "dev", apInterface); err != nil {
		if out2, err2 := executeArgv("ip", "addr", "replace", req.Gateway+"/24", "dev", apInterface); err2 != nil {
			log.Printf("Warning: Error setting IP on interface %s: %s", apInterface, strings.TrimSpace(out+out2))
		}
	}

	if out, err := executeArgv("ip", "link", "set", apInterface, "up"); err != nil {
		log.Printf("Warning: Error bringing interface %s up: %s", apInterface, strings.TrimSpace(out))
	} else {
		log.Printf("Successfully created and activated virtual interface %s", apInterface)
		if checkOut, checkErr := executeArgv("ip", "link", "show", apInterface); checkErr == nil {
			log.Printf("Interface %s verified: %s", apInterface, strings.TrimSpace(checkOut))
		}
	}

	configPath := "/etc/hostapd/hostapd.conf"

	_, _ = executeArgv("mkdir", "-p", "/etc/hostapd")

	configContent := renderLegacyHostapdConfig(req, apInterface)

	tmpF, tmpErr := os.CreateTemp("", "hostberry-hostapd-*")
	if tmpErr != nil {
		log.Printf("Error creating temporary config file: %v", tmpErr)
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Error creating temporary config file: %v", tmpErr),
			"success": false,
		})
	}
	tmpFile := tmpF.Name()
	tmpF.Close()
	defer os.Remove(tmpFile)
	log.Printf("Creating temporary config file: %s", tmpFile)
	if err := os.WriteFile(tmpFile, []byte(configContent), 0644); err != nil {
		log.Printf("Error creating temporary config file: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Error creating temporary config file: %v", err),
			"success": false,
		})
	}

	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		log.Printf("Temporary file was not created: %s", tmpFile)
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to create temporary config file",
			"success": false,
		})
	}

	log.Printf("Temporary file created successfully, size: %d bytes", len(configContent))

	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		log.Printf("Temporary file does not exist before copy: %s", tmpFile)
		return c.Status(500).JSON(fiber.Map{
			"error":   "Temporary file was not created or was deleted",
			"success": false,
		})
	}

	if fileInfo, err := os.Stat(tmpFile); err == nil {
		log.Printf("Temporary file exists, size: %d bytes, mode: %v", fileInfo.Size(), fileInfo.Mode())
	} else {
		log.Printf("Cannot stat temporary file: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Cannot access temporary file: %v", err),
			"success": false,
		})
	}

	log.Printf("Ensuring /etc/hostapd directory exists...")
	if out, err := executeArgv("mkdir", "-p", "/etc/hostapd"); err != nil {
		log.Printf("Warning: Error creating /etc/hostapd directory: %v, output: %s", err, out)
	}
	if out, err := executeArgv("chmod", "755", "/etc/hostapd"); err != nil {
		log.Printf("Warning: Error setting permissions on /etc/hostapd: %v, output: %s", err, out)
	}

	if _, err := os.Stat("/etc/hostapd"); os.IsNotExist(err) {
		log.Printf("Error: /etc/hostapd directory does not exist after creation attempt")
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to create /etc/hostapd directory. Please run: sudo mkdir -p /etc/hostapd && sudo chmod 755 /etc/hostapd",
			"success": false,
		})
	}

	os.Chmod(tmpFile, 0644)

	log.Printf("Executing: cp %s %s", tmpFile, configPath)
	out, err := executeArgv("cp", tmpFile, configPath)
	if err != nil {
		log.Printf("Error copying config file: %v, output: '%s'", err, out)
		os.Remove(tmpFile) // Limpiar archivo temporal
		errorMsg := strings.TrimSpace(out)
		if errorMsg == "" {
			errorMsg = err.Error()
		}
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Error saving hostapd configuration: %s. Please check sudo permissions for cp command.", errorMsg),
			"success": false,
		})
	}
	log.Printf("File copied successfully, output: '%s'", strings.TrimSpace(out))

	log.Printf("Setting permissions on %s", configPath)
	if out, err := executeArgv("chmod", "644", configPath); err != nil {
		log.Printf("Warning: Error setting permissions: %v, output: %s", err, strings.TrimSpace(out))
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		os.Remove(tmpFile)
		log.Printf("Config file was not created at: %s", configPath)
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Config file was not created at %s", configPath),
			"success": false,
		})
	}

	log.Printf("HostAPD config file created successfully at: %s", configPath)

	os.Remove(tmpFile)

	dnsmasqConfigPath := "/etc/dnsmasq.conf"
	_, _ = executeArgv("cp", dnsmasqConfigPath, dnsmasqConfigPath+".backup")

	dhcpStart := req.DHCPRangeStart
	dhcpEnd := req.DHCPRangeEnd

	dnsmasqManaged := fmt.Sprintf(`except-interface=lo
bind-interfaces
interface=%s
no-dhcp-interface=%s
server=8.8.8.8
server=8.8.4.4
domain-needed
bogus-priv
address=/#/%s
dhcp-range=%s,%s,255.255.255.0,%s
dhcp-option=3,%s
dhcp-option=6,%s
dhcp-option=114,http://%s/api/captive-portal
`, apInterface, phyInterface, req.Gateway, dhcpStart, dhcpEnd, req.LeaseTime, req.Gateway, req.Gateway, req.Gateway)

	// Preservar la configuración dnsmasq del usuario: solo se sustituye el
	// bloque gestionado por HostBerry, no se sobrescribe el archivo entero.
	existingDnsmasq, _ := os.ReadFile(dnsmasqConfigPath)
	dnsmasqContent := mergeManagedConfigBlock(string(existingDnsmasq), dnsmasqManagedBeginMarker, dnsmasqManagedEndMarker, dnsmasqManaged)

	tmpDnsmasqF, tmpDnsmasqErr := os.CreateTemp("", "hostberry-dnsmasq-*")
	if tmpDnsmasqErr != nil {
		log.Printf("Error creating temporary dnsmasq config file: %v", tmpDnsmasqErr)
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Error creating temporary dnsmasq config file: %v", tmpDnsmasqErr),
			"success": false,
		})
	}
	tmpDnsmasqFile := tmpDnsmasqF.Name()
	tmpDnsmasqF.Close()
	defer os.Remove(tmpDnsmasqFile)

	if err := os.WriteFile(tmpDnsmasqFile, []byte(dnsmasqContent), 0644); err != nil {
		log.Printf("Error writing temporary dnsmasq config file: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Error creating temporary dnsmasq config file: %v", err),
			"success": false,
		})
	}

	os.Chmod(tmpDnsmasqFile, 0644)
	if _, err := executeArgv("cp", tmpDnsmasqFile, dnsmasqConfigPath); err != nil {
		os.Remove(tmpDnsmasqFile) // Limpiar archivo temporal
		log.Printf("Error writing dnsmasq config file: %s", err)
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Error saving dnsmasq configuration: %s", err),
			"success": false,
		})
	}
	_, _ = executeArgv("chmod", "644", dnsmasqConfigPath)

	os.Remove(tmpDnsmasqFile)

	// `sysctl -w` ya escribe /proc/sys/net/ipv4/ip_forward; el `echo|tee` era redundante.
	_, _ = executeArgv("sysctl", "-w", "net.ipv4.ip_forward=1")

	// Persistir en /etc/sysctl.conf si aún no está (stdin directo, sin shell).
	if content, err := os.ReadFile("/etc/sysctl.conf"); err == nil &&
		!strings.Contains(string(content), "net.ipv4.ip_forward=1") {
		if teeCmd, err := utils.NewArgvCommand("tee", "-a", "/etc/sysctl.conf"); err == nil {
			teeCmd.Stdin = strings.NewReader("net.ipv4.ip_forward=1\n")
			teeCmd.Stdout = io.Discard
			teeCmd.Stderr = io.Discard
			_ = teeCmd.Run()
		}
	}

	mainInterface := "eth0"
	if routeOut, _ := executeArgv("ip", "route"); routeOut != "" {
		for _, line := range strings.Split(routeOut, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "default" {
				continue
			}
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] == "dev" {
					mainInterface = fields[i+1]
					break
				}
			}
			if mainInterface != "" {
				break
			}
		}
	}

	apIPBegin := req.Gateway
	if lastDot := strings.LastIndex(req.Gateway, "."); lastDot > 0 {
		apIPBegin = req.Gateway[:lastDot]
	}

	if mainInterface != "" && mainInterface != apInterface {
		// Borrar reglas existentes (los errores se ignoran, como el `|| true` original).
		_, _ = executeArgv("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", apIPBegin+".0/24", "!", "-d", apIPBegin+".0/24", "-j", "MASQUERADE")
		_, _ = executeArgv("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", mainInterface, "-j", "MASQUERADE")
		_, _ = executeArgv("iptables", "-D", "FORWARD", "-i", apInterface, "-o", mainInterface, "-j", "ACCEPT")
		_, _ = executeArgv("iptables", "-D", "FORWARD", "-i", mainInterface, "-o", apInterface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

		_, _ = executeArgv("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", apIPBegin+".0/24", "!", "-d", apIPBegin+".0/24", "-j", "MASQUERADE")
		_, _ = executeArgv("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", mainInterface, "-j", "MASQUERADE")
		_, _ = executeArgv("iptables", "-A", "FORWARD", "-i", apInterface, "-o", mainInterface, "-j", "ACCEPT")
		_, _ = executeArgv("iptables", "-A", "FORWARD", "-i", mainInterface, "-o", apInterface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}

	overrideDir := "/etc/systemd/system/hostapd.service.d"
	_, _ = executeArgv("mkdir", "-p", overrideDir)
	overrideContent := fmt.Sprintf(`[Service]
ExecStart=
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd.pid %s
PIDFile=/run/hostapd.pid
Type=forking
`, configPath)
	overrideTmpF, overrideTmpErr := os.CreateTemp("", "hostberry-override-*")
	if overrideTmpErr != nil {
		log.Printf("Warning: Error creating temporary override file: %v", overrideTmpErr)
	} else {
		tmpOverrideFile := overrideTmpF.Name()
		overrideTmpF.Close()
		defer os.Remove(tmpOverrideFile)
		if err := os.WriteFile(tmpOverrideFile, []byte(overrideContent), 0644); err != nil {
			log.Printf("Warning: Error writing temporary override file: %v", err)
		} else {
			overridePath := fmt.Sprintf("%s/override.conf", overrideDir)
			os.Chmod(tmpOverrideFile, 0644)
			if _, err := executeArgv("cp", tmpOverrideFile, overridePath); err != nil {
				log.Printf("Warning: Error writing override file: %s", err)
			} else {
				_, _ = executeArgv("chmod", "644", overridePath)
				log.Printf("Override file created successfully")
			}
			os.Remove(tmpOverrideFile)
		}
	}

	manageAp0Script := `#!/bin/bash
# check if hostapd service success to start or not
# in our case, it cannot start when /var/run/hostapd/ap0 exist
# so we have to delete it
echo 'Check if hostapd.service is hang cause ap0 exist...'
hostapd_is_running=$(systemctl is-active hostapd 2>/dev/null | grep -c "active")
if test 1 -ne "${hostapd_is_running}"; then
    rm -rf /var/run/hostapd/ap0 || echo "ap0 interface does not exist, the failure is elsewhere"
    # También limpiar el PID file si existe
    rm -f /run/hostapd.pid || true
fi
# Asegurar que ap0 existe antes de iniciar hostapd
if ! ip link show ap0 > /dev/null 2>&1; then
    # Intentar crear ap0 si no existe
    phy=$(iw dev wlan0 info 2>/dev/null | grep wiphy | awk '{print $2}')
    if [ -n "$phy" ]; then
        iw phy $phy interface add ap0 type __ap 2>/dev/null || true
        sleep 1
    fi
fi
`
	manageAp0Path := "/bin/manage-ap0-iface.sh"
	manageTmpF, manageTmpErr := os.CreateTemp("", "hostberry-manageap0-*")
	if manageTmpErr == nil {
		tmpManageAp0 := manageTmpF.Name()
		manageTmpF.Close()
		defer os.Remove(tmpManageAp0)
		if err := os.WriteFile(tmpManageAp0, []byte(manageAp0Script), 0755); err == nil {
			if _, err := executeArgv("cp", tmpManageAp0, manageAp0Path); err == nil {
				_, _ = executeArgv("chmod", "+x", manageAp0Path)
			}
			os.Remove(tmpManageAp0)
			log.Printf("Created manage-ap0-iface.sh script")
		}
	}

	overridePath := fmt.Sprintf("%s/override.conf", overrideDir)
	overrideContentWithPreStart := fmt.Sprintf(`[Service]
ExecStart=
ExecStartPre=/bin/manage-ap0-iface.sh
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd.pid %s
PIDFile=/run/hostapd.pid
Type=forking
TimeoutStartSec=30
TimeoutStopSec=10
`, configPath)
	override2TmpF, override2TmpErr := os.CreateTemp("", "hostberry-override-*")
	if override2TmpErr == nil {
		tmpOverrideFile2 := override2TmpF.Name()
		override2TmpF.Close()
		defer os.Remove(tmpOverrideFile2)
		if err := os.WriteFile(tmpOverrideFile2, []byte(overrideContentWithPreStart), 0644); err == nil {
			if _, err := executeArgv("cp", tmpOverrideFile2, overridePath); err != nil {
				log.Printf("Warning: Error updating override file with pre-start: %s", err)
			} else {
				_, _ = executeArgv("chmod", "644", overridePath)
				log.Printf("Override file updated with pre-start script and PID file configuration")
			}
			os.Remove(tmpOverrideFile2)
		}
	}

	_, _ = executeArgv("systemctl", "daemon-reload")

	apIPBeginForScript := req.Gateway
	if lastDot := strings.LastIndex(req.Gateway, "."); lastDot > 0 {
		apIPBeginForScript = req.Gateway[:lastDot]
	}
	rpiWifiScript := fmt.Sprintf(`#!/bin/bash
echo 'Starting Wifi AP and STA client...'
/usr/sbin/ifdown --force %s 2>/dev/null || true
/usr/sbin/ifdown --force %s 2>/dev/null || true
/usr/sbin/ifup --force %s 2>/dev/null || true
/usr/sbin/ifup --force %s 2>/dev/null || true
/usr/sbin/sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
/usr/sbin/iptables -t nat -A POSTROUTING -s %s.0/24 ! -d %s.0/24 -j MASQUERADE 2>/dev/null || true
/usr/bin/systemctl restart dnsmasq 2>/dev/null || true
echo 'WPA Supplicant reconfigure in 5sec...'
/usr/bin/sleep 5
wpa_cli -i %s reconfigure 2>/dev/null || true
`, phyInterface, apInterface, apInterface, phyInterface, apIPBeginForScript, apIPBeginForScript, phyInterface)
	rpiWifiPath := "/bin/rpi-wifi.sh"
	rpiTmpF, rpiTmpErr := os.CreateTemp("", "hostberry-rpiwifi-*")
	if rpiTmpErr == nil {
		tmpRpiWifi := rpiTmpF.Name()
		rpiTmpF.Close()
		defer os.Remove(tmpRpiWifi)
		if err := os.WriteFile(tmpRpiWifi, []byte(rpiWifiScript), 0755); err == nil {
			if _, err := executeArgv("cp", tmpRpiWifi, rpiWifiPath); err == nil {
				_, _ = executeArgv("chmod", "+x", rpiWifiPath)
			}
			os.Remove(tmpRpiWifi)
			log.Printf("Created rpi-wifi.sh script")
		}
	}

	_, _ = executeArgv("systemctl", "enable", "hostapd")
	_, _ = executeArgv("systemctl", "enable", "dnsmasq")

	if out, err := executeArgv("systemctl", "restart", "dnsmasq"); err != nil {
		log.Printf("Warning: Error restarting dnsmasq: %s", strings.TrimSpace(out))
	}

	if apInterface == "ap0" {
		ap0CheckOut, ap0CheckErr := executeArgv("ip", "link", "show", "ap0")
		if ap0CheckErr != nil || strings.TrimSpace(ap0CheckOut) == "" {
			log.Printf("Warning: ap0 interface does not exist, attempting to create it before starting hostapd")
			createAp0Out, _ := executeArgv("iw", "phy", phyName, "interface", "add", "ap0", "type", "__ap")
			if createAp0Out != "" {
				log.Printf("ap0 creation attempt: %s", strings.TrimSpace(createAp0Out))
			}
			time.Sleep(1 * time.Second)
			ap0CheckOut2, _ := executeArgv("ip", "link", "show", "ap0")
			if strings.TrimSpace(ap0CheckOut2) == "" {
				log.Printf("ERROR: ap0 interface still does not exist after creation attempt")
				return c.Status(500).JSON(fiber.Map{
					"error":   "Failed to create ap0 interface. Please check WiFi hardware and drivers.",
					"success": false,
				})
			}
		}
	}

	_, _ = executeArgv("rm", "-rf", "/var/run/hostapd/ap0")
	_, _ = executeArgv("rm", "-f", "/run/hostapd.pid")

	if out, err := executeArgv("systemctl", "restart", "hostapd"); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   fmt.Sprintf("Configuration saved but failed to restart hostapd: %s", strings.TrimSpace(out)),
			"success": false,
		})
	}

	time.Sleep(2 * time.Second)
	hostapdStatusOut, _ := executeArgv("systemctl", "is-active", "hostapd")
	if strings.TrimSpace(hostapdStatusOut) != "active" {
		log.Printf("Warning: hostapd service may not be active after restart. Status: %s", strings.TrimSpace(hostapdStatusOut))
		pgrepOut, _ := executeArgv("pgrep", "hostapd")
		if strings.TrimSpace(pgrepOut) != "" {
			log.Printf("hostapd process check: running (pid %s)", strings.Fields(pgrepOut)[0])
		} else {
			log.Printf("hostapd process check: not running")
		}
	}

	// Asegurar que ap0 tenga la IP del gateway y reiniciar dnsmasq para que los clientes reciban IP por DHCP
	_, _ = executeArgv("ip", "addr", "replace", "192.168.4.1/24", "dev", "ap0")
	if out, err := executeArgv("systemctl", "restart", "dnsmasq"); err != nil {
		log.Printf("Warning: dnsmasq restart after hostapd config: %s", strings.TrimSpace(out))
	}

	if err := EnsureSingleClientLimitIfPending(); err != nil {
		log.Printf("Warning: could not enforce single-client AP limit: %v", err)
	}

	// Sincronizar el perfil dual-band persistido: si no, una llamada posterior a
	// EnsureDualBandHostapd (cambio de banda, wizard, arranque) regeneraría
	// hostapd.conf desde ap-dual-band.json y revertiría esta configuración.
	syncDualBandProfileFromLegacyConfig(req)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Configuration saved and services restarted",
	})
}

// syncDualBandProfileFromLegacyConfig refleja la configuración single-band del
// endpoint /hostapd/config en los perfiles dual-band (ap-dual-band.json) para
// que ambos caminos de escritura de hostapd.conf no diverjan.
func syncDualBandProfileFromLegacyConfig(req HostapdConfigBody) {
	country := strings.ToUpper(strings.TrimSpace(req.Country))
	cfg := wifi.LoadDualBandAPConfig(country)
	for _, p := range []*wifi.DualBandAPProfile{&cfg.Band24, &cfg.Band5} {
		p.SSID = req.SSID
		p.Security = req.Security
		p.Password = req.Password
		p.Country = country
	}
	if req.Channel > 14 {
		cfg.Band5.Channel = req.Channel
	} else {
		cfg.Band24.Channel = req.Channel
	}
	if err := wifi.SaveDualBandAPConfig(cfg); err != nil {
		log.Printf("Warning: could not sync dual-band AP profile: %v", err)
	}
}
