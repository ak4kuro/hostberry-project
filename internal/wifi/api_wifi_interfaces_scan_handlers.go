package wifi

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/constants"
)

func listWiFiInterfacesFromSys() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}

	var ifaces []string
	for _, e := range entries {
		if !e.IsDir() && e.Type().IsRegular() {
			// /sys/class/net/<iface> es un directorio, pero dejamos este guard por robustez.
			continue
		}

		name := e.Name()
		if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wl") {
			if validateInterfaceName(name) == nil {
				ifaces = append(ifaces, name)
			}
		}
	}

	sort.Strings(ifaces)
	return ifaces
}

func detectWiFiInterface() string {
	if sta := staInterfaceFromDnsmasq(); sta != "" {
		return sta
	}
	for _, name := range listWiFiInterfacesFromSys() {
		if isApInterfaceName(name) {
			continue
		}
		if wifiInterfaceType(name) == "AP" {
			continue
		}
		return name
	}
	return constants.DefaultWiFiInterface
}

func isApInterfaceName(name string) bool {
	name = strings.TrimSpace(name)
	return name == "ap0" || strings.HasPrefix(name, "ap")
}

func staInterfaceFromDnsmasq() string {
	paths := []string{
		"/etc/dnsmasq.d/hostberry-ap.conf",
		"/etc/dnsmasq.conf",
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "no-dhcp-interface=") {
				continue
			}
			iface := strings.TrimSpace(strings.TrimPrefix(line, "no-dhcp-interface="))
			if validateInterfaceName(iface) == nil {
				return iface
			}
		}
	}
	return ""
}

func wifiInterfaceType(iface string) string {
	if err := validateInterfaceName(iface); err != nil {
		return ""
	}
	out, err := execPrivilegedArgv("iw", "dev", iface, "info")
	if err != nil {
		return ""
	}
	text := strings.ToLower(out)
	switch {
	case strings.Contains(text, "type ap"):
		return "AP"
	case strings.Contains(text, "type managed"):
		return "managed"
	default:
		return ""
	}
}

// DetectWiFiInterface wrapper exportado para usarlo desde main (setup/auto-conexión).
func DetectWiFiInterface() string {
	return detectWiFiInterface()
}

// WifiInterfacesHandler devuelve una lista simple de interfaces WiFi y su estado.
func WifiInterfacesHandler(c *fiber.Ctx) error {
	var interfaces []fiber.Map
	for _, ifaceName := range listWiFiInterfacesFromSys() {
		operstatePath := filepath.Join("/sys/class/net", ifaceName, "operstate")
		b, err := os.ReadFile(operstatePath)
		state := "unknown"
		if err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				state = s
			}
		}

		interfaces = append(interfaces, fiber.Map{
			"name":  ifaceName,
			"type":  "wifi",
			"state": state,
		})
	}

	if len(interfaces) == 0 {
		interfaces = append(interfaces, fiber.Map{
			"name":  constants.DefaultWiFiInterface,
			"type":  "wifi",
			"state": "unknown",
		})
	}

	return c.JSON(fiber.Map{
		"success":    true,
		"interfaces": interfaces,
	})
}

// WifiScanHandler escanea redes WiFi (útil también para el setup wizard).
func WifiScanHandler(c *fiber.Ctx) error {
	// Para el setup wizard puede que no exista sesión/token.
	// Escanear redes no requiere usuario; solo la interfaz a usar.
	interfaceName := c.Query("interface", "")
	if interfaceName == "" {
		var req struct {
			Interface string `json:"interface"`
		}
		if err := c.BodyParser(&req); err == nil {
			interfaceName = req.Interface
		}
	}

	if interfaceName == "" {
		interfaceName = detectWiFiInterface()
	}
	if interfaceName == "" {
		interfaceName = constants.DefaultWiFiInterface
	}

	if err := validateInterfaceName(interfaceName); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Nombre de interfaz inválido"})
	}

	refresh := c.Query("refresh") == "1" || c.Query("refresh") == "true"
	// Banda opcional ("2.4"/"5"): el asistente la pasa para escanear la banda elegida en la radio única.
	band := c.Query("band")
	result := ScanWiFiNetworksBand(interfaceName, refresh, band)
	if success, ok := result["success"].(bool); ok && !success {
		if errMsg, ok := result["error"].(string); ok && errMsg != "" {
			if strings.Contains(errMsg, "No se encontraron redes") {
				return c.JSON([]map[string]interface{}{})
			}
			return c.Status(500).JSON(fiber.Map{"success": false, "error": errMsg})
		}
		return c.Status(500).JSON(fiber.Map{"success": false, "error": "Error escaneando redes"})
	}

	networks, _ := result["networks"].([]map[string]interface{})
	if networks == nil {
		networks = []map[string]interface{}{}
	}
	return c.JSON(networks)
}
