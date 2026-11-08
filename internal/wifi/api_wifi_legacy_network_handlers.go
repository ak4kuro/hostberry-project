package wifi

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/constants"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/models"
)

func WifiLegacyStoredNetworksHandler(c *fiber.Ctx) error {
	var networks []fiber.Map
	var lastConnected []string

	interfaceName := DetectWiFiInterface()
	if err := validateInterfaceName(interfaceName); err != nil {
		interfaceName = constants.DefaultWiFiInterface
	}

	listOut, err := exec.Command("sudo", "wpa_cli", "-i", interfaceName, "list_networks").CombinedOutput()
	if err != nil {
		// Fallback por si se ejecuta como root o sin sudo.
		listOut, err = exec.Command("wpa_cli", "-i", interfaceName, "list_networks").CombinedOutput()
	}

	if err == nil && len(listOut) > 0 {
		lines := strings.Split(string(listOut), "\n")
		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue // Saltar encabezado y líneas vacías
			}

			fields := strings.Fields(line)
			if len(fields) >= 2 {
				networkID := fields[0]
				ssid := fields[1]

				if ssid != "" && ssid != "--" {
					ssid = strings.Trim(ssid, "\"")

					network := fiber.Map{
						"id":     networkID,
						"ssid":   ssid,
						"status": "saved",
					}

					// networkID esperado numérico (wpa_cli ids).
					if _, convErr := strconv.Atoi(networkID); convErr == nil {
						enabledOut, _ := exec.Command("sudo", "wpa_cli", "-i", interfaceName, "get_network", networkID, "disabled").CombinedOutput()
						if len(enabledOut) == 0 {
							enabledOut, _ = exec.Command("wpa_cli", "-i", interfaceName, "get_network", networkID, "disabled").CombinedOutput()
						}
						if strings.TrimSpace(string(enabledOut)) == "0" {
							network["enabled"] = true
							lastConnected = append(lastConnected, ssid)
						} else {
							network["enabled"] = false
						}
					}

					networks = append(networks, network)
				}
			}
		}
	}

	return c.JSON(fiber.Map{
		"success":        true,
		"networks":       networks,
		"last_connected": lastConnected,
	})
}

func WifiLegacyAutoconnectHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"success": false})
}

func WifiLegacyScanHandler(c *fiber.Ctx) error {
	userInterface := c.Locals("user")
	if userInterface == nil {
		log.Printf("ERROR: Usuario no encontrado en wifiLegacyScanHandler")
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "No autenticado. Por favor, inicia sesión nuevamente.",
		})
	}

	user, ok := userInterface.(*models.User)
	if !ok || user == nil {
		log.Printf("ERROR: Usuario inválido en wifiLegacyScanHandler")
		return c.Status(401).JSON(fiber.Map{
			"success": false,
			"error":   "Usuario no encontrado. Por favor, inicia sesión nuevamente.",
		})
	}

	interfaceName := c.Query("interface", constants.DefaultWiFiInterface)
	if err := validateInterfaceName(interfaceName); err != nil {
		return c.Status(400).JSON(fiber.Map{"success": false, "error": "Nombre de interfaz inválido"})
	}
	result := ScanWiFiNetworks(interfaceName, true)
	if networks, ok := result["networks"]; ok {
		return c.JSON(fiber.Map{"success": true, "networks": networks})
	}
	return c.JSON(fiber.Map{"success": true, "networks": []fiber.Map{}})
}

func WifiLegacyDisconnectHandler(c *fiber.Ctx) error {
	// Para el setup wizard puede que no haya sesión/token.
	// Permitir desconectar sin auth: la lógica seguirá funcionando y omitimos logs.
	username := "setup_wizard"
	var userID *int
	if u, ok := middleware.GetUser(c); ok && u != nil {
		username = u.Username
		id := u.ID
		userID = &id
	}

	activeConnCmd := execCommand("nmcli -t -f NAME,TYPE,DEVICE connection show --active | grep -i wifi")
	activeConnOut, err := activeConnCmd.Output()

	var connectionName string
	if err == nil && len(activeConnOut) > 0 {
		lines := strings.Split(strings.TrimSpace(string(activeConnOut)), "\n")
		if len(lines) > 0 {
			// nmcli -t escapa ':' y '\' dentro de los campos; buscar el primer
			// separador no escapado para no truncar nombres con ':' dentro.
			if name, _ := splitNMCLIField(lines[0]); name != "" {
				connectionName = unescapeNMCLIField(name)
			}
		}
	}

	if connectionName != "" {
		disconnectCmd := execCommand(fmt.Sprintf("nmcli connection down %s", shellQuote(connectionName)))
		disconnectOut, disconnectErr := disconnectCmd.CombinedOutput()

		if disconnectErr == nil {
			if userID != nil {
				database.InsertLog("INFO", database.LogMsg("Desconexión WiFi de "+connectionName, username), "wifi", userID)
			}
			return c.JSON(fiber.Map{"success": true, "message": "Disconnected from " + connectionName})
		}

		log.Printf("Error desconectando conexión %s: %s, intentando desconectar dispositivo", connectionName, string(disconnectOut))
	}

	wifiDeviceCmd := execCommand("nmcli -t -f DEVICE,TYPE device status | grep -i wifi | head -1 | cut -d: -f1")
	wifiDeviceOut, err := wifiDeviceCmd.Output()

	if err == nil && len(wifiDeviceOut) > 0 {
		deviceName := strings.TrimSpace(string(wifiDeviceOut))
		if deviceName != "" && validateInterfaceName(deviceName) == nil {
			deviceDisconnectCmd := execCommand(fmt.Sprintf("nmcli device disconnect %s", shellQuote(deviceName)))
			deviceDisconnectOut, deviceDisconnectErr := deviceDisconnectCmd.CombinedOutput()

			if deviceDisconnectErr == nil {
				if userID != nil {
					database.InsertLog("INFO", database.LogMsg("Dispositivo WiFi desconectado: "+deviceName, username), "wifi", userID)
				}
				return c.JSON(fiber.Map{"success": true, "message": "Disconnected from WiFi device " + deviceName})
			}

			log.Printf("Error desconectando dispositivo %s: %s", deviceName, string(deviceDisconnectOut))
		}
	}

	networkingOffCmd := execCommand("nmcli networking off")
	networkingOffOut, networkingOffErr := networkingOffCmd.CombinedOutput()

	if networkingOffErr != nil {
		errorMsg := fmt.Sprintf("Error desconectando WiFi: %s", strings.TrimSpace(string(networkingOffOut)))
		if userID != nil {
			database.InsertLog("ERROR", database.LogMsgErr("desconectar WiFi", errorMsg, username), "wifi", userID)
		}
		return c.Status(500).JSON(fiber.Map{"success": false, "error": errorMsg})
	}

	time.Sleep(1 * time.Second)

	networkingOnCmd := execCommand("nmcli networking on")
	networkingOnOut, networkingOnErr := networkingOnCmd.CombinedOutput()

	if networkingOnErr != nil {
		errorMsg := fmt.Sprintf("Error reactivando networking: %s", strings.TrimSpace(string(networkingOnOut)))
		if userID != nil {
			database.InsertLog("ERROR", database.LogMsgErr("reactivar red tras desconexión WiFi", errorMsg, username), "wifi", userID)
		}
		return c.Status(500).JSON(fiber.Map{"success": false, "error": errorMsg})
	}

	if userID != nil {
		database.InsertLog("INFO", database.LogMsg("Desconexión WiFi (método alternativo)", username), "wifi", userID)
	}
	return c.JSON(fiber.Map{"success": true, "message": "Disconnected from WiFi"})
}
