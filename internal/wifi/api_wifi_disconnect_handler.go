package wifi

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
)

func WifiDisconnectHandler(c *fiber.Ctx) error {
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
