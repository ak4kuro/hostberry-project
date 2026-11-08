package wifi

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/utils"
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

	// `nmcli -t ... | grep -i wifi` → argv + filtro en Go.
	activeConnOut, err := utils.ExecuteArgv("nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active")

	var connectionName string
	if err == nil && activeConnOut != "" {
		for _, line := range strings.Split(activeConnOut, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(strings.ToLower(line), "wireless") {
				continue
			}
			// nmcli -t escapa ':' y '\' dentro de los campos; buscar el primer
			// separador no escapado para no truncar nombres con ':' dentro.
			if name, _ := splitNMCLIField(line); name != "" {
				connectionName = unescapeNMCLIField(name)
				break
			}
		}
	}

	if connectionName != "" {
		disconnectOut, disconnectErr := utils.ExecuteArgv("nmcli", "connection", "down", connectionName)

		if disconnectErr == nil {
			if userID != nil {
				database.InsertLog("INFO", database.LogMsg("Desconexión WiFi de "+connectionName, username), "wifi", userID)
			}
			return c.JSON(fiber.Map{"success": true, "message": "Disconnected from " + connectionName})
		}

		log.Printf("Error desconectando conexión %s: %s, intentando desconectar dispositivo", connectionName, strings.TrimSpace(disconnectOut))
	}

	// `nmcli -t -f DEVICE,TYPE device status | grep -i wifi | head -1 | cut -d: -f1` → argv + parseo.
	wifiDeviceOut, err := utils.ExecuteArgv("nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status")

	if err == nil && wifiDeviceOut != "" {
		for _, line := range strings.Split(wifiDeviceOut, "\n") {
			line = strings.TrimSpace(line)
			fields := strings.SplitN(line, ":", 2)
			if len(fields) < 2 || !strings.Contains(strings.ToLower(fields[1]), "wifi") {
				continue
			}
			deviceName := strings.TrimSpace(fields[0])
			if deviceName == "" || validateInterfaceName(deviceName) != nil {
				break
			}
			deviceDisconnectOut, deviceDisconnectErr := utils.ExecuteArgv("nmcli", "device", "disconnect", deviceName)

			if deviceDisconnectErr == nil {
				if userID != nil {
					database.InsertLog("INFO", database.LogMsg("Dispositivo WiFi desconectado: "+deviceName, username), "wifi", userID)
				}
				return c.JSON(fiber.Map{"success": true, "message": "Disconnected from WiFi device " + deviceName})
			}

			log.Printf("Error desconectando dispositivo %s: %s", deviceName, strings.TrimSpace(deviceDisconnectOut))
			break
		}
	}

	networkingOffOut, networkingOffErr := utils.ExecuteArgv("nmcli", "networking", "off")

	if networkingOffErr != nil {
		errorMsg := fmt.Sprintf("Error desconectando WiFi: %s", strings.TrimSpace(networkingOffOut))
		if userID != nil {
			database.InsertLog("ERROR", database.LogMsgErr("desconectar WiFi", errorMsg, username), "wifi", userID)
		}
		return c.Status(500).JSON(fiber.Map{"success": false, "error": errorMsg})
	}

	time.Sleep(1 * time.Second)

	networkingOnOut, networkingOnErr := utils.ExecuteArgv("nmcli", "networking", "on")

	if networkingOnErr != nil {
		errorMsg := fmt.Sprintf("Error reactivando networking: %s", strings.TrimSpace(networkingOnOut))
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
