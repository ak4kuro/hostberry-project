package wifi

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/constants"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/utils"
)

func WifiToggleHandler(c *fiber.Ctx) error {
	user, ok := middleware.GetUser(c)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "No autorizado"})
	}
	userID := user.ID

	interfaceName := c.Query("interface", constants.DefaultWiFiInterface)
	if err := validateInterfaceName(interfaceName); err != nil {
		return c.Status(400).JSON(fiber.Map{"success": false, "error": "Nombre de interfaz inválido"})
	}

	rfkillOut, rfkillErr := execPrivilegedArgvTimeout([]string{"rfkill", "list", "wifi"}, 8*time.Second)
	if rfkillErr != nil {
		// Fallback por si no hay sudo o si el proceso corre como root.
		if fb, _ := exec.Command("rfkill", "list", "wifi").CombinedOutput(); len(fb) > 0 {
			rfkillOut = string(fb)
		}
	}
	softBlocked := strings.Contains(strings.ToLower(rfkillOut), "soft blocked: yes")
	isBlocked := softBlocked

	result := ToggleWiFi(interfaceName, isBlocked)

	if success, ok := result["success"].(bool); ok && success {
		database.InsertLog("INFO", database.LogMsg("WiFi activado o desactivado correctamente", user.Username), "wifi", &userID)
		return c.JSON(result)
	}

	if errorMsg, ok := result["error"].(string); ok && errorMsg != "" {
		database.InsertLog("ERROR", database.LogMsgErr("cambiar estado WiFi", errorMsg, user.Username), "wifi", &userID)
		return c.Status(500).JSON(fiber.Map{"success": false, "error": errorMsg})
	}

	rfkillListOut, rfkillListErr := utils.ExecuteArgv("rfkill", "list", "wifi")
	if rfkillListErr == nil && strings.Contains(strings.ToLower(rfkillListOut), "wifi") {
		isBlocked = strings.Contains(strings.ToLower(rfkillListOut), "soft blocked: yes")

		var rfkillArgs []string
		var wasEnabled bool
		if isBlocked {
			rfkillArgs = []string{"rfkill", "unblock", "wifi"}
			wasEnabled = false
		} else {
			rfkillArgs = []string{"rfkill", "block", "wifi"}
			wasEnabled = true
		}

		_, rfkillToggleErr := utils.ExecuteArgv(rfkillArgs...)
		if rfkillToggleErr == nil {
			if !wasEnabled {
				time.Sleep(1 * time.Second)
				iface := strings.TrimSpace(interfaceName)
				if iface == "" {
					iface = firstWirelessIface()
				}
				if iface != "" {
					_, _ = utils.ExecuteArgv("ip", "link", "set", iface, "up")
					time.Sleep(1 * time.Second)
				}
			}
			database.InsertLog("INFO", database.LogMsg("WiFi activado o desactivado correctamente (rfkill)", user.Username), "wifi", &userID)
			return c.JSON(fiber.Map{"success": true, "message": "WiFi toggle exitoso"})
		}
	}

	var iface string
	iface = strings.TrimSpace(interfaceName)
	if iface == "" {
		iface = firstWirelessIface()
	}

	if iface == "" {
		// `iwconfig | grep wlan | head -1 | awk '{print $1}'` → parseo en Go.
		if iwOut, iwErr := utils.ExecuteArgv("iwconfig"); iwErr == nil {
			for _, line := range strings.Split(iwOut, "\n") {
				fields := strings.Fields(line)
				if len(fields) > 0 && strings.Contains(strings.ToLower(fields[0]), "wlan") {
					iface = fields[0]
					break
				}
			}
		}
	}

	if iface != "" {
		statusOut, _ := exec.Command("ip", "link", "show", iface).CombinedOutput()
		isDown := strings.Contains(strings.ToLower(string(statusOut)), "down") || strings.Contains(strings.ToLower(string(statusOut)), "disabled")

		if isDown {
			_, _ = utils.ExecuteArgv("rfkill", "unblock", "wifi")
			_, _ = utils.ExecuteArgv("ip", "link", "set", iface, "up")
			_, _ = utils.ExecuteArgv("ifconfig", iface, "up")
			time.Sleep(1 * time.Second)
			database.InsertLog("INFO", database.LogMsg("WiFi activado en interfaz "+iface, user.Username), "wifi", &userID)
			return c.JSON(fiber.Map{"success": true, "message": fmt.Sprintf("WiFi activado en interfaz %s", iface)})
		} else {
			_, _ = utils.ExecuteArgv("ifconfig", iface, "down")
			database.InsertLog("INFO", database.LogMsg("WiFi desactivado en interfaz "+iface, user.Username), "wifi", &userID)
			return c.JSON(fiber.Map{"success": true, "message": fmt.Sprintf("WiFi desactivado en interfaz %s", iface)})
		}
	}

	errorMsg := "No se pudo cambiar el estado de WiFi. Verifica que tengas permisos sudo configurados (NOPASSWD) o que rfkill/ip estén disponibles. Para configurar sudo sin contraseña, ejecuta: sudo visudo y agrega: usuario ALL=(ALL) NOPASSWD: /usr/sbin/rfkill, /sbin/ip, /sbin/ifconfig"
	database.InsertLog("ERROR", database.LogMsgErr("cambiar estado WiFi", errorMsg, user.Username), "wifi", &userID)
	return c.Status(500).JSON(fiber.Map{"success": false, "error": errorMsg})
}
