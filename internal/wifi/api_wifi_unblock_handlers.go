package wifi

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/utils"
)

func WifiUnblockHandler(c *fiber.Ctx) error {
	user, ok := middleware.GetUser(c)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "No autorizado"})
	}
	userID := user.ID

	success := false
	method := ""
	var lastError error

	if _, err := exec.LookPath("rfkill"); err == nil {
		rfkillOut, rfkillErr := utils.ExecuteArgv("rfkill", "list", "wifi")
		if rfkillErr == nil && strings.Contains(strings.ToLower(rfkillOut), "wifi") {
			rfkillOutSudo, rfkillUnblockErr := utils.ExecuteArgv("rfkill", "unblock", "wifi")
			if rfkillUnblockErr == nil {
				success = true
				method = "rfkill (con sudo)"
			} else {
				lastError = fmt.Errorf("rfkill error: %s", rfkillOutSudo)
			}
		}
	}

	if !success {
		if _, err := exec.LookPath("nmcli"); err == nil {
			nmcliOut, nmcliErr := utils.ExecuteArgv("nmcli", "radio", "wifi", "on")
			if nmcliErr == nil {
				success = true
				method = "nmcli (con sudo)"
			} else {
				if lastError == nil {
					lastError = fmt.Errorf("nmcli error: %s", nmcliOut)
				}
			}
		}
	}

	if success && method == "rfkill (con sudo)" {
		if _, err := exec.LookPath("nmcli"); err == nil {
			_, _ = utils.ExecuteArgv("nmcli", "radio", "wifi", "on")
		}
	}

	if success {
		time.Sleep(1 * time.Second)

		database.InsertLog("INFO", database.LogMsg("WiFi desbloqueado correctamente", user.Username), "wifi", &userID)
		return c.JSON(fiber.Map{"success": true, "message": "WiFi desbloqueado exitosamente"})
	}

	errorDetails := "No se pudo desbloquear WiFi."
	if lastError != nil {
		errorDetails += fmt.Sprintf(" Último error: %v", lastError)
	}

	availableCmds := []string{}
	if _, err := exec.LookPath("rfkill"); err == nil {
		availableCmds = append(availableCmds, "rfkill")
	}
	if _, err := exec.LookPath("nmcli"); err == nil {
		availableCmds = append(availableCmds, "nmcli")
	}

	if len(availableCmds) == 0 {
		errorDetails += " No se encontraron comandos rfkill ni nmcli instalados."
	} else {
		errorDetails += fmt.Sprintf(" Comandos disponibles: %s. Verifica permisos sudo (NOPASSWD) ejecutando: sudo fix_wifi_permissions.sh", strings.Join(availableCmds, ", "))
	}

	database.InsertLog("ERROR", database.LogMsgErr("desbloquear WiFi", errorDetails, user.Username), "wifi", &userID)
	return c.Status(500).JSON(fiber.Map{"error": errorDetails})
}
