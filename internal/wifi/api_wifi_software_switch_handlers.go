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

func WifiSoftwareSwitchHandler(c *fiber.Ctx) error {
	user, ok := middleware.GetUser(c)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "No autorizado"})
	}
	userID := user.ID

	if _, err := exec.LookPath("rfkill"); err != nil {
		errorMsg := "rfkill no está disponible en el sistema"
		database.InsertLog("ERROR", database.LogMsgErr("cambiar conmutador de software WiFi", errorMsg, user.Username), "wifi", &userID)
		return c.Status(500).JSON(fiber.Map{"success": false, "error": errorMsg})
	}

	statusOut, _ := utils.ExecuteArgv("rfkill", "list", "wifi")
	statusStr := strings.ToLower(statusOut)
	isBlocked := strings.Contains(statusStr, "soft blocked: yes")

	var rfkillArgs []string
	var action string
	if isBlocked {
		rfkillArgs = []string{"rfkill", "unblock", "wifi"}
		action = "desbloqueado"
	} else {
		rfkillArgs = []string{"rfkill", "block", "wifi"}
		action = "bloqueado"
	}

	output, err := utils.ExecuteArgv(rfkillArgs...)
	if err != nil {
		errorMsg := fmt.Sprintf("Error ejecutando rfkill: %s", output)
		database.InsertLog("ERROR", database.LogMsgErr("cambiar conmutador de software WiFi", errorMsg, user.Username), "wifi", &userID)
		return c.Status(500).JSON(fiber.Map{"success": false, "error": errorMsg})
	}

	time.Sleep(1 * time.Second)

	newStatusOut, _ := utils.ExecuteArgv("rfkill", "list", "wifi")
	newStatusStr := strings.ToLower(newStatusOut)
	newIsBlocked := strings.Contains(newStatusStr, "soft blocked: yes")

	if isBlocked == newIsBlocked {
		errorMsg := "El switch de software no cambió de estado"
		database.InsertLog("WARN", database.LogMsgWarn("el conmutador de software WiFi no cambió: "+errorMsg, user.Username), "wifi", &userID)
		return c.Status(500).JSON(fiber.Map{"success": false, "error": errorMsg})
	}

	message := fmt.Sprintf("Switch de software %s exitosamente", action)
	database.InsertLog("INFO", database.LogMsg("Conmutador de software WiFi "+action+" correctamente", user.Username), "wifi", &userID)
	return c.JSON(fiber.Map{
		"success": true,
		"message": message,
		"blocked": newIsBlocked,
	})
}
