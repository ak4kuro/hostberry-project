package wifi

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/utils"
	"hostberry/internal/validators"
)

// WifiConfigHandler gestiona únicamente el cambio de región WiFi (iw reg set).
// La conexión WiFi se realiza por /api/v1/wifi/connect (WifiConnectHandler),
// que tiene validación y logging completos; la antigua rama SSID de este
// endpoint era un duplicado con validación más débil y se eliminó.
func WifiConfigHandler(c *fiber.Ctx) error {
	user, ok := middleware.GetUser(c)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "No autorizado"})
	}
	userID := user.ID

	var req struct {
		Region string `json:"region"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Datos inválidos"})
	}

	if req.Region == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Se requiere region"})
	}
	req.Region = strings.ToUpper(strings.TrimSpace(req.Region))
	if err := validators.ValidateCountryCode(req.Region); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}

	{
		req.Region = strings.ToUpper(strings.TrimSpace(req.Region))
		if err := validators.ValidateCountryCode(req.Region); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}

		writeSudoTee := func(path string, content string) error {
			// stdin directo vía privileged-exec (sin shell ni `sudo` directo,
			// que sudoers no autoriza). stdout/stderr se ignoran.
			cmd, err := utils.NewArgvCommand("tee", path)
			if err != nil {
				return err
			}
			cmd.Stdin = strings.NewReader(content)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			return cmd.Run()
		}

		if _, err := exec.LookPath("iw"); err == nil {
			iwCmd, iwCmdErr := utils.NewArgvCommand("iw", "reg", "set", req.Region)
			var out []byte
			var err error
			if iwCmdErr != nil {
				err = iwCmdErr
			} else {
				out, err = iwCmd.CombinedOutput()
			}
			output := strings.TrimSpace(string(out))

			if err != nil {
				// Fallback si se ejecuta como root o si sudo no está disponible.
				out, err = exec.Command("iw", "reg", "set", req.Region).CombinedOutput()
				output = strings.TrimSpace(string(out))
			}

			if err == nil {
				verifyOut, _ := exec.Command("iw", "reg", "get").CombinedOutput()
				verifyOutput := strings.TrimSpace(string(verifyOut))

				if strings.Contains(verifyOutput, req.Region) || output == "" {
					database.InsertLog("INFO", database.LogMsg("Región WiFi cambiada a "+req.Region, user.Username), "wifi", &userID)
					// Intentar persistir la región en ficheros comunes, y reiniciar WiFi.
					content := "REGDOMAIN=" + req.Region + "\n"
					if err := writeSudoTee("/etc/default/crda", content); err == nil {
						database.InsertLog("INFO", database.LogMsg("Región WiFi configurada a "+req.Region+" (crda)", user.Username), "wifi", &userID)
						_, _ = execPrivilegedArgv("nmcli", "radio", "wifi", "off")
						time.Sleep(1 * time.Second)
						_, _ = execPrivilegedArgv("nmcli", "radio", "wifi", "on")
						return c.JSON(fiber.Map{"success": true, "message": "Región WiFi configurada exitosamente. WiFi reiniciado para aplicar cambios."})
					}
					if err := writeSudoTee("/etc/conf.d/wireless-regdom", content); err == nil {
						database.InsertLog("INFO", database.LogMsg("Región WiFi configurada a "+req.Region+" (wireless-regdom)", user.Username), "wifi", &userID)
						return c.JSON(fiber.Map{"success": true, "message": "Región WiFi configurada. Reinicia WiFi o el sistema para aplicar cambios."})
					}

					// Si no se pudo persistir, al menos el set con iw fue correcto.
					return c.JSON(fiber.Map{"success": true, "message": "Región WiFi cambiada exitosamente a " + req.Region})
				}
			}
		}

		// Fallback: intentar persistir crda aunque no exista iw o no se pudiera verificar el cambio.
		if err := writeSudoTee("/etc/default/crda", "REGDOMAIN="+req.Region+"\n"); err == nil {
			database.InsertLog("INFO", database.LogMsg("Región WiFi configurada a "+req.Region, user.Username), "wifi", &userID)
			return c.JSON(fiber.Map{"success": true, "message": "Región WiFi configurada. Reinicia WiFi para aplicar cambios."})
		}

		errorMsg := fmt.Sprintf("No se pudo cambiar la región WiFi automáticamente. Verifica que 'iw' esté instalado (sudo apt-get install iw) y que tengas permisos sudo configurados. Puedes configurarlo manualmente ejecutando: sudo iw reg set %s", req.Region)
		database.InsertLog("ERROR", database.LogMsgErr("cambiar región WiFi a "+req.Region, errorMsg, user.Username), "wifi", &userID)
		return c.Status(500).JSON(fiber.Map{"error": errorMsg})
	}
}

func WifiStatusHandler(c *fiber.Ctx) error {
	return wifiRuntimeStatusHandler(c)
}
