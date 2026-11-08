package system

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/utils"
	"hostberry/internal/validators"
)

func filterSudoErrors(output []byte) string {
	return utils.FilterSudoErrors(output)
}

func currentUserInfo(c *fiber.Ctx) (string, *int) {
	user, ok := middleware.GetUser(c)
	if !ok || user == nil {
		return "unknown", nil
	}
	id := user.ID
	return user.Username, &id
}

func SystemUpdatesExecuteHandler(c *fiber.Ctx) error {
	username, userID := currentUserInfo(c)
	_ = database.InsertLog("INFO", database.LogMsg("Actualización del sistema iniciada", username), "system", userID)

	go func(user string, uid *int) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
		defer cancel()

		env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

		updateCmd := exec.CommandContext(ctx, "sudo", "apt-get", "update", "-y")
		updateCmd.Env = env
		out1, err1 := updateCmd.CombinedOutput()
		output1 := strings.TrimSpace(filterSudoErrors(out1))

		if ctx.Err() == context.DeadlineExceeded {
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar sistema", "operación cancelada por tiempo de espera agotado", ""), "system", uid)
			return
		}

		if err1 != nil {
			msg := fmt.Sprintf("Error en actualización del sistema (%s): %v", user, err1)
			if output1 != "" {
				msg = msg + " | " + output1
			}
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar sistema", msg, ""), "system", uid)
			return
		}

		upgradeCmd := exec.CommandContext(ctx, "sudo", "apt-get", "upgrade", "-y")
		upgradeCmd.Env = env
		out2, err2 := upgradeCmd.CombinedOutput()
		output2 := strings.TrimSpace(filterSudoErrors(out2))

		if err2 != nil {
			msg := fmt.Sprintf("Error en actualización del sistema (%s): %v", user, err2)
			if output2 != "" {
				msg = msg + " | " + output2
			}
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar sistema", msg, ""), "system", uid)
			return
		}

		_ = database.SetConfig("system_last_update", time.Now().Format(time.RFC3339))
		_ = database.InsertLog("INFO", database.LogMsg("Actualización del sistema completada correctamente", user), "system", uid)
	}(username, userID)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Actualización del sistema iniciada en segundo plano",
	})
}

func SystemUpdatesProjectHandler(c *fiber.Ctx) error {
	username, userID := currentUserInfo(c)
	repoPath, err := os.Getwd()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "No se pudo determinar el directorio del proyecto"})
	}
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Este despliegue no está en un repositorio git"})
	}

	_ = database.InsertLog("INFO", database.LogMsg("Actualización del proyecto iniciada", username), "system", userID)

	go func(user string, uid *int, path string) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		// Solo actualizar si el remoto es el repositorio oficial y estamos en main:
		// evita que un remote manipulado reciba credenciales o traiga código ajeno.
		remoteOut, err := exec.CommandContext(ctx, "git", "-C", path, "remote", "get-url", "origin").Output()
		if err != nil {
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar proyecto", "no se pudo leer el remoto git", ""), "system", uid)
			return
		}
		remote := strings.ToLower(strings.TrimSpace(string(remoteOut)))
		if !strings.Contains(remote, "github.com/ak4kuro/hostberry-project") &&
			!strings.Contains(remote, "github.com/hostberry-project/hostberry-project") {
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar proyecto", "remoto git no reconocido: "+remote, ""), "system", uid)
			return
		}
		branchOut, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "--abbrev-ref", "HEAD").Output()
		if err != nil || strings.TrimSpace(string(branchOut)) != "main" {
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar proyecto", "la rama actual no es main", ""), "system", uid)
			return
		}

		cmd := exec.CommandContext(ctx, "git", "-C", path, "pull", "--ff-only")
		out, err := cmd.CombinedOutput()
		output := strings.TrimSpace(string(out))

		if ctx.Err() == context.DeadlineExceeded {
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar proyecto", "operación cancelada por tiempo de espera agotado", ""), "system", uid)
			return
		}
		if err != nil {
			msg := fmt.Sprintf("Error actualizando proyecto (%s): %v", user, err)
			if output != "" {
				msg = msg + " | " + output
			}
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar proyecto", msg, ""), "system", uid)
			return
		}

		_ = database.SetConfig("project_last_update", time.Now().Format(time.RFC3339))
		_ = database.InsertLog("INFO", database.LogMsg("Proyecto actualizado correctamente", user), "system", uid)
	}(username, userID, repoPath)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Actualización del proyecto iniciada en segundo plano",
	})
}

func getConfigValue(key string) string {
	value, err := database.GetConfig(key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func SystemNotificationsTestEmailHandler(c *fiber.Ctx) error {
	var req struct {
		To string `json:"to"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Payload inválido"})
	}

	req.To = strings.TrimSpace(req.To)
	if req.To == "" {
		return c.Status(400).JSON(fiber.Map{
			"error":   "El destinatario es obligatorio",
			"message": "El destinatario es obligatorio",
		})
	}
	if err := validators.ValidateEmail(req.To); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   err.Error(),
			"message": err.Error(),
		})
	}

	smtpHost := getConfigValue("smtp_host")
	smtpPort := getConfigValue("smtp_port")
	smtpUser := getConfigValue("smtp_user")
	smtpPassword := getConfigValue("smtp_password")
	smtpFrom := getConfigValue("smtp_from")
	if smtpFrom == "" {
		smtpFrom = smtpUser
	}

	if smtpHost == "" || smtpPort == "" || smtpFrom == "" {
		return c.Status(400).JSON(fiber.Map{
			"error":   "Falta configuración SMTP",
			"message": "Rellena y guarda Host, Puerto y From antes de enviar email de prueba",
		})
	}
	if _, err := strconv.Atoi(smtpPort); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   "Puerto SMTP inválido",
			"message": "Puerto SMTP inválido",
		})
	}

	subject := "HostBerry: email de prueba"
	body := "Este es un email de prueba enviado por HostBerry."
	message := fmt.Sprintf(
		"To: %s\r\nFrom: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		req.To,
		smtpFrom,
		subject,
		body,
	)

	address := net.JoinHostPort(smtpHost, smtpPort)
	var auth smtp.Auth
	if smtpUser != "" && smtpPassword != "" {
		auth = smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)
	}

	if err := smtp.SendMail(address, auth, smtpFrom, []string{req.To}, []byte(message)); err != nil {
		username, userID := currentUserInfo(c)
		_ = database.InsertLog("ERROR", database.LogMsgErr("enviar email de prueba", fmt.Sprint(err), username), "system", userID)
		return c.Status(500).JSON(fiber.Map{
			"error":   "No se pudo enviar el email de prueba",
			"detail":  "Revisa la configuración SMTP y vuelve a intentarlo",
			"message": "No se pudo enviar el email de prueba",
		})
	}

	username, userID := currentUserInfo(c)
	_ = database.InsertLog("INFO", database.LogMsg("Email de prueba enviado a "+req.To, username), "system", userID)
	return c.JSON(fiber.Map{
		"success": true,
		"message": "Email de prueba enviado.",
	})
}
