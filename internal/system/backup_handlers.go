package system

import (
	"path/filepath"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
)

func SystemBackupHandler(c *fiber.Ctx) error {
	path, err := CreateSystemBackup()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"error":   err.Error(),
		})
	}
	// Solo se devuelve el nombre del archivo: la ruta absoluta revela la
	// estructura de instalación y no la necesita el cliente.
	name := filepath.Base(path)
	user, _ := middleware.GetUser(c)
	msg := "Backup creado: " + name
	if user != nil {
		uid := user.ID
		_ = database.InsertLog("INFO", database.LogMsg("Backup del sistema creado", user.Username), "system", &uid)
	}
	return c.JSON(fiber.Map{
		"success": true,
		"message": msg,
		"file":    name,
	})
}

func SystemBackupsListHandler(c *fiber.Ctx) error {
	files, err := ListSystemBackups()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"success": false, "error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true, "backups": files})
}

func SystemRestoreHandler(c *fiber.Ctx) error {
	var req struct {
		File string `json:"file"`
	}
	if err := c.BodyParser(&req); err != nil || req.File == "" {
		return c.Status(400).JSON(fiber.Map{"success": false, "error": "Campo file requerido"})
	}
	if err := RestoreSystemBackup(req.File); err != nil {
		return c.Status(500).JSON(fiber.Map{"success": false, "error": err.Error()})
	}
	user, _ := middleware.GetUser(c)
	if user != nil {
		uid := user.ID
		_ = database.InsertLog("WARN", database.LogMsg("Restauración de backup: "+req.File, user.Username), "system", &uid)
	}
	return c.JSON(fiber.Map{
		"success": true,
		"message": "Restauración completada. Reinicia el servicio hostberry para aplicar cambios.",
		"file":    req.File,
	})
}
