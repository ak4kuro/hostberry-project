package system

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/config"
	"hostberry/internal/database"
	"hostberry/internal/i18n"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/validators"
)

var allowedSystemConfigKeys = map[string]struct{}{
	"language":            {},
	"theme":               {},
	"timezone":            {},
	"dhcp_enabled":        {},
	"dhcp_interface":      {},
	"dhcp_range_start":    {},
	"dhcp_range_end":      {},
	"dhcp_gateway":        {},
	"dhcp_lease_time":     {},
	"dns_server":          {},
	"max_login_attempts":  {},
	"session_timeout":     {},
	"cache_enabled":       {},
	"cache_size":          {},
	"compression_enabled": {},
	"email_notifications": {},
	"email_address":       {},
	"smtp_host":           {},
	"smtp_port":           {},
	"smtp_user":           {},
	"smtp_password":       {},
	"smtp_from":           {},
	"smtp_tls":            {},
	"system_alerts":       {},
}

var booleanSystemConfigKeys = map[string]struct{}{
	"dhcp_enabled":        {},
	"cache_enabled":       {},
	"compression_enabled": {},
	"email_notifications": {},
	"smtp_tls":            {},
	"system_alerts":       {},
}

func normalizeSystemConfigValue(key string, value interface{}) (string, bool, error) {
	switch key {
	case "language":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "es" && s != "en" {
			return "", false, fiber.NewError(400, "Idioma inválido")
		}
		return s, false, nil
	case "theme":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "light" && s != "dark" && s != "auto" {
			return "", false, fiber.NewError(400, "Tema inválido")
		}
		return s, false, nil
	case "timezone":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if err := validateTimezoneValue(s); err != nil {
			return "", false, err
		}
		return s, false, nil
	case "dhcp_interface":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if s != "" {
			if err := validators.ValidateIfaceName(s); err != nil {
				return "", false, err
			}
		}
		return s, false, nil
	case "dhcp_range_start", "dhcp_range_end", "dhcp_gateway":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if s != "" {
			if err := validators.ValidateIP(s); err != nil {
				return "", false, err
			}
		}
		return s, false, nil
	case "dhcp_lease_time":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if s != "" {
			if err := validators.ValidateDhcpLeaseTime(s); err != nil {
				return "", false, err
			}
		}
		return s, false, nil
	case "dns_server":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if err := validateDNSList(s); err != nil {
			return "", false, err
		}
		return s, false, nil
	case "max_login_attempts":
		return normalizeIntValue(value, 1, 10, "Número máximo de intentos inválido")
	case "session_timeout":
		return normalizeIntValue(value, 5, 1440, "Tiempo de sesión inválido")
	case "cache_size":
		return normalizeIntValue(value, 10, 200, "Tamaño de caché inválido")
	case "email_address", "smtp_from":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if err := validators.ValidateEmail(s); err != nil {
			return "", false, err
		}
		return s, false, nil
	case "smtp_host":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if err := validateSMTPHost(s); err != nil {
			return "", false, err
		}
		return s, false, nil
	case "smtp_port":
		return normalizeIntValue(value, 1, 65535, "Puerto SMTP inválido")
	case "smtp_user":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		s = strings.TrimSpace(s)
		if len(s) > 254 {
			return "", false, fiber.NewError(400, "Usuario SMTP demasiado largo")
		}
		if strings.ContainsAny(s, "\x00\r\n") {
			return "", false, fiber.NewError(400, "Usuario SMTP inválido")
		}
		return s, false, nil
	case "smtp_password":
		s, err := requireString(value, key)
		if err != nil {
			return "", false, err
		}
		if strings.TrimSpace(s) == "" {
			return "", true, nil
		}
		if len(s) > 512 {
			return "", false, fiber.NewError(400, "Contraseña SMTP demasiado larga")
		}
		if strings.Contains(s, "\x00") {
			return "", false, fiber.NewError(400, "Contraseña SMTP inválida")
		}
		return s, false, nil
	default:
		if _, ok := booleanSystemConfigKeys[key]; ok {
			return normalizeBoolValue(value, key)
		}
	}

	return "", false, fiber.NewError(400, "Clave no soportada")
}

func requireString(value interface{}, key string) (string, error) {
	s, ok := value.(string)
	if !ok {
		return "", fiber.NewError(400, fmt.Sprintf("Valor inválido para %s", key))
	}
	return s, nil
}

func normalizeBoolValue(value interface{}, key string) (string, bool, error) {
	switch v := value.(type) {
	case bool:
		return strconv.FormatBool(v), false, nil
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		if s == "true" || s == "1" || s == "on" {
			return "true", false, nil
		}
		if s == "false" || s == "0" || s == "off" || s == "" {
			return "false", false, nil
		}
	}
	return "", false, fiber.NewError(400, fmt.Sprintf("Booleano inválido para %s", key))
}

func normalizeIntValue(value interface{}, minValue, maxValue int, errorMsg string) (string, bool, error) {
	var n int
	switch v := value.(type) {
	case float64:
		if v != float64(int(v)) {
			return "", false, fiber.NewError(400, errorMsg)
		}
		n = int(v)
	case int:
		n = v
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return "", false, fiber.NewError(400, errorMsg)
		}
		parsed, err := strconv.Atoi(s)
		if err != nil {
			return "", false, fiber.NewError(400, errorMsg)
		}
		n = parsed
	case nil:
		return "", false, fiber.NewError(400, errorMsg)
	default:
		return "", false, fiber.NewError(400, errorMsg)
	}
	if n < minValue || n > maxValue {
		return "", false, fiber.NewError(400, errorMsg)
	}
	return strconv.Itoa(n), false, nil
}

func validateTimezoneValue(tz string) error {
	return validators.ValidateTimezone(tz)
}

func validateSMTPHost(host string) error {
	if host == "" {
		return nil
	}
	if len(host) > 253 || strings.ContainsAny(host, " \t\r\n\x00/\\") {
		return fiber.NewError(400, "Host SMTP inválido")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fiber.NewError(400, "Host SMTP inválido")
	}
	return nil
}

func validateDNSList(value string) error {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 2 {
		return fiber.NewError(400, "Se permiten como máximo dos DNS")
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return fiber.NewError(400, "Servidor DNS inválido")
		}
		if err := validators.ValidateIP(part); err != nil {
			return err
		}
	}
	return nil
}

func validateDHCPConfig(values map[string]string) error {
	enabled := values["dhcp_enabled"] == "true"
	if !enabled {
		return nil
	}
	required := map[string]string{
		"dhcp_interface":   "Interfaz DHCP requerida",
		"dhcp_range_start": "Inicio del rango DHCP requerido",
		"dhcp_range_end":   "Fin del rango DHCP requerido",
		"dhcp_gateway":     "Gateway DHCP requerido",
		"dhcp_lease_time":  "Tiempo de concesión DHCP requerido",
	}
	for key, msg := range required {
		if strings.TrimSpace(values[key]) == "" {
			return fiber.NewError(400, msg)
		}
	}

	start := net.ParseIP(values["dhcp_range_start"]).To4()
	end := net.ParseIP(values["dhcp_range_end"]).To4()
	gateway := net.ParseIP(values["dhcp_gateway"]).To4()
	if start == nil || end == nil || gateway == nil {
		return fiber.NewError(400, "Configuración DHCP inválida")
	}
	if start[0] != end[0] || start[1] != end[1] || start[2] != end[2] ||
		start[0] != gateway[0] || start[1] != gateway[1] || start[2] != gateway[2] {
		return fiber.NewError(400, "Gateway y rango DHCP deben pertenecer a la misma subred /24")
	}
	if compareIPv4(start, end) > 0 {
		return fiber.NewError(400, "El inicio del rango DHCP no puede ser mayor que el final")
	}
	if compareIPv4(gateway, start) >= 0 && compareIPv4(gateway, end) <= 0 {
		return fiber.NewError(400, "El gateway no debe estar dentro del rango DHCP")
	}
	return nil
}

func compareIPv4(a, b net.IP) int {
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// SystemConfigHandler guarda la configuración del sistema recibida desde la UI.
func SystemConfigHandler(c *fiber.Ctx) error {
	var req map[string]interface{}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}

	user, ok := middleware.GetUser(c)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "No autorizado"})
	}
	userID := user.ID

	updatedKeys := []string{}
	errors := []string{}
	normalized := make(map[string]string, len(req))

	currentConfigs, err := database.GetAllConfigs()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "No se pudo cargar la configuración actual"})
	}

	for key, value := range req {
		if _, ok := allowedSystemConfigKeys[key]; !ok {
			errors = append(errors, fmt.Sprintf("Clave no permitida: %s", key))
			continue
		}

		valueStr, skip, err := normalizeSystemConfigValue(key, value)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		if skip {
			continue
		}
		normalized[key] = valueStr
	}

	merged := make(map[string]string, len(currentConfigs)+len(normalized))
	for k, v := range currentConfigs {
		merged[k] = v
	}
	for k, v := range normalized {
		merged[k] = v
	}
	if err := validateDHCPConfig(merged); err != nil {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		return c.Status(400).JSON(fiber.Map{
			"message": "Configuración inválida",
			"errors":  errors,
		})
	}

	for key, valueStr := range normalized {
		if err := database.SetConfig(key, valueStr); err != nil {
			i18n.LogTf("logs.config_save_error", key, err)
			errors = append(errors, fmt.Sprintf("Error guardando %s", key))
			continue
		}

		if key == "timezone" && valueStr != "" {
			tz := strings.TrimSpace(valueStr)
			cmd := exec.Command("sudo", "/usr/local/sbin/hostberry-safe/set-timezone", tz)
			output, err := cmd.CombinedOutput()
			if err != nil {
				combined := strings.TrimSpace(string(output))
				i18n.LogTf("logs.config_timezone_error", err, combined)

				baseMsg := "No se pudo aplicar la zona horaria al sistema"
				if combined != "" {
					if strings.Contains(strings.ToLower(combined), "sudo") &&
						(strings.Contains(strings.ToLower(combined), "password") || strings.Contains(strings.ToLower(combined), "required")) {
						errors = append(errors, "Permisos insuficientes (sudo requerido)")
					} else {
						errors = append(errors, fmt.Sprintf("%s: %s", baseMsg, combined[:min(len(combined), 200)]))
					}
				} else {
					errors = append(errors, fmt.Sprintf("%s (rc=%v)", baseMsg, err))
				}
			} else {
				i18n.LogTf("logs.config_timezone_success", tz)
			}
		}

		if key == "session_timeout" {
			if timeout, err := strconv.Atoi(valueStr); err == nil && timeout > 0 {
				config.AppConfig.Security.TokenExpiry = timeout
				i18n.LogTf("logs.config_session_timeout", timeout)
			}
		}

		if key == "max_login_attempts" {
			i18n.LogTf("logs.config_max_login", valueStr)
		}

		if key == "cache_enabled" {
			i18n.LogTf("logs.config_cache_enabled", valueStr)
		}

		if key == "compression_enabled" {
			i18n.LogTf("logs.config_compression", valueStr)
		}

		updatedKeys = append(updatedKeys, key)
	}

	response := fiber.Map{
		"message":      "Configuración guardada",
		"updated_keys": updatedKeys,
	}

	if len(errors) > 0 {
		response["errors"] = errors
		response["message"] = fmt.Sprintf("Configuración guardada con advertencias (Algunos errores: %s)", strings.Join(errors, ", "))
	} else {
		response["message"] = "Configuración actualizada exitosamente"
	}

	database.InsertLog("INFO", database.LogMsg("Configuración del sistema actualizada", user.Username), "system", &userID)
	return c.JSON(response)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
