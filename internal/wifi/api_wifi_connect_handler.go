package wifi

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"hostberry/internal/auth"
	"hostberry/internal/constants"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/validators"

	"github.com/gofiber/fiber/v2"
)

var hexPSKRegex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// WifiConnectHandler conecta a una red WiFi (útil para el setup wizard).
func WifiConnectHandler(c *fiber.Ctx) error {
	var req struct {
		SSID      string `json:"ssid"`
		Password  string `json:"password"`
		Country   string `json:"country"`
		Interface string `json:"interface"`
		Band      string `json:"band"`
		Security  string `json:"security"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Datos inválidos",
		})
	}
	// No loguear SSID ni metadatos del payload: pueden ser información sensible.

	if err := validators.ValidateSSID(req.SSID); err != nil {
		return err
	}

	if len(req.Password) > 128 {
		return c.Status(400).JSON(fiber.Map{
			"error": "La contraseña no puede tener más de 128 caracteres",
		})
	}

	// Validación real de la contraseña WiFi (STA). Para redes protegidas (WPA/WPA2/WPA3/SAE) la
	// clave debe tener entre 8 y 63 caracteres (o un PSK hexadecimal de 64). Damos un mensaje
	// claro para que el wizard lo muestre tal cual, en lugar de fallar en silencio tras reiniciar.
	secUpper := strings.ToUpper(strings.TrimSpace(req.Security))
	isOpenNetwork := secUpper == "" || secUpper == "NONE" || strings.Contains(secUpper, "OPEN")
	needsPassword := strings.Contains(secUpper, "WPA") || strings.Contains(secUpper, "SAE") || strings.Contains(secUpper, "PSK")
	if req.Password != "" {
		if n := len(req.Password); (n < 8 || n > 63) && !hexPSKRegex.MatchString(req.Password) {
			return c.Status(400).JSON(fiber.Map{
				"error": "La contraseña WiFi debe tener entre 8 y 63 caracteres.",
			})
		}
	} else if needsPassword && !isOpenNetwork {
		return c.Status(400).JSON(fiber.Map{
			"error": "Introduce la contraseña WiFi de esta red.",
		})
	}

	// Para el setup wizard puede que no haya sesión/token.
	// En ese caso permitimos conectar igualmente y usamos un usuario "setup_wizard" solo para logs.
	username := "setup_wizard"
	var userID *int
	if u, ok := middleware.GetUser(c); ok && u != nil {
		username = u.Username
		id := u.ID
		userID = &id
	}

	country := strings.ToUpper(strings.TrimSpace(req.Country))
	if country == "" {
		country = c.Query("country", constants.DefaultCountryCode)
	}
	if country == "" {
		country = constants.DefaultCountryCode
	}
	if err := validators.ValidateCountryCode(country); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Código de país inválido",
		})
	}

	interfaceName := req.Interface
	if interfaceName == "" {
		interfaceName = constants.DefaultWiFiInterface
	}

	if len(interfaceName) > 16 || !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(interfaceName) {
		return c.Status(400).JSON(fiber.Map{
			"error": "Nombre de interfaz inválido",
		})
	}

	// Durante el asistente inicial NO conectamos en caliente: primero verificamos la contraseña
	// sin conectar realmente, luego guardamos la red elegida y la conexión se aplica al finalizar
	// el wizard (al reiniciar).
	if auth.IsInitialSetupPending() {
		// Verificar la contraseña sin conectar
		secUpper := strings.ToUpper(strings.TrimSpace(req.Security))
		isOpenNetwork := secUpper == "" || secUpper == "NONE" || strings.Contains(secUpper, "OPEN")

		// Si la red tiene contraseña, verificarla antes de guardar
		if !isOpenNetwork && req.Password != "" {
			verifyResult := VerifyWiFiPassword(req.SSID, req.Password, interfaceName, country)
			if !verifyResult["success"].(bool) {
				authFailed, _ := verifyResult["auth_failed"].(bool)
				if authFailed {
					return c.Status(400).JSON(fiber.Map{
						"success": false,
						"error":   verifyResult["error"].(string),
					})
				}
				log.Printf("[WIZARD] verificación de contraseña no concluyente para %q: %s — guardando red igualmente (conexión diferida)", req.SSID, verifyResult["error"])
			}
		}

		// Guardar la configuración WiFi para conectar al finalizar
		if err := SaveWizardPendingWiFi(WizardPendingWiFi{
			SSID:      req.SSID,
			Password:  req.Password,
			Country:   country,
			Security:  req.Security,
			Interface: interfaceName,
		}); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"success": false,
				"error":   err.Error(),
			})
		}
		if userID != nil {
			database.InsertLog("INFO", database.LogMsg("Red WiFi «"+req.SSID+"» guardada; se conectará al finalizar el asistente", username), "wifi", userID)
		}
		return c.JSON(fiber.Map{
			"success":  true,
			"deferred": true,
			"ssid":     req.SSID,
			"message":  "Contraseña verificada. Red guardada; se conectará al finalizar el asistente",
		})
	}

	result := ConnectWiFi(req.SSID, req.Password, interfaceName, country, username)

	if _, hasSuccess := result["success"]; !hasSuccess {
		result["success"] = false
	}
	if _, hasError := result["error"]; !hasError {
		if result["success"] == false {
			result["error"] = "Error desconocido al conectar a la red WiFi"
		} else {
			result["error"] = ""
		}
	}

	if success, ok := result["success"].(bool); ok && success {
		if userID != nil {
			database.InsertLog("INFO", database.LogMsg("Conexión WiFi a "+req.SSID+" correcta", username), "wifi", userID)
		}
		return c.JSON(result)
	}

	errorMsg := "Error desconocido"
	if errorMsgVal, ok := result["error"].(string); ok && errorMsgVal != "" {
		errorMsg = errorMsgVal
	}
	if userID != nil {
		database.InsertLog("ERROR", database.LogMsgErr("conectar WiFi a "+req.SSID, errorMsg, username), "wifi", userID)
	}

	return c.Status(500).JSON(fiber.Map{
		"success": false,
		"error":   errorMsg,
		"message": fmt.Sprintf("Error conectando a %s", req.SSID),
	})
}
