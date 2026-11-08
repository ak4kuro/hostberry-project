package system

import (
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/auth"
	"hostberry/internal/constants"
	"hostberry/internal/database"
	"hostberry/internal/hostapd"
	"hostberry/internal/i18n"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/validators"
	"hostberry/internal/wifi"
)

// validateWizardParameters comprueba que todos los parámetros guardados durante
// el asistente inicial son coherentes y válidos. Devuelve "" si todo es correcto
// o un mensaje de error describiendo el primer parámetro inválido. Si falla, el
// handler restaura la configuración de fábrica y NO marca el wizard como completado.
func validateWizardParameters() string {
	// 1) Red WiFi upstream pendiente (STA).
	if w, ok := wifi.GetWizardPendingWiFi(); ok {
		if err := validators.ValidateSSID(w.SSID); err != nil {
			return "La red WiFi guardada tiene un nombre (SSID) no válido."
		}
		if err := validators.ValidateIfaceName(w.Interface); err != nil {
			return "La interfaz WiFi guardada no es válida."
		}
		if err := validators.ValidateCountryCode(w.Country); err != nil {
			return "El código de país WiFi guardado no es válido."
		}
		sec := strings.ToUpper(strings.TrimSpace(w.Security))
		isOpen := sec == "" || sec == "NONE" || strings.Contains(sec, "OPEN")
		needsPass := !isOpen && (strings.Contains(sec, "WPA") || strings.Contains(sec, "SAE") || strings.Contains(sec, "PSK"))
		if isOpen && w.Password != "" {
			return "La red WiFi está marcada como abierta pero tiene contraseña."
		}
		if needsPass && w.Password == "" {
			return "La red WiFi elegida no tiene contraseña."
		}
		if w.Password != "" {
			if n := len(w.Password); (n < 8 || n > 63) && !isHexPSK(w.Password) {
				return "La contraseña WiFi guardada no es válida (8-63 caracteres o PSK de 64 hex)."
			}
			for _, r := range w.Password {
				if r < 0x20 || r == 0x7F {
					return "La contraseña WiFi guardada contiene caracteres no permitidos."
				}
			}
		}
	}

	// 2) Perfiles del punto de acceso HostBerry (dual-band).
	cfg := wifi.LoadDualBandAPConfig(constants.DefaultCountryCode)
	profiles := []struct {
		name   string
		prof   wifi.DualBandAPProfile
		maxCh  int
		minCh5 bool
	}{
		{"2.4 GHz", cfg.Band24, 14, false},
		{"5 GHz", cfg.Band5, 165, true},
	}
	for _, p := range profiles {
		if err := validators.ValidateSSID(p.prof.SSID); err != nil {
			return "El nombre (SSID) del punto de acceso " + p.name + " no es válido."
		}
		sec := strings.ToLower(strings.TrimSpace(p.prof.Security))
		if sec == "" {
			sec = "open"
		}
		if sec != "open" && sec != "wpa2" && sec != "wpa3" {
			return "La seguridad del punto de acceso " + p.name + " no es válida."
		}
		minCh := 1
		if p.minCh5 {
			minCh = 36
		}
		if p.prof.Channel < minCh || p.prof.Channel > p.maxCh {
			return "El canal del punto de acceso " + p.name + " no es válido."
		}
		if sec != "open" {
			if n := len(p.prof.Password); n < 8 || n > 63 {
				return "La contraseña del punto de acceso " + p.name + " debe tener entre 8 y 63 caracteres."
			}
			for _, r := range p.prof.Password {
				if r < 0x20 || r == 0x7F {
					return "La contraseña del punto de acceso " + p.name + " contiene caracteres no permitidos."
				}
			}
		}
		if p.prof.Country != "" {
			if err := validators.ValidateCountryCode(p.prof.Country); err != nil {
				return "El código de país del punto de acceso " + p.name + " no es válido."
			}
		}
	}

	return ""
}

// isHexPSK indica si la contraseña es un PSK hexadecimal de 64 caracteres.
func isHexPSK(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// SetupWizardCompleteAPIHandler marca el wizard como completado y devuelve la ruta siguiente.
func SetupWizardCompleteAPIHandler(c *fiber.Ctx) error {
	user, ok := middleware.GetUser(c)
	if !ok || user == nil {
		return c.Status(401).JSON(fiber.Map{
			"error": i18n.T(c, "auth.unauthorized", "Unauthorized"),
		})
	}

	reboot := false
	if !user.SetupWizardCompleted {
		// El wizard solo "cambia" si TODOS los parámetros guardados son correctos.
		// Si algo es inválido se restaura la configuración de fábrica y el asistente
		// sigue pendiente para que el usuario lo complete correctamente.
		if msg := validateWizardParameters(); msg != "" {
			log.Printf("[WIZARD-COMPLETE] parámetros inválidos, restaurando fábrica: %s", msg)
			wifi.ClearWizardPendingWiFi()
			// AP a valores de fábrica: no debe quedar una configuración parcial/inválida.
			_ = wifi.SaveDualBandAPConfig(wifi.DefaultDualBandAPConfig(constants.DefaultCountryCode))
			ClearWizardDirty()
			go ResetWizardConfigurations(user.Username)
			return c.Status(400).JSON(fiber.Map{
				"error":         i18n.T(c, "setup_wizard.invalid_params_reset", "La configuración del asistente no es válida. Se han restaurado los valores de fábrica; completa el asistente de nuevo."),
				"detail":        msg,
				"factory_reset": true,
			})
		}
		user.SetupWizardCompleted = true
		if err := database.DB.Save(user).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": i18n.T(c, "errors.general_error_message", "An unexpected error occurred"),
			})
		}
		_ = database.SetConfig("setup_wizard_completed_by_api", "1")
		// La configuración aplicada queda confirmada: ya no debe revertirse al reabrir.
		ClearWizardDirty()
		if err := hostapd.ApplySingleClientAPLimit(false); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": i18n.T(c, "setup_wizard.release_ap_limit_failed", "Setup saved but the access point could not allow more clients. Check hostapd and dnsmasq."),
			})
		}
		// Desactivar el portal cautivo y habilitar el reparto de Internet del AP. Se persiste en
		// disco (config dnsmasq + servicio captivo deshabilitado + sysctl), de modo que tras el
		// reinicio el AP "hostberry" da Internet y el panel queda accesible en hostberry.local.
		hostapd.ApplyNormalAPMode()
		prefBand := wifi.GetWizardPreferredBand()
		log.Printf("[WIZARD-COMPLETE] banda preferida: %q", prefBand)
		if prefBand != "" {
			if err := wifi.PersistPreferredBandForReboot(prefBand); err != nil {
				log.Printf("[WIZARD-COMPLETE] ERROR PersistPreferredBandForReboot: %v", err)
			} else {
				log.Printf("[WIZARD-COMPLETE] PersistPreferredBandForReboot OK (band=%s)", prefBand)
			}
		}
		// Aplicar la red WiFi elegida en el asistente: se deja lista en wpa_supplicant para que el
		// equipo se conecte al arrancar tras el reinicio (la conexión se difiere a "Finalizar").
		pending, hasPending := wifi.GetWizardPendingWiFi()
		log.Printf("[WIZARD-COMPLETE] red pendiente: exists=%v ssid=%q iface=%q", hasPending, pending.SSID, pending.Interface)
		if err := wifi.PersistPendingWiFiForReboot(); err != nil {
			log.Printf("[WIZARD-COMPLETE] ERROR PersistPendingWiFiForReboot: %v", err)
		} else {
			log.Printf("[WIZARD-COMPLETE] PersistPendingWiFiForReboot OK")
		}
		wifi.ClearWizardPendingWiFi()
		// Devolver wlan0 a NetworkManager: durante el asistente estuvo bajo un supplicant dedicado
		// (sin autoscan). Al reiniciar, NM debe gestionarlo de nuevo para la autoconexión normal.
		wifi.StopSetupModeSupplicant()
		reboot = true
		username := user.Username
		go func() {
			time.Sleep(2 * time.Second)
			SystemRestart(username)
		}()
	}

	redirect := "/first-login"
	if !auth.IsPasswordChangeRequired(user) {
		redirect = "/dashboard"
	}

	return c.JSON(fiber.Map{
		"message":  i18n.T(c, "setup_wizard.completed_redirect", "Setup complete. Continue to secure your account."),
		"redirect": redirect,
		"reboot":   reboot,
	})
}
