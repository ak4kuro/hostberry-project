package hostapd

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/auth"
	"hostberry/internal/constants"
	"hostberry/internal/validators"
	"hostberry/internal/wifi"
)

type dualBandConfigBody struct {
	SSID24   string `json:"ssid_24"`
	SSID5    string `json:"ssid_5"`
	Channel24 int   `json:"channel_24"`
	Channel5  int   `json:"channel_5"`
	Security string `json:"security"`
	Password string `json:"password"`
	Country  string `json:"country"`
	Interface string `json:"interface"`
}

// HostapdDualBandGetHandler devuelve la configuración dual-band almacenada.
func HostapdDualBandGetHandler(c *fiber.Ctx) error {
	country := constants.DefaultCountryCode
	cfg := wifi.LoadDualBandAPConfig(country)
	iface := wifi.DetectWiFiInterface()
	band := wifi.ConcurrentOperatingBandExport(iface)
	return c.JSON(fiber.Map{
		"success":     true,
		"ssid_24":     cfg.Band24.SSID,
		"ssid_5":      cfg.Band5.SSID,
		"channel_24":  cfg.Band24.Channel,
		"channel_5":   cfg.Band5.Channel,
		"security":    cfg.Band24.Security,
		"active_band": band,
		"dual_radio":  wifi.SecondaryPhyExport(wifi.PhyForInterfaceExport(iface)) != "",
	})
}

// HostapdDualBandConfigHandler guarda perfiles 2.4/5 GHz y los aplica.
func HostapdDualBandConfigHandler(c *fiber.Ctx) error {
	var req dualBandConfigBody
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"success": false, "error": "Invalid request body"})
	}
	log.Printf("[WIZARD-DEBUG] dual-band payload: ssid_24=%q ssid_5=%q ch24=%d ch5=%d security=%q pwd_len=%d iface=%q", req.SSID24, req.SSID5, req.Channel24, req.Channel5, req.Security, len(req.Password), req.Interface)

	country := strings.ToUpper(strings.TrimSpace(req.Country))
	if country == "" {
		country = constants.DefaultCountryCode
	}
	if err := validators.ValidateCountryCode(country); err != nil {
		return c.Status(400).JSON(fiber.Map{"success": false, "error": "Código de país inválido"})
	}
	security := strings.TrimSpace(req.Security)
	if security == "" {
		security = "open"
	}
	if security != "open" && security != "wpa2" && security != "wpa3" {
		security = "open"
	}

	// Validación real de la contraseña del AP: WPA2/WPA3 exige 8–63 caracteres (estándar
	// hostapd/WiFi). Devolvemos un mensaje claro para que el wizard lo muestre tal cual.
	if security != "open" {
		if n := len(req.Password); n < 8 || n > 63 {
			return c.Status(400).JSON(fiber.Map{
				"success": false,
				"error":   "La contraseña del punto de acceso debe tener entre 8 y 63 caracteres (estándar WiFi WPA2/WPA3).",
			})
		}
		for _, r := range req.Password {
			if r < 0x20 || r == 0x7F {
				return c.Status(400).JSON(fiber.Map{
					"success": false,
					"error":   "La contraseña del punto de acceso contiene caracteres no permitidos.",
				})
			}
		}
	}

	if s := strings.TrimSpace(req.SSID24); s != "" {
		if err := validators.ValidateSSID(s); err != nil {
			return c.Status(400).JSON(fiber.Map{"success": false, "error": "SSID 2.4 GHz inválido"})
		}
	}
	if s := strings.TrimSpace(req.SSID5); s != "" {
		if err := validators.ValidateSSID(s); err != nil {
			return c.Status(400).JSON(fiber.Map{"success": false, "error": "SSID 5 GHz inválido"})
		}
	}

	cfg := wifi.DefaultDualBandAPConfig(country)
	if s := strings.TrimSpace(req.SSID24); s != "" {
		cfg.Band24.SSID = s
	}
	if s := strings.TrimSpace(req.SSID5); s != "" {
		cfg.Band5.SSID = s
	}
	if req.Channel24 >= 1 && req.Channel24 <= 14 {
		cfg.Band24.Channel = req.Channel24
	}
	if req.Channel5 >= 36 && req.Channel5 <= 165 {
		cfg.Band5.Channel = req.Channel5
	}
	cfg.Band24.Security = security
	cfg.Band5.Security = security
	cfg.Band24.Password = req.Password
	cfg.Band5.Password = req.Password
	cfg.Band24.Country = country
	cfg.Band5.Country = country

	if err := wifi.SaveDualBandAPConfig(cfg); err != nil {
		return c.Status(500).JSON(fiber.Map{"success": false, "error": err.Error()})
	}

	iface := strings.TrimSpace(req.Interface)
	if iface == "" {
		iface = wifi.DetectWiFiInterface()
	}
	result := wifi.EnsureDualBandHostapd(iface, auth.IsInitialSetupPending())
	if success, ok := result["success"].(bool); ok && !success {
		if errMsg, ok := result["error"].(string); ok && errMsg != "" {
			return c.Status(500).JSON(fiber.Map{"success": false, "error": errMsg})
		}
	}

	if warn := applyDualBandHostapdServices(); warn != "" {
		result["ap_restart_warning"] = warn
	}
	result["success"] = true
	return c.JSON(result)
}

// applyDualBandHostapdServices aplica cambios de SSID/clave sin reiniciar hostapd en caliente
// durante el wizard (evita perder el AP en canales DFS 5 GHz).
func applyDualBandHostapdServices() string {
	// Durante el asistente inicial NO se toca el AP en caliente. El cliente del portal cautivo
	// está conectado a través del propio AP "hostberry"; un reload de hostapd (o un CSA) corta
	// el BSS y tira esa conexión, dejando la petición de guardado SIN respuesta. Como el fetch
	// del navegador no tiene timeout, el botón se queda en "Guardando..." de forma indefinida.
	// La configuración ya queda persistida en disco (EnsureDualBandHostapd) y se aplica al
	// finalizar el asistente (reinicio), así que aquí no hay nada más que hacer.
	if auth.IsInitialSetupPending() {
		log.Printf("Setup: omitido reload/CSA de hostapd durante el wizard (config guardada en disco)")
		return ""
	}
	iface := constants.DefaultWiFiInterface
	if hostapdProcessOrUnitActive() {
		if out, err := executeCommand("hostapd_cli -i ap0 reload"); err != nil {
			log.Printf("Warning: hostapd_cli reload: %v (%s)", err, strings.TrimSpace(out))
		}
		if freq := wifi.StaLinkFrequencyExport(iface); freq > 0 {
			wifi.AlignAPToFreqViaCSAExport(freq)
		}
		return ""
	}
	restartAPNetworkServices()
	return ""
}
