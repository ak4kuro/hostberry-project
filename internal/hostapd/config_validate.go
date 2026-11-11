package hostapd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/validators"
)

// sanitizeHostapdConfValue elimina caracteres que romperían la sintaxis de
// hostapd.conf (saltos de línea, caracteres de control, comillas y '#') al
// incrustar un valor en una directiva `clave=valor`.
func sanitizeHostapdConfValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F || r == '"' || r == '\'' || r == '#' {
			return -1
		}
		return r
	}, s)
}

// HostapdConfigBody es el cuerpo JSON de configuración HostAPD (POST).
type HostapdConfigBody struct {
	Interface      string `json:"interface"`
	SSID           string `json:"ssid"`
	Password       string `json:"password"`
	Channel        int    `json:"channel"`
	Security       string `json:"security"`
	Gateway        string `json:"gateway"`
	DHCPRangeStart string `json:"dhcp_range_start"`
	DHCPRangeEnd   string `json:"dhcp_range_end"`
	LeaseTime      string `json:"lease_time"`
	Country        string `json:"country"`
}

// validateWiFiChannel acepta canales 2.4 GHz (1-14) y 5 GHz (36-165).
func validateWiFiChannel(ch int) error {
	if (ch >= 1 && ch <= 14) || (ch >= 36 && ch <= 165) {
		return nil
	}
	return fiber.NewError(400, "Canal WiFi inválido (2.4 GHz: 1-14, 5 GHz: 36-165)")
}

func hwModeForChannel(ch int) string {
	if ch > 14 {
		return "a"
	}
	return "g"
}

// renderLegacyHostapdConfig genera el contenido de hostapd.conf para el endpoint
// single-band /hostapd/config. Función pura: los valores ya vienen validados por
// validateHostapdPOST y se sanitizan de nuevo por defensa en profundidad.
func renderLegacyHostapdConfig(req HostapdConfigBody, apInterface string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `interface=%s
driver=nl80211
ctrl_interface=/run/hostapd
ctrl_interface_group=0
ssid=%s
hw_mode=%s
channel=%d
country_code=%s
ieee80211d=1
ieee80211n=1
`, apInterface, sanitizeHostapdConfValue(req.SSID), hwModeForChannel(req.Channel), req.Channel, req.Country)
	if req.Channel > 14 {
		b.WriteString("ieee80211ac=1\n")
	}

	switch req.Security {
	case "open":
		b.WriteString("auth_algs=0\n")
	case "wpa2":
		fmt.Fprintf(&b, `wpa=2
wpa_passphrase=%s
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
`, sanitizeHostapdConfValue(req.Password))
	case "wpa3":
		fmt.Fprintf(&b, `wpa=2
wpa_passphrase=%s
wpa_key_mgmt=WPA-PSK-SHA256
wpa_pairwise=CCMP
rsn_pairwise=CCMP
`, sanitizeHostapdConfValue(req.Password))
	}

	return b.String()
}

const (
	dnsmasqManagedBeginMarker = "# >>> hostberry-dnsmasq >>>"
	dnsmasqManagedEndMarker   = "# <<< hostberry-dnsmasq <<<"
)

// mergeManagedConfigBlock devuelve `existing` con el bloque delimitado por
// begin/end sustituido por `managed`. Si no existe bloque previo, se añade al
// final. El resto del archivo (config del usuario, otros servicios) se conserva.
func mergeManagedConfigBlock(existing, beginMarker, endMarker, managed string) string {
	var kept []string
	inBlock := false
	for _, line := range strings.Split(existing, "\n") {
		t := strings.TrimSpace(line)
		if t == beginMarker {
			inBlock = true
			continue
		}
		if t == endMarker {
			inBlock = false
			continue
		}
		if !inBlock {
			kept = append(kept, line)
		}
	}

	body := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	block := beginMarker + "\n" + strings.TrimRight(managed, "\n") + "\n" + endMarker + "\n"
	if body == "" {
		return block
	}
	return body + "\n\n" + block
}

func respondValidatorError(c *fiber.Ctx, err error) error {
	var fe *fiber.Error
	if errors.As(err, &fe) {
		return c.Status(fe.Code).JSON(fiber.Map{"error": fe.Message, "success": false})
	}
	return c.Status(400).JSON(fiber.Map{"error": err.Error(), "success": false})
}

// validateHostapdPOST valida campos tras aplicar valores por defecto.
func validateHostapdPOST(req *HostapdConfigBody) error {
	if err := validators.ValidateIfaceName(req.Interface); err != nil {
		return err
	}
	if err := validators.ValidateSSID(req.SSID); err != nil {
		return err
	}
	if err := validateWiFiChannel(req.Channel); err != nil {
		return err
	}
	if err := validators.ValidateIP(req.Gateway); err != nil {
		return err
	}
	if err := validators.ValidateIP(req.DHCPRangeStart); err != nil {
		return err
	}
	if err := validators.ValidateIP(req.DHCPRangeEnd); err != nil {
		return err
	}
	if err := validators.ValidateDhcpLeaseTime(req.LeaseTime); err != nil {
		return err
	}
	if err := validators.ValidateCountryCode(req.Country); err != nil {
		return err
	}
	if req.Security == "wpa2" || req.Security == "wpa3" {
		if err := validators.ValidateWPAPSK(req.Password); err != nil {
			return err
		}
	}
	return nil
}
