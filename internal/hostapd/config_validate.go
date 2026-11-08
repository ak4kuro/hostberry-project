package hostapd

import (
	"errors"
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
