package validators

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/gofiber/fiber/v2"
)

func ValidateUsername(username string) error {
	if len(username) < 3 {
		return fiber.NewError(400, "El nombre de usuario debe tener al menos 3 caracteres")
	}
	if len(username) > 50 {
		return fiber.NewError(400, "El nombre de usuario no puede tener más de 50 caracteres")
	}
	usernameRegex := regexp.MustCompile("^[a-zA-Z0-9_]+$")
	if !usernameRegex.MatchString(username) {
		return fiber.NewError(400, "El nombre de usuario solo puede contener letras, números y guiones bajos")
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fiber.NewError(400, "La contraseña debe tener al menos 8 caracteres")
	}
	if len(password) > 100 {
		return fiber.NewError(400, "La contraseña no puede tener más de 100 caracteres")
	}
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return fiber.NewError(400, "La contraseña debe contener al menos una letra mayúscula")
	}
	if !hasLower {
		return fiber.NewError(400, "La contraseña debe contener al menos una letra minúscula")
	}
	if !hasNumber {
		return fiber.NewError(400, "La contraseña debe contener al menos un número")
	}
	if !hasSpecial {
		return fiber.NewError(400, "La contraseña debe contener al menos un carácter especial")
	}
	return nil
}

func ValidateEmail(email string) error {
	if email == "" {
		return nil
	}
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fiber.NewError(400, "Formato de email inválido")
	}
	return nil
}

func ValidateIP(ip string) error {
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if !ipRegex.MatchString(ip) {
		return fiber.NewError(400, "Formato de IP inválido")
	}
	parts := strings.Split(ip, ".")
	for _, part := range parts {
		if len(part) > 1 && part[0] == '0' {
			return fiber.NewError(400, "IP inválida: no se permiten ceros a la izquierda")
		}
		var n int
		for _, c := range part {
			if c < '0' || c > '9' {
				return fiber.NewError(400, "Formato de IP inválido")
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return fiber.NewError(400, "IP inválida: octeto fuera de rango (0-255)")
		}
	}
	return nil
}

func ValidateSSID(ssid string) error {
	if len(ssid) == 0 {
		return fiber.NewError(400, "El SSID no puede estar vacío")
	}
	if len(ssid) > 32 {
		return fiber.NewError(400, "El SSID no puede tener más de 32 caracteres")
	}
	// El SSID se escribe en ficheros de configuración (wpa_supplicant.conf,
	// hostapd.conf) y en comandos de shell: rechazar caracteres de control,
	// comillas y barra invertida evita inyección de directivas/comandos.
	for _, r := range ssid {
		if r < 0x20 || r == 0x7F || r == '"' || r == '\\' {
			return fiber.NewError(400, "El SSID contiene caracteres no permitidos")
		}
	}
	return nil
}

// ValidateWPAPSK valida contraseña WPA2-PSK / WPA3-SAE (longitud estándar 8–63 ASCII imprimible).
func ValidateWPAPSK(password string) error {
	if len(password) < 8 || len(password) > 63 {
		return fiber.NewError(400, "La contraseña WPA debe tener entre 8 y 63 caracteres")
	}
	for _, r := range password {
		if r < 32 || r == 127 {
			return fiber.NewError(400, "La contraseña WPA contiene caracteres no permitidos")
		}
	}
	return nil
}

var countryCodeRegex = regexp.MustCompile(`^[A-Za-z]{2}$`)

// ValidateCountryCode código país ISO 3166-1 alpha-2 (dos letras).
func ValidateCountryCode(cc string) error {
	cc = strings.TrimSpace(cc)
	if !countryCodeRegex.MatchString(cc) {
		return fiber.NewError(400, "Código de país inválido (use dos letras, ej. ES, US)")
	}
	return nil
}

var dhcpLeaseTimeRegex = regexp.MustCompile(`(?i)^[0-9]+[smhd]?$`)

// ValidateDhcpLeaseTime formato tipo dnsmasq/hostapd: número + opcional s|m|h|d (ej. 12h, 30m).
func ValidateDhcpLeaseTime(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fiber.NewError(400, "Tiempo de concesión DHCP vacío")
	}
	if !dhcpLeaseTimeRegex.MatchString(s) {
		return fiber.NewError(400, "Tiempo de concesión inválido (ej. 12h, 30m, 3600s)")
	}
	return nil
}

// phyNameRegex: nombres devueltos por nl80211 (phy0, phy1, …).
var phyNameRegex = regexp.MustCompile(`^phy[0-9]+$`)

// ValidatePhyName comprueba un identificador wiphy antes de usarlo en `iw phy`.
func ValidatePhyName(phy string) error {
	phy = strings.TrimSpace(phy)
	if !phyNameRegex.MatchString(phy) {
		return fiber.NewError(400, "Identificador phy inválido")
	}
	return nil
}

// ifaceNameRegex: nombres de interfaz Linux habituales (IFNAMSIZ ≤ 16, sin espacios ni metacaracteres de shell).
var ifaceNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,14}$`)

// ValidateIfaceName comprueba un nombre de interfaz antes de pasarlo a comandos del sistema.
func ValidateIfaceName(iface string) error {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return fiber.NewError(400, "Nombre de interfaz vacío")
	}
	if len(iface) > 15 {
		return fiber.NewError(400, "Nombre de interfaz demasiado largo")
	}
	if !ifaceNameRegex.MatchString(iface) {
		return fiber.NewError(400, "Nombre de interfaz inválido")
	}
	return nil
}

const maxConfigSize = 64 * 1024 // 64 KB

func firstDirectiveToken(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return ""
	}
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(fields[0]))
}

func ValidateWireGuardConfig(config string) error {
	if len(config) == 0 {
		return fiber.NewError(400, "Configuración requerida")
	}
	if len(config) > maxConfigSize {
		return fiber.NewError(400, "Configuración demasiado grande")
	}
	if strings.Contains(config, "\x00") {
		return fiber.NewError(400, "Configuración contiene bytes nulos inválidos")
	}
	lower := strings.ToLower(config)
	if !strings.Contains(lower, "[interface]") && !strings.Contains(lower, "privatekey") {
		return fiber.NewError(400, "Configuración WireGuard inválida: debe contener [Interface] y PrivateKey")
	}
	// wg-quick ejecuta estos hooks como shell; no aceptamos configs arbitrarias con comandos.
	dangerous := map[string]struct{}{
		"preup":    {},
		"postup":   {},
		"predown":  {},
		"postdown": {},
	}
	for _, line := range strings.Split(config, "\n") {
		if tok := firstDirectiveToken(line); tok != "" {
			if _, blocked := dangerous[tok]; blocked {
				return fiber.NewError(400, "Configuración WireGuard inválida: contiene directivas de ejecución no permitidas")
			}
		}
	}
	return nil
}

func ValidateVPNConfig(config string) error {
	if len(config) == 0 {
		return fiber.NewError(400, "Configuración requerida")
	}
	if len(config) > maxConfigSize {
		return fiber.NewError(400, "Configuración demasiado grande")
	}
	if strings.Contains(config, "\x00") {
		return fiber.NewError(400, "Configuración contiene bytes nulos inválidos")
	}
	lower := strings.ToLower(config)
	if !strings.Contains(lower, "client") && !strings.Contains(lower, "dev ") && !strings.Contains(lower, "remote ") {
		return fiber.NewError(400, "Configuración OpenVPN inválida: debe parecer un config cliente válido")
	}
	// OpenVPN puede ejecutar scripts/plugins desde el config; rechazamos directivas peligrosas.
	dangerous := map[string]struct{}{
		"up":                    {},
		"down":                  {},
		"route-up":              {},
		"ipchange":              {},
		"learn-address":         {},
		"tls-verify":            {},
		"auth-user-pass-verify": {},
		"client-connect":        {},
		"client-disconnect":     {},
		"plugin":                {},
		"script-security":       {},
		"setenv":                {},
		"setenv-safe":           {},
	}
	for _, line := range strings.Split(config, "\n") {
		if tok := firstDirectiveToken(line); tok != "" {
			if _, blocked := dangerous[tok]; blocked {
				return fiber.NewError(400, "Configuración OpenVPN inválida: contiene directivas de ejecución no permitidas")
			}
		}
	}
	return nil
}
