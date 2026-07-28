package wifi

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"hostberry/internal/constants"
	"hostberry/internal/database"
)

const (
	wizardPendingSSIDKey      = "wizard_pending_wifi_ssid"
	wizardPendingPasswordKey  = "wizard_pending_wifi_password"
	wizardPendingCountryKey   = "wizard_pending_wifi_country"
	wizardPendingSecurityKey  = "wizard_pending_wifi_security"
	wizardPendingInterfaceKey = "wizard_pending_wifi_interface"
)

// WizardPendingWiFi describe la red WiFi upstream elegida durante el asistente. Su conexión se
// difiere hasta finalizar el wizard (se aplica en el reinicio) para no cortar el panel mientras
// el usuario configura el equipo en hardware de radio única (AP+STA).
type WizardPendingWiFi struct {
	SSID      string
	Password  string
	Country   string
	Security  string
	Interface string
}

// SaveWizardPendingWiFi persiste la red elegida en el asistente.
func SaveWizardPendingWiFi(w WizardPendingWiFi) error {
	w.SSID = strings.TrimSpace(w.SSID)
	if w.SSID == "" {
		return fmt.Errorf("SSID requerido")
	}
	if strings.TrimSpace(w.Country) == "" {
		w.Country = constants.DefaultCountryCode
	}
	if strings.TrimSpace(w.Interface) == "" {
		w.Interface = constants.DefaultWiFiInterface
	}
	if err := database.SetConfig(wizardPendingSSIDKey, w.SSID); err != nil {
		return err
	}
	if err := database.SetConfig(wizardPendingPasswordKey, w.Password); err != nil {
		return err
	}
	if err := database.SetConfig(wizardPendingCountryKey, w.Country); err != nil {
		return err
	}
	if err := database.SetConfig(wizardPendingSecurityKey, w.Security); err != nil {
		return err
	}
	return database.SetConfig(wizardPendingInterfaceKey, w.Interface)
}

// GetWizardPendingWiFi devuelve la red pendiente y si existe (hay SSID guardado).
func GetWizardPendingWiFi() (WizardPendingWiFi, bool) {
	ssid, err := database.GetConfig(wizardPendingSSIDKey)
	if err != nil || strings.TrimSpace(ssid) == "" {
		return WizardPendingWiFi{}, false
	}
	w := WizardPendingWiFi{SSID: strings.TrimSpace(ssid)}
	w.Password, _ = database.GetConfig(wizardPendingPasswordKey)
	w.Country, _ = database.GetConfig(wizardPendingCountryKey)
	w.Security, _ = database.GetConfig(wizardPendingSecurityKey)
	w.Interface, _ = database.GetConfig(wizardPendingInterfaceKey)
	if strings.TrimSpace(w.Country) == "" {
		w.Country = constants.DefaultCountryCode
	}
	if strings.TrimSpace(w.Interface) == "" {
		w.Interface = constants.DefaultWiFiInterface
	}
	return w, true
}

// ClearWizardPendingWiFi borra la red pendiente (al finalizar el asistente o tras aplicarla).
func ClearWizardPendingWiFi() {
	_ = database.SetConfig(wizardPendingSSIDKey, "")
	_ = database.SetConfig(wizardPendingPasswordKey, "")
	_ = database.SetConfig(wizardPendingCountryKey, "")
	_ = database.SetConfig(wizardPendingSecurityKey, "")
	_ = database.SetConfig(wizardPendingInterfaceKey, "")
}

// PersistPendingWiFiForReboot escribe la configuración de wpa_supplicant para la red pendiente,
// de modo que el arranque en frío (tras finalizar el asistente) se conecte sin cortar el panel.
// No inicia la conexión en caliente: solo deja la conf lista para el reinicio.
func PersistPendingWiFiForReboot() error {
	w, ok := GetWizardPendingWiFi()
	if !ok {
		return nil
	}
	iface := w.Interface
	if iface == "" {
		iface = constants.DefaultWiFiInterface
	}
	country := w.Country
	if country == "" {
		country = constants.DefaultCountryCode
	}

	escape := func(s string) string {
		s = strings.ReplaceAll(s, "\\", "\\\\")
		return strings.ReplaceAll(s, "\"", "\\\"")
	}

	secUpper := strings.ToUpper(strings.TrimSpace(w.Security))
	var networkBlock string
	switch {
	case w.Password != "" && (strings.Contains(secUpper, "WPA3") || strings.Contains(secUpper, "SAE")):
		networkBlock = fmt.Sprintf("network={\n\tssid=\"%s\"\n\tkey_mgmt=SAE\n\tsae_password=\"%s\"\n}", escape(w.SSID), escape(w.Password))
	case w.Password != "":
		cmd := exec.Command("wpa_passphrase", w.SSID, w.Password)
		cmd.Env = append(os.Environ(), "LANG=C")
		out, err := cmd.Output()
		if err != nil || !strings.Contains(string(out), "network=") {
			networkBlock = fmt.Sprintf("network={\n\tssid=\"%s\"\n\tpsk=\"%s\"\n}", escape(w.SSID), escape(w.Password))
		} else {
			networkBlock = strings.TrimSpace(string(out))
		}
	default:
		networkBlock = fmt.Sprintf("network={\n\tssid=\"%s\"\n\tkey_mgmt=NONE\n}", strings.ReplaceAll(w.SSID, "\\", "\\\\"))
	}

	configContent := fmt.Sprintf("ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev\nupdate_config=1\ncountry=%s\n\n%s", country, networkBlock)
	log.Printf("[WIZARD-PERSIST] escribiendo config wpa_supplicant para iface=%s ssid=%s country=%s", iface, w.SSID, country)
	if _, err := writeWpaSupplicantConfig(iface, configContent); err != nil {
		log.Printf("[WIZARD-PERSIST] ERROR writeWpaSupplicantConfig: %v", err)
		return err
	}
	log.Printf("[WIZARD-PERSIST] config wpa_supplicant escrita OK para iface=%s", iface)
	return nil
}
