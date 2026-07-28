package wifi

import (
	"fmt"
	"strings"

	"hostberry/internal/database"
)

const WizardPreferredBandConfigKey = "wizard_preferred_wifi_band"

// SaveWizardPreferredBand guarda la banda WiFi upstream elegida en el asistente (2.4 o 5).
func SaveWizardPreferredBand(band string) error {
	band = strings.TrimSpace(band)
	if band != band24GHz && band != band5GHz {
		return nil
	}
	return database.SetConfig(WizardPreferredBandConfigKey, band)
}

// GetWizardPreferredBand devuelve la banda guardada en el wizard o "" si no hay preferencia.
func GetWizardPreferredBand() string {
	val, err := database.GetConfig(WizardPreferredBandConfigKey)
	if err != nil {
		return ""
	}
	switch strings.TrimSpace(val) {
	case band24GHz, band5GHz:
		return strings.TrimSpace(val)
	default:
		return ""
	}
}

// PersistPreferredBandForReboot escribe hostapd.conf con la configuración completa (SSID,
// contraseña, seguridad, canal) de la banda elegida antes del reinicio post-wizard.
// Usa EnsureDualBandHostapd con setupPending=false para que el arranque en frío aplique
// la seguridad guardada por el usuario (no solo el canal).
func PersistPreferredBandForReboot(band string) error {
	if band != band24GHz && band != band5GHz {
		return nil
	}
	result := EnsureDualBandHostapdForBand("", false, band)
	if success, ok := result["success"].(bool); ok && !success {
		if errMsg, ok := result["error"].(string); ok && errMsg != "" {
			return fmt.Errorf("%s", errMsg)
		}
	}
	return nil
}
