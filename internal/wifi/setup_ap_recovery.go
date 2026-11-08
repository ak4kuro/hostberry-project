package wifi

import (
	"log"
	"time"

	"hostberry/internal/auth"
)

// EnsureWizardAPBroadcasting garantiza que el AP "hostberry" emite en 2.4 GHz durante el wizard.
// Si la STA upstream está en 5 GHz en la misma radio, desconecta la STA para que el móvil pueda
// volver a ver la red hostberry (el paso 1 del wizard volverá a conectar upstream con CSA).
func EnsureWizardAPBroadcasting(staInterface string) {
	if !auth.IsInitialSetupPending() {
		return
	}
	if staInterface == "" {
		staInterface = detectWiFiInterface()
	}
	if !hostapdServiceActive() {
		RecoverSetupAPIfNeeded(staInterface)
		return
	}
	staFreq := staLinkFrequency(staInterface)
	apFreq := apLinkFrequency()
	if staFreq <= 0 {
		return
	}
	if bandFromFrequency(staFreq) == band5GHz && bandFromFrequency(apFreq) != band5GHz {
		log.Printf("HostBerry: wizard AP en 2.4 GHz bloqueado por STA en 5 GHz; desconectando upstream")
		disconnectSTA(staInterface)
		time.Sleep(1500 * time.Millisecond)
		_, _ = execPrivilegedArgv("systemctl", "restart", "hostapd")
	}
}

// RecoverSetupAPIfNeeded restaura el AP "hostberry" en 2.4 GHz durante el wizard si hostapd
// no está activo. En radio única AP+STA no se puede arrancar hostapd en 2.4 GHz mientras la
// STA sigue en 5 GHz (p. ej. canal DFS); se desconecta la STA upstream temporalmente.
func RecoverSetupAPIfNeeded(staInterface string) bool {
	if !auth.IsInitialSetupPending() {
		return false
	}
	if hostapdServiceActive() {
		return false
	}
	if staInterface == "" {
		staInterface = detectWiFiInterface()
	}

	freq := staLinkFrequency(staInterface)
	if bandFromFrequency(freq) == band5GHz {
		log.Printf("HostBerry: recuperando AP del wizard (desconectando STA en 5 GHz temporalmente)")
		disconnectSTA(staInterface)
		time.Sleep(2 * time.Second)
	}

	country := regulatoryCountry()
	cfg := LoadDualBandAPConfig(country)
	profile := cfg.Band24
	profile.Security = "open"
	profile.Password = ""
	if profile.Channel < 1 || profile.Channel > 14 {
		profile.Channel = 6
	}
	if profile.Country == "" {
		profile.Country = country
	}

	content := renderHostapdConfig(apCSAInterface, profile, band24GHz, true)
	if err := writePrivilegedHostapdConfig(hostapdActiveConfigPath, content); err != nil {
		log.Printf("HostBerry: no se pudo escribir hostapd.conf de recuperación: %v", err)
		return false
	}
	_, _ = execPrivilegedArgv("systemctl", "reset-failed", "hostapd")
	_, _ = execPrivilegedArgv("systemctl", "start", "hostapd")
	if !hostapdServiceActive() {
		log.Printf("HostBerry: hostapd no arrancó tras recuperación del AP del wizard")
		return false
	}
	log.Printf("HostBerry: AP del wizard activo (SSID %q, canal %d)", profile.SSID, profile.Channel)
	return true
}

func disconnectSTA(interfaceName string) {
	socketDir := findWorkingWpaSupplicantSocket(interfaceName)
	if socketDir != "" {
		_, _ = runPrivilegedCommand("wpa_cli", "-i", interfaceName, "-p", socketDir, "disconnect")
		_, _ = runPrivilegedCommand("wpa_cli", "-i", interfaceName, "-p", socketDir, "disable_network", "all")
		_, _ = runPrivilegedCommand("wpa_cli", "-i", interfaceName, "-p", socketDir, "save_config")
		return
	}
	_, _ = execPrivilegedArgv("wpa_cli", "-i", interfaceName, "-p", "/run/wpa_supplicant", "disconnect")
	_, _ = execPrivilegedArgv("wpa_cli", "-i", interfaceName, "-p", "/run/wpa_supplicant", "disable_network", "all")
}
