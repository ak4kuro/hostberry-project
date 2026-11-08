package system

import (
	"strings"
	"testing"

	"hostberry/internal/wifi"
)

func validWizardInputs() (wifi.WizardPendingWiFi, wifi.DualBandAPConfig) {
	pending := wifi.WizardPendingWiFi{
		SSID:      "MiRed",
		Password:  "password123",
		Country:   "ES",
		Security:  "WPA2-PSK",
		Interface: "wlan0",
	}
	cfg := wifi.DefaultDualBandAPConfig("ES")
	cfg.Band24.Security = "wpa2"
	cfg.Band24.Password = "apassword1"
	cfg.Band5.Security = "wpa2"
	cfg.Band5.Password = "apassword1"
	return pending, cfg
}

func TestValidateWizardInputsValid(t *testing.T) {
	pending, cfg := validWizardInputs()
	if msg := validateWizardInputs(pending, true, cfg); msg != "" {
		t.Fatalf("expected valid, got: %s", msg)
	}
}

func TestValidateWizardInputsNoPending(t *testing.T) {
	_, cfg := validWizardInputs()
	if msg := validateWizardInputs(wifi.WizardPendingWiFi{}, false, cfg); msg != "" {
		t.Fatalf("expected valid without pending wifi, got: %s", msg)
	}
}

func TestValidateWizardInputsBadPendingSSID(t *testing.T) {
	pending, cfg := validWizardInputs()
	pending.SSID = "bad\nssid"
	if msg := validateWizardInputs(pending, true, cfg); msg == "" || !strings.Contains(msg, "SSID") {
		t.Fatalf("expected SSID error, got: %q", msg)
	}
}

func TestValidateWizardInputsOpenWithPassword(t *testing.T) {
	pending, cfg := validWizardInputs()
	pending.Security = "OPEN"
	pending.Password = "shouldnotbehere"
	if msg := validateWizardInputs(pending, true, cfg); msg == "" {
		t.Fatal("expected error for open network with password")
	}
}

func TestValidateWizardInputsWPAWithoutPassword(t *testing.T) {
	pending, cfg := validWizardInputs()
	pending.Password = ""
	if msg := validateWizardInputs(pending, true, cfg); msg == "" {
		t.Fatal("expected error for WPA network without password")
	}
}

func TestValidateWizardInputsBadAPPPassword(t *testing.T) {
	_, cfg := validWizardInputs()
	cfg.Band24.Password = "short"
	if msg := validateWizardInputs(wifi.WizardPendingWiFi{}, false, cfg); msg == "" || !strings.Contains(msg, "2.4") {
		t.Fatalf("expected AP 2.4GHz password error, got: %q", msg)
	}
}

func TestValidateWizardInputsBadAPChannel(t *testing.T) {
	_, cfg := validWizardInputs()
	cfg.Band5.Channel = 6 // canal 2.4 GHz en perfil 5 GHz
	if msg := validateWizardInputs(wifi.WizardPendingWiFi{}, false, cfg); msg == "" || !strings.Contains(msg, "5 GHz") {
		t.Fatalf("expected 5GHz channel error, got: %q", msg)
	}
}

func TestValidateWizardInputsBadAPSecurity(t *testing.T) {
	_, cfg := validWizardInputs()
	cfg.Band24.Security = "wep"
	if msg := validateWizardInputs(wifi.WizardPendingWiFi{}, false, cfg); msg == "" {
		t.Fatal("expected error for invalid AP security")
	}
}
