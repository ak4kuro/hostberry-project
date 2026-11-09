package hostapd

import "testing"

func validHostapdBody() HostapdConfigBody {
	return HostapdConfigBody{
		Interface:      "wlan0",
		SSID:           "TestAP",
		Password:       "SecurePass9!",
		Channel:        6,
		Security:       "wpa2",
		Gateway:        "192.168.4.1",
		DHCPRangeStart: "192.168.4.10",
		DHCPRangeEnd:   "192.168.4.50",
		LeaseTime:      "12h",
		Country:        "ES",
	}
}

func TestValidateHostapdPOSTValid(t *testing.T) {
	body := validHostapdBody()
	if err := validateHostapdPOST(&body); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateHostapdPOSTInvalidChannel(t *testing.T) {
	body := validHostapdBody()
	body.Channel = 200 // fuera de 2.4 GHz (1-14) y 5 GHz (36-165)
	if err := validateHostapdPOST(&body); err == nil {
		t.Fatal("expected channel validation error")
	}
}

func TestValidateHostapdPOSTInvalidSSID(t *testing.T) {
	body := validHostapdBody()
	body.SSID = ""
	if err := validateHostapdPOST(&body); err == nil {
		t.Fatal("expected SSID validation error")
	}
}
