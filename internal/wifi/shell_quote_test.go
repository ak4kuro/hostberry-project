package wifi

import "testing"

func TestQuoteWpaCliSetNetworkValue(t *testing.T) {
	// Campos de cadena: comillas dobles literales + escape, sin quoting de shell.
	args := quoteWpaCliSetNetworkValue("set_network", "0", "ssid", "My$WiFi")
	if len(args) != 4 || args[3] != `"My$WiFi"` {
		t.Fatalf("unexpected quoted args: %#v", args)
	}

	// Caracteres que romperían el valor se escapan para wpa_supplicant.
	args = quoteWpaCliSetNetworkValue("set_network", "0", "ssid", `Mi"Red`)
	if args[3] != `"Mi\"Red"` {
		t.Fatalf("unexpected escaped args: %#v", args)
	}

	// Campos no-string (p. ej. psk hex, freq_list) pasan sin comillas.
	args = quoteWpaCliSetNetworkValue("set_network", "0", "psk", "a1b2c3")
	if args[3] != "a1b2c3" {
		t.Fatalf("unexpected psk args: %#v", args)
	}

	unchanged := quoteWpaCliSetNetworkValue("status")
	if len(unchanged) != 1 || unchanged[0] != "status" {
		t.Fatalf("unexpected status args: %#v", unchanged)
	}
}
