package utils

import (
	"os/exec"
	"testing"
)

func TestValidateArgvAllowList_Allowed(t *testing.T) {
	cases := [][]string{
		{"ip", "route"},
		{"nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"},
		{"systemctl", "restart", "hostapd"},
		{"wpa_cli", "-i", "wlan0", "status"},
		// La ruta se reduce al basename antes de validar.
		{"/sbin/ifconfig", "wlan0", "up"},
		{"/usr/bin/pkill", "-f", "wpa_supplicant.*wlan0"},
	}

	for _, args := range cases {
		if err := validateArgvAllowList(args); err != nil {
			t.Fatalf("expected allow for %v, got err=%v", args, err)
		}
	}
}

func TestValidateArgvAllowList_Denies(t *testing.T) {
	cases := [][]string{
		{},
		{"sh", "-c", "id"},
		{"bash", "-c", "id"},
		{"curl", "http://evil"},
		{"wget", "http://evil"},
		// Aunque el basename sea válido, un path traversal no lo es: el
		// basename de ".." no está en la allowlist.
		{"../bin/sh", "-c", "id"},
	}

	for _, args := range cases {
		err := validateArgvAllowList(args)
		if err == nil {
			t.Fatalf("expected deny for %v, got allow", args)
		}
		if err != exec.ErrNotFound {
			t.Fatalf("expected exec.ErrNotFound for %v, got %v", args, err)
		}
	}
}

// TestArgvArgsAreLiteral verifica que los argumentos con metacaracteres de
// shell se aceptan tal cual: al no pasar por un shell, `;`, `&`, `$`, pipes
// y espacios son datos para el binario, no sintaxis.
func TestArgvArgsAreLiteral(t *testing.T) {
	cases := [][]string{
		{"echo", "a;b&c|d", "$HOME", "two words"},
		{"cat", "/tmp/file with spaces"},
		{"echo", "host; rm -rf /"}, // argumento, no segundo comando
	}

	for _, args := range cases {
		if err := validateArgvAllowList(args); err != nil {
			t.Fatalf("metachar args should be allowed (literal data): %v err=%v", args, err)
		}
	}
}
