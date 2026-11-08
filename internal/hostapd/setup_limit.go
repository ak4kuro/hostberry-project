package hostapd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"hostberry/internal/auth"
	"hostberry/internal/constants"
	"hostberry/internal/wifi"
)

const (
	hostapdConfigPath     = "/etc/hostapd/hostapd.conf"
	dnsmasqAPConfigPath   = "/etc/dnsmasq.d/hostberry-ap.conf"
	dnsmasqMainConfigPath = "/etc/dnsmasq.conf"
	defaultSetupClientIP  = "192.168.4.2"
	defaultDHCPRangeEnd   = "192.168.4.254"
	defaultDHCPNetmask    = "255.255.255.0"
	defaultDHCPLeaseTime  = "12h"
	// Durante el asistente: pool pequeño y lease corto. Así, cuando un dispositivo se desconecta,
	// su IP se libera en ~2 min (lease mínimo de dnsmasq) y el siguiente móvil puede conectarse,
	// evitando el bloqueo "no address available" del rango de una sola IP.
	setupDHCPRangeEnd   = "192.168.4.20"
	setupDHCPLeaseTime  = "2m"
	hostapdMaxNumSTAKey = "max_num_sta"
)

// ApplySingleClientAPLimit ajusta hostapd y dnsmasq para permitir solo un cliente
// en la red hostberry (max_num_sta=1 y un único lease DHCP) o restaura el rango normal.
func ApplySingleClientAPLimit(enable bool) error {
	if err := writeSingleClientLimitConfigs(enable); err != nil {
		return err
	}
	if auth.IsInitialSetupPending() {
		if hostapdProcessOrUnitActive() {
			if out, err := executeArgv("hostapd_cli", "-i", "ap0", "reload"); err != nil {
				log.Printf("Warning: hostapd_cli reload (setup limit): %v (%s)", err, strings.TrimSpace(out))
			}
		}
		return nil
	}
	restartAPNetworkServices()
	return nil
}

// EnsureSingleClientLimitIfPending reaplica el límite en disco si el wizard sigue pendiente.
func EnsureSingleClientLimitIfPending() error {
	if !auth.IsInitialSetupPending() {
		return nil
	}
	return writeSingleClientLimitConfigs(true)
}

func writeSingleClientLimitConfigs(enable bool) error {
	var errs []string

	if err := patchConfigFile(hostapdConfigPath, func(content []byte) ([]byte, error) {
		return mutateHostapdMaxNumSTA(content, enable), nil
	}); err != nil {
		errs = append(errs, fmt.Sprintf("hostapd: %v", err))
	}

	for _, path := range []string{dnsmasqAPConfigPath, dnsmasqMainConfigPath} {
		if err := patchConfigFile(path, func(content []byte) ([]byte, error) {
			return mutateDnsmasqDHCPRange(content, enable), nil
		}); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf(strings.Join(errs, "; "))
	}
	return nil
}

func restartAPNetworkServices() {
	if out, err := executeArgv("systemctl", "restart", "hostapd"); err != nil {
		log.Printf("Warning: restart hostapd: %v (%s)", err, strings.TrimSpace(out))
	}
	if out, err := executeArgv("systemctl", "restart", "dnsmasq"); err != nil {
		log.Printf("Warning: restart dnsmasq: %v (%s)", err, strings.TrimSpace(out))
	}
}

// EnsureAPRunningForSetup inicia hostapd/dnsmasq si el wizard inicial sigue pendiente y el AP está parado.
func EnsureAPRunningForSetup() {
	if !auth.IsInitialSetupPending() {
		return
	}
	if _, err := os.Stat("/sys/class/net/ap0"); err != nil {
		return
	}
	if hostapdProcessOrUnitActive() {
		return
	}
	log.Printf("Setup pendiente: recuperando AP hostberry para el wizard")
	if wifi.RecoverSetupAPIfNeeded(constants.DefaultWiFiInterface) {
		if out, err := executeArgv("systemctl", "start", "dnsmasq"); err != nil {
			log.Printf("Warning: start dnsmasq en setup: %v (%s)", err, strings.TrimSpace(out))
		}
		return
	}
	if out, err := executeArgv("systemctl", "start", "hostapd"); err != nil {
		log.Printf("Warning: start hostapd en setup: %v (%s)", err, strings.TrimSpace(out))
	}
	if out, err := executeArgv("systemctl", "start", "dnsmasq"); err != nil {
		log.Printf("Warning: start dnsmasq en setup: %v (%s)", err, strings.TrimSpace(out))
	}
}

func patchConfigFile(path string, mutator func([]byte) ([]byte, error)) error {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	updated, err := mutator(content)
	if err != nil {
		return err
	}
	if bytes.Equal(content, updated) {
		return nil
	}
	return writeConfigFilePrivileged(path, updated)
}

func writeConfigFilePrivileged(path string, content []byte) error {
	tmpF, err := os.CreateTemp("", "hostberry-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := tmpF.Name()
	tmpF.Close()
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, content, 0644); err != nil {
		return err
	}

	if _, err := executeArgv("cp", tmp, path); err != nil {
		return err
	}
	if _, err := executeArgv("chmod", "644", path); err != nil {
		return err
	}
	return nil
}

func mutateHostapdMaxNumSTA(content []byte, enable bool) []byte {
	if enable {
		return []byte(upsertConfigKey(string(content), hostapdMaxNumSTAKey, "1"))
	}
	return []byte(removeConfigKey(string(content), hostapdMaxNumSTAKey))
}

func mutateDnsmasqDHCPRange(content []byte, enable bool) []byte {
	text := string(content)
	if !strings.Contains(text, "dhcp-range=") {
		return content
	}

	start, _, mask, lease := parseDHCPRangeFromConfig(text)
	if start == "" {
		start = defaultSetupClientIP
	}
	if mask == "" {
		mask = defaultDHCPNetmask
	}

	var end string
	if enable {
		// Setup: pool pequeño (.2–.20) y lease corto (2m) para liberar la IP al desconectarse.
		end = setupDHCPRangeEnd
		lease = setupDHCPLeaseTime
	} else {
		// Restaurar rango y lease normales tras el setup.
		end = defaultDHCPRangeEnd
		lease = defaultDHCPLeaseTime
	}

	return []byte(setDHCPRangeLine(text, start, end, mask, lease))
}

func upsertConfigKey(content, key, value string) string {
	lines := strings.Split(content, "\n")
	keyPrefix := key + "="
	found := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, keyPrefix) {
			lines[i] = key + "=" + value
			found = true
			break
		}
	}

	if !found {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		return content + key + "=" + value + "\n"
	}

	return strings.Join(lines, "\n")
}

func removeConfigKey(content, key string) string {
	lines := strings.Split(content, "\n")
	keyPrefix := key + "="
	out := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && strings.HasPrefix(trimmed, keyPrefix) {
			continue
		}
		out = append(out, line)
	}

	return strings.Join(out, "\n")
}

func parseDHCPRangeFromConfig(content string) (start, end, mask, lease string) {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "dhcp-range=") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(trimmed, "dhcp-range="), ",")
		if len(parts) < 2 {
			return
		}
		start = strings.TrimSpace(parts[0])
		end = strings.TrimSpace(parts[1])
		if len(parts) > 2 {
			mask = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			lease = strings.TrimSpace(parts[3])
		}
		return
	}
	return
}

func setDHCPRangeLine(content, start, end, mask, lease string) string {
	lines := strings.Split(content, "\n")
	newLine := fmt.Sprintf("dhcp-range=%s,%s,%s,%s", start, end, mask, lease)
	replaced := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "dhcp-range=") {
			lines[i] = newLine
			replaced = true
			break
		}
	}

	if !replaced {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		return content + newLine + "\n"
	}

	return strings.Join(lines, "\n")
}
