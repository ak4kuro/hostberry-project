package wifi

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"hostberry/internal/auth"
	"hostberry/internal/constants"
	"hostberry/internal/database"
	"hostberry/internal/i18n"
	"hostberry/internal/utils"
)

var interfaceNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)

func validateInterfaceName(interfaceName string) error {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return fmt.Errorf("interfaz WiFi requerida")
	}
	if len(interfaceName) > 32 {
		return fmt.Errorf("nombre de interfaz inválido")
	}
	if !interfaceNameRegex.MatchString(interfaceName) {
		return fmt.Errorf("nombre de interfaz inválido")
	}
	return nil
}

func runSudoSilently(args ...string) error {
	_, err := execPrivilegedOutput(strings.Join(args, " "))
	return err
}

// execPrivilegedOutput ejecuta un comando vía privileged-exec (sin caché; p. ej. escaneos WiFi).
func execPrivilegedOutput(cmd string) (string, error) {
	return execPrivilegedOutputTimeout(cmd, 45*time.Second)
}

func execPrivilegedOutputTimeout(cmd string, timeout time.Duration) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", fmt.Errorf("comando vacío")
	}
	// Este camino no pasa por ExecuteCommandWithTimeout: validar igualmente el
	// allowlist para que un comando mal construido no llegue a privileged-exec.
	if err := utils.ValidateShellCommand(cmd); err != nil {
		return "", fmt.Errorf("comando no permitido: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	base := utils.ExecCommand(cmd)
	c := exec.CommandContext(ctx, base.Path)
	c.Args = base.Args
	c.Env = append(os.Environ(), "SUDO_ASKPASS=/bin/false")
	out, err := c.CombinedOutput()
	return string(out), err
}

const (
	wpaCliPrivilegedTimeout = 8 * time.Second
	iwScanPrivilegedTimeout = 8 * time.Second
	wpaCliScanBudget        = 10 * time.Second
	wpaCliScanBudgetLimited = 10 * time.Second
)

// runPrivilegedCommand ejecuta vía privileged-exec (sudo directo falla bajo ProtectSystem=strict).
func runPrivilegedCommand(args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("comando vacío")
	}
	return execPrivilegedOutput(strings.Join(args, " "))
}

func runPrivilegedCommandFast(args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("comando vacío")
	}
	return execPrivilegedOutputTimeout(strings.Join(args, " "), wpaCliPrivilegedTimeout)
}

// ScanWiFiNetworks escanea redes WiFi con iw y devuelve un mapa con "success", "networks" y "error".
// Si refresh es false, puede devolver resultados en caché recientes (más rápido en el wizard).
func ScanWiFiNetworks(interfaceName string, refresh bool) map[string]interface{} {
	return ScanWiFiNetworksBand(interfaceName, refresh, "")
}

// resolveScanBand decide qué banda escanear. Prioridad: banda explícita pedida por el cliente,
// luego la preferida del asistente (radio única: el AP sigue en 2.4 pero la radio puede escanear
// 5 GHz off-channel), y por último la banda real de la radio en AP+STA.
func resolveScanBand(interfaceName, bandOverride string) string {
	switch strings.TrimSpace(bandOverride) {
	case band24GHz, "2.4GHz", "24":
		return band24GHz
	case band5GHz, "5GHz", "5G":
		return band5GHz
	}
	if database.DB != nil && auth.IsInitialSetupPending() {
		if pref := GetWizardPreferredBand(); pref != "" {
			return pref
		}
		return band24GHz
	}
	return operatingBandForScan(interfaceName)
}

// ScanWiFiNetworksBand escanea redes filtrando por banda. bandOverride ("2.4"/"5") fuerza la banda;
// vacío usa la preferida del asistente (si está en setup) o la banda real de la radio en AP+STA.
func ScanWiFiNetworksBand(interfaceName string, refresh bool, bandOverride string) map[string]interface{} {
	result := make(map[string]interface{})
	networks := []map[string]interface{}{}
	if interfaceName == "" {
		interfaceName = constants.DefaultWiFiInterface
	}

	if err := validateInterfaceName(interfaceName); err != nil {
		result["success"] = false
		result["error"] = "Nombre de interfaz inválido"
		result["networks"] = networks
		return result
	}

	scanBand := resolveScanBand(interfaceName, bandOverride)

	if !refresh {
		if cached := getCachedScanNetworks(interfaceName, scanBand); len(cached) > 0 {
			result["success"] = true
			result["networks"] = cached
			result["count"] = len(cached)
			result["cached"] = true
			return result
		}
	}

	scanOpMu.Lock()
	defer scanOpMu.Unlock()

	if !refresh {
		if cached := getCachedScanNetworks(interfaceName, scanBand); len(cached) > 0 {
			result["success"] = true
			result["networks"] = cached
			result["count"] = len(cached)
			result["cached"] = true
			return result
		}
	}

	prepareWiFiInterfaceForScan(interfaceName)

	socketDir := wpaSupplicantSocketDir(interfaceName)

	// En AP+STA (brcmfmac) wpa_cli escanea bien con hostapd activo; iw scan trigger suele ser
	// rechazado ("command rejected") y el dump cacheado puede filtrarse a 0 redes.
	if concurrentAPInterfacePresent() && socketDir != "" {
		networks = readWpaCliScanNetworks(interfaceName, socketDir, scanBand, true)
		if len(networks) == 0 {
			time.Sleep(400 * time.Millisecond)
			networks = readWpaCliScanNetworks(interfaceName, socketDir, scanBand, true)
		}
	}

	if len(networks) == 0 && concurrentAPInterfacePresent() {
		if scanOut, err := runIwScanFast(interfaceName); err == nil {
			networks = parseIwScanOutput(scanOut, scanBand)
		}
	}

	// Sin AP concurrente, o si lo anterior falló: wpa_cli sin socket previo o iw completo.
	if socketDir == "" {
		socketDir = wpaSupplicantSocketDir(interfaceName)
	}
	if len(networks) == 0 && socketDir != "" && !concurrentAPInterfacePresent() {
		networks = readWpaCliScanNetworks(interfaceName, socketDir, scanBand, false)
		if len(networks) == 0 {
			networks = readWpaCliScanNetworks(interfaceName, socketDir, scanBand, true)
		}
		// Reintento automático: en AP+STA el primer escaneo puede salir vacío si la radio
		// estaba ocupada por el AP; reintentamos una vez antes de dar error.
		if len(networks) == 0 {
			time.Sleep(500 * time.Millisecond)
			networks = readWpaCliScanNetworks(interfaceName, socketDir, scanBand, true)
		}
	}

	if len(networks) == 0 && scanBand != "" {
		// Fallback: escaneo completo si el limitado por banda no devolvió nada (p. ej. hostapd.conf desactualizado).
		if socketDir != "" {
			networks = readWpaCliScanNetworks(interfaceName, socketDir, "", true)
			networks = filterScanNetworksByBand(networks, scanBand)
		}
		if len(networks) == 0 {
			if scanOut, err := runIwScanFast(interfaceName); err == nil {
				networks = parseIwScanOutput(scanOut, scanBand)
			}
		}
	} else if len(networks) == 0 && scanBand == "" {
		if scanOut, err := runIwScanFast(interfaceName); err == nil {
			networks = parseIwScanOutput(scanOut, "")
		}
	}

	if len(networks) > 0 {
		setCachedScanNetworks(interfaceName, scanBand, networks)
		result["success"] = true
		result["networks"] = networks
		result["count"] = len(networks)
		return result
	}

	result["success"] = false
	result["error"] = "No se encontraron redes WiFi cercanas. Comprueba que la antena WiFi esté activa e inténtalo de nuevo."
	result["networks"] = networks
	result["count"] = 0
	return result
}

func prepareWiFiInterfaceForScan(interfaceName string) {
	_, _ = execPrivilegedOutputTimeout("rfkill unblock wifi 2>/dev/null || true", 2*time.Second)
	_, _ = execPrivilegedOutputTimeout(fmt.Sprintf("ip link set %s up", interfaceName), 2*time.Second)
}

// StartScanPrefetch lanza, tras un breve margen para que la radio se asiente, un escaneo en
// segundo plano que calienta la caché. Así el primer "Buscar redes" del wizard es instantáneo.
func StartScanPrefetch() {
	go func() {
		time.Sleep(6 * time.Second)
		PrefetchScan()
	}()
}

// PrefetchScan calienta la caché de redes si no hay resultados recientes.
func PrefetchScan() {
	iface := detectWiFiInterface()
	if iface == "" {
		iface = constants.DefaultWiFiInterface
	}
	if getCachedScanNetworks(iface, resolveScanBand(iface, "")) != nil {
		return
	}
	_ = ScanWiFiNetworks(iface, true)
}

func isWiFiScanBusy(err error, output string) bool {
	text := strings.ToLower(output)
	if strings.Contains(text, "resource busy") || strings.Contains(text, "device or resource busy") {
		return true
	}
	if err != nil {
		es := strings.ToLower(err.Error())
		return strings.Contains(es, "busy") || strings.Contains(es, "exit status 240")
	}
	return false
}

func runIwScanFast(interfaceName string) (string, error) {
	trigOut, trigErr := execPrivilegedOutputTimeout(fmt.Sprintf("iw dev %s scan trigger", interfaceName), iwScanPrivilegedTimeout)
	trigText := strings.ToLower(strings.TrimSpace(trigOut))
	if trigErr != nil || strings.Contains(trigText, "rejected") || strings.Contains(trigText, "busy") {
		return "", fmt.Errorf("iw scan trigger no disponible: %v %s", trigErr, strings.TrimSpace(trigOut))
	}
	time.Sleep(1500 * time.Millisecond)
	dumpOut, dumpErr := execPrivilegedOutputTimeout(fmt.Sprintf("iw dev %s scan dump", interfaceName), iwScanPrivilegedTimeout)
	if dumpErr == nil && strings.TrimSpace(dumpOut) != "" {
		return dumpOut, nil
	}
	if dumpErr != nil {
		return dumpOut, dumpErr
	}
	return "", fmt.Errorf("sin resultados de escaneo")
}

func runIwScan(interfaceName string) (string, error) {
	scanCmd := fmt.Sprintf("iw dev %s scan", interfaceName)
	scanOut, err := execPrivilegedOutput(scanCmd)
	if err == nil && strings.TrimSpace(scanOut) != "" {
		return scanOut, nil
	}
	lastErr := err

	if _, trigErr := execPrivilegedOutput(fmt.Sprintf("iw dev %s scan trigger", interfaceName)); trigErr != nil {
		if lastErr == nil {
			lastErr = trigErr
		}
	}
	time.Sleep(4 * time.Second)

	dumpOut, dumpErr := execPrivilegedOutput(fmt.Sprintf("iw dev %s scan dump", interfaceName))
	if dumpErr == nil && strings.TrimSpace(dumpOut) != "" {
		return dumpOut, nil
	}

	if lastErr != nil {
		return scanOut, lastErr
	}
	if dumpErr != nil {
		return dumpOut, dumpErr
	}
	return scanOut, fmt.Errorf("sin resultados de escaneo")
}

func parseIwScanOutput(raw string, band string) []map[string]interface{} {
	networks := []map[string]interface{}{}
	lines := strings.Split(raw, "\n")
	currentNetwork := make(map[string]interface{})
	seenNetworks := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BSS ") {
			if len(currentNetwork) > 0 {
				if ssid, ok := currentNetwork["ssid"].(string); ok && ssid != "" && isScanNetworkOnBand(currentNetwork, band) {
					if !seenNetworks[ssid] {
						seenNetworks[ssid] = true
						networks = append(networks, currentNetwork)
					}
				}
			}
			currentNetwork = make(map[string]interface{})
			currentNetwork["security"] = "Open"
			currentNetwork["signal"] = 0
		} else if strings.HasPrefix(line, "SSID:") {
			ssid := strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
			if ssid != "" {
				currentNetwork["ssid"] = ssid
			}
		} else if strings.Contains(line, "signal:") {
			re := regexp.MustCompile(`signal:\s*(-?\d+\.?\d*)\s*dBm?`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				if n, e := parseFloat(matches[1]); e == nil {
					if n > 0 {
						n = -n
					}
					if n >= -100 && n <= -30 {
						currentNetwork["signal"] = int(n)
					}
				}
			}
		} else if strings.Contains(line, "freq:") {
			re := regexp.MustCompile(`freq:\s*(\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				if freq, e := parseInt(matches[1]); e == nil {
					currentNetwork["frequency"] = freq
					channel := freqToChannel(freq)
					if channel > 0 {
						currentNetwork["channel"] = channel
					}
				}
			}
		} else if strings.Contains(line, "RSN:") {
			if strings.Contains(line, "WPA3") || strings.Contains(line, "SAE") {
				currentNetwork["security"] = "WPA3"
			} else {
				currentNetwork["security"] = "WPA2"
			}
		} else if strings.Contains(line, "WPA:") {
			currentNetwork["security"] = "WPA2"
		}
	}

	if len(currentNetwork) > 0 {
		if ssid, ok := currentNetwork["ssid"].(string); ok && ssid != "" && !seenNetworks[ssid] && isScanNetworkOnBand(currentNetwork, band) {
			networks = append(networks, currentNetwork)
		}
	}
	return networks
}

func wpaSupplicantSocketDir(interfaceName string) string {
	dirs := []string{"/run/wpa_supplicant", "/var/run/wpa_supplicant", WpaSupplicantCtrlDir}
	for _, dir := range dirs {
		if _, err := os.Stat(filepath.Join(dir, interfaceName)); err == nil {
			return dir
		}
	}
	return ""
}

func readWpaCliScanNetworks(interfaceName, socketDir string, band string, forceScan bool) []map[string]interface{} {
	if socketDir == "" {
		return nil
	}

	fetch := func() []map[string]interface{} {
		out, _ := runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "scan_results")
		if !strings.Contains(out, "\t") {
			return nil
		}
		if nets := parseWpaCliScanResults(out, band); len(nets) > 0 {
			return nets
		}
		// Resultados cacheados de otra banda: re-filtrar sin descartar el parseo por banda en línea.
		if band != "" {
			return filterScanNetworksByBand(parseWpaCliScanResults(out, ""), band)
		}
		return nil
	}

	if !forceScan {
		return fetch()
	}

	budget := wpaCliScanBudget
	scanArgs := []string{"wpa_cli", "-i", interfaceName, "-p", socketDir, "scan"}
	restricted := false
	if freqArg := scanFreqArgForBand(band); freqArg != "" {
		// Limitar el escaneo a la banda activa (2.4 o 5 GHz) acelera la búsqueda en AP+STA.
		scanArgs = append(scanArgs, freqArg)
		budget = wpaCliScanBudgetLimited
		restricted = true
	}

	deadline := time.Now().Add(budget)
	_, _ = runPrivilegedCommandFast(scanArgs...)
	for time.Now().Before(deadline) {
		if nets := fetch(); len(nets) > 0 {
			return nets
		}
		time.Sleep(250 * time.Millisecond)
	}

	// Fallback de fiabilidad: un escaneo restringido a una banda DISTINTA a la que retiene el AP
	// (p. ej. 5 GHz mientras el AP "hostberry" sigue en 2.4 GHz en radio única) suele ser rechazado
	// por brcmfmac y devuelve 0 redes — eso es lo que el usuario percibe como "el cambio de banda
	// falla". Reintentamos con un escaneo COMPLETO (sin freq=), que el driver sí acepta con el AP
	// activo, y filtramos el resultado por la banda elegida (fetch ya aplica el filtro de banda).
	if restricted {
		fullArgs := []string{"wpa_cli", "-i", interfaceName, "-p", socketDir, "scan"}
		_, _ = runPrivilegedCommandFast(fullArgs...)
		fullDeadline := time.Now().Add(wpaCliScanBudget)
		for time.Now().Before(fullDeadline) {
			if nets := fetch(); len(nets) > 0 {
				return nets
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	return nil
}

// scan24GHzFreqArg construye el argumento freq= para wpa_cli/SCAN con los canales 2.4 GHz (1-13).
func scan24GHzFreqArg() string {
	freqs := make([]string, 0, 13)
	for ch := 1; ch <= 13; ch++ {
		freqs = append(freqs, fmt.Sprintf("%d", 2412+(ch-1)*5))
	}
	return "freq=" + strings.Join(freqs, ",")
}

func scanWiFiWithWpaCli(interfaceName string, band string, forceScan bool) []map[string]interface{} {
	socketDir := wpaSupplicantSocketDir(interfaceName)
	if socketDir == "" {
		socketDir = findWorkingWpaSupplicantSocket(interfaceName)
	}
	if socketDir == "" {
		return nil
	}
	return readWpaCliScanNetworks(interfaceName, socketDir, band, forceScan)
}

func parseWpaCliScanResults(out string, band string) []map[string]interface{} {
	networks := []map[string]interface{}{}
	seen := make(map[string]bool)
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		freq, freqErr := parseInt(strings.TrimSpace(fields[1]))
		if band != "" && freqErr == nil {
			netBand := bandFromFrequency(freq)
			if netBand != "" && netBand != band {
				continue
			}
		}
		ssid := strings.TrimSpace(fields[4])
		if ssid == "" || seen[ssid] {
			continue
		}
		seen[ssid] = true
		net := map[string]interface{}{
			"ssid":     ssid,
			"security": "Open",
			"signal":   0,
		}
		if freqErr == nil && freq > 0 {
			net["frequency"] = freq
			if ch := freqToChannel(freq); ch > 0 {
				net["channel"] = ch
			}
		}
		if signal, e := parseInt(strings.TrimSpace(fields[2])); e == nil {
			net["signal"] = signal
		}
		flags := strings.ToUpper(fields[3])
		switch {
		case strings.Contains(flags, "WPA3") || strings.Contains(flags, "SAE"):
			net["security"] = "WPA3"
		case strings.Contains(flags, "WPA2") || strings.Contains(flags, "WPA"):
			net["security"] = "WPA2"
		}
		networks = append(networks, net)
	}
	return networks
}

func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func freqToChannel(freq int) int {
	if freq >= 2412 && freq <= 2484 {
		return (freq-2412)/5 + 1
	}
	if freq >= 5000 && freq <= 5825 {
		return (freq - 5000) / 5
	}
	if freq >= 5955 && freq <= 7115 {
		return (freq - 5955) / 5
	}
	return 0
}

// concurrentAPInterfacePresent indica AP+STA (p. ej. ap0 + wlan0 en la misma radio del Pi).
func concurrentAPInterfacePresent() bool {
	_, err := os.Stat("/sys/class/net/ap0")
	return err == nil
}

func is5GHzFrequency(freq int) bool {
	return freq >= 5000 && freq < 5955
}

func is24GHzFrequency(freq int) bool {
	return freq >= 2412 && freq <= 2484
}

// scanResultFrequencyForSSID devuelve la frecuencia (MHz) del BSS con mejor señal para ssid,
// leída de los resultados de escaneo de wpa_cli. Sirve para mover el AP al canal de la red
// objetivo (CSA) antes de conectar la STA en modo AP+STA de radio única.
func scanResultFrequencyForSSID(interfaceName, socketDir, ssid, band string) int {
	if socketDir == "" || ssid == "" {
		return 0
	}
	out, _ := runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "scan_results")
	bestFreq := 0
	bestSignal := -1000
	for i, line := range strings.Split(out, "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 || strings.TrimSpace(fields[4]) != ssid {
			continue
		}
		freq, err := parseInt(strings.TrimSpace(fields[1]))
		if err != nil {
			continue
		}
		// Respetar la banda elegida en el wizard (p. ej. no usar 2.4 GHz si el usuario eligió 5 GHz).
		if band == band5GHz && !is5GHzFrequency(freq) {
			continue
		}
		if band == band24GHz && !is24GHzFrequency(freq) {
			continue
		}
		signal, _ := parseInt(strings.TrimSpace(fields[2]))
		if signal > bestSignal {
			bestSignal = signal
			bestFreq = freq
		}
	}
	return bestFreq
}

// scanResultSignalForSSID devuelve la mejor señal (dBm) del SSID en los resultados de escaneo y si
// se encontró algún BSS en la banda indicada. Sirve para diagnosticar fallos de conexión: si no se
// encuentra, la red está fuera de alcance/apagada; si la señal es muy baja, está demasiado lejos.
func scanResultSignalForSSID(interfaceName, socketDir, ssid, band string) (signal int, found bool) {
	if socketDir == "" || ssid == "" {
		return 0, false
	}
	out, _ := runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "scan_results")
	best := -1000
	for i, line := range strings.Split(out, "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 || strings.TrimSpace(fields[4]) != ssid {
			continue
		}
		freq, err := parseInt(strings.TrimSpace(fields[1]))
		if err != nil {
			continue
		}
		if band == band5GHz && !is5GHzFrequency(freq) {
			continue
		}
		if band == band24GHz && !is24GHzFrequency(freq) {
			continue
		}
		sig, _ := parseInt(strings.TrimSpace(fields[2]))
		if !found || sig > best {
			best = sig
			found = true
		}
	}
	if !found {
		return 0, false
	}
	return best, true
}

func is5GHzScanNetwork(net map[string]interface{}) bool {
	if freq, ok := net["frequency"].(int); ok && is5GHzFrequency(freq) {
		return true
	}
	if ch, ok := net["channel"].(int); ok && ch > 14 {
		return true
	}
	return false
}

// ToggleWiFi habilita o deshabilita la interfaz WiFi (rfkill + ip link).
func ToggleWiFi(interfaceName string, enable bool) map[string]interface{} {
	result := make(map[string]interface{})
	if interfaceName == "" {
		interfaceName = constants.DefaultWiFiInterface
	}

	if err := validateInterfaceName(interfaceName); err != nil {
		result["success"] = false
		result["error"] = "Nombre de interfaz inválido"
		result["enabled"] = false
		return result
	}

	if enable {
		if err := runSudoSilently("rfkill", "unblock", "wifi"); err != nil {
			result["success"] = false
			result["error"] = "No se pudo desbloquear WiFi (rfkill)"
			result["enabled"] = false
			return result
		}
		if err := runSudoSilently("ip", "link", "set", interfaceName, "up"); err != nil {
			result["success"] = false
			result["error"] = "No se pudo activar la interfaz WiFi (ip link)"
			result["enabled"] = false
			return result
		}

		result["success"] = true
		result["message"] = "WiFi habilitado"
		result["enabled"] = true
	} else {
		if err := runSudoSilently("rfkill", "block", "wifi"); err != nil {
			result["success"] = false
			result["error"] = "No se pudo bloquear WiFi (rfkill)"
			result["enabled"] = false
			return result
		}
		if err := runSudoSilently("ip", "link", "set", interfaceName, "down"); err != nil {
			result["success"] = false
			result["error"] = "No se pudo desactivar la interfaz WiFi (ip link)"
			result["enabled"] = false
			return result
		}

		result["success"] = true
		result["message"] = "WiFi deshabilitado"
		result["enabled"] = false
	}
	return result
}

// VerifyWiFiPassword verifica si una contraseña WiFi es correcta sin conectar realmente a la red.
// Usa wpa_supplicant para validar la credencial temporalmente.
func VerifyWiFiPassword(ssid, password, interfaceName, country string) map[string]interface{} {
	result := make(map[string]interface{})
	result["success"] = false
	result["error"] = ""
	result["auth_failed"] = false
	country = sanitizeCountryCode(country)

	if ssid == "" {
		result["error"] = "SSID requerido"
		return result
	}
	if interfaceName == "" {
		interfaceName = constants.DefaultWiFiInterface
	}

	if err := validateInterfaceName(interfaceName); err != nil {
		result["error"] = "Nombre de interfaz inválido"
		return result
	}

	_ = runSudoSilently("rfkill", "unblock", "wifi")
	_ = runSudoSilently("ip", "link", "set", interfaceName, "up")

	// Radio única AP+STA: si el AP (hostapd) está activo en esta radio, debemos liberarla para poder
	// escanear y asociar en otra banda/canal (incluido DFS, donde la STA actúa solo como cliente). Si
	// no lo hacemos, la asociación nunca completa y una contraseña correcta se reporta como errónea.
	// Tras verificar restauramos el AP para no dejar caído el portal del asistente.
	apWasActive := concurrentAPInterfacePresent() && hostapdServiceActive()
	if apWasActive {
		_, _ = execPrivilegedOutput("systemctl stop hostapd")
		time.Sleep(700 * time.Millisecond)
	}
	defer func() {
		if apWasActive {
			restoreAPAfterConnect(interfaceName)
		}
	}()

	// Crear directorio de config temporal si no existe
	if _, err := os.Stat(WpaSupplicantConfigDir); os.IsNotExist(err) {
		_ = runSudoSilently("mkdir", "-p", WpaSupplicantConfigDir)
		_ = runSudoSilently("chmod", "755", WpaSupplicantConfigDir)
	}

	var networkBlock string
	securityType := "WPA2"
	if password != "" {
		securityType = detectSSIDSecurityFromWpaCli(interfaceName, ssid)
	}

	escape := wpaConfEscape

	if password != "" && strings.EqualFold(securityType, "WPA3") {
		networkBlock = fmt.Sprintf("network={\n\tssid=\"%s\"\n\tkey_mgmt=SAE\n\tsae_password=\"%s\"\n}", escape(ssid), escape(password))
	} else if password != "" {
		cmd := exec.Command("wpa_passphrase", ssid, password)
		cmd.Env = append(os.Environ(), "LANG=C")
		out, err := cmd.Output()
		if err != nil || !strings.Contains(string(out), "network=") {
			result["error"] = "Contraseña incorrecta. Verifica el SSID y la contraseña."
			return result
		}
		networkBlock = strings.TrimSpace(string(out))
	} else {
		networkBlock = fmt.Sprintf("network={\n\tssid=\"%s\"\n\tkey_mgmt=NONE\n}", escape(ssid))
	}

	// Crear config temporal para verificación (nombre aleatorio: la ruta
	// predecible en /tmp permitía ataques de symlink).
	tmpF, tmpErr := os.CreateTemp("", "wpa-verify-*.conf")
	if tmpErr != nil {
		result["error"] = fmt.Sprintf("Error al crear config temporal: %v", tmpErr)
		return result
	}
	tempConfigPath := tmpF.Name()
	tmpF.Close()
	defer os.Remove(tempConfigPath)

	configContent := fmt.Sprintf("ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev\nupdate_config=1\ncountry=%s\n\n%s", country, networkBlock)

	if err := os.WriteFile(tempConfigPath, []byte(configContent), 0600); err != nil {
		result["error"] = fmt.Sprintf("Error al crear config temporal: %v", err)
		return result
	}

	// Copiar a ubicación con permisos
	_, err := execPrivilegedOutput(fmt.Sprintf("cp %s %s", tempConfigPath, WpaSupplicantConfigDir+"/"+filepath.Base(tempConfigPath)))
	if err != nil {
		result["error"] = fmt.Sprintf("Error al copiar config: %v", err)
		return result
	}
	defer execPrivilegedOutput(fmt.Sprintf("rm -f %s/%s", WpaSupplicantConfigDir, filepath.Base(tempConfigPath)))

	finalConfigPath := WpaSupplicantConfigDir + "/" + filepath.Base(tempConfigPath)

	// Intentar conectar temporalmente solo para verificar
	socketDir := findWorkingWpaSupplicantSocket(interfaceName)
	if socketDir == "" {
		// Iniciar wpa_supplicant temporalmente
		activeRunDir = "/run/wpa_supplicant"
		stopWpaSupplicant(interfaceName)
		time.Sleep(500 * time.Millisecond)

		if err := startWpaSupplicant(interfaceName, finalConfigPath, "/run/wpa_supplicant"); err != nil {
			result["error"] = fmt.Sprintf("Error al iniciar wpa_supplicant: %v", err)
			return result
		}
		defer stopWpaSupplicant(interfaceName)

		socketDir, err = waitForWpaCliConnection(interfaceName, 5)
		if err != nil {
			result["error"] = "No se pudo conectar con wpa_supplicant"
			return result
		}
	}

	// Agregar red temporalmente
	addCmd := []string{"wpa_cli", "-i", interfaceName, "-p", socketDir, "add_network"}
	out, err := runPrivilegedCommandFast(addCmd...)
	if err != nil {
		result["error"] = "Error al agregar red temporal"
		return result
	}
	netID := strings.TrimSpace(out)
	if netID == "" || netID == "FAIL" {
		result["error"] = "Error al crear red temporal"
		return result
	}

	// Configurar SSID
	_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "set_network", netID, "ssid", fmt.Sprintf("\"%s\"", escape(ssid)))

	// Configurar contraseña si existe
	if password != "" {
		if strings.EqualFold(securityType, "WPA3") {
			_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "set_network", netID, "key_mgmt", "SAE")
			_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "set_network", netID, "sae_password", fmt.Sprintf("\"%s\"", escape(password)))
		} else {
			_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "set_network", netID, "psk", fmt.Sprintf("\"%s\"", escape(password)))
		}
	} else {
		_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "set_network", netID, "key_mgmt", "NONE")
	}

	// Habilitar red e intentar asociar para verificar la credencial.
	_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "enable_network", netID)
	_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "select_network", netID)
	_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "reconnect")

	// La asociación + handshake WPA en radio única (la antena debe abandonar el canal del AP,
	// escanear y asociar) puede tardar varios segundos: esperar solo 3 s provocaba falsos negativos
	// (una clave correcta se reportaba como "Contraseña incorrecta" y el asistente no avanzaba).
	// Sondeamos el estado durante una ventana amplia y detectamos pronto el fallo de autenticación
	// (clave incorrecta) sin tener que esperar al timeout completo. Misma lógica que ConnectWiFi.
	completed := false
	authFailed := false
	sawHandshake := false
	handshakeDrops := 0
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		statusOut, _ := runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "status")
		// Solo wpa_state=COMPLETED garantiza que el handshake WPA terminó; ASSOCIATED puede
		// aparecer con una contraseña incorrecta antes de que falle la autenticación.
		if strings.Contains(statusOut, "wpa_state=COMPLETED") {
			completed = true
			break
		}
		if password == "" {
			continue
		}
		// Detección temprana directa (algunos drivers exponen el motivo en el estado).
		if strings.Contains(statusOut, "AUTH_FAILED") || strings.Contains(statusOut, "WRONG_KEY") {
			authFailed = true
			break
		}
		// Detección por oscilación del handshake: con clave errónea wpa_supplicant alcanza el
		// 4-way handshake y vuelve a SCANNING/DISCONNECTED sin completar, de forma repetida.
		if strings.Contains(statusOut, "wpa_state=4WAY_HANDSHAKE") {
			sawHandshake = true
		} else if sawHandshake && (strings.Contains(statusOut, "wpa_state=SCANNING") || strings.Contains(statusOut, "wpa_state=DISCONNECTED")) {
			handshakeDrops++
			sawHandshake = false
			if handshakeDrops >= 2 {
				authFailed = true
				break
			}
		}
		if handshakeDrops >= 1 && i >= 10 && i%4 == 0 && wifiAuthFailureDetected(interfaceName, statusOut) {
			authFailed = true
			break
		}
	}

	// Eliminar red temporal: la conexión definitiva se difiere al finalizar el asistente.
	_, _ = runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", socketDir, "remove_network", netID)

	if completed {
		result["success"] = true
		result["message"] = "Contraseña verificada correctamente"
	} else if authFailed {
		result["auth_failed"] = true
		result["error"] = "Contraseña incorrecta. Verifica la clave de «" + ssid + "» e inténtalo de nuevo."
	} else {
		result["error"] = "No se pudo verificar la contraseña de «" + ssid + "». Comprueba que la red esté dentro de alcance e inténtalo de nuevo."
	}

	return result
}

// ConnectWiFi conecta a una red WiFi; usa helpers de wpa_supplicant (startWpaSupplicant, waitForWpaCliConnection, etc.).
func ConnectWiFi(ssid, password, interfaceName, country, user string) map[string]interface{} {
	result := make(map[string]interface{})
	result["success"] = false
	result["error"] = ""
	country = sanitizeCountryCode(country)
	if ssid == "" {
		result["error"] = "SSID requerido"
		return result
	}
	if interfaceName == "" {
		interfaceName = constants.DefaultWiFiInterface
	}

	if err := validateInterfaceName(interfaceName); err != nil {
		result["error"] = "Nombre de interfaz inválido"
		return result
	}

	_ = runSudoSilently("rfkill", "unblock", "wifi")
	_ = runSudoSilently("ip", "link", "set", interfaceName, "up")

	// Crear directorio de config si no existe
	if _, err := os.Stat(WpaSupplicantConfigDir); os.IsNotExist(err) {
		_ = runSudoSilently("mkdir", "-p", WpaSupplicantConfigDir)
		_ = runSudoSilently("chmod", "755", WpaSupplicantConfigDir)
	}

	var networkBlock string

	// Detectar tipo de seguridad sin escaneo completo (evita bloquear la radio ~15s).
	securityType := "WPA2"
	if password != "" {
		securityType = detectSSIDSecurityFromWpaCli(interfaceName, ssid)
	}

	escape := wpaConfEscape

	if password != "" && strings.EqualFold(securityType, "WPA3") {
		// WPA3 Personal (SAE)
		networkBlock = fmt.Sprintf("network={\n\tssid=\"%s\"\n\tkey_mgmt=SAE\n\tsae_password=\"%s\"\n}", escape(ssid), escape(password))
	} else if password != "" {
		// WPA2/PSK
		cmd := exec.Command("wpa_passphrase", ssid, password)
		cmd.Env = append(os.Environ(), "LANG=C")
		out, err := cmd.Output()
		if err != nil || !strings.Contains(string(out), "network=") {
			result["error"] = "Error al generar la clave PSK. Verifica el SSID y la contraseña."
			return result
		}
		networkBlock = strings.TrimSpace(string(out))
	} else {
		networkBlock = fmt.Sprintf("network={\n\tssid=\"%s\"\n\tkey_mgmt=NONE\n}", escape(ssid))
	}

	runDir := WpaSupplicantCtrlDir
	if err := os.MkdirAll(runDir, 0770); err != nil {
		result["error"] = fmt.Sprintf("no se pudo preparar el socket de control WiFi: %v", err)
		return result
	}

	configContent := fmt.Sprintf("ctrl_interface=DIR=%s GROUP=netdev\nupdate_config=1\ncountry=%s\n\n%s", runDir, country, networkBlock)
	wpaConfigPath, err := writeWpaSupplicantConfig(interfaceName, configContent)
	if err != nil {
		result["error"] = err.Error()
		log.Printf("ConnectWiFi config error (%s): %v", ssid, err)
		return result
	}

	if socketDir := findWorkingWpaSupplicantSocket(interfaceName); socketDir != "" {
		log.Printf("ConnectWiFi: usando wpa_supplicant del sistema (%s)", socketDir)
		return connectWiFiViaWpaCli(socketDir, interfaceName, ssid, password, securityType, escape)
	}

	if dbusWpaSupplicantRunning() {
		for attempt := 0; attempt < 20; attempt++ {
			time.Sleep(500 * time.Millisecond)
			if socketDir := findWorkingWpaSupplicantSocket(interfaceName); socketDir != "" {
				log.Printf("ConnectWiFi: wpa_supplicant dbus disponible tras espera (%s)", socketDir)
				return connectWiFiViaWpaCli(socketDir, interfaceName, ssid, password, securityType, escape)
			}
		}
		result["error"] = "El gestor WiFi del sistema no responde. Espera unos segundos y vuelve a intentar."
		return result
	}

	activeRunDir = runDir
	stopWpaSupplicant(interfaceName)
	time.Sleep(1 * time.Second)

	if err := startWpaSupplicant(interfaceName, wpaConfigPath, runDir); err != nil {
		if socketDir := findWorkingWpaSupplicantSocket(interfaceName); socketDir != "" {
			log.Printf("ConnectWiFi: fallback a wpa_supplicant del sistema (%s)", socketDir)
			return connectWiFiViaWpaCli(socketDir, interfaceName, ssid, password, securityType, escape)
		}
		result["error"] = err.Error()
		return result
	}

	socketDir, err := waitForWpaCliConnection(interfaceName, 10)
	if err != nil {
		result["error"] = "wpa_cli no puede comunicarse con wpa_supplicant. Verifica permisos del socket."
		return result
	}

	return connectWiFiViaWpaCli(socketDir, interfaceName, ssid, password, securityType, escape)
}

// AutoConnectToLastNetwork intenta conectarse automáticamente a la última red WiFi conectada
func AutoConnectToLastNetwork(interfaceName string) {
	if interfaceName == "" {
		interfaceName = constants.DefaultWiFiInterface
	}

	i18n.LogTf("logs.wifi_auto_connect_start", interfaceName)

	cmd := exec.Command("ip", "link", "show", interfaceName)
	if err := cmd.Run(); err != nil {
		i18n.LogTf("logs.wifi_interface_not_exists", interfaceName)
		return
	}

	// Activar switch y WiFi
	i18n.LogT("logs.wifi_activating")
	_, _ = utils.ExecuteArgv("rfkill", "unblock", "wifi")
	_, _ = utils.ExecuteArgv("ip", "link", "set", interfaceName, "up")
	time.Sleep(1 * time.Second)

	// Intentar reconectar con wpa_cli si wpa_supplicant está corriendo
	i18n.LogT("logs.wifi_searching_network")

	socketDirs := WpaSocketDirs
	var workingSocketDir string
	var useGlobalSocket bool

	for _, dir := range socketDirs {
		socketPath := fmt.Sprintf("%s/%s", dir, interfaceName)
		if _, err := os.Stat(socketPath); err == nil {
			workingSocketDir = dir
			i18n.LogTf("logs.wifi_socket_interface_found", socketPath)
			break
		}
	}

	if workingSocketDir == "" {
		for _, dir := range socketDirs {
			globalSocket := fmt.Sprintf("%s/global", dir)
			if _, err := os.Stat(globalSocket); err == nil {
				workingSocketDir = dir
				useGlobalSocket = true
				i18n.LogTf("logs.wifi_socket_global_found", globalSocket)
				break
			}
		}
	}

	if workingSocketDir != "" {
		i18n.LogT("logs.wifi_wpa_running")

		runWpaCli := func(args ...string) (string, error) {
			args = quoteWpaCliSetNetworkValue(args...)
			var base []string
			if useGlobalSocket {
				base = []string{"wpa_cli", "-g", workingSocketDir, "-i", interfaceName}
			} else {
				base = []string{"wpa_cli", "-i", interfaceName, "-p", workingSocketDir}
			}
			out, err := runPrivilegedCommand(append(base, args...)...)
			return strings.TrimSpace(out), err
		}

		statusOut, err := runWpaCli("status")
		if strings.Contains(statusOut, "wpa_state=COMPLETED") {
			i18n.LogT("logs.wifi_already_connected")
			go func() {
				if ip := ifaceIPv4(interfaceName); strings.TrimSpace(ip) == "" {
					startDHCPForIface(interfaceName)
				}
				EnsureAPChannelAligned(interfaceName)
			}()
			return
		}
		if err == nil {
			listOut, _ := runWpaCli("list_networks")
			if listOut != "" {
				lines := strings.Split(listOut, "\n")
				if len(lines) > 1 {
					var netID string
					for i, line := range lines {
						if i == 0 {
							continue
						}
						fields := strings.Fields(line)
						if len(fields) >= 1 {
							if len(fields) >= 4 && fields[3] == "[CURRENT]" {
								netID = fields[0]
								break
							} else if netID == "" && len(fields) >= 2 {
								netID = fields[0]
							}
						}
					}

					if netID != "" {
						i18n.LogTf("logs.wifi_reconnecting", netID)
						runWpaCli("enable_network", netID)
						runWpaCli("select_network", netID)
						runWpaCli("reconnect")

						for attempt := 0; attempt < 5; attempt++ {
							time.Sleep(1 * time.Second)
							statusOut2, _ := runWpaCli("status")
							if strings.Contains(statusOut2, "wpa_state=COMPLETED") {
								i18n.LogT("logs.wifi_reconnected")
								go func() {
									requestWiFiDHCP(interfaceName)
									EnsureAPChannelAligned(interfaceName)
								}()
								return
							}
						}
						i18n.LogT("logs.wifi_reconnect_started")
					}
				}
			}
		}
	} else {
		i18n.LogT("logs.wifi_wpa_not_running")
	}

	// Si no hay wpa_supplicant corriendo o no se pudo reconectar,
	// buscar el último archivo de configuración y conectarse usando ConnectWiFi
	i18n.LogT("logs.wifi_searching_config")
	ssid, _, err := getLastConnectedNetwork(interfaceName)
	if err != nil {
		i18n.LogTf("logs.wifi_config_not_found", err)
		i18n.LogT("logs.wifi_trying_other_way")

		// Último recurso: buscar cualquier config reciente
		configDirs := []string{WpaSupplicantRuntimeConfigDir, WpaSupplicantConfigDir, WpaSupplicantAltConfigDir}
		for _, configDir := range configDirs {
			configFiles, err := os.ReadDir(configDir)
			if err != nil {
				continue
			}
			var lastFile os.DirEntry
			var lastTime time.Time
			for _, file := range configFiles {
				if strings.HasPrefix(file.Name(), "wpa_supplicant-") && strings.HasSuffix(file.Name(), ".conf") {
					info, err := file.Info()
					if err == nil && info.ModTime().After(lastTime) {
						lastTime = info.ModTime()
						lastFile = file
					}
				}
			}
			if lastFile != nil {
				configPath := fmt.Sprintf("%s/%s", configDir, lastFile.Name())
				contentBytes, err := readPrivilegedFile(configPath)
				if err != nil {
					if b, readErr := os.ReadFile(configPath); readErr == nil {
						contentBytes = string(b)
					} else {
						continue
					}
				}
				lines := strings.Split(contentBytes, "\n")
				for _, line := range lines {
					if strings.HasPrefix(strings.TrimSpace(line), "ssid=") {
						ssid = strings.Trim(strings.TrimPrefix(strings.TrimSpace(line), "ssid="), "\"")
						if ssid != "" {
							i18n.LogTf("logs.wifi_network_found_file", lastFile.Name(), ssid)
							break
						}
					}
				}
				if ssid != "" {
					break
				}
			}
		}

		if ssid == "" {
			i18n.LogT("logs.wifi_no_network_found")
			return
		}
	}

	wpaConfigPath := resolveWpaConfigPath(interfaceName, wpaConfigPathForInterface(interfaceName))

	if _, err := os.Stat(wpaConfigPath); os.IsNotExist(err) {
		configDirs := []string{WpaSupplicantRuntimeConfigDir, WpaSupplicantConfigDir, WpaSupplicantAltConfigDir}
		found := false
		for _, configDir := range configDirs {
			configFiles, err := os.ReadDir(configDir)
			if err != nil {
				continue
			}
			for _, file := range configFiles {
				if file.Name() == fmt.Sprintf("wpa_supplicant-%s.conf", interfaceName) {
					wpaConfigPath = filepath.Join(configDir, file.Name())
					found = true
					i18n.LogTf("logs.wifi_config_file_found", wpaConfigPath)
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			country := constants.DefaultCountryCode
			result := ConnectWiFi(ssid, "", interfaceName, country, "system")
			if success, ok := result["success"].(bool); ok && success {
				i18n.LogTf("logs.wifi_auto_success", ssid)
				return
			}
			errorMsg := "Error desconocido"
			if errStr, ok := result["error"].(string); ok && errStr != "" {
				errorMsg = errStr
			}
			i18n.LogTf("logs.wifi_auto_error", errorMsg)
			return
		}
	}

	// Detener cualquier wpa_supplicant existente y arrancar con el archivo de config
	// que ya contiene la red guardada (con PSK/SAE hasheada por wpa_passphrase).
	// NO llamar ConnectWiFi con password vacía: eso sobreescribiría el config con
	// key_mgmt=NONE y la conexión fallaría tras el reinicio post-wizard.
	stopWpaSupplicant(interfaceName)
	if dbusWpaSupplicantRunning() {
		_, _ = utils.ExecuteArgv("systemctl", "stop", "wpa_supplicant")
		time.Sleep(1 * time.Second)
	}
	time.Sleep(1 * time.Second)

	runDir := getRunDir()
	i18n.LogT("logs.wifi_starting_wpa")
	if err := startWpaSupplicant(interfaceName, wpaConfigPath, runDir); err != nil {
		i18n.LogTf("logs.wifi_wpa_start_error", err)
		i18n.LogT("logs.wifi_trying_connect")
		country := constants.DefaultCountryCode
		result := ConnectWiFi(ssid, "", interfaceName, country, "system")
		if success, ok := result["success"].(bool); ok && success {
			i18n.LogTf("logs.wifi_auto_success", ssid)
		} else {
			errStr, _ := result["error"].(string)
			i18n.LogTf("logs.wifi_auto_error", errStr)
		}
		return
	}

	time.Sleep(2 * time.Second)

	socketDir, err := waitForWpaCliConnection(interfaceName, 5)
	if err != nil {
		return
	}

	runWpaCli := func(args ...string) (string, error) {
		args = quoteWpaCliSetNetworkValue(args...)
		base := []string{"wpa_cli", "-i", interfaceName, "-p", socketDir}
		out, err := runPrivilegedCommand(append(base, args...)...)
		return strings.TrimSpace(out), err
	}

	i18n.LogT("logs.wifi_enabling_network")
	runWpaCli("enable_network", "0")
	runWpaCli("select_network", "0")
	runWpaCli("reconnect")

	i18n.LogT("logs.wifi_waiting_auth")
	connected := false
	for attempt := 0; attempt < 8; attempt++ {
		time.Sleep(1 * time.Second)
		statusOut, _ := runWpaCli("status")
		if strings.Contains(statusOut, "wpa_state=COMPLETED") {
			connected = true
			i18n.LogTf("logs.wifi_authenticated", ssid)
			break
		}
		if attempt%3 == 0 && attempt > 0 {
			i18n.LogTf("logs.wifi_status_attempt3", statusOut, attempt+1)
		}
	}

	if !connected {
		log.Printf("⚠️  No se pudo autenticar después de 8 segundos. Estado final:")
		statusOut, _ := runWpaCli("status")
		log.Printf("Estado: %s", statusOut)
	}

	log.Printf("📡 Solicitando IP con DHCP...")
	go func() {
		_, _ = utils.ExecuteArgv("pkill", "-f", "dhclient.*"+interfaceName+"|udhcpc.*"+interfaceName)
		time.Sleep(300 * time.Millisecond)
		requestWiFiDHCP(interfaceName)
	}()

	var ip string
	for ipAttempt := 0; ipAttempt < 5; ipAttempt++ {
		time.Sleep(1 * time.Second)
		ip = strings.TrimSpace(ifaceIPv4(interfaceName))
		if ip != "" && ip != "N/A" && !strings.HasPrefix(ip, "169.254") {
			log.Printf("✅✅ Autoconexión completa: %s (IP: %s)", ssid, ip)
			EnsureAPChannelAligned(interfaceName)
			return
		}
	}

	if connected {
		log.Printf("✅ Autoconexión exitosa a %s (IP se asignará en segundo plano)", ssid)
		EnsureAPChannelAligned(interfaceName)
	} else {
		log.Printf("⚠️  Autoconexión iniciada, puede tardar unos segundos más en completarse")
	}
}
