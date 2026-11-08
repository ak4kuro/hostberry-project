package wifi

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"hostberry/internal/constants"
	"hostberry/internal/i18n"
	"hostberry/internal/utils"
)

const WpaSupplicantConfigDir = "/etc/wpa_supplicant"
const WpaSupplicantAltConfigDir = "/tmp/hostberry/wpa_supplicant"
const WpaSupplicantRuntimeConfigDir = "/opt/hostberry/data"
const WpaSupplicantCtrlDir = "/opt/hostberry/data/wpa_ctrl"

// WpaSocketDirs: directorios donde wpa_supplicant puede crear el socket (evita repetir la lista).
var WpaSocketDirs = []string{WpaSupplicantCtrlDir, "/run/wpa_supplicant", "/var/run/wpa_supplicant", "/tmp/wpa_supplicant"}

// wpaConfEscape escapa un valor para incrustarlo entre comillas dobles en
// wpa_supplicant.conf. Elimina caracteres de control (saltos de línea, etc.)
// que romperían la sintaxis del fichero o permitirían inyectar directivas,
// y escapa '\' y '"' para el parser de wpa_supplicant.
func wpaConfEscape(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
	s = strings.ReplaceAll(s, "\\", "\\\\")
	return strings.ReplaceAll(s, "\"", "\\\"")
}

// sanitizeCountryCode normaliza un código de país WiFi a ISO alpha-2 mayúsculas.
// Si no es válido devuelve el país por defecto (evita inyectar líneas en la
// cabecera `country=` de wpa_supplicant.conf).
func sanitizeCountryCode(country string) string {
	country = strings.ToUpper(strings.TrimSpace(country))
	if len(country) != 2 {
		return constants.DefaultCountryCode
	}
	for _, r := range country {
		if r < 'A' || r > 'Z' {
			return constants.DefaultCountryCode
		}
	}
	return country
}

// sanitizeHostapdValue elimina caracteres que romperían la sintaxis de
// hostapd.conf (saltos de línea, caracteres de control y comillas) al
// incrustar un valor en una directiva `clave=valor`.
func sanitizeHostapdValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F || r == '"' || r == '\'' || r == '#' {
			return -1
		}
		return r
	}, s)
}

// splitNMCLIField devuelve el primer campo de una línea `nmcli -t` y el resto.
// nmcli escapa ':' y '\' dentro de los valores (\: y \\), así que el
// separador real es el primer ':' no precedido por '\'.
func splitNMCLIField(line string) (field, rest string) {
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' && i+1 < len(line) {
			i++
			continue
		}
		if line[i] == ':' {
			return line[:i], line[i+1:]
		}
	}
	return line, ""
}

// unescapeNMCLIField revierte el escape de campos de `nmcli -t` (\: y \\).
func unescapeNMCLIField(s string) string {
	s = strings.ReplaceAll(s, `\:`, ":")
	return strings.ReplaceAll(s, `\\`, `\`)
}

// shellQuote envuelve un valor para uso seguro en sh -c (evita que $, ;, etc. rompan privileged-exec).
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// wpaStringNetworkFields son los campos de set_network cuyo valor es una cadena y que
// wpa_supplicant exige entre comillas dobles literales (p. ej. ssid="MiRed"). Sin esas
// comillas el valor se interpreta como hex y falla: "failed to parse ssid '...'.".
var wpaStringNetworkFields = map[string]bool{
	"ssid":               true,
	"sae_password":       true,
	"identity":           true,
	"anonymous_identity": true,
	"password":           true,
}

// quoteWpaCliSetNetworkValue escapa el valor de set_network (ssid, psk, sae_password, ...).
// Para campos de tipo cadena añade las comillas dobles que requiere wpa_supplicant ANTES de
// aplicar el escapado de shell; de lo contrario el shell elimina las comillas y wpa_cli recibe
// el valor sin comillas, provocando que wpa_supplicant no pueda parsear el SSID/contraseña.
func quoteWpaCliSetNetworkValue(args ...string) []string {
	if len(args) < 4 || args[0] != "set_network" {
		return args
	}
	out := append([]string(nil), args...)
	value := out[3]
	if wpaStringNetworkFields[out[2]] {
		value = `"` + value + `"`
	}
	out[3] = shellQuote(value)
	return out
}

func readPrivilegedFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("ruta vacía")
	}
	out, err := runPrivilegedCommand("cat", shellQuote(path))
	if err != nil {
		return "", err
	}
	return out, nil
}

func wpaRuntimeConfigPath(interfaceName string) string {
	return filepath.Join(WpaSupplicantRuntimeConfigDir, fmt.Sprintf("wpa_supplicant-%s.conf", interfaceName))
}

func wpaConfigPathForInterface(interfaceName string) string {
	return filepath.Join(WpaSupplicantConfigDir, fmt.Sprintf("wpa_supplicant-%s.conf", interfaceName))
}

func resolveWpaConfigPath(interfaceName, preferred string) string {
	candidates := []string{}
	if preferred != "" {
		candidates = append(candidates, preferred)
	}
	candidates = append(candidates,
		wpaRuntimeConfigPath(interfaceName),
		wpaConfigPathForInterface(interfaceName),
		filepath.Join(WpaSupplicantAltConfigDir, fmt.Sprintf("wpa_supplicant-%s.conf", interfaceName)),
	)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if preferred != "" {
		return preferred
	}
	return wpaRuntimeConfigPath(interfaceName)
}

// writeWpaSupplicantConfig guarda la config en /opt/hostberry/data (escribible por el servicio).
func writeWpaSupplicantConfig(interfaceName, content string) (string, error) {
	runtimePath := wpaRuntimeConfigPath(interfaceName)
	if err := os.MkdirAll(WpaSupplicantRuntimeConfigDir, 0750); err != nil {
		return "", fmt.Errorf("no se pudo preparar el directorio de configuración WiFi: %v", err)
	}
	if err := os.WriteFile(runtimePath, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("no se pudo guardar la configuración WiFi: %v", err)
	}

	etcPath := wpaConfigPathForInterface(interfaceName)
	syncCmd := fmt.Sprintf(
		"mkdir -p %s && cp %s %s && chmod 600 %s",
		WpaSupplicantConfigDir, runtimePath, etcPath, etcPath,
	)
	if out, err := execPrivilegedOutput(syncCmd); err != nil {
		log.Printf("Warning: wpa_supplicant no sincronizado en %s (%v): %s", etcPath, err, strings.TrimSpace(out))
	}

	alt := filepath.Join(WpaSupplicantAltConfigDir, fmt.Sprintf("wpa_supplicant-%s.conf", interfaceName))
	altCmd := fmt.Sprintf("mkdir -p %s && cp %s %s && chmod 644 %s", WpaSupplicantAltConfigDir, runtimePath, alt, alt)
	if _, err := execPrivilegedOutput(altCmd); err != nil {
		log.Printf("Warning: copia auxiliar wpa_supplicant en %s: %v", alt, err)
	}

	return runtimePath, nil
}

var activeRunDir string

func getRunDir() string {
	if activeRunDir != "" {
		return activeRunDir
	}
	candidates := WpaSocketDirs
	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			testFile := fmt.Sprintf("%s/.test_write", dir)
			if err := os.WriteFile(testFile, []byte("test"), 0644); err == nil {
				os.Remove(testFile)
				activeRunDir = dir
				i18n.LogTf("logs.socket_dir_selected", activeRunDir)
				return activeRunDir
			} else {
				i18n.LogTf("logs.socket_dir_not_writable", dir, err)
			}
		} else {
			if err := os.MkdirAll(dir, 0755); err == nil {
				testFile := fmt.Sprintf("%s/.test_write", dir)
				if err := os.WriteFile(testFile, []byte("test"), 0644); err == nil {
					os.Remove(testFile)
					activeRunDir = dir
					i18n.LogTf("logs.socket_dir_created", activeRunDir)
					return activeRunDir
				}
			}
		}
	}
	activeRunDir = "/tmp/wpa_supplicant"
	os.MkdirAll(activeRunDir, 0755)
	i18n.LogTf("logs.socket_dir_default", activeRunDir)
	return activeRunDir
}

func ensureWpaSupplicantDirs() error {
	if _, err := os.Stat(WpaSupplicantConfigDir); os.IsNotExist(err) {
		i18n.LogTf("logs.wpa_config_dir_creating", WpaSupplicantConfigDir)
		cmd := exec.Command("sudo", "mkdir", "-p", WpaSupplicantConfigDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			i18n.LogTf("logs.wpa_config_dir_error", WpaSupplicantConfigDir, err, string(out))
		}
	}
	exec.Command("sudo", "chmod", "755", WpaSupplicantConfigDir).Run()
	exec.Command("sudo", "chown", "root:netdev", WpaSupplicantConfigDir).Run()

	runDirCandidates := WpaSocketDirs
	var createdDir string

	for _, dir := range runDirCandidates {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			i18n.LogTf("logs.socket_dir_exists", dir)
			createdDir = dir
			break
		}

		i18n.LogTf("logs.socket_dir_creating", dir)
		cmd := exec.Command("sudo", "mkdir", "-p", dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			i18n.LogTf("logs.socket_dir_create_error", dir, err, string(out))
			continue
		}

		if _, err := os.Stat(dir); err == nil {
			i18n.LogTf("logs.socket_dir_created_ok", dir)
			createdDir = dir
			break
		}
	}

	if createdDir == "" {
		createdDir = "/tmp/wpa_supplicant"
		os.MkdirAll(createdDir, 0775)
		i18n.LogTf("logs.socket_dir_temp", createdDir)
	}

	exec.Command("sudo", "chmod", "775", createdDir).Run()
	exec.Command("sudo", "chown", "root:netdev", createdDir).Run()

	activeRunDir = createdDir
	i18n.LogTf("logs.socket_dir_active", activeRunDir)
	return nil
}

var (
	iwFreqRegex    = regexp.MustCompile(`(?i)freq:\s*([0-9]+)`)
	iwChannelRegex = regexp.MustCompile(`(?i)channel[[:space:]]+([0-9]+)`)
	wpaFreqRegex   = regexp.MustCompile(`freq=(\d+)`)
)

// SyncAPChannelWithSTA alinea hostapd.conf con el canal/frecuencia de la STA en la misma radio.
// Devuelve true si la configuración cambió.
func SyncAPChannelWithSTA(interfaceName string) bool {
	freq := staLinkFrequency(interfaceName)
	ch := freqToChannel(freq)
	if ch <= 0 {
		return false
	}

	mode := "g"
	if ch > 14 {
		mode = "a"
	}

	curCh, curMode := readHostapdChannelMode()
	if curCh == ch && curMode == mode {
		return false
	}

	log.Printf("HostBerry: alineando AP al canal %d (%d MHz, hw_mode=%s) según %s", ch, freq, mode, interfaceName)
	if err := writeHostapdChannelMode(ch, mode); err != nil {
		log.Printf("HostBerry: no se pudo actualizar hostapd.conf: %v", err)
		return false
	}
	return true
}

func writeHostapdChannelMode(channel int, hwMode string) error {
	content, err := readPrivilegedFile(hostapdConfigPath)
	if err != nil {
		return err
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)+2)
	insertedMode := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "hw_mode=") {
			if !insertedMode {
				out = append(out, "hw_mode="+hwMode)
				insertedMode = true
			}
			continue
		}
		if strings.HasPrefix(trim, "channel=") {
			continue
		}
		out = append(out, line)
	}
	if !insertedMode {
		out = append(out, "hw_mode="+hwMode)
	}
	out = append(out, fmt.Sprintf("channel=%d", channel))
	updated := strings.Join(out, "\n")
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}

	tmpPath := filepath.Join(WpaSupplicantRuntimeConfigDir, "hostapd.conf")
	if err := os.MkdirAll(WpaSupplicantRuntimeConfigDir, 0750); err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, []byte(updated), 0600); err != nil {
		return err
	}
	_, err = execPrivilegedOutput(fmt.Sprintf("cp %s %s && chmod 644 %s && cp %s /opt/hostberry/data/hostapd-active.conf && chmod 644 /opt/hostberry/data/hostapd-active.conf", tmpPath, hostapdConfigPath, hostapdConfigPath, tmpPath))
	return err
}

func detectSSIDSecurityFromWpaCli(interfaceName, ssid string) string {
	socketDir := findWorkingWpaSupplicantSocket(interfaceName)
	if socketDir == "" {
		return "WPA2"
	}
	out, err := runPrivilegedCommand("wpa_cli", "-i", interfaceName, "-p", socketDir, "scan_results")
	if err != nil || strings.TrimSpace(out) == "" {
		return "WPA2"
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		if strings.TrimSpace(fields[4]) != ssid {
			continue
		}
		flags := strings.ToUpper(fields[3])
		if strings.Contains(flags, "WPA3") || strings.Contains(flags, "SAE") {
			return "WPA3"
		}
		return "WPA2"
	}
	return "WPA2"
}

func dbusWpaSupplicantRunning() bool {
	out, err := exec.Command("pgrep", "-af", "wpa_supplicant").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "wpa_supplicant") && strings.Contains(string(out), " -u ")
}

func wpaPassphrasePSK(ssid, password string) (string, error) {
	cmd := exec.Command("wpa_passphrase", ssid, password)
	cmd.Env = append(os.Environ(), "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "psk=") && !strings.HasPrefix(line, "#psk=") {
			return strings.TrimPrefix(line, "psk="), nil
		}
	}
	return "", fmt.Errorf("psk no generado")
}

func stopWpaSupplicant(interfaceName string) {
	if dbusWpaSupplicantRunning() {
		log.Printf("ConnectWiFi: omitiendo stop de wpa_supplicant dbus del sistema")
		return
	}
	i18n.LogTf("logs.wpa_stopping", interfaceName)

	_, _ = execPrivilegedOutput("systemctl stop wpa_supplicant")
	_, _ = execPrivilegedOutput(fmt.Sprintf("pkill -f wpa_supplicant.*-i.*%s", interfaceName))
	_, _ = execPrivilegedOutput(fmt.Sprintf("pkill -f wpa_supplicant.*%s", interfaceName))
	_, _ = execPrivilegedOutput("killall wpa_supplicant")

	for i := 0; i < 5; i++ {
		checkCmd := exec.Command("pgrep", "-f", fmt.Sprintf("wpa_supplicant.*%s", interfaceName))
		if out, _ := checkCmd.Output(); strings.TrimSpace(string(out)) == "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
		if i == 4 {
			i18n.LogT("logs.wpa_force_kill")
			_, _ = execPrivilegedOutput(fmt.Sprintf("pkill -9 -f wpa_supplicant.*%s", interfaceName))
			_, _ = execPrivilegedOutput("killall -9 wpa_supplicant")
		}
	}

	for _, dir := range WpaSocketDirs {
		_, _ = execPrivilegedOutput(fmt.Sprintf("rm -f %s/%s", dir, interfaceName))
		_, _ = execPrivilegedOutput(fmt.Sprintf("rm -f %s/%s", dir, "p2p-dev-"+interfaceName))
	}
}

// findWorkingWpaSupplicantSocket devuelve el directorio del socket si wpa_supplicant ya gestiona la interfaz.
func findWorkingWpaSupplicantSocket(interfaceName string) string {
	if dir := wpaSupplicantSocketDir(interfaceName); dir != "" {
		return dir
	}
	dirs := []string{"/run/wpa_supplicant", "/var/run/wpa_supplicant", WpaSupplicantCtrlDir}
	for _, dir := range dirs {
		socketPath := filepath.Join(dir, interfaceName)
		if _, err := os.Stat(socketPath); err != nil {
			continue
		}
		if out, _ := runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", dir, "ping"); strings.Contains(out, "PONG") {
			return dir
		}
		if out, _ := runPrivilegedCommandFast("wpa_cli", "-i", interfaceName, "-p", dir, "status"); strings.Contains(out, "wpa_state=") {
			return dir
		}
	}
	return ""
}

func requestInterfaceDHCP(interfaceName string) {
	_, _ = execPrivilegedOutput(fmt.Sprintf("pkill -f dhclient.*%s", interfaceName))
	_, _ = execPrivilegedOutput(fmt.Sprintf("pkill -f udhcpc.*%s", interfaceName))
	if _, err := execPrivilegedOutput(fmt.Sprintf("dhclient -v %s", interfaceName)); err != nil {
		_, _ = execPrivilegedOutput(fmt.Sprintf("udhcpc -i %s -q -n", interfaceName))
	}
}

// clearLeftoverWiFiNetworks elimina cualquier red WiFi residual antes de conectar en el asistente,
// para que el equipo solo conozca la red que el usuario acaba de elegir. Evita que una red antigua
// (de otra banda o de una prueba previa) se autoconecte y "gane" el canal/banda de la radio única.
func clearLeftoverWiFiNetworks(interfaceName, socketDir string) {
	wpa := func(args ...string) {
		base := []string{"wpa_cli", "-i", interfaceName, "-p", socketDir}
		_, _ = runPrivilegedCommand(append(base, args...)...)
	}
	// Desasociar de cualquier red actual y borrar TODAS las redes conocidas del wpa_supplicant.
	wpa("disconnect")
	wpa("remove_network", "all")
	// Persistir el borrado (si update_config está activo) para que no reaparezcan tras reiniciar.
	wpa("save_config")
	// Eliminar perfiles WiFi guardados por NetworkManager que podrían autoconectar a redes viejas.
	removeStaleNMWiFiConnections()
}

// removeStaleNMWiFiConnections borra los perfiles de conexión WiFi de NetworkManager (best-effort),
// dejando intactas las conexiones por cable (Ethernet). Solo se usa para limpiar restos antes de
// que el asistente conecte a la red elegida por el usuario.
func removeStaleNMWiFiConnections() {
	out, err := execPrivilegedOutputTimeout("nmcli -t -f UUID,TYPE connection show", 5*time.Second)
	if err != nil || strings.TrimSpace(out) == "" {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		uuid := fields[0]
		connType := fields[len(fields)-1]
		if uuid == "" || !strings.Contains(connType, "wireless") {
			continue
		}
		_, _ = execPrivilegedOutputTimeout("nmcli connection delete uuid "+uuid, 5*time.Second)
	}
}

// connectWiFiViaWpaCli configura y conecta usando un wpa_supplicant ya en ejecución.
func connectWiFiViaWpaCli(socketDir, interfaceName, ssid, password, securityType string, escape func(string) string) map[string]interface{} {
	result := make(map[string]interface{})
	result["success"] = false

	apConcurrent := concurrentAPInterfacePresent()
	apWasActive := apConcurrent && hostapdServiceActive()
	// Radio única AP+STA (brcmfmac): el CSA "en caliente" siempre falla en este chip y, además,
	// escanear/asociar mientras el AP está activo en un canal DFS provoca SCAN-FAILED (-52).
	// Por eso detenemos hostapd durante la conexión para liberar la radio y poder escanear y
	// asociar en cualquier canal (incluido DFS, donde la STA actúa solo como cliente). Tras
	// conectar realineamos y volvemos a levantar el AP en un canal válido (nunca DFS).
	if apWasActive {
		_, _ = execPrivilegedOutput("systemctl stop hostapd")
		time.Sleep(700 * time.Millisecond)
	}
	defer func() {
		if !apWasActive {
			return
		}
		restoreAPAfterConnect(interfaceName)
	}()

	runWpaCli := func(args ...string) (string, error) {
		args = quoteWpaCliSetNetworkValue(args...)
		base := []string{"wpa_cli", "-i", interfaceName, "-p", socketDir}
		out, err := runPrivilegedCommand(append(base, args...)...)
		return strings.TrimSpace(out), err
	}

	// Borrar cualquier resto de redes anteriores antes de conectar: así el equipo solo conoce la
	// red que el usuario acaba de elegir y ninguna red antigua (de otra banda o de una prueba
	// previa) puede autoconectarse y "robar" el canal/banda de la radio única.
	clearLeftoverWiFiNetworks(interfaceName, socketDir)

	preferredBand := GetWizardPreferredBand()
	if freqArg := scanFreqArgForBand(preferredBand); freqArg != "" {
		_, _ = runWpaCli("scan", freqArg)
	} else {
		_, _ = runWpaCli("scan")
	}
	time.Sleep(3 * time.Second)

	netIDOut, netIDErr := runWpaCli("add_network")
	if netIDErr != nil || netIDOut == "" {
		result["error"] = fmt.Sprintf("Error agregando red: %v", netIDErr)
		return result
	}

	netID := strings.TrimSpace(netIDOut)
	if _, err := runWpaCli("set_network", netID, "ssid", ssid); err != nil {
		result["error"] = "Error configurando SSID"
		return result
	}

	if password != "" && strings.EqualFold(securityType, "WPA3") {
		runWpaCli("set_network", netID, "key_mgmt", "SAE")
		if _, err := runWpaCli("set_network", netID, "sae_password", password); err != nil {
			result["error"] = "Error configurando contraseña WPA3"
			return result
		}
	} else if password != "" {
		psk, err := wpaPassphrasePSK(ssid, password)
		if err != nil || psk == "" {
			result["error"] = "Error al generar la clave PSK. Verifica el SSID y la contraseña."
			return result
		}
		if _, err := runWpaCli("set_network", netID, "psk", psk); err != nil {
			result["error"] = "Error configurando PSK"
			return result
		}
	} else {
		runWpaCli("set_network", netID, "key_mgmt", "NONE")
	}

	// Restringir la asociación a la banda elegida en el asistente: en redes con el mismo SSID en
	// 2.4 y 5 GHz, evita que wpa_supplicant se conecte al BSS de la banda no elegida.
	if fl := bandFreqList(preferredBand); fl != "" {
		runWpaCli("set_network", netID, "freq_list", fl)
	}

	runWpaCli("enable_network", netID)
	runWpaCli("select_network", netID)
	runWpaCli("reconnect")
	runWpaCli("save_config")

	authFailed := false
	// Señal de contraseña incorrecta sin depender de journalctl (bloqueado en el sandbox):
	// con clave errónea wpa_supplicant alcanza el 4-way handshake y vuelve a SCANNING/
	// DISCONNECTED sin completar. Si eso ocurre repetidamente, es casi seguro clave incorrecta.
	sawHandshake := false
	handshakeDrops := 0
	for i := 0; i < 45; i++ {
		time.Sleep(1 * time.Second)
		statusOut, _ := runWpaCli("status")
		if strings.Contains(statusOut, "wpa_state=COMPLETED") {
			// DHCP en segundo plano: la asociación + handshake WPA ya validan la red y la clave,
			// así que devolvemos éxito de inmediato (el asistente avanza) y dejamos que la IP
			// llegue en paralelo. dhclient puede tardar (reintentos/DECLINE) y no debe bloquear.
			go requestInterfaceDHCP(interfaceName)
			result["success"] = true
			result["message"] = "Conectado"
			if freq := staLinkFrequency(interfaceName); freq > 0 {
				result["frequency"] = freq
				if ch := freqToChannel(freq); ch > 0 {
					result["channel"] = ch
				}
			}
			result["ap_concurrent"] = apConcurrent
			return result
		}
		if password != "" {
			// Detección temprana directa (algunos drivers exponen el motivo en el estado).
			if strings.Contains(statusOut, "AUTH_FAILED") || strings.Contains(statusOut, "WRONG_KEY") {
				authFailed = true
				break
			}
			// Detección por oscilación del handshake (no requiere journalctl).
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
			// Tras una primera caída del handshake, confirmamos por logs (más rápido que
			// esperar el timeout completo) si la clave es incorrecta.
			if handshakeDrops >= 1 && i >= 10 && i%4 == 0 && wifiAuthFailureDetected(interfaceName, statusOut) {
				authFailed = true
				break
			}
		}
	}

	// Clasificar el motivo del fallo para dar un mensaje claro al usuario.
	statusOut, _ := runWpaCli("status")
	if authFailed || wifiAuthFailureDetected(interfaceName, statusOut) {
		result["error"] = "Contraseña incorrecta. Revisa la clave de «" + ssid + "» e inténtalo de nuevo."
		log.Printf("ConnectWiFi error (%s): contraseña incorrecta", ssid)
		return result
	}

	signal, found := scanResultSignalForSSID(interfaceName, socketDir, ssid, preferredBand)
	if !found {
		result["error"] = "No se encontró la red «" + ssid + "». Puede estar demasiado lejos (fuera de alcance) o apagada. Acerca el HostBerry al router."
	} else if signal <= -82 {
		result["error"] = fmt.Sprintf("La red «%s» tiene una señal muy débil (%d dBm): está demasiado lejos. Acerca el HostBerry al router e inténtalo de nuevo.", ssid, signal)
	} else if password != "" {
		result["error"] = "No se pudo conectar a «" + ssid + "». Comprueba que la contraseña sea correcta; si lo es, puede ser por señal débil o saturación del canal."
	} else {
		result["error"] = "No se pudo conectar a «" + ssid + "». Comprueba que esté encendida y dentro de alcance e inténtalo de nuevo."
	}
	log.Printf("ConnectWiFi error (%s): %s (encontrada=%v, señal=%d dBm)", ssid, result["error"], found, signal)
	return result
}

// wifiAuthFailureDetected indica que el fallo de conexión se debe a contraseña/clave incorrecta,
// combinando el estado de wpa_cli con los eventos recientes de wpa_supplicant (TEMP-DISABLED por
// WRONG_KEY, 4-Way Handshake fallido, etc.).
func wifiAuthFailureDetected(interfaceName, statusOut string) bool {
	if strings.Contains(statusOut, "AUTH_FAILED") || strings.Contains(statusOut, "WRONG_KEY") {
		return true
	}
	out, err := execPrivilegedOutputTimeout("journalctl -u wpa_supplicant --since '-40 seconds' --no-pager", 4*time.Second)
	if err != nil || out == "" {
		return false
	}
	lower := strings.ToLower(out)
	return strings.Contains(lower, "wrong_key") ||
		strings.Contains(lower, "pre-shared key may be incorrect") ||
		strings.Contains(lower, "4-way handshake failed") ||
		strings.Contains(lower, "reason=15") // 4WAY_HANDSHAKE_TIMEOUT
}

func startWpaSupplicant(interfaceName, configPath, runDir string) error {
	if runDir == "" {
		runDir = "/run/wpa_supplicant"
	}
	i18n.LogTf("logs.wpa_starting", interfaceName, configPath, runDir)

	utils.ExecuteCommand(fmt.Sprintf("sudo mkdir -p %s 2>/dev/null || true", runDir))
	utils.ExecuteCommand(fmt.Sprintf("sudo chmod 775 %s 2>/dev/null || true", runDir))
	utils.ExecuteCommand(fmt.Sprintf("sudo chown root:netdev %s 2>/dev/null || true", runDir))
	utils.ExecuteCommand(fmt.Sprintf("sudo rm -f %s/%s 2>/dev/null || true", runDir, interfaceName))

	configPath = resolveWpaConfigPath(interfaceName, configPath)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("no se pudo crear la configuración de wpa_supplicant para %s", interfaceName)
	}

	wpaSupplicantPath := ""
	possiblePaths := []string{
		"/usr/sbin/wpa_supplicant",
		"/sbin/wpa_supplicant",
		"/usr/bin/wpa_supplicant",
		"/bin/wpa_supplicant",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			wpaSupplicantPath = path
			break
		}
	}

	if wpaSupplicantPath == "" {
		whichCmd := exec.Command("which", "wpa_supplicant")
		if whichOut, err := whichCmd.Output(); err == nil {
			wpaSupplicantPath = strings.TrimSpace(string(whichOut))
		}
	}

	if wpaSupplicantPath == "" {
		return fmt.Errorf("wpa_supplicant no se encontró en el sistema. Instala el paquete wpa_supplicant")
	}

	i18n.LogTf("logs.wpa_path", wpaSupplicantPath)

	if fi, err := os.Stat(wpaSupplicantPath); err != nil || fi.Mode()&0111 == 0 {
		return fmt.Errorf("wpa_supplicant no es ejecutable en %s", wpaSupplicantPath)
	}

	tryStart := func(driver string) (out []byte, runErr error) {
		args := []string{wpaSupplicantPath, "-B", "-i", interfaceName, "-c", configPath}
		if driver != "" {
			args = append(args, "-D", driver)
		}
		if runDir != "" {
			args = append(args, "-C", runDir)
		}
		outStr, runErr := runPrivilegedCommand(args...)
		return []byte(outStr), runErr
	}

	tryDrivers := []string{"nl80211,wext", "wext", "nl80211", ""}
	var lastErr error
	var lastOut string

	for _, driver := range tryDrivers {
		utils.ExecuteCommand(fmt.Sprintf("sudo rm -f %s/%s 2>/dev/null || true", runDir, interfaceName))
		startOut, startErr := tryStart(driver)
		outStr := string(startOut)
		if startErr != nil {
			lastOut = outStr
			lastErr = startErr
			i18n.LogTf("logs.wpa_start_error", startErr, outStr)
			if strings.Contains(outStr, "not found") || strings.Contains(outStr, "No such file") {
				return fmt.Errorf("wpa_supplicant no se encontró en %s. Instala el paquete wpa_supplicant (apt install wpasupplicant)", wpaSupplicantPath)
			}
			if strings.Contains(outStr, "ctrl_iface exists") || strings.Contains(outStr, "cannot override it") {
				i18n.LogT("logs.wpa_socket_in_use")
				utils.ExecuteCommand(fmt.Sprintf("sudo rm -f %s/%s 2>/dev/null || true", runDir, interfaceName))
				startOut, startErr = tryStart(driver)
				if startErr != nil {
					lastOut = string(startOut)
					lastErr = fmt.Errorf("error iniciando wpa_supplicant tras limpiar socket: %v, output: %s", startErr, string(startOut))
					continue
				}
				outStr = string(startOut)
				startErr = nil
			} else {
				// Error de driver u otro: probar siguiente driver antes de devolver error
				driverHint := ""
				if driver != "" {
					driverHint = " (driver " + driver + ")"
				}
				lastErr = fmt.Errorf("error iniciando wpa_supplicant%v: %v. %s", driverHint, startErr, strings.TrimSpace(outStr))
				if strings.Contains(strings.ToLower(outStr), "driver") ||
					strings.Contains(strings.ToLower(outStr), "nl80211") ||
					strings.Contains(strings.ToLower(outStr), "wext") ||
					strings.Contains(outStr, "Could not configure") {
					continue
				}
				return lastErr
			}
		}

		i18n.LogTf("logs.wpa_command_executed", strings.TrimSpace(outStr))
		time.Sleep(2 * time.Second)

		pidFound := false
		var pid string

		pidCmd := exec.Command("pgrep", "-f", fmt.Sprintf("wpa_supplicant.*%s", interfaceName))
		if pidOut, err := pidCmd.Output(); err == nil {
			pid = strings.TrimSpace(string(pidOut))
			if pid != "" {
				pidFound = true
			}
		}

		if !pidFound {
			pidCmd2 := exec.Command("pgrep", "-f", fmt.Sprintf("%s.*%s", wpaSupplicantPath, interfaceName))
			if pidOut2, err2 := pidCmd2.Output(); err2 == nil {
				pid = strings.TrimSpace(string(pidOut2))
				if pid != "" {
					pidFound = true
				}
			}
		}

		if !pidFound {
			pidCmd3 := exec.Command("pgrep", "-f", fmt.Sprintf("wpa_supplicant.*%s", interfaceName))
			if psOut, err := pidCmd3.Output(); err == nil {
				pid = strings.TrimSpace(string(psOut))
				if pid != "" {
					pidFound = true
				}
			}
		}

		if pidFound {
			i18n.LogTf("logs.wpa_running", pid)
			return nil
		}

		utils.ExecuteCommand(fmt.Sprintf("sudo pkill -f 'wpa_supplicant.*%s' 2>/dev/null || true", interfaceName))
		lastErr = fmt.Errorf("wpa_supplicant se ejecutó pero se detuvo de inmediato. Comprueba la interfaz %s y los logs (journalctl -u hostberry)", interfaceName)
		lastOut = outStr
	}

	if lastErr != nil {
		i18n.LogT("logs.wpa_not_running")
		if dmesgOut, err := exec.Command("dmesg").Output(); err == nil {
			// Filtrar en Go para evitar pipelines/shell residual.
			lines := strings.Split(string(dmesgOut), "\n")
			matches := make([]string, 0, 20)
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "wpa") {
					matches = append(matches, line)
				}
			}
			if len(matches) == 0 {
				i18n.LogT("logs.wpa_dmesg")
			} else {
				start := 0
				if len(matches) > 20 {
					start = len(matches) - 20
				}
				i18n.LogTf("logs.wpa_dmesg", strings.Join(matches[start:], "\n"))
			}
		}
		if lastOut != "" {
			return fmt.Errorf("%v. Salida: %s", lastErr, strings.TrimSpace(lastOut))
		}
		return lastErr
	}

	return nil
}

func waitForWpaCliConnection(interfaceName string, maxAttempts int) (string, error) {
	i18n.LogTf("logs.wpa_cli_waiting", interfaceName)

	socketDirs := []string{}
	if activeRunDir != "" {
		socketDirs = append(socketDirs, activeRunDir)
	}
	socketDirs = append(socketDirs, WpaSocketDirs...)

	seen := map[string]bool{}
	uniqueDirs := []string{}
	for _, dir := range socketDirs {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		uniqueDirs = append(uniqueDirs, dir)
	}

	var workingSocketDir string
	var lastPingOutput string
	var lastStatusOutput string
	var lastPingErr error
	var lastStatusErr error

	runWpaCli := func(args ...string) (string, error) {
		out, err := runPrivilegedCommand(args...)
		return strings.TrimSpace(out), err
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		workingSocketDir = ""
		for _, dir := range uniqueDirs {
			socketPath := fmt.Sprintf("%s/%s", dir, interfaceName)
			if _, err := os.Stat(socketPath); err == nil {
				i18n.LogTf("logs.wpa_socket_found", socketPath)
				workingSocketDir = dir
				utils.ExecuteCommand(fmt.Sprintf("sudo chmod 660 %s 2>/dev/null || true", socketPath))
				utils.ExecuteCommand(fmt.Sprintf("sudo chown root:netdev %s 2>/dev/null || true", socketPath))
			}

			pingOut, pingErr := runWpaCli("wpa_cli", "-i", interfaceName, "-p", dir, "ping")
			lastPingOutput = pingOut
			lastPingErr = pingErr
			if lastPingOutput != "" {
				i18n.LogTf("logs.wpa_cli_ping", dir, lastPingOutput)
			}
			if pingErr != nil && lastPingOutput != "" {
				i18n.LogTf("logs.wpa_cli_ping_error", dir, pingErr)
			}
			if strings.Contains(lastPingOutput, "PONG") {
				i18n.LogTf("logs.wpa_cli_responded", dir)
				return dir, nil
			}

			statusOut, statusErr := runWpaCli("wpa_cli", "-i", interfaceName, "-p", dir, "status")
			lastStatusOutput = statusOut
			lastStatusErr = statusErr
			if lastStatusOutput != "" {
				i18n.LogTf("logs.wpa_cli_status", dir, lastStatusOutput)
			}
			if statusErr != nil && lastStatusOutput != "" {
				i18n.LogTf("logs.wpa_cli_status_error", dir, statusErr)
			}
			if strings.Contains(lastStatusOutput, "wpa_state=") {
				i18n.LogTf("logs.wpa_cli_status_valid", dir)
				return dir, nil
			}

			globalSocket := fmt.Sprintf("%s/global", dir)
			if _, err := os.Stat(globalSocket); err == nil {
				globalPingOut, globalPingErr := runWpaCli("wpa_cli", "-g", dir, "-i", interfaceName, "ping")
				if strings.TrimSpace(globalPingOut) != "" {
					i18n.LogTf("logs.wpa_cli_global_ping", dir, strings.TrimSpace(globalPingOut))
				}
				if globalPingErr == nil && strings.Contains(globalPingOut, "PONG") {
					i18n.LogTf("logs.wpa_cli_global_responded", dir)
					return dir, nil
				}

				globalStatusOut, globalStatusErr := runWpaCli("wpa_cli", "-g", dir, "-i", interfaceName, "status")
				if strings.TrimSpace(globalStatusOut) != "" {
					i18n.LogTf("logs.wpa_cli_global_status", dir, strings.TrimSpace(globalStatusOut))
				}
				if globalStatusErr == nil && strings.Contains(globalStatusOut, "wpa_state=") {
					i18n.LogTf("logs.wpa_cli_global_status_valid", dir)
					return dir, nil
				}
			}
		}

		if workingSocketDir != "" {
			i18n.LogTf("logs.wpa_cli_attempt", attempt+1, maxAttempts, workingSocketDir)
		} else {
			i18n.LogTf("logs.wpa_cli_socket_not_found", attempt+1, maxAttempts)
		}

		time.Sleep(1 * time.Second)
	}

	if lastPingOutput != "" || lastStatusOutput != "" {
		return "", fmt.Errorf("wpa_cli no pudo comunicarse con wpa_supplicant después de %d intentos (último ping: %s, error: %v; último status: %s, error: %v)", maxAttempts, lastPingOutput, lastPingErr, lastStatusOutput, lastStatusErr)
	}
	return "", fmt.Errorf("wpa_cli no pudo comunicarse con wpa_supplicant después de %d intentos", maxAttempts)
}

// getLastConnectedNetwork obtiene la última red WiFi conectada desde los archivos de configuración.
func getLastConnectedNetwork(interfaceName string) (string, string, error) {
	if interfaceName == "" {
		interfaceName = constants.DefaultWiFiInterface
	}

	// Primero intentar obtener desde wpa_cli si wpa_supplicant está corriendo
	socketDirs := WpaSocketDirs
	for _, dir := range socketDirs {
		// Intentar socket de interfaz
		socketPath := fmt.Sprintf("%s/%s", dir, interfaceName)
		if _, err := os.Stat(socketPath); err == nil {
			runWpaCli := func(args ...string) (string, error) {
				base := []string{"wpa_cli", "-i", interfaceName, "-p", dir}
				out, err := runPrivilegedCommand(append(base, args...)...)
				return strings.TrimSpace(out), err
			}

			listOut, err := runWpaCli("list_networks")
			if err == nil && listOut != "" {
				lines := strings.Split(listOut, "\n")
				if len(lines) > 1 {
					// Buscar la red activa o la primera habilitada
					for i, line := range lines {
						if i == 0 {
							continue
						}
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							ssid := strings.Trim(fields[1], "\"")
							if ssid != "" && ssid != "--" {
								// Verificar si está habilitada o es CURRENT
								if len(fields) >= 4 && (fields[3] == "[CURRENT]" || fields[2] == "[ENABLED]") {
									log.Printf("Red encontrada en wpa_cli: %s", ssid)
									return ssid, "", nil
								}
							}
						}
					}

					// Si no hay red activa, tomar la primera
					if len(lines) > 1 {
						firstLine := lines[1]
						fields := strings.Fields(firstLine)
						if len(fields) >= 2 {
							ssid := strings.Trim(fields[1], "\"")
							if ssid != "" && ssid != "--" {
								i18n.LogTf("logs.wifi_first_network_cli", ssid)
								return ssid, "", nil
							}
						}
					}
				}
			}
		}

		// Intentar socket global
		globalSocket := fmt.Sprintf("%s/global", dir)
		if _, err := os.Stat(globalSocket); err == nil {
			runWpaCli := func(args ...string) (string, error) {
				base := []string{"wpa_cli", "-g", dir, "-i", interfaceName}
				out, err := runPrivilegedCommand(append(base, args...)...)
				return strings.TrimSpace(out), err
			}

			listOut, err := runWpaCli("list_networks")
			if err == nil && listOut != "" {
				lines := strings.Split(listOut, "\n")
				if len(lines) > 1 {
					// Buscar la red activa o la primera habilitada
					for i, line := range lines {
						if i == 0 {
							continue
						}
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							ssid := strings.Trim(fields[1], "\"")
							if ssid != "" && ssid != "--" {
								if len(fields) >= 4 && (fields[3] == "[CURRENT]" || fields[2] == "[ENABLED]") {
									i18n.LogTf("logs.wifi_network_found_global", ssid)
									return ssid, "", nil
								}
							}
						}
					}

					// Si no hay red activa, tomar la primera
					if len(lines) > 1 {
						firstLine := lines[1]
						fields := strings.Fields(firstLine)
						if len(fields) >= 2 {
							ssid := strings.Trim(fields[1], "\"")
							if ssid != "" && ssid != "--" {
								i18n.LogTf("logs.wifi_first_network_global", ssid)
								return ssid, "", nil
							}
						}
					}
				}
			}
		}
	}

	// Si no se encontró en wpa_cli, buscar en archivos de configuración
	configDirs := []string{WpaSupplicantConfigDir, WpaSupplicantAltConfigDir}
	var lastConfigFile os.DirEntry
	var lastModTime time.Time
	var foundConfigDir string

	for _, configDir := range configDirs {
		configFiles, err := os.ReadDir(configDir)
		if err != nil {
			continue
		}

		// Buscar el archivo de configuración más reciente
		for _, file := range configFiles {
			if strings.HasPrefix(file.Name(), "wpa_supplicant-") && strings.HasSuffix(file.Name(), ".conf") {
				info, err := file.Info()
				if err != nil {
					continue
				}
				if info.ModTime().After(lastModTime) {
					lastModTime = info.ModTime()
					lastConfigFile = file
					foundConfigDir = configDir
				}
			}
		}
	}

	if lastConfigFile == nil {
		return "", "", fmt.Errorf("no se encontró ninguna red guardada")
	}

	configPath := fmt.Sprintf("%s/%s", foundConfigDir, lastConfigFile.Name())

	configContent, err := readPrivilegedFile(configPath)
	if err != nil {
		// Fallback: config en /opt/hostberry/data es legible por el servicio sin privilegios.
		if b, readErr := os.ReadFile(configPath); readErr == nil {
			configContent = string(b)
		} else {
			return "", "", fmt.Errorf("error leyendo archivo de configuración: %v", err)
		}
	}

	// Extraer SSID del archivo de configuración
	ssid := ""
	lines := strings.Split(string(configContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ssid=") {
			ssid = strings.Trim(strings.TrimPrefix(line, "ssid="), "\"")
			break
		}
	}

	if ssid == "" {
		return "", "", fmt.Errorf("no se pudo extraer SSID del archivo de configuración")
	}

	i18n.LogTf("logs.wifi_ssid_found_config", ssid)
	// No retornamos password porque no podemos obtenerla del archivo (está hasheada)
	return ssid, "", nil
}
