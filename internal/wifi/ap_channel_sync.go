package wifi

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"hostberry/internal/auth"
	"hostberry/internal/constants"
)

const hostapdConfigPath = "/etc/hostapd/hostapd.conf"

// apCSAInterface es la interfaz virtual del AP "hostberry" en modo AP+STA (radio única).
const apCSAInterface = "ap0"

// switchAPChannelViaCSA mueve el AP en caliente al canal de freq usando un Channel Switch
// Announcement (hostapd_cli chan_switch). Los clientes asociados (p. ej. el móvil en el
// wizard) reciben el CSA en la baliza y siguen al AP al nuevo canal SIN desasociarse, así
// no se pierde la conexión al AP. Aplica a 2.4 y 5 GHz (la radio única comparte canal).
func switchAPChannelViaCSA(freq int) bool {
	if freq <= 0 || !concurrentAPInterfacePresent() {
		return false
	}
	if !hostapdServiceActive() {
		return false
	}
	ch := freqToChannel(freq)
	var attempts [][]string
	if is24GHzFrequency(freq) {
		attempts = [][]string{
			{"hostapd_cli", "-i", apCSAInterface, "chan_switch", "5", fmt.Sprint(freq), "ht"},
			{"hostapd_cli", "-i", apCSAInterface, "chan_switch", "5", fmt.Sprint(freq)},
		}
	} else if is5GHzFrequency(freq) {
		attempts = [][]string{
			{"hostapd_cli", "-i", apCSAInterface, "chan_switch", "5", fmt.Sprint(freq), "vht"},
			{"hostapd_cli", "-i", apCSAInterface, "chan_switch", "5", fmt.Sprint(freq)},
		}
	} else {
		return false
	}
	for _, args := range attempts {
		out, err := execPrivilegedArgvTimeout(args, 6*time.Second)
		if err == nil && !strings.Contains(strings.ToUpper(out), "FAIL") {
			log.Printf("HostBerry: AP movido al canal %d (%d MHz) vía CSA sin reiniciar (los clientes mantienen la conexión)", ch, freq)
			return true
		}
		log.Printf("HostBerry: CSA chan_switch no aplicado (%v): err=%v out=%s", args, err, strings.TrimSpace(out))
	}
	return false
}

// alignAPToFreqViaCSA alinea el AP al canal de freq sin reiniciar hostapd: persiste el canal
// en hostapd.conf (para futuros arranques) y lo aplica en caliente con CSA. Devuelve true si el
// AP ya estaba alineado o se movió correctamente. Soporta 2.4 y 5 GHz (radio única AP+STA).
func alignAPToFreqViaCSA(freq int) bool {
	if freq <= 0 || !concurrentAPInterfacePresent() {
		return false
	}
	ch := freqToChannel(freq)
	if ch <= 0 {
		return false
	}
	mode := hwModeForFrequency(freq)
	if curCh, curMode := readHostapdChannelMode(); curCh == ch && curMode == mode {
		return true
	}
	if err := writeHostapdChannelMode(ch, mode); err != nil {
		log.Printf("HostBerry: no se pudo persistir canal %d (hw_mode=%s) en hostapd.conf: %v", ch, mode, err)
	}
	return switchAPChannelViaCSA(freq)
}

// alignAPForConnect mueve el AP al canal de la red upstream antes de conectar la STA.
// Intenta CSA primero; en brcmfmac CSA suele fallar, así que reinicia hostapd en el canal
// objetivo (corte breve del portal cautivo, pero permite conectar en radio única AP+STA).
func alignAPForConnect(freq int) bool {
	if freq <= 0 || !concurrentAPInterfacePresent() {
		return false
	}
	if apFreq := apLinkFrequency(); apFreq > 0 && freqToChannel(apFreq) == freqToChannel(freq) {
		return true
	}
	if alignAPToFreqViaCSA(freq) {
		time.Sleep(500 * time.Millisecond)
		if apFreq := apLinkFrequency(); apFreq > 0 && freqToChannel(apFreq) == freqToChannel(freq) {
			return true
		}
	}
	ch := freqToChannel(freq)
	mode := hwModeForFrequency(freq)
	if ch <= 0 {
		return false
	}
	if err := writeHostapdChannelMode(ch, mode); err != nil {
		log.Printf("HostBerry: alignAPForConnect no pudo escribir canal %d: %v", ch, err)
		return false
	}
	log.Printf("HostBerry: CSA falló; reiniciando hostapd en canal %d (%d MHz) para conectar upstream", ch, freq)
	if out, err := execPrivilegedArgv("systemctl", "restart", "hostapd"); err != nil {
		log.Printf("HostBerry: restart hostapd en connect: %v (%s)", err, strings.TrimSpace(out))
		return false
	}
	_, _ = execPrivilegedArgv("systemctl", "restart", "dnsmasq")
	time.Sleep(2500 * time.Millisecond)
	apFreq := apLinkFrequency()
	ok := apFreq > 0 && freqToChannel(apFreq) == ch
	if !ok {
		log.Printf("HostBerry: tras restart hostapd AP en freq=%d, esperado canal %d", apFreq, ch)
	}
	return ok
}

// restoreAPAfterConnect vuelve a levantar el AP "hostberry" tras un intento de conexión STA.
// En radio única (brcmfmac) el AP debe compartir el canal de la STA: si la STA ya está conectada
// (incluso en un canal DFS) la radio ya está en ese canal y el AP puede seguirla sin CAC. El script
// ExecStartPre de hostapd (hostberry-sync-hostapd-channel.sh) lee el enlace de la STA en vivo y
// alinea el canal del AP, degradando a un canal NO-DFS solo cuando NO hay STA (arranque en frío).
// Por eso aquí basta con reiniciar los servicios y dejar que ese script haga la alineación.
func restoreAPAfterConnect(interfaceName string) {
	staFreq := staLinkFrequency(interfaceName)
	if staFreq > 0 {
		ch := freqToChannel(staFreq)
		mode := hwModeForFrequency(staFreq)
		if ch > 0 {
			if err := writeHostapdChannelMode(ch, mode); err != nil {
				log.Printf("HostBerry: restoreAPAfterConnect no pudo escribir canal %d: %v", ch, err)
			}
		}
	} else {
		// Conexión fallida (sin enlace STA): restaurar el AP en su canal por defecto NO-DFS para
		// que el portal del asistente vuelva a estar disponible.
		band := GetWizardPreferredBand()
		if band != band24GHz && band != band5GHz {
			band = band24GHz
		}
		ch := defaultAPChannelForBand(band)
		mode := "g"
		if band == band5GHz {
			mode = "a"
		}
		if err := writeHostapdChannelMode(ch, mode); err != nil {
			log.Printf("HostBerry: restoreAPAfterConnect no pudo escribir canal %d: %v", ch, err)
		}
	}
	if out, err := execPrivilegedArgv("systemctl", "restart", "hostapd"); err != nil {
		log.Printf("HostBerry: restoreAPAfterConnect restart hostapd: %v (%s)", err, strings.TrimSpace(out))
	}
	_, _ = execPrivilegedArgv("systemctl", "restart", "dnsmasq")
}

// StartAPChannelSyncDaemon vigila wlan0 y alinea hostapd al mismo canal en modo AP+STA.
// Durante el wizard inicial no reinicia el AP periódicamente (evita desconexiones del móvil).
func StartAPChannelSyncDaemon() {
	go func() {
		time.Sleep(45 * time.Second)
		iface := constants.DefaultWiFiInterface
		if !concurrentAPInterfacePresent() {
			return
		}
		if auth.IsInitialSetupPending() {
			log.Printf("HostBerry: sincronización periódica de canal AP omitida (wizard inicial pendiente)")
			return
		}
		EnsureAPChannelAligned(iface)

		ticker := time.NewTicker(90 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if auth.IsInitialSetupPending() {
				continue
			}
			if !concurrentAPInterfacePresent() {
				continue
			}
			if staLinkFrequency(iface) <= 0 {
				continue
			}
			EnsureAPChannelAligned(iface)
		}
	}()
}

// EnsureAPChannelAligned actualiza hostapd.conf y reinicia el AP si el canal no coincide con la STA.
func EnsureAPChannelAligned(interfaceName string) {
	if !concurrentAPInterfacePresent() {
		return
	}
	staFreq := staLinkFrequency(interfaceName)
	if staFreq <= 0 {
		return
	}

	// Radio única (brcmfmac AP+STA): el driver impone que el AP comparta el canal de la STA.
	// Si el AP ya emite en el mismo canal que la STA, NO hay nada que alinear: reiniciar hostapd
	// o forzar CSA solo provoca que los clientes del portal se desconecten/reconecten en bucle.
	if apFreq := apLinkFrequency(); apFreq > 0 && freqToChannel(apFreq) == freqToChannel(staFreq) {
		return
	}

	// Durante el wizard: mover el AP con CSA sin persistir canal DFS en hostapd.conf
	// (un reinicio en frío a 5 GHz DFS fallaría en brcmfmac).
	if auth.IsInitialSetupPending() {
		alignAPToFreqViaCSA(staFreq)
		return
	}

	changed := SyncAPChannelWithSTA(interfaceName)
	active := hostapdServiceActive()

	if !changed && active {
		return
	}

	if !active {
		log.Printf("HostBerry: iniciando hostapd alineado al canal de %s", interfaceName)
		_, _ = execPrivilegedArgv("systemctl", "start", "hostapd")
		_, _ = execPrivilegedArgv("systemctl", "restart", "dnsmasq")
		return
	}

	// hostapd activo y cambió el canal: moverlo en caliente con CSA para que los clientes
	// del AP "hostberry" sigan al AP sin desconectarse. Solo reiniciamos como último recurso.
	if freq := staLinkFrequency(interfaceName); freq > 0 && switchAPChannelViaCSA(freq) {
		return
	}
	log.Printf("HostBerry: CSA no disponible; reiniciando hostapd tras cambio de canal de %s", interfaceName)
	_, _ = execPrivilegedArgv("systemctl", "restart", "hostapd")
	_, _ = execPrivilegedArgv("systemctl", "restart", "dnsmasq")
}

func hostapdServiceActive() bool {
	out, err := execPrivilegedArgv("systemctl", "is-active", "hostapd")
	return err == nil && strings.TrimSpace(out) == "active"
}

// staLinkFrequency devuelve la frecuencia (MHz) de la STA conectada, o 0 si no hay enlace.
func staLinkFrequency(interfaceName string) int {
	if freq := linkFrequencyFromIwDev(interfaceName); freq > 0 {
		return freq
	}
	linkOut, err := execPrivilegedArgv("iw", "dev", interfaceName, "link")
	if err != nil || strings.Contains(linkOut, "Not connected") {
		return staFrequencyFromWpaCli(interfaceName)
	}

	if freq := parseFrequencyFromIwLink(linkOut); freq > 0 {
		return freq
	}
	return staFrequencyFromWpaCli(interfaceName)
}

func parseFrequencyFromIwLink(linkOut string) int {
	if m := iwFreqRegex.FindStringSubmatch(linkOut); len(m) > 1 {
		freq, _ := strconv.Atoi(m[1])
		return freq
	}
	if m := iwChannelRegex.FindStringSubmatch(linkOut); len(m) > 1 {
		if ch, e := strconv.Atoi(m[1]); e == nil && ch > 0 {
			return channelToCenterFreq(ch)
		}
	}
	return 0
}

func channelToCenterFreq(ch int) int {
	if ch >= 1 && ch <= 14 {
		return 2412 + (ch-1)*5
	}
	if ch > 14 && ch < 200 {
		return 5000 + ch*5
	}
	return 0
}

func staFrequencyFromWpaCli(interfaceName string) int {
	socketDir := findWorkingWpaSupplicantSocket(interfaceName)
	if socketDir == "" {
		return 0
	}
	statusOut, _ := runPrivilegedCommand("wpa_cli", "-i", interfaceName, "-p", socketDir, "status")
	if !strings.Contains(statusOut, "wpa_state=COMPLETED") {
		return 0
	}
	if m := wpaFreqRegex.FindStringSubmatch(statusOut); len(m) > 1 {
		freq, _ := strconv.Atoi(m[1])
		return freq
	}
	return 0
}

func readHostapdChannelMode() (channel int, hwMode string) {
	content, err := readPrivilegedFile(hostapdConfigPath)
	if err != nil {
		return 0, ""
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "channel=") {
			if v, e := strconv.Atoi(strings.TrimPrefix(line, "channel=")); e == nil && v > 0 {
				channel = v
			}
		}
		if strings.HasPrefix(line, "hw_mode=") {
			if v := strings.TrimPrefix(line, "hw_mode="); v != "" {
				hwMode = v
			}
		}
	}
	return channel, hwMode
}
