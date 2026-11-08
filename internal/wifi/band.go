package wifi

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	band24GHz = "2.4"
	band5GHz  = "5"
)

// bandFromFrequency devuelve "2.4" o "5" según la frecuencia en MHz; cadena vacía si no es WiFi.
func bandFromFrequency(freq int) string {
	switch {
	case is24GHzFrequency(freq):
		return band24GHz
	case is5GHzFrequency(freq):
		return band5GHz
	default:
		return ""
	}
}

// isDFSFrequency indica si la frecuencia 5 GHz cae en un canal DFS (radar): 52–64 y 100–144.
// El driver brcmfmac del Raspberry Pi NO puede ejecutar un AP en canales DFS (no hace detección
// de radar/CAC), por lo que el AP "hostberry" nunca debe persistir ni arrancar en estos canales.
func isDFSFrequency(freq int) bool {
	if !is5GHzFrequency(freq) {
		return false
	}
	ch := freqToChannel(freq)
	return (ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144)
}

// hwModeForFrequency devuelve el hw_mode de hostapd ("g" para 2.4 GHz, "a" para 5 GHz).
func hwModeForFrequency(freq int) string {
	if ch := freqToChannel(freq); ch > 14 {
		return "a"
	}
	return "g"
}

// defaultAPChannelForBand devuelve un canal por defecto sensato para la banda indicada.
// Para 5 GHz se usa el canal 36 (UNII-1, NO es DFS) para que hostapd pueda arrancar en frío
// sin esperar el CAC de radar que exigen los canales DFS (52–144) en brcmfmac.
func defaultAPChannelForBand(band string) int {
	if band == band5GHz {
		return 36
	}
	return 6
}

// SetWizardAPBand fija la banda del AP "hostberry" (2.4 o 5 GHz) durante el asistente inicial.
// Devuelve el canal operativo real, la banda operativa ("2.4" o "5") y un error si la banda pedida
// no pudo aplicarse (p. ej. brcmfmac mantiene el AP en 2.4 aunque hostapd.conf diga 5 GHz).
func SetWizardAPBand(band string) (channel int, actualBand string, err error) {
	if band != band24GHz && band != band5GHz {
		return 0, "", fmt.Errorf("banda inválida: %q (use 2.4 o 5)", band)
	}
	ch := defaultAPChannelForBand(band)
	freq := channelToCenterFreq(ch)
	mode := "g"
	if band == band5GHz {
		mode = "a"
	}

	if apFreq := apLinkFrequency(); apFreq > 0 && bandFromFrequency(apFreq) == band {
		opCh := freqToChannel(apFreq)
		_ = writeHostapdChannelMode(opCh, hwModeForFrequency(apFreq))
		return opCh, band, nil
	}

	if hostapdServiceActive() && switchAPChannelViaCSA(freq) {
		_ = writeHostapdChannelMode(ch, mode)
		time.Sleep(1500 * time.Millisecond)
		return finalizeWizardAPBand(band, ch)
	}

	if err := writeHostapdChannelMode(ch, mode); err != nil {
		return 0, "", fmt.Errorf("no se pudo escribir hostapd.conf: %w", err)
	}
	if out, restartErr := execPrivilegedArgv("systemctl", "restart", "hostapd"); restartErr != nil {
		return 0, "", fmt.Errorf("no se pudo reiniciar hostapd: %v (%s)", restartErr, strings.TrimSpace(out))
	}
	_, _ = execPrivilegedArgv("systemctl", "restart", "dnsmasq")
	time.Sleep(2 * time.Second)
	return finalizeWizardAPBand(band, ch)
}

func finalizeWizardAPBand(requestedBand string, requestedCh int) (int, string, error) {
	opFreq := apLinkFrequency()
	if opFreq <= 0 {
		return requestedCh, requestedBand, nil
	}
	opCh := freqToChannel(opFreq)
	opMode := hwModeForFrequency(opFreq)
	opBand := bandFromFrequency(opFreq)
	if opBand == "" {
		opBand = band24GHz
	}
	_ = writeHostapdChannelMode(opCh, opMode)
	if opBand != requestedBand {
		return opCh, opBand, fmt.Errorf(
			"no se pudo mover el AP a %s GHz; la antena sigue en %s GHz (solo se muestran redes de esa banda)",
			requestedBand, opBand,
		)
	}
	return opCh, opBand, nil
}

// apLinkFrequency devuelve la frecuencia (MHz) del AP concurrente (ap0), o 0 si no aplica.
func apLinkFrequency() int {
	if !concurrentAPInterfacePresent() {
		return 0
	}
	if freq := linkFrequencyFromIwDev(apCSAInterface); freq > 0 {
		return freq
	}
	out, err := execPrivilegedArgvTimeout([]string{"iw", "dev", apCSAInterface, "info"}, 3*time.Second)
	if err != nil {
		return 0
	}
	if m := iwFreqRegex.FindStringSubmatch(out); len(m) > 1 {
		if freq, e := strconv.Atoi(m[1]); e == nil && freq > 0 {
			return freq
		}
	}
	if m := iwChannelRegex.FindStringSubmatch(out); len(m) > 1 {
		if ch, e := strconv.Atoi(m[1]); e == nil && ch > 0 {
			return channelToCenterFreq(ch)
		}
	}
	return 0
}

// linkFrequencyFromIwDev lee la frecuencia con `iw dev <iface> info/link` sin privilegios elevados.
func linkFrequencyFromIwDev(iface string) int {
	if err := validateInterfaceName(iface); err != nil {
		return 0
	}
	for _, sub := range []string{"link", "info"} {
		cmd := exec.Command("iw", "dev", iface, sub)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		text := string(out)
		if strings.Contains(text, "Not connected") && sub == "link" {
			continue
		}
		if freq := parseFrequencyFromIwLink(text); freq > 0 {
			return freq
		}
	}
	return 0
}

// concurrentOperatingBand detecta la banda activa en modo AP+STA (STA > AP > hostapd.conf).
// Devuelve "2.4", "5" o "" si no hay AP concurrente.
func concurrentOperatingBand(interfaceName string) string {
	if !concurrentAPInterfacePresent() {
		return ""
	}
	if freq := staLinkFrequency(interfaceName); freq > 0 {
		if band := bandFromFrequency(freq); band != "" {
			return band
		}
	}
	if freq := apLinkFrequency(); freq > 0 {
		if band := bandFromFrequency(freq); band != "" {
			return band
		}
	}
	// No confiar en hostapd.conf: en brcmfmac puede decir 5 GHz mientras la radio emite 2.4 GHz.
	return band24GHz
}

// operatingBandForScan elige la banda para escanear en AP+STA. Prioriza la radio real (STA/AP)
// frente a hostapd.conf, que puede quedar desactualizado.
func operatingBandForScan(interfaceName string) string {
	if !concurrentAPInterfacePresent() {
		return ""
	}
	if freq := linkFrequencyFromIwDev(interfaceName); freq > 0 {
		if band := bandFromFrequency(freq); band != "" {
			return band
		}
	}
	if freq := linkFrequencyFromIwDev(apCSAInterface); freq > 0 {
		if band := bandFromFrequency(freq); band != "" {
			return band
		}
	}
	// Nunca usar hostapd.conf para escanear: un conf desactualizado filtraría la banda equivocada.
	return band24GHz
}

// scanFreqArgForBand construye el argumento freq= para wpa_cli scan limitado a una banda.
func scanFreqArgForBand(band string) string {
	switch band {
	case band24GHz:
		return scan24GHzFreqArg()
	case band5GHz:
		return scan5GHzFreqArg()
	default:
		return ""
	}
}

// scan5GHzFreqArg construye freq= con los canales 5 GHz habituales (36–165).
func scan5GHzFreqArg() string {
	channels := []int{
		36, 40, 44, 48, 52, 56, 60, 64,
		100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
		149, 153, 157, 161, 165,
	}
	freqs := make([]string, 0, len(channels))
	for _, ch := range channels {
		if freq := channelToCenterFreq(ch); freq > 0 {
			freqs = append(freqs, fmt.Sprintf("%d", freq))
		}
	}
	return "freq=" + strings.Join(freqs, ",")
}

// bandFreqList devuelve las frecuencias (separadas por espacio) de una banda para usar con
// `wpa_cli set_network <id> freq_list ...`. Restringe la asociación a la banda elegida en el
// asistente, de modo que en SSIDs de doble banda (mismo nombre en 2.4 y 5 GHz) wpa_supplicant
// no elija el BSS de la otra banda (p. ej. conectarse a 5 GHz cuando el usuario eligió 2.4).
func bandFreqList(band string) string {
	var freqs []string
	switch band {
	case band24GHz:
		for ch := 1; ch <= 13; ch++ {
			freqs = append(freqs, fmt.Sprintf("%d", 2412+(ch-1)*5))
		}
	case band5GHz:
		for _, ch := range []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165} {
			if f := channelToCenterFreq(ch); f > 0 {
				freqs = append(freqs, fmt.Sprintf("%d", f))
			}
		}
	default:
		return ""
	}
	return strings.Join(freqs, " ")
}

func isScanNetworkOnBand(net map[string]interface{}, band string) bool {
	if band == "" {
		return true
	}
	on5 := is5GHzScanNetwork(net)
	switch band {
	case band5GHz:
		return on5
	case band24GHz:
		return !on5
	default:
		return true
	}
}

// filterScanNetworksByBand deja solo redes de la banda indicada; band vacía = sin filtrar.
func filterScanNetworksByBand(networks []map[string]interface{}, band string) []map[string]interface{} {
	if band == "" || len(networks) == 0 {
		return networks
	}
	filtered := make([]map[string]interface{}, 0, len(networks))
	for _, net := range networks {
		if isScanNetworkOnBand(net, band) {
			filtered = append(filtered, net)
		}
	}
	return filtered
}
