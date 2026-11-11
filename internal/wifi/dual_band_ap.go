package wifi

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	dualBandProfilesPath    = "/opt/hostberry/data/ap-dual-band.json"
	hostapdActiveConfigPath = "/etc/hostapd/hostapd.conf"
	hostapdActiveDataPath   = "/opt/hostberry/data/hostapd-active.conf"
	hostapd2GDataPath       = "/opt/hostberry/data/hostapd-2g.conf"
	hostapd5GDataPath       = "/opt/hostberry/data/hostapd-5g.conf"
	secondaryAPInterface    = "ap1"
)

// DualBandAPProfile describe un punto de acceso HostBerry en una banda.
type DualBandAPProfile struct {
	SSID     string `json:"ssid"`
	Channel  int    `json:"channel"`
	Security string `json:"security"` // open, wpa2, wpa3
	Password string `json:"password,omitempty"`
	Country  string `json:"country"`
}

// DualBandAPConfig almacena los perfiles 2.4 y 5 GHz del portal HostBerry.
type DualBandAPConfig struct {
	Band24 DualBandAPProfile `json:"band_24"`
	Band5  DualBandAPProfile `json:"band_5"`
}

// DefaultDualBandAPConfig devuelve la configuración por defecto (hostberry + hostberry-5G).
func DefaultDualBandAPConfig(country string) DualBandAPConfig {
	if country == "" {
		country = "ES"
	}
	return DualBandAPConfig{
		Band24: DualBandAPProfile{
			SSID:     "hostberry",
			Channel:  6,
			Security: "open",
			Country:  country,
		},
		Band5: DualBandAPProfile{
			SSID:     "hostberry-5G",
			Channel:  36,
			Security: "open",
			Country:  country,
		},
	}
}

// LoadDualBandAPConfig carga perfiles desde disco o devuelve valores por defecto.
func LoadDualBandAPConfig(country string) DualBandAPConfig {
	def := DefaultDualBandAPConfig(country)
	b, err := os.ReadFile(dualBandProfilesPath)
	if err != nil {
		return def
	}
	var cfg DualBandAPConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return def
	}
	if strings.TrimSpace(cfg.Band24.SSID) == "" {
		cfg.Band24 = def.Band24
	}
	if strings.TrimSpace(cfg.Band5.SSID) == "" {
		cfg.Band5 = def.Band5
	}
	if cfg.Band24.Channel < 1 {
		cfg.Band24.Channel = def.Band24.Channel
	}
	if cfg.Band5.Channel < 36 {
		cfg.Band5.Channel = def.Band5.Channel
	}
	// El AP no puede operar en canales DFS (brcmfmac): forzar el canal NO-DFS por defecto.
	if isDFSFrequency(channelToCenterFreq(cfg.Band5.Channel)) {
		cfg.Band5.Channel = def.Band5.Channel
	}
	if cfg.Band24.Country == "" {
		cfg.Band24.Country = country
	}
	if cfg.Band5.Country == "" {
		cfg.Band5.Country = country
	}
	return cfg
}

// SaveDualBandAPConfig persiste los perfiles dual-band.
func SaveDualBandAPConfig(cfg DualBandAPConfig) error {
	if err := os.MkdirAll(filepath.Dir(dualBandProfilesPath), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dualBandProfilesPath, b, 0600)
}

// ProfileForBand devuelve el perfil correspondiente a "2.4" o "5".
func (c DualBandAPConfig) ProfileForBand(band string) DualBandAPProfile {
	if band == band5GHz {
		return c.Band5
	}
	return c.Band24
}

func complementaryBand(band string) string {
	if band == band5GHz {
		return band24GHz
	}
	return band5GHz
}

func listPhyNames() []string {
	entries, err := os.ReadDir("/sys/class/ieee80211")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func phyForInterface(iface string) string {
	if iface == "" {
		return ""
	}
	path := filepath.Join("/sys/class/net", iface, "phy80211", "name")
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func secondaryPhy(primaryPhy string) string {
	for _, p := range listPhyNames() {
		if p != primaryPhy {
			return p
		}
	}
	return ""
}

func renderHostapdConfig(iface string, profile DualBandAPProfile, band string) string {
	ch := profile.Channel
	if ch <= 0 {
		ch = defaultAPChannelForBand(band)
	}
	mode := "g"
	if band == band5GHz || ch > 14 {
		mode = "a"
	}
	country := strings.ToUpper(strings.TrimSpace(profile.Country))
	if len(country) != 2 {
		country = "ES"
	}
	for _, r := range country {
		if r < 'A' || r > 'Z' {
			country = "ES"
			break
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "interface=%s\n", iface)
	b.WriteString("driver=nl80211\n")
	b.WriteString("ctrl_interface=/run/hostapd\n")
	b.WriteString("ctrl_interface_group=0\n")
	// hostapd.conf no admite escapes: eliminar caracteres de control y comillas
	// del SSID/contraseña para no inyectar directivas (config validada al entrar,
	// esto cubre valores antiguos ya persistidos).
	fmt.Fprintf(&b, "ssid=%s\n", sanitizeHostapdValue(profile.SSID))
	fmt.Fprintf(&b, "hw_mode=%s\n", mode)
	fmt.Fprintf(&b, "channel=%d\n", ch)
	fmt.Fprintf(&b, "country_code=%s\n", country)
	b.WriteString("ieee80211d=1\n")
	b.WriteString("ignore_broadcast_ssid=0\n")
	b.WriteString("wmm_enabled=1\n")
	b.WriteString("ieee80211n=1\n")
	// Aislamiento entre clientes: hostapd descarta las tramas entre estaciones
	// asociadas, de modo que los dispositivos WiFi no pueden verse ni comunicarse
	// entre sí (solo con la pasarela/Internet). Mejora la privacidad y la seguridad.
	b.WriteString("ap_isolate=1\n")
	if mode == "a" {
		b.WriteString("ieee80211ac=1\n")
	}

	switch profile.Security {
	case "wpa2":
		b.WriteString("auth_algs=1\n")
		b.WriteString("wpa=2\n")
		fmt.Fprintf(&b, "wpa_passphrase=%s\n", sanitizeHostapdValue(profile.Password))
		b.WriteString("wpa_key_mgmt=WPA-PSK\n")
		b.WriteString("wpa_pairwise=CCMP\n")
		b.WriteString("rsn_pairwise=CCMP\n")
	case "wpa3":
		b.WriteString("auth_algs=1\n")
		b.WriteString("wpa=2\n")
		fmt.Fprintf(&b, "wpa_passphrase=%s\n", sanitizeHostapdValue(profile.Password))
		b.WriteString("wpa_key_mgmt=WPA-PSK-SHA256\n")
		b.WriteString("wpa_pairwise=CCMP\n")
		b.WriteString("rsn_pairwise=CCMP\n")
	default:
		b.WriteString("auth_algs=1\n")
		b.WriteString("wpa=0\n")
	}

	return b.String()
}

func writeHostapdConfigFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0640)
}

func writePrivilegedHostapdConfig(path, content string) error {
	dataPath := hostapdActiveDataPath
	if path != hostapdActiveConfigPath {
		dataPath = filepath.Join(WpaSupplicantRuntimeConfigDir, "hostapd-"+filepath.Base(path)+".tmp")
	}
	if err := writeHostapdConfigFile(dataPath, content); err != nil {
		return err
	}
	if path == hostapdActiveConfigPath {
		if err := writeHostapdConfigFile(hostapdActiveDataPath, content); err != nil {
			return err
		}
	}
	if _, err := execPrivilegedArgv("cp", dataPath, path); err != nil {
		return err
	}
	_, err := execPrivilegedArgv("chmod", "644", path)
	return err
}

func ensureVirtualAP(phyName, iface string) error {
	if _, err := os.Stat(filepath.Join("/sys/class/net", iface)); err == nil {
		_, _ = execPrivilegedArgvTimeout([]string{"ip", "link", "set", iface, "up"}, 2*time.Second)
		return nil
	}
	if _, err := execPrivilegedArgvTimeout([]string{"iw", "phy", phyName, "interface", "add", iface, "type", "__ap"}, 8*time.Second); err != nil {
		return err
	}
	if _, err := execPrivilegedArgvTimeout([]string{"ip", "link", "set", iface, "up"}, 3*time.Second); err != nil {
		log.Printf("dual_band_ap: ip link set %s up: %v", iface, err)
	}
	// `ip addr add` falla si la dirección ya existe; `replace` cubre ambos casos.
	_, _ = execPrivilegedArgvTimeout([]string{"ip", "addr", "replace", "192.168.4.1/24", "dev", iface}, 3*time.Second)
	return nil
}

// EnsureDualBandHostapd escribe perfiles 2.4/5 GHz y activa el AP según la banda de la STA.
// Con una segunda radio (USB), emite también la banda complementaria en ap1.
func EnsureDualBandHostapd(staInterface string, setupPending bool) map[string]interface{} {
	return ensureDualBandHostapdImpl(staInterface, setupPending, "")
}

// EnsureDualBandHostapdForBand es como EnsureDualBandHostapd pero fuerza la banda activa del AP.
// Se usa al finalizar el wizard: la STA aún no está conectada a la banda objetivo, así que
// concurrentOperatingBand devolvería "2.4" y el AP quedaría con el SSID/canal equivocado.
func EnsureDualBandHostapdForBand(staInterface string, setupPending bool, forcedBand string) map[string]interface{} {
	return ensureDualBandHostapdImpl(staInterface, setupPending, forcedBand)
}

func ensureDualBandHostapdImpl(staInterface string, setupPending bool, forcedBand string) map[string]interface{} {
	result := map[string]interface{}{"success": true}
	if staInterface == "" {
		staInterface = detectWiFiInterface()
	}

	country := regulatoryCountry()
	cfg := LoadDualBandAPConfig(country)
	activeBand := concurrentOperatingBand(staInterface)
	if activeBand == "" {
		activeBand = band24GHz
	}

	coldStartSetup := setupPending && !hostapdServiceActive()

	// Si se fuerza una banda (p. ej. al finalizar el wizard), usarla directamente.
	if forcedBand == band24GHz || forcedBand == band5GHz {
		activeBand = forcedBand
	} else if setupPending {
		activeBand = band24GHz
		if cfg.Band24.Channel < 1 || cfg.Band24.Channel > 14 {
			cfg.Band24.Channel = 6
		}
	} else {
		// Fuera del asistente: ajustar canal del perfil activo al de la STA/AP si ya hay enlace.
		// Nunca persistir un canal DFS (52–144) en el perfil del AP: brcmfmac no puede emitir el
		// AP en DFS, así que para esas redes el AP se queda en su canal NO-DFS por defecto.
		if freq := staLinkFrequency(staInterface); freq > 0 && !isDFSFrequency(freq) {
			if ch := freqToChannel(freq); ch > 0 {
				if activeBand == band5GHz {
					cfg.Band5.Channel = ch
				} else {
					cfg.Band24.Channel = ch
				}
			}
		} else if apFreq := apLinkFrequency(); apFreq > 0 {
			if ch := freqToChannel(apFreq); ch > 0 {
				if b := bandFromFrequency(apFreq); b == band5GHz {
					cfg.Band5.Channel = ch
					activeBand = band5GHz
				} else if b == band24GHz {
					cfg.Band24.Channel = ch
					activeBand = band24GHz
				}
			}
		}
	}

	_ = SaveDualBandAPConfig(cfg)

	content24 := renderHostapdConfig(apCSAInterface, cfg.Band24, band24GHz)
	content5 := renderHostapdConfig(apCSAInterface, cfg.Band5, band5GHz)

	if err := writeHostapdConfigFile(hostapd2GDataPath, content24); err != nil {
		log.Printf("HostBerry dual-band: no se pudo escribir %s: %v", hostapd2GDataPath, err)
	}
	if err := writeHostapdConfigFile(hostapd5GDataPath, content5); err != nil {
		log.Printf("HostBerry dual-band: no se pudo escribir %s: %v", hostapd5GDataPath, err)
	}

	activeProfile := cfg.ProfileForBand(activeBand)
	// Durante TODO el asistente el portal cautivo "hostberry" debe ser ABIERTO (sin contraseña) para
	// que cualquiera pueda conectarse y abrirlo. La seguridad elegida por el usuario se guarda en el
	// JSON y se aplica al reiniciar al finalizar el asistente. Antes solo se forzaba en arranque en
	// frío; con hostapd ya activo el AP quedaba con WPA2 y pedía clave.
	if setupPending {
		activeProfile.Security = "open"
		activeProfile.Password = ""
	}
	if coldStartSetup && (activeProfile.Channel < 1 || activeProfile.Channel > 14) {
		activeProfile.Channel = 6
	}
	activeContent := renderHostapdConfig(apCSAInterface, activeProfile, activeBand)
	if err := writePrivilegedHostapdConfig(hostapdActiveConfigPath, activeContent); err != nil {
		result["success"] = false
		result["error"] = err.Error()
		return result
	}

	result["active_band"] = activeBand
	result["ssid_24"] = cfg.Band24.SSID
	result["ssid_5"] = cfg.Band5.SSID
	result["channel_24"] = cfg.Band24.Channel
	result["channel_5"] = cfg.Band5.Channel
	result["dual_radio"] = false

	primaryPhy := phyForInterface(staInterface)
	secPhy := secondaryPhy(primaryPhy)
	if secPhy != "" {
		result["dual_radio"] = true
		otherBand := complementaryBand(activeBand)
		otherProfile := cfg.ProfileForBand(otherBand)
		otherContent := renderHostapdConfig(secondaryAPInterface, otherProfile, otherBand)
		otherPath := hostapd2GDataPath
		if otherBand == band5GHz {
			otherPath = hostapd5GDataPath
		}
		if err := ensureVirtualAP(secPhy, secondaryAPInterface); err != nil {
			log.Printf("HostBerry dual-band: no se pudo crear %s en %s: %v", secondaryAPInterface, secPhy, err)
		} else if err := writeHostapdConfigFile(otherPath, otherContent); err != nil {
			log.Printf("HostBerry dual-band: no se pudo escribir perfil secundario: %v", err)
		} else {
			result["secondary_ap"] = secondaryAPInterface
			result["secondary_band"] = otherBand
			result["secondary_ssid"] = otherProfile.SSID
		}
	}

	// Alinear en caliente si hostapd ya está activo (nunca reiniciar en frío a 5 GHz DFS).
	// Durante el asistente el AP debe permanecer en 2.4 GHz: no alinear a una STA en 5 GHz.
	if !coldStartSetup {
		if freq := staLinkFrequency(staInterface); freq > 0 {
			if !setupPending || bandFromFrequency(freq) == band24GHz {
				alignAPToFreqViaCSA(freq)
			}
		}
	}

	return result
}

// ConcurrentOperatingBandExport expone la banda activa AP+STA para otros paquetes.
func ConcurrentOperatingBandExport(interfaceName string) string {
	return concurrentOperatingBand(interfaceName)
}

// PhyForInterfaceExport devuelve el nombre phy de una interfaz.
func PhyForInterfaceExport(iface string) string {
	return phyForInterface(iface)
}

// SecondaryPhyExport devuelve un phy distinto al primario (p. ej. dongle USB).
func SecondaryPhyExport(primaryPhy string) string {
	return secondaryPhy(primaryPhy)
}

// StaLinkFrequencyExport expone la frecuencia STA conectada (MHz).
func StaLinkFrequencyExport(interfaceName string) int {
	return staLinkFrequency(interfaceName)
}

// AlignAPToFreqViaCSAExport alinea el AP al canal de freq sin reiniciar hostapd.
func AlignAPToFreqViaCSAExport(freq int) bool {
	return alignAPToFreqViaCSA(freq)
}
