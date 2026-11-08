package wifi

import (
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/auth"
	"hostberry/internal/constants"
)

// WifiSetupInfoHandler devuelve información para el asistente inicial: interfaz STA detectada,
// si existe un AP concurrente (radio única AP+STA), si el driver soporta CSA (cambio de canal
// sin desconectar clientes), el dominio regulatorio (país) y, si ya hay conexión WiFi, el canal
// y la frecuencia actuales para que el AP "hostberry" pueda alinearse al mismo canal.
func WifiSetupInfoHandler(c *fiber.Ctx) error {
	iface := detectWiFiInterface()
	if iface == "" {
		iface = constants.DefaultWiFiInterface
	}

	concurrent := concurrentAPInterfacePresent()

	freq := staLinkFrequency(iface)
	channel := 0
	if freq > 0 {
		channel = freqToChannel(freq)
	}

	band := band24GHz
	if concurrent {
		if b := concurrentOperatingBand(iface); b != "" {
			band = b
		}
	} else if freq > 0 {
		if b := bandFromFrequency(freq); b != "" {
			band = b
		}
	}

	defaultAPChannel := defaultAPChannelForBand(band)
	if channel > 0 {
		defaultAPChannel = channel
	} else if apFreq := apLinkFrequency(); apFreq > 0 {
		if apCh := freqToChannel(apFreq); apCh > 0 {
			defaultAPChannel = apCh
		}
	}

	country := regulatoryCountry()
	if country == "" {
		country = constants.DefaultCountryCode
	}

	resp := fiber.Map{
		"success":            true,
		"interface":          iface,
		"concurrent_ap":      concurrent,
		"csa_supported":      driverSupportsCSA(),
		"country":            country,
		"band":               band,
		"default_ap_channel": defaultAPChannel,
		"connected":          channel > 0,
	}
	if channel > 0 {
		resp["channel"] = channel
		resp["frequency"] = freq
	}
	if auth.IsInitialSetupPending() {
		resp["scan_band"] = band24GHz
		resp["deferred_band"] = true
		if pb := GetWizardPreferredBand(); pb != "" {
			resp["preferred_band"] = pb
			resp["band"] = pb
		} else {
			resp["band"] = band24GHz
		}
	}
	return c.JSON(resp)
}

// regulatoryCountry lee el dominio regulatorio actual con `iw reg get` (p. ej. "ES").
func regulatoryCountry() string {
	out, err := execPrivilegedArgvTimeout([]string{"iw", "reg", "get"}, 3*time.Second)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "country ") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "country "))
		code := strings.TrimSpace(strings.SplitN(rest, ":", 2)[0])
		if len(code) == 2 && code != "00" {
			return strings.ToUpper(code)
		}
	}
	return ""
}

// driverSupportsCSA indica si el driver anuncia el comando de channel switch (CSA), necesario
// para mover el AP de canal sin desasociar a los clientes (móvil del wizard). La capacidad es
// estática (hardware/driver), así que se cachea para no ejecutar `iw list` en cada petición.
var (
	csaOnce      sync.Once
	csaSupported bool
)

func driverSupportsCSA() bool {
	csaOnce.Do(func() {
		out, err := execPrivilegedArgvTimeout([]string{"iw", "list"}, 5*time.Second)
		if err != nil || strings.TrimSpace(out) == "" {
			csaSupported = false
			return
		}
		low := strings.ToLower(out)
		csaSupported = strings.Contains(low, "channel_switch") || strings.Contains(low, "channel switch")
	})
	return csaSupported
}
