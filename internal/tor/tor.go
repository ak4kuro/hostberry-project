package tor

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"hostberry/internal/i18n"
	"hostberry/internal/utils"
	"hostberry/internal/validators"
)

// TorConfigOptions agrupa todas las opciones de configuración de Tor (incl. estilo Onion Pi).
type TorConfigOptions struct {
	User                  string
	EnableSocks           bool
	SocksPort             int
	EnableControlPort     bool
	ControlPort           int
	EnableHiddenService   bool
	EnableTransPort       bool // Proxy transparente (TransPort), estilo Onion Pi
	TransPort             int  // Por defecto 9040
	EnableDNSPort         bool // DNS a través de Tor
	DNSPort               int  // Por defecto 53
	ClientOnly            bool // Solo cliente, no relay ni exit
	AutomapHostsOnResolve bool // Resolver .onion y .exit a través de Tor
}

// Rutas típicas del binario tor (por si PATH no incluye /usr/bin en el proceso)
var torBinaryPaths = []string{"/usr/bin/tor", "/usr/sbin/tor"}

func executeArgv(args ...string) (string, error) {
	return utils.ExecuteArgv(args...)
}

func isTorInstalled() bool {
	// Primero: PATH (sin shell).
	if _, err := exec.LookPath("tor"); err == nil {
		return true
	}
	// Segundo: comprobar rutas conocidas (útil cuando el proceso no tiene /usr/bin en PATH, p. ej. systemd)
	for _, p := range torBinaryPaths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// Funciones para Tor
func getTorStatus() map[string]interface{} {
	result := make(map[string]interface{})

	// Verificar si está instalado (PATH + rutas conocidas)
	installed := isTorInstalled()
	result["installed"] = installed

	if !installed {
		result["active"] = false
		result["success"] = true
		return result
	}

	// Verificar estado del servicio
	status := "inactive"
	if statusOut, err := exec.Command("systemctl", "is-active", "tor").Output(); err == nil {
		status = strings.TrimSpace(string(statusOut))
	}
	result["active"] = status == "active"
	result["status"] = status

	// Verificar si está habilitado para iniciar al arranque
	enabled := "disabled"
	if enabledOut, err := exec.Command("systemctl", "is-enabled", "tor").Output(); err == nil {
		enabled = strings.TrimSpace(string(enabledOut))
	}
	result["enabled"] = enabled == "enabled"

	// Leer configuración si existe
	configPath := "/etc/tor/torrc"
	if _, err := os.Stat(configPath); err == nil {
		result["config_exists"] = true
		result["config_path"] = configPath
	} else {
		result["config_exists"] = false
	}

	// Verificar puerto SOCKS si está activo
	if result["active"] == true {
		// Intentar conectar al puerto SOCKS por defecto (9050) sin pipeline.
		socksListening := false
		if out, err := exec.Command("netstat", "-tuln").Output(); err == nil {
			if strings.Contains(string(out), ":9050") {
				socksListening = true
			}
		}
		if !socksListening {
			if out, err := exec.Command("ss", "-tuln").Output(); err == nil {
				if strings.Contains(string(out), ":9050") {
					socksListening = true
				}
			}
		}
		result["socks_port"] = "9050"
		result["socks_listening"] = socksListening
	}

	// Verificar IP actual a través de Tor (si está activo)
	if result["active"] == true && result["socks_listening"] == true {
		// Intentar obtener IP a través de Tor usando curl
		ipOut, err := exec.Command(
			"curl",
			"-s",
			"--socks5-hostname",
			"127.0.0.1:9050",
			"https://api.ipify.org",
		).Output()
		if err == nil {
			ip := strings.TrimSpace(string(ipOut))
			if ip != "" && !strings.Contains(ip, "error") {
				result["tor_ip"] = ip
			}
		}
	}

	// Estado de iptables (red hostapd torificada)
	iptStatus := getTorIptablesStatus()
	if active, ok := iptStatus["active"].(bool); ok {
		result["iptables_active"] = active
	}
	if iface, ok := iptStatus["interface"].(string); ok {
		result["iptables_interface"] = iface
	}

	result["success"] = true
	return result
}

func installTor(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.tor_installing", user)

	// Verificar si ya está instalado
	if isTorInstalled() {
		result["success"] = true
		result["message"] = "Tor ya está instalado"
		result["already_installed"] = true
		return result
	}

	// Intentar instalar Tor (update + install como argv separados)
	var out string
	var err error
	if _, uerr := executeArgv("apt-get", "update"); uerr == nil {
		out, err = executeArgv("apt-get", "install", "-y", "tor")
	} else {
		err = uerr
	}
	if err != nil {
		// Si falla, intentar con otros métodos (por compatibilidad: devolvemos el error)
		i18n.LogTf("logs.tor_install_error", err)
		result["success"] = false
		result["error"] = fmt.Sprintf("Error instalando Tor: %v", err)
		if out != "" {
			result["error"] = strings.TrimSpace(out)
		}
		return result
	}

	result["success"] = true
	result["message"] = "Tor instalado correctamente"
	i18n.LogT("logs.tor_installed")
	return result
}

func configureTor(opts TorConfigOptions) map[string]interface{} {
	result := make(map[string]interface{})

	if opts.User == "" {
		opts.User = "unknown"
	}

	i18n.LogTf("logs.tor_configuring", opts.User)

	// Verificar si está instalado
	if !isTorInstalled() {
		result["success"] = false
		result["error"] = "Tor no está instalado. Instálalo primero."
		return result
	}

	configDir := "/etc/tor"
	configPath := filepath.Join(configDir, "torrc")

	// Crear directorio si no existe
	_, _ = executeArgv("mkdir", "-p", configDir)

	// Valores por defecto
	if opts.SocksPort == 0 {
		opts.SocksPort = 9050
	}
	if opts.ControlPort == 0 {
		opts.ControlPort = 9051
	}
	if opts.TransPort == 0 {
		opts.TransPort = 9040
	}
	if opts.DNSPort == 0 {
		opts.DNSPort = 53
	}

	// Bloques opcionales para torrc
	socksBlock := ""
	if opts.EnableSocks {
		socksBlock = fmt.Sprintf("SocksPort %d\nSocksPolicy accept 127.0.0.1\nSocksPolicy reject *\n", opts.SocksPort)
	} else {
		socksBlock = fmt.Sprintf("# SocksPort %d (deshabilitado)\n", opts.SocksPort)
	}

	controlBlock := ""
	if opts.EnableControlPort {
		controlBlock = fmt.Sprintf("ControlPort %d\nCookieAuthentication 1\n", opts.ControlPort)
	} else {
		controlBlock = fmt.Sprintf("# ControlPort %d (deshabilitado)\n", opts.ControlPort)
	}

	// Estilo Onion Pi: proxy transparente, DNS y resolución .onion/.exit
	transBlock := ""
	if opts.EnableTransPort {
		transBlock = fmt.Sprintf("TransPort %d\n", opts.TransPort)
	}
	dnsBlock := ""
	if opts.EnableDNSPort {
		dnsBlock = fmt.Sprintf("DNSPort %d\n", opts.DNSPort)
	}

	clientOnlyLine := ""
	if opts.ClientOnly {
		clientOnlyLine = "ClientOnly 1\n"
	}

	automapLines := ""
	if opts.AutomapHostsOnResolve {
		automapLines = "AutomapHostsSuffixes .onion,.exit\nAutomapHostsOnResolve 1\n"
	}

	hiddenBlock := ""
	if opts.EnableHiddenService {
		hiddenBlock = `# Servicio oculto (ejemplo)
# HiddenServiceDir /var/lib/tor/hidden_service/
# HiddenServicePort 80 127.0.0.1:80
`
	}

	configContent := fmt.Sprintf(`# Configuración Tor para HostBerry (compatible con estilo Onion Pi)
# Generado automáticamente - https://github.com/breadtk/onion_pi

DataDirectory /var/lib/tor
Log notice file /var/log/tor/notices.log
RunAsDaemon 1

# SOCKS Proxy (puerto explícito para aplicaciones)
%s
# Control Port
%s
# Proxy transparente (para redirección por iptables, estilo Onion Pi)
%s
# DNS a través de Tor (DNSPort)
%s
# Solo cliente, no relay ni exit
%s
# Resolver .onion y .exit a través de Tor
%s
DisableDebuggerAttachment 1
NumEntryGuards 3
CircuitBuildTimeout 10
KeepalivePeriod 60
NewCircuitPeriod 30
SafeLogging 1
AvoidDiskWrites 0

%s
`, socksBlock, controlBlock, transBlock, dnsBlock, clientOnlyLine, automapLines, hiddenBlock)

	// Escribir configuración
	if teeCmd, err := utils.NewArgvCommand("tee", configPath); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error escribiendo configuración: %v", err)
		return result
	} else {
		teeCmd.Stdin = strings.NewReader(configContent)
		teeCmd.Stdout = io.Discard
		teeCmd.Stderr = io.Discard
		if err := teeCmd.Run(); err != nil {
			result["success"] = false
			result["error"] = fmt.Sprintf("Error escribiendo configuración: %v", err)
			i18n.LogTf("logs.tor_config_error", err)
			return result
		}
	}

	// Crear directorio de datos y logs
	_, _ = executeArgv("mkdir", "-p", "/var/lib/tor")
	_, _ = executeArgv("mkdir", "-p", "/var/log/tor")
	if _, err := executeArgv("chown", "debian-tor:debian-tor", "/var/lib/tor", "/var/log/tor"); err != nil {
		_, _ = executeArgv("chown", "tor:tor", "/var/lib/tor", "/var/log/tor")
	}

	result["success"] = true
	result["message"] = "Tor configurado correctamente"
	i18n.LogT("logs.tor_configured")
	return result
}

func enableTor(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.tor_enabling", user)

	// Verificar si está instalado
	if !isTorInstalled() {
		result["success"] = false
		result["error"] = "Tor no está instalado. Instálalo primero."
		return result
	}

	// Verificar configuración
	configPath := "/etc/tor/torrc"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Configurar con valores por defecto (estilo Onion Pi: SOCKS, TransPort, DNSPort, ClientOnly, Automap)
		configResult := configureTor(TorConfigOptions{
			User:                  user,
			EnableSocks:           true,
			SocksPort:             9050,
			EnableControlPort:     true,
			ControlPort:           9051,
			EnableTransPort:       true,
			TransPort:             9040,
			EnableDNSPort:         true,
			DNSPort:               53,
			ClientOnly:            true,
			AutomapHostsOnResolve: true,
		})
		if success, ok := configResult["success"].(bool); !ok || !success {
			result["success"] = false
			result["error"] = "Error configurando Tor antes de iniciarlo"
			if errMsg, ok := configResult["error"].(string); ok {
				result["error"] = errMsg
			}
			return result
		}
	}

	// Iniciar servicio
	if out, err := executeArgv("systemctl", "start", "tor"); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error iniciando Tor: %v", err)
		if out != "" {
			result["error"] = strings.TrimSpace(out)
		}
		i18n.LogTf("logs.tor_start_error", err)
		return result
	}

	// Habilitar para iniciar al arranque
	_, _ = executeArgv("systemctl", "enable", "tor")

	// Esperar un poco para que Tor se inicie
	time.Sleep(2 * time.Second)

	result["success"] = true
	result["message"] = "Tor habilitado correctamente"
	i18n.LogT("logs.tor_enabled")
	return result
}

func disableTor(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.tor_disabling", user)

	// Detener servicio
	_, _ = executeArgv("systemctl", "stop", "tor")
	_, _ = executeArgv("systemctl", "disable", "tor")

	result["success"] = true
	result["message"] = "Tor deshabilitado correctamente"
	i18n.LogT("logs.tor_disabled")
	return result
}

func getTorCircuitInfo() map[string]interface{} {
	result := make(map[string]interface{})

	status := "inactive"
	if statusOut, err := exec.Command("systemctl", "is-active", "tor").Output(); err == nil {
		status = strings.TrimSpace(string(statusOut))
	}

	if status != "active" {
		result["active"] = false
		result["success"] = true
		return result
	}

	// Intentar obtener información del circuito usando control port
	controlCmd := exec.Command("nc", "127.0.0.1", "9051")
	controlCmd.Stdin = strings.NewReader("GETINFO circuit-status\n")
	controlOut, err := controlCmd.Output()
	if err == nil {
		controlOutput := strings.TrimSpace(string(controlOut))
		if controlOutput != "" {
			result["circuit_info"] = controlOutput
		}
	}

	// Intentar obtener IP a través de Tor
	ipOut, err := exec.Command(
		"curl",
		"-s",
		"--socks5-hostname",
		"127.0.0.1:9050",
		"https://api.ipify.org",
	).Output()
	if err == nil {
		ip := strings.TrimSpace(string(ipOut))
		if ip != "" && !strings.Contains(ip, "error") {
			result["tor_ip"] = ip
		}
	}

	result["active"] = true
	result["success"] = true
	return result
}

const torIptablesComment = "HostBerry-Tor"

// runCommandWithOptionalSudo construye un *exec.Cmd privilegiado como argv.
// utils.NewArgvCommand ya decide entre ejecución directa (root) y
// privileged-exec --argv (sudo NOPASSWD), con SUDO_ASKPASS desactivado.
func runCommandWithOptionalSudo(bin string, args ...string) (*exec.Cmd, error) {
	argv := append([]string{bin}, args...)
	return utils.NewArgvCommand(argv...)
}

func iptablesListPREROUTING() (string, error) {
	// Sin shell: la salida se parsea en Go.
	cmd, err := runCommandWithOptionalSudo("iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v")
	if err != nil {
		return "", err
	}
	out, err := cmd.Output()
	return string(out), err
}

func runIptablesRule(args ...string) error {
	cmd, err := runCommandWithOptionalSudo("iptables", args...)
	if err != nil {
		return err
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func persistIptablesRules() {
	// Guardar con netfilter-persistent cuando exista. Ignoramos errores para no bloquear la funcionalidad principal.
	if cmd, err := runCommandWithOptionalSudo("netfilter-persistent", "save"); err == nil {
		_ = cmd.Run()
	}

	// Volcar reglas a /etc/iptables/rules.v4 (estilo heredado del proyecto).
	rulesCmd, err := runCommandWithOptionalSudo("iptables-save")
	if err != nil {
		return
	}
	rules, err := rulesCmd.Output()
	if err != nil {
		return
	}

	teeCmd, err := runCommandWithOptionalSudo("tee", "/etc/iptables/rules.v4")
	if err != nil {
		return
	}
	teeCmd.Stdin = strings.NewReader(string(rules))
	teeCmd.Stdout = io.Discard
	teeCmd.Stderr = io.Discard
	_ = teeCmd.Run()
}

func getHostapdInterface() string {
	configPath := "/etc/hostapd/hostapd.conf"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "ap0"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				iface := strings.TrimSpace(parts[1])
				if iface != "" {
					if validators.ValidateIfaceName(iface) == nil {
						return iface
					}
					return "ap0"
				}
			}
			break
		}
	}
	return "ap0"
}

func getTorIptablesStatus() map[string]interface{} {
	result := make(map[string]interface{})
	result["active"] = false
	result["interface"] = getHostapdInterface()
	result["success"] = true

	out, err := iptablesListPREROUTING()
	if err != nil {
		return result
	}
	// Similar a grep -c "...": basta con saber si existe al menos una regla marcada.
	result["active"] = strings.Contains(out, torIptablesComment)
	return result
}

func enableTorIptables(user string) map[string]interface{} {
	result := make(map[string]interface{})
	if user == "" {
		user = "unknown"
	}

	// Comprobar que Tor está instalado y activo
	status := getTorStatus()
	if inst, _ := status["installed"].(bool); !inst {
		result["success"] = false
		result["error"] = "Tor no está instalado. Instálalo y habilítalo primero."
		return result
	}
	if active, _ := status["active"].(bool); !active {
		result["success"] = false
		result["error"] = "Tor no está activo. Habilita Tor primero."
		return result
	}

	iface := getHostapdInterface()
	transPort := 9040
	dnsPort := 53
	// Opcional: leer puertos del torrc
	if data, err := os.ReadFile("/etc/tor/torrc"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "TransPort ") {
				fmt.Sscanf(line, "TransPort %d", &transPort)
			}
			if strings.HasPrefix(line, "DNSPort ") {
				fmt.Sscanf(line, "DNSPort %d", &dnsPort)
			}
		}
	}

	// Quitar reglas previas para evitar duplicados
	disableTorIptables("")

	// DNS (UDP 53 -> DNSPort)
	if err := runIptablesRule(
		"-t", "nat", "-A", "PREROUTING",
		"-i", iface,
		"-p", "udp",
		"--dport", "53",
		"-j", "REDIRECT",
		"--to-ports", strconv.Itoa(dnsPort),
		"-m", "comment", "--comment", torIptablesComment,
	); err != nil {
		result["success"] = false
		result["error"] = "Error añadiendo regla DNS: " + err.Error()
		i18n.LogTf("logs.tor_iptables_error", err.Error())
		return result
	}

	// TCP (SYN -> TransPort)
	if err := runIptablesRule(
		"-t", "nat", "-A", "PREROUTING",
		"-i", iface,
		"-p", "tcp",
		"--syn",
		"-j", "REDIRECT",
		"--to-ports", strconv.Itoa(transPort),
		"-m", "comment", "--comment", torIptablesComment,
	); err != nil {
		// Intentamos deshacer la regla DNS si existe.
		_ = runIptablesRule(
			"-t", "nat", "-D", "PREROUTING",
			"-i", iface,
			"-p", "udp",
			"--dport", "53",
			"-j", "REDIRECT",
			"--to-ports", strconv.Itoa(dnsPort),
			"-m", "comment", "--comment", torIptablesComment,
		)
		result["success"] = false
		result["error"] = "Error añadiendo regla TCP: " + err.Error()
		return result
	}

	// Persistir reglas si netfilter-persistent está disponible
	persistIptablesRules()

	result["success"] = true
	result["message"] = fmt.Sprintf("Tráfico de la red Hostberry (%s) redirigido a Tor. Los clientes WiFi usarán Tor.", iface)
	result["interface"] = iface
	i18n.LogTf("logs.tor_iptables_enabled", user)
	return result
}

func disableTorIptables(user string) map[string]interface{} {
	result := make(map[string]interface{})
	if user == "" {
		user = "unknown"
	}

	iface := getHostapdInterface()
	transPort := 9040
	dnsPort := 53
	if data, err := os.ReadFile("/etc/tor/torrc"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "TransPort ") {
				fmt.Sscanf(line, "TransPort %d", &transPort)
			}
			if strings.HasPrefix(line, "DNSPort ") {
				fmt.Sscanf(line, "DNSPort %d", &dnsPort)
			}
		}
	}

	// Eliminar reglas (pueden estar duplicadas si se activó dos veces).
	// Repetimos para cubrir casos donde haya más de una regla idéntica.
	for i := 0; i < 5; i++ {
		err := runIptablesRule(
			"-t", "nat", "-D", "PREROUTING",
			"-i", iface,
			"-p", "udp",
			"--dport", "53",
			"-j", "REDIRECT",
			"--to-ports", strconv.Itoa(dnsPort),
			"-m", "comment", "--comment", torIptablesComment,
		)
		if err != nil {
			break
		}
	}
	for i := 0; i < 5; i++ {
		err := runIptablesRule(
			"-t", "nat", "-D", "PREROUTING",
			"-i", iface,
			"-p", "tcp",
			"--syn",
			"-j", "REDIRECT",
			"--to-ports", strconv.Itoa(transPort),
			"-m", "comment", "--comment", torIptablesComment,
		)
		if err != nil {
			break
		}
	}

	persistIptablesRules()

	result["success"] = true
	result["message"] = "Redirección de la red Hostberry a Tor desactivada."
	i18n.LogTf("logs.tor_iptables_disabled", user)
	return result
}

// ---- wrappers exportados ----

func GetTorStatus() map[string]interface{}                      { return getTorStatus() }
func InstallTor(user string) map[string]interface{}             { return installTor(user) }
func ConfigureTor(opts TorConfigOptions) map[string]interface{} { return configureTor(opts) }
func EnableTor(user string) map[string]interface{}              { return enableTor(user) }
func DisableTor(user string) map[string]interface{}             { return disableTor(user) }
func GetTorCircuitInfo() map[string]interface{}                 { return getTorCircuitInfo() }
func GetTorIptablesStatus() map[string]interface{}              { return getTorIptablesStatus() }
func EnableTorIptables(user string) map[string]interface{}      { return enableTorIptables(user) }
func DisableTorIptables(user string) map[string]interface{}     { return disableTorIptables(user) }
