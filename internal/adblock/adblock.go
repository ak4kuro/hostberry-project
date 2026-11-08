package adblock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"hostberry/internal/i18n"
	"hostberry/internal/utils"

	"gopkg.in/yaml.v3"
)

// executeCommand delega al helper seguro en internal/utils.
// Se mantiene el mismo nombre para minimizar cambios mecánicos al mover el módulo.
func executeCommand(cmd string) (string, error) {
	return utils.ExecuteCommand(cmd)
}

func getAdBlockStatus() map[string]interface{} {
	result := make(map[string]interface{})

	dnsmasqOut, _ := exec.Command("systemctl", "is-active", "dnsmasq").Output()
	dnsmasqStatus := strings.TrimSpace(string(dnsmasqOut))
	if dnsmasqStatus == "" {
		dnsmasqStatus = "inactive"
	}

	piholeOut, _ := exec.Command("systemctl", "is-active", "pihole-FTL").Output()
	piholeStatus := strings.TrimSpace(string(piholeOut))
	if piholeStatus == "" {
		piholeStatus = "inactive"
	}

	// Verificar DNSCrypt
	dnscryptOut, _ := exec.Command("systemctl", "is-active", "dnscrypt-proxy").Output()
	dnscryptStatus := strings.TrimSpace(string(dnscryptOut))
	if dnscryptStatus == "" {
		dnscryptStatus = "inactive"
	}

	// Verificar Blocky
	blockyOut, _ := exec.Command("systemctl", "is-active", "blocky").Output()
	blockyStatus := strings.TrimSpace(string(blockyOut))
	if blockyStatus == "" {
		blockyStatus = "inactive"
	}

	// Verificar si dnscrypt-proxy está instalado
	_, dnscryptLookErr := exec.LookPath("dnscrypt-proxy")
	dnscryptInstalled := dnscryptLookErr == nil

	blockyInstalled := blockyBinaryExists()

	result["active"] = dnsmasqStatus == "active" || piholeStatus == "active" || dnscryptStatus == "active" || blockyStatus == "active"
	result["type"] = "none"

	// Prioridad: Blocky > DNSCrypt > dnsmasq > Pi-hole
	if blockyStatus == "active" {
		result["type"] = "blocky"
	} else if dnscryptStatus == "active" {
		result["type"] = "dnscrypt"
	} else if dnsmasqStatus == "active" {
		result["type"] = "dnsmasq"
	} else if piholeStatus == "active" {
		result["type"] = "pihole"
	}

	result["dnscrypt_installed"] = dnscryptInstalled
	result["dnscrypt_active"] = dnscryptStatus == "active"
	result["blocky_installed"] = blockyInstalled
	result["blocky_active"] = blockyStatus == "active"

	if result["active"] == true {
		if result["type"] == "blocky" {
			result["blocked_domains"] = 0 // Blocky no expone conteo por API; la web mostrará estado de bloqueo
		} else if hostsContent, err := os.ReadFile("/etc/hosts"); err == nil {
			blockedCount := strings.Count(string(hostsContent), "0.0.0.0")
			result["blocked_domains"] = blockedCount
		} else {
			result["blocked_domains"] = 0
		}
	} else {
		result["blocked_domains"] = 0
	}

	result["success"] = true
	return result
}

func enableAdBlock(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.adblock_enabling", user)

	dnsmasqCmd := "sudo systemctl start dnsmasq"
	if _, err := executeCommand(dnsmasqCmd); err != nil {
		piholeCmd := "sudo systemctl start pihole-FTL"
		if out2, err2 := executeCommand(piholeCmd); err2 != nil {
			result["success"] = false
			result["error"] = err2.Error()
			if out2 != "" {
				result["error"] = strings.TrimSpace(out2)
			}
			result["message"] = "Error iniciando servicio AdBlock"
			i18n.LogTf("logs.adblock_enable_error", err2)
			return result
		}
	}

	result["success"] = true
	result["message"] = "AdBlock habilitado"
	i18n.LogT("logs.adblock_enabled")
	return result
}

func disableAdBlock(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.adblock_disabling", user)

	executeCommand("sudo systemctl stop dnsmasq 2>/dev/null || true")
	executeCommand("sudo systemctl stop blocky")

	result["success"] = true
	result["message"] = "AdBlock deshabilitado"
	i18n.LogT("logs.adblock_disabled")
	return result
}

// Funciones para DNSCrypt
func getDNSCryptStatus() map[string]interface{} {
	result := make(map[string]interface{})

	// Verificar si está instalado
	_, err := exec.LookPath("dnscrypt-proxy")
	installed := err == nil
	result["installed"] = installed

	if !installed {
		result["active"] = false
		result["success"] = true
		return result
	}

	// Verificar estado del servicio
	statusOut, _ := exec.Command("systemctl", "is-active", "dnscrypt-proxy").Output()
	status := strings.TrimSpace(string(statusOut))
	result["active"] = status == "active"
	result["status"] = status

	// Verificar si está habilitado para iniciar al arranque
	enabledOut, _ := exec.Command("systemctl", "is-enabled", "dnscrypt-proxy").Output()
	enabled := strings.TrimSpace(string(enabledOut))
	result["enabled"] = enabled == "enabled"

	// Leer configuración si existe
	configPath := "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
	if _, err := os.Stat(configPath); err == nil {
		result["config_exists"] = true
		result["config_path"] = configPath
	} else {
		result["config_exists"] = false
	}

	// Verificar qué servidor está usando
	if result["active"] == true {
		logOut, err := exec.Command("journalctl", "-u", "dnscrypt-proxy", "-n", "10", "--no-pager").Output()
		if err == nil {
			matches := []string{}
			for _, line := range strings.Split(string(logOut), "\n") {
				if strings.Contains(strings.ToLower(line), "server") {
					if s := strings.TrimSpace(line); s != "" {
						matches = append(matches, s)
					}
				}
			}
			if len(matches) > 0 {
				result["current_server"] = matches[len(matches)-1]
			}
		}
	}

	result["success"] = true
	return result
}

func installDNSCrypt(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.dnscrypt_installing", user)

	// Verificar si ya está instalado
	if _, err := exec.LookPath("dnscrypt-proxy"); err == nil {
		result["success"] = true
		result["message"] = "DNSCrypt ya está instalado"
		result["already_installed"] = true
		return result
	}

	// Intentar instalar dnscrypt-proxy
	// Primero intentar con apt (Debian/Ubuntu)
	installCmd := "sudo apt-get update && sudo apt-get install -y dnscrypt-proxy"
	if out, err := executeCommand(installCmd); err != nil {
		// Si falla, intentar compilar desde fuente o usar otro método
		i18n.LogTf("logs.dnscrypt_install_error", err)
		result["success"] = false
		result["error"] = fmt.Sprintf("Error instalando DNSCrypt: %v", err)
		if out != "" {
			result["error"] = strings.TrimSpace(out)
		}
		return result
	}

	result["success"] = true
	result["message"] = "DNSCrypt instalado correctamente"
	i18n.LogT("logs.dnscrypt_installed")
	return result
}

func configureDNSCrypt(serverName string, blockAds bool, user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.dnscrypt_configuring", user)

	// Verificar si está instalado
	if _, err := exec.LookPath("dnscrypt-proxy"); err != nil {
		result["success"] = false
		result["error"] = "DNSCrypt no está instalado. Instálalo primero."
		return result
	}

	configDir := "/etc/dnscrypt-proxy"
	configPath := filepath.Join(configDir, "dnscrypt-proxy.toml")

	// Crear directorio si no existe
	executeCommand(fmt.Sprintf("sudo mkdir -p %s", configDir))

	// Servidores DNSCrypt recomendados que filtran publicidad
	servers := map[string]string{
		"adguard-dns":      "sdns://AQMAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		"adguard-dns-ipv6": "sdns://AQMAAAAAAAAAGVsyYTAwOjVhODA6MjIwMDo6XTo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		"quad9-dnscrypt":   "sdns://AQMAAAAAAAAADTkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LXByb3h5LnF1YWQ5Lm5ldA",
		"cloudflare":       "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5",
	}

	// Solo se aceptan los servidores conocidos: el nombre se incrusta en el
	// TOML y un valor arbitrario permitiría inyectar directivas.
	if _, ok := servers[serverName]; !ok {
		serverName = "adguard-dns"
	}
	serverSDNS := servers[serverName]

	// Configuración básica de dnscrypt-proxy.toml
	configContent := fmt.Sprintf(`# Configuración DNSCrypt para HostBerry
# Generado automáticamente

listen_addresses = ['127.0.0.1:53', '[::1]:53']

# Servidor DNSCrypt
server_names = ['%s']

# Si no se especifica servidor, usar lista pública
[static]
  [static.'%s']
    stamp = '%s'

# Bloquear dominios de publicidad si está habilitado
%s

# Logs
log_file = '/var/log/dnscrypt-proxy/dnscrypt-proxy.log'
log_level = 2

# Cache
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400

# Consultas simultáneas
max_clients = 250

# Timeouts
timeout = 5000
`, serverName, serverName, serverSDNS, func() string {
		if blockAds {
			return `# Lista de bloqueo de publicidad
[blocked_names]
  blocked_names_file = '/etc/dnscrypt-proxy/blocklist.txt'
  log_file = '/var/log/dnscrypt-proxy/blocked.log'
  log_format = 'tsv'
`
		}
		return ""
	}())

	// Escribir configuración
	cmd := exec.Command("sudo", "tee", configPath)
	cmd.Stdin = strings.NewReader(configContent)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error escribiendo configuración: %v", err)
		i18n.LogTf("logs.dnscrypt_config_error", err)
		return result
	}

	// Si blockAds está habilitado, crear lista de bloqueo básica
	if blockAds {
		blocklistPath := "/etc/dnscrypt-proxy/blocklist.txt"
		blocklistContent := `# Lista de bloqueo de publicidad y rastreadores
# Dominios comunes de publicidad
ads.*
advertising.*
tracking.*
analytics.*
doubleclick.*
googleadservices.*
googlesyndication.*
`

		blocklistCmd := exec.Command("sudo", "tee", blocklistPath)
		blocklistCmd.Stdin = strings.NewReader(blocklistContent)
		blocklistCmd.Stdout = io.Discard
		blocklistCmd.Stderr = io.Discard
		blocklistCmd.Run() // Ignorar errores
	}

	// Crear directorio de logs
	executeCommand("sudo mkdir -p /var/log/dnscrypt-proxy")

	result["success"] = true
	result["message"] = "DNSCrypt configurado correctamente"
	i18n.LogT("logs.dnscrypt_configured")
	return result
}

func enableDNSCrypt(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.dnscrypt_enabling", user)

	// Verificar si está instalado
	if _, err := exec.LookPath("dnscrypt-proxy"); err != nil {
		result["success"] = false
		result["error"] = "DNSCrypt no está instalado. Instálalo primero."
		return result
	}

	// Verificar configuración
	configPath := "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Configurar con valores por defecto
		configResult := configureDNSCrypt("adguard-dns", true, user)
		if success, ok := configResult["success"].(bool); !ok || !success {
			result["success"] = false
			result["error"] = "Error configurando DNSCrypt antes de iniciarlo"
			if errMsg, ok := configResult["error"].(string); ok {
				result["error"] = errMsg
			}
			return result
		}
	}

	// Iniciar servicio
	startCmd := "sudo systemctl start dnscrypt-proxy"
	if out, err := executeCommand(startCmd); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error iniciando DNSCrypt: %v", err)
		if out != "" {
			result["error"] = strings.TrimSpace(out)
		}
		i18n.LogTf("logs.dnscrypt_start_error", err)
		return result
	}

	// Habilitar para iniciar al arranque
	executeCommand("sudo systemctl enable dnscrypt-proxy")

	// Configurar sistema para usar DNSCrypt como DNS local
	// Cambiar /etc/resolv.conf para apuntar a 127.0.0.1
	resolvConf := "/etc/resolv.conf"
	backupCmd := fmt.Sprintf("sudo cp %s %s.backup 2>/dev/null || true", resolvConf, resolvConf)
	executeCommand(backupCmd)

	// Leer resolv.conf actual
	content, err := os.ReadFile(resolvConf)
	newLines := []string{}
	if err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "nameserver") {
				newLines = append(newLines, line)
			}
		}
	}

	// Agregar nameserver local
	newLines = append(newLines, "nameserver 127.0.0.1")
	newLines = append(newLines, "nameserver ::1")

	newContent := strings.Join(newLines, "\n")
	writeCmd := exec.Command("sudo", "tee", resolvConf)
	writeCmd.Stdin = strings.NewReader(newContent)
	writeCmd.Stdout = io.Discard
	writeCmd.Stderr = io.Discard
	if err := writeCmd.Run(); err != nil {
		i18n.LogTf("logs.dnscrypt_resolv_error", err)
		// No es crítico, continuar
	}

	// Reiniciar systemd-resolved si existe
	executeCommand("sudo systemctl restart systemd-resolved 2>/dev/null || true")

	result["success"] = true
	result["message"] = "DNSCrypt habilitado correctamente"
	i18n.LogT("logs.dnscrypt_enabled")
	return result
}

func disableDNSCrypt(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.dnscrypt_disabling", user)

	// Detener servicio
	executeCommand("sudo systemctl stop dnscrypt-proxy")
	executeCommand("sudo systemctl disable dnscrypt-proxy")

	// Restaurar /etc/resolv.conf si existe backup
	resolvConf := "/etc/resolv.conf"
	backupPath := resolvConf + ".backup"
	if _, err := os.Stat(backupPath); err == nil {
		restoreCmd := fmt.Sprintf("sudo cp %s %s", backupPath, resolvConf)
		executeCommand(restoreCmd)
	} else {
		// Si no hay backup, usar DNS públicos por defecto
		content := "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
		writeCmd := exec.Command("sudo", "tee", resolvConf)
		writeCmd.Stdin = strings.NewReader(content)
		writeCmd.Stdout = io.Discard
		writeCmd.Stderr = io.Discard
		writeCmd.Run()
	}

	// Reiniciar systemd-resolved si existe
	executeCommand("sudo systemctl restart systemd-resolved 2>/dev/null || true")

	result["success"] = true
	result["message"] = "DNSCrypt deshabilitado correctamente"
	i18n.LogT("logs.dnscrypt_disabled")
	return result
}

// --- Blocky ---

const blockyConfigDir = "/etc/blocky"
const blockyConfigPath = "/etc/blocky/config.yml"
const blockyHTTPPort = "4000"
const blockyVersion = "v0.28.2"

func blockyBinaryExists() bool {
	// Servicio blocky o binario en path
	if out, err := exec.Command("systemctl", "cat", "blocky").Output(); err == nil && strings.Contains(string(out), "blocky") {
		return true
	}
	if _, err := exec.LookPath("blocky"); err == nil {
		return true
	}
	if _, err := os.Stat("/usr/local/bin/blocky"); err == nil {
		return true
	}
	return false
}

// blockyAPIBlockingStatus llama a la API de Blocky (GET /api/blocking/status) y devuelve el JSON como map.
func blockyAPIBlockingStatus() map[string]interface{} {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + blockyHTTPPort + "/api/blocking/status")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out map[string]interface{}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	return out
}

// blockyMetrics obtiene estadísticas desde el endpoint Prometheus /metrics de Blocky.
// Devuelve blocked (consultas bloqueadas), total (consultas totales), cached (desde caché).
func blockyMetrics() (blocked, total, cached int64) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + blockyHTTPPort + "/metrics")
	if err != nil || resp == nil {
		return 0, 0, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, 0
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, 0
	}
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// blocky_response_total{..., response_type="Blocked"} 123
		if strings.HasPrefix(line, "blocky_response_total") {
			idx := strings.LastIndex(line, " ")
			if idx <= 0 {
				continue
			}
			valStr := strings.TrimSpace(line[idx:])
			val, _ := strconv.ParseInt(valStr, 10, 64)
			if strings.Contains(line, `response_type="Blocked"`) {
				blocked += val
			} else if strings.Contains(line, `response_type="Cached"`) {
				cached += val
			}
			continue
		}
		// blocky_query_total{client="...", type="A"} 456
		if strings.HasPrefix(line, "blocky_query_total") {
			idx := strings.LastIndex(line, " ")
			if idx <= 0 {
				continue
			}
			valStr := strings.TrimSpace(line[idx:])
			val, _ := strconv.ParseInt(valStr, 10, 64)
			total += val
		}
	}
	return blocked, total, cached
}

func getBlockyStatus() map[string]interface{} {
	result := make(map[string]interface{})
	installed := blockyBinaryExists()
	result["installed"] = installed
	result["active"] = false
	result["success"] = true

	if !installed {
		return result
	}

	statusOut, _ := exec.Command("systemctl", "is-active", "blocky").Output()
	status := strings.TrimSpace(string(statusOut))
	result["active"] = status == "active"
	result["status"] = status

	enabledOut, _ := exec.Command("systemctl", "is-enabled", "blocky").Output()
	result["enabled"] = strings.TrimSpace(string(enabledOut)) == "enabled"

	if _, err := os.Stat(blockyConfigPath); err == nil {
		result["config_exists"] = true
		result["config_path"] = blockyConfigPath
	} else {
		result["config_exists"] = false
	}

	// Datos desde la API de Blocky (bloqueo habilitado/deshabilitado, grupos)
	if result["active"] == true {
		if apiStatus := blockyAPIBlockingStatus(); apiStatus != nil {
			result["blocking_enabled"] = apiStatus["enabled"]
			result["disabled_groups"] = apiStatus["disabledGroups"]
		}
		// Estadísticas desde Prometheus /metrics (consultas bloqueadas, totales, caché)
		blocked, total, cached := blockyMetrics()
		result["blocked_queries"] = blocked
		result["total_queries"] = total
		result["cached_queries"] = cached
	}

	return result
}

// blockyConfigYAML refleja la estructura que escribimos en config.yml para poder leerla.
type blockyConfigYAML struct {
	Upstreams struct {
		Groups map[string][]string `yaml:"groups"`
	} `yaml:"upstreams"`
	Blocking struct {
		Denylists map[string][]string `yaml:"denylists"`
	} `yaml:"blocking"`
}

// getBlockyConfig lee la configuración actual de Blocky y devuelve upstreams y block_lists.
func getBlockyConfig() map[string]interface{} {
	result := map[string]interface{}{
		"upstreams":   []string{},
		"block_lists": []string{},
	}
	cmd := exec.Command("sudo", "cat", blockyConfigPath)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return result
	}
	var cfg blockyConfigYAML
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		return result
	}
	if g, ok := cfg.Upstreams.Groups["default"]; ok {
		result["upstreams"] = g
	}
	if d, ok := cfg.Blocking.Denylists["default"]; ok {
		result["block_lists"] = d
	}
	return result
}

func installBlocky(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.blocky_installing", user)

	if blockyBinaryExists() {
		result["success"] = true
		result["message"] = "Blocky ya está instalado"
		result["already_installed"] = true
		return result
	}

	// Detectar arquitectura en tiempo de ejecución (uname -m)
	var arch string
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		switch strings.TrimSpace(string(out)) {
		case "x86_64", "amd64":
			arch = "x86_64"
		case "aarch64":
			arch = "arm64"
		case "armv7l", "armhf":
			arch = "armv7"
		case "armv6l":
			arch = "armv6"
		default:
			arch = "x86_64"
		}
	} else {
		switch runtime.GOARCH {
		case "amd64", "386":
			arch = "x86_64"
		case "arm64":
			arch = "arm64"
		case "arm":
			arch = "armv7"
		default:
			arch = "x86_64"
		}
	}

	url := fmt.Sprintf("https://github.com/0xERR0R/blocky/releases/download/%s/blocky_%s_Linux_%s.tar.gz", blockyVersion, blockyVersion, arch)
	tmpDir := "/tmp/blocky_install"
	executeCommand("sudo rm -rf " + tmpDir)
	executeCommand("sudo mkdir -p " + tmpDir)

	// Descargar con HTTP desde Go (no depender de curl en PATH)
	tarballPath := filepath.Join(os.TempDir(), "blocky_download.tar.gz")
	client := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error preparando descarga: %v", err)
		return result
	}
	req.Header.Set("User-Agent", "HostBerry/1.0")
	resp, err := client.Do(req)
	if err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error descargando Blocky: %v", err)
		i18n.LogTf("logs.blocky_install_error", err)
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error descargando Blocky: HTTP %d", resp.StatusCode)
		return result
	}
	tarballFile, err := os.Create(tarballPath)
	if err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error creando archivo temporal: %v", err)
		return result
	}
	defer tarballFile.Close()
	_, err = io.Copy(tarballFile, resp.Body)
	if err != nil {
		os.Remove(tarballPath)
		result["success"] = false
		result["error"] = fmt.Sprintf("Error guardando descarga: %v", err)
		i18n.LogTf("logs.blocky_install_error", err)
		return result
	}
	defer os.Remove(tarballPath)

	// Copiar a dir con sudo y extraer con tar (ruta absoluta para no depender de PATH)
	copyCmd := fmt.Sprintf("sudo cp %s %s/blocky.tar.gz", tarballPath, tmpDir)
	if out, err := executeCommand(copyCmd); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error copiando descarga: %v", err)
		if out != "" {
			result["error"] = strings.TrimSpace(out)
		}
		return result
	}
	// Importante: evitar "sudo sh -c" para no depender de shells desde executeCommand.
	tarballInTmp := filepath.Join(tmpDir, "blocky.tar.gz")
	if out, err := exec.Command("sudo", "tar", "-xzf", tarballInTmp, "-C", tmpDir).CombinedOutput(); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error extrayendo Blocky: %v", err)
		if out != nil {
			outStr := strings.TrimSpace(string(out))
			if outStr != "" {
				result["error"] = outStr
			}
		}
		return result
	}
	if out, err := exec.Command("sudo", "cp", filepath.Join(tmpDir, "blocky"), "/usr/local/bin/blocky").CombinedOutput(); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error copiando Blocky: %v", err)
		if out != nil {
			outStr := strings.TrimSpace(string(out))
			if outStr != "" {
				result["error"] = outStr
			}
		}
		return result
	}
	if out, err := exec.Command("sudo", "chmod", "+x", "/usr/local/bin/blocky").CombinedOutput(); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error haciendo ejecutable Blocky: %v", err)
		if out != nil {
			outStr := strings.TrimSpace(string(out))
			if outStr != "" {
				result["error"] = outStr
			}
		}
		return result
	}

	// Crear directorio de configuración
	executeCommand("sudo mkdir -p " + blockyConfigDir)

	// Crear unidad systemd
	serviceContent := `[Unit]
Description=Blocky DNS proxy and ad-blocker
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/blocky --config ` + blockyConfigPath + `
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`
	servicePath := "/etc/systemd/system/blocky.service"
	writeCmd := exec.Command("sudo", "tee", servicePath)
	writeCmd.Stdin = strings.NewReader(serviceContent)
	if err := writeCmd.Run(); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error creando servicio systemd: %v", err)
		return result
	}
	executeCommand("sudo systemctl daemon-reload")
	// Que Blocky arranque con el sistema
	executeCommand("sudo systemctl enable blocky")

	executeCommand("sudo rm -rf " + tmpDir)

	result["success"] = true
	result["message"] = "Blocky instalado correctamente"
	i18n.LogT("logs.blocky_installed")
	return result
}

func configureBlocky(upstreams []string, blockLists []string, user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.blocky_configuring", user)

	if !blockyBinaryExists() {
		result["success"] = false
		result["error"] = "Blocky no está instalado. Instálalo primero."
		return result
	}

	if len(upstreams) == 0 {
		upstreams = []string{"1.1.1.1", "8.8.8.8", "https://dns.cloudflare.com/dns-query"}
	}
	if len(blockLists) == 0 {
		blockLists = []string{
			"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
		}
	}

	// Generar config.yml. Rechazar valores con caracteres de control: un '\n'
	// permitiría inyectar claves arbitrarias en el YAML de Blocky.
	yamlSafe := func(s string) bool {
		for _, r := range s {
			if r < 0x20 || r == 0x7F {
				return false
			}
		}
		return true
	}
	var upLines []string
	for _, u := range upstreams {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if !yamlSafe(u) {
			result["success"] = false
			result["error"] = "Upstream DNS contiene caracteres no permitidos"
			return result
		}
		upLines = append(upLines, "    - "+u)
	}
	var listLines []string
	for _, l := range blockLists {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !yamlSafe(l) {
			result["success"] = false
			result["error"] = "URL de lista de bloqueo contiene caracteres no permitidos"
			return result
		}
		listLines = append(listLines, "  - "+l)
	}

	configContent := `# Blocky - Configuración generada por HostBerry
# No editar manualmente si se gestiona desde la web.

upstreams:
  groups:
    default:
` + strings.Join(upLines, "\n") + `

blocking:
  denylists:
    default:
` + strings.Join(listLines, "\n") + `
  blockType: zeroIp
  refreshPeriod: 4h

ports:
  dns: 127.0.0.1:53
  http: 127.0.0.1:4000

log:
  level: warn
  format: text
`

	// Escribir configuración: si somos root, escribir directamente; si no, temporal + sudo cp
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(blockyConfigDir, 0755); err != nil {
			result["success"] = false
			result["error"] = fmt.Sprintf("Error creando directorio: %v", err)
			return result
		}
		if err := os.WriteFile(blockyConfigPath, []byte(configContent), 0644); err != nil {
			result["success"] = false
			result["error"] = fmt.Sprintf("Error escribiendo configuración: %v", err)
			i18n.LogTf("logs.blocky_config_error", err)
			return result
		}
	} else {
		if _, err := executeCommand("sudo mkdir -p " + blockyConfigDir); err != nil {
			result["success"] = false
			result["error"] = fmt.Sprintf("Error creando directorio: %v", err)
			return result
		}
		tmpFile, err := os.CreateTemp("", "blocky_config_*.yml")
		if err != nil {
			result["success"] = false
			result["error"] = fmt.Sprintf("Error creando archivo temporal: %v", err)
			return result
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)
		if _, err := tmpFile.WriteString(configContent); err != nil {
			tmpFile.Close()
			result["success"] = false
			result["error"] = fmt.Sprintf("Error escribiendo configuración: %v", err)
			return result
		}
		if err := tmpFile.Close(); err != nil {
			result["success"] = false
			result["error"] = fmt.Sprintf("Error cerrando archivo: %v", err)
			return result
		}
		cpCmd := "sudo cp " + tmpPath + " " + blockyConfigPath
		out, cpErr := executeCommand(cpCmd)
		if cpErr != nil {
			result["success"] = false
			result["error"] = "Error escribiendo configuración: " + strings.TrimSpace(out)
			if out == "" {
				result["error"] = fmt.Sprintf("Error escribiendo configuración: %v", cpErr)
			}
			i18n.LogTf("logs.blocky_config_error", cpErr)
			return result
		}
	}

	result["success"] = true
	result["message"] = "Blocky configurado correctamente"
	i18n.LogT("logs.blocky_configured")
	return result
}

func enableBlocky(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.blocky_enabling", user)

	if !blockyBinaryExists() {
		result["success"] = false
		result["error"] = "Blocky no está instalado. Instálalo primero."
		return result
	}

	if _, err := os.Stat(blockyConfigPath); os.IsNotExist(err) {
		configResult := configureBlocky(nil, nil, user)
		if success, ok := configResult["success"].(bool); !ok || !success {
			result["success"] = false
			result["error"] = "Error generando configuración por defecto"
			if errMsg, ok := configResult["error"].(string); ok {
				result["error"] = errMsg
			}
			return result
		}
	}

	// Liberar puerto 53: detener dnsmasq si está (Blocky es el único DNS que usamos)
	executeCommand("sudo systemctl stop dnsmasq 2>/dev/null || true")

	startCmd := "sudo systemctl start blocky"
	if out, err := executeCommand(startCmd); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error iniciando Blocky: %v", err)
		if out != "" {
			result["error"] = strings.TrimSpace(out)
		}
		i18n.LogTf("logs.blocky_start_error", err)
		return result
	}

	executeCommand("sudo systemctl enable blocky")

	// Configurar resolv.conf para usar Blocky local (temp file + sudo cp para no requerir sudo sh)
	resolvConf := "/etc/resolv.conf"
	backupCmd := fmt.Sprintf("sudo cp %s %s.backup 2>/dev/null || true", resolvConf, resolvConf)
	executeCommand(backupCmd)

	content, _ := os.ReadFile(resolvConf)
	newLines := []string{}
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "nameserver") {
			newLines = append(newLines, line)
		}
	}
	newLines = append(newLines, "nameserver 127.0.0.1", "nameserver ::1")
	newContent := strings.Join(newLines, "\n")
	tmpResolv := filepath.Join(os.TempDir(), "hostberry_resolv.conf")
	if err := os.WriteFile(tmpResolv, []byte(newContent), 0644); err == nil {
		executeCommand(fmt.Sprintf("sudo cp %s %s", tmpResolv, resolvConf))
		os.Remove(tmpResolv)
	}
	executeCommand("sudo systemctl restart systemd-resolved 2>/dev/null || true")

	result["success"] = true
	result["message"] = "Blocky habilitado correctamente"
	i18n.LogT("logs.blocky_enabled")
	return result
}

func disableBlocky(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.blocky_disabling", user)

	executeCommand("sudo systemctl stop blocky")
	executeCommand("sudo systemctl disable blocky")

	resolvConf := "/etc/resolv.conf"
	backupPath := resolvConf + ".backup"
	if _, err := os.Stat(backupPath); err == nil {
		executeCommand(fmt.Sprintf("sudo cp %s %s", backupPath, resolvConf))
	} else {
		tmpResolv := filepath.Join(os.TempDir(), "hostberry_resolv.conf")
		if err := os.WriteFile(tmpResolv, []byte("nameserver 8.8.8.8\nnameserver 8.8.4.4\n"), 0644); err == nil {
			executeCommand(fmt.Sprintf("sudo cp %s %s", tmpResolv, resolvConf))
			os.Remove(tmpResolv)
		}
	}
	executeCommand("sudo systemctl restart systemd-resolved 2>/dev/null || true")

	result["success"] = true
	result["message"] = "Blocky deshabilitado correctamente"
	i18n.LogT("logs.blocky_disabled")
	return result
}

// blockyAPIProxy realiza una petición a la API de Blocky y devuelve el cuerpo y código.
// Usado por el handler que hace de proxy para el frontend.
func blockyAPIProxy(method, path string, body []byte) (int, []byte) {
	baseURL := "http://127.0.0.1:" + blockyHTTPPort + "/api"
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := baseURL + path
	var req *http.Request
	var err error
	if len(body) > 0 {
		req, err = http.NewRequest(method, url, bytes.NewReader(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// ---- Exportados para el paquete principal ----

func GetAdBlockStatus() map[string]interface{}           { return getAdBlockStatus() }
func EnableAdBlock(user string) map[string]interface{}   { return enableAdBlock(user) }
func DisableAdBlock(user string) map[string]interface{}  { return disableAdBlock(user) }
func GetDNSCryptStatus() map[string]interface{}          { return getDNSCryptStatus() }
func InstallDNSCrypt(user string) map[string]interface{} { return installDNSCrypt(user) }
func ConfigureDNSCrypt(serverName string, blockAds bool, user string) map[string]interface{} {
	return configureDNSCrypt(serverName, blockAds, user)
}
func EnableDNSCrypt(user string) map[string]interface{}  { return enableDNSCrypt(user) }
func DisableDNSCrypt(user string) map[string]interface{} { return disableDNSCrypt(user) }

func GetBlockyStatus() map[string]interface{}          { return getBlockyStatus() }
func GetBlockyConfig() map[string]interface{}          { return getBlockyConfig() }
func InstallBlocky(user string) map[string]interface{} { return installBlocky(user) }
func ConfigureBlocky(upstreams []string, blockLists []string, user string) map[string]interface{} {
	return configureBlocky(upstreams, blockLists, user)
}
func EnableBlocky(user string) map[string]interface{}  { return enableBlocky(user) }
func DisableBlocky(user string) map[string]interface{} { return disableBlocky(user) }
func BlockyAPIProxy(method, path string, body []byte) (int, []byte) {
	return blockyAPIProxy(method, path, body)
}
