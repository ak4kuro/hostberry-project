package utils

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"hostberry/internal/auth"
	"hostberry/internal/config"
	"hostberry/internal/database"
	"hostberry/internal/i18n"
	"hostberry/internal/models"
	"hostberry/internal/validators"
)

const (
	defaultCommandTimeout = 30 * time.Second
	cacheTTL              = 5 * time.Second
)

type cachedResult struct {
	output    string
	err       error
	timestamp time.Time
}

var (
	commandCache  = make(map[string]*cachedResult)
	cacheMutex    sync.RWMutex
	sudoAvailable *bool
)

// CreateDefaultAdmin crea el usuario admin inicial si la BD está vacía.
func CreateDefaultAdmin() {
	var count int64
	if err := database.DB.Model(&models.User{}).Count(&count).Error; err != nil {
		if config.AppConfig.Server.Debug {
			i18n.LogTf("logs.utils_count_error", err)
		}
		return
	}

	if config.AppConfig.Server.Debug {
		i18n.LogTf("logs.utils_users_count", count)
	}

	if count == 0 {
		if config.AppConfig.Server.Debug {
			i18n.LogTln("logs.utils_creating_admin")
		}

		adminPassword := strings.TrimSpace(os.Getenv("HOSTBERRY_DEFAULT_ADMIN_PASSWORD"))
		if adminPassword == "" {
			log.Printf("SECURITY: No se creó el usuario admin inicial porque falta HOSTBERRY_DEFAULT_ADMIN_PASSWORD. Define una contraseña fuerte y reinicia el servicio.")
			return
		}
		if err := validators.ValidatePassword(adminPassword); err != nil {
			i18n.LogTf("logs.utils_admin_error", fmt.Errorf("HOSTBERRY_DEFAULT_ADMIN_PASSWORD inválida: %w", err))
			return
		}

		var admin *models.User
		var err error
		admin, err = auth.Register("admin", adminPassword, "admin@hostberry.local")
		if err != nil {
			i18n.LogTf("logs.utils_admin_error", err)
		} else {
			if config.AppConfig.Server.Debug {
				i18n.LogT("logs.utils_admin_success")
			}
			_ = admin
		}
	}
}

// ExecuteCommand ejecuta un comando permitido con timeout por defecto.
func ExecuteCommand(cmd string) (string, error) {
	return ExecuteCommandWithTimeout(cmd, defaultCommandTimeout)
}

// ExecuteCommandWithTimeout ejecuta un comando permitido con caché y timeout.
func ExecuteCommandWithTimeout(cmd string, timeout time.Duration) (string, error) {
	cacheKey := cmd + "|" + timeout.String()

	cacheMutex.RLock()
	if cached, exists := commandCache[cacheKey]; exists {
		if time.Since(cached.timestamp) < cacheTTL {
			cacheMutex.RUnlock()
			return cached.output, cached.err
		}
	}
	cacheMutex.RUnlock()

	if err := validateShellCommandAllowList(cmd, allowedShellCommands); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	baseCmd := execCommand(cmd)
	cmdObj := exec.CommandContext(ctx, baseCmd.Path)
	cmdObj.Args = baseCmd.Args
	cmdObj.Env = append(os.Environ(),
		"SUDO_ASKPASS=/bin/false",
		"SUDO_LOG_FILE=",
		"HOSTNAME="+getHostname(),
	)

	out, err := cmdObj.CombinedOutput()
	outputStr := FilterSudoErrorString(string(out))

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = exec.ErrNotFound
		}
		if outputStr == "" {
			cacheMutex.Lock()
			commandCache[cacheKey] = &cachedResult{output: "", err: err, timestamp: time.Now()}
			cacheMutex.Unlock()
			return "", err
		}
	}

	result := strings.TrimSpace(outputStr)

	cacheMutex.Lock()
	commandCache[cacheKey] = &cachedResult{output: result, err: err, timestamp: time.Now()}
	if len(commandCache) > 100 {
		for k := range commandCache {
			if time.Since(commandCache[k].timestamp) > cacheTTL*2 {
				delete(commandCache, k)
			}
		}
	}
	cacheMutex.Unlock()

	return result, err
}

// allowedShellCommands es la allowlist de comandos base permitidos en cadenas
// shell. No se permiten shells ("sh"/"bash"): la cadena completa ya se ejecuta
// con "sh -c" internamente y permitirlos permitiría escapar del allowlist.
var allowedShellCommands = []string{
	"hostname", "hostnamectl", "uname", "cat", "grep", "awk", "sed", "cut", "head", "tail",
	"top", "free", "df", "nproc", "journalctl",
	"iwlist", "nmcli", "iw",
	"ip", "wg", "wg-quick", "systemctl", "pgrep",
	"reboot", "shutdown", "poweroff",
	"rfkill", "ifconfig", "iwconfig",
	"hostapd", "hostapd_cli", "dnsmasq", "iptables", "iptables-save", "netfilter-persistent", "sysctl", "tee", "cp", "mkdir", "echo", "chmod", "chown", "rm",
	"dhclient", "udhcpc", "wpa_supplicant", "wpa_cli", "pkill", "killall",
	"apt-get", "apt",
	"true",
}

// ValidateShellCommand exporta la validación del allowlist para paquetes que
// construyen comandos shell propios (p. ej. execPrivilegedOutput en wifi).
func ValidateShellCommand(cmd string) error {
	return validateShellCommandAllowList(cmd, allowedShellCommands)
}

func validateShellCommandAllowList(cmd string, allowedCommands []string) error {
	// Caracteres que típicamente permiten encadenar instrucciones o sustituciones.
	// Mitigan inyección cuando "cmd" viene construido con variables.
	if strings.ContainsAny(cmd, ";\n\r`$") {
		return exec.ErrNotFound
	}

	// Hardening extra: desactivar redirecciones arbitrarias.
	// Permitimos únicamente:
	// - `>/dev/null`, `2>/dev/null`, `1>/dev/null` (con o sin espacios)
	// - `2>&1` (combinación típica de stderr->stdout)
	// Prohibimos:
	// - cualquier uso de `>>` (append)
	// - cualquier uso de `<` (input redirect)
	if strings.Contains(cmd, "<") {
		return exec.ErrNotFound
	}
	if strings.Contains(cmd, ">>") {
		return exec.ErrNotFound
	}
	// Recorremos cada '>' y validamos su destino.
	for i := 0; ; {
		relIdx := strings.IndexByte(cmd[i:], '>')
		if relIdx < 0 {
			break
		}
		idx := i + relIdx

		// Permitir únicamente el patrón exacto `2>&1` (sin espacios).
		// Ej: " ... 2>&1"
		if idx > 0 &&
			cmd[idx-1] == '2' &&
			idx+2 < len(cmd) &&
			cmd[idx+1] == '&' &&
			cmd[idx+2] == '1' {
			i = idx + 1
			continue
		}

		// Permitir redirect a /dev/null.
		j := idx + 1
		for j < len(cmd) && (cmd[j] == ' ' || cmd[j] == '\t') {
			j++
		}
		if !strings.HasPrefix(cmd[j:], "/dev/null") {
			return exec.ErrNotFound
		}

		i = idx + 1
	}

	// Construimos set para validar tokens base por átomo.
	allowed := make(map[string]struct{}, len(allowedCommands))
	for _, a := range allowedCommands {
		allowed[a] = struct{}{}
	}

	tokens := shellTokenizeForAllowList(cmd)
	if tokens == nil {
		// Quoting no balanceado o tokenización inválida.
		return exec.ErrNotFound
	}
	if len(tokens) == 0 {
		return nil
	}

	// Validamos el comando base en cada átomo separado por operadores.
	// Operadores permitidos: pipes y lógica (||, &&).
	// (Los operadores se usan en el código actual para "|| true" y pipelines de grep/awk).
	expectCommand := true
	sawCommand := false

	for _, tok := range tokens {
		switch tok {
		case "|", "||", "&&":
			expectCommand = true
			continue
		}

		if !expectCommand {
			continue
		}

		// Saltamos "sudo" como prefijo del comando base.
		if tok == "sudo" {
			continue
		}

		base := strings.Trim(tok, `"'`)
		if base == "" {
			return exec.ErrNotFound
		}

		if _, ok := allowed[base]; !ok {
			return exec.ErrNotFound
		}

		sawCommand = true
		expectCommand = false
	}

	if !sawCommand {
		return exec.ErrNotFound
	}

	return nil
}

// shellTokenizeForAllowList separa tokens respetando comillas simples y dobles para que
// validateShellCommandAllowList no dependa de strings.Fields (que rompe tokens dentro de quotes).
//
// No es un parser de shell completo: solo necesita aislar comandos base y operadores |, ||, && fuera de quotes.
func shellTokenizeForAllowList(cmd string) []string {
	var tokens []string
	var cur strings.Builder

	inSingle := false
	inDouble := false

	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}

	// Nota: iteramos por bytes porque este validator trabaja con ASCII de comandos.
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]

		if inSingle {
			if ch == '\'' {
				inSingle = false
				continue
			}
			cur.WriteByte(ch)
			continue
		}

		if inDouble {
			// '\"' y '\\' dentro de comillas dobles son escapes: no deben
			// cerrar/reabrir el estado de comillas.
			if ch == '\\' && i+1 < len(cmd) {
				cur.WriteByte(ch)
				cur.WriteByte(cmd[i+1])
				i++
				continue
			}
			if ch == '"' {
				inDouble = false
				continue
			}
			// Dentro de dobles comillas mantenemos el contenido tal cual; el allowlist
			// valida solo comandos base y operadores.
			cur.WriteByte(ch)
			continue
		}

		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case ' ', '\t', '\r', '\n':
			flush()
		case '|':
			flush()
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				tokens = append(tokens, "||")
				i++
			} else {
				tokens = append(tokens, "|")
			}
		case '&':
			flush()
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				tokens = append(tokens, "&&")
				i++
			} else {
				// `&` suelto puede aparecer en redirecciones tipo `2>&1`.
				// Lo tratamos como carácter normal del token.
				cur.WriteByte('&')
			}
		default:
			cur.WriteByte(ch)
		}
	}

	if inSingle || inDouble {
		return nil
	}
	flush()
	return tokens
}

// FilterSudoErrors filtra líneas típicas de errores de `sudo`.
func FilterSudoErrors(output []byte) string {
	return FilterSudoErrorString(string(output))
}

// FilterSudoErrorString filtra errores típicos de `sudo`.
func FilterSudoErrorString(output string) string {
	lines := strings.Split(output, "\n")
	var cleanLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" &&
			!strings.Contains(line, "sudo: unable to open log file") &&
			!strings.Contains(line, "Read-only file system") &&
			!strings.Contains(line, "sudo: unable to stat") &&
			!strings.Contains(line, "sudo: unable to resolve host") &&
			!strings.Contains(line, "Name or service not known") {
			cleanLines = append(cleanLines, line)
		}
	}
	return strings.Join(cleanLines, "\n")
}

func getHostname() string {
	hostname := os.Getenv("HOSTNAME")
	if hostname == "" {
		if h, err := exec.Command("hostname").Output(); err == nil {
			hostname = strings.TrimSpace(string(h))
		}
	}
	return hostname
}

func canUseSudo() bool {
	if sudoAvailable != nil {
		return *sudoAvailable
	}

	result := false
	defer func() {
		sudoAvailable = &result
	}()

	if os.Geteuid() == 0 {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := exec.LookPath("sudo"); err != nil {
		return false
	}

	// Comprobar si hay reglas sudo específicas (p. ej. NOPASSWD solo para privileged-exec).
	if priv := privilegedExecPath(); priv != "" {
		if _, err := os.Stat(priv); err == nil {
			testPriv := exec.CommandContext(ctx, "sudo", "-n", priv, "true")
			if _, err := testPriv.CombinedOutput(); err == nil {
				result = true
				return true
			}
			result = true
			return true
		}
	}

	// `sudo -n true` no requiere shell; así mantenemos semántica sin `sh -c`.
	testCmd := exec.CommandContext(ctx, "sudo", "-n", "true")
	output, err := testCmd.CombinedOutput()
	outputStr := strings.ToLower(string(output))

	if err == nil {
		result = true
		return true
	}

	if strings.Contains(outputStr, "no new privileges") {
		result = false
		return false
	}

	if strings.Contains(outputStr, "password") || strings.Contains(outputStr, "a password is required") {
		result = true
		return true
	}

	return false
}

func execCommand(cmd string) *exec.Cmd {
	cmd = strings.TrimSpace(cmd)
	cmd = strings.TrimPrefix(cmd, "sudo ")

	if os.Geteuid() == 0 {
		return exec.Command("/bin/sh", "-c", cmd)
	}

	if canUseSudo() {
		if priv := privilegedExecPath(); priv != "" {
			if _, err := os.Stat(priv); err == nil {
				return exec.Command("sudo", priv, cmd)
			}
		}
		cmd = "sudo " + cmd
	}

	return exec.Command("/bin/sh", "-c", cmd)
}

func privilegedExecPath() string {
	if p := strings.TrimSpace(os.Getenv("HOSTBERRY_PRIVILEGED_EXEC")); p != "" {
		return p
	}
	return "/usr/local/sbin/hostberry-safe/privileged-exec"
}

// ExecCommand es un wrapper exportado para que el paquete main pueda usar
// el helper sin tener que re-implementar la lógica de sudo/no-sudo.
func ExecCommand(cmd string) *exec.Cmd {
	return execCommand(cmd)
}

func clearCommandCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	commandCache = make(map[string]*cachedResult)
}

// StrconvAtoiSafe parsea un string como entero positivo (solo dígitos), sin usar strconv.Atoi.
func StrconvAtoiSafe(s string) (int, error) {
	const maxInt = int(^uint(0) >> 1)
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid int")
		}
		d := int(r - '0')
		if n > (maxInt-d)/10 {
			return 0, fmt.Errorf("int overflow")
		}
		n = n*10 + d
	}
	return n, nil
}

// IPv4OnInterface devuelve la primera dirección IPv4 de una interfaz usando
// `ip -o -4 addr show` con argumentos separados (sin shell). Devuelve "" si la
// interfaz no existe o no tiene IPv4.
func IPv4OnInterface(iface string) string {
	if validators.ValidateIfaceName(iface) != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", "-o", "-4", "addr", "show", iface)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, "inet ")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("inet "):])
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i]
		}
		if ip := strings.TrimSpace(rest); ip != "" {
			return ip
		}
	}
	return ""
}

func MapActiveStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "active" {
		return "connected"
	}
	return "disconnected"
}

func MapBoolStatus(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "true" || v == "1" || v == "yes" {
		return "connected"
	}
	return "disconnected"
}
