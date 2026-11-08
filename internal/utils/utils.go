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
	sudoOnce      sync.Once
	sudoAvailable bool
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
// El caché solo aplica a comandos de solo lectura que terminan bien: cachear
// errores o comandos de escritura devuelve estado obsoleto tras mutaciones.
func ExecuteCommandWithTimeout(cmd string, timeout time.Duration) (string, error) {
	cacheable := commandIsReadOnly(cmd)
	cacheKey := cmd + "|" + timeout.String()

	if cacheable {
		cacheMutex.RLock()
		if cached, exists := commandCache[cacheKey]; exists {
			if time.Since(cached.timestamp) < cacheTTL {
				cacheMutex.RUnlock()
				return cached.output, cached.err
			}
		}
		cacheMutex.RUnlock()
	}

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
			return "", err
		}
	}

	result := strings.TrimSpace(outputStr)

	if cacheable && err == nil {
		cacheMutex.Lock()
		commandCache[cacheKey] = &cachedResult{output: result, timestamp: time.Now()}
		if len(commandCache) > 100 {
			for k := range commandCache {
				if time.Since(commandCache[k].timestamp) > cacheTTL*2 {
					delete(commandCache, k)
				}
			}
		}
		cacheMutex.Unlock()
	}

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
	"udevadm",
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

	// `&` suelto es un separador de comandos en shell (background). Solo se
	// permite dentro de la redirección `2>&1` (el `&` va precedido de `>`).
	// Sin este chequeo, `cmd&otro` colaría `otro` sin validar en el allowlist.
	if hasIllegalAmpersand(cmd) {
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

// hasIllegalAmpersand detecta `&` usados como operador de shell fuera de
// comillas. Se permite únicamente el patrón `>&` (p. ej. `2>&1`); cualquier
// otro `&` suelto o `&&`... (`&&` se tokeniza como operador válido) se
// considera ilegal salvo el de redirección.
func hasIllegalAmpersand(cmd string) bool {
	inSingle, inDouble := false, false
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(cmd) {
				i++
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '&':
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				i++
				continue
			}
			// `>&` es la redirección `2>&1` (ya validada por la regla de `>`).
			if i > 0 && cmd[i-1] == '>' {
				continue
			}
			return true
		}
	}
	return false
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
	sudoOnce.Do(func() {
		sudoAvailable = detectSudo()
	})
	return sudoAvailable
}

func detectSudo() bool {
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
				return true
			}
			// Si el helper existe pero el test falla, no assumir sudo: seguir
			// con la prueba genérica antes de decidir.
		}
	}

	// `sudo -n true` no requiere shell; así mantenemos semántica sin `sh -c`.
	testCmd := exec.CommandContext(ctx, "sudo", "-n", "true")
	_, err := testCmd.CombinedOutput()
	return err == nil
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

// validateArgvAllowList comprueba que el binario de una invocación argv esté
// en la allowlist. Los argumentos no se inspeccionan: al no pasar por un
// shell no pueden inyectar sintaxis.
func validateArgvAllowList(args []string) error {
	if len(args) == 0 {
		return exec.ErrNotFound
	}
	base := args[0]
	if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
		base = base[idx+1:]
	}
	for _, a := range allowedShellCommands {
		if base == a {
			return nil
		}
	}
	return exec.ErrNotFound
}

// argvBase devuelve el nombre del binario sin ruta.
func argvBase(args []string) string {
	base := args[0]
	if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
		base = base[idx+1:]
	}
	return base
}

// execArgvCommand construye el *exec.Cmd equivalente a execCommand pero sin
// pasar por un shell: los argumentos llegan literalmente al binario.
func execArgvCommand(args []string) *exec.Cmd {
	if os.Geteuid() == 0 {
		return exec.Command(args[0], args[1:]...)
	}

	if canUseSudo() {
		if priv := privilegedExecPath(); priv != "" {
			if _, err := os.Stat(priv); err == nil {
				argv := make([]string, 0, len(args)+2)
				argv = append(argv, priv, "--argv")
				argv = append(argv, args...)
				return exec.Command("sudo", argv...)
			}
		}
		return exec.Command("sudo", args...)
	}

	return exec.Command(args[0], args[1:]...)
}

// ExecuteArgv ejecuta un comando como argv (sin shell) con timeout por
// defecto. Solo se permiten binarios de la allowlist; los argumentos se
// pasan literalmente, eliminando la clase de bugs de quoting/inyección.
func ExecuteArgv(args ...string) (string, error) {
	return ExecuteArgvWithTimeout(args, defaultCommandTimeout)
}

// ExecuteArgvWithTimeout igual que ExecuteArgv con timeout explícito.
// El caché solo aplica a invocaciones de solo lectura que terminan bien,
// reutilizando la misma clasificación que la variante shell.
func ExecuteArgvWithTimeout(args []string, timeout time.Duration) (string, error) {
	if err := validateArgvAllowList(args); err != nil {
		return "", err
	}

	base := argvBase(args)
	cacheable := isReadOnlyInvocation(base, args[1:])
	cacheKey := strings.Join(args, "\x00") + "|" + timeout.String()

	if cacheable {
		cacheMutex.RLock()
		if cached, exists := commandCache[cacheKey]; exists {
			if time.Since(cached.timestamp) < cacheTTL {
				cacheMutex.RUnlock()
				return cached.output, cached.err
			}
		}
		cacheMutex.RUnlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	baseCmd := execArgvCommand(args)
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
			return "", err
		}
	}

	result := strings.TrimSpace(outputStr)

	if cacheable && err == nil {
		cacheMutex.Lock()
		commandCache[cacheKey] = &cachedResult{output: result, timestamp: time.Now()}
		if len(commandCache) > 100 {
			for k := range commandCache {
				if time.Since(commandCache[k].timestamp) > cacheTTL*2 {
					delete(commandCache, k)
				}
			}
		}
		cacheMutex.Unlock()
	}

	return result, err
}

// commandIsReadOnly indica si todos los comandos de la cadena son de solo
// lectura. Solo esos resultados son seguros de cachear: cachear comandos de
// escritura (o lecturas que pueden mutar, como `wpa_cli scan`) devolvería
// estado obsoleto tras cambios.
func commandIsReadOnly(cmd string) bool {
	tokens := shellTokenizeForAllowList(cmd)
	if tokens == nil || len(tokens) == 0 {
		return false
	}

	var base string
	var args []string
	flushAtom := func() bool {
		if base == "" {
			return true
		}
		return isReadOnlyInvocation(base, args)
	}

	expectCommand := true
	for _, tok := range tokens {
		switch tok {
		case "|", "||", "&&":
			if !flushAtom() {
				return false
			}
			base, args = "", nil
			expectCommand = true
			continue
		}

		if !expectCommand {
			args = append(args, tok)
			continue
		}
		if tok == "sudo" {
			continue
		}
		base = strings.Trim(tok, `"'`)
		expectCommand = false
	}
	return flushAtom()
}

func argsContainAny(args []string, words ...string) bool {
	for _, a := range args {
		a = strings.Trim(a, `"'`)
		for _, w := range words {
			if a == w {
				return true
			}
		}
	}
	return false
}

// isReadOnlyInvocation decide si una invocación concreta (binario + args) es
// de solo lectura. Ante la duda devuelve false: no cachear es siempre seguro.
func isReadOnlyInvocation(base string, args []string) bool {
	switch base {
	case "cat", "grep", "awk", "cut", "head", "tail", "pgrep",
		"journalctl", "free", "df", "nproc", "uname", "true":
		return true
	case "iwconfig", "iwlist":
		// `scan` activa un escaneo; sus resultados no deben servirse de caché.
		return !argsContainAny(args, "scan")
	case "sed":
		// `sed -i` (incl. `-i.bak`) escribe en el archivo.
		for _, a := range args {
			a = strings.Trim(a, `"'`)
			if a == "--in-place" || strings.HasPrefix(a, "-i") {
				return false
			}
		}
		return true
	case "hostname":
		// `hostname` solo imprime; `hostname <nombre>` lo cambia.
		return len(args) == 0
	case "hostnamectl":
		// `hostnamectl <campo>` a secas consulta; `<campo> <valor>` escribe.
		// Además existen verbos set-* que siempre mutan.
		if argsContainAny(args, "set-hostname", "set-icon-name", "set-chassis",
			"set-deployment", "set-location") {
			return false
		}
		var nonFlag int
		for _, a := range args {
			a = strings.Trim(a, `"'`)
			if a != "" && !strings.HasPrefix(a, "-") {
				nonFlag++
			}
		}
		// Con 2+ argumentos posicionales es una asignación (p. ej.
		// `hostnamectl chassis server`); con 0-1 es consulta.
		return nonFlag <= 1
	case "ip":
		// `ip addr/route/link/neigh [show]` son lecturas; los verbos de
		// mutación (set/add/del/...) y `monitor` quedan fuera.
		return !argsContainAny(args, "set", "add", "del", "delete", "replace",
			"change", "flush", "monitor")
	case "iw":
		return !argsContainAny(args, "set", "add", "del", "delete", "connect",
			"disconnect", "scan")
	case "systemctl":
		return !argsContainAny(args,
			"start", "stop", "restart", "reload", "try-restart", "condrestart",
			"enable", "disable", "mask", "unmask", "daemon-reload", "kexec",
			"poweroff", "halt", "reboot", "suspend", "hibernate", "hybrid-sleep",
			"isolate", "edit", "set-property", "add-wants", "add-requires",
			"add-sysv-wants", "add-sysv-requires", "import-environment",
			"unset-environment", "link", "enable-linger", "disable-linger")
	case "nmcli":
		return !argsContainAny(args,
			"up", "down", "modify", "add", "delete", "disconnect", "connect",
			"off", "on", "reload", "monitor", "import", "export", "rescan", "set")
	case "wpa_cli":
		// Denegar los verbos que mutan estado; el resto (status, signal_poll,
		// list_networks, get_network, bss...) son consultas cacheables. `scan`
		// también se excluye: sus resultados deben ser frescos.
		return !argsContainAny(args,
			"set_network", "add_network", "remove_network", "select_network",
			"enable_network", "disable_network", "reconfigure", "reassociate",
			"disconnect", "scan", "save_config", "reload")
	case "hostapd_cli":
		return argsContainAny(args, "status", "all_sta", "get") &&
			len(args) <= 3
	case "rfkill":
		return len(args) > 0 && strings.Trim(args[0], `"'`) == "list"
	case "ifconfig":
		// `ifconfig <iface>` imprime; con más args puede configurar.
		return len(args) <= 1 || (len(args) == 1 && strings.Trim(args[0], `"'`) == "-a")
	case "wg":
		return len(args) > 0 && strings.Trim(args[0], `"'`) == "show"
	default:
		return false
	}
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
