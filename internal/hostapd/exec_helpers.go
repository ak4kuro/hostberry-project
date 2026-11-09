package hostapd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"hostberry/internal/utils"
	"hostberry/internal/validators"
)

const hostapdCmdTimeout = 45 * time.Second

var phyNameRe = regexp.MustCompile(`^phy[0-9]+$`)

// validatePhyName comprueba identificadores wiphy típicos (phy0, phy1, …).
func validatePhyName(s string) bool {
	return phyNameRe.MatchString(strings.TrimSpace(s))
}

// runSudo ejecuta un binario privilegiado como argv. Pasa por
// privileged-exec --argv (la única vía permitida por sudoers) en lugar de
// `sudo` directo, que sudoers no autoriza y podría quedarse esperando password.
func runSudo(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hostapdCmdTimeout)
	defer cancel()
	argv := append([]string{bin}, args...)
	cmd, err := utils.NewArgvCommandContext(ctx, argv...)
	if err != nil {
		return "", err
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// runIP ejecuta ip con argumentos (sin shell).
func runIP(args ...string) (string, error) {
	return runSudo("ip", args...)
}

// runIw ejecuta iw con argumentos (sin shell).
func runIw(args ...string) (string, error) {
	return runSudo("iw", args...)
}

func systemctlIsActive(unit string) bool {
	out, err := exec.Command("systemctl", "is-active", unit).Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

func pgrepExists(pattern string) bool {
	err := exec.Command("pgrep", pattern).Run()
	return err == nil
}

func hostapdProcessOrUnitActive() bool {
	if systemctlIsActive("hostapd") {
		return true
	}
	return pgrepExists("hostapd")
}

func readIfaceSysFile(iface string, parts ...string) ([]byte, error) {
	iface = strings.TrimSpace(iface)
	if validators.ValidateIfaceName(iface) != nil {
		return nil, errors.New("invalid interface name")
	}
	p := filepath.Join(append([]string{"/sys/class/net", iface}, parts...)...)
	if !strings.HasPrefix(filepath.Clean(p), filepath.Join("/sys/class/net", iface)) {
		return nil, errors.New("invalid sysfs path")
	}
	return os.ReadFile(p)
}

func readPhyNameFromSys(iface string) (string, error) {
	b, err := readIfaceSysFile(iface, "phy80211", "name")
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" || !validatePhyName(s) {
		return "", errors.New("invalid phy name from sysfs")
	}
	return s, nil
}

func iwDevInfo(iface string) (string, error) {
	return runIw("dev", iface, "info")
}

func iwDevInfoShowsAP(info string) bool {
	return strings.Contains(strings.ToLower(info), "type ap")
}

func wiphyFromIwDevInfo(info string) string {
	re := regexp.MustCompile(`(?m)wiphy\s+(\S+)`)
	m := re.FindStringSubmatch(info)
	if len(m) < 2 {
		return ""
	}
	w := strings.TrimSpace(m[1])
	if validatePhyName(w) {
		return w
	}
	// `iw dev` suele mostrar «wiphy 0»; el identificador para `iw phy` es «phy0».
	if matched, _ := regexp.MatchString(`^[0-9]+$`, w); matched {
		cand := "phy" + w
		if validatePhyName(cand) {
			return cand
		}
	}
	return ""
}

func firstWiphyFromIwPhy() string {
	out, err := runIw("phy")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Wiphy ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && validatePhyName(parts[1]) {
				return parts[1]
			}
		}
	}
	return ""
}

func hostapdCli(iface string, args ...string) (string, error) {
	iface = strings.TrimSpace(iface)
	if validators.ValidateIfaceName(iface) != nil {
		return "", errors.New("invalid interface for hostapd_cli")
	}
	ctx, cancel := context.WithTimeout(context.Background(), hostapdCmdTimeout)
	defer cancel()
	full := append([]string{"-i", iface}, args...)
	cmd := exec.CommandContext(ctx, "hostapd_cli", full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func hostapdCliStatusEnabled(iface string) bool {
	out, err := hostapdCli(iface, "status")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(out), "state=enabled")
}

func hostapdCliCountStations(iface string) int {
	out, err := hostapdCli(iface, "all_sta")
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "sta=") {
			n++
		}
	}
	return n
}

func systemctlIsEnabled(unit string) string {
	out, _ := exec.Command("systemctl", "is-enabled", unit).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func ipLinkShow(iface string) (string, error) {
	if validators.ValidateIfaceName(iface) != nil {
		return "", errors.New("invalid interface")
	}
	return runIP("link", "show", iface)
}

// ifaceFromHostapdConf lee interface= de hostapd.conf con validación.
func ifaceFromHostapdConf(path string, def string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return def
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface=") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "interface="))
			if validators.ValidateIfaceName(v) == nil {
				return v
			}
			return def
		}
	}
	return def
}

func sanitizeIfaceOrDefault(name, def string) string {
	name = strings.TrimSpace(name)
	if name == "" || validators.ValidateIfaceName(name) != nil {
		return def
	}
	return name
}

// resolvePhyName obtiene el nombre phy (phy0, …) para una interfaz WiFi física.
func resolvePhyName(phyInterface string) string {
	phyInterface = sanitizeIfaceOrDefault(phyInterface, "wlan0")
	if s, err := readPhyNameFromSys(phyInterface); err == nil && s != "" {
		return s
	}
	if info, err := iwDevInfo(phyInterface); err == nil {
		if w := wiphyFromIwDevInfo(info); w != "" {
			return w
		}
	}
	if w := firstWiphyFromIwPhy(); w != "" {
		return w
	}
	return "phy0"
}
