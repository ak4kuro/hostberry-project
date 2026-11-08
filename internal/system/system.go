package system

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"hostberry/internal/i18n"
	"hostberry/internal/utils"
)

func executeArgv(args ...string) (string, error) {
	return utils.ExecuteArgv(args...)
}

func readFirstMatchCPUInfo() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "model name") || strings.Contains(lower, "processor") || strings.Contains(lower, "hardware") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func uptimeSeconds() int {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int(f)
}

func loadAverageString() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "0.00, 0.00, 0.00"
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return "0.00, 0.00, 0.00"
	}
	// Mantener compatibilidad de formato (con comas + espacios).
	return fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
}

func cpuUsagePercent() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0.0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// cpu  user nice system idle iowait irq softirq steal guest guest_nice
		if len(fields) < 5 {
			return 0.0
		}
		user, err1 := strconv.ParseFloat(fields[1], 64)
		niceV, err2 := strconv.ParseFloat(fields[2], 64)
		systemV, err3 := strconv.ParseFloat(fields[3], 64)
		idleV, err4 := strconv.ParseFloat(fields[4], 64)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			return 0.0
		}
		den := user + niceV + systemV + idleV
		if den <= 0 {
			return 0.0
		}
		usage := (user + systemV) * 100.0 / den
		if usage < 0 || usage > 100 {
			return 0.0
		}
		return usage
	}
	return 0.0
}

func memoryUsagePercent() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0.0
	}
	var totalKB, availKB float64
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, _ = strconv.ParseFloat(fields[1], 64)
			}
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				availKB, _ = strconv.ParseFloat(fields[1], 64)
			}
		}
	}
	if totalKB <= 0 {
		return 0.0
	}
	usedKB := totalKB - availKB
	if usedKB < 0 {
		usedKB = 0
	}
	usage := usedKB * 100.0 / totalKB
	if usage < 0 || usage > 100 {
		return 0.0
	}
	return usage
}

func diskUsagePercent(path string) float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0.0
	}
	if st.Blocks == 0 {
		return 0.0
	}
	used := float64(st.Blocks-st.Bfree) * 100.0 / float64(st.Blocks)
	if used < 0 || used > 100 {
		return 0.0
	}
	return used
}

func cpuTemperatureC() float64 {
	b, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		return 0.0
	}
	s := strings.TrimSpace(string(b))
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0.0
	}
	// En la mayoría de sistemas viene en miligrados.
	return v / 1000.0
}

func getSystemInfo() map[string]interface{} {
	result := make(map[string]interface{})

	if hostname, err := exec.Command("hostname").Output(); err == nil {
		result["hostname"] = strings.TrimSpace(string(hostname))
	} else {
		result["hostname"] = "unknown"
	}

	if kernel, err := exec.Command("uname", "-r").Output(); err == nil {
		result["kernel_version"] = strings.TrimSpace(string(kernel))
	} else {
		result["kernel_version"] = "unknown"
	}

	if arch, err := exec.Command("uname", "-m").Output(); err == nil {
		result["architecture"] = strings.TrimSpace(string(arch))
	} else {
		result["architecture"] = "unknown"
	}

	if processor := strings.TrimSpace(readFirstMatchCPUInfo()); processor != "" {
		result["processor"] = processor
	} else {
		result["processor"] = "ARM Processor"
	}

	osVersion := "Unknown"
	if osRelease, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(osRelease), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osVersion = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	result["os_version"] = osVersion

	uptimeS := uptimeSeconds()
	result["uptime_seconds"] = uptimeS
	result["boot_time"] = time.Now().Unix() - int64(uptimeS)

	result["load_average"] = loadAverageString()

	return result
}

func getSystemStats() map[string]interface{} {
	result := make(map[string]interface{})

	result["cpu_usage"] = cpuUsagePercent()

	result["memory_usage"] = memoryUsagePercent()

	result["disk_usage"] = diskUsagePercent("/")

	result["uptime"] = uptimeSeconds()

	result["cpu_temperature"] = cpuTemperatureC()

	coresCmd := exec.Command("nproc")
	if coresOut, err := coresCmd.Output(); err == nil {
		if cores, err := strconv.Atoi(strings.TrimSpace(string(coresOut))); err == nil {
			result["cpu_cores"] = cores
		} else {
			result["cpu_cores"] = 1
		}
	} else {
		result["cpu_cores"] = 1
	}

	if hostname, err := exec.Command("hostname").Output(); err == nil {
		result["hostname"] = strings.TrimSpace(string(hostname))
	} else {
		result["hostname"] = "unknown"
	}

	if kernel, err := exec.Command("uname", "-r").Output(); err == nil {
		result["kernel_version"] = strings.TrimSpace(string(kernel))
	} else {
		result["kernel_version"] = "unknown"
	}

	if arch, err := exec.Command("uname", "-m").Output(); err == nil {
		result["architecture"] = strings.TrimSpace(string(arch))
	} else {
		result["architecture"] = "unknown"
	}

	if processorStr := strings.TrimSpace(readFirstMatchCPUInfo()); processorStr != "" {
		result["processor"] = processorStr
	} else {
		result["processor"] = "ARM Processor"
	}

	osVersion := "Unknown"
	if osRelease, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(osRelease), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osVersion = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	result["os_version"] = osVersion

	result["load_average"] = loadAverageString()

	return result
}

func systemRestart(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.system_restart_requested", user)

	if _, err := executeArgv("systemctl", "reboot"); err != nil {
		i18n.LogTf("logs.system_restart_fallback", err)
		found := false
		for _, path := range []string{"/usr/sbin/shutdown", "/sbin/shutdown", "shutdown"} {
			if _, lookErr := exec.LookPath(path); lookErr != nil {
				continue
			}
			if out2, err2 := executeArgv(path, "-r", "+1"); err2 == nil {
				result["success"] = true
				result["message"] = "Sistema se reiniciará en 1 minuto"
				result["output"] = strings.TrimSpace(out2)
				i18n.LogT("logs.system_restart_success")
				return result
			}
			found = true
			break
		}
		if !found {
			if _, err3 := executeArgv("reboot"); err3 != nil {
				result["success"] = false
				result["error"] = err3.Error()
				result["message"] = "Error al ejecutar comando de reinicio"
				i18n.LogTf("logs.system_restart_error", err3)
				return result
			}
			result["success"] = true
			result["message"] = "Sistema se reiniciará en breve"
			result["output"] = ""
			return result
		}
		result["success"] = false
		result["error"] = err.Error()
		result["message"] = "Error al ejecutar comando de reinicio"
		i18n.LogTf("logs.system_restart_error", err)
		return result
	}

	result["success"] = true
	result["message"] = "Sistema se reiniciará en breve"
	result["output"] = ""
	i18n.LogT("logs.system_restart_success")
	return result
}

func systemShutdown(user string) map[string]interface{} {
	result := make(map[string]interface{})

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.system_shutdown_requested", user)

	if _, err := executeArgv("systemctl", "poweroff"); err != nil {
		i18n.LogTf("logs.system_shutdown_fallback", err)
		found := false
		for _, path := range []string{"/usr/sbin/shutdown", "/sbin/shutdown", "shutdown"} {
			if _, lookErr := exec.LookPath(path); lookErr != nil {
				continue
			}
			if out2, err2 := executeArgv(path, "-h", "+1"); err2 == nil {
				result["success"] = true
				result["message"] = "Sistema se apagará en 1 minuto"
				result["output"] = strings.TrimSpace(out2)
				i18n.LogT("logs.system_shutdown_success")
				return result
			}
			found = true
			break
		}
		if !found {
			if _, err3 := executeArgv("poweroff"); err3 != nil {
				result["success"] = false
				result["error"] = err3.Error()
				result["message"] = "Error al ejecutar comando de apagado"
				i18n.LogTf("logs.system_shutdown_error", err3)
				return result
			}
			result["success"] = true
			result["message"] = "Sistema se apagará en breve"
			result["output"] = ""
			return result
		}
		result["success"] = false
		result["error"] = err.Error()
		result["message"] = "Error al ejecutar comando de apagado"
		i18n.LogTf("logs.system_shutdown_error", err)
		return result
	}

	result["success"] = true
	result["message"] = "Sistema se apagará en breve"
	result["output"] = ""
	i18n.LogT("logs.system_shutdown_success")
	return result
}

// ---- Exportados para el paquete principal ----

func GetSystemInfo() map[string]interface{}  { return getSystemInfo() }
func GetSystemStats() map[string]interface{} { return getSystemStats() }
func SystemRestart(user string) map[string]interface{} {
	return systemRestart(user)
}
func SystemShutdown(user string) map[string]interface{} {
	return systemShutdown(user)
}
