package vpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"hostberry/internal/i18n"
	"hostberry/internal/utils"
	"hostberry/internal/validators"
)

const openvpnClientConfigPath = "/etc/openvpn/client.conf"

// executeCommand proxy para mantener compatibilidad interna con el código original.
func executeCommand(cmd string) (string, error) {
	return utils.ExecuteCommand(cmd)
}

func readRedactedConfigMetadata(path, vpnName string) map[string]interface{} {
	result := map[string]interface{}{
		"success":  true,
		"exists":   false,
		"redacted": true,
		"message":  fmt.Sprintf("La configuración de %s no se devuelve por API por seguridad", vpnName),
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return result
		}
		result["success"] = false
		result["error"] = fmt.Sprintf("Error accediendo a la configuración de %s: %v", vpnName, err)
		return result
	}

	result["exists"] = true
	result["size"] = info.Size()
	return result
}

func getOpenVPNServiceStatus() string {
	if out, err := exec.Command("systemctl", "is-active", "openvpn").Output(); err == nil {
		status := strings.TrimSpace(string(out))
		if status != "" {
			return status
		}
	}
	if err := exec.Command("pgrep", "openvpn").Run(); err == nil {
		return "active"
	}
	return "inactive"
}

func wgShow(args ...string) (string, error) {
	out, err := exec.Command("wg", args...).Output()
	return strings.TrimSpace(string(out)), err
}

func wgInterfaces() []string {
	out, err := wgShow("show", "interfaces")
	if err != nil || out == "" {
		return []string{}
	}
	fields := strings.Fields(out)
	result := make([]string, 0, len(fields))
	for _, iface := range fields {
		if validators.ValidateIfaceName(iface) == nil {
			result = append(result, iface)
		}
	}
	return result
}

func getOpenVPNConfig() map[string]interface{} {
	return readRedactedConfigMetadata(openvpnClientConfigPath, "OpenVPN")
}

func saveOpenVPNConfig(config, user string) map[string]interface{} {
	result := make(map[string]interface{})
	if config == "" {
		result["success"] = false
		result["error"] = "Configuración requerida"
		return result
	}
	if err := validators.ValidateVPNConfig(config); err != nil {
		result["success"] = false
		result["error"] = err.Error()
		return result
	}
	if user == "" {
		user = "unknown"
	}
	if err := os.WriteFile(openvpnClientConfigPath, []byte(config), 0600); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error guardando configuración: %v", err)
		return result
	}
	i18n.LogTf("logs.vpn_openvpn_config_saved", user)
	result["success"] = true
	result["message"] = "Configuración OpenVPN guardada"
	return result
}

func getVPNStatus() map[string]interface{} {
	result := make(map[string]interface{})

	openvpnStatus := getOpenVPNServiceStatus()

	result["openvpn"] = map[string]interface{}{
		"active": openvpnStatus == "active",
		"status": openvpnStatus,
	}

	wgOut, _ := wgShow("show")
	wgActive := wgOut != ""

	result["wireguard"] = map[string]interface{}{
		"active":     wgActive,
		"interfaces": []string{},
	}

	if wgActive {
		result["wireguard"] = map[string]interface{}{
			"active":     wgActive,
			"interfaces": wgInterfaces(),
		}
	}

	result["success"] = true
	return result
}

func connectVPN(config, vpnType, user string) map[string]interface{} {
	result := make(map[string]interface{})

	if config == "" {
		result["success"] = false
		result["error"] = "Configuración requerida"
		return result
	}
	if vpnType == "wireguard" {
		if err := validators.ValidateWireGuardConfig(config); err != nil {
			result["success"] = false
			result["error"] = err.Error()
			return result
		}
	} else {
		if err := validators.ValidateVPNConfig(config); err != nil {
			result["success"] = false
			result["error"] = err.Error()
			return result
		}
	}

	if vpnType == "" {
		vpnType = "openvpn"
	}
	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.vpn_connecting", vpnType, user)

	if vpnType == "openvpn" {
		configFile := "/etc/openvpn/client.conf"
		if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
			result["success"] = false
			result["error"] = fmt.Sprintf("Error guardando configuración: %v", err)
			return result
		}

		cmd := "sudo systemctl start openvpn@client"
		if out, err := executeCommand(cmd); err != nil {
			result["success"] = false
			result["error"] = err.Error()
			if out != "" {
				result["error"] = strings.TrimSpace(out)
			}
		} else {
			result["success"] = true
			result["message"] = "OpenVPN iniciado"
		}
	} else if vpnType == "wireguard" {
		configFile := "/etc/wireguard/wg0.conf"
		if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
			result["success"] = false
			result["error"] = fmt.Sprintf("Error guardando configuración: %v", err)
			return result
		}

		cmd := "sudo wg-quick up wg0"
		if out, err := executeCommand(cmd); err != nil {
			result["success"] = false
			result["error"] = err.Error()
			if out != "" {
				result["error"] = strings.TrimSpace(out)
			}
		} else {
			result["success"] = true
			result["message"] = "WireGuard activado"
		}
	} else {
		result["success"] = false
		result["error"] = fmt.Sprintf("Tipo de VPN no soportado: %s", vpnType)
	}

	return result
}

func getWireGuardStatus() map[string]interface{} {
	result := make(map[string]interface{})

	wgOut, _ := wgShow("show")
	wgActive := wgOut != ""

	result["active"] = wgActive
	result["interfaces"] = []map[string]interface{}{}

	if wgActive {
		interfaceList := []map[string]interface{}{}
		for _, iface := range wgInterfaces() {
			interfaceInfo := map[string]interface{}{
				"name": iface,
			}
			if detailsOut, err := wgShow("show", iface); err == nil {
				interfaceInfo["details"] = detailsOut
			} else {
				interfaceInfo["details"] = ""
			}
			interfaceList = append(interfaceList, interfaceInfo)
		}
		result["interfaces"] = interfaceList
	} else {
		result["message"] = "WireGuard no está activo"
	}

	result["success"] = true
	return result
}

func configureWireGuard(config, user string) map[string]interface{} {
	result := make(map[string]interface{})

	if err := validators.ValidateWireGuardConfig(config); err != nil {
		result["success"] = false
		result["error"] = err.Error()
		return result
	}

	if user == "" {
		user = "unknown"
	}

	i18n.LogTf("logs.vpn_wireguard_config", user)

	configFile := "/etc/wireguard/wg0.conf"
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		result["success"] = false
		result["error"] = fmt.Sprintf("Error guardando configuración: %v", err)
		result["message"] = "Error guardando configuración"
		i18n.LogTf("logs.vpn_wireguard_error", err)
		return result
	}

	if wgStatusOut, err := wgShow("show", "wg0"); err == nil && wgStatusOut != "" {
		executeCommand("sudo wg-quick down wg0 2>/dev/null")
		executeCommand("sudo wg-quick up wg0 2>/dev/null")
		result["message"] = "WireGuard reiniciado con nueva configuración"
	} else {
		result["message"] = "Configuración guardada (no activa)"
	}

	result["success"] = true
	i18n.LogT("logs.vpn_wireguard_success")
	return result
}

func vpnCmdTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 90*time.Second)
}

// toggleOpenVPNService arranca o detiene el servicio OpenVPN cliente según su estado actual.
func toggleOpenVPNService() (started bool, output string, err error) {
	active := getOpenVPNServiceStatus() == "active"
	action := "start"
	if active {
		action = "stop"
	}
	ctx, cancel := vpnCmdTimeout()
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "systemctl", action, "openvpn@client")
	out, err := cmd.CombinedOutput()
	return !active, strings.TrimSpace(string(out)), err
}

// toggleWireGuardService levanta o baja un interfaz WireGuard (wg-quick).
func toggleWireGuardService(iface string) (started bool, output string, err error) {
	if validators.ValidateIfaceName(iface) != nil {
		return false, "", fmt.Errorf("invalid interface name")
	}
	active := false
	if out, e := wgShow("show", iface); e == nil && out != "" {
		active = true
	}
	action := "up"
	if active {
		action = "down"
	}
	ctx, cancel := vpnCmdTimeout()
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "wg-quick", action, iface)
	out, err := cmd.CombinedOutput()
	return !active, strings.TrimSpace(string(out)), err
}

// toggleVPNByName conmuta el servicio VPN indicado ("openvpn", "wireguard" o "wg0").
func toggleVPNByName(name string) (map[string]interface{}, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "openvpn":
		started, out, err := toggleOpenVPNService()
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, out)
		}
		if started {
			return map[string]interface{}{"success": true, "message": "OpenVPN iniciado", "output": out}, nil
		}
		return map[string]interface{}{"success": true, "message": "OpenVPN detenido", "output": out}, nil
	case "wireguard", "wg0":
		started, out, err := toggleWireGuardService("wg0")
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, out)
		}
		if started {
			return map[string]interface{}{"success": true, "message": "WireGuard activado", "output": out}, nil
		}
		return map[string]interface{}{"success": true, "message": "WireGuard desactivado", "output": out}, nil
	default:
		return nil, fmt.Errorf("tipo de VPN no soportado: %s", name)
	}
}

// openvpnRemote devuelve el host del "remote" de la configuración OpenVPN cliente.
func openvpnRemote() string {
	b, err := os.ReadFile(openvpnClientConfigPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "remote" {
			return fields[1]
		}
	}
	return ""
}

// wgEndpoints devuelve los endpoints (host:puerto) configurados en los túneles WireGuard activos.
func wgEndpoints() []string {
	var endpoints []string
	for _, iface := range wgInterfaces() {
		out, err := wgShow("show", iface, "endpoints")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				endpoints = append(endpoints, fields[1])
			}
		}
	}
	return endpoints
}

// ifaceIPv4 delega en utils.IPv4OnInterface (argv, sin shell).
func ifaceIPv4(iface string) string {
	return utils.IPv4OnInterface(iface)
}

// ---- wrappers exportados ----

func GetOpenVPNConfig() map[string]interface{} { return getOpenVPNConfig() }
func GetWireGuardConfigMetadata() map[string]interface{} {
	return readRedactedConfigMetadata("/etc/wireguard/wg0.conf", "WireGuard")
}
func SaveOpenVPNConfig(config, user string) map[string]interface{} {
	return saveOpenVPNConfig(config, user)
}
func GetVPNStatus() map[string]interface{} { return getVPNStatus() }
func ConnectVPN(config, vpnType, user string) map[string]interface{} {
	return connectVPN(config, vpnType, user)
}
func GetWireGuardStatus() map[string]interface{} { return getWireGuardStatus() }
func ConfigureWireGuard(config, user string) map[string]interface{} {
	return configureWireGuard(config, user)
}
func ToggleVPNByName(name string) (map[string]interface{}, error) {
	return toggleVPNByName(name)
}
