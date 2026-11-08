package vpn

import "os"

// ResetVPNConfig revierte toda la configuración VPN (OpenVPN y WireGuard) aplicada durante el
// asistente: detiene los servicios/túneles y elimina los ficheros de configuración. Se usa al
// reabrir el asistente sin finalizarlo, para volver a un estado limpio.
func ResetVPNConfig() {
	_, _ = executeArgv("systemctl", "stop", "openvpn@client")
	_, _ = executeArgv("systemctl", "stop", "openvpn")
	_, _ = executeArgv("systemctl", "disable", "openvpn@client")
	_, _ = executeArgv("wg-quick", "down", "wg0")

	_ = os.Remove("/etc/openvpn/client.conf")
	_ = os.Remove("/etc/wireguard/wg0.conf")
}
