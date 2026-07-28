package hostapd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"hostberry/internal/constants"
	"hostberry/internal/wifi"
)

// ApplyNormalAPMode deja el AP "hostberry" en modo NORMAL (post-asistente):
//   - dnsmasq: quita el secuestro DNS del portal cautivo (address=/#/) y la URL de portal
//     (dhcp-option=114), conservando la resolución local de hostberry.local y añadiendo
//     reenviadores DNS reales para que los clientes naveguen.
//   - Desactiva el servicio del portal cautivo y borra sus reglas (REDIRECT :80, REJECT 443/853),
//     de modo que el tráfico de los clientes salga a Internet en lugar de redirigirse al panel.
//   - Habilita el reenvío IPv4 (persistente) y el NAT (MASQUERADE) del subred del AP hacia el
//     uplink real (Ethernet o la WiFi STA), independientemente de la interfaz de salida.
//   - Aplica la configuración de seguridad (SSID/contraseña) guardada en el asistente.
//
// Es idempotente: se ejecuta al finalizar el asistente y en cada arranque cuando el setup ya está
// completado (porque las reglas iptables no persisten tras reiniciar).
func ApplyNormalAPMode() {
	dnsmasqChanged := normalizeDnsmasqAPConfig()

	// El servicio del portal cautivo reañade el REDIRECT en cada arranque: hay que deshabilitarlo.
	executeCommand("systemctl disable hostberry-captive-portal.service 2>/dev/null || true")
	executeCommand("systemctl stop hostberry-captive-portal.service 2>/dev/null || true")

	clearCaptivePortalRules()
	enableAPInternetSharing()

	// Aplicar la configuración de seguridad guardada en el asistente (SSID/contraseña)
	// Esto asegura que hostapd.conf tenga la contraseña correcta después del reinicio
	applySavedHostapdSecurity()

	if dnsmasqChanged {
		if out, err := executeCommand("systemctl restart dnsmasq 2>/dev/null || true"); err != nil {
			log.Printf("AP normal: restart dnsmasq: %v (%s)", err, strings.TrimSpace(out))
		}
	}
}

// ApplyCaptivePortalMode restaura el portal cautivo del AP "hostberry" (modo asistente): vuelve a
// activar el secuestro DNS y la URL de portal en dnsmasq y rehabilita el servicio del portal
// cautivo. Es el inverso de ApplyNormalAPMode y se ejecuta en arranque cuando el setup sigue
// pendiente, de modo que reabrir/resetear el asistente recupere la apertura automática en móviles.
func ApplyCaptivePortalMode() {
	changed := captivizeDnsmasqAPConfig()

	executeCommand("systemctl enable hostberry-captive-portal.service 2>/dev/null || true")
	executeCommand("systemctl start hostberry-captive-portal.service 2>/dev/null || true")

	if changed {
		if out, err := executeCommand("systemctl restart dnsmasq 2>/dev/null || true"); err != nil {
			log.Printf("Portal cautivo: restart dnsmasq: %v (%s)", err, strings.TrimSpace(out))
		}
	}
}

// captivizeDnsmasqAPConfig reañade el secuestro DNS y la URL de portal. Devuelve true si cambió.
func captivizeDnsmasqAPConfig() bool {
	content, err := os.ReadFile(dnsmasqAPConfigPath)
	if err != nil {
		return false
	}
	updated := buildCaptiveDnsmasqAP(content)
	if bytes.Equal(content, updated) {
		return false
	}
	if err := writeConfigFilePrivileged(dnsmasqAPConfigPath, updated); err != nil {
		log.Printf("Portal cautivo: escribir %s: %v", dnsmasqAPConfigPath, err)
		return false
	}
	log.Printf("Portal cautivo: dnsmasq con secuestro DNS restaurado para el asistente")
	return true
}

// buildCaptiveDnsmasqAP asegura las líneas del portal cautivo conservando hostberry.local.
func buildCaptiveDnsmasqAP(content []byte) []byte {
	gw := constants.DefaultAPGatewayIP
	lines := strings.Split(string(content), "\n")
	out := make([]string, 0, len(lines)+3)
	hasHijack := false
	hasOpt114 := false
	hasLocal := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "address=/#/") {
			hasHijack = true
		}
		if strings.HasPrefix(trimmed, "dhcp-option=114") {
			hasOpt114 = true
		}
		if strings.HasPrefix(trimmed, "address=/hostberry.local/") {
			hasLocal = true
		}
		out = append(out, line)
	}

	// hostberry.local debe ir ANTES del comodín address=/#/ para que tenga prioridad.
	if !hasLocal {
		out = append(out, "address=/hostberry.local/"+gw)
	}
	if !hasHijack {
		out = append(out, "address=/#/"+gw)
	}
	if !hasOpt114 {
		out = append(out, "dhcp-option=114,http://"+gw+"/api/captive-portal")
	}

	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res)
}

// normalizeDnsmasqAPConfig reescribe hostberry-ap.conf a modo normal. Devuelve true si cambió.
func normalizeDnsmasqAPConfig() bool {
	content, err := os.ReadFile(dnsmasqAPConfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("AP normal: leer %s: %v", dnsmasqAPConfigPath, err)
		}
		return false
	}
	updated := buildNormalDnsmasqAP(content)
	if bytes.Equal(content, updated) {
		return false
	}
	if err := writeConfigFilePrivileged(dnsmasqAPConfigPath, updated); err != nil {
		log.Printf("AP normal: escribir %s: %v", dnsmasqAPConfigPath, err)
		return false
	}
	log.Printf("AP normal: dnsmasq sin portal cautivo (DNS real, hostberry.local conservado)")
	return true
}

// buildNormalDnsmasqAP transforma la config del portal cautivo en una config de AP con Internet.
func buildNormalDnsmasqAP(content []byte) []byte {
	gw := constants.DefaultAPGatewayIP

	// Restaurar el rango DHCP normal (pool completo + lease largo) por si quedó el del asistente.
	text := string(mutateDnsmasqDHCPRange(content, false))

	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines)+3)
	hasLocal := false
	hasDNS1 := false
	hasDNS2 := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Quitar el secuestro DNS (resuelve todo al gateway) y la URL de portal cautivo.
		if strings.HasPrefix(trimmed, "address=/#/") {
			continue
		}
		if strings.HasPrefix(trimmed, "dhcp-option=114") {
			continue
		}
		if strings.HasPrefix(trimmed, "address=/hostberry.local/") {
			hasLocal = true
		}
		if trimmed == "server=1.1.1.1" {
			hasDNS1 = true
		}
		if trimmed == "server=8.8.8.8" {
			hasDNS2 = true
		}
		out = append(out, line)
	}

	// Conservar el acceso al panel por nombre.
	if !hasLocal {
		out = append(out, "address=/hostberry.local/"+gw)
	}
	// Reenviadores DNS reales para que dnsmasq resuelva Internet para los clientes del AP.
	if !hasDNS1 {
		out = append(out, "server=1.1.1.1")
	}
	if !hasDNS2 {
		out = append(out, "server=8.8.8.8")
	}

	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res)
}

// clearCaptivePortalRules elimina las reglas del portal cautivo en ap0 (REDIRECT :80 a todos los
// destinos y los REJECT de 443/853 que se usan para forzar la detección de portal).
func clearCaptivePortalRules() {
	const iface = "ap0"
	// El REDIRECT amplio captura TODO el HTTP saliente del cliente; hay que borrarlo (varios
	// puertos destino posibles según versión del instalador).
	for _, port := range []string{"8000", "443", "8443", "8080", "80", "4433"} {
		executeCommand(fmt.Sprintf("iptables -t nat -D PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-ports %s 2>/dev/null || true", iface, port))
	}
	// Los REJECT de 443/853 (cadena INPUT) bloquean el acceso al panel por HTTPS y a DoT/DoQ.
	executeCommand(fmt.Sprintf("iptables -D INPUT -i %s -p tcp --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null || true", iface))
	executeCommand(fmt.Sprintf("iptables -D INPUT -i %s -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null || true", iface))
	executeCommand(fmt.Sprintf("iptables -D INPUT -i %s -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true", iface))
}

// enableAPInternetSharing habilita el reenvío IPv4 y el NAT del subred del AP hacia el uplink.
func enableAPInternetSharing() {
	cidr := constants.DefaultAPNetworkCIDR // 192.168.4.0/24

	// Reenvío IPv4. No lo persistimos en /etc/sysctl.d (privileged-exec restringe el destino del
	// cp): como el NAT y el desmontaje del portal cautivo tampoco persisten en iptables, todo el
	// modo normal se reaplica en cada arranque desde Bootstrap, donde se vuelve a poner a 1.
	executeCommand("sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true")

	// MASQUERADE independiente de la interfaz de salida: vale tanto si el uplink es Ethernet como
	// si es la WiFi STA (wlan0). Usamos -C para no duplicar la regla.
	executeCommand(fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s ! -d %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s ! -d %s -j MASQUERADE", cidr, cidr, cidr, cidr))

	// Permitir el reenvío del subred del AP (defensa por si la política FORWARD no fuera ACCEPT).
	// La regla de aislamiento ap0->ap0 (si existe) se inserta en la posición 1 y mantiene prioridad.
	executeCommand(fmt.Sprintf("iptables -C FORWARD -s %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -s %s -j ACCEPT", cidr, cidr))
	executeCommand(fmt.Sprintf("iptables -C FORWARD -d %s -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -d %s -m state --state RELATED,ESTABLISHED -j ACCEPT", cidr, cidr))
}

// applySavedHostapdSecurity aplica la configuración de seguridad (SSID/contraseña) guardada
// en el asistente al hostapd.conf activo. Esto asegura que después del reinicio el AP tenga
// la contraseña correcta configurada por el usuario.
func applySavedHostapdSecurity() {
	country := constants.DefaultCountryCode
	cfg := wifi.LoadDualBandAPConfig(country)
	
	// Determinar la banda activa actual (ConcurrentOperatingBandExport devuelve "2.4" o "5")
	activeBand := wifi.GetWizardPreferredBand()
	if activeBand == "" {
		activeBand = wifi.ConcurrentOperatingBandExport(wifi.DetectWiFiInterface())
	}
	if activeBand == "" {
		activeBand = "2.4"
	}
	
	// Seleccionar el perfil según la banda activa
	var profile wifi.DualBandAPProfile
	if activeBand == "5" {
		profile = cfg.Band5
	} else {
		profile = cfg.Band24
	}
	
	// Si el perfil tiene seguridad configurada, aplicarla
	if profile.Security != "open" && profile.Password != "" {
		log.Printf("AP normal: aplicando configuración de seguridad guardada (SSID=%s, security=%s)", profile.SSID, profile.Security)
		
		// Usar EnsureDualBandHostapd con setupPending=false para aplicar la configuración guardada
		result := wifi.EnsureDualBandHostapdForBand("", false, activeBand)
		if success, ok := result["success"].(bool); ok && !success {
			log.Printf("AP normal: error aplicando configuración de seguridad: %v", result["error"])
		}
		
		// Reiniciar hostapd para aplicar la nueva configuración
		if out, err := executeCommand("systemctl restart hostapd 2>/dev/null || true"); err != nil {
			log.Printf("AP normal: restart hostapd tras aplicar seguridad: %v (%s)", err, strings.TrimSpace(out))
		}
	}
}
