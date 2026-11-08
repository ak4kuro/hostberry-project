package vpn

import (
	"fmt"
	"os"

	"github.com/gofiber/fiber/v2"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/utils"
)

func VpnConnectionsHandler(c *fiber.Ctx) error {
	result := GetVPNStatus()

	var conns []fiber.Map
	if ov, ok := result["openvpn"].(map[string]interface{}); ok {
		status := fmt.Sprintf("%v", ov["status"])
		conns = append(conns, fiber.Map{"name": "openvpn", "type": "openvpn", "status": utils.MapActiveStatus(status), "bandwidth": "-"})
	}
	if wg, ok := result["wireguard"].(map[string]interface{}); ok {
		active := fmt.Sprintf("%v", wg["active"])
		conns = append(conns, fiber.Map{"name": "wireguard", "type": "wireguard", "status": utils.MapBoolStatus(active), "bandwidth": "-"})
	}
	return c.JSON(conns)
}

// VpnServersHandler lista los servidores VPN configurados (remote OpenVPN y
// endpoints WireGuard) con su estado actual.
func VpnServersHandler(c *fiber.Ctx) error {
	var servers []fiber.Map

	if remote := openvpnRemote(); remote != "" {
		status := "stopped"
		if getOpenVPNServiceStatus() == "active" {
			status = "running"
		}
		servers = append(servers, fiber.Map{
			"name":          "openvpn",
			"address":       remote,
			"status":        status,
			"clients_count": 0,
		})
	}

	for _, ep := range wgEndpoints() {
		servers = append(servers, fiber.Map{
			"name":          "wireguard",
			"address":       ep,
			"status":        "running",
			"clients_count": 0,
		})
	}

	if servers == nil {
		servers = []fiber.Map{}
	}
	return c.JSON(servers)
}

// VpnClientsHandler muestra la sesión VPN del propio dispositivo: nombre del
// túnel, IP asignada y estado de conexión.
func VpnClientsHandler(c *fiber.Ctx) error {
	var clients []fiber.Map

	if getOpenVPNServiceStatus() == "active" {
		clients = append(clients, fiber.Map{
			"name":      "openvpn",
			"address":   ifaceIPv4("tun0"),
			"connected": true,
			"bandwidth": "-",
		})
	}

	for _, iface := range wgInterfaces() {
		clients = append(clients, fiber.Map{
			"name":      iface,
			"address":   ifaceIPv4(iface),
			"connected": true,
			"bandwidth": "-",
		})
	}

	if clients == nil {
		clients = []fiber.Map{}
	}
	return c.JSON(clients)
}

// VpnToggleHandler conmuta el VPN activo (OpenVPN si está activo; si no,
// WireGuard). Si ninguno está activo, elige el que tenga configuración
// guardada en lugar de asumir siempre OpenVPN.
func VpnToggleHandler(c *fiber.Ctx) error {
	status := GetVPNStatus()
	name := ""
	if ovpn, ok := status["openvpn"].(map[string]interface{}); ok {
		if active, _ := ovpn["active"].(bool); active {
			name = "openvpn"
		}
	}
	if name == "" {
		if wg, ok := status["wireguard"].(map[string]interface{}); ok {
			if active, _ := wg["active"].(bool); active {
				name = "wireguard"
			}
		}
	}
	if name == "" {
		// Nada activo: preferir WireGuard solo si existe su config y no la de
		// OpenVPN; si ambas faltan, OpenVPN es el default histórico.
		_, wgErr := os.Stat("/etc/wireguard/wg0.conf")
		_, ovpnErr := os.Stat(openvpnClientConfigPath)
		if wgErr == nil && ovpnErr != nil {
			name = "wireguard"
		} else {
			name = "openvpn"
		}
	}
	result, err := ToggleVPNByName(name)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"success": false, "error": err.Error()})
	}
	return c.JSON(result)
}
func VpnGetConfigHandler(c *fiber.Ctx) error {
	result := GetOpenVPNConfig()
	return c.JSON(result)
}

func VpnConfigHandler(c *fiber.Ctx) error {
	var req struct {
		Config string `json:"config"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Datos inválidos"})
	}
	user, ok := middleware.GetUser(c)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "No autorizado"})
	}
	result := SaveOpenVPNConfig(req.Config, user.Username)
	if success, ok := result["success"].(bool); ok && success {
		return c.JSON(result)
	}
	if errorMsg, ok := result["error"].(string); ok {
		return c.Status(400).JSON(fiber.Map{"error": errorMsg})
	}
	return c.Status(500).JSON(fiber.Map{"error": "Error desconocido"})
}
func VpnConnectionToggleHandler(c *fiber.Ctx) error {
	name := c.Params("name")
	result, err := ToggleVPNByName(name)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"success": false, "error": err.Error()})
	}
	return c.JSON(result)
}
func VpnCertificatesGenerateHandler(c *fiber.Ctx) error {
	return c.Status(501).JSON(fiber.Map{"error": "VPN certificates no implementado"})
}
