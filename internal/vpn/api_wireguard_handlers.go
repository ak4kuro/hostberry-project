package vpn

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/i18n"
	"hostberry/internal/middleware"
	"hostberry/internal/models"
	"hostberry/internal/templates"
	"hostberry/internal/validators"
)

func WireguardStatusHandler(c *fiber.Ctx) error {
	result := GetWireGuardStatus()
	return c.JSON(result)
}

func WireguardInterfacesHandler(c *fiber.Ctx) error {
	out, err := exec.Command("wg", "show", "interfaces").CombinedOutput()
	if err != nil {
		result := GetWireGuardStatus()
		if interfaces, ok := result["interfaces"].([]map[string]interface{}); ok && len(interfaces) > 0 {
			var resp []fiber.Map
			for _, iface := range interfaces {
				if name, ok := iface["name"].(string); ok {
					resp = append(resp, fiber.Map{
						"name":        name,
						"status":      "up",
						"address":     "",
						"peers_count": 0,
					})
				}
			}
			return c.JSON(resp)
		}
		return c.Status(500).JSON(fiber.Map{"error": strings.TrimSpace(string(out))})
	}

	ifaces := strings.Fields(strings.TrimSpace(string(out)))
	var resp []fiber.Map
	for _, iface := range ifaces {
		detailsOut, _ := exec.Command("wg", "show", iface).CombinedOutput()
		details := string(detailsOut)
		peersCount := 0
		for _, line := range strings.Split(details, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "peer:") {
				peersCount++
			}
		}
		resp = append(resp, fiber.Map{
			"name":        iface,
			"status":      "up",
			"address":     "", // opcional (depende de ip)
			"peers_count": peersCount,
		})
	}
	return c.JSON(resp)
}

func WireguardPeersHandler(c *fiber.Ctx) error {
	out, err := exec.Command("wg", "show").CombinedOutput()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": strings.TrimSpace(string(out))})
	}
	text := string(out)
	var peers []fiber.Map

	var curPeer string
	var handshake string
	var transfer string

	flush := func() {
		if curPeer == "" {
			return
		}
		connected := true
		if strings.Contains(handshake, "never") || handshake == "" {
			connected = false
		}
		name := curPeer
		if len(name) > 12 {
			name = name[:12] + "..."
		}
		peers = append(peers, fiber.Map{
			"name":      name,
			"connected": connected,
			"bandwidth": transfer,
			"uptime":    handshake,
		})
		curPeer, handshake, transfer = "", "", ""
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "peer:") {
			flush()
			curPeer = strings.TrimSpace(strings.TrimPrefix(line, "peer:"))
			continue
		}
		if strings.HasPrefix(line, "latest handshake:") {
			handshake = strings.TrimSpace(strings.TrimPrefix(line, "latest handshake:"))
			continue
		}
		if strings.HasPrefix(line, "transfer:") {
			transfer = strings.TrimSpace(strings.TrimPrefix(line, "transfer:"))
			continue
		}
	}
	flush()
	return c.JSON(peers)
}

func WireguardGetConfigHandler(c *fiber.Ctx) error {
	result := GetWireGuardConfigMetadata()
	if success, ok := result["success"].(bool); ok && !success {
		if errorMsg, ok := result["error"].(string); ok && errorMsg != "" {
			return c.Status(500).JSON(fiber.Map{"error": errorMsg})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Error obteniendo metadatos de configuración"})
	}
	return c.JSON(result)
}

func WireguardToggleHandler(c *fiber.Ctx) error {
	statusOut, _ := exec.Command("wg", "show").CombinedOutput()
	active := strings.TrimSpace(string(statusOut)) != ""

	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if active {
		cmd = exec.CommandContext(ctx, "sudo", "wg-quick", "down", "wg0")
	} else {
		cmd = exec.CommandContext(ctx, "sudo", "wg-quick", "up", "wg0")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": strings.TrimSpace(string(out))})
	}
	return c.JSON(fiber.Map{"success": true, "output": strings.TrimSpace(string(out))})
}

func WireguardRestartHandler(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out1, err1 := exec.CommandContext(ctx, "sudo", "wg-quick", "down", "wg0").CombinedOutput()
	out2, err2 := exec.CommandContext(ctx, "sudo", "wg-quick", "up", "wg0").CombinedOutput()
	if err1 != nil || err2 != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":  "Error reiniciando WireGuard (requiere sudo NOPASSWD)",
			"down":   strings.TrimSpace(string(out1)),
			"up":     strings.TrimSpace(string(out2)),
			"downOk": err1 == nil,
			"upOk":   err2 == nil,
		})
	}
	return c.JSON(fiber.Map{"success": true})
}

func WireguardConfigHandler(c *fiber.Ctx) error {
	var req struct {
		Config string `json:"config"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Datos inválidos"})
	}
	if err := validators.ValidateWireGuardConfig(req.Config); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	config := req.Config

	return middleware.RunActionWithUser(c, "wireguard", "WireGuard configurado correctamente", "configurar WireGuard", func(user *models.User) map[string]interface{} {
		return ConfigureWireGuard(config, user.Username)
	})
}

func WireguardPageHandler(c *fiber.Ctx) error {
	return templates.RenderTemplate(c, "wireguard", fiber.Map{
		"Title":            i18n.T(c, "wireguard.overview", "WireGuard Overview"),
		"wireguard_stats":  fiber.Map{},
		"wireguard_status": fiber.Map{},
		"wireguard_config": fiber.Map{},
		"last_update":      time.Now().Unix(),
	})
}
