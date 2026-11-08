package middleware

import (
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/captiveportal"
	"hostberry/internal/constants"
)

func isLocalCaptiveHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return true
	}
	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		hostOnly = host
	}
	switch hostOnly {
	case constants.DefaultAPGatewayIP, "hostberry.local", "localhost", "127.0.0.1":
		return true
	}
	if ip := net.ParseIP(hostOnly); ip != nil {
		if apNet := captiveportal.APClientNetwork(); apNet != nil && apNet.Contains(ip) {
			return true
		}
	}
	return false
}

func captivePortalAllowedPath(path string) bool {
	if strings.HasPrefix(path, "/static/") {
		return true
	}
	if strings.HasPrefix(path, "/health") || path == "/metrics" {
		return true
	}
	if strings.HasPrefix(path, "/api/v1/auth/") {
		return true
	}
	return captiveportal.IsAllowedWebPath(path)
}

// HostBerryLocalMiddleware en la red AP envía hostberry.local al asistente de configuración.
func HostBerryLocalMiddleware(c *fiber.Ctx) error {
	if !captiveportal.IsAPClientIP(c.IP()) {
		return c.Next()
	}
	hostOnly := strings.ToLower(strings.TrimSpace(c.Hostname()))
	if h, _, err := net.SplitHostPort(hostOnly); err == nil {
		hostOnly = h
	}
	if hostOnly != "hostberry.local" {
		return c.Next()
	}
	path := strings.TrimSuffix(c.Path(), "/")
	if path == "" || path == "/" || path == "/login" || path == "/portal" {
		return c.Redirect(constants.DefaultAPSetupURL, fiber.StatusFound)
	}
	return c.Next()
}

// CaptivePortalMiddleware redirige al login de HostBerry las peticiones de clientes
// en la red AP (192.168.4.0/24) cuyo Host es externo (p. ej. google.es tras DNS del portal).
func CaptivePortalMiddleware(c *fiber.Ctx) error {
	if !captiveportal.IsAPClientIP(c.IP()) {
		return c.Next()
	}
	path := c.Path()
	if captivePortalAllowedPath(path) {
		return c.Next()
	}
	if isLocalCaptiveHost(c.Hostname()) {
		return c.Next()
	}
	target := constants.DefaultAPSetupURL
	return c.Redirect(target, fiber.StatusFound)
}
