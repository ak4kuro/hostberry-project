package system

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/config"
	"hostberry/internal/database"
	"hostberry/internal/security"
	"hostberry/internal/utils"
)

// strconvAtoiSafe wrapper para mantener el comportamiento anterior.
func strconvAtoiSafe(s string) (int, error) {
	return utils.StrconvAtoiSafe(s)
}

func SystemActivityHandler(c *fiber.Ctx) error {
	limitStr := c.Query("limit", "10")
	limit := 10
	if v, err := strconvAtoiSafe(limitStr); err == nil && v > 0 && v <= 100 {
		limit = v
	}

	logs, _, err := database.GetLogs("all", limit, 0)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	var activities []fiber.Map
	for _, l := range logs {
		activities = append(activities, fiber.Map{
			"timestamp": l.CreatedAt.Format(time.RFC3339),
			"level":     l.Level,
			"message":   l.Message,
			"source":    l.Source,
		})
	}

	return c.JSON(activities)
}

func SystemNetworkHandler(c *fiber.Ctx) error {
	out, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"raw": string(out)})
}

func SystemUpdatesHandler(c *fiber.Ctx) error {
	pkgSet := make(map[string]struct{})

	// 1) Intentar con `apt list --upgradable` (sin shell/pipes).
	aptCtx, aptCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer aptCancel()
	if out, err := exec.CommandContext(aptCtx, "apt", "list", "--upgradable").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Listing") {
				continue
			}
			// Formato típico: "paquete/xxx ...".
			if parts := strings.SplitN(line, "/", 2); len(parts) == 2 {
				pkg := strings.TrimSpace(parts[0])
				if pkg != "" {
					pkgSet[pkg] = struct{}{}
				}
			}
		}
	}

	// 2) Si no hay resultados, fallback a `apt-get -s upgrade`.
	if len(pkgSet) == 0 {
		if out, err := exec.CommandContext(aptCtx, "apt-get", "-s", "upgrade").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "Inst ") {
					continue
				}
				// Formato típico: "Inst paquete ...".
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					pkg := strings.TrimSpace(fields[1])
					if pkg != "" {
						pkgSet[pkg] = struct{}{}
					}
				}
			}
		}
	}

	updates := make([]string, 0, len(pkgSet))
	for pkg := range pkgSet {
		updates = append(updates, pkg)
	}
	sort.Strings(updates)

	return c.JSON(fiber.Map{
		"success":           true,
		"updates_available": len(updates) > 0,
		"update_count":      len(updates),
		"updates":           updates,
		"available":         len(updates) > 0, // compatibilidad con clientes antiguos
	})
}

// systemHttpsInfoHandler devuelve información básica sobre el estado HTTP/HTTPS actual.
// Útil para mostrar en la página System una guía de configuración TLS.
func SystemHttpsInfoHandler(c *fiber.Ctx) error {
	isHttps := security.IsHTTPSRequest(c)

	return c.JSON(fiber.Map{
		"is_https": isHttps,
		"host":     config.AppConfig.Server.Host,
		"port":     config.AppConfig.Server.Port,
	})
}
