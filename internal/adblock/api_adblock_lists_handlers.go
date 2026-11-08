package adblock

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/database"
	middleware "hostberry/internal/middleware"
	"hostberry/internal/utils"
)

var (
	adblockDefaultLists = []struct {
		Name    string
		Domains int
		URL     string
	}{
		{Name: "StevenBlack", Domains: 50000, URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
		{Name: "OISD", Domains: 250000, URL: "https://big.oisd.nl/"},
		{Name: "EasyList", Domains: 40000, URL: "https://easylist.to/easylist/easylist.txt"},
	}
	adblockDomainRegex  = regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	adblockRuleDomainRe = regexp.MustCompile(`^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^`)
)

const (
	adblockHostsPath    = "/etc/hosts"
	adblockHostsBegin   = "# >>> hostberry-adblock >>>"
	adblockHostsEnd     = "# <<< hostberry-adblock <<<"
	adblockFetchTimeout = 60 * time.Second
	adblockMaxListBytes = 64 << 20 // 64 MiB por lista
)

func adblockCurrentUserInfo(c *fiber.Ctx) (string, *int) {
	user, ok := middleware.GetUser(c)
	if !ok || user == nil {
		return "unknown", nil
	}
	id := user.ID
	return user.Username, &id
}

func adblockConfigValue(key string) string {
	value, err := database.GetConfig(key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func AdblockListsHandler(c *fiber.Ctx) error {
	disabled := getDisabledAdblockLists()
	lastUpdate := adblockConfigValue("adblock_last_update")
	if lastUpdate == "" {
		lastUpdate = "N/A"
	}

	lists := make([]fiber.Map, 0, len(adblockDefaultLists))
	for _, item := range adblockDefaultLists {
		key := strings.ToLower(item.Name)
		lists = append(lists, fiber.Map{
			"name":          item.Name,
			"enabled":       !disabled[key],
			"domains_count": item.Domains,
			"last_update":   lastUpdate,
		})
	}

	return c.JSON(lists)
}

func AdblockDomainsHandler(c *fiber.Ctx) error {
	base := readBlockedDomainsFromHosts(400)
	overrides := getAdblockDomainOverrides()

	for domain, blocked := range overrides {
		base[domain] = blocked
	}

	names := make([]string, 0, len(base))
	for domain := range base {
		names = append(names, domain)
	}
	sort.Strings(names)
	if len(names) > 200 {
		names = names[:200]
	}

	domains := make([]fiber.Map, 0, len(names))
	for _, domain := range names {
		domains = append(domains, fiber.Map{
			"name":    domain,
			"blocked": base[domain],
		})
	}

	return c.JSON(domains)
}

func AdblockUpdateHandler(c *fiber.Ctx) error {
	username, userID := adblockCurrentUserInfo(c)

	// La descarga de las listas puede tardar minutos: se ejecuta en segundo
	// plano y el resultado queda en el log de actividad y en adblock_last_update.
	go func(user string, uid *int) {
		stats, err := updateAdblockHosts()
		if err != nil {
			_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar listas AdBlock", err.Error(), user), "adblock", uid)
			return
		}
		_ = database.SetConfig("adblock_last_update", time.Now().Format(time.RFC3339))
		_ = database.InsertLog("INFO", database.LogMsg(fmt.Sprintf("Listas AdBlock actualizadas: %d dominios de %d listas", stats.Domains, stats.Lists), user), "adblock", uid)
	}(username, userID)

	_ = database.InsertLog("INFO", database.LogMsg("Actualización de listas AdBlock iniciada", username), "adblock", userID)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Actualización de listas AdBlock iniciada en segundo plano",
	})
}

// applyAdblockUpdateAsync regenera /etc/hosts en segundo plano tras un toggle.
// Las listas descargadas no se cachean: cada toggle provoca una actualización
// completa (aceptable para un panel de administración).
func applyAdblockUpdateAsync() {
	if _, err := updateAdblockHosts(); err != nil {
		_ = database.InsertLog("ERROR", database.LogMsgErr("actualizar AdBlock tras toggle", err.Error(), ""), "adblock", nil)
	}
}

type adblockUpdateStats struct {
	Domains int
	Lists   int
}

// updateAdblockHosts descarga las listas habilitadas y regenera el bloque
// gestionado por HostBerry dentro de /etc/hosts, preservando el resto del
// archivo. Devuelve el número de dominios y listas aplicadas.
func updateAdblockHosts() (adblockUpdateStats, error) {
	var stats adblockUpdateStats

	disabled := getDisabledAdblockLists()
	overrides := getAdblockDomainOverrides()

	domains := make(map[string]bool)
	for _, list := range adblockDefaultLists {
		if disabled[strings.ToLower(list.Name)] {
			continue
		}
		listDomains, err := fetchAdblockListDomains(list.URL)
		if err != nil {
			return stats, fmt.Errorf("lista %s: %w", list.Name, err)
		}
		for d := range listDomains {
			domains[d] = true
		}
		stats.Lists++
	}

	// Overrides del usuario: false = desbloquear explícitamente.
	for domain, blocked := range overrides {
		if blocked {
			domains[domain] = true
		} else {
			delete(domains, domain)
		}
	}

	if err := writeAdblockHostsSection(domains); err != nil {
		return stats, err
	}

	stats.Domains = len(domains)
	if _, err := utils.ExecuteCommand("sudo systemctl reload dnsmasq 2>/dev/null || sudo systemctl restart dnsmasq 2>/dev/null || true"); err != nil {
		return stats, fmt.Errorf("recargar dnsmasq: %w", err)
	}
	return stats, nil
}

// fetchAdblockListDomains descarga una blocklist y extrae dominios. Soporta el
// formato hosts (0.0.0.0/127.0.0.1 dominio) y reglas adblock `||dominio^`.
func fetchAdblockListDomains(rawURL string) (map[string]bool, error) {
	client := &http.Client{Timeout: adblockFetchTimeout}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HostBerry-AdBlock/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return parseAdblockListDomains(resp.Body)
}

// parseAdblockListDomains extrae dominios de un reader con una blocklist.
// Soporta formato hosts (0.0.0.0/127.0.0.1 dominio) y reglas adblock `||dominio^`.
// Límite de lectura: adblockMaxListBytes.
func parseAdblockListDomains(r io.Reader) (map[string]bool, error) {
	domains := make(map[string]bool)
	reader := bufio.NewReaderSize(io.LimitReader(r, adblockMaxListBytes), 64*1024)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			if strings.HasPrefix(line, "0.0.0.0") || strings.HasPrefix(line, "127.0.0.1") {
				for _, f := range strings.Fields(line)[1:] {
					if adblockDomainRegex.MatchString(f) {
						domains[strings.ToLower(f)] = true
					}
				}
			} else if m := adblockRuleDomainRe.FindStringSubmatch(line); m != nil {
				domains[strings.ToLower(m[1])] = true
			}
		}
		if err != nil {
			break
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("la lista no contiene dominios válidos")
	}
	return domains, nil
}

// writeAdblockHostsSection reescribe /etc/hosts sustituyendo el bloque marcado
// por HostBerry (o añadiéndolo al final si no existe).
func writeAdblockHostsSection(domains map[string]bool) error {
	var original []byte
	if b, err := os.ReadFile(adblockHostsPath); err == nil {
		original = b
	}

	// Eliminar bloque gestionado previo si existe.
	var kept []string
	inBlock := false
	for _, line := range strings.Split(string(original), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == adblockHostsBegin {
			inBlock = true
			continue
		}
		if trimmed == adblockHostsEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			kept = append(kept, line)
		}
	}

	names := make([]string, 0, len(domains))
	for d := range domains {
		names = append(names, d)
	}
	sort.Strings(names)

	var block bytes.Buffer
	block.WriteString(adblockHostsBegin + "\n")
	block.WriteString("# Bloqueo de publicidad generado por HostBerry. No editar manualmente.\n")
	for _, d := range names {
		block.WriteString("0.0.0.0 " + d + "\n")
	}
	block.WriteString(adblockHostsEnd + "\n")

	var out bytes.Buffer
	for _, line := range kept {
		out.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			out.WriteString("\n")
		}
	}
	out.Write(block.Bytes())

	tmpF, err := os.CreateTemp("", "hostberry-hosts-*")
	if err != nil {
		return err
	}
	tmp := tmpF.Name()
	tmpF.Close()
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, out.Bytes(), 0644); err != nil {
		return err
	}
	if _, err := utils.ExecuteCommand("sudo cp " + tmp + " " + adblockHostsPath + " && sudo chmod 644 " + adblockHostsPath); err != nil {
		return fmt.Errorf("escribir %s: %w", adblockHostsPath, err)
	}
	return nil
}

func AdblockToggleListHandler(c *fiber.Ctx) error {
	listName := strings.TrimSpace(c.Params("name"))
	if listName == "" || len(listName) > 100 {
		return c.Status(400).JSON(fiber.Map{"error": "Nombre de lista inválido"})
	}

	disabled := getDisabledAdblockLists()
	key := strings.ToLower(listName)

	enabled := true
	if disabled[key] {
		delete(disabled, key)
		enabled = true
	} else {
		disabled[key] = true
		enabled = false
	}

	if err := saveDisabledAdblockLists(disabled); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "No se pudo guardar el estado de la lista"})
	}

	go applyAdblockUpdateAsync()

	return c.JSON(fiber.Map{
		"success": true,
		"name":    listName,
		"enabled": enabled,
	})
}

func AdblockToggleDomainHandler(c *fiber.Ctx) error {
	domain := strings.ToLower(strings.TrimSpace(c.Params("name")))
	if domain == "" || len(domain) > 255 || !adblockDomainRegex.MatchString(domain) {
		return c.Status(400).JSON(fiber.Map{"error": "Dominio inválido"})
	}

	base := readBlockedDomainsFromHosts(2000)
	overrides := getAdblockDomainOverrides()

	current := base[domain]
	if val, ok := overrides[domain]; ok {
		current = val
	}
	newValue := !current
	overrides[domain] = newValue

	if err := saveAdblockDomainOverrides(overrides); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "No se pudo guardar el estado del dominio"})
	}

	go applyAdblockUpdateAsync()

	return c.JSON(fiber.Map{
		"success": true,
		"name":    domain,
		"blocked": newValue,
	})
}

func AdblockConfigHandler(c *fiber.Ctx) error {
	var req struct {
		UpdateInterval string `json:"update_interval"`
		MaxLists       int    `json:"max_lists"`
		CacheSize      int    `json:"cache_size"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Payload inválido"})
	}

	req.UpdateInterval = strings.TrimSpace(req.UpdateInterval)
	switch req.UpdateInterval {
	case "daily", "weekly", "monthly":
	default:
		return c.Status(400).JSON(fiber.Map{"error": "update_interval inválido"})
	}

	if req.MaxLists < 1 || req.MaxLists > 100 {
		return c.Status(400).JSON(fiber.Map{"error": "max_lists fuera de rango (1-100)"})
	}
	if req.CacheSize < 1 || req.CacheSize > 100000 {
		return c.Status(400).JSON(fiber.Map{"error": "cache_size fuera de rango (1-100000)"})
	}

	if err := database.SetConfig("adblock_update_interval", req.UpdateInterval); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "No se pudo guardar update_interval"})
	}
	if err := database.SetConfig("adblock_max_lists", strconv.Itoa(req.MaxLists)); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "No se pudo guardar max_lists"})
	}
	if err := database.SetConfig("adblock_cache_size", strconv.Itoa(req.CacheSize)); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "No se pudo guardar cache_size"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Configuración de AdBlock guardada",
	})
}

func getDisabledAdblockLists() map[string]bool {
	result := make(map[string]bool)
	raw := adblockConfigValue("adblock_disabled_lists")
	if raw == "" {
		return result
	}
	for _, part := range strings.Split(raw, ",") {
		key := strings.ToLower(strings.TrimSpace(part))
		if key != "" && len(key) <= 100 {
			result[key] = true
		}
	}
	return result
}

func saveDisabledAdblockLists(disabled map[string]bool) error {
	entries := make([]string, 0, len(disabled))
	for key, value := range disabled {
		if value {
			entries = append(entries, key)
		}
	}
	sort.Strings(entries)
	return database.SetConfig("adblock_disabled_lists", strings.Join(entries, ","))
}

func getAdblockDomainOverrides() map[string]bool {
	result := make(map[string]bool)
	raw := adblockConfigValue("adblock_domain_overrides")
	if raw == "" {
		return result
	}
	var parsed map[string]bool
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return result
	}
	// Solo conservar entradas con dominio válido: la config puede estar
	// corrupta o manipulada y no debe propagarse al bloque de /etc/hosts.
	for domain, blocked := range parsed {
		if len(domain) <= 255 && adblockDomainRegex.MatchString(domain) {
			result[strings.ToLower(domain)] = blocked
		}
	}
	return result
}

func saveAdblockDomainOverrides(overrides map[string]bool) error {
	data, err := json.Marshal(overrides)
	if err != nil {
		return err
	}
	return database.SetConfig("adblock_domain_overrides", string(data))
}

func readBlockedDomainsFromHosts(limit int) map[string]bool {
	result := make(map[string]bool)
	content, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return result
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if commentIndex := strings.Index(line, "#"); commentIndex >= 0 {
			line = strings.TrimSpace(line[:commentIndex])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		if ip != "0.0.0.0" && ip != "127.0.0.1" {
			continue
		}

		for _, domain := range fields[1:] {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain == "" || domain == "localhost" || !adblockDomainRegex.MatchString(domain) {
				continue
			}
			result[domain] = true
			if limit > 0 && len(result) >= limit {
				return result
			}
		}
	}
	return result
}
