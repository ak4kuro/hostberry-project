package adblock

import (
	"github.com/gofiber/fiber/v2"

	i18n "hostberry/internal/i18n"
	"hostberry/internal/middleware"
	"hostberry/internal/models"
	webtemplates "hostberry/internal/templates"
)

func AdblockStatusHandler(c *fiber.Ctx) error {
	result := GetAdBlockStatus()
	return c.JSON(result)
}

func AdblockEnableHandler(c *fiber.Ctx) error {
	return middleware.RunActionWithUser(c, "adblock", "AdBlock habilitado correctamente", "habilitar AdBlock", func(user *models.User) map[string]interface{} {
		return EnableAdBlock(user.Username)
	})
}

func AdblockDisableHandler(c *fiber.Ctx) error {
	return middleware.RunActionWithUser(c, "adblock", "AdBlock deshabilitado correctamente", "deshabilitar AdBlock", func(user *models.User) map[string]interface{} {
		return DisableAdBlock(user.Username)
	})
}

func DnscryptStatusHandler(c *fiber.Ctx) error {
	result := GetDNSCryptStatus()
	return c.JSON(result)
}

func DnscryptInstallHandler(c *fiber.Ctx) error {
	return middleware.RunActionWithUser(c, "adblock", "DNSCrypt instalado correctamente", "instalar DNSCrypt", func(user *models.User) map[string]interface{} {
		return InstallDNSCrypt(user.Username)
	})
}

func DnscryptConfigureHandler(c *fiber.Ctx) error {
	var req struct {
		ServerName string `json:"server_name"`
		BlockAds   bool   `json:"block_ads"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Datos inválidos"})
	}
	if req.ServerName == "" {
		req.ServerName = "adguard-dns"
	}

	return middleware.RunActionWithUser(c, "adblock", "DNSCrypt configurado correctamente", "configurar DNSCrypt", func(user *models.User) map[string]interface{} {
		return ConfigureDNSCrypt(req.ServerName, req.BlockAds, user.Username)
	})
}

func DnscryptEnableHandler(c *fiber.Ctx) error {
	return middleware.RunActionWithUser(c, "adblock", "DNSCrypt habilitado correctamente", "habilitar DNSCrypt", func(user *models.User) map[string]interface{} {
		return EnableDNSCrypt(user.Username)
	})
}

func DnscryptDisableHandler(c *fiber.Ctx) error {
	return middleware.RunActionWithUser(c, "adblock", "DNSCrypt deshabilitado correctamente", "deshabilitar DNSCrypt", func(user *models.User) map[string]interface{} {
		return DisableDNSCrypt(user.Username)
	})
}

func BlockyStatusHandler(c *fiber.Ctx) error {
	result := GetBlockyStatus()
	return c.JSON(result)
}

func BlockyConfigHandler(c *fiber.Ctx) error {
	cfg := GetBlockyConfig()
	return c.JSON(cfg)
}

func BlockyInstallHandler(c *fiber.Ctx) error {
	return middleware.RunActionWithUser(c, "adblock", "Blocky instalado correctamente", "instalar Blocky", func(user *models.User) map[string]interface{} {
		return InstallBlocky(user.Username)
	})
}

func BlockyConfigureHandler(c *fiber.Ctx) error {
	var req struct {
		Upstreams  []string `json:"upstreams"`
		BlockLists []string `json:"block_lists"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Datos inválidos"})
	}

	return middleware.RunActionWithUser(c, "adblock", "Blocky configurado correctamente", "configurar Blocky", func(user *models.User) map[string]interface{} {
		return ConfigureBlocky(req.Upstreams, req.BlockLists, user.Username)
	})
}

func BlockyEnableHandler(c *fiber.Ctx) error {
	return middleware.RunActionWithUser(c, "adblock", "Blocky habilitado correctamente", "habilitar Blocky", func(user *models.User) map[string]interface{} {
		return EnableBlocky(user.Username)
	})
}

func BlockyDisableHandler(c *fiber.Ctx) error {
	return middleware.RunActionWithUser(c, "adblock", "Blocky deshabilitado correctamente", "deshabilitar Blocky", func(user *models.User) map[string]interface{} {
		return DisableBlocky(user.Username)
	})
}

func BlockyAPIProxyHandler(c *fiber.Ctx) error {
	path := c.Params("*")
	if path == "" {
		// Petición a /blocky/api sin subruta: proxy a la raíz de la API de Blocky.
		path = "/"
	}

	method := c.Method()
	var body []byte
	if method == "POST" && c.Body() != nil {
		body = c.Body()
	}

	code, data := BlockyAPIProxy(method, path, body)
	if code == 0 {
		return c.Status(502).JSON(fiber.Map{"error": "Blocky no responde. ¿Está el servicio activo?"})
	}

	c.Set("Content-Type", "application/json")
	return c.Status(code).Send(data)
}

func AdblockPageHandler(c *fiber.Ctx) error {
	return webtemplates.RenderTemplate(c, "adblock", fiber.Map{
		"Title": i18n.T(c, "adblock.overview", "AdBlock (Blocky)"),
	})
}
