package server

import (
	"github.com/gofiber/fiber/v2"
	"hostberry/internal/auth"
	"hostberry/internal/captiveportal"
	"hostberry/internal/constants"
	"hostberry/internal/database"
	"hostberry/internal/models"
)

// IsCaptivePortalClient indica si la petición viene de un cliente en la red AP (ap0).
func IsCaptivePortalClient(c *fiber.Ctx) bool {
	return captiveportal.IsAPClientIP(c.IP())
}

func captivePortalHTMLRedirect() string {
	url := constants.DefaultAPSetupURL
	return `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=` + url +
		`"><title>HostBerry</title></head><body><a href="` + url + `">HostBerry</a></body></html>`
}

func captivePortalAndroidRedirect(c *fiber.Ctx) error {
	return c.Redirect(constants.DefaultAPSetupURL, fiber.StatusFound)
}

func captivePortalIOSOKHTML() string {
	return "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
}

// respondCaptivePortalProbe responde a comprobaciones de conectividad del SO.
// Muchos Android/Samsung reaccionan mejor a 200+HTML que a 302; iOS espera "Success".
func respondCaptivePortalProbe(c *fiber.Ctx) error {
	path := c.Path()
	if !IsCaptivePortalClient(c) {
		switch path {
		case "/hotspot-detect.html", "/hotspotdetect.html":
			return c.Type("html").SendString(captivePortalIOSOKHTML())
		case "/ncsi.txt", "/connecttest.txt":
			return c.SendString("Microsoft Connect Test")
		case "/success.txt":
			return c.SendString("success")
		default:
			return c.SendStatus(fiber.StatusNoContent)
		}
	}

	switch path {
	case "/hotspot-detect.html", "/hotspotdetect.html":
		url := constants.DefaultAPSetupURL
		html := `<HTML><HEAD><TITLE>HostBerry</TITLE>` +
			`<meta http-equiv="refresh" content="0;url=` + url + `">` +
			`</HEAD><BODY>HostBerry</BODY></HTML>`
		return c.Type("html").SendString(html)
	case "/ncsi.txt", "/connecttest.txt":
		// Windows: cualquier cosa distinta de "Microsoft Connect Test" abre el portal.
		return c.Status(fiber.StatusOK).SendString("HostBerry captive portal")
	case "/generate_204", "/gen_204", "/generate_205":
		// Pixel/Android: 302 al asistente es más fiable que 204 o meta refresh.
		return captivePortalAndroidRedirect(c)
	default:
		// Otros dispositivos: 200 con HTML (meta refresh) abre el asistente CNA.
		return c.Status(fiber.StatusOK).Type("html").SendString(captivePortalHTMLRedirect())
	}
}

// CaptivePortalLandingHandler abre la web de configuración al conectar a la WiFi hostberry.
func CaptivePortalLandingHandler(c *fiber.Ctx) error {
	if !IsCaptivePortalClient(c) {
		return c.Redirect("/login")
	}
	if token := c.Cookies("access_token"); token != "" {
		if claims, err := auth.ValidateToken(token); err == nil {
			var user models.User
			if err := database.DB.First(&user, claims.UserID).Error; err == nil && user.IsActive {
				return c.Redirect(auth.PostLoginWebPath(&user), fiber.StatusFound)
			}
		}
	}
	return c.Redirect(constants.DefaultAPSetupURL, fiber.StatusFound)
}

// CaptivePortalAPIHandler implementa la API de portal cautivo (RFC 8908) para Android 11+ vía DHCP 114.
func CaptivePortalAPIHandler(c *fiber.Ctx) error {
	if !IsCaptivePortalClient(c) {
		return c.JSON(fiber.Map{"captive": false})
	}
	return c.JSON(fiber.Map{
		"captive":         true,
		"user-portal-url": constants.DefaultAPSetupURL,
	})
}

// CaptivePortalIOSDetectHandler mantiene compatibilidad con la ruta histórica de iOS.
func CaptivePortalIOSDetectHandler(c *fiber.Ctx) error {
	return respondCaptivePortalProbe(c)
}

// CaptivePortalDetectHandler responde a comprobaciones de portal cautivo del SO móvil.
func CaptivePortalDetectHandler(c *fiber.Ctx) error {
	return respondCaptivePortalProbe(c)
}

func setupCaptivePortalRoutes(app *fiber.App) {
	app.Get("/portal", CaptivePortalLandingHandler)
	app.Get(captiveportal.APIPath, CaptivePortalAPIHandler)
	for _, p := range captiveportal.ProbePaths {
		app.Get(p, CaptivePortalDetectHandler)
	}
}
