package auth

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/config"
	"hostberry/internal/security"
)

// cookieSecure indica si la cookie debe llevar flag Secure. Además de la
// petición HTTPS actual, se fuerza cuando enforce_https está activo (toda
// petición HTTP se redirige a HTTPS de todos modos).
func cookieSecure(c *fiber.Ctx) bool {
	return security.IsHTTPSRequest(c) || config.AppConfig.Security.EnforceHTTPS
}

func setAccessTokenCookie(c *fiber.Ctx, token string) {
	cookieExpiry := time.Duration(config.AppConfig.Security.TokenExpiry) * time.Minute
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    token,
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Strict",
		MaxAge:   int(cookieExpiry.Seconds()),
		Secure:   cookieSecure(c),
	})
}

func clearAccessTokenCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Strict",
		Secure:   cookieSecure(c),
		MaxAge:   -1,
	})
}

func finalizeCredentialChange() {
	security.RemoveInstallCredentialsFile()
}
