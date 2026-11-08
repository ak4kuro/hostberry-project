package middleware

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/auth"
	"hostberry/internal/config"
	"hostberry/internal/security"
)

const tokenRefreshThreshold = 15 * time.Minute

// RefreshSessionCookieMiddleware renueva la cookie JWT si la sesión está cerca de expirar.
func RefreshSessionCookieMiddleware(c *fiber.Ctx) error {
	if err := c.Next(); err != nil {
		return err
	}
	if c.Response().StatusCode() >= 400 {
		return nil
	}
	if strings.TrimSpace(c.Get("Authorization")) != "" {
		return nil
	}
	token := c.Cookies("access_token")
	if token == "" {
		return nil
	}
	// Solo se refresca cuando la ruta ya autenticó al usuario (GetUser != nil),
	// por lo que basta verificar firma/expiración sin repetir la query a BD.
	claims, err := auth.ParseTokenClaims(token)
	if err != nil || claims.ExpiresAt == nil {
		return nil
	}
	if time.Until(claims.ExpiresAt.Time) > tokenRefreshThreshold {
		return nil
	}
	user, ok := GetUser(c)
	if !ok || user == nil {
		return nil
	}
	newToken, err := auth.GenerateToken(user)
	if err != nil {
		return nil
	}
	cookieExpiry := time.Duration(config.AppConfig.Security.TokenExpiry) * time.Minute
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    newToken,
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Strict",
		MaxAge:   int(cookieExpiry.Seconds()),
		Secure:   security.IsHTTPSRequest(c),
	})
	return nil
}
