package middleware

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/auth"
	"hostberry/internal/captiveportal"
	"hostberry/internal/config"
	"hostberry/internal/constants"
	"hostberry/internal/database"
	"hostberry/internal/i18n"
	"hostberry/internal/metrics"
	"hostberry/internal/security"
	webtemplates "hostberry/internal/templates"
	"hostberry/internal/models"
	"hostberry/internal/wifisetup"
)

func isUnsafeMethod(method string) bool {
	switch method {
	case fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete:
		return true
	default:
		return false
	}
}

// Permite requests mutantes autenticadas por cookie solo desde mismo origen.
// Mitiga CSRF cuando no se usa Authorization: Bearer.
func isSameOriginForCookieAuth(c *fiber.Ctx) bool {
	// Navegadores modernos marcan peticiones cross-site (p. ej. formularios maliciosos).
	if strings.EqualFold(strings.TrimSpace(c.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}

	origin := strings.TrimSpace(c.Get("Origin"))
	referer := strings.TrimSpace(c.Get("Referer"))

	// Para acciones "unsafe" con auth por cookie, exigir Origin o Referer
	// reduce el riesgo de CSRF desde formularios o peticiones cross-site.
	if origin == "" && referer == "" {
		return false
	}

	host := strings.ToLower(strings.TrimSpace(c.Hostname()))
	if host == "" {
		return false
	}

	// Puerto efectivo de la petición: el de la cabecera Host si existe; si no,
	// el puerto por defecto del esquema (los navegadores siempre incluyen el
	// puerto en Host/Origin cuando no es el estándar).
	reqPort := "80"
	if security.IsHTTPSRequest(c) {
		reqPort = "443"
	}
	if hostHeader := strings.TrimSpace(c.Get(fiber.HeaderHost)); hostHeader != "" {
		if _, port, err := net.SplitHostPort(hostHeader); err == nil && port != "" {
			reqPort = port
		}
	}

	// sameOriginURL valida esquema-host-puerto de una URL de Origin/Referer.
	sameOriginURL := func(raw string) bool {
		u, err := url.Parse(raw)
		if err != nil || !strings.EqualFold(u.Hostname(), host) {
			return false
		}
		uPort := u.Port()
		if uPort == "" {
			if strings.EqualFold(u.Scheme, "https") {
				uPort = "443"
			} else {
				uPort = "80"
			}
		}
		return uPort == reqPort
	}

	if origin != "" {
		return sameOriginURL(origin)
	}

	if referer != "" {
		return sameOriginURL(referer)
	}

	return true
}

func isWifiSetupAPIPath(path string) bool {
	n := strings.TrimSuffix(path, "/")
	switch n {
	case "/api/v1/wifi/status", "/api/v1/wifi/setup-info", "/api/v1/wifi/scan", "/api/v1/wifi/connect", "/api/v1/wifi/disconnect", "/api/v1/wifi/setup-band":
		return true
	default:
		return false
	}
}

// isSetupWizardAPIPath enumera los endpoints de la API que necesita el asistente inicial.
// Durante la configuración inicial estos se auto-autentican con el admin de arranque para que
// el wizard funcione aunque el navegador del portal cautivo (Android CNA) no conserve la cookie
// ni envíe Origin/Referer en peticiones POST.
func isSetupWizardAPIPath(path string) bool {
	n := strings.TrimSuffix(path, "/")
	switch n {
	case "/api/v1/wifi/status", "/api/v1/wifi/setup-info", "/api/v1/wifi/scan",
		"/api/v1/wifi/connect", "/api/v1/wifi/disconnect", "/api/v1/wifi/setup-band",
		"/api/v1/hostapd/dual-band",
		"/api/v1/setup-wizard/complete",
		"/api/v1/vpn/config", "/api/v1/vpn/connect",
		"/api/v1/wireguard/config",
		"/api/v1/tor/status", "/api/v1/tor/install", "/api/v1/tor/enable", "/api/v1/tor/disable",
		"/api/v1/tor/iptables-enable", "/api/v1/tor/iptables-disable":
		return true
	default:
		return false
	}
}

// isOnboardingCookieAuthExempt enumera endpoints del onboarding inicial exentos de la
// verificación CSRF por Origin/Referer en auth por cookie. El cambio de credenciales del
// primer acceso forma parte del onboarding (wizard -> first-login), pero como el wizard ya
// está completado, IsInitialSetupPending() es false y no entra en el bypass del asistente.
// Los navegadores de portal cautivo (Android CNA) suelen NO enviar Origin ni Referer en los
// POST, lo que provocaba un 403 ("origen no permitido") y que "guardar" no hiciera nada.
// Es seguro relajar SOLO la comprobación de origen aquí porque el handler valida igualmente
// el JWT de sesión y el estado de onboarding (SetupWizardCompleted && !FirstLoginCompleted),
// y el endpoint únicamente es funcional durante el primer acceso con credenciales por defecto.
func isOnboardingCookieAuthExempt(path string) bool {
	return strings.TrimSuffix(path, "/") == "/api/v1/auth/first-login/change"
}

// markWizardDirtyIfMutation registra que el asistente aplicó configuración (WiFi, AP,
// VPN/WireGuard/Tor). Si el wizard se reabre sin finalizar (sin pulsar "Terminar"), esta
// marca dispara la reversión total. Solo se llama dentro del flujo del wizard pendiente.
func markWizardDirtyIfMutation(c *fiber.Ctx) {
	if !isUnsafeMethod(c.Method()) {
		return
	}
	switch strings.TrimSuffix(c.Path(), "/") {
	case "/api/v1/wifi/connect", "/api/v1/wifi/disconnect",
		"/api/v1/hostapd/dual-band",
		"/api/v1/vpn/config", "/api/v1/vpn/connect",
		"/api/v1/wireguard/config",
		"/api/v1/tor/install", "/api/v1/tor/enable",
		"/api/v1/tor/iptables-enable":
		_ = database.SetConfig("wizard_dirty", "1")
	}
}

// RequireAuth protege rutas: valida token/JWT y carga el usuario en Locals.
func RequireAuth(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodOptions {
		return c.Next()
	}

	path := c.Path()

	if strings.HasPrefix(path, "/static/") {
		return c.Next()
	}
	if path == "/login" || path == "/first-login" || path == "/" || path == "/portal" {
		return c.Next()
	}

	publicPaths := map[string]bool{
		"/api/v1/auth/login":     true,
		"/api/v1/auth/login/":    true,
		"/api/v1/translations":   true,
		"/api/v1/translations/":  true,
		"/health":                 true,
		"/health/":                true,
		"/health/ready":           true,
		"/health/ready/":          true,
		"/health/live":            true,
		"/health/live/":           true,
	}

	normalizedPath := strings.TrimRight(path, "/")
	if normalizedPath == "" {
		normalizedPath = "/"
	}

	if publicPaths[path] || publicPaths[normalizedPath] {
		return c.Next()
	}
	if strings.HasPrefix(path, "/api/v1/translations/") {
		return c.Next()
	}

	// API WiFi de asistente: ya no es pública; aceptar JWT/cookie o token de setup por cabecera.
	if strings.HasPrefix(path, "/api/") && isWifiSetupAPIPath(path) {
		candidate := wifisetup.ExtractFromRequest(
			func(k string) string { return c.Get(k) },
			func(k string) string { return c.Query(k) },
		)
		if wifisetup.Valid(candidate) {
			return c.Next()
		}
	}

	// Configuración inicial: el asistente debe poder llamar a su API aunque el navegador del
	// portal cautivo (Android CNA) no conserve la cookie ni envíe Origin/Referer en los POST.
	// Auto-autenticamos al admin de arranque para los endpoints del wizard cuando la petición
	// llega desde la red del AP (192.168.4.0/24), o es de mismo origen, o es un método seguro.
	// Desde la LAN también se auto-autentica: el wizard es un flujo de bootstrap que debe funcionar
	// desde cualquier red, y algunos navegadores no envían Origin/Referer en POST same-origin.
	if strings.HasPrefix(path, "/api/") && isSetupWizardAPIPath(path) && auth.IsInitialSetupPending() {
		if !isUnsafeMethod(c.Method()) || isAPCaptiveClient(c) || isSameOriginForCookieAuth(c) || isLANClient(c) {
			if user, err := auth.BootstrapSetupSessionUser(c); err == nil && user != nil {
				c.Locals("user", user)
				c.Locals("user_id", user.ID)
				markWizardDirtyIfMutation(c)
				return c.Next()
			}
		}
	}

	var token string
	if strings.HasPrefix(path, "/api/") {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			token = c.Cookies("access_token")
			if token == "" {
				return c.Status(401).JSON(fiber.Map{
					"error": "No autorizado - token requerido",
				})
			}
			if isUnsafeMethod(c.Method()) && !isSameOriginForCookieAuth(c) && !isOnboardingCookieAuthExempt(path) {
				return c.Status(403).JSON(fiber.Map{
					"error": "Origen no permitido para autenticación por cookie",
				})
			}
		} else {
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return c.Status(401).JSON(fiber.Map{
					"error": "Formato de token inválido",
				})
			}
			token = parts[1]
		}
	} else {
		token = c.Cookies("access_token")
		if token == "" {
			if isSetupWizardWebPath(path) {
				// Renderiza el wizard en la MISMA petición fijando la cookie, sin redirigir.
				// Los navegadores de portal cautivo (Android CNA) a menudo no reenvían la
				// cookie tras un 302, lo que provocaba un bucle de redirección.
				user, err := auth.BootstrapSetupSessionUser(c)
				if err != nil {
					return err
				}
				if user != nil {
					c.Locals("user", user)
					c.Locals("user_id", user.ID)
					return c.Next()
				}
			}
			return c.Redirect("/login")
		}
	}

	claims, err := auth.ValidateToken(token)
	if err != nil {
		if strings.HasPrefix(path, "/api/") {
			return c.Status(401).JSON(fiber.Map{
				"error": "Token inválido o expirado",
			})
		}
		return c.Redirect("/login")
	}

	var user models.User
	if err := database.DB.First(&user, claims.UserID).Error; err != nil {
		i18n.LogTf("logs.middleware_user_not_found", claims.UserID, err)
		if strings.HasPrefix(path, "/api/") {
			return c.Status(401).JSON(fiber.Map{
				"error": "Usuario no encontrado. Por favor, inicia sesión nuevamente.",
				"code":  "USER_NOT_FOUND",
			})
		}
		return c.Redirect("/login")
	}

	if !user.IsActive {
		if strings.HasPrefix(path, "/api/") {
			return c.Status(401).JSON(fiber.Map{
				"error": "Usuario inactivo",
			})
		}
		return c.Redirect("/login")
	}

	c.Locals("user", &user)
	c.Locals("user_id", user.ID)

	if redirect := enforceWebOnboarding(c, &user); redirect != nil {
		return redirect
	}

	return c.Next()
}

func isSetupWizardWebPath(path string) bool {
	return path == "/setup-wizard" || strings.HasPrefix(path, "/setup-wizard/")
}

func isFirstLoginWebPath(path string) bool {
	return path == "/first-login"
}

// enforceWebOnboarding redirige al flujo inicial: wizard → first-login → panel.
func enforceWebOnboarding(c *fiber.Ctx, user *models.User) error {
	if strings.HasPrefix(c.Path(), "/api/") {
		return nil
	}
	path := c.Path()

	if auth.IsSetupWizardRequired(user) {
		if isSetupWizardWebPath(path) {
			return nil
		}
		return c.Redirect("/setup-wizard")
	}

	if auth.IsPasswordChangeRequired(user) {
		if isFirstLoginWebPath(path) {
			return nil
		}
		return c.Redirect("/first-login")
	}

	if isFirstLoginWebPath(path) {
		return c.Redirect("/dashboard")
	}

	return nil
}

// GetUser obtiene el usuario autenticado de forma segura (evita panic por type assertion).
// Solo debe usarse en rutas protegidas por RequireAuth.
func GetUser(c *fiber.Ctx) (*models.User, bool) {
	u := c.Locals("user")
	if u == nil {
		return nil, false
	}
	user, ok := u.(*models.User)
	return user, ok && user != nil
}

// RequireAdmin asegura que el usuario autenticado tenga rol "admin".
func RequireAdmin(c *fiber.Ctx) error {
	user, ok := GetUser(c)
	if !ok || user == nil {
		if strings.HasPrefix(c.Path(), "/api/") {
			return c.Status(401).JSON(fiber.Map{"error": "No autorizado"})
		}
		return c.Redirect("/login")
	}
	if !auth.IsAdmin(user.Role) {
		userID := user.ID
		database.InsertLog(
			"WARN",
			database.LogMsgWarn(
				"acceso denegado a función de administrador (ruta "+c.Method()+" "+c.Path()+", rol actual: "+user.Role+")",
				user.Username,
			),
			"auth",
			&userID,
		)
		if strings.HasPrefix(c.Path(), "/api/") {
			return c.Status(403).JSON(fiber.Map{"error": "Permisos insuficientes (se requiere rol admin)"})
		}
		return c.Redirect("/dashboard")
	}
	return c.Next()
}

// RunActionWithUser exige usuario autenticado, ejecuta action(user) y devuelve JSON según result["success"]/result["error"].
func RunActionWithUser(c *fiber.Ctx, source, successAction, errorActionPrefix string, action func(*models.User) map[string]interface{}) error {
	user, ok := GetUser(c)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "No autorizado"})
	}
	userID := user.ID
	result := action(user)

	if success, ok := result["success"].(bool); ok && success {
		database.InsertLog("INFO", database.LogMsg(successAction, user.Username), source, &userID)
		return c.JSON(result)
	}
	if errorMsg, ok := result["error"].(string); ok {
		database.InsertLog("ERROR", database.LogMsgErr(errorActionPrefix, errorMsg, user.Username), source, &userID)
		return c.Status(500).JSON(fiber.Map{"error": errorMsg})
	}
	return c.Status(500).JSON(fiber.Map{"error": "Error desconocido"})
}

func LoggingMiddleware(c *fiber.Ctx) error {
	start := time.Now()
	err := c.Next()

	duration := time.Since(start)
	path := c.Path()
	if strings.HasPrefix(path, "/static/") {
		return err
	}

	method := c.Method()
	ip := c.IP()
	status := c.Response().StatusCode()

	// Contadores de métricas HTTP
	if status >= 200 && status < 300 {
		metrics.Add2xx()
	} else if status >= 400 && status < 500 {
		metrics.Add4xx()
	} else if status >= 500 {
		metrics.Add5xx()
	}

	userID := c.Locals("user_id")
	var userIDPtr *int
	if userID != nil {
		if id, ok := userID.(int); ok {
			userIDPtr = &id
		}
	}

	statusEmoji := "✅"
	if status >= 400 && status < 500 {
		statusEmoji = "⚠️"
	} else if status >= 500 {
		statusEmoji = "❌"
	}

	durationStr := duration.String()
	if duration < time.Millisecond {
		durationStr = fmt.Sprintf("%.0fµs", float64(duration.Nanoseconds())/1000)
	} else if duration < time.Second {
		durationStr = fmt.Sprintf("%.2fms", float64(duration.Nanoseconds())/1000000)
	} else {
		durationStr = fmt.Sprintf("%.2fs", duration.Seconds())
	}

	if config.AppConfig.Server.Debug || status >= 400 {
		go func() {
			msg := fmt.Sprintf("%s %s %s desde %s en %s (HTTP %d)", statusEmoji, method, path, ip, durationStr, status)
			database.InsertLog("INFO", msg, "http", userIDPtr)
		}()
	}

	return err
}

func ErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "Error interno del servidor"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	method := c.Method()
	path := c.Path()
	errMsg := err.Error()

	userID := c.Locals("user_id")
	var userIDPtr *int
	if userID != nil {
		if id, ok := userID.(int); ok {
			userIDPtr = &id
		}
	}

	if code >= 500 {
		if config.AppConfig.Server.Debug {
			i18n.LogTf("logs.middleware_error", method, path, err)
		}
		go func() {
			database.InsertLog("ERROR", database.LogMsgErr("procesar petición "+path, errMsg, ""), "http", userIDPtr)
		}()
	}

	if strings.HasPrefix(c.Path(), "/api/") {
		resp := fiber.Map{
			"error": message,
		}
		return c.Status(code).JSON(resp)
	}

	renderDetails := ""

	if renderErr := webtemplates.RenderTemplate(c, "error", fiber.Map{
		"Title":   "Error",
		"Code":    code,
		"Message": message,
		"Details": renderDetails,
	}); renderErr != nil {
		i18n.LogTf("logs.middleware_render_error", renderErr)
		return c.Status(code).SendString(fmt.Sprintf(
			"<html><body><h1>Error %d</h1><p>%s</p></body></html>",
			code, message,
		))
	}

	return nil
}

// SecurityHeadersMiddleware añade cabeceras de seguridad básicas.
func SecurityHeadersMiddleware(c *fiber.Ctx) error {
	if c.Get("X-Content-Type-Options") == "" {
		c.Set("X-Content-Type-Options", "nosniff")
	}
	if c.Get("X-Frame-Options") == "" {
		c.Set("X-Frame-Options", "DENY")
	}
	if c.Get("X-XSS-Protection") == "" {
		c.Set("X-XSS-Protection", "1; mode=block")
	}
	if c.Get("Referrer-Policy") == "" {
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	}
	if c.Get("Permissions-Policy") == "" {
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), usb=(), payment=()")
	}
	if c.Get("Cross-Origin-Opener-Policy") == "" {
		c.Set("Cross-Origin-Opener-Policy", "same-origin")
	}
	if c.Get("Cross-Origin-Resource-Policy") == "" {
		c.Set("Cross-Origin-Resource-Policy", "same-origin")
	}
	isHTTPS := security.IsHTTPSRequest(c)
	if isHTTPS && !isAPCaptiveClient(c) && c.Get("Strict-Transport-Security") == "" {
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	if c.Get("Content-Security-Policy") == "" {
		c.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
	}
	return c.Next()
}

// EnforceHTTPSMiddleware redirige HTTP -> HTTPS cuando:
// - Security.EnforceHTTPS es true
// - Se detecta que hay TLS directo o un proxy que marca X-Forwarded-Proto=https.
// Los clientes en la red AP (192.168.4.0/24) quedan excluidos: el portal cautivo usa HTTP.
// Las rutas de sondeo CNA (generate_204, etc.) nunca se redirigen: Android/Pixel las exigen en HTTP.
func EnforceHTTPSMiddleware(c *fiber.Ctx) error {
	if !config.AppConfig.Security.EnforceHTTPS {
		return c.Next()
	}

	if isAPCaptiveClient(c) {
		return c.Next()
	}

	if captiveportal.IsProbePath(c.Path()) {
		return c.Next()
	}

	// Ya es HTTPS: no hacer nada.
	if security.IsHTTPSRequest(c) {
		return c.Next()
	}

	// No intentes forzar HTTPS en health/métricas para no romper sondas locales.
	path := c.Path()
	if strings.HasPrefix(path, "/health") || path == "/metrics" {
		return c.Next()
	}

	host := c.Hostname()
	if host == "" {
		host = fmt.Sprintf("%s:%d", config.AppConfig.Server.Host, config.AppConfig.Server.Port)
	}

	u := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     c.Path(),
		RawQuery: c.Context().URI().QueryArgs().String(),
	}
	return c.Redirect(u.String(), fiber.StatusPermanentRedirect)
}

func isAPCaptiveClient(c *fiber.Ctx) bool {
	_, apNet, err := net.ParseCIDR(constants.DefaultAPNetworkCIDR)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(c.IP()))
	if ip == nil {
		return false
	}
	return apNet.Contains(ip)
}

// isLANClient indica si la petición proviene de una red local privada
// (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) o loopback.
func isLANClient(c *fiber.Ctx) bool {
	ip := net.ParseIP(strings.TrimSpace(c.IP()))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	return false
}

