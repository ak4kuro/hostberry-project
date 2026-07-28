package auth

import (
	"github.com/gofiber/fiber/v2"
	"hostberry/internal/database"
	"hostberry/internal/models"
)

// IsSetupWizardRequired indica si el usuario debe completar el asistente inicial.
func IsSetupWizardRequired(user *models.User) bool {
	return user != nil && !user.SetupWizardCompleted
}

// IsInitialSetupPending indica si el admin aún no ha completado el wizard inicial.
func IsInitialSetupPending() bool {
	return bootstrapSetupAdminUser() != nil
}

func bootstrapSetupAdminUser() *models.User {
	var user models.User
	if err := database.DB.Where("role = ? AND is_active = ?", "admin", true).First(&user).Error; err != nil {
		return nil
	}
	if !IsSetupWizardRequired(&user) {
		return nil
	}
	return &user
}

// RedirectBootstrapSetupSession inicia sesión automática del admin mientras el wizard
// esté pendiente y redirige a la ruta de onboarding. Devuelve (true, err) si redirigió.
func RedirectBootstrapSetupSession(c *fiber.Ctx) (bool, error) {
	user := bootstrapSetupAdminUser()
	if user == nil {
		return false, nil
	}

	token, err := GenerateToken(user)
	if err != nil {
		return false, err
	}
	setAccessTokenCookie(c, token)
	return true, c.Redirect(PostLoginWebPath(user))
}

// BootstrapSetupSessionUser inicia sesión automática del admin durante el wizard inicial y
// fija la cookie, pero SIN redirigir: devuelve el usuario para renderizar la página en la misma
// petición. Esto evita el bucle de redirección en navegadores de portal cautivo (Android CNA)
// que no reenvían la cookie tras un 302. Devuelve nil si el wizard no está pendiente.
func BootstrapSetupSessionUser(c *fiber.Ctx) (*models.User, error) {
	user := bootstrapSetupAdminUser()
	if user == nil {
		return nil, nil
	}
	token, err := GenerateToken(user)
	if err != nil {
		return nil, err
	}
	setAccessTokenCookie(c, token)
	return user, nil
}

// IsPasswordChangeRequired indica si debe pasar por /first-login (tras el wizard).
func IsPasswordChangeRequired(user *models.User) bool {
	if user == nil || !user.SetupWizardCompleted {
		return false
	}
	return !user.FirstLoginCompleted || (user.Username == "admin" && CheckPassword("admin", user.Password))
}

// PostLoginWebPath devuelve la ruta web tras autenticarse: wizard → first-login → panel.
func PostLoginWebPath(user *models.User) string {
	if IsSetupWizardRequired(user) {
		return "/setup-wizard"
	}
	if IsPasswordChangeRequired(user) {
		return "/first-login"
	}
	return "/dashboard"
}
