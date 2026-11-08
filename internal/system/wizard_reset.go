package system

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"sync"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/auth"
	"hostberry/internal/database"
	"hostberry/internal/i18n"
	"hostberry/internal/models"
	"hostberry/internal/tor"
	"hostberry/internal/vpn"
	"hostberry/internal/wifi"
)

// Sesión del asistente: una cookie de navegador (sin caducidad → se borra al cerrar el
// navegador) más un token persistido en la base de datos. Si al cargar la página del
// asistente el token de la cookie no coincide con el almacenado, se considera una
// REAPERTURA del wizard y, si había configuración sin confirmar, se revierte todo. Un
// simple refresco mantiene la cookie y el token, por lo que NO dispara la reversión.
//
// IMPORTANTE: el token se guarda en la base de datos (no solo en memoria). Si viviera solo
// en memoria, cada reinicio del servicio lo perdería y la siguiente carga del wizard se
// interpretaría como una reapertura, disparando un reset que borra el WiFi/AP del usuario.
const wizardSessionCookieName = "hb_wizard_session"
const wizardSessionTokenConfigKey = "wizard_session_token"

var wizardSessionMu sync.Mutex

func newWizardSessionToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fail closed: un token basado en tiempo es adivinable y permitiría
		// falsificar la cookie de sesión del wizard. Devolver "" hace que no
		// se emita cookie ni se persista token.
		log.Printf("ERROR: crypto/rand falló generando token de sesión del wizard: %v", err)
		return ""
	}
	return hex.EncodeToString(b)
}

// HandleWizardSessionReset decide si la carga de la página del asistente es una reapertura
// (y, en ese caso, revierte la configuración sin confirmar) o una continuación (refresco).
func HandleWizardSessionReset(c *fiber.Ctx, user *models.User) {
	if user == nil || !auth.IsSetupWizardRequired(user) {
		return
	}

	cookie := c.Cookies(wizardSessionCookieName)

	wizardSessionMu.Lock()
	stored, storedErr := database.GetConfig(wizardSessionTokenConfigKey)
	if storedErr != nil {
		log.Printf("WARNING: no se pudo leer el token de sesión del wizard: %v", storedErr)
	}
	valid := stored != "" && cookie != "" && cookie == stored
	if valid {
		wizardSessionMu.Unlock()
		return
	}
	tok := newWizardSessionToken()
	if tok != "" {
		if err := database.SetConfig(wizardSessionTokenConfigKey, tok); err != nil {
			log.Printf("WARNING: no se pudo persistir el token de sesión del wizard: %v", err)
		}
	}
	// Limpiamos la marca de forma atómica bajo el mutex para que varias cargas
	// concurrentes (p. ej. sondas del portal cautivo) no disparen el reset más de una vez.
	needReset := IsWizardDirty()
	if needReset {
		ClearWizardDirty()
	}
	wizardSessionMu.Unlock()

	if tok != "" {
		c.Cookie(&fiber.Cookie{
			Name:     wizardSessionCookieName,
			Value:    tok,
			Path:     "/",
			HTTPOnly: true,
			SameSite: "Lax",
		})
	}

	if needReset {
		// Revertir en segundo plano para que la página del asistente responda primero
		// (la reversión puede reiniciar el AP y cortar momentáneamente la conexión).
		go ResetWizardConfigurations(user.Username)
	}
}

// WizardDirtyConfigKey marca que el asistente aplicó configuración que aún no se ha
// confirmado pulsando "Terminar". Si el wizard se reabre en ese estado, se revierte todo.
const WizardDirtyConfigKey = "wizard_dirty"

// MarkWizardDirty registra que el asistente ha aplicado alguna configuración.
func MarkWizardDirty() {
	_ = database.SetConfig(WizardDirtyConfigKey, "1")
}

// ClearWizardDirty limpia la marca (al finalizar el asistente o tras revertir).
func ClearWizardDirty() {
	_ = database.SetConfig(WizardDirtyConfigKey, "0")
}

// IsWizardDirty indica si hay configuración del asistente sin confirmar.
func IsWizardDirty() bool {
	v, err := database.GetConfig(WizardDirtyConfigKey)
	if err != nil {
		return false
	}
	return v == "1"
}

// ResetWizardConfigurations revierte TODA la configuración aplicada durante el asistente
// inicial (WiFi conectado, AP "hostberry", VPN/WireGuard/Tor) cuando este se reabre sin
// haberse finalizado. Es la implementación del comportamiento "si no le das a Terminar,
// que se reinicien todas las configuraciones".
func ResetWizardConfigurations(user string) {
	i18n.LogTln("logs.wizard_reset_start")
	// Seguridad: desactivar y borrar VPN, WireGuard y Tor.
	vpn.ResetVPNConfig()
	tor.ResetTorState(user)
	// Red: olvidar WiFi y restablecer el AP a valores por defecto (esto puede cortar
	// brevemente la conexión del cliente; se hace al reabrir el asistente a propósito).
	wifi.ResetWizardNetworkState()
	ClearWizardDirty()
	i18n.LogTln("logs.wizard_reset_done")
}
