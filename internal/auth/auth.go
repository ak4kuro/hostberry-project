package auth

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"hostberry/internal/config"
	"hostberry/internal/database"
	"hostberry/internal/models"
	"hostberry/internal/validators"
)

// GenerateToken genera un JWT para el usuario.
func GenerateToken(user *models.User) (string, error) {
	tokenVersion := user.TokenVersion
	if tokenVersion <= 0 {
		tokenVersion = 1
	}
	expirationTime := time.Now().Add(time.Duration(config.AppConfig.Security.TokenExpiry) * time.Minute)
	claims := &models.Claims{
		Username:     user.Username,
		UserID:       user.ID,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "hostberry",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.AppConfig.Security.JWTSecret))
}

// ValidateToken valida un JWT y devuelve los claims.
func ValidateToken(tokenString string) (*models.Claims, error) {
	if tokenString == "" {
		return nil, errors.New("token vacío")
	}
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("método de firma inválido")
		}
		return []byte(config.AppConfig.Security.JWTSecret), nil
	})
	if err != nil {
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "expired") || strings.Contains(errMsg, "token is expired") {
			return nil, errors.New("token expirado")
		}
		if strings.Contains(errMsg, "not valid yet") || strings.Contains(errMsg, "token is not valid yet") {
			return nil, errors.New("token aún no válido")
		}
		if strings.Contains(errMsg, "malformed") || strings.Contains(errMsg, "token is malformed") {
			return nil, errors.New("token malformado")
		}
		return nil, fmt.Errorf("error validando token: %v", err)
	}
	if !token.Valid {
		return nil, errors.New("token inválido")
	}
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, errors.New("token expirado")
	}
	var user models.User
	if err := database.DB.Select("id", "is_active", "token_version").First(&user, claims.UserID).Error; err != nil {
		return nil, errors.New("usuario no encontrado")
	}
	if !user.IsActive {
		return nil, errors.New("usuario inactivo")
	}
	if user.TokenVersion <= 0 {
		user.TokenVersion = 1
		_ = database.DB.Model(&user).Update("token_version", user.TokenVersion).Error
	}
	if claims.TokenVersion != user.TokenVersion {
		return nil, errors.New("token revocado")
	}
	return claims, nil
}

// ParseTokenClaims verifica firma HMAC y validez del JWT sin consultar la base
// de datos. Solo debe usarse cuando la petición ya pasó por autenticación
// completa (p. ej. RefreshSessionCookieMiddleware tras RequireAuth).
func ParseTokenClaims(tokenString string) (*models.Claims, error) {
	if tokenString == "" {
		return nil, errors.New("token vacío")
	}
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("método de firma inválido")
		}
		return []byte(config.AppConfig.Security.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("token inválido")
	}
	return claims, nil
}

// HashPassword hashea una contraseña con bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), config.AppConfig.Security.BcryptCost)
	return string(bytes), err
}

func isBcryptHash(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")
}

// CheckPassword compara contraseña con hash.
func CheckPassword(password, hash string) bool {
	if !isBcryptHash(hash) {
		return false
	}
	normalized := hash
	if strings.HasPrefix(hash, "$2y$") {
		normalized = "$2a$" + strings.TrimPrefix(hash, "$2y$")
	}
	return bcrypt.CompareHashAndPassword([]byte(normalized), []byte(password)) == nil
}

func getMaxLoginAttempts() int {
	defaultAttempts := 3
	raw, err := database.GetConfig("max_login_attempts")
	if err != nil {
		return defaultAttempts
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 || v > 20 {
		return defaultAttempts
	}
	return v
}

func getLockoutMinutes() int {
	if config.AppConfig.Security.LockoutMinutes > 0 {
		return config.AppConfig.Security.LockoutMinutes
	}
	return 15
}

// IsDefaultAdminCredentialsInUse indica si el usuario admin existe con contraseña "admin".
func IsDefaultAdminCredentialsInUse() bool {
	var user models.User
	if err := database.DB.Where("username = ? AND is_active = ?", "admin", true).First(&user).Error; err != nil {
		return false
	}
	return CheckPassword("admin", user.Password)
}

// Login autentica usuario y devuelve el usuario, token JWT o error (LoginError).
func Login(username, password string) (*models.User, string, error) {
	username = strings.TrimSpace(username)
	var user models.User
	if err := database.DB.Where("username = ? AND is_active = ?", username, true).First(&user).Error; err != nil {
		return nil, "", &models.LoginError{Key: "auth.invalid_credentials", Default: "usuario o contraseña incorrectos"}
	}
	maxAttempts := getMaxLoginAttempts()
	lockoutMin := getLockoutMinutes()
	now := time.Now()

	if user.FailedAttempts >= maxAttempts {
		if user.LockedUntil != nil && now.Before(*user.LockedUntil) {
			remaining := time.Until(*user.LockedUntil).Round(time.Second)
			return nil, "", &models.LoginError{Key: "auth.account_locked_retry_in", Default: "cuenta bloqueada. Podrás intentar de nuevo en " + remaining.String(), Args: []interface{}{remaining.String()}}
		}
		user.FailedAttempts = 0
		user.LockedUntil = nil
		_ = database.DB.Save(&user).Error
	}

	if !CheckPassword(password, user.Password) {
		user.FailedAttempts++
		if user.FailedAttempts >= maxAttempts && lockoutMin > 0 {
			until := now.Add(time.Duration(lockoutMin) * time.Minute)
			user.LockedUntil = &until
		}
		_ = database.DB.Save(&user).Error
		if user.FailedAttempts >= maxAttempts {
			if user.LockedUntil != nil {
				return nil, "", &models.LoginError{Key: "auth.too_many_attempts_time", Default: "demasiados intentos fallidos. Cuenta bloqueada " + strconv.Itoa(lockoutMin) + " minutos.", Args: []interface{}{lockoutMin}}
			}
			return nil, "", &models.LoginError{Key: "auth.too_many_attempts", Default: "demasiados intentos fallidos. Intenta nuevamente más tarde"}
		}
		return nil, "", &models.LoginError{Key: "auth.invalid_credentials", Default: "usuario o contraseña incorrectos"}
	}

	user.FailedAttempts = 0
	user.LockedUntil = nil
	user.LastLogin = &now
	user.LoginCount++
	if user.TokenVersion <= 0 {
		user.TokenVersion = 1
	}
	_ = database.DB.Save(&user).Error

	token, err := GenerateToken(&user)
	if err != nil {
		return nil, "", err
	}
	return &user, token, nil
}

// Register registra un nuevo usuario (validación completa).
func Register(username, password, email string) (*models.User, error) {
	if username == "" {
		return nil, errors.New("el nombre de usuario no puede estar vacío")
	}
	if err := validators.ValidateUsername(username); err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("la contraseña no puede estar vacía")
	}
	if err := validators.ValidatePassword(password); err != nil {
		return nil, err
	}
	if err := validators.ValidateEmail(email); err != nil {
		return nil, err
	}
	var existingUser models.User
	if err := database.DB.Where("username = ?", username).First(&existingUser).Error; err == nil {
		return nil, errors.New("el usuario ya existe")
	}
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("error hasheando contraseña: %v", err)
	}
	user := models.User{
		Username: username, Password: hashedPassword, Email: email,
		Role: "admin", Timezone: "UTC", IsActive: true, TokenVersion: 1,
		FirstLoginCompleted: false,
	}
	if err := database.DB.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("error creando usuario en BD: %v", err)
	}
	return &user, nil
}

// RegisterBootstrap crea el usuario inicial sin validar fortaleza de contraseña.
func RegisterBootstrap(username, password, email string) (*models.User, error) {
	if username == "" || password == "" {
		return nil, errors.New("usuario y contraseña no pueden estar vacíos")
	}
	if err := validators.ValidateUsername(username); err != nil {
		return nil, err
	}
	var existingUser models.User
	if err := database.DB.Where("username = ?", username).First(&existingUser).Error; err == nil {
		return nil, errors.New("el usuario ya existe")
	}
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("error hasheando contraseña: %v", err)
	}
	user := models.User{
		Username: username, Password: hashedPassword, Email: email,
		Role: "admin", Timezone: "UTC", IsActive: true, TokenVersion: 1,
		FirstLoginCompleted: false,
	}
	if err := database.DB.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("error creando usuario en BD: %v", err)
	}
	return &user, nil
}
