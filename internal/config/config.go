package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"hostberry/internal/constants"

	"gopkg.in/yaml.v3"
)

// Config es la configuración principal de la aplicación.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// LoggingConfig configuración de logs rotativos.
type LoggingConfig struct {
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
}

// ServerConfig configuración del servidor HTTP.
type ServerConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Debug        bool   `yaml:"debug"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
	TLSCertFile  string `yaml:"tls_cert_file"`
	TLSKeyFile   string `yaml:"tls_key_file"`
	// HTTPRedirectPort: si es > 0 y hay TLS, se abre un listener HTTP en este puerto que redirige a HTTPS (server.port).
	// 0 = no abrir listener HTTP de redirección (sólo HTTPS en server.port).
	HTTPRedirectPort int `yaml:"http_redirect_port"`
}

// DatabaseConfig configuración de la base de datos.
type DatabaseConfig struct {
	Type     string `yaml:"type"`
	Path     string `yaml:"path"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

// SecurityConfig configuración de seguridad.
type SecurityConfig struct {
	JWTSecret      string `yaml:"jwt_secret"`
	TokenExpiry    int    `yaml:"token_expiry"`
	BcryptCost     int    `yaml:"bcrypt_cost"`
	RateLimitRPS   int    `yaml:"rate_limit_rps"`
	LockoutMinutes int    `yaml:"lockout_minutes"`
	EnforceHTTPS   bool   `yaml:"enforce_https"`
	// TrustedProxyIPs: IPs/CIDRs que pueden enviar X-Forwarded-Proto de confianza (127.0.0.1 y ::1 siempre).
	TrustedProxyIPs []string `yaml:"trusted_proxy_ips"`
	// WifiSetupToken: si está vacío tras cargar config, se genera uno por arranque (ver logs).
	// Permite llamar a /api/v1/wifi/{status,scan,connect,disconnect} sin JWT usando cabecera
	// X-HostBerry-WiFi-Setup-Token (solo para automatización / recuperación).
	WifiSetupToken string `yaml:"wifi_setup_token"`
	// CORSAllowOrigins: orígenes adicionales permitidos con credenciales (proxy, otro hostname, etc.).
	CORSAllowOrigins []string `yaml:"cors_allow_origins"`
}

// AppConfig es la configuración cargada (acceso global desde el resto del paquete main).
var AppConfig *Config

// GenerateRandomSecret genera un secreto aleatorio para JWT u otro uso.
func GenerateRandomSecret() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable while generating secret: %v", err))
	}
	return hex.EncodeToString(bytes)
}

// Load lee config.yaml y asigna AppConfig. Si el archivo no existe, usa valores por defecto.
func Load() error {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		AppConfig = &Config{
			Server: ServerConfig{
				Host:         constants.DefaultServerHost,
				Port:         constants.DefaultServerPort,
				Debug:        false,
				ReadTimeout:  30,
				WriteTimeout: 30,
			},
			Database: DatabaseConfig{
				Type: "sqlite",
				Path: "data/hostberry.db",
			},
			Security: SecurityConfig{
				JWTSecret:      GenerateRandomSecret(),
				TokenExpiry:    30,
				BcryptCost:     10,
				RateLimitRPS:   10,
				LockoutMinutes: 15,
			},
			Logging: LoggingConfig{
				Level:      "info",
				File:       "logs/hostberry.log",
				MaxSize:    10,
				MaxBackups: 5,
			},
		}
		return nil
	}
	AppConfig = &Config{}
	return yaml.Unmarshal(data, AppConfig)
}

// Normalize endurece la configuración de seguridad (JWT no vacío, bcrypt cost en rango).
// Debe llamarse tras Load(). OnNormalized puede ser un callback para log (ej. LogTf).
func Normalize(onNormalized func(string, ...interface{})) {
	if AppConfig == nil {
		return
	}
	if strings.TrimSpace(AppConfig.Security.JWTSecret) == "" {
		AppConfig.Security.JWTSecret = GenerateRandomSecret()
		if onNormalized != nil {
			onNormalized("logs.config_jwt_regenerated", "JWT secret vacío en config.yaml: generado uno nuevo en memoria")
		}
	}
	if AppConfig.Security.BcryptCost < 4 || AppConfig.Security.BcryptCost > 15 {
		if onNormalized != nil {
			onNormalized("logs.config_bcrypt_cost_normalized", AppConfig.Security.BcryptCost)
		}
		AppConfig.Security.BcryptCost = 10
	}
	if AppConfig.Security.TokenExpiry <= 0 || AppConfig.Security.TokenExpiry > 1440 {
		AppConfig.Security.TokenExpiry = 30
	}
	cert := strings.TrimSpace(AppConfig.Server.TLSCertFile)
	key := strings.TrimSpace(AppConfig.Server.TLSKeyFile)
	if cert != "" && key != "" {
		AppConfig.Security.EnforceHTTPS = true
	} else if AppConfig.Security.EnforceHTTPS {
		AppConfig.Security.EnforceHTTPS = false
		if onNormalized != nil {
			onNormalized("logs.config_enforce_https_disabled", "enforce_https desactivado: no hay certificados TLS configurados")
		}
	}
}
