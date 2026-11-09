package templates

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"hostberry/internal/config"
	"hostberry/internal/constants"
	"hostberry/internal/i18n"
)

func registerTemplateFuncs(engine *html.Engine) {
	if engine == nil {
		return
	}

	engine.AddFunc("t", func(key string, defaultValue ...string) string {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return key
	})

	engine.AddFunc("eq", func(a, b interface{}) bool {
		return a == b
	})

	engine.AddFunc("ne", func(a, b interface{}) bool {
		return a != b
	})

	engine.AddFunc("contains", func(s, substr string) bool {
		return strings.Contains(s, substr)
	})

	engine.AddFunc("Seq", func(start, end int) []int {
		var seq []int
		for i := start; i <= end; i++ {
			seq = append(seq, i)
		}
		return seq
	})

	// Interfaz WiFi por defecto (p. ej. monitoring.html).
	engine.AddFunc("DefaultWiFiInterface", func() string {
		return constants.DefaultWiFiInterface
	})
}

// CreateTemplateEngine intenta crear el motor de templates usando:
// 1) directorios locales (varias rutas candidatas)
// 2) fallback contra FS embebido (si existe)
// 3) forzado final contra /opt/hostberry/website/templates
func CreateTemplateEngine(templatesFS embed.FS) *html.Engine {
	var engine *html.Engine

	// Preferimos primero el FS embebido (si existe) para reducir I/O en SD.
	// Si falla, hacemos fallback a disco.
	if tmplFS, err := fs.Sub(templatesFS, "website/templates"); err == nil && tmplFS != nil {
		criticalTemplates := []string{"dashboard.html", "login.html", "base.html"}
		allCriticalFound := true
		for _, tmpl := range criticalTemplates {
			if testFile, err := tmplFS.Open(tmpl); err == nil {
				_ = testFile.Close()
			} else {
				allCriticalFound = false
				break
			}
		}

		if allCriticalFound {
			engine = html.NewFileSystem(http.FS(tmplFS), ".html")
			if engine != nil {
				registerTemplateFuncs(engine)
				if loadErr := engine.Load(); loadErr == nil {
					engine.Reload(!config.AppConfig.Server.Debug)
					i18n.LogT("logs.templates_loaded_embed_first")
					return engine
				} else {
					i18n.LogTf("logs.templates_embedded_load_error", loadErr)
					engine = nil
				}
			}
		}
	}

	paths := []string{
		"/opt/hostberry/website/templates", // Ruta de instalación estándar
	}

	// Intentar desde el directorio actual
	if wd, err := os.Getwd(); err == nil && wd != "" {
		cur := wd
		for i := 0; i < 6; i++ {
			candidate := filepath.Join(cur, "website", "templates")
			if candidate != "/opt/hostberry/website/templates" {
				paths = append(paths, candidate)
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
	}

	// Intentar también desde el dir del binario
	exePath, _ := os.Executable()
	if exePath != "" {
		exeDir := filepath.Dir(exePath)
		templatesPath := filepath.Join(exeDir, "website", "templates")
		if templatesPath != "/opt/hostberry/website/templates" {
			paths = append(paths, templatesPath)
		}
	}

	// Cargar desde disco
	for _, path := range paths {
		if engine != nil {
			break
		}

		if stat, err := os.Stat(path); err != nil || !stat.IsDir() {
			continue
		}

		entries, err := os.ReadDir(path)
		if err != nil {
			continue
		}

		var foundTemplates int
		var htmlFiles []string
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.HasSuffix(entry.Name(), ".html") {
				foundTemplates++
				htmlFiles = append(htmlFiles, entry.Name())
			}
		}

		// Si hay muchos ficheros, asumimos que está bien.
		if foundTemplates <= 0 {
			continue
		}

		// Engine
		engine = html.New(path, ".html")
		if engine == nil {
			continue
		}

		registerTemplateFuncs(engine)
		if err := engine.Load(); err != nil {
			i18n.LogTf("logs.templates_load_error", path, err)
			engine = nil
			continue
		}

		i18n.LogTf("logs.templates_loaded", path)
		i18n.LogTf("logs.templates_html_count", len(htmlFiles))
		i18n.LogTf("logs.templates_registered", foundTemplates)
		engine.Reload(!config.AppConfig.Server.Debug)
		break
	}

	// fallback con templates embebidos
	if engine == nil {
		i18n.LogTln("logs.templates_fs_unavailable")

		// Nota: templatesFS puede estar vacío si no existe go:embed en el build.
		tmplFS, err := fs.Sub(templatesFS, "website/templates")
		if err == nil {
			if entries, err := fs.ReadDir(tmplFS, "."); err == nil {
				htmlFiles := 0
				var templateNames []string
				for _, entry := range entries {
					if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".html") {
						htmlFiles++
						if len(templateNames) < 5 {
							templateNames = append(templateNames, entry.Name())
						}
					}
				}

				if htmlFiles > 0 {
					criticalTemplates := []string{"dashboard.html", "login.html", "base.html"}
					allCriticalFound := true
					for _, tmpl := range criticalTemplates {
						if testFile, err := tmplFS.Open(tmpl); err == nil {
							testFile.Close()
							i18n.LogTf("logs.templates_embedded_verified", tmpl)
						} else {
							i18n.LogTf("logs.templates_embedded_open_error", tmpl, err)
							allCriticalFound = false
						}
					}

					if allCriticalFound {
						engine = html.NewFileSystem(http.FS(tmplFS), ".html")
						if engine != nil {
							registerTemplateFuncs(engine)
							if loadErr := engine.Load(); loadErr != nil {
								i18n.LogTf("logs.templates_embedded_load_error", loadErr)
								engine = nil
							} else {
								engine.Reload(false)
								i18n.LogTf("logs.templates_embedded_loaded", htmlFiles)
								i18n.LogTf("logs.templates_embedded_list", templateNames)
							}
						}
					}
				}
			}
		}
	}

	if engine == nil {
		log.Println("⚠️  No se encontró engine después de todos los intentos, forzando desde /opt/hostberry/website/templates")
		forcePath := "/opt/hostberry/website/templates"
		if stat, err := os.Stat(forcePath); err == nil && stat.IsDir() {
			engine = html.New(forcePath, ".html")
			if engine != nil {
				registerTemplateFuncs(engine)
				if err := engine.Load(); err != nil {
					log.Printf("❌ Error cargando templates forzados desde %s: %v", forcePath, err)
					engine = nil
				} else {
					engine.Reload(!config.AppConfig.Server.Debug)
				}
			}
		}
	}

	if engine == nil {
		log.Fatal("❌ Error crítico: engine es nil después de todos los intentos de carga")
	}

	return engine
}

func RenderTemplate(c *fiber.Ctx, name string, data fiber.Map) error {
	language := i18n.GetCurrentLanguage(c)
	i18nFuncs := i18n.TemplateFuncs(c)

	if data == nil {
		data = fiber.Map{}
	}

	data["page"] = name

	// Cache-busting de assets (si el handler no lo provee)
	if _, ok := data["last_update"]; !ok {
		data["last_update"] = time.Now().Unix()
	}

	data["language"] = language
	data["t"] = i18nFuncs["t"]
	data["common"] = i18nFuncs["common"]
	data["navigation"] = i18nFuncs["navigation"]
	data["dashboard"] = i18nFuncs["dashboard"]
	data["auth"] = i18nFuncs["auth"]
	data["system"] = i18nFuncs["system"]
	data["network"] = i18nFuncs["network"]
	data["wifi"] = i18nFuncs["wifi"]
	data["vpn"] = i18nFuncs["vpn"]
	data["wireguard"] = i18nFuncs["wireguard"]
	data["adblock"] = i18nFuncs["adblock"]
	data["settings"] = i18nFuncs["settings"]
	data["errors"] = i18nFuncs["errors"]

	// Traducciones se cargan por API en el cliente (sin embeber JSON en la página)
	if user := c.Locals("user"); user != nil {
		data["current_user"] = user
	}

	templateName := name

	log.Printf("📂 Intentando renderizar template: %s", templateName)

	// Try multiple conventions: templateName, templateName+".html", etc.
	if err := c.Render(templateName, data, "base"); err == nil {
		return nil
	}
	if err := c.Render(templateName+".html", data, "base"); err == nil {
		return nil
	}
	if err := c.Render(templateName, data, "base.html"); err == nil {
		return nil
	}
	if err := c.Render(templateName+".html", data, "base.html"); err == nil {
		return nil
	}
	if err := c.Render(templateName, data); err == nil {
		return nil
	}

	log.Printf("   ❌ Todos los intentos fallaron para: %s", name)
	if views := c.App().Config().Views; views != nil {
		log.Printf("   ℹ️ Motor de templates está presente")
	} else {
		log.Printf("   ⚠️ Motor de templates NO está configurado")
	}

	return fiber.NewError(500, fmt.Sprintf("Error renderizando template: %s", name))
}

// --- compat helpers (no-op wrappers are intentionally omitted) ---
// En caso de necesitar copia/transferencia de static files, dejarlo en `main` (depende del runtime y del embed).
