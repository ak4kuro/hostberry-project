package middleware

import (
	"net"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"hostberry/internal/captiveportal"
	"hostberry/internal/constants"
)

func apClientRequestCtx(host string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost(host)
	addr, err := net.ResolveTCPAddr("tcp", "192.168.4.42:12345")
	if err != nil {
		panic(err)
	}
	ctx.SetRemoteAddr(addr)
	return ctx
}

func TestCaptivePortalMiddlewareRedirectsExternalHost(t *testing.T) {
	app := fiber.New()
	app.Use(CaptivePortalMiddleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	ctx := apClientRequestCtx("google.es")
	app.Handler()(ctx)

	if got := ctx.Response.StatusCode(); got != fiber.StatusFound {
		t.Fatalf("status = %d, want %d", got, fiber.StatusFound)
	}
	loc := string(ctx.Response.Header.Peek("Location"))
	if loc != constants.DefaultAPSetupURL {
		t.Fatalf("Location = %q", loc)
	}
}

func TestHostBerryLocalMiddlewareRedirectsToWizard(t *testing.T) {
	app := fiber.New()
	app.Use(HostBerryLocalMiddleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	ctx := apClientRequestCtx("hostberry.local")
	app.Handler()(ctx)

	if got := ctx.Response.StatusCode(); got != fiber.StatusFound {
		t.Fatalf("status = %d, want %d", got, fiber.StatusFound)
	}
	loc := string(ctx.Response.Header.Peek("Location"))
	if loc != constants.DefaultAPSetupURL {
		t.Fatalf("Location = %q", loc)
	}
}

func TestCaptivePortalMiddlewareAllowsLocalHost(t *testing.T) {
	app := fiber.New()
	app.Use(CaptivePortalMiddleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	ctx := apClientRequestCtx("192.168.4.1")
	app.Handler()(ctx)

	if got := ctx.Response.StatusCode(); got != fiber.StatusOK {
		t.Fatalf("status = %d, want %d", got, fiber.StatusOK)
	}
}

func TestIsAPCaptiveClientIP(t *testing.T) {
	if !captiveportal.IsAPClientIP("192.168.4.50") {
		t.Fatal("expected AP client IP")
	}
	if captiveportal.IsAPClientIP("192.168.1.50") {
		t.Fatal("expected LAN client IP to be excluded")
	}
}
