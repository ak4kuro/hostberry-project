package middleware

import (
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// mutationLocks serializa operaciones mutantes pesadas para evitar estados inconsistentes.
// Implementación simple tipo semaphore (capacidad 1).
var (
	mutationLocks   = make(map[string]chan struct{})
	mutationLocksMu sync.Mutex
)

// mutationLockMaxEntries acota el mapa de locks. Las claves actuales son
// constantes, pero si alguna vez se usara una clave controlada por el cliente
// el mapa no debe crecer sin límite.
const mutationLockMaxEntries = 128

func getMutationLock(key string) chan struct{} {
	mutationLocksMu.Lock()
	defer mutationLocksMu.Unlock()

	if ch, ok := mutationLocks[key]; ok {
		return ch
	}

	// Limpieza perezosa: eliminar canales ociosos (token disponible = sin
	// operación en curso). Un canal ocupado nunca se borra, por lo que dos
	// peticiones concurrentes no pueden obtener locks distintos para la
	// misma clave.
	if len(mutationLocks) >= mutationLockMaxEntries {
		for k, ch := range mutationLocks {
			if len(ch) == 1 {
				delete(mutationLocks, k)
			}
		}
	}

	ch := make(chan struct{}, 1)
	ch <- struct{}{} // token inicial
	mutationLocks[key] = ch
	return ch
}

// MutationLock obtiene un lock por recurso antes de ejecutar la petición.
// Si no se obtiene en el tiempo dado, devuelve 423 Locked.
func MutationLock(resource string, timeout time.Duration) fiber.Handler {
	if resource == "" {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	lockCh := getMutationLock(resource)

	return func(c *fiber.Ctx) error {
		if c.Method() == fiber.MethodOptions {
			return c.Next()
		}

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-lockCh:
			// acquired
			defer func() { lockCh <- struct{}{} }()
			return c.Next()
		case <-timer.C:
			return c.Status(fiber.StatusLocked).JSON(fiber.Map{
				"error": "Operación en curso. Intenta de nuevo en unos segundos.",
			})
		}
	}
}
