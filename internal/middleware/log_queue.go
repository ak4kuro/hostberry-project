package middleware

import (
	"sync"

	"hostberry/internal/database"
)

// pendingHTTPLog es una entrada de log pendiente de escribir en BD.
type pendingHTTPLog struct {
	level   string
	message string
	source  string
	userID  *int
}

var (
	httpLogCh   = make(chan pendingHTTPLog, 256)
	httpLogOnce sync.Once
)

// enqueueHTTPLog serializa los logs HTTP en un único worker con cola acotada.
// Antes se lanzaba una goroutine por request: un flood de 4xx/5xx podía crear
// goroutines y escrituras a BD sin límite. Si la cola está llena se descarta
// el log (mejor perder un log que bloquear o tumbar el servicio).
func enqueueHTTPLog(level, message, source string, userID *int) {
	httpLogOnce.Do(func() {
		go func() {
			for item := range httpLogCh {
				_ = database.InsertLog(item.level, item.message, item.source, item.userID)
			}
		}()
	})
	select {
	case httpLogCh <- pendingHTTPLog{level: level, message: message, source: source, userID: userID}:
	default:
	}
}
