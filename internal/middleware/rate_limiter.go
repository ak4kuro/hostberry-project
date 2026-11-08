package middleware

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/config"
)

type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	maxReqs  int
	window   time.Duration
}

var (
	globalRateLimiter *RateLimiter
	rateLimiterOnce   sync.Once
)

func NewRateLimiter(maxReqs int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		maxReqs:  maxReqs,
		window:   window,
	}

	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	allowed, _ := rl.AllowWithRetry(key)
	return allowed
}

func (rl *RateLimiter) AllowWithRetry(key string) (bool, time.Duration) {
	// maxReqs <= 0 desactiva el límite (evita bloquear toda la API si la
	// configuración trae un valor inválido).
	if rl.maxReqs <= 0 {
		return true, 0
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	validReqs := []time.Time{}
	for _, reqTime := range rl.requests[key] {
		if reqTime.After(cutoff) {
			validReqs = append(validReqs, reqTime)
		}
	}
	rl.requests[key] = validReqs

	if len(rl.requests[key]) >= rl.maxReqs {
		oldest := rl.requests[key][0]
		retryAfter := oldest.Add(rl.window).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
		return false, retryAfter
	}

	rl.requests[key] = append(rl.requests[key], now)
	return true, 0
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-rl.window)

		for key, reqs := range rl.requests {
			validReqs := []time.Time{}
			for _, reqTime := range reqs {
				if reqTime.After(cutoff) {
					validReqs = append(validReqs, reqTime)
				}
			}
			if len(validReqs) == 0 {
				delete(rl.requests, key)
			} else {
				rl.requests[key] = validReqs
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware limita peticiones por IP (y, si existe `user_id`, también por usuario).
func RateLimitMiddleware(c *fiber.Ctx) error {
	rateLimiterOnce.Do(func() {
		globalRateLimiter = NewRateLimiter(
			config.AppConfig.Security.RateLimitRPS,
			time.Second,
		)
	})

	key := c.IP()
	if userID := c.Locals("user_id"); userID != nil {
		switch v := userID.(type) {
		case int:
			key = "user_" + strconv.Itoa(v)
		case int64:
			key = "user_" + strconv.FormatInt(v, 10)
		case float64:
			key = "user_" + strconv.FormatInt(int64(v), 10)
		default:
			key = "user_" + fmt.Sprintf("%v", v)
		}
	}

	allowed, _ := globalRateLimiter.AllowWithRetry(key)
	if !allowed {
		return c.Status(429).JSON(fiber.Map{
			"error": "Demasiadas peticiones. Por favor, intenta más tarde.",
		})
	}

	return c.Next()
}
