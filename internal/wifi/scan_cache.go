package wifi

import (
	"sync"
	"time"
)

const scanCacheTTL = 18 * time.Second

type scanCacheEntry struct {
	networks      []map[string]interface{}
	cachedAt      time.Time
	interfaceName string
	band          string
}

var scanResultCache struct {
	mu   sync.RWMutex
	data scanCacheEntry
}

var scanOpMu sync.Mutex

// scanFlightCall representa un escaneo en curso para una clave (interfaz+banda).
// Los callers concurrentes esperan en done y comparten result: evitan
// serializar dos escaneos idénticos (p. ej. prefetch + clic manual) y duplicar
// el tiempo de espera. La radio sigue serializada por scanOpMu entre bandas.
type scanFlightCall struct {
	done   chan struct{}
	result map[string]interface{}
}

var scanFlights = struct {
	mu sync.Mutex
	m  map[string]*scanFlightCall
}{m: make(map[string]*scanFlightCall)}

// getCachedScanNetworks devuelve la caché si coincide interfaz y banda. La banda forma parte de la
// clave para no devolver redes 2.4 cuando se pide 5 GHz (o viceversa) durante el asistente.
func getCachedScanNetworks(interfaceName, band string) []map[string]interface{} {
	scanResultCache.mu.RLock()
	defer scanResultCache.mu.RUnlock()
	if scanResultCache.data.interfaceName != interfaceName {
		return nil
	}
	if scanResultCache.data.band != band {
		return nil
	}
	if time.Since(scanResultCache.data.cachedAt) > scanCacheTTL {
		return nil
	}
	if len(scanResultCache.data.networks) == 0 {
		return nil
	}
	return cloneScanNetworks(scanResultCache.data.networks)
}

func setCachedScanNetworks(interfaceName, band string, networks []map[string]interface{}) {
	if len(networks) == 0 {
		return
	}
	scanResultCache.mu.Lock()
	defer scanResultCache.mu.Unlock()
	scanResultCache.data = scanCacheEntry{
		interfaceName: interfaceName,
		band:          band,
		networks:      cloneScanNetworks(networks),
		cachedAt:      time.Now(),
	}
}

func cloneScanNetworks(networks []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, len(networks))
	for i, n := range networks {
		dup := make(map[string]interface{}, len(n))
		for k, v := range n {
			dup[k] = v
		}
		out[i] = dup
	}
	return out
}
