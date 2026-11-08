package captiveportal

import (
	"net"
	"strings"

	"hostberry/internal/constants"
)

// APClientNetwork devuelve la red de clientes del AP (192.168.4.0/24) o nil si la
// constante es inválida. Se parsea una vez por llamada; el resultado es inmutable.
func APClientNetwork() *net.IPNet {
	_, n, err := net.ParseCIDR(constants.DefaultAPNetworkCIDR)
	if err != nil {
		return nil
	}
	return n
}

// IsAPClientIP indica si la IP pertenece a la red de clientes del AP cautivo.
func IsAPClientIP(ipStr string) bool {
	apNet := APClientNetwork()
	if apNet == nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	return apNet.Contains(ip)
}
