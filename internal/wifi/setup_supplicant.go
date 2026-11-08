package wifi

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hostberry/internal/constants"
)

// Durante el asistente inicial, en hardware de radio única (AP+STA), NetworkManager escanea wlan0
// de forma periódica para buscar redes. Cada escaneo obliga a la radio a abandonar el canal del AP
// "hostberry", lo que expulsa al cliente del portal cautivo cada 1-2 minutos (pasa en cualquier
// banda). Para evitarlo, durante el setup sacamos wlan0 de NetworkManager (nmcli, en runtime) y lo
// dejamos bajo un wpa_supplicant DEDICADO (servicio systemd), sin redes configuradas y sin autoscan:
// solo escanea cuando el asistente lo pide explícitamente (wpa_cli scan). Al finalizar el wizard (o
// si el setup ya está completo) devolvemos wlan0 a NetworkManager para que la autoconexión normal
// funcione tras el reinicio.
//
// Notas de despliegue:
//   - El servicio hostberry.service corre con ProtectSystem=strict; el proceso NO puede escribir en
//     /etc/systemd/system. Por eso el unit se PREINSTALA (install.sh) y la app solo lo arranca/para.
//   - /etc/wpa_supplicant SÍ está en ReadWritePaths, así que la conf del supplicant la escribe la app.
//   - No se escribe ninguna conf en /etc/NetworkManager: el unmanage es en runtime (nmcli) y lo
//     reaplica el arranque mientras el setup siga pendiente.

const (
	setupSupplicantUnit     = "hostberry-wifi-setup.service"
	setupSupplicantConfPath = "/etc/wpa_supplicant/hostberry-wlan0-setup.conf"
	// setupSupplicantSocket: el wpa_supplicant dedicado crea aquí el socket de control, alineado con
	// los directorios que ya inspeccionan las rutas de escaneo (wpaSupplicantSocketDir).
	setupSupplicantSocket = "/run/wpa_supplicant"
)

func setupSupplicantConfContent() string {
	return fmt.Sprintf("ctrl_interface=%s\nctrl_interface_group=netdev\nupdate_config=1\n", setupSupplicantSocket)
}

// installSetupSupplicantConf escribe la conf del wpa_supplicant dedicado en /etc/wpa_supplicant
// (escribe primero un tmp en un directorio escribible y lo copia con el ejecutor privilegiado).
func installSetupSupplicantConf() error {
	if err := os.MkdirAll(WpaSupplicantRuntimeConfigDir, 0750); err != nil {
		return fmt.Errorf("preparar dir runtime: %w", err)
	}
	tmp := filepath.Join(WpaSupplicantRuntimeConfigDir, fmt.Sprintf("setup-%d-wlan0-setup.conf", time.Now().UnixNano()))
	if err := os.WriteFile(tmp, []byte(setupSupplicantConfContent()), 0600); err != nil {
		return fmt.Errorf("escribir tmp: %w", err)
	}
	if _, err := execPrivilegedArgv("cp", tmp, setupSupplicantConfPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("instalar %s: %v", setupSupplicantConfPath, err)
	}
	if _, err := execPrivilegedArgv("chmod", "600", setupSupplicantConfPath); err != nil {
		log.Printf("Setup supplicant: chmod %s: %v", setupSupplicantConfPath, err)
	}
	_ = os.Remove(tmp)
	return nil
}

// StartSetupModeSupplicant deja wlan0 bajo el wpa_supplicant dedicado (sin autoscan) durante el
// asistente. Es idempotente. Requiere que el unit systemd esté preinstalado; si no existe, no toca
// NetworkManager (degrada al comportamiento previo). Si el supplicant no toma la interfaz, revierte.
func StartSetupModeSupplicant() {
	iface := constants.DefaultWiFiInterface

	// Solo aplica en hardware con AP concurrente (ap0) y la interfaz STA presente. En otros entornos
	// (p. ej. desarrollo) no tocamos NetworkManager.
	if _, err := os.Stat("/sys/class/net/ap0"); err != nil {
		return
	}
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		return
	}

	// El unit debe estar preinstalado (install.sh). Sin él, no intervenimos para no dejar wlan0
	// sin gestor.
	if out, err := execPrivilegedArgv("systemctl", "list-unit-files", setupSupplicantUnit); err != nil || !strings.Contains(out, setupSupplicantUnit) {
		log.Printf("Setup supplicant: unit %s no instalada; se mantiene wlan0 en NetworkManager", setupSupplicantUnit)
		return
	}

	if err := installSetupSupplicantConf(); err != nil {
		log.Printf("Setup supplicant: conf wpa_supplicant: %v", err)
		return
	}

	// Sacar wlan0 de NetworkManager (efecto inmediato): NM libera la interfaz y deja de escanearla.
	if out, err := execPrivilegedArgv("nmcli", "device", "set", iface, "managed", "no"); err != nil {
		log.Printf("Setup supplicant: nmcli managed no: %v (%s)", err, out)
	}
	// Margen para que NM suelte la interfaz antes de que el supplicant dedicado la tome.
	time.Sleep(1500 * time.Millisecond)

	if out, err := execPrivilegedArgv("systemctl", "restart", setupSupplicantUnit); err != nil {
		log.Printf("Setup supplicant: restart unit: %v (%s)", err, out)
		revertSetupModeSupplicant(iface)
		return
	}

	// Verificar que el socket de control aparece (señal de que el supplicant tomó la interfaz).
	socketPath := filepath.Join(setupSupplicantSocket, iface)
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := os.Stat(socketPath); err == nil {
			log.Printf("Setup supplicant: wlan0 bajo supplicant dedicado sin autoscan (portal estable durante el asistente)")
			return
		}
		time.Sleep(400 * time.Millisecond)
	}

	log.Printf("Setup supplicant: el socket %s no apareció; revirtiendo a NetworkManager", socketPath)
	revertSetupModeSupplicant(iface)
}

// StopSetupModeSupplicant devuelve wlan0 a NetworkManager (fin del asistente o setup ya completo).
// Es idempotente: si nunca se activó el modo setup, simplemente se asegura de que wlan0 esté
// gestionado y el supplicant dedicado parado.
func StopSetupModeSupplicant() {
	revertSetupModeSupplicant(constants.DefaultWiFiInterface)
}

func revertSetupModeSupplicant(iface string) {
	_, _ = execPrivilegedArgv("systemctl", "stop", setupSupplicantUnit)
	if out, err := execPrivilegedArgv("nmcli", "device", "set", iface, "managed", "yes"); err != nil {
		log.Printf("Setup supplicant: nmcli managed yes: %v (%s)", err, out)
	}
	// Recargar NetworkManager para que reconozca la configuración de wpa_supplicant escrita por el wizard
	// Esto es necesario para que NetworkManager se conecte automáticamente a la red guardada después del reinicio
	_, _ = execPrivilegedArgv("nmcli", "connection", "reload")
	// Opcionalmente, intentar reconectar la interfaz para forzar la conexión inmediata
	if _, err := execPrivilegedArgv("nmcli", "device", "connect", iface); err != nil {
		log.Printf("Setup supplicant: nmcli device connect: %v", err)
	}
}
