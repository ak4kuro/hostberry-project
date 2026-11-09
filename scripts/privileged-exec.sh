#!/bin/bash
# HostBerry — ejecutor privilegiado argv con allowlist (única entrada sudoers).
# Solo modo --argv: los argumentos se pasan literalmente, sin intérprete de
# comandos. No existe modo shell: cualquier invocación sin --argv se rechaza.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$1" != "--argv" ]; then
	echo "usage: privileged-exec --argv <command> [args...]" >&2
	exit 1
fi
shift

allowed_tokens=(
	hostname hostnamectl uname cat grep awk sed cut head tail journalctl
	top free df nproc iwlist nmcli iw ip wg wg-quick systemctl pgrep
	reboot shutdown poweroff rfkill ifconfig iwconfig
	hostapd hostapd_cli dnsmasq iptables iptables-save netfilter-persistent sysctl tee cp mkdir echo chmod chown rm
	dhclient udhcpc wpa_supplicant wpa_cli pkill killall true
	udevadm
	apt-get apt
	tar mount
)

# Modo argv: los argumentos se pasan literalmente, sin shell. Solo se
# valida el binario contra la allowlist; los argumentos no pueden
# inyectar sintaxis porque nunca pasan por un intérprete de comandos.
CMD="$1"
base="${CMD##*/}"
ok=0
for t in "${allowed_tokens[@]}"; do
	if [ "$base" = "$t" ]; then
		ok=1
		break
	fi
done
if [ "$ok" -ne 1 ]; then
	echo "command not allowed: $base" >&2
	exit 1
fi
shift
exec "$CMD" "$@"
