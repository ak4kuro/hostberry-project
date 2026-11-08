#!/bin/bash
# HostBerry — ejecutor privilegiado con allowlist (única entrada sudoers recomendada).
set -euo pipefail

if [ "$#" -lt 1 ]; then
	echo "usage: privileged-exec <command>" >&2
	exit 1
fi

CMD="$1"

# Caracteres peligrosos (alineado con internal/utils validateShellCommandAllowList).
if [[ "$CMD" == *";"* || "$CMD" == *$'\n'* || "$CMD" == *$'\r'* || "$CMD" == *'`'* || "$CMD" == *'$'* ]]; then
	echo "command rejected" >&2
	exit 1
fi
if [[ "$CMD" == *"<<"* || "$CMD" == *">>"* || "$CMD" == *"<"* ]]; then
	echo "command rejected" >&2
	exit 1
fi

# '&' solo se admite como '&&' o dentro de '>&' (p. ej. 2>&1). Un '&' suelto
# ejecutaría el comando en segundo plano o encadenaría de forma no prevista.
amp="${CMD//&&/}"
amp="${amp//>&/}"
if [[ "$amp" == *"&"* ]]; then
	echo "command rejected" >&2
	exit 1
fi

# '>' solo se admite redirigiendo a /dev/null (p. ej. 2>/dev/null, >/dev/null)
# o como '2>&1'. Cualquier otra redirección queda rechazada (misma regla que
# validateShellCommandAllowList en Go).
stripped="$CMD"
while [[ "$stripped" =~ [0-9]*\>[[:space:]]*/dev/null|2\>\&1 ]]; do
	stripped="${stripped/"${BASH_REMATCH[0]}"/}"
done
if [[ "$stripped" == *">"* ]]; then
	echo "command rejected" >&2
	exit 1
fi

allowed_tokens=(
	hostname hostnamectl uname cat grep awk sed cut head tail journalctl
	top free df nproc iwlist nmcli iw ip wg wg-quick systemctl pgrep
	reboot shutdown poweroff rfkill ifconfig iwconfig
	hostapd hostapd_cli dnsmasq iptables iptables-save netfilter-persistent sysctl tee cp mkdir echo chmod chown rm
	dhclient udhcpc wpa_supplicant wpa_cli pkill killall true mount
	apt-get apt
)

first="${CMD%% *}"
if [ "$first" = "sudo" ]; then
	rest="${CMD#sudo }"
	first="${rest%% *}"
fi
base="${first##*/}"

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

exec /bin/sh -c "$CMD"
