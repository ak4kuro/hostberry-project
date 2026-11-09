#!/bin/bash
# Descarga binarios precompilados desde GitHub Releases (pure Go, sin CGO).

HOSTBERRY_RELEASE_REPO="${HOSTBERRY_RELEASE_REPO:-ak4kuro/hostberry-project}"

hostberry_detect_arch() {
    local machine
    machine="$(uname -m 2>/dev/null || echo unknown)"
    case "$machine" in
        aarch64|arm64)             echo "arm64" ;;   # Pi 3/4/5 y Zero 2 con OS de 64 bits, PC ARM64
        x86_64|amd64)              echo "amd64" ;;   # PC/servidor x86 de 64 bits
        armv7l|armv7|armv8l|armhf) echo "armv7" ;;   # Pi 2/3/4 con OS de 32 bits
        armv6l|armv6)              echo "armv6" ;;   # Pi 1 / Pi Zero (32 bits)
        i386|i486|i586|i686|x86)   echo "386" ;;     # PC x86 de 32 bits
        riscv64)                   echo "riscv64" ;; # placas RISC-V de 64 bits
        *)                         echo "unknown" ;;
    esac
}

hostberry_release_tag() {
    if [ -n "${HOSTBERRY_RELEASE_TAG:-}" ]; then
        printf '%s' "$HOSTBERRY_RELEASE_TAG"
        return 0
    fi
    if [ -f "${SCRIPT_DIR}/internal/constants/constants.go" ]; then
        local ver
        ver="$(grep -E 'Version\s*=' "${SCRIPT_DIR}/internal/constants/constants.go" 2>/dev/null | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
        if [ -n "$ver" ]; then
            printf 'v%s' "$ver"
            return 0
        fi
    fi
    printf 'latest'
}

# Devuelve 0 si instaló un binario válido en ${INSTALL_DIR}/hostberry
hostberry_try_release_binary() {
    local use_release="${HOSTBERRY_USE_RELEASE_BINARY:-auto}"
    case "$use_release" in
        0|false|no|never) return 1 ;;
        auto|1|true|yes)
            # install y update: intentar binario publicado antes de compilar
            ;;
    esac

    local arch asset tag url tmp checksum_url expected
    arch="$(hostberry_detect_arch)"
    if [ "$arch" = "unknown" ]; then
        return 1
    fi

    asset="hostberry-linux-${arch}"
    tag="$(hostberry_release_tag)"
    url="https://github.com/${HOSTBERRY_RELEASE_REPO}/releases/download/${tag}/${asset}"
    checksum_url="${url}.sha256"

    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        return 1
    fi

    print_info "Intentando binario precompilado (${asset}, tag ${tag})..."
    tmp="$(mktemp)"
    if command -v curl &>/dev/null; then
        if ! curl -fsSL --connect-timeout 15 --max-time 300 -o "$tmp" "$url" 2>/dev/null; then
            rm -f "$tmp"
            return 1
        fi
    else
        if ! wget -q -T 300 -O "$tmp" "$url" 2>/dev/null; then
            rm -f "$tmp"
            return 1
        fi
    fi

    if [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        return 1
    fi

    expected=""
    if command -v curl &>/dev/null; then
        expected="$(curl -fsSL --connect-timeout 10 --max-time 30 "$checksum_url" 2>/dev/null | awk '{print $1}')"
    else
        expected="$(wget -q -O - "$checksum_url" 2>/dev/null | awk '{print $1}')"
    fi
    if [ -n "$expected" ] && command -v sha256sum &>/dev/null; then
        local actual
        actual="$(sha256sum "$tmp" | awk '{print $1}')"
        if [ "$expected" != "$actual" ]; then
            print_warning "Checksum del binario precompilado no coincide; se compilará desde fuente."
            rm -f "$tmp"
            return 1
        fi
    fi

    chmod +x "$tmp"
    if ! "$tmp" -version >/dev/null 2>&1; then
        print_warning "Binario precompilado no arranca (-version); se compilará desde fuente."
        rm -f "$tmp"
        return 1
    fi

    if declare -F hostberry_backup_binary >/dev/null 2>&1; then
        hostberry_backup_binary
    fi
    install -m 0755 -o "$USER_NAME" -g "$GROUP_NAME" "$tmp" "${INSTALL_DIR}/hostberry"
    rm -f "$tmp"
    if declare -F hostberry_store_binary_checksum >/dev/null 2>&1; then
        hostberry_store_binary_checksum
    fi
    print_success "Binario precompilado instalado (${asset})"
    return 0
}
