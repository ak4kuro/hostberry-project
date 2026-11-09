<div align="center">

# 🍓 HostBerry

**Turn your Raspberry Pi (or any Linux box) into a WiFi router + privacy gateway, managed from your browser.**

**Convierte tu Raspberry Pi (o cualquier Linux) en un router WiFi + pasarela de privacidad, gestionado desde el navegador.**

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

**🌐 [English](#-english)  ·  [Español](#-español)**

</div>

---

## 📸 Screenshots / Capturas

> Add your images to `docs/screenshots/` · Añade tus imágenes en `docs/screenshots/`

| Dashboard | Setup Wizard / Asistente |
|:---:|:---:|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Wizard](docs/screenshots/wizard.png) |
| **WiFi** | **VPN** |
| ![WiFi](docs/screenshots/wifi.png) | ![VPN](docs/screenshots/vpn.png) |

---

## 🇬🇧 English

### What is HostBerry?

HostBerry runs on your Raspberry Pi and gives you a simple web panel to:

- 📶 **Share internet** — your Pi becomes a WiFi access point (AP) while also connecting to another WiFi or cable.
- 🛡️ **Block ads** network-wide (Blocky DNS).
- 🔒 **VPN** — OpenVPN and WireGuard.
- 🧅 **Tor** routing.
- 🔥 **Firewall** with easy rules.
- 📊 **Monitor** system, network and run speed tests.

Everything from a clean, secure (HTTPS) web page. No command line needed after install.

### ✅ Supported devices

| Device | Works? |
|---|---|
| Raspberry Pi 3 / 4 / 5 (64-bit OS) | ✅ |
| Raspberry Pi 2 / 3 / 4 (32-bit OS) | ✅ |
| Raspberry Pi 1 / Pi Zero | ✅ |
| Regular PC / server (x86) | ✅ |
| RISC-V boards | ✅ |

The installer **auto-detects your device** and downloads the right ready-made program. If there is none, it builds it for you.

### 🚀 Install (1 command)

```bash
git clone https://github.com/ak4kuro/hostberry-project.git
cd hostberry-project
sudo ./install.sh
```

That's it. When it finishes (it may reboot once), open the panel:

1. Go to **`https://hostberry.local`** (or `https://<your-Pi-IP>`).
2. Your first password is in **`/opt/hostberry/INSTALL_CREDENTIALS.txt`**.
3. Log in as **`admin`** and follow the setup wizard.

> 💡 Faster install (skips VPN/ad-blocker extras): `HOSTBERRY_FAST_INSTALL=1 sudo ./install.sh`

### 🔄 Update / ❌ Uninstall

```bash
sudo ./install.sh --update     # update (keeps your data)
sudo ./install.sh --remove     # uninstall
```

Updates keep a backup of the previous version and roll back automatically if the new one fails to start.

### 📄 License

**GNU General Public License v3.0 (GPL-3.0)** — free software: you can use, study, modify and share it. If you distribute it (modified or not), you **must** keep it open and release your source under the same GPL-3.0 license, preserving the original copyright notices. See [LICENSE](LICENSE).

### ✍️ Author

Created and maintained by **HostBerry-project**. Please keep the attribution.

---

## 🇪🇸 Español

### ¿Qué es HostBerry?

HostBerry se instala en tu Raspberry Pi y te da un panel web sencillo para:

- 📶 **Compartir internet** — tu Pi se convierte en un punto de acceso WiFi (AP) y a la vez se conecta a otra WiFi o cable.
- 🛡️ **Bloquear anuncios** en toda la red (Blocky DNS).
- 🔒 **VPN** — OpenVPN y WireGuard.
- 🧅 Salida por **Tor**.
- 🔥 **Cortafuegos** con reglas fáciles.
- 📊 **Monitorizar** sistema y red, y hacer test de velocidad.

Todo desde una página web limpia y segura (HTTPS). No necesitas usar la terminal después de instalar.

### ✅ Dispositivos compatibles

| Dispositivo | ¿Funciona? |
|---|---|
| Raspberry Pi 3 / 4 / 5 (SO de 64 bits) | ✅ |
| Raspberry Pi 2 / 3 / 4 (SO de 32 bits) | ✅ |
| Raspberry Pi 1 / Pi Zero | ✅ |
| PC / servidor normal (x86) | ✅ |
| Placas RISC-V | ✅ |

El instalador **detecta tu dispositivo automáticamente** y descarga el programa ya hecho para tu arquitectura. Si no hay ninguno, lo compila por ti.

### 🚀 Instalar (1 comando)

```bash
git clone https://github.com/ak4kuro/hostberry-project.git
cd hostberry-project
sudo ./install.sh
```

Ya está. Cuando termine (puede reiniciar una vez), abre el panel:

1. Entra en **`https://hostberry.local`** (o `https://<IP-de-tu-Pi>`).
2. Tu primera contraseña está en **`/opt/hostberry/INSTALL_CREDENTIALS.txt`**.
3. Accede como **`admin`** y sigue el asistente de configuración.

> 💡 Instalación rápida (omite VPN/bloqueador de anuncios): `HOSTBERRY_FAST_INSTALL=1 sudo ./install.sh`

### 🔄 Actualizar / ❌ Desinstalar

```bash
sudo ./install.sh --update     # actualizar (conserva tus datos)
sudo ./install.sh --remove     # desinstalar
```

Las actualizaciones guardan una copia de la versión anterior y la restauran automáticamente si la nueva no arranca.

### 📄 Licencia

**Licencia Pública General de GNU v3.0 (GPL-3.0)** — software libre: puedes usarlo, estudiarlo, modificarlo y compartirlo. Si lo distribuyes (modificado o no), **debes** mantenerlo abierto y publicar tu código fuente bajo la misma licencia GPL-3.0, conservando los avisos de copyright originales. Ver [LICENSE](LICENSE).

### ✍️ Autoría

Creado y mantenido por **HostBerry-project**. Por favor, mantén la atribución.

---

<div align="center">
<sub>Made with 🍓 for the Raspberry Pi community · Hecho con 🍓 para la comunidad Raspberry Pi</sub>
</div>
