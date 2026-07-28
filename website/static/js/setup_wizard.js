(function() {
  const lang = (document.documentElement && document.documentElement.getAttribute('lang')) || document.querySelector('html')?.getAttribute('lang') || 'es';
  const isEn = (lang === 'en');
  function d(enVal, esVal) { return isEn ? enVal : (esVal || enVal); }
  const t = window.HostBerry && window.HostBerry.t ? function(k, fallback) { return HostBerry.t(k, fallback); } : function(_, fallback) { return fallback || _; };
  const showAlert = window.HostBerry && window.HostBerry.showAlert ? function(type, msg) { HostBerry.showAlert(type, msg); } : function(type, msg) { if (window.showAlert) window.showAlert(type || 'info', msg); else alert(msg); };
  const apiRequest = window.HostBerry && window.HostBerry.apiRequest ? function(u, o) { return HostBerry.apiRequest(u, o); } : function(u, o) { return fetch(u, Object.assign({ credentials: 'include' }, o)); };

  let selectedSSID = null;
  let selectedSecurity = null; // seguridad de la red seleccionada (OPEN/WPA2/WPA3)
  let currentConnectedSSID = null; // SSID al que está conectado el dispositivo (desde wifi/status)
  let wizardStep = 1;
  let selectedSecurityOption = null; // 'vpn' | 'wireguard' | 'tor'
  let selectedBand = null; // banda elegida en el paso 2 ('2.4' | '5')
  let selectedConnectionType = null; // 'cable' | 'wifi' elegido en el paso 1

  // Información del entorno WiFi/AP detectada por el backend (interfaz STA, AP concurrente,
  // soporte CSA, país y canal de la WiFi ya conectada). Sirve para no hardcodear valores.
  var setupInfo = {
    interface: 'wlan0',
    concurrent: false,
    csaSupported: true,
    country: 'ES',
    band: '2.4',
    scanBand: '2.4',
    defaultApChannel: 6,
    connectedChannel: null,
    deferred: true // durante el asistente la conexión WiFi se difiere al final (no se conecta en vivo)
  };
  var setupInfoLoaded = false;

  async function fetchSetupInfo() {
    try {
      var resp = await apiRequest('/api/v1/wifi/setup-info', { method: 'GET' });
      if (resp && resp.ok) {
        var data = await resp.json().catch(function() { return {}; });
        if (data.interface) setupInfo.interface = data.interface;
        setupInfo.concurrent = !!data.concurrent_ap;
        setupInfo.csaSupported = data.csa_supported !== false;
        if (data.country) setupInfo.country = String(data.country).toUpperCase();
        setupInfo.connectedChannel = (data.channel && Number(data.channel) > 0) ? Number(data.channel) : null;
        if (data.band) setupInfo.band = String(data.band);
        // deferred_band=true ⇒ estamos en el asistente: la conexión WiFi (STA) NO se aplica en vivo,
        // se guarda y se conecta al reiniciar tras finalizar. Esto cambia cómo tratamos los errores.
        setupInfo.deferred = (data.deferred_band === true);
        if (data.scan_band) setupInfo.scanBand = String(data.scan_band);
        else if (data.deferred_band) setupInfo.scanBand = '2.4';
        if (data.preferred_band) setupInfo.band = String(data.preferred_band);
        if (data.default_ap_channel && Number(data.default_ap_channel) > 0) {
          setupInfo.defaultApChannel = Number(data.default_ap_channel);
        }
        setupInfoLoaded = true;
      }
    } catch (e) {}
    applySetupInfoToUI();
  }

  function bandLabel(band) {
    return band === '5' ? d('5 GHz', '5 GHz') : d('2.4 GHz', '2.4 GHz');
  }

  function updateBandCardSelection(band) {
    document.querySelectorAll('.wizard-band-card').forEach(function(card) {
      var cardBand = card.getAttribute('data-band');
      var selected = cardBand === band;
      card.classList.toggle('selected', selected);
      card.setAttribute('aria-pressed', selected ? 'true' : 'false');
    });
  }

  function setBandCardsDisabled(disabled) {
    document.querySelectorAll('.wizard-band-card').forEach(function(card) {
      card.classList.toggle('disabled', !!disabled);
    });
  }

  function applySetupInfoToUI() {
    // Aviso de banda activa y advertencia de CSA solo en modo AP+STA (radio única).
    var bandNotice = document.getElementById('wizard-band-notice');
    if (bandNotice) {
      var noticeSpan = bandNotice.querySelector('span:last-child');
      if (noticeSpan) {
        var scanBand = setupInfo.scanBand || '2.4';
        var preferred = setupInfo.band || '2.4';
        if (preferred !== scanBand) {
          noticeSpan.textContent = t('setup_wizard.band_notice_deferred', d(
            'During setup only {scan} networks are shown. Your choice ({preferred}) will apply after the device reboots at the end of the wizard.',
            'Durante la configuración solo se muestran redes de {scan}. Tu elección ({preferred}) se aplicará al reiniciar al final del asistente.'
          )).replace('{scan}', bandLabel(scanBand)).replace('{preferred}', bandLabel(preferred));
        } else {
          noticeSpan.textContent = t('setup_wizard.band_notice', d(
            'Showing {band} networks. Your chosen band applies to the device after it reboots at the end of the wizard.',
            'Mostrando redes de {band}. La banda elegida se aplicará al equipo al reiniciar tras finalizar el asistente.'
          )).replace('{band}', bandLabel(scanBand));
        }
      }
      bandNotice.classList.toggle('d-none', !setupInfo.concurrent);
    }
    var csaWarning = document.getElementById('wizard-csa-warning');
    if (csaWarning) csaWarning.classList.toggle('d-none', !(setupInfo.concurrent && !setupInfo.csaSupported));

    // País detectado por defecto en el selector.
    var countrySel = document.getElementById('wizard-country');
    if (countrySel && setupInfo.country) {
      var found = Array.prototype.some.call(countrySel.options, function(o) { return o.value === setupInfo.country; });
      if (!found) {
        var opt = document.createElement('option');
        opt.value = setupInfo.country;
        opt.textContent = setupInfo.country;
        countrySel.appendChild(opt);
      }
      countrySel.value = setupInfo.country;
    }

    // Paso 1: solo marcamos una tarjeta cuando el usuario elige (no pre-seleccionamos banda).
    if (selectedBand) {
      updateBandCardSelection(selectedBand);
      var bandNextBtn = document.getElementById('wizard-band-next');
      if (bandNextBtn) bandNextBtn.disabled = false;
    }

    updateApChannelNote();
    updateHostapdBandUI();
    updateBandStepTexts();
  }

  // updateBandStepTexts adapta el paso 2 al tipo de conexión: por WiFi la banda elegida decide en
  // qué frecuencia se buscan las redes upstream; por cable solo define la banda del AP HostBerry.
  function updateBandStepTexts() {
    var isCable = selectedConnectionType === 'cable';
    var titleEl = document.getElementById('wizard-band-step-title');
    var descEl = document.getElementById('wizard-band-step-desc');
    var helpEl = document.getElementById('wizard-band-step-help');
    if (titleEl) {
      titleEl.textContent = isCable
        ? t('setup_wizard.step_band_title_ap', d('Choose the HostBerry network band', 'Elegir banda de la red HostBerry'))
        : t('setup_wizard.step_band_title', d('Choose WiFi band', 'Elegir banda WiFi'));
    }
    if (descEl) {
      descEl.textContent = isCable
        ? t('setup_wizard.step_band_desc_ap', d('Select the band your HostBerry will broadcast on (2.4 GHz or 5 GHz).', 'Selecciona la banda en la que emitirá tu HostBerry (2.4 GHz o 5 GHz).'))
        : t('setup_wizard.step_band_desc', d('Select the WiFi band you want to use. We will then look for networks on that frequency.', 'Selecciona la banda WiFi que quieres usar. Luego buscaremos las redes de esa frecuencia.'));
    }
    if (helpEl) {
      helpEl.textContent = isCable
        ? t('setup_wizard.band_select_help_ap', d('The chosen band applies to the HostBerry access point after the device reboots at the end of the wizard.', 'La banda elegida se aplicará al punto de acceso HostBerry al reiniciar al final del asistente.'))
        : t('setup_wizard.band_select_help', d('During setup the AP stays on 2.4 GHz so your connection is not dropped. The chosen band applies after the reboot at the end of the wizard.', 'Durante la configuración el AP usa 2.4 GHz para que no se corte tu conexión. La banda elegida se aplicará al reiniciar al final del asistente.'));
    }
  }

  // channelsForBand devuelve los canales válidos del AP en cada banda: 1-13 en 2.4 GHz y los
  // canales estándar de 5 GHz.
  function channelsForBand(band) {
    if (band === '5') return [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165];
    return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
  }

  function defaultChannelForBand(band) {
    var connCh = setupInfo.connectedChannel;
    var connBand = connCh ? (connCh > 14 ? '5' : '2.4') : null;
    if (connCh && connBand === band && channelsForBand(band).indexOf(connCh) >= 0) return connCh;
    var def = Number(setupInfo.defaultApChannel);
    if (band === '5') return (def >= 36 && channelsForBand('5').indexOf(def) >= 0) ? def : 36;
    return (def >= 1 && def <= 13) ? def : 6;
  }

  // fillApChannelOptions rellena el selector de canal del paso 4 con los canales de la banda
  // elegida y mantiene la elección del usuario si sigue siendo válida.
  function fillApChannelOptions() {
    var select = document.getElementById('wizard-ap-channel');
    if (!select) return;
    var band = setupInfo.band === '5' ? '5' : '2.4';
    var channels = channelsForBand(band);
    var previous = Number(select.value);
    select.innerHTML = '';
    channels.forEach(function(ch) {
      var opt = document.createElement('option');
      opt.value = String(ch);
      opt.textContent = t('setup_wizard.network_channel', d('Ch {channel}', 'Canal {channel}')).replace('{channel}', ch);
      select.appendChild(opt);
    });
    var target = (select.dataset.userEdited && channels.indexOf(previous) >= 0) ? previous : defaultChannelForBand(band);
    select.value = String(target);
    var help = document.getElementById('wizard-ap-channel-help');
    if (help) {
      help.textContent = band === '5'
        ? t('setup_wizard.ap_channel_help_5', d('5 GHz channels (36-165).', 'Canales de 5 GHz (36-165).'))
        : t('setup_wizard.ap_channel_help_24', d('2.4 GHz channels (1-13).', 'Canales de 2.4 GHz (1-13).'));
    }
  }

  function getSelectedApChannel() {
    var band = setupInfo.band === '5' ? '5' : '2.4';
    var select = document.getElementById('wizard-ap-channel');
    var ch = select ? Number(select.value) : NaN;
    if (channelsForBand(band).indexOf(ch) >= 0) return ch;
    return defaultChannelForBand(band);
  }

  // updateHostapdBandUI ajusta el campo SSID y la ayuda del paso 3 según la banda elegida:
  // "hostberry" para 2.4 GHz y "hostberry-5G" para 5 GHz (campo único).
  function updateHostapdBandUI() {
    var band = setupInfo.band === '5' ? '5' : '2.4';
    var ssidInput = document.getElementById('wizard-ap-ssid');
    if (ssidInput && !ssidInput.dataset.userEdited) {
      ssidInput.value = band === '5' ? 'hostberry-5G' : 'hostberry';
      ssidInput.placeholder = band === '5' ? 'hostberry-5G' : 'hostberry';
    }
    var help = document.getElementById('wizard-ap-ssid-help');
    if (help) {
      help.textContent = band === '5'
        ? t('setup_wizard.ssid_5_help_single', d('5 GHz network (broadcast by your HostBerry)', 'Red 5 GHz (la que emite tu HostBerry)'))
        : t('setup_wizard.ssid_24_help_single', d('2.4 GHz network (broadcast by your HostBerry)', 'Red 2.4 GHz (la que emite tu HostBerry)'));
    }
  }

  // applyBand mueve el AP "hostberry" a la banda elegida (2.4/5 GHz) y vuelve a escanear. En radio
  // única, cambiar la banda del AP cambia la banda en la que se ven y conectan las redes.
  async function applyBand(band) {
    if (!band || (band !== '2.4' && band !== '5')) return;
    var previousBand = setupInfo.band === '5' ? '5' : '2.4';
    setBandCardsDisabled(true);
    var grid = document.getElementById('wizard-networks-grid');
    if (grid) {
      grid.innerHTML = '<p class="wizard-networks-empty text-muted"><i class="bi bi-arrow-clockwise spinning me-2"></i>' +
        t('setup_wizard.switching_band', d('Switching band...', 'Cambiando de banda...')) + '</p>';
    }
    try {
      var resp = await apiRequest('/api/v1/wifi/setup-band', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ band: band })
      });
      var data = {};
      if (resp) data = await resp.json().catch(function() { return {}; });
      var actualBand = (data && data.band) ? String(data.band) : band;
      if (resp && resp.ok && data && data.success) {
        setupInfo.band = actualBand;
        if (data.scan_band) setupInfo.scanBand = String(data.scan_band);
        if (data.channel) setupInfo.defaultApChannel = Number(data.channel);
        applySetupInfoToUI();
        if (data.deferred) {
          // Radio única: forzar un escaneo activo de la otra banda (p. ej. 5 GHz con el AP en 2.4)
          // abandona el canal del portal y desconecta a los clientes. Usamos la caché (que el sistema
          // refresca en segundo plano); si está vacía, el backend escanea una sola vez. El botón
          // "Buscar redes" sigue forzando un escaneo si el usuario lo pide expresamente.
          await scanNetworks(false);
          return;
        }
        await new Promise(function(res) { setTimeout(res, actualBand === '5' ? 3000 : 1500); });
        await scanNetworks(true);
        return;
      }
      if (data && data.band) {
        setupInfo.band = actualBand;
        updateBandCardSelection(actualBand);
        applySetupInfoToUI();
      } else {
        updateBandCardSelection(previousBand);
      }
      showAlert('warning', (data && data.error) ? data.error : t('setup_wizard.error_band', d('Could not switch band', 'No se pudo cambiar de banda')));
      if (data && data.band) {
        await scanNetworks(true);
      } else {
        fillNetworksList([]);
      }
    } catch (e) {
      updateBandCardSelection(previousBand);
      showAlert('danger', t('setup_wizard.error_band', d('Could not switch band', 'No se pudo cambiar de banda')));
      fillNetworksList([]);
    } finally {
      setBandCardsDisabled(false);
    }
  }

  function updateApChannelNote() {
    var note = document.getElementById('wizard-ap-channel-note');
    if (!note) return;
    var span = note.querySelector('span');
    if (!setupInfo.concurrent) { note.classList.add('d-none'); return; }
    var band = setupInfo.band === '5' ? '5' : '2.4';
    // El canal del AP debe corresponder a la banda elegida. Solo reutilizamos el canal de la WiFi
    // conectada si pertenece a la MISMA banda (un canal 2.4 GHz no aplica si se eligió 5 GHz).
    var connCh = setupInfo.connectedChannel;
    var connBand = connCh ? (connCh > 14 ? '5' : '2.4') : null;
    var msg;
    if (connCh && connBand === band) {
      msg = t('setup_wizard.ap_channel_note', d('Channel: {channel} (same as your WiFi)', 'Canal: {channel} (igual que tu WiFi)')).replace('{channel}', connCh);
    } else {
      var defCh;
      if (band === '5') {
        defCh = (setupInfo.defaultApChannel && setupInfo.defaultApChannel > 14) ? setupInfo.defaultApChannel : 36;
      } else {
        defCh = (setupInfo.defaultApChannel && setupInfo.defaultApChannel <= 14) ? setupInfo.defaultApChannel : 6;
      }
      msg = t('setup_wizard.ap_channel_note_default', d(
        'Channel: {channel} (default on {band}, no WiFi connected)',
        'Canal: {channel} (por defecto en {band}, sin WiFi conectada)'
      )).replace('{channel}', defCh).replace('{band}', bandLabel(band));
    }
    if (span) span.textContent = msg;
    note.classList.remove('d-none');
  }

  function setStep(step) {
    wizardStep = step;
    document.querySelectorAll('.setup-step').forEach(function(el) {
      el.classList.toggle('d-none', parseInt(el.getAttribute('data-step'), 10) !== step);
    });
    document.querySelectorAll('.step-dot').forEach(function(el) {
      el.classList.toggle('active', parseInt(el.getAttribute('data-step'), 10) === step);
    });

    // Mostrar/ocultar step dots según el tipo de conexión
    updateStepIndicators();

    // En el paso 3 (conectar WiFi), refrescar periódicamente el estado WiFi
    // para mantener actualizado el banner y la red marcada como conectada.
    if (step === 3) {
      if (!window.__hbWizardWifiTimer) {
        window.__hbWizardWifiTimer = setInterval(function() {
          fetchWifiStatus();
        }, 10000);
      }
    } else if (window.__hbWizardWifiTimer) {
      clearInterval(window.__hbWizardWifiTimer);
      window.__hbWizardWifiTimer = null;
    }

    // Al entrar en el paso 4 (config hostapd), ajustar SSID/ayuda y canal según la banda elegida.
    if (step === 4) {
      updateHostapdBandUI();
      updateApChannelNote();
      fillApChannelOptions();
    }
  }

  function updateStepIndicators() {
    // Si es cable, ocultar pasos 2 y 3 (banda y WiFi)
    // Si es WiFi, mostrar todos los pasos
    const isCable = selectedConnectionType === 'cable';
    document.querySelectorAll('.step-dot').forEach(function(el) {
      const stepNum = parseInt(el.getAttribute('data-step'), 10);
      if (isCable) {
        // Cable: pasos 1, 2 (banda del AP), 4 y 5 visibles; se omite el paso 3 (conectar WiFi).
        if (stepNum === 3) {
          el.classList.add('d-none');
          el.nextElementSibling && el.nextElementSibling.classList.contains('step-line') && el.nextElementSibling.classList.add('d-none');
        } else {
          el.classList.remove('d-none');
          el.nextElementSibling && el.nextElementSibling.classList.contains('step-line') && el.nextElementSibling.classList.remove('d-none');
        }
      } else {
        // WiFi: todos los pasos visibles
        el.classList.remove('d-none');
        el.nextElementSibling && el.nextElementSibling.classList.contains('step-line') && el.nextElementSibling.classList.remove('d-none');
      }
    });
  }

  function signalBars(signal) {
    if (signal == null || signal === '') return '';
    var n = Number(signal);
    if (isNaN(n)) return '';
    if (n >= -50) return '4'; // 4 barras
    if (n >= -60) return '3';
    if (n >= -70) return '2';
    if (n >= -80) return '1';
    return '0';
  }

  // signalDistanceLabel traduce la intensidad de señal (dBm) en una proximidad aproximada.
  function signalDistanceLabel(signal) {
    if (signal == null || signal === '') return '';
    var n = Number(signal);
    if (isNaN(n)) return '';
    if (n >= -50) return t('setup_wizard.dist_very_close', d('Very close', 'Muy cerca'));
    if (n >= -60) return t('setup_wizard.dist_close', d('Close', 'Cerca'));
    if (n >= -70) return t('setup_wizard.dist_medium', d('Medium', 'Media'));
    if (n >= -80) return t('setup_wizard.dist_far', d('Far', 'Lejos'));
    return t('setup_wizard.dist_very_far', d('Very far', 'Muy lejos'));
  }

  function fillNetworksList(networks) {
    const grid = document.getElementById('wizard-networks-grid');
    if (!grid) return;
    grid.innerHTML = '';
    if (!Array.isArray(networks) || networks.length === 0) {
      grid.innerHTML = '<p class="wizard-networks-empty text-muted">' + t('setup_wizard.select_network', d('Select a network', 'Selecciona una red')) + '</p>';
      return;
    }
    networks = networks.slice().sort(function(a, b) {
      var sigA = a.signal != null ? Number(a.signal) : (a.signal_strength != null ? Number(a.signal_strength) : -999);
      var sigB = b.signal != null ? Number(b.signal) : (b.signal_strength != null ? Number(b.signal_strength) : -999);
      if (isNaN(sigA)) sigA = -999;
      if (isNaN(sigB)) sigB = -999;
      return sigB - sigA;
    });
    var escapeHtml = window.HostBerry && HostBerry.escapeHtml ? function(s) { return HostBerry.escapeHtml(s); } : function(s) { return s; };
    networks.forEach(function(net) {
      const ssid = net.ssid || net.SSID || '';
      if (!ssid) return;
      const isConnected = currentConnectedSSID && ssid === currentConnectedSSID;
      const signal = net.signal != null ? net.signal : net.signal_strength;
      const bars = signalBars(signal);
      const security = (net.security || '').toString().toUpperCase();
      var secLabel = '';
      if (security === 'WPA3') {
        secLabel = d('WPA3', 'WPA3');
      } else if (security === 'WPA2' || security === 'WPA') {
        secLabel = d('WPA2', 'WPA2');
      } else if (security === 'OPEN') {
        secLabel = d('Open', 'Abierta');
      }
      const channel = (net.channel != null && Number(net.channel) > 0) ? Number(net.channel) : null;
      var channelLabel = channel ? t('setup_wizard.network_channel', d('Ch {channel}', 'Canal {channel}')).replace('{channel}', channel) : '';
      var isSecured = security && security !== 'OPEN';
      var iconClass = 'bi-wifi';
      if (bars === '0') iconClass = 'bi-wifi-off';
      else if (bars === '1') iconClass = 'bi-wifi-1';
      else if (bars === '2') iconClass = 'bi-wifi-2';
      const card = document.createElement('button');
      card.type = 'button';
      card.className = 'wizard-network-card' + (isConnected ? ' wizard-network-connected' : '');
      card.dataset.ssid = ssid;
      card.dataset.security = security || '';
      if (channel) card.dataset.channel = channel;
      card.title = ssid;
      var distLabel = signalDistanceLabel(signal);
      card.innerHTML =
        (isSecured ? '<i class="bi bi-lock-fill wizard-network-lock"></i>' : '') +
        '<i class="bi bi-check-lg wizard-network-check"></i>' +
        '<span class="wizard-network-icon"><i class="bi ' + iconClass + '"></i></span>' +
        '<span class="wizard-network-ssid">' + escapeHtml(ssid) + '</span>' +
        (distLabel ? '<span class="wizard-network-dist">' + escapeHtml(distLabel) + '</span>' : '');
      card.addEventListener('click', function() {
        selectedSSID = ssid;
        selectedSecurity = (card.dataset.security || '').toUpperCase();
        grid.querySelectorAll('.wizard-network-card').forEach(function(c) { c.classList.remove('selected'); });
        card.classList.add('selected');
        var pwdBox = document.getElementById('wizard-wifi-password-box');
        var pwdInput = document.getElementById('wizard-wifi-password');
        var sec = (card.dataset.security || '').toUpperCase();
        // Mostramos SIEMPRE el campo de contraseña. La detección de seguridad del escaneo no es
        // fiable (algunas redes WPA2/WPA3 aparecen como "Open"); si lo ocultáramos, el usuario no
        // podría introducir su clave y la red se guardaría abierta y no conectaría tras reiniciar.
        // Para redes detectadas como abiertas dejamos la contraseña como opcional.
        if (pwdBox) pwdBox.classList.remove('d-none');
        if (pwdInput) {
          pwdInput.value = '';
          pwdInput.placeholder = (sec === 'OPEN')
            ? d('WiFi password (leave empty if the network is open)', 'Contraseña WiFi (déjalo vacío si la red es abierta)')
            : d('WiFi password', 'Contraseña WiFi');
          pwdInput.focus();
        }
      });
      grid.appendChild(card);
    });
  }

  function setupPasswordToggle(inputId, toggleBtnId) {
    var input = document.getElementById(inputId);
    var btn = document.getElementById(toggleBtnId);
    if (!input || !btn) return;
    var icon = btn.querySelector('i.bi');
    var showLabel = t('setup_wizard.show_password', d('Show password', 'Ver contraseña'));
    var hideLabel = t('setup_wizard.hide_password', d('Hide password', 'Ocultar contraseña'));
    btn.addEventListener('click', function() {
      if (input.type === 'password') {
        input.type = 'text';
        btn.title = hideLabel;
        btn.setAttribute('aria-label', hideLabel);
        if (icon) { icon.classList.remove('bi-eye'); icon.classList.add('bi-eye-slash'); }
      } else {
        input.type = 'password';
        btn.title = showLabel;
        btn.setAttribute('aria-label', showLabel);
        if (icon) { icon.classList.remove('bi-eye-slash'); icon.classList.add('bi-eye'); }
      }
    });
  }

  function showCurrentWifiBanner(ssid, connectionType) {
    var banner = document.getElementById('wizard-current-wifi-banner');
    var textEl = document.getElementById('wizard-current-wifi-text');
    var iconWrap = banner && banner.querySelector('.wizard-connection-icon');
    if (!banner || !textEl) return;
    currentConnectedSSID = ssid || null;
    var msg;
    if (connectionType === 'ethernet') {
      msg = t('setup_wizard.connected_via_cable', d('Connected via cable (Ethernet)', 'Conectado por cable (Ethernet)'));
      if (iconWrap) { iconWrap.innerHTML = '<i class="bi bi-ethernet me-2"></i>'; }
    } else {
      var wifiLabel = t('setup_wizard.connection_type_wifi', d('WiFi', 'WiFi'));
      var part = t('setup_wizard.connected_to_wifi', d('Connected to', 'Conectado a'));
      msg = (ssid ? part + ' ' + ssid + ' (' + wifiLabel + ')' : part + ' ' + wifiLabel).trim();
      if (iconWrap) { iconWrap.innerHTML = '<i class="bi bi-wifi me-2"></i>'; }
    }
    textEl.textContent = msg;
    banner.classList.remove('d-none');
    window.HostBerry&&window.HostBerry.setVisible(banner, true);
    if (window.HostBerry && HostBerry.attachTransientAlert) {
      HostBerry.attachTransientAlert(banner);
    }
  }

  function hideCurrentWifiBanner() {
    var banner = document.getElementById('wizard-current-wifi-banner');
    if (banner) {
      if (window.HostBerry && HostBerry.dismissTransientAlert) {
        HostBerry.dismissTransientAlert(banner);
      }
      banner.classList.add('d-none');
    }
    currentConnectedSSID = null;
  }

  async function fetchWifiStatus() {
    try {
      var resp = await apiRequest('/api/v1/wifi/status', { method: 'GET' });
      if (!resp || !resp.ok) return;
      var data = await resp.json().catch(function() { return {}; });
      var ssid = data.ssid || data.current_connection || '';
      var connectionType = data.connection_type || '';
      if (connectionType === 'ethernet') {
        showCurrentWifiBanner(null, 'ethernet');
      } else if (ssid) {
        // Si tenemos SSID, mostramos la conexión por WiFi aunque el backend marque connected=false
        // (evita que no se muestre la red actual cuando el escaneo falla).
        showCurrentWifiBanner(ssid, 'wifi');
      } else if (data.connected) {
        // Conectado pero sin SSID detectado: mostramos WiFi genérico para que el usuario pueda continuar.
        showCurrentWifiBanner(null, 'wifi');
      }
    } catch (e) {}
  }

  async function scanNetworks(forceRefresh) {
    const btn = document.getElementById('wizard-scan-btn');
    const grid = document.getElementById('wizard-networks-grid');
    if (grid) {
      grid.innerHTML = '<p class="wizard-networks-empty text-muted"><i class="bi bi-arrow-clockwise spinning me-2"></i>' +
        t('setup_wizard.scanning', d('Scanning...', 'Escaneando...')) + '</p>';
    }
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="bi bi-arrow-clockwise spinning me-2"></i>' + t('setup_wizard.scanning', d('Scanning...', 'Escaneando...'));
    }
    try {
      var params = new URLSearchParams();
      if (forceRefresh) params.set('refresh', '1');
      // Solo fijamos la interfaz si ya la detectó setup-info; si no, dejamos que el backend
      // autodetecte (evita escanear una interfaz equivocada en la primera carga).
      if (setupInfoLoaded && setupInfo.interface) params.set('interface', setupInfo.interface);
      // Banda elegida en el asistente: escanea 2.4 o 5 GHz según la tarjeta seleccionada.
      if (setupInfo.scanBand) params.set('band', setupInfo.scanBand);
      var scanUrl = '/api/v1/wifi/scan' + (params.toString() ? ('?' + params.toString()) : '');
      var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
      var timeoutId = controller ? setTimeout(function() { controller.abort(); }, 45000) : null;
      const resp = await apiRequest(scanUrl, { method: 'GET', signal: controller ? controller.signal : undefined });
      if (timeoutId) clearTimeout(timeoutId);
      let data = [];
      if (resp && resp.ok) {
        data = await resp.json().catch(function() { return []; });
      } else {
        var errData = {};
        try { errData = await resp.json(); } catch (_e) {}
        var errMsg = (errData && errData.error) ? String(errData.error) : t('setup_wizard.error_scan', d('Error scanning networks', 'Error al buscar redes'));
        showAlert('danger', errMsg);
        fillNetworksList([]);
        return;
      }
      var networks = Array.isArray(data) ? data : (data.networks || []);
      fillNetworksList(networks);
      if (!networks.length) {
        showAlert('warning', t('setup_wizard.no_networks_found', d('No WiFi networks found. Make sure WiFi is enabled and try again.', 'No se encontraron redes WiFi. Comprueba que el WiFi esté activo e inténtalo de nuevo.')));
      }
    } catch (e) {
      if (e && e.name === 'AbortError') {
        showAlert('warning', t('setup_wizard.error_scan_timeout', d('Scan is taking too long. Try again in a few seconds.', 'El escaneo tarda demasiado. Inténtalo de nuevo en unos segundos.')));
      } else {
        showAlert('danger', t('setup_wizard.error_scan', d('Error scanning networks', 'Error al buscar redes')));
      }
      fillNetworksList([]);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-arrow-clockwise me-2"></i>' + t('setup_wizard.scan_networks', d('Scan networks', 'Buscar redes'));
      }
    }
  }

  function getSelectedCountry() {
    var sel = document.getElementById('wizard-country');
    var c = sel && sel.value ? String(sel.value).toUpperCase() : (setupInfo.country || 'ES');
    return /^[A-Z]{2}$/.test(c) ? c : 'ES';
  }

  // isOpenNetwork: solo consideramos "abierta" (sin contraseña) una red EXPLÍCITAMENTE abierta.
  // Si el escaneo no informó del tipo de seguridad (selectedSecurity vacío/desconocido) asumimos
  // que está protegida y exigimos contraseña: así no se guarda una red WPA sin clave (que luego
  // no conectaría tras reiniciar).
  function isOpenNetwork() {
    var sec = (selectedSecurity || '').toUpperCase();
    return sec === 'OPEN' || sec === 'NONE';
  }

  // securityForBackend: normaliza la seguridad enviada al backend. Para redes protegidas con tipo
  // desconocido enviamos "WPA2" para que el backend exija contraseña en lugar de tratarla como abierta.
  function securityForBackend() {
    // Si el usuario introdujo una contraseña, la red es protegida aunque el escaneo la marcara
    // como abierta: así el backend genera PSK/SAE y la conexión funciona tras reiniciar.
    var pwd = ((document.getElementById('wizard-wifi-password') || {}).value || '').trim();
    if (pwd !== '') {
      var sec = (selectedSecurity || '').toUpperCase();
      if (sec.indexOf('WPA3') >= 0 || sec.indexOf('SAE') >= 0) return 'WPA3';
      return 'WPA2';
    }
    if (isOpenNetwork()) return 'OPEN';
    return selectedSecurity || 'WPA2';
  }

  function validateWifiPassword(password) {
    // Si hay contraseña, validamos su longitud (red protegida WPA2/WPA3: 8-63 caracteres).
    if (password) {
      if (password.length < 8) {
        return t('setup_wizard.wifi_password_too_short', d('The WiFi password must be at least 8 characters.', 'La contraseña WiFi debe tener al menos 8 caracteres.'));
      }
      if (password.length > 63) {
        return t('setup_wizard.wifi_password_too_long', d('The WiFi password must be at most 63 characters.', 'La contraseña WiFi debe tener como máximo 63 caracteres.'));
      }
      return null;
    }
    // Sin contraseña: solo es válido si la red se detectó como abierta.
    if (isOpenNetwork()) return null;
    return t('setup_wizard.wifi_password_required', d('Enter the WiFi password for this network.', 'Introduce la contraseña WiFi de esta red.'));
  }

  // Validación de contraseña con requisitos de seguridad (8 min, 1 mayúscula, 1 símbolo)
  function validateSecurePassword(password, fieldName) {
    if (!password || password.length < 8) {
      return t('setup_wizard.password_too_short', d('The password must be at least 8 characters.', 'La contraseña debe tener al menos 8 caracteres.'));
    }
    if (!/[A-Z]/.test(password)) {
      return t('setup_wizard.password_no_uppercase', d('The password must contain at least one uppercase letter.', 'La contraseña debe contener al menos una mayúscula.'));
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) {
      return t('setup_wizard.password_no_symbol', d('The password must contain at least one special symbol.', 'La contraseña debe contener al menos un símbolo especial.'));
    }
    return null;
  }

  function updateConnectionCardSelection(connectionType) {
    document.querySelectorAll('.wizard-connection-card').forEach(function(card) {
      var cardType = card.getAttribute('data-connection');
      var selected = cardType === connectionType;
      card.classList.toggle('selected', selected);
      card.setAttribute('aria-pressed', selected ? 'true' : 'false');
    });
  }

  function setConnectionCardsDisabled(disabled) {
    document.querySelectorAll('.wizard-connection-card').forEach(function(card) {
      card.classList.toggle('disabled', !!disabled);
    });
  }

  function showConnectResult(data) {
    var box = document.getElementById('wizard-connect-result');
    var ch = data && data.channel ? Number(data.channel) : null;
    var msg;
    if (ch && setupInfo.concurrent && setupInfo.csaSupported) {
      msg = t('setup_wizard.connected_channel_info', d('Connected on channel {channel}. The «hostberry» access point moved to the same channel without dropping your connection.', 'Conectado en el canal {channel}. El punto de acceso «hostberry» se movió al mismo canal sin cortar tu conexión.')).replace('{channel}', ch);
    } else if (ch) {
      msg = t('setup_wizard.connected', d('Connected', 'Conectado')) + ' (' + t('setup_wizard.network_channel', d('Ch {channel}', 'Canal {channel}')).replace('{channel}', ch) + ')';
    } else {
      msg = t('setup_wizard.connected', d('Connected', 'Conectado'));
    }
    if (ch) {
      setupInfo.connectedChannel = ch;
      if (data.frequency && Number(data.frequency) >= 5000) setupInfo.band = '5';
      else if (ch <= 14) setupInfo.band = '2.4';
      updateApChannelNote();
    }
    if (box) { box.textContent = msg; box.classList.remove('d-none'); }
    showAlert('success', t('setup_wizard.connected', d('Connected', 'Conectado')));
    pollNewDeviceIP();
  }

  // showDeferredConnectResult informa de que la red quedó guardada y se conectará al finalizar el
  // asistente (el dispositivo se reinicia al pulsar "Finalizar" y entonces se conecta a esa WiFi).
  function showDeferredConnectResult(ssid) {
    var box = document.getElementById('wizard-connect-result');
    var msg = t('setup_wizard.connect_deferred', d(
      'Password checked. Network «{ssid}» saved — the device will connect to it when you finish the wizard.',
      'Contraseña comprobada. Red «{ssid}» guardada: el equipo se conectará a ella al finalizar el asistente.'
    )).replace('{ssid}', ssid || '');
    if (box) { box.textContent = msg; box.classList.remove('d-none'); }
    showAlert('success', msg);
  }

  async function pollNewDeviceIP() {
    var box = document.getElementById('wizard-connect-result');
    for (var i = 0; i < 10; i++) {
      try {
        var r = await apiRequest('/api/v1/wifi/status', { method: 'GET' });
        if (r && r.ok) {
          var s = await r.json().catch(function() { return {}; });
          var ip = (s && s.connection_info && s.connection_info.ip) ? s.connection_info.ip : '';
          if (ip && !/^169\.254/.test(ip)) {
            if (box && box.textContent.indexOf(ip) === -1) {
              var ipMsg = t('setup_wizard.new_ip_detected', d('HostBerry detected at {ip}', 'HostBerry detectado en {ip}')).replace('{ip}', ip);
              box.textContent = box.textContent + ' — ' + ipMsg;
            }
            return;
          }
        }
      } catch (_) {}
      await new Promise(function(res) { setTimeout(res, 2500); });
    }
  }

  async function connectWiFi() {
    if (!selectedSSID) return;
    const password = (document.getElementById('wizard-wifi-password') || {}).value || '';
    var pwdError = validateWifiPassword(password);
    if (pwdError) { showAlert('warning', pwdError); return; }
    const connectBtn = document.getElementById('wizard-connect-btn');
    const btnText = connectBtn && connectBtn.querySelector('.btn-text');
    if (connectBtn) {
      connectBtn.disabled = true;
      // Durante el asistente NO se conecta aquí: solo se valida la clave y se guarda la red. La
      // conexión real ocurre al finalizar (al reiniciar). Por eso el botón "comprueba", no "conecta".
      if (btnText) btnText.textContent = t('setup_wizard.checking', d('Checking...', 'Comprobando...'));
    }
    var timeoutId;
    var timeoutMs = 90000; // 90 s: el backend puede tardar hasta ~80 s (WPA + DHCP)
    var connectPromise = apiRequest('/api/v1/wifi/connect', {
      method: 'POST',
      body: {
        ssid: selectedSSID,
        password: password,
        country: getSelectedCountry(),
        interface: setupInfo.interface,
        band: setupInfo.band || setupInfo.scanBand || selectedBand || '2.4',
        security: securityForBackend()
      }
    });
    var timeoutPromise = new Promise(function(_, reject) {
      timeoutId = setTimeout(function() {
        var msg = t(
          'setup_wizard.error_connect_timeout',
          d(
            'Connection is taking too long. If the password is correct, wait 1-2 minutes and open the panel again (the device may have connected and have a new IP).',
            'La conexión tarda más de lo esperado. Si la contraseña es correcta, espera 1-2 minutos y abre de nuevo el panel (el dispositivo puede haberse conectado y tener otra IP).'
          )
        );
        reject(new Error(msg));
      }, timeoutMs);
    });
    try {
      const resp = await Promise.race([connectPromise, timeoutPromise]);
      clearTimeout(timeoutId);
      const data = await resp.json().catch(function() { return {}; });
      if (resp.ok && data.success !== false) {
        // Durante el asistente la conexión se difiere a "Finalizar": el backend solo guarda la red.
        if (data.deferred) {
          showDeferredConnectResult(selectedSSID);
        } else {
          showConnectResult(data);
        }
        setStep(4);
      } else {
        // El cuerpo ya se leyó en `data`; usamos su error (no se puede volver a leer resp.json()).
        var errMsg = (data && data.error) ? String(data.error) : t('setup_wizard.error_connect', d('Error connecting', 'Error al conectar'));
        if (resp && resp.status === 423) {
          errMsg = t('setup_wizard.error_connect_busy', d('Connection already in progress. Wait a moment and try again.', 'Ya hay una conexión en curso. Espera un momento e inténtalo de nuevo.'));
        }
        showAlert('danger', errMsg);
      }
    } catch (e) {
      clearTimeout(timeoutId);
      var msg = e && e.message ? e.message : t('setup_wizard.error_connect', d('Error connecting', 'Error al conectar'));
      var isNetworkError = (e && (e.name === 'TypeError' || e.message === 'Failed to fetch' || (typeof e.message === 'string' && (e.message.indexOf('fetch') !== -1 || e.message.indexOf('NetworkError') !== -1))));
      // Durante el asistente la conexión está DIFERIDA: el equipo NO se conecta ahora ni cambia de
      // IP. Si el fetch falla aquí es porque el WiFi del HostBerry se cortó un instante (radio única:
      // al ver redes de 5 GHz la antena abandona el canal 2.4 del portal). NO tiene sentido hablar de
      // "nueva IP" ni sondear una conexión que no ocurre: solo hay que reconectarse al AP y reintentar.
      if (isNetworkError && setupInfo.deferred) {
        showAlert('warning', t('setup_wizard.error_deferred_ap_dropped', d(
          'The HostBerry WiFi dropped for a moment (single radio: scanning 5 GHz leaves the 2.4 GHz portal channel). Reconnect to the «hostberry» network and press «Check and continue» again — nothing was applied yet.',
          'El WiFi del HostBerry se cortó un momento (radio única: al buscar redes de 5 GHz la antena deja el canal 2.4 del portal). Reconéctate a la red «hostberry» y pulsa «Comprobar y continuar» otra vez — todavía no se ha aplicado nada.'
        )));
        return;
      }
      if (isNetworkError) {
        if (selectedSSID) {
          msg = (t('setup_wizard.error_network_device_switching_ssid', d('The connection may have succeeded to «{ssid}». Wait about 30 seconds and open the panel again (the HostBerry may have a new IP on your WiFi).', 'La conexión puede haberse completado a «{ssid}». Espera unos 30 segundos y abre de nuevo el panel (el HostBerry puede tener una nueva IP en tu WiFi).')).replace(/\{ssid\}/g, selectedSSID));
        } else {
          msg = t('setup_wizard.error_network_device_switching', d('The connection may have succeeded, but the device is switching networks. Wait about 30 seconds and open the panel again (the HostBerry may have a new IP on your WiFi).', 'La conexión puede haberse completado, pero el dispositivo está cambiando de red. Espera unos 30 segundos y abre de nuevo el panel (el HostBerry puede tener una nueva IP en tu WiFi).'));
        }
        showAlert('warning', msg);

        // Verificación automática: aunque el fetch falle, la conexión puede haberse completado.
        // Intentamos consultar el estado durante un rato y avanzar si ya está conectado al SSID esperado.
        (async function verifyConnectionAfterSwitch() {
          var startTs = Date.now();
          var maxWaitMs = 120000; // 2 min
          var pollEveryMs = 3000;
          function normSSID(x) {
            try {
              return String(x || '')
                .replace(/^"+|"+$/g, '')
                .trim()
                .toLowerCase();
            } catch (_) {
              return '';
            }
          }

          while (Date.now() - startTs < maxWaitMs) {
            try {
              var r = await apiRequest('/api/v1/wifi/status', { method: 'GET' });
              if (r && r.ok) {
                var s = await r.json().catch(function() { return {}; });
                if (s && s.connection_type === 'ethernet') {
                  showAlert('success', t('setup_wizard.connected', d('Connected', 'Conectado')));
                  setStep(4);
                  return;
                }
                // WiFi: algunos firmwares/devices devuelven comillas o cambian el formato del SSID.
                // Validamos por SSID normalizado y confirmamos conexión real si existe.
                // Fallback: si ya estamos conectados por WiFi pero el backend no devuelve SSID,
                // igualmente avanzamos para que el wizard no se quede atascado.
                if (s && s.connection_type === 'wifi' && (s.connected === true || s.connected === undefined)) {
                  showAlert('success', t('setup_wizard.connected', d('Connected', 'Conectado')));
                  setStep(4);
                  return;
                }
                if (selectedSSID && s && normSSID(s.ssid) && normSSID(selectedSSID) === normSSID(s.ssid)) {
                  if (s.connected === true || s.connection_type === 'wifi') {
                    showAlert('success', t('setup_wizard.connected', d('Connected', 'Conectado')));
                    setStep(4);
                    return;
                  }
                }
              }
            } catch (_) {
              // Ignorar: en algunos momentos el hostberry ya cambió IP/red.
            }
            await new Promise(function(res) { setTimeout(res, pollEveryMs); });
          }

          // Si no se confirma conexión, dejamos el aviso original.
        })();
      } else {
        showAlert('danger', msg);
      }
    } finally {
      if (connectBtn) {
        connectBtn.disabled = false;
        if (btnText) btnText.textContent = t('setup_wizard.connect_continue', d('Check and continue', 'Comprobar y continuar'));
      }
    }
  }

  // saveBandPreference guarda la banda elegida sin escanear ni tocar el AP en caliente. Se usa en
  // la ruta por cable, donde la banda solo define la red que emitirá el HostBerry.
  async function saveBandPreference(band) {
    try {
      var resp = await apiRequest('/api/v1/wifi/setup-band', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ band: band })
      });
      var data = resp ? await resp.json().catch(function() { return {}; }) : {};
      if (data && data.channel && Number(data.channel) > 0) setupInfo.defaultApChannel = Number(data.channel);
    } catch (e) {}
  }

  async function saveHostapd() {
    const band = setupInfo.band === '5' ? '5' : '2.4';
    const base = ((document.getElementById('wizard-ap-ssid') || {}).value || '').trim() || (band === '5' ? 'hostberry-5G' : 'hostberry');
    // Campo SSID único: derivamos ambos perfiles (2.4/5) a partir del nombre de la banda elegida.
    var ssid24, ssid5;
    if (band === '5') {
      ssid5 = base;
      ssid24 = base.replace(/-?5g$/i, '') || 'hostberry';
    } else {
      ssid24 = base;
      ssid5 = /-?5g$/i.test(base) ? base : (base + '-5G');
    }
    const password = (document.getElementById('wizard-ap-password') || {}).value.trim();
    const saveBtn = document.getElementById('wizard-next-4');
    // La red HostBerry SIEMPRE lleva contraseña (WPA2/WPA3): obligatoria para continuar.
    // Validación con requisitos de seguridad: 8 min, 1 mayúscula, 1 símbolo
    var pwdError = validateSecurePassword(password, 'hostapd');
    if (pwdError) {
      showAlert('warning', pwdError);
      var pwdInput = document.getElementById('wizard-ap-password');
      if (pwdInput) pwdInput.focus();
      return;
    }
    if (password.length > 63) {
      showAlert('warning', t('setup_wizard.ap_password_too_long', d('The password must be at most 63 characters.', 'La contraseña debe tener como máximo 63 caracteres.')));
      var pwdInput = document.getElementById('wizard-ap-password');
      if (pwdInput) pwdInput.focus();
      return;
    }
    if (saveBtn) {
      saveBtn.disabled = true;
      var btnText = saveBtn.querySelector('.btn-text');
      if (btnText) btnText.textContent = t('common.saving', d('Saving...', 'Guardando...'));
    }
    // El canal elegido corresponde a la banda seleccionada (1-13 en 2.4 GHz, 36-165 en 5 GHz);
    // el perfil de la otra banda conserva su canal por defecto.
    const selectedChannel = getSelectedApChannel();
    const ch24 = band === '2.4' ? selectedChannel : 6;
    const ch5 = band === '5' ? selectedChannel : 36;
    const payload = {
      interface: setupInfo.interface || 'wlan0',
      ssid_24: ssid24,
      ssid_5: ssid5,
      channel_24: ch24,
      channel_5: ch5,
      security: 'wpa2',
      password: password,
      country: getSelectedCountry()
    };
    // Red de seguridad: si por cualquier motivo la petición no responde (p. ej. el AP se
    // reinicia y corta la conexión), abortamos a los 30 s para no dejar "Guardando..." infinito.
    var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var abortTimer = controller ? setTimeout(function() { controller.abort(); }, 30000) : null;
    try {
      const opts = { method: 'POST', body: payload };
      if (controller) opts.signal = controller.signal;
      const resp = await apiRequest('/api/v1/hostapd/dual-band', opts);
      const data = await resp.json().catch(function() { return {}; });
      if (resp.ok && data.success !== false) {
        showAlert('success', t('setup_wizard.success_ap_dual', d('Dual-band access point configured (2.4 GHz and 5 GHz profiles).', 'Punto de acceso dual-band configurado (perfiles 2.4 y 5 GHz).')));
        setStep(5);
      } else {
        showAlert('danger', data.error || t('setup_wizard.error_save_ap', d('Error saving access point configuration', 'Error al guardar la configuración del punto de acceso')));
        if (saveBtn) { saveBtn.disabled = false; var bt = saveBtn.querySelector('.btn-text'); if (bt) bt.textContent = t('setup_wizard.next', d('Next', 'Siguiente')); }
      }
    } catch (e) {
      showAlert('danger', t('setup_wizard.error_save_ap', d('Error saving access point configuration', 'Error al guardar la configuración del punto de acceso')));
      if (saveBtn) { saveBtn.disabled = false; var bt = saveBtn.querySelector('.btn-text'); if (bt) bt.textContent = t('setup_wizard.next', d('Next', 'Siguiente')); }
    } finally {
      if (abortTimer) clearTimeout(abortTimer);
    }
  }

  function setAccountSubmitting(submitting) {
    var btn = document.getElementById('wizard-account-submit');
    if (!btn) return;
    btn.disabled = !!submitting;
    var bt = btn.querySelector('.btn-text');
    if (bt) {
      bt.textContent = submitting
        ? t('common.saving', d('Saving...', 'Guardando...'))
        : t('setup_wizard.finish_wizard', d('Finish', 'Finalizar'));
    }
  }

  // submitAccount valida y guarda las credenciales del primer acceso. Mensajes reales: validación
  // local clara y, si el backend rechaza (longitud, complejidad, usuario en uso...), se muestra su
  // mensaje tal cual (data.error). Tras el éxito, finaliza el asistente (complete + reinicio).
  async function submitAccount(e) {
    if (e && e.preventDefault) e.preventDefault();
    var username = ((document.getElementById('wizard-acc-username') || {}).value || '').trim();
    var password = (document.getElementById('wizard-acc-password') || {}).value || '';
    var confirm = (document.getElementById('wizard-acc-password2') || {}).value || '';

    if (username.length < 3 || username.length > 50) {
      showAlert('warning', t('setup_wizard.acc_username_invalid', d('The username must be between 3 and 50 characters.', 'El usuario debe tener entre 3 y 50 caracteres.')));
      return;
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      showAlert('warning', t('setup_wizard.acc_username_chars', d('The username can only contain letters, numbers and underscores.', 'El usuario solo puede contener letras, números y guiones bajos.')));
      return;
    }
    // Validación con requisitos de seguridad: 8 min, 1 mayúscula, 1 símbolo
    var pwdError = validateSecurePassword(password, 'account');
    if (pwdError) {
      showAlert('warning', pwdError);
      return;
    }
    if (password !== confirm) {
      showAlert('warning', t('auth.passwords_dont_match', d('Passwords do not match.', 'Las contraseñas no coinciden.')));
      return;
    }

    setAccountSubmitting(true);
    try {
      var resp = await apiRequest('/api/v1/auth/first-login/change', {
        method: 'POST',
        body: { new_username: username, new_password: password }
      });
      var data = await resp.json().catch(function() { return {}; });
      if (resp && resp.ok) {
        showAlert('success', (data && data.message) ? data.message : t('auth.credentials_updated', d('Credentials updated', 'Credenciales actualizadas')));
        // Finalizar el asistente: marca el wizard como completado y reinicia para aplicar el WiFi.
        if (window.HostBerry && typeof window.HostBerry.finishSetupWizard === 'function') {
          window.HostBerry.finishSetupWizard();
        } else {
          window.location.href = '/dashboard';
        }
        return; // dejamos el botón deshabilitado: el flujo de finalización toma el control.
      }
      var errMsg = (data && (data.error || data.message)) ? (data.error || data.message)
        : t('errors.general_error_message', d('An unexpected error occurred', 'Ha ocurrido un error inesperado'));
      showAlert('danger', errMsg);
      setAccountSubmitting(false);
    } catch (err) {
      showAlert('danger', t('errors.connection_error', d('Connection error', 'Error de conexión')));
      setAccountSubmitting(false);
    }
  }

  function init() {
    fetchWifiStatus();
    var scanBtn = document.getElementById('wizard-scan-btn');
    if (scanBtn) scanBtn.addEventListener('click', function() { scanNetworks(true); });

    // Paso 1 — Tarjetas de conexión (Cable/WiFi): al elegir, se marca y se habilita "Siguiente".
    document.querySelectorAll('.wizard-connection-card').forEach(function(card) {
      card.addEventListener('click', function() {
        if (card.classList.contains('disabled')) return;
        selectedConnectionType = card.getAttribute('data-connection');
        updateConnectionCardSelection(selectedConnectionType);
        updateBandStepTexts();
        var nextBtn = document.getElementById('wizard-connection-next');
        if (nextBtn) nextBtn.disabled = false;
      });
      card.addEventListener('keydown', function(e) {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        card.click();
      });
    });
    // Paso 1 — "Siguiente": según el tipo de conexión, va al paso correspondiente.
    var connectionNext = document.getElementById('wizard-connection-next');
    if (connectionNext) connectionNext.addEventListener('click', function() {
      // Ambas rutas eligen primero la banda (paso 2): por WiFi determina en qué frecuencia se
      // buscan las redes; por cable, la banda en la que emitirá el AP HostBerry.
      if (selectedConnectionType === 'cable' || selectedConnectionType === 'wifi') {
        setStep(2);
      }
    });

    // Paso 2 — Tarjetas de banda 2.4/5 GHz: al elegir, se marca y se habilita "Siguiente".
    document.querySelectorAll('.wizard-band-card').forEach(function(card) {
      card.addEventListener('click', function() {
        if (card.classList.contains('disabled')) return;
        selectedBand = card.getAttribute('data-band');
        updateBandCardSelection(selectedBand);
        var nextBtn = document.getElementById('wizard-band-next');
        if (nextBtn) nextBtn.disabled = false;
      });
      card.addEventListener('keydown', function(e) {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        card.click();
      });
    });
    // Paso 2 — "Siguiente": aplica la banda elegida, pasa al escaneo y busca redes de esa banda.
    var bandNext = document.getElementById('wizard-band-next');
    if (bandNext) bandNext.addEventListener('click', function() {
      var band = selectedBand || (setupInfo.band === '5' ? '5' : '2.4');
      if (selectedConnectionType === 'cable') {
        // Cable: no hay que escanear redes; se guarda la banda del AP y se configura hostapd.
        setupInfo.band = band;
        setStep(4);
        saveBandPreference(band).then(function() {
          updateApChannelNote();
          fillApChannelOptions();
        });
        return;
      }
      setupInfo.scanBand = band;
      setStep(3);
      applyBand(band);
    });
    var connectBtn = document.getElementById('wizard-connect-btn');
    if (connectBtn) connectBtn.addEventListener('click', connectWiFi);

    // Continuar (mantener conexión): comprobar primero que hay conexión
    var continueBtn = document.getElementById('wizard-continue-connected-btn');
    if (continueBtn) {
      continueBtn.addEventListener('click', function() {
        (async function() {
          try {
            var r = await apiRequest('/api/v1/wifi/status', { method: 'GET' });
            if (r && r.ok) {
              var s = await r.json().catch(function() { return {}; });
              if ((s && s.connection_type === 'ethernet') || (s && s.connection_type === 'wifi' && (s.connected === true || s.connected === undefined))) {
                setStep(4);
                return;
              }
            }
          } catch (_) {}
          showAlert('warning', t('setup_wizard.error_no_connection', d('No active network connection detected. Please connect to a WiFi or use Ethernet before continuing.', 'No se ha detectado una conexión de red activa. Conéctate a una WiFi o usa cable Ethernet antes de continuar.')));
        })();
      });
    }
    var back2 = document.getElementById('wizard-back-2');
    if (back2) back2.addEventListener('click', function() { setStep(1); });
    var back3 = document.getElementById('wizard-back-3');
    var back4 = document.getElementById('wizard-back-4');
    var next4 = document.getElementById('wizard-next-4');
    var back5 = document.getElementById('wizard-back-5');
    if (back3) back3.addEventListener('click', function() { setStep(2); });
    if (back4) back4.addEventListener('click', function() {
      // Si es cable, volver a la elección de banda. Si es WiFi, volver a la conexión WiFi.
      if (selectedConnectionType === 'cable') {
        setStep(2);
      } else {
        setStep(3);
      }
    });
    if (next4) next4.addEventListener('click', function() { saveHostapd(); });
    if (back5) back5.addEventListener('click', function() { setStep(4); });

    document.querySelectorAll('.wizard-skip-btn').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        e.preventDefault();
        var stepEl = btn.closest('.setup-step');
        var step = stepEl ? parseInt(stepEl.getAttribute('data-step'), 10) : wizardStep;
        if (step === 3) {
          setStep(4);
          return;
        }
      });
    });

    // Paso 5 — Credenciales (first-login): cambia el usuario/contraseña por defecto y, al tener
    // éxito, finaliza el asistente (que reinicia el equipo para aplicar el WiFi elegido).
    var accountForm = document.getElementById('wizard-account-form');
    if (accountForm) accountForm.addEventListener('submit', submitAccount);

    setupPasswordToggle('wizard-wifi-password', 'wizard-wifi-toggle-pwd');
    setupPasswordToggle('wizard-ap-password', 'wizard-ap-toggle-pwd');
    setupPasswordToggle('wizard-acc-password', 'wizard-acc-toggle-pwd');
    setupPasswordToggle('wizard-acc-password2', 'wizard-acc-toggle-pwd2');

    // Si el usuario edita el SSID, no lo sobrescribimos con el valor por defecto de la banda.
    var apSsidInput = document.getElementById('wizard-ap-ssid');
    if (apSsidInput) apSsidInput.addEventListener('input', function() { apSsidInput.dataset.userEdited = '1'; });

    // Si el usuario elige un canal, no lo sobrescribimos con el valor por defecto de la banda.
    var apChannelSelect = document.getElementById('wizard-ap-channel');
    if (apChannelSelect) apChannelSelect.addEventListener('change', function() { apChannelSelect.dataset.userEdited = '1'; });

    var params = new URLSearchParams(window.location.search || '');
    var stepParam = params.get('step');
    // step=5 (o el antiguo 4) abre directamente la pantalla de seguridad al volver de una subpágina.
    if (stepParam === '5' || stepParam === '4') {
      setStep(5);
    } else {
      setStep(1);
    }
    // Cargar info del entorno (interfaz, país, banda). El escaneo se lanza al pasar al paso 3.
    fetchSetupInfo();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
