(function () {
  var t = window.HostBerry && window.HostBerry.t
    ? function (k, fallback) { return HostBerry.t(k, fallback); }
    : function (_, fallback) { return fallback || _; };
  var apiRequest = window.HostBerry && window.HostBerry.apiRequest
    ? function (u, o) { return HostBerry.apiRequest(u, o); }
    : function (u, o) { return fetch(u, Object.assign({ credentials: 'include' }, o || {})); };
  var showAlert = window.HostBerry && window.HostBerry.showAlert
    ? function (type, msg) { HostBerry.showAlert(type, msg); }
    : function (type, msg) { if (window.showAlert) window.showAlert(type || 'info', msg); else alert(msg); };

  function currentLangQS() {
    var lang = (document.documentElement && document.documentElement.lang) || 'es';
    return 'lang=' + encodeURIComponent(lang);
  }

  async function finishSetupWizard() {
    var buttons = document.querySelectorAll('.wizard-finish-btn');
    buttons.forEach(function (btn) { btn.disabled = true; });
    try {
      var resp = await apiRequest('/api/v1/setup-wizard/complete', { method: 'POST' });
      var data = await resp.json().catch(function () { return {}; });
      if (!resp || !resp.ok) {
        showAlert('danger', (data && data.error) || t('errors.general_error_message', 'Ha ocurrido un error inesperado'));
        buttons.forEach(function (btn) { btn.disabled = false; });
        return;
      }
      if (data && data.reboot) {
        showAlert('info', t('setup_wizard.reboot_pending', 'Configuración guardada. El equipo se reinicia para aplicar el WiFi. Vuelve a conectarte en un minuto.'));
        var dest = (data && data.redirect) || '/first-login';
        var join = dest.indexOf('?') >= 0 ? '&' : '?';
        var target = dest + join + currentLangQS();
        setTimeout(function() { window.location.href = target; }, 90000);
        return;
      }
      var dest = (data && data.redirect) || '/first-login';
      var join = dest.indexOf('?') >= 0 ? '&' : '?';
      window.location.href = dest + join + currentLangQS();
    } catch (e) {
      showAlert('danger', t('errors.general_error_message', 'Ha ocurrido un error inesperado'));
      buttons.forEach(function (btn) { btn.disabled = false; });
    }
  }

  document.querySelectorAll('.wizard-finish-btn').forEach(function (el) {
    el.addEventListener('click', function (e) {
      e.preventDefault();
      finishSetupWizard();
    });
  });

  window.HostBerry = window.HostBerry || {};
  window.HostBerry.finishSetupWizard = finishSetupWizard;
})();
