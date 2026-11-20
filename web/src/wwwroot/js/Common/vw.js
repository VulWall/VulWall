(function () {
  'use strict';

  const VW = window.VW || {};

  // VW.postJson(url, formElement, optionalBody)
  // CSRF-authenticated JSON POST. formElement is used to read the antiforgery token.
  // If body is omitted, sends FormData from formElement as JSON.
  // Throws on non-2xx response.
  VW.postJson = async function (url, form, body) {
    const token = form
      ? (form.querySelector('input[name="__RequestVerificationToken"]') || {}).value
      : document.querySelector('input[name="__RequestVerificationToken"]')?.value;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'RequestVerificationToken': token } : {})
      },
      body: JSON.stringify(body !== undefined ? body : Object.fromEntries(new FormData(form)))
    });
    if (!response.ok) throw new Error(`Request failed: ${response.status}`);
    return response;
  };

  // VW.setButtonLoading(btn, loadingHtml, isLoading)
  // Toggles a button between its normal and loading state.
  VW.setButtonLoading = function (btn, loadingHtml, isLoading) {
    if (isLoading) {
      btn.dataset.originalHtml = btn.innerHTML;
      btn.innerHTML = loadingHtml;
      btn.disabled = true;
    } else {
      btn.innerHTML = btn.dataset.originalHtml || btn.innerHTML;
      btn.disabled = false;
    }
  };

  // VW.copyWithFeedback(button, text, durationMs = 2000)
  // Copies text to clipboard and shows visual feedback on the button.
  VW.copyWithFeedback = function (button, text, durationMs) {
    durationMs = durationMs || 2000;
    var clip = navigator.clipboard && navigator.clipboard.writeText(text);
    Promise.resolve(clip || Promise.reject(new Error('clipboard unavailable')))
      .then(function () {
        var original = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i> Copied';
        button.disabled = true;
        setTimeout(function () {
          button.innerHTML = original;
          button.disabled = false;
        }, durationMs);
      })
      .catch(function () {
        VW.showError('Could not copy to clipboard — copy it manually.');
      });
  };

  // VW.showToast(message, tone)
  // tone: 'success' | 'error' | 'info' | 'warning'
  // Uses a Bootstrap toast injected into a shared container.
  VW.showToast = function (message, tone) {
    tone = tone || 'info';
    const colorMap = {
      success: 'text-bg-success',
      error:   'text-bg-danger',
      warning: 'text-bg-warning',
      info:    'text-bg-secondary'
    };
    let container = document.getElementById('vw-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'vw-toast-container';
      container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
      container.style.zIndex = '1100';
      document.body.appendChild(container);
    }
    const id = 'toast-' + Date.now();
    const toastEl = document.createElement('div');
    toastEl.id = id;
    toastEl.className = 'toast align-items-center ' + (colorMap[tone] || colorMap.info);
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    toastEl.innerHTML =
      '<div class="d-flex">' +
        '<div class="toast-body"></div>' +
        '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>' +
      '</div>';
    toastEl.querySelector('.toast-body').textContent = message;
    container.appendChild(toastEl);
    const toast = new bootstrap.Toast(toastEl, { delay: 4000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', function () { toastEl.remove(); });
  };

  VW.showError   = function (msg) { VW.showToast(msg, 'error'); };
  VW.showSuccess = function (msg) { VW.showToast(msg, 'success'); };
  VW.showInfo    = function (msg) { VW.showToast(msg, 'info'); };

  // VW.activateChip(groupEl, chipEl, activeClass = 'is-active')
  // Removes activeClass from all siblings in groupEl, adds it to chipEl.
  // Sets aria-pressed accordingly.
  VW.activateChip = function (groupEl, chipEl, activeClass) {
    activeClass = activeClass || 'is-active';
    Array.from(groupEl.querySelectorAll('[role="button"], button, [data-filter]'))
      .forEach(function (el) {
        el.classList.remove(activeClass, 'active');
        el.setAttribute('aria-pressed', 'false');
      });
    chipEl.classList.add(activeClass);
    chipEl.setAttribute('aria-pressed', 'true');
  };

  window.VW = VW;
})();
