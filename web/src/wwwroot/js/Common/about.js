// About dialog (Common/Views/_AboutDialog.cshtml): loads versions when it opens, copies the
// system info text and the upgrade command. The update status is rendered on the server.

const dialog = document.getElementById('aboutDialog');
if (dialog) init(dialog);

function init(dialog) {
    const versions = dialog.querySelector('[data-about-versions]');
    const loadError = dialog.querySelector('[data-about-load-error]');
    const copyButton = dialog.querySelector('[data-about-copy]');
    const command = dialog.querySelector('[data-about-command]');
    const commandButton = dialog.querySelector('[data-about-command-copy]');
    const commandStatus = dialog.querySelector('[data-about-command-status]');
    const status = dialog.querySelector('[data-about-status]');
    const fallback = dialog.querySelector('[data-about-copy-fallback]');
    let copyText = '';

    dialog.addEventListener('show.bs.modal', async () => {
        // Below the lg breakpoint the trigger lives in the sidebar offcanvas, which has its own
        // focus trap. Close it first, or the two traps fight and focus stays behind the dialog.
        const sidebar = document.getElementById('sidebarOffcanvas');
        if (sidebar && window.bootstrap) window.bootstrap.Offcanvas.getInstance(sidebar)?.hide();
        try {
            const response = await fetch('/about/info', { headers: { Accept: 'application/json' } });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const info = await response.json();
            renderVersions(versions, info.versions || []);
            copyText = typeof info.copyText === 'string' ? info.copyText : '';
            copyButton.disabled = copyText === '';
            loadError.classList.add('d-none');
        } catch (err) {
            console.warn('About: could not load system info', err);
            loadError.classList.remove('d-none');
        }
    });

    dialog.addEventListener('hidden.bs.modal', () => {
        setStatus(status, '');
        if (commandStatus) setStatus(commandStatus, '');
        fallback.classList.add('d-none');
    });

    // Copy synchronously from the text loaded on open: an await before writeText can lose the
    // user gesture some browsers require.
    copyButton.addEventListener('click', () => {
        if (!copyText) return;
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(copyText)
                .then(() => setStatus(status, 'System info copied.'))
                .catch(() => copyWithFallback(fallback, copyText, status));
        } else {
            // navigator.clipboard is missing on plain-HTTP LAN installs. The textarea lives inside
            // the modal so Bootstrap's focus trap does not steal focus from it.
            copyWithFallback(fallback, copyText, status);
        }
    });

    // Only rendered when a newer release is known.
    if (command && commandButton && commandStatus) {
        commandButton.addEventListener('click', () => copyCommand(command, commandStatus));
    }
}

function renderVersions(list, rows) {
    const items = [];
    for (const row of rows) {
        const dt = document.createElement('dt');
        dt.textContent = String(row.label ?? '');
        const dd = document.createElement('dd');
        dd.textContent = String(row.value ?? '');
        if (dd.textContent === 'unknown') dd.classList.add('is-unknown');
        items.push(dt, dd);
    }
    if (items.length) list.replaceChildren(...items);
}

function copyWithFallback(textarea, text, status) {
    textarea.value = text;
    textarea.classList.remove('d-none');
    textarea.focus();
    textarea.select();
    let copied = false;
    try {
        copied = document.execCommand('copy');
    } catch {
        copied = false;
    }
    if (copied) {
        textarea.classList.add('d-none');
        setStatus(status, 'System info copied.');
    } else {
        setStatus(status, 'Your browser blocked copying. The text is selected below: press Ctrl+C or Cmd+C.');
    }
}

function copyCommand(code, status) {
    const text = code.textContent.trim();
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(() => setStatus(status, 'Command copied.'))
            .catch(() => selectAndCopy(code, status));
    } else {
        selectAndCopy(code, status);
    }
}

// Plain-HTTP LAN installs have no navigator.clipboard: select the command and try the old copy
// command; if the browser blocks that too, the selection stays for Ctrl+C.
function selectAndCopy(element, status) {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
    let copied = false;
    try {
        copied = document.execCommand('copy');
    } catch {
        copied = false;
    }
    setStatus(status, copied
        ? 'Command copied.'
        : 'Your browser blocked copying. The command is selected: press Ctrl+C or Cmd+C.');
}

function setStatus(status, text) {
    status.textContent = text;
}
