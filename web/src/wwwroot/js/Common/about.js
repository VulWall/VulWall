// About dialog (Common/Views/_AboutDialog.cshtml): loads versions when it opens, copies the
// system info text, and checks for updates only when the button is clicked.

const dialog = document.getElementById('aboutDialog');
if (dialog) init(dialog);

function init(dialog) {
    const versions = dialog.querySelector('[data-about-versions]');
    const loadError = dialog.querySelector('[data-about-load-error]');
    const copyButton = dialog.querySelector('[data-about-copy]');
    const checkButton = dialog.querySelector('[data-about-check]');
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

    checkButton.addEventListener('click', () => checkForUpdates(checkButton, status));
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

async function checkForUpdates(button, status) {
    const token = document.querySelector('input[name="__RequestVerificationToken"]')?.value || '';
    button.disabled = true;
    setStatus(status, 'Checking for updates...');
    try {
        const response = await fetch('/about/check-updates', {
            method: 'POST',
            headers: { RequestVerificationToken: token, Accept: 'application/json' }
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        showUpdateResult(status, await response.json());
    } catch (err) {
        console.warn('About: update check failed', err);
        setStatus(status, 'Could not check for updates. Try again later.');
    } finally {
        button.disabled = false;
    }
}

function showUpdateResult(status, result) {
    const latest = typeof result.latestVersion === 'string' ? result.latestVersion : '';
    const url = typeof result.releaseUrl === 'string' && result.releaseUrl.startsWith('https://github.com/VulWall/VulWall/')
        ? result.releaseUrl : '';
    switch (result.status) {
        case 'Latest':
            setStatus(status, "You're on the latest version.");
            break;
        case 'Available':
            setStatus(status, `${latest} is available. `, url, 'Release notes');
            break;
        case 'Unknown':
            setStatus(status, `This is a development build. The latest release is ${latest}. `, url, 'Release notes');
            break;
        case 'NoRelease':
            setStatus(status, 'No published release found yet.');
            break;
        case 'RateLimited':
            setStatus(status, 'GitHub limits update checks right now. Try again in an hour.');
            break;
        case 'Unreachable':
            setStatus(status, "Could not reach GitHub. Check the server's internet connection and try again.");
            break;
        default:
            setStatus(status, 'Could not check for updates. Try again later.');
    }
}

function setStatus(status, text, linkUrl, linkText) {
    status.replaceChildren(document.createTextNode(text));
    if (linkUrl) {
        const a = document.createElement('a');
        a.href = linkUrl;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = linkText;
        status.append(a);
    }
}
