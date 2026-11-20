// No inline event handlers — attach all listeners here.
// CSP: script-src 'self', no 'unsafe-inline'. This file is loaded type="module".

const DOMAIN_REGEX = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;
const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
// Loose IPv6 shape check; the server does the authoritative parse.
const IPV6_REGEX = /^[0-9a-f:]+$/i;

function isValidDomain(val) {
    if (!val) return null; // null = empty, not invalid
    return DOMAIN_REGEX.test(val);
}

function isValidIp(val) {
    if (!val) return null;
    return IPV4_REGEX.test(val) || (val.includes(':') && IPV6_REGEX.test(val));
}

function setValidityUI(validIconId, invalidIconId, helperId, valid, neutralText, validText, invalidText) {
    const vIcon = document.getElementById(validIconId);
    const xIcon = document.getElementById(invalidIconId);
    const help = document.getElementById(helperId);
    if (valid === null) {
        vIcon?.classList.remove('visible');
        xIcon?.classList.remove('visible');
        if (help) { help.className = 'add-helper-text'; help.innerHTML = neutralText; }
    } else if (valid) {
        vIcon?.classList.add('visible');
        xIcon?.classList.remove('visible');
        if (help) { help.className = 'add-helper-text add-helper-valid'; help.innerHTML = validText; }
    } else {
        vIcon?.classList.remove('visible');
        xIcon?.classList.add('visible');
        if (help) { help.className = 'add-helper-text add-helper-invalid'; help.innerHTML = invalidText; }
    }
}

function hookTypeToggle() {
    const domainFields = document.getElementById('domainFields');
    const ipFields = document.getElementById('ipFields');

    document.querySelectorAll('input[name="AssetType"]').forEach(radio => {
        radio.addEventListener('change', () => {
            const isIp = document.getElementById('assetTypeIp')?.checked === true;
            if (domainFields) domainFields.hidden = isIp;
            if (ipFields) ipFields.hidden = !isIp;
            (isIp ? document.getElementById('ipInput') : document.getElementById('domainInput'))?.focus();
        });
    });
}

function hookInputValidation() {
    const domainInput = document.getElementById('domainInput');
    const ipInput = document.getElementById('ipInput');

    domainInput?.addEventListener('input', () => {
        setValidityUI(
            'domainValidIcon', 'domainInvalidIcon', 'domainHelper', isValidDomain(domainInput.value.trim()),
            '<i class="fas fa-circle-info"></i> No http:// or paths, just the bare domain.',
            '<i class="fas fa-circle-check"></i> Looks good: a valid domain.',
            '<i class="fas fa-circle-exclamation"></i> That doesn\'t look like a valid domain name.'
        );
    });

    ipInput?.addEventListener('input', () => {
        setValidityUI(
            'ipValidIcon', 'ipInvalidIcon', 'ipHelper', isValidIp(ipInput.value.trim()),
            '<i class="fas fa-circle-info"></i> A public address. Private ranges are not scanned.',
            '<i class="fas fa-circle-check"></i> Looks good: a valid IP address.',
            '<i class="fas fa-circle-exclamation"></i> That doesn\'t look like a valid IP address.'
        );
    });
}

document.addEventListener('DOMContentLoaded', () => {
    hookTypeToggle();
    hookInputValidation();
});
