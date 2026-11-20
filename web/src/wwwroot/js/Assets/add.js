// No inline event handlers — attach all listeners here.
// CSP: script-src 'self', no 'unsafe-inline'. This file is loaded type="module".
//
// Domain is currently the only asset type (IP assets are temporarily disabled while
// ownership verification is built), so there is no type toggle — just live validation
// of the domain field.

const DOMAIN_REGEX = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;

function isValidDomain(val) {
    if (!val) return null; // null = empty, not invalid
    return DOMAIN_REGEX.test(val);
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

function hookInputValidation() {
    const domainInput = document.getElementById('domainInput');

    domainInput?.addEventListener('input', () => {
        const val = domainInput.value.trim();
        setValidityUI(
            'domainValidIcon', 'domainInvalidIcon', 'domainHelper', isValidDomain(val),
            '<i class="fas fa-circle-info"></i> No http:// or paths — just the bare domain.',
            '<i class="fas fa-circle-check"></i> Looks good — a valid domain.',
            '<i class="fas fa-circle-exclamation"></i> That doesn\'t look like a valid domain name.'
        );
    });
}

document.addEventListener('DOMContentLoaded', () => {
    hookInputValidation();
});
