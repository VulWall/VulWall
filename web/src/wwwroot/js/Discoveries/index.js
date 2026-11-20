// Discoveries page — expand/collapse + ownership change.

const STATUS_CONFIG = {
    '0': { label: 'Verified', style: 'border-color: var(--vw-success); color: var(--vw-success);' },
    '1': { label: 'Not sure', style: 'border-color: var(--severity-medium); color: var(--severity-medium);' },
    '2': { label: 'Not mine', style: 'border-color: var(--severity-high); color: var(--severity-high);' },
    '3': { label: 'Ignore', style: 'border-color: var(--vw-gray-400); color: var(--vw-gray-400);' },
};

let pendingChange = null;

// --- Domain expand/collapse (toggles sibling child rows) ---
function initDomainExpand() {
    document.querySelectorAll('.domain-expand').forEach(btn => {
        btn.addEventListener('click', e => {
            e.stopPropagation();
            const parentWrap = btn.closest('.disc-row-wrap');
            const parentId = parentWrap?.dataset.discoveryId;
            if (!parentId) return;

            const chevron = btn.querySelector('.chevron-icon');
            const isExpanded = parentWrap.dataset.expanded === 'true';

            document.querySelectorAll(`.disc-row-wrap[data-parent-id="${parentId}"]`).forEach(child => {
                child.style.display = isExpanded ? 'none' : '';
            });

            parentWrap.dataset.expanded = isExpanded ? 'false' : 'true';
            chevron?.classList.toggle('expanded', !isExpanded);
            btn.setAttribute('aria-expanded', String(!isExpanded));
        });
    });
}

// --- Row detail drawer expand/collapse ---
function initRowExpand() {
    document.querySelectorAll('.row-expand').forEach(btn => {
        btn.addEventListener('click', e => {
            e.stopPropagation();
            const drawerId = btn.dataset.target;
            if (!drawerId) return;
            const drawer = document.getElementById(drawerId);
            if (!drawer) return;

            const isOpen = drawer.classList.contains('open');
            drawer.classList.toggle('open', !isOpen);
            btn.setAttribute('aria-expanded', String(!isOpen));

            const icon = btn.querySelector('.expand-icon');
            if (icon) {
                icon.classList.toggle('fa-circle-plus', isOpen);
                icon.classList.toggle('fa-circle-minus', !isOpen);
            }
        });
    });
}

// --- Broken geo image handling ---
function initGeoImages() {
    document.querySelectorAll('.geo-flag, .geo-cloud-logo').forEach(img => {
        img.addEventListener('error', () => img.classList.add('image-error'));
        // Handle images that already 404'd before the listener attached (cached responses).
        if (img.complete && img.naturalWidth === 0) img.classList.add('image-error');
    });
}

// --- Ownership change with confirmation modal ---
function initOwnershipChange() {
    document.querySelectorAll('.status-select').forEach(select => {
        // Snapshot baseline at init and on focus so keyboard users are covered.
        select._oldValue = select.value;
        select._oldStyle = select.getAttribute('style') || '';
        select.addEventListener('focus', () => {
            select._oldValue = select.value;
            select._oldStyle = select.getAttribute('style') || '';
        });

        select.addEventListener('change', () => {
            const form = select.closest('.status-change-form');
            if (!form) return;

            const newValue = select.value;
            const config = STATUS_CONFIG[newValue];
            if (!config) return;

            // No-op if value didn't actually change.
            if (select._oldValue === newValue) return;

            const discoveryName = select.dataset.discoveryName || 'this asset';

            // Optimistic color update.
            select.setAttribute('style', config.style);

            pendingChange = {
                select,
                form,
                oldValue: select._oldValue,
                oldStyle: select._oldStyle,
                newValue,
            };

            const dynamicContent = document.getElementById('statusChangeContent');
            if (dynamicContent) {
                dynamicContent.innerHTML =
                    `<p class="mb-0">Mark <strong></strong> as <strong></strong>?</p>`;
                const strongs = dynamicContent.querySelectorAll('strong');
                if (strongs[0]) strongs[0].textContent = discoveryName;
                if (strongs[1]) strongs[1].textContent = config.label;
            }

            const confirmBtn = document.getElementById('confirmStatusChangeModalConfirm');
            if (confirmBtn) {
                // Replace the node to drop any previously attached listener.
                const freshBtn = confirmBtn.cloneNode(true);
                confirmBtn.parentNode?.replaceChild(freshBtn, confirmBtn);
                freshBtn.addEventListener('click', confirmOwnershipChange);
            }

            const modal = document.getElementById('confirmStatusChangeModal');
            if (modal) new bootstrap.Modal(modal).show();
        });
    });

    // Revert when the modal is dismissed without confirming.
    const modal = document.getElementById('confirmStatusChangeModal');
    if (modal) {
        modal.addEventListener('hidden.bs.modal', () => {
            if (pendingChange) {
                const { select, oldValue, oldStyle } = pendingChange;
                select.value = oldValue;
                select.setAttribute('style', oldStyle);
                pendingChange = null;
            }
        });
    }
}

async function confirmOwnershipChange() {
    if (!pendingChange) return;

    // Capture everything we need locally; clearing pendingChange before the
    // await prevents the modal's hidden handler from reverting a confirmed change.
    const { select, form, newValue, oldValue, oldStyle } = pendingChange;
    pendingChange = null;

    const modal = document.getElementById('confirmStatusChangeModal');
    bootstrap.Modal.getInstance(modal)?.hide();

    try {
        const res = await fetch(form.dataset.action, { method: 'POST', body: new FormData(form) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        // Persist the new baseline and refresh triage state on the row wrapper.
        select._oldValue = newValue;
        select._oldStyle = select.getAttribute('style') || '';

        const wrap = select.closest('.disc-row-wrap');
        if (wrap) {
            const isTriage = newValue === '1' || newValue === '2';
            wrap.dataset.needsTriage = isTriage ? 'true' : 'false';

            const STATUS_ROW_CLASS = { '1': 'status-not-sure', '2': 'status-not-mine', '3': 'status-ignore' };
            wrap.classList.remove('status-not-sure', 'status-not-mine', 'status-ignore');
            if (STATUS_ROW_CLASS[newValue]) wrap.classList.add(STATUS_ROW_CLASS[newValue]);
        }

        document.dispatchEvent(new CustomEvent('disc:ownershipChanged'));
    } catch (err) {
        console.error('Failed to update ownership status:', err);
        select.value = oldValue;
        select.setAttribute('style', oldStyle);
        VW.showError('Failed to save status change. Please try again.');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Collapse child rows by default — only domain/parent rows show on load.
    document.querySelectorAll('.disc-row-wrap[data-is-child="true"]').forEach(row => {
        row.style.display = 'none';
    });
    // Mark all parent rows as collapsed so applyFilters() can respect expand state.
    document.querySelectorAll('.disc-row-wrap[data-is-child="false"]').forEach(row => {
        row.dataset.expanded = 'false';
    });

    initDomainExpand();
    initRowExpand();
    initGeoImages();
    initOwnershipChange();
});
