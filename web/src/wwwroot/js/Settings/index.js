(function () {
    const tabsLoaded = {
        billing: false,
        plans: false,
        preferences: false
    };

    function loadTabData(tabName, endpoint, errorMessage) {
        const loadingEl = document.getElementById(`${tabName}-loading`);
        const contentEl = document.getElementById(`${tabName}-content`);

        fetch(endpoint, { cache: 'no-store' })
            .then(response => {
                if (!response.ok) throw new Error(`Failed to load ${tabName} data`);
                return response.text();
            })
            .then(html => {
                contentEl.innerHTML = html;
                loadingEl.style.display = 'none';
                contentEl.style.display = 'block';
                tabsLoaded[tabName] = true;
            })
            .catch(error => {
                console.error(`Error loading ${tabName} data:`, error);
                contentEl.innerHTML = `<div class="alert alert-danger">${errorMessage}</div>`;
                loadingEl.style.display = 'none';
                contentEl.style.display = 'block';
            });
    }

    function initLazyTab(tabId, tabName, endpoint, errorMessage) {
        const tab = document.getElementById(tabId);
        if (!tab) return;

        tab.addEventListener('shown.bs.tab', () => {
            if (!tabsLoaded[tabName]) {
                loadTabData(tabName, endpoint, errorMessage);
            }
        });
    }

    function initConfirmationModal(triggerBtnId, confirmBtnId, formId, modalId, requireValidation = false) {
        const triggerBtn = document.getElementById(triggerBtnId);
        const confirmBtn = document.getElementById(confirmBtnId);
        const form = document.getElementById(formId);
        const modal = document.getElementById(modalId);

        if (!triggerBtn || !confirmBtn || !form || !modal) return;

        const modalInstance = new bootstrap.Modal(modal);

        triggerBtn.addEventListener('click', (e) => {
            e.preventDefault();

            if (requireValidation && !form.checkValidity()) {
                form.reportValidity();
                return;
            }

            modalInstance.show();
        });

        confirmBtn.addEventListener('click', () => {
            modalInstance.hide();
            form.submit();
        });
    }

    initLazyTab('billing-tab', 'billing', '/Settings/GetBillingData', 'Failed to load billing data. Please refresh the page.');
    initLazyTab('plans-tab', 'plans', '/Settings/GetPlansData', 'Failed to load plans. Please refresh the page.');
    initLazyTab('preferences-tab', 'preferences', '/Settings/GetPreferencesData', 'Failed to load preferences. Please refresh the page.');

    initConfirmationModal('saveCompanyBtn', 'confirmCompanyModalConfirm', 'companyForm', 'confirmCompanyModal', true);
    initConfirmationModal('removeLogoBtn', 'confirmRemoveLogoModalConfirm', 'removeLogoForm', 'confirmRemoveLogoModal');
})();
