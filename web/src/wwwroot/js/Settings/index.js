(function () {
    const tabsLoaded = {
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

    // Show only the schedule fields that apply to the chosen frequency.
    function initScheduleForm() {
        const frequency = document.getElementById('scheduleFrequency');
        if (!frequency) return;
        const fields = document.querySelectorAll('#scanScheduleForm [data-schedule-for]');
        const sync = () => {
            fields.forEach(el => {
                el.hidden = !el.dataset.scheduleFor.split(' ').includes(frequency.value);
            });
        };
        frequency.addEventListener('change', sync);
        sync();
    }

    // Open the tab named in the URL hash (e.g. /Settings#schedule after saving the schedule).
    function openTabFromHash() {
        const id = window.location.hash.slice(1);
        if (!/^[a-z-]+$/.test(id)) return;
        const tab = document.getElementById(`${id}-tab`);
        if (tab && window.bootstrap) bootstrap.Tab.getOrCreateInstance(tab).show();
    }

    initScheduleForm();
    openTabFromHash();

    initLazyTab('preferences-tab', 'preferences', '/Settings/GetPreferencesData', 'Failed to load preferences. Please refresh the page.');

    initConfirmationModal('removeLogoBtn', 'confirmRemoveLogoModalConfirm', 'removeLogoForm', 'confirmRemoveLogoModal');
})();
