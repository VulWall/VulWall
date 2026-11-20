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

    // The schedule uses the browser's time zone: fill the hidden field and say which zone that is.
    function initScheduleTimeZone() {
        const field = document.getElementById('scheduleTimeZone');
        if (!field) return;
        let zone = '';
        try {
            zone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        } catch {
            zone = '';
        }
        if (!zone) return; // the server keeps the saved zone, else UTC, as the note already says

        field.value = zone;
        field.form?.addEventListener('submit', () => { field.value = zone; });

        // The times in the form are in the zone they were saved in (UTC when none was saved).
        const formZone = field.dataset.formZone || 'UTC';
        if (formZone !== zone) {
            const hint = document.querySelector('[data-schedule-zone-hint]');
            if (hint) {
                hint.textContent = `Saved in ${formZone}. Saving again uses your current time zone (${zone}).`;
                hint.hidden = false;
            }
            return;
        }

        const year = new Date().getFullYear();
        const hasDst = new Date(year, 0, 1).getTimezoneOffset() !== new Date(year, 6, 1).getTimezoneOffset();
        const note = document.querySelector('[data-schedule-zone-note]');
        if (note) {
            note.textContent = `Times are in your time zone (${zone}). `
                + (hasDst ? 'When daylight saving time starts or ends, the scan time moves by one hour. ' : '')
                + 'Changes apply within 5 minutes.';
        }
    }

    // Open the tab named in the URL hash (e.g. /Settings#schedule after saving the schedule).
    function openTabFromHash() {
        const id = window.location.hash.slice(1);
        if (!/^[a-z-]+$/.test(id)) return;
        const tab = document.getElementById(`${id}-tab`);
        if (tab && window.bootstrap) bootstrap.Tab.getOrCreateInstance(tab).show();
    }

    initScheduleForm();
    initScheduleTimeZone();
    openTabFromHash();

    initLazyTab('preferences-tab', 'preferences', '/Settings/GetPreferencesData', 'Failed to load preferences. Please refresh the page.');

    initConfirmationModal('removeLogoBtn', 'confirmRemoveLogoModalConfirm', 'removeLogoForm', 'confirmRemoveLogoModal');
})();
