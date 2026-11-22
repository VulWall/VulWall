document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('assetAddedFlag')) {
        const addedModal = document.getElementById('assetAddedModal');
        if (addedModal) {
            new bootstrap.Modal(addedModal).show();
        }
    }

    let pendingDeleteForm = null;
    let pendingToggle = null;

    const confirmModal = document.getElementById('confirmDeleteModal');
    const confirmBtn = document.getElementById('confirmDeleteModalConfirm');
    let modalInstance = null;

    const toggleModal = document.getElementById('confirmToggleModal');
    const toggleConfirmBtn = document.getElementById('confirmToggleModalConfirm');
    let toggleModalInstance = null;

    if (confirmModal) {
        modalInstance = new bootstrap.Modal(confirmModal);
    }

    if (toggleModal) {
        toggleModalInstance = new bootstrap.Modal(toggleModal);
    }

    // A 409 carries a message for the user (for example: a scan is running). Other errors get
    // the generic text.
    async function errorMessage(response, fallback) {
        if (response.status === 409) {
            const text = (await response.text()).trim();
            if (text) return text;
        }
        return fallback;
    }

    async function fetchStatistics() {
        try {
            const response = await fetch('/Assets/GetStatistics');
            if (!response.ok) {
                throw new Error('Failed to fetch statistics');
            }
            const stats = await response.json();

            const totalEl   = document.getElementById('totalAssetsCount');
            const activeEl  = document.getElementById('activeAssetsCount');
            const inactiveEl = document.getElementById('inactiveAssetsCount');

            const totalVal = stats.totalAssets;
            if (totalEl)   totalEl.textContent   = totalVal;
            if (activeEl)  activeEl.textContent  = stats.activeAssets;
            if (inactiveEl) inactiveEl.textContent = stats.inactiveAssets;

            const footerTotal = document.getElementById('assets-total');
            if (footerTotal) footerTotal.textContent = totalVal;
        } catch (error) {
            console.error('Failed to update statistics:', error);
        }
    }

    // The row forms (delete, status change) are sent with fetch below. Other forms, such as
    // "Scan now" in the confirmation after adding an asset, submit normally.
    document.addEventListener('submit', function(e) {
        if (e.target.closest('.asset-actions')) {
            e.preventDefault();
        }
    });

    // Show modal when delete button is clicked
    document.addEventListener('click', function(e) {
        if (e.target.closest('.delete-asset-btn')) {
            const btn = e.target.closest('.delete-asset-btn');
            pendingDeleteForm = btn.closest('form');
            confirmModal.dataset.assetName = btn.dataset.assetName;
            if (modalInstance) {
                modalInstance.show();
            }
        }
    });

    // Handle delete confirmation
    if (confirmBtn) {
        confirmBtn.addEventListener('click', async function() {
            if (!pendingDeleteForm) return;

            const formData = new FormData(pendingDeleteForm);
            const row = pendingDeleteForm.closest('.asset-row');

            try {
                const response = await fetch(pendingDeleteForm.dataset.action, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    VW.showError(await errorMessage(response, 'Failed to delete asset. Please try again.'));
                    modalInstance.hide();
                    return;
                }

                if (row) {
                    row.remove();
                }

                document.dispatchEvent(new CustomEvent('assets:changed'));
                await fetchStatistics();
                modalInstance.hide();

            } catch (error) {
                console.error('Failed to delete asset:', error);
                VW.showError('Failed to delete asset. Please try again.');
            }
        });
    }

    // Clear pending form when modal closes
    if (confirmModal) {
        confirmModal.addEventListener('hidden.bs.modal', () => {
            pendingDeleteForm = null;
        });
    }

    // Handle active/inactive toggle - show confirmation first
    document.addEventListener('change', function(e) {
        if (e.target.type !== 'checkbox' || !e.target.classList.contains('form-check-input')) return;

        const checkbox = e.target;
        const form = checkbox.closest('form');
        if (!form || !form.dataset.action) return;

        const enabledInput = form.querySelector('input[name="enabled"]');
        if (!enabledInput) return;

        // Revert checkbox immediately - will be set again on confirm
        const newEnabled = checkbox.checked;
        checkbox.checked = !newEnabled;

        // Get asset name from the row
        const row = checkbox.closest('.asset-row');
        const assetName = row?.querySelector('.asset-name')?.textContent || 'this asset';

        // Store pending toggle info
        pendingToggle = {
            checkbox,
            form,
            enabledInput,
            newEnabled,
            assetName
        };

        // Update modal content
        const content = document.getElementById('assetToggleContent');
        if (content) {
            const box = document.createElement('div');
            box.className = `alert alert-${newEnabled ? 'success' : 'warning'} mb-0`;
            const strong = document.createElement('strong');
            strong.textContent = assetName;
            const p = document.createElement('p');
            p.className = 'mb-0 mt-1 small';
            p.textContent = newEnabled
                ? 'This will enable scanning for this asset and show its results again.'
                : 'This will disable scanning for this asset and hide its results. Enable it again to show them.';
            box.append(strong, p);
            content.replaceChildren(box);
        }

        if (toggleModalInstance) {
            toggleModalInstance.show();
        }
    });

    // Handle toggle confirmation
    if (toggleConfirmBtn) {
        toggleConfirmBtn.addEventListener('click', async function() {
            if (!pendingToggle) return;

            const { checkbox, form, enabledInput, newEnabled } = pendingToggle;

            // Apply the change
            checkbox.checked = newEnabled;
            enabledInput.value = newEnabled.toString().toLowerCase();

            const formData = new FormData(form);

            try {
                const response = await fetch(form.dataset.action, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    VW.showError(await errorMessage(response, 'Failed to update asset status. Please try again.'));
                    checkbox.checked = !newEnabled;
                    enabledInput.value = (!newEnabled).toString().toLowerCase();
                    toggleModalInstance.hide();
                    return;
                }

                // Update the row's status pill and data-attr so filters stay correct
                const toggledRow = checkbox.closest('.asset-row');
                if (toggledRow) {
                    const newStatus = newEnabled ? 'active' : 'inactive';
                    toggledRow.dataset.assetStatus = newStatus;
                    const pill = toggledRow.querySelector('.asset-status');
                    if (pill) {
                        pill.classList.remove('is-active', 'is-inactive');
                        pill.classList.add(`is-${newStatus}`);
                        const dot = pill.querySelector('.asset-status-dot');
                        const label = newEnabled ? 'Active' : 'Inactive';
                        pill.replaceChildren();
                        if (dot) pill.appendChild(dot);
                        pill.appendChild(document.createTextNode(label));
                    }
                }
                document.dispatchEvent(new CustomEvent('assets:changed'));
                await fetchStatistics();
                toggleModalInstance.hide();

            } catch (error) {
                console.error('Failed to update asset status:', error);
                VW.showError('Failed to update asset status. Please try again.');
                // Revert on error
                checkbox.checked = !newEnabled;
                enabledInput.value = (!newEnabled).toString().toLowerCase();
                toggleModalInstance.hide();
            }
        });
    }

    // Clear pending toggle when modal closes
    if (toggleModal) {
        toggleModal.addEventListener('hidden.bs.modal', () => {
            pendingToggle = null;
        });
    }

    // Update asset name dynamically in the delete confirmation modal
    if (confirmModal) {
        confirmModal.addEventListener('show.bs.modal', function() {
            const assetName = confirmModal.dataset.assetName || '';
            const content = document.getElementById('assetDeleteContent');
            if (content) {
                const box = document.createElement('div');
                box.className = 'alert alert-warning mb-3';
                const strong = document.createElement('strong');
                strong.textContent = assetName;
                box.appendChild(strong);
                content.replaceChildren(box);
            }
        });
    }
});
