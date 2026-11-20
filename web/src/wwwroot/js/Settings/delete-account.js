(function () {
    'use strict';

    // -------------------------------------------------------------------------
    // Element references
    // -------------------------------------------------------------------------
    const deleteAccountBtn = document.getElementById('deleteAccountBtn');
    const confirmDeleteModal = document.getElementById('confirmDeleteAccountModal');
    const confirmDeleteBtn = document.getElementById('confirmDeleteAccountModalConfirm');
    const otpModal = document.getElementById('otpVerificationModal');
    const otpInput = document.getElementById('otpInput');
    const otpError = document.getElementById('otpError');
    const applyOtpBtn = document.getElementById('applyOtpBtn');
    const antiforgeryForm = document.getElementById('deletionAntiforgeryForm');

    // If the danger zone section is not present on this page, exit early.
    if (!deleteAccountBtn || !confirmDeleteModal || !otpModal || !antiforgeryForm) return;

    const confirmDeleteModalInstance = new bootstrap.Modal(confirmDeleteModal);
    const otpModalInstance = new bootstrap.Modal(otpModal, { backdrop: 'static', keyboard: false });

    // -------------------------------------------------------------------------
    // Step 1: Open the confirmation modal when "Delete Account" is clicked
    // -------------------------------------------------------------------------
    deleteAccountBtn.addEventListener('click', () => {
        confirmDeleteModalInstance.show();
    });

    // -------------------------------------------------------------------------
    // Step 2: User confirms → call RequestAccountDeletion, switch to OTP modal
    // -------------------------------------------------------------------------
    confirmDeleteBtn.addEventListener('click', async () => {
        VW.setButtonLoading(confirmDeleteBtn, loadingHtml('Sending code...'), true);

        try {
            await VW.postJson('/Settings/RequestAccountDeletion', antiforgeryForm, {});

            confirmDeleteModalInstance.hide();
            resetOtpForm();
            otpModalInstance.show();
            otpInput.focus();
        } catch (error) {
            console.error('RequestAccountDeletion error:', error);
            // Show error inside the confirmation modal body area
            showConfirmModalError(error.message);
        } finally {
            VW.setButtonLoading(confirmDeleteBtn, '', false);
        }
    });

    // -------------------------------------------------------------------------
    // Step 3: User enters OTP and clicks "Delete My Account"
    // -------------------------------------------------------------------------
    applyOtpBtn.addEventListener('click', async () => {
        const otp = (otpInput.value || '').trim();

        if (!/^\d{6}$/.test(otp)) {
            showOtpError('Please enter a valid 6-digit code.');
            return;
        }

        hideOtpError();
        VW.setButtonLoading(applyOtpBtn, loadingHtml('Deleting...'), true);

        try {
            const response = await VW.postJson('/Settings/ConfirmAccountDeletion', antiforgeryForm, { otp });
            const data = await response.json();

            // Navigate to the signout endpoint — a full page navigation is required
            // so the Auth0 redirect chain can complete correctly.
            window.location.href = data.redirectUrl;
        } catch (error) {
            console.error('ConfirmAccountDeletion error:', error);
            showOtpError(error.message);
            VW.setButtonLoading(applyOtpBtn, '', false);
        }
    });

    // Allow submitting the OTP via Enter key
    otpInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') applyOtpBtn.click();
    });

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    // Spinner markup used while a deletion step is in flight.
    const loadingHtml = text => `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>${text}`;

    function showOtpError(message) {
        if (!otpError) return;
        otpError.textContent = message;
        otpError.classList.remove('d-none');
    }

    function hideOtpError() {
        if (!otpError) return;
        otpError.textContent = '';
        otpError.classList.add('d-none');
    }

    function resetOtpForm() {
        if (otpInput) otpInput.value = '';
        hideOtpError();
        if (applyOtpBtn && applyOtpBtn.dataset.originalHtml) {
            applyOtpBtn.innerHTML = applyOtpBtn.dataset.originalHtml;
            delete applyOtpBtn.dataset.originalHtml;
            applyOtpBtn.disabled = false;
        }
    }

    function showConfirmModalError(message) {
        // Insert an inline error alert in the confirmation modal body if possible
        const body = confirmDeleteModal.querySelector('.modal-body');
        if (!body) return;

        let errEl = body.querySelector('.delete-confirm-error');
        if (!errEl) {
            errEl = document.createElement('div');
            errEl.className = 'alert alert-danger mt-3 delete-confirm-error';
            body.appendChild(errEl);
        }
        errEl.textContent = message;
    }
})();
