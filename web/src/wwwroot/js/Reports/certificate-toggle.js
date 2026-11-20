// Certificate Toggle Module
// Handles certificate visibility toggle functionality

export function initializeCertificateToggle() {
    const toggleSwitch = document.getElementById('certVisibilityToggle');
    const certificateCard = document.getElementById('certificateCard');
    const modal = document.getElementById('certVisibilityModal');

    if (!toggleSwitch || !certificateCard || !modal) return;

    const modalInstance = new bootstrap.Modal(modal);
    // Updated selectors for the _ConfirmationModal structure
    const modalMessage = modal.querySelector('.modal-body > p.fw-semibold');
    const dynamicContent = document.getElementById('certModalDynamicContent');
    const confirmButton = document.getElementById('certVisibilityModalConfirm');

    let pendingToggleValue = null;

    // Handle toggle change
    toggleSwitch.addEventListener('change', function(e) {
        const newValue = this.checked;
        pendingToggleValue = newValue;

        // Configure modal based on enable/disable action
        if (newValue) {
            // Enabling certificate
            modalMessage.textContent = 'Are you sure you want to make your certificate publicly visible?';
            dynamicContent.innerHTML = `
                <div class="alert alert-warning mb-0">
                    <p class="fw-semibold mb-2"><i class="fas fa-shield-alt me-2"></i>Security Note:</p>
                    <p class="mb-0">The certificate will be publicly accessible via URL and iframe embed. Only enable this if you want to share your security status publicly.</p>
                </div>
            `;
        } else {
            // Disabling certificate
            modalMessage.textContent = 'Are you sure you want to make your certificate private?';
            dynamicContent.innerHTML = '';
        }

        // Show modal
        modalInstance.show();
    });

    // Handle confirmation
    confirmButton.addEventListener('click', async function() {
        modalInstance.hide();

        const isVisible = pendingToggleValue;

        // Disable toggle during request
        toggleSwitch.disabled = true;

        try {
            // Make API call to update visibility
            const response = await VW.postJson('/Reports/UpdateCertVisibility', null, isVisible);
            const data = await response.json();

            // Update card state using data attributes
            updateCertificateCardState(certificateCard, data.certVisible);
        } catch (error) {
            // Revert toggle on error
            toggleSwitch.checked = !isVisible;
            console.error('Error updating certificate visibility:', error);
        } finally {
            // Re-enable toggle
            toggleSwitch.disabled = false;
            pendingToggleValue = null;
        }
    });

    // Handle modal close (X button, Cancel button, or backdrop click)
    modal.addEventListener('hidden.bs.modal', function() {
        if (pendingToggleValue !== null) {
            // Revert toggle if modal was closed without confirmation
            toggleSwitch.checked = !pendingToggleValue;
            pendingToggleValue = null;
        }
    });

    // Prevent card selection when disabled
    certificateCard.addEventListener('click', function(e) {
        if (this.classList.contains('disabled') && !e.target.closest('#certVisibilityToggle')) {
            e.stopPropagation();
            e.preventDefault();
        }
    });

    // Stop propagation from toggle to prevent card selection
    toggleSwitch.addEventListener('click', function(e) {
        e.stopPropagation();
    });

    // Initialize certificate button handlers
    initializeCertificateButtons();
}

// Centralized state management for certificate card
function updateCertificateCardState(card, isVisible) {
    const statusText = card.querySelector('small.text-muted');

    if (isVisible) {
        card.classList.remove('disabled');
        card.dataset.visible = 'true';
        if (statusText) statusText.textContent = 'Public';
    } else {
        card.classList.add('disabled');
        card.dataset.visible = 'false';
        if (statusText) statusText.textContent = 'Private';
    }
}

// Separate module for certificate button handlers
export function initializeCertificateButtons() {
    const copyCertificateLinkButtons = document.querySelectorAll('.btn-copy-certificate-link');

    copyCertificateLinkButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.stopPropagation();

            const card = button.closest('.report-type-card');

            // Don't allow action if card is disabled
            if (card && card.classList.contains('disabled')) {
                return;
            }

            // Get the certificate URL from data attribute
            const certificatePath = button.getAttribute('data-certificate-url') || '/Certs/default';
            const certificateUrl = window.location.origin + certificatePath;
            VW.copyWithFeedback(button, certificateUrl);
        });
    });
}