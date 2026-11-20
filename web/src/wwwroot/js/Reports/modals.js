// Modals Module
// Handles all modal interactions for the Reports page

export function initializeModals(scans = []) {
    const generateLinkModal = document.getElementById('generateLinkModal');
    const revokeAccessModal = document.getElementById('revokeAccessModal');

    // Resolve a friendly date for the selected scan from the scans passed in by the page entry
    // point so the modal can pre-fill a sensible default report name.
    function getSelectedScanDate(scanId) {
        if (!scanId) return '';
        const scan = scans.find(s => s.id === scanId);
        if (!scan?.createdAt) return '';
        return new Date(scan.createdAt).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
    }

    // Password generation utility
    function generateSecurePassword(length = 16) {
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*';
        const allChars = lowercase + uppercase + numbers + symbols;

        let password = '';

        // Ensure at least one character from each set
        password += lowercase[Math.floor(Math.random() * lowercase.length)];
        password += uppercase[Math.floor(Math.random() * uppercase.length)];
        password += numbers[Math.floor(Math.random() * numbers.length)];
        password += symbols[Math.floor(Math.random() * symbols.length)];

        // Fill the rest with random characters
        for (let i = password.length; i < length; i++) {
            password += allChars[Math.floor(Math.random() * allChars.length)];
        }

        // Shuffle the password
        return password.split('').sort(() => Math.random() - 0.5).join('');
    }

    // Password validation
    function validatePassword(password) {
        const minLength = 8;
        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);

        const errors = [];
        if (password.length < minLength) {
            errors.push(`at least ${minLength} characters`);
        }
        if (!hasUppercase) {
            errors.push('an uppercase letter');
        }
        if (!hasLowercase) {
            errors.push('a lowercase letter');
        }
        if (!hasNumber) {
            errors.push('a number');
        }

        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }

    // Generate Link Modal
    function initializeGenerateLinkModal() {
        const confirmBtn = document.getElementById('confirmGenerateLink');
        const passwordField = document.getElementById('linkPassword');
        const togglePasswordBtn = document.getElementById('togglePassword');
        const generatePasswordBtn = document.getElementById('generatePassword');
        const copyPasswordBtn = document.getElementById('copyPassword');
        const passwordHelpText = document.getElementById('passwordHelpText');
        const reportTitleField = document.getElementById('reportTitle');

        if (!confirmBtn || !passwordField || !togglePasswordBtn || !generatePasswordBtn || !copyPasswordBtn) return;

        // Set default report name when modal is shown
        generateLinkModal.addEventListener('shown.bs.modal', function() {
            const companyName = generateLinkModal.getAttribute('data-company-name') || 'Organization';
            const scanId = document.getElementById('rptSelectedScanId')?.value;
            const scanDate = getSelectedScanDate(scanId);

            // Set default report name
            if (!reportTitleField.value.trim()) {
                reportTitleField.value = scanDate ? `${companyName} - ${scanDate}` : companyName;
            }

            // Clear password field
            passwordField.value = '';
            passwordField.classList.remove('is-invalid');

            // Reset password field to hidden state
            passwordField.type = 'password';
            togglePasswordBtn.innerHTML = '<i class="fas fa-eye"></i>';
        });

        // Toggle password visibility
        togglePasswordBtn.addEventListener('click', function() {
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                togglePasswordBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else {
                passwordField.type = 'password';
                togglePasswordBtn.innerHTML = '<i class="fas fa-eye"></i>';
            }
        });

        // Generate new password button
        generatePasswordBtn.addEventListener('click', function() {
            passwordField.value = generateSecurePassword();
            passwordField.classList.remove('is-invalid');

            // Visual feedback for generation
            const originalHTML = generatePasswordBtn.innerHTML;
            generatePasswordBtn.innerHTML = '<i class="fas fa-check"></i>';
            generatePasswordBtn.classList.add('btn-success');
            generatePasswordBtn.classList.remove('btn-outline-secondary');

            setTimeout(function() {
                generatePasswordBtn.innerHTML = originalHTML;
                generatePasswordBtn.classList.remove('btn-success');
                generatePasswordBtn.classList.add('btn-outline-secondary');
            }, 1000);
        });

        // Copy password button
        copyPasswordBtn.addEventListener('click', function() {
            if (passwordField.value) {
                VW.copyWithFeedback(copyPasswordBtn, passwordField.value);
            }
        });

        confirmBtn.addEventListener('click', async function() {
            const reportTitle = reportTitleField.value;
            const expirationDays = parseInt(document.getElementById('linkExpiration').value);
            const password = passwordField.value;
            const scanIdInput = document.getElementById('rptSelectedScanId');
            const scanId = scanIdInput ? scanIdInput.value : '';

            // Validate required fields
            if (!reportTitle.trim()) {
                reportTitleField.classList.add('is-invalid');
                reportTitleField.focus();
                return;
            }
            reportTitleField.classList.remove('is-invalid');

            if (!scanId) {
                return;
            }

            // Validate password
            if (!password.trim()) {
                passwordField.classList.add('is-invalid');
                passwordHelpText.textContent = 'Password is required';
                passwordHelpText.classList.add('text-danger');
                passwordField.focus();
                return;
            }

            const passwordValidation = validatePassword(password);
            if (!passwordValidation.isValid) {
                passwordField.classList.add('is-invalid');
                passwordHelpText.textContent = `Password must have ${passwordValidation.errors.join(', ')}`;
                passwordHelpText.classList.add('text-danger');
                passwordField.focus();
                return;
            }

            passwordField.classList.remove('is-invalid');
            passwordHelpText.textContent = 'Min 8 characters with uppercase, lowercase, and number';
            passwordHelpText.classList.remove('text-danger');

            // Disable button while creating
            VW.setButtonLoading(confirmBtn, '<i class="fas fa-spinner fa-spin me-1"></i> Creating...', true);

            try {
                const response = await VW.postJson('/Reports/CreateSharedLink', null, {
                    reportName: reportTitle,
                    scanId: scanId,
                    password: password,
                    expirationDays: expirationDays
                });

                const result = await response.json();

                if (result.success) {
                    // Copy link to clipboard
                    await navigator.clipboard.writeText(result.shareableUrl);

                    // Close modal and refresh page
                    const modal = bootstrap.Modal.getInstance(generateLinkModal);
                    modal.hide();

                    // Clear form fields
                    reportTitleField.value = '';
                    passwordField.value = '';

                    // Reload the page to show the new link
                    window.location.reload();
                } else {
                    passwordHelpText.textContent = result.error || 'Failed to create link';
                    passwordHelpText.classList.add('text-danger');
                }
            } catch (error) {
                console.error('Error creating shared link:', error);
                passwordHelpText.textContent = 'An error occurred. Please try again.';
                passwordHelpText.classList.add('text-danger');
            } finally {
                VW.setButtonLoading(confirmBtn, '', false);
            }
        });
    }

    // Revoke Access Modal
    function initializeRevokeModal() {
        let currentRevokeButton = null;
        let currentLinkId = null;

        const showRevokeModal = function(reportName, buttonElement) {
            currentRevokeButton = buttonElement;
            currentLinkId = buttonElement.getAttribute('data-link-id');

            // Update modal with report name dynamically. The name is user-supplied
            // (CreateSharedLink request), so set it via textContent — never parse it as HTML.
            const content = document.getElementById('revokeReportContent');
            if (content) {
                content.innerHTML = '<p class="text-muted small mb-0">Link: <span class="fw-medium"></span></p>';
                content.querySelector('.fw-medium').textContent = reportName ?? '';
            }

            // Show modal
            const modal = new bootstrap.Modal(revokeAccessModal);
            modal.show();
        };

        const confirmBtn = document.getElementById('revokeAccessModalConfirm');
        if (confirmBtn) {
            confirmBtn.addEventListener('click', async function() {
                if (!currentRevokeButton || !currentLinkId) {
                    return;
                }

                // Disable button while revoking
                VW.setButtonLoading(confirmBtn, '<i class="fas fa-spinner fa-spin me-1"></i> Revoking...', true);

                try {
                    const response = await VW.postJson('/Reports/RevokeSharedLink', null, currentLinkId);

                    const result = await response.json();

                    if (result.success) {
                        const row = currentRevokeButton.closest('tr');
                        row.style.opacity = '0.5';

                        // Update expires column to show "Revoked" (Expires is the 4th column)
                        const expiresCell = row.querySelector('td:nth-child(4)');
                        if (expiresCell) {
                            expiresCell.innerHTML = '<span class="sev-badge sev-info">Revoked</span>';
                        }

                        // Show success feedback
                        const actionsCell = currentRevokeButton.closest('td');
                        actionsCell.innerHTML = '<small class="text-muted">Link revoked</small>';
                    } else {
                        VW.showError('Failed to revoke link: ' + (result.error || 'Unknown error'));
                    }
                } catch (error) {
                    console.error('Error revoking shared link:', error);
                    VW.showError('An error occurred while revoking the link. Please try again.');
                } finally {
                    VW.setButtonLoading(confirmBtn, '', false);

                    // Clear references
                    currentRevokeButton = null;
                    currentLinkId = null;

                    // Close modal
                    const modal = bootstrap.Modal.getInstance(revokeAccessModal);
                    modal.hide();
                }
            });
        }

        return { showRevokeModal };
    }

    // Initialize all modals
    initializeGenerateLinkModal();
    const revokeHandlers = initializeRevokeModal();

    // Return modal control functions
    return {
        showGenerateLinkModal: function() {
            const modal = new bootstrap.Modal(generateLinkModal);
            modal.show();
        },
        showRevokeModal: revokeHandlers.showRevokeModal
    };
}