// Shared Links Module
// Handles shared links table interactions

export function initializeSharedLinks(modalHandlers) {
    // Get the shareable URL for a link token
    function getShareableUrl(token) {
        return `${window.location.origin}/shared-reports/${token}`;
    }

    // Copy Link buttons
    function initializeCopyLinks() {
        const copyLinkButtons = document.querySelectorAll('.btn-copy-link');
        copyLinkButtons.forEach(function(button) {
            button.addEventListener('click', function() {
                // Get the link token from the row's data attribute
                const row = button.closest('tr');
                const token = row ? row.getAttribute('data-link-token') : null;

                if (!token) {
                    console.error('Link token not found');
                    return;
                }

                const shareableUrl = getShareableUrl(token);
                VW.copyWithFeedback(button, shareableUrl);
            });
        });
    }

    // Open in new tab buttons
    function initializeOpenLinks() {
        const openButtons = document.querySelectorAll('.btn-open-link');
        openButtons.forEach(function(button) {
            button.addEventListener('click', function() {
                // Get the link token from the row's data attribute
                const row = button.closest('tr');
                const token = row ? row.getAttribute('data-link-token') : null;

                if (!token) {
                    console.error('Link token not found');
                    return;
                }

                const shareableUrl = getShareableUrl(token);
                window.open(shareableUrl, '_blank');
            });
        });
    }

    // Revoke access buttons
    function initializeRevokeButtons() {
        const revokeButtons = document.querySelectorAll('.btn-revoke');
        revokeButtons.forEach(function(button) {
            button.addEventListener('click', function() {
                const reportName = button.getAttribute('data-report-name');

                // Show revoke modal
                if (modalHandlers && modalHandlers.showRevokeModal) {
                    modalHandlers.showRevokeModal(reportName, button);
                }
            });
        });
    }

    // Initialize all shared links functionality
    initializeCopyLinks();
    initializeOpenLinks();
    initializeRevokeButtons();
}