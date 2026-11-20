// Type Cards Module
// Handles report type card selection and actions

export function initializeTypeCards() {
    const typeCards = document.querySelectorAll('.report-type-card');

    // Return object with useful methods and data
    return {
        cards: typeCards
    };
}

export function initializeTypeActions(modalHandlers) {
    const typeCards = document.querySelectorAll('.report-type-card');

    // Preview buttons
    const previewButtons = document.querySelectorAll('.btn-preview');
    previewButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.stopPropagation();
            const card = button.closest('.report-type-card');
            const typeId = card.getAttribute('data-type-id');

            // Handle certificate preview - open in new tab
            if (typeId === 'certificate') {
                const orgId = card.getAttribute('data-org-id');
                if (orgId) {
                    window.open(`/certs/${orgId}`, '_blank');
                } else {
                    console.error('Organization ID not found for certificate preview');
                }
                return;
            }

            // Navigate to report preview page with selected scan
            const scanIdInput = document.getElementById('rptSelectedScanId');
            const scanId = scanIdInput ? scanIdInput.value : '';
            const scanParam = scanId ? `?scanId=${encodeURIComponent(scanId)}` : '';

            if (typeId === 'summary') {
                window.location.href = `/Reports/Summary${scanParam}`;
            } else if (typeId === 'technical') {
                window.location.href = `/Reports/Technical${scanParam}`;
            }
        });
    });

    // Generate Link buttons
    const generateLinkButtons = document.querySelectorAll('.btn-generate-link');
    generateLinkButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.stopPropagation();

            // Show generate link modal
            if (modalHandlers && modalHandlers.showGenerateLinkModal) {
                modalHandlers.showGenerateLinkModal();
            }
        });
    });

    // Embed buttons (for certificate)
    const embedButtons = document.querySelectorAll('.btn-embed');
    embedButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.stopPropagation();

            // Show embed code modal
            if (modalHandlers && modalHandlers.showEmbedModal) {
                modalHandlers.showEmbedModal();
            }
        });
    });
}