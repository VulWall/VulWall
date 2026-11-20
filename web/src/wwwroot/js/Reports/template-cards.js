// Type Cards Module
// Handles report type card selection and actions

export function initializeTypeCards() {
    const typeCards = document.querySelectorAll('.report-type-card');

    // Return object with useful methods and data
    return {
        cards: typeCards
    };
}

export function initializeTypeActions() {
    // Preview buttons
    const previewButtons = document.querySelectorAll('.btn-preview');
    previewButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.stopPropagation();
            const card = button.closest('.report-type-card');
            const typeId = card.getAttribute('data-type-id');

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
}