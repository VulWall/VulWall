/**
 * Finding suppression UI logic.
 * Handles the inline dismiss dropdown on the index list and the suppress/undo
 * panel on the detail view. All forms use the server-rendered data-action
 * pattern — no fetch/XHR; just form submission with anti-forgery tokens.
 *
 * Data is passed from the view via:
 *   <script id="suppression-data" type="application/json">...</script>
 */

document.addEventListener('DOMContentLoaded', () => {
    initSuppressionForms();
});

function initSuppressionForms() {
    // Wire up all suppress forms that carry a status select
    document.querySelectorAll('[data-suppress-form]').forEach(form => {
        const statusSelect = form.querySelector('[data-suppress-status]');
        if (!statusSelect) return;

        // Validate status before submit
        form.addEventListener('submit', e => {
            const status = statusSelect.value;
            if (!status) {
                e.preventDefault();
                statusSelect.classList.add('is-invalid');
                return;
            }
            statusSelect.classList.remove('is-invalid');
        });

        statusSelect.addEventListener('change', () => {
            statusSelect.classList.remove('is-invalid');
        });
    });

    // Collapsible note fields: show note field when a status is selected
    document.querySelectorAll('[data-suppress-status]').forEach(select => {
        const form = select.closest('[data-suppress-form]');
        if (!form) return;
        const noteWrapper = form.querySelector('[data-note-wrapper]');
        if (!noteWrapper) return;

        const toggle = () => {
            noteWrapper.style.display = select.value ? '' : 'none';
        };

        toggle();
        select.addEventListener('change', toggle);
    });
}
