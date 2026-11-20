// Report "Print / Save as PDF" button: opens the browser's print dialog, where
// "Save as PDF" is one of the destinations. The print CSS hides the toolbar.
document.querySelectorAll('[data-report-print]').forEach(button => {
    button.addEventListener('click', () => window.print());
});
