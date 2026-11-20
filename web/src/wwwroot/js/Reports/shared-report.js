// Shared report page. The CSP (script-src 'self') blocks inline handlers, so the print button
// is wired here.
document.getElementById('printReportBtn')?.addEventListener('click', () => window.print());
