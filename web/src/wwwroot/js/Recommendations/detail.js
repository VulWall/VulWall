// Handle collapse icon rotation for collapsible sections
document.addEventListener('DOMContentLoaded', () => {
    const collapsibles = document.querySelectorAll('.recommendation-section.collapsible');

    collapsibles.forEach(section => {
        const collapseEl = section.querySelector('.collapse');
        if (!collapseEl) return;

        collapseEl.addEventListener('show.bs.collapse', () => {
            section.classList.remove('collapsed');
        });

        collapseEl.addEventListener('hide.bs.collapse', () => {
            section.classList.add('collapsed');
        });
    });
});
