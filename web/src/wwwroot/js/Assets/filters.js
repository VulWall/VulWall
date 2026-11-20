document.addEventListener('DOMContentLoaded', function () {
    const searchInput = document.getElementById('search');
    const tbody = document.getElementById('assets-tbody');
    const shownEl = document.getElementById('assets-shown');

    let activeType = 'all';
    let activeStatus = 'all';

    function applyFilters() {
        if (!tbody) return;
        const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
        const rows = tbody.querySelectorAll('.asset-row');
        let visible = 0;

        rows.forEach(row => {
            const name = (row.dataset.assetName || '');
            const type = (row.dataset.assetType || '');
            const status = (row.dataset.assetStatus || '');

            const matchName   = !q || name.includes(q);
            const matchType   = activeType === 'all' || type === activeType;
            const matchStatus = activeStatus === 'all' || status === activeStatus;

            if (matchName && matchType && matchStatus) {
                row.style.display = '';
                visible++;
            } else {
                row.style.display = 'none';
            }
        });

        if (shownEl) shownEl.textContent = visible;

        // Empty state
        let emptyEl = tbody.querySelector('#no-results-row');
        if (visible === 0 && rows.length > 0) {
            if (!emptyEl) {
                emptyEl = document.createElement('div');
                emptyEl.id = 'no-results-row';
                emptyEl.className = 'assets-empty';
                emptyEl.innerHTML = '<i class="fas fa-search"></i><p>No assets match your filters.</p>';
                tbody.appendChild(emptyEl);
            }
            emptyEl.style.display = '';
        } else if (emptyEl) {
            emptyEl.style.display = 'none';
        }
    }

    // Search
    if (searchInput) {
        searchInput.addEventListener('input', applyFilters);
    }

    // Type filter
    const typeGroup = document.getElementById('typeFilterGroup');
    if (typeGroup) {
        typeGroup.addEventListener('click', function (e) {
            const btn = e.target.closest('.assets-seg-btn[data-filter-type]');
            if (!btn) return;
            VW.activateChip(typeGroup, btn);
            activeType = btn.dataset.filterType;
            applyFilters();
        });
    }

    // Status filter
    const statusGroup = document.getElementById('statusFilterGroup');
    if (statusGroup) {
        statusGroup.addEventListener('click', function (e) {
            const btn = e.target.closest('.assets-seg-btn[data-filter-status]');
            if (!btn) return;
            VW.activateChip(statusGroup, btn);
            activeStatus = btn.dataset.filterStatus;
            applyFilters();
        });
    }

    // index.js dispatches this after DOM mutations (toggle/delete) so filters stay in sync.
    document.addEventListener('assets:changed', applyFilters);
});
