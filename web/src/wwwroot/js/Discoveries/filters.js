// Discoveries page — search + filter chip logic.
// Client-side only, no pagination. If asset count grows into the hundreds,
// move filtering server-side.

let activeFilter = 'all';
let searchTerm = '';

function getRows() {
    return Array.from(document.querySelectorAll('.discovery-row-wrap'));
}

function matchesSearch(row, term) {
    if (!term) return true;
    const name = row.dataset.discoveryName || '';
    const ip = row.dataset.discoveryIp || '';
    return name.includes(term) || ip.includes(term);
}

function matchesFilter(row, filter) {
    if (filter === 'all') return true;
    if (filter === 'triage') return row.dataset.needsTriage === 'true';
    if (filter === 'issues') return row.dataset.hasIssues === 'true';
    return true;
}

function applyFilters() {
    const isFiltering = activeFilter !== 'all' || searchTerm !== '';
    const rows = getRows();
    let visible = 0;
    const visibleParentIds = new Set();

    // First pass: show/hide rows respecting both filter state and tree collapse state.
    rows.forEach(row => {
        const isChild = row.dataset.isChild === 'true';
        const parentId = row.dataset.parentId;
        const matches = matchesSearch(row, searchTerm) && matchesFilter(row, activeFilter);

        let show;
        if (isChild) {
            if (isFiltering) {
                // Active search/filter: show children that match (collapse state ignored).
                show = matches;
            } else {
                // Normal view: respect the parent's expand/collapse state.
                const parentWrap = parentId
                    ? document.querySelector(`.disc-row-wrap[data-discovery-id="${parentId}"]`)
                    : null;
                show = parentWrap?.dataset.expanded === 'true';
            }
        } else {
            show = matches;
        }

        row.style.display = show ? '' : 'none';

        if (show) {
            visible++;
            if (isChild && parentId) visibleParentIds.add(parentId);
        }
    });

    // Second pass (filtering only): if a child matched, ensure its parent is visible.
    if (isFiltering) {
        rows.forEach(row => {
            if (row.dataset.isChild !== 'true' && visibleParentIds.has(row.dataset.discoveryId)) {
                if (row.style.display === 'none') {
                    row.style.display = '';
                    visible++;
                }
            }
        });
    }

    const footerEl = document.getElementById('disc-footer-count');
    if (footerEl) footerEl.textContent = visible;

    let emptyRow = document.getElementById('disc-no-results');
    const tbody = document.getElementById('disc-tbody');
    if (visible === 0 && tbody) {
        if (!emptyRow) {
            emptyRow = document.createElement('div');
            emptyRow.id = 'disc-no-results';
            emptyRow.className = 'disc-empty';
            emptyRow.innerHTML = '<div><i class="fas fa-magnifying-glass"></i></div><div>No assets match your search.</div>';
            tbody.appendChild(emptyRow);
        }
        emptyRow.style.display = '';
    } else if (emptyRow) {
        emptyRow.style.display = 'none';
    }
}

function updateChipCounts() {
    const rows = getRows();
    let triageCount = 0;
    let issuesCount = 0;

    rows.forEach(row => {
        if (row.dataset.needsTriage === 'true') triageCount++;
        if (row.dataset.hasIssues === 'true') issuesCount++;
    });

    const triageStat = document.getElementById('triage-stat-count');
    const chipTriage = document.getElementById('chip-count-triage');
    const chipIssues = document.getElementById('chip-count-issues');
    const chipAll = document.getElementById('chip-count-all');

    if (triageStat) triageStat.textContent = triageCount;
    if (chipTriage) chipTriage.textContent = triageCount;
    if (chipIssues) chipIssues.textContent = issuesCount;
    if (chipAll) chipAll.textContent = rows.length;
}

function initFilters() {
    const searchInput = document.getElementById('disc-search');
    if (searchInput) {
        searchInput.addEventListener('input', e => {
            searchTerm = e.target.value.toLowerCase().trim();
            applyFilters();
        });
    }

    const chipGroup = document.querySelector('.disc-toolbar');
    document.querySelectorAll('.disc-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            VW.activateChip(chipGroup, chip, 'active');
            activeFilter = chip.dataset.filter;
            applyFilters();
        });
    });

    updateChipCounts();

    // index.js dispatches this after an ownership change so counts stay in sync.
    document.addEventListener('disc:ownershipChanged', () => {
        updateChipCounts();
        applyFilters();
    });
}

document.addEventListener('DOMContentLoaded', initFilters);
