document.addEventListener('DOMContentLoaded', function() {
    initializeHeatmap();
    restoreInitialSelection();
    initLiveStatusPolling();
});

function initializeHeatmap() {
    const heatmapWeeks = document.getElementById('heatmapWeeks');
    const heatmapMonthsLabels = document.getElementById('heatmapMonthsLabels');

    if (!heatmapWeeks || !heatmapMonthsLabels) {
        console.warn('Heatmap elements not found');
        return;
    }

    const heatmapDataEl = document.getElementById('heatmap-data');
    if (!heatmapDataEl) {
        console.warn('Heatmap data not found');
        heatmapWeeks.innerHTML = `
            <div class="text-center text-muted py-3">
                <i class="fas fa-exclamation-triangle mb-2"></i>
                <p class="mb-0 small">Failed to load heatmap data</p>
            </div>
        `;
        return;
    }

    try {
        let scansHeatmapData = [];
        try {
            scansHeatmapData = JSON.parse(heatmapDataEl.textContent || '[]');
        } catch (parseError) {
            console.error('Failed to parse heatmap data:', parseError);
            return;
        }
        const scanData = parseScanData(scansHeatmapData);
        const weeks = generateHeatmapData(scanData);
        renderHeatmap(weeks, heatmapWeeks, heatmapMonthsLabels);
    } catch (error) {
        console.error('Error rendering heatmap:', error);
        heatmapWeeks.innerHTML = `
            <div class="text-center text-muted py-3">
                <i class="fas fa-exclamation-triangle mb-2"></i>
                <p class="mb-0 small">Failed to render heatmap</p>
            </div>
        `;
    }
}

function parseScanData(heatmapData) {
    if (!heatmapData || !Array.isArray(heatmapData)) {
        console.warn('Invalid heatmap data');
        return [];
    }

    return heatmapData.map(scan => {
        const [year, month, day] = scan.date.split('-').map(Number);
        const date = new Date(year, month - 1, day);

        return {
            date: date,
            critical: scan.critical,
            high: scan.high,
            medium: scan.medium,
            low: scan.low,
            scanId: scan.scanId || null,
            scanType: scan.scanType || null
        };
    });
}

function generateHeatmapData(scanData) {
    const weeks = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const jan1 = new Date(today.getFullYear(), 0, 1);
    jan1.setHours(0, 0, 0, 0);

    const scansByDate = new Map();
    scanData.forEach(scan => {
        // Use local date format to match the loop below
        const dateKey = scan.date.getFullYear() + '-' +
            String(scan.date.getMonth() + 1).padStart(2, '0') + '-' +
            String(scan.date.getDate()).padStart(2, '0');
        if (!scansByDate.has(dateKey)) {
            scansByDate.set(dateKey, []);
        }
        scansByDate.get(dateKey).push(scan);
    });

    // Build set of scheduled dates for quick lookup (passed via JSON block to comply with CSP)
    let scheduledScanDates = [];
    try {
        const el = document.getElementById('scheduled-scan-dates');
        if (el) scheduledScanDates = JSON.parse(el.textContent);
    } catch (error) {
        console.warn('Failed to parse scheduled scan dates:', error);
    }
    const scheduledDates = new Set(scheduledScanDates || []);

    // Start weeks on Monday to match row labels (Mon-Sun)
    const startDate = new Date(jan1);
    const dayOfWeek = startDate.getDay();
    const mondayOffset = (dayOfWeek === 0) ? 6 : dayOfWeek - 1; // days since Monday
    if (mondayOffset !== 0) {
        startDate.setDate(startDate.getDate() - mondayOffset);
    }

    let currentDate = new Date(startDate);
    let currentWeek = [];

    const dec31 = new Date(today.getFullYear(), 11, 31);
    dec31.setHours(0, 0, 0, 0);
    const endDate = new Date(dec31);
    const dec31Day = dec31.getDay();
    const daysUntilSunday = (dec31Day === 0) ? 0 : 7 - dec31Day; // pad to Sunday
    endDate.setDate(endDate.getDate() + daysUntilSunday);

    // Pre-compute today string for comparison
    const todayStr = today.getFullYear() + '-' +
        String(today.getMonth() + 1).padStart(2, '0') + '-' +
        String(today.getDate()).padStart(2, '0');

    while (currentDate <= endDate) {
        // Use local date to match scheduled dates from server (which are in UTC but date-only)
        const dateStr = currentDate.getFullYear() + '-' +
            String(currentDate.getMonth() + 1).padStart(2, '0') + '-' +
            String(currentDate.getDate()).padStart(2, '0');
        const dayScans = scansByDate.get(dateStr) || [];
        const severityCounts = dayScans.reduce((acc, scan) => ({
            critical: acc.critical + scan.critical,
            high: acc.high + scan.high,
            medium: acc.medium + scan.medium,
            low: acc.low + scan.low
        }), { critical: 0, high: 0, medium: 0, low: 0 });

        // Check if this is a future or today's scheduled date
        const isFutureOrToday = dateStr >= todayStr;
        const isScheduled = isFutureOrToday && scheduledDates.has(dateStr);

        let severity = 'no-scan';
        if (isScheduled) {
            severity = 'scheduled';
        } else if (dayScans.length > 0) {
            if (severityCounts.critical > 0) severity = 'severity-critical';
            else if (severityCounts.high > 0) severity = 'severity-high';
            else if (severityCounts.medium > 0) severity = 'severity-medium';
            else if (severityCounts.low > 0) severity = 'severity-low';
            else severity = 'severity-none';
        }

        // When multiple scans land on the same day, the latest one wins as the selectable target
        const scanId = dayScans.length > 0 ? dayScans[dayScans.length - 1].scanId : null;
        const scanTypes = [...new Set(dayScans.map(s => s.scanType).filter(Boolean))];

        currentWeek.push({
            date: new Date(currentDate),
            severity,
            isOutOfRange: currentDate < jan1 || currentDate > dec31,
            scanCount: dayScans.length,
            severityCounts,
            isScheduled,
            scanId,
            scanTypes
        });

        if (currentWeek.length === 7) {
            weeks.push(currentWeek);
            currentWeek = [];
        }

        currentDate.setDate(currentDate.getDate() + 1);
    }

    if (currentWeek.length > 0) {
        weeks.push(currentWeek);
    }

    return weeks;
}

function renderHeatmap(weeks, weeksContainer, monthsContainer) {
    weeksContainer.innerHTML = '';
    monthsContainer.innerHTML = '';

    let tooltip = document.getElementById('heatmap-tooltip');
    if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.id = 'heatmap-tooltip';
        tooltip.className = 'heatmap-tooltip';
        document.body.appendChild(tooltip);
    }

    let currentMonth = -1;
    let weekPosition = 0;

    weeks.forEach(week => {
        const weekDiv = document.createElement('div');
        weekDiv.className = 'heatmap-week';

        week.forEach(day => {
            const cell = document.createElement('div');
            cell.className = `heatmap-cell ${day.severity}`;

            if (day.isOutOfRange) {
                cell.classList.add('out-of-range');
            }

            if (!day.isOutOfRange) {
                cell.addEventListener('mouseenter', (e) => showHeatmapTooltip(e, day, tooltip));
                cell.addEventListener('mouseleave', () => hideHeatmapTooltip(tooltip));

                // Days with a completed scan become selectable compare targets
                if (day.scanCount > 0 && day.scanId) {
                    const dateLabel = day.date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
                    cell.dataset.scanId = day.scanId;
                    cell.dataset.dateLabel = dateLabel;
                    cell.addEventListener('click', () => onHeatmapCellClick(cell, day.scanId, dateLabel));
                }
            }

            weekDiv.appendChild(cell);
        });

        weeksContainer.appendChild(weekDiv);

        const firstNonOutOfRangeDay = week.find(day => !day.isOutOfRange);
        if (firstNonOutOfRangeDay && firstNonOutOfRangeDay.date.getMonth() !== currentMonth) {
            currentMonth = firstNonOutOfRangeDay.date.getMonth();
            const monthLabel = document.createElement('span');
            monthLabel.className = 'month-label';
            monthLabel.textContent = firstNonOutOfRangeDay.date.toLocaleDateString('en-US', { month: 'short' });
            monthLabel.style.left = `${weekPosition * 18}px`; // 14px cell + 4px gap
            monthsContainer.appendChild(monthLabel);
        }

        weekPosition++;
    });
}

function showHeatmapTooltip(event, day, tooltip) {
    const dateStr = day.date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric'
    });

    let content = `<div class="tooltip-date">${dateStr}</div>`;

    // Handle scheduled scans
    if (day.isScheduled) {
        const relativeTime = getRelativeTime(day.date);
        content += `<div class="tooltip-scheduled"><i class="fas fa-clock"></i> Scheduled scan ${relativeTime}</div>`;
        tooltip.innerHTML = content;
        tooltip.style.display = 'block';
        positionTooltip(event, tooltip);
        return;
    }

    const counts = day.severityCounts;
    const severities = [
        { name: 'Critical', value: counts.critical, class: 'severity-critical' },
        { name: 'High', value: counts.high, class: 'severity-high' },
        { name: 'Medium', value: counts.medium, class: 'severity-medium' },
        { name: 'Low', value: counts.low, class: 'severity-low' }
    ].filter(s => s.value > 0);

    content += `<div class="tooltip-scans">${day.scanCount} scan${day.scanCount !== 1 ? 's' : ''}</div>`;

    if (day.scanTypes && day.scanTypes.length > 0) {
        const typeLabels = day.scanTypes.map(t => t === 'Requested'
            ? '<i class="fas fa-bolt"></i> On-demand'
            : '<i class="fas fa-calendar-alt"></i> Scheduled');
        content += `<div class="tooltip-scan-type">${typeLabels.join(' &amp; ')}</div>`;
    }

    if (severities.length > 0) {
        content += '<div class="tooltip-severities">';
        severities.forEach(s => {
            content += `<div class="severity-item"><span class="severity-dot ${s.class}"></span> ${s.name}: ${s.value}</div>`;
        });
        content += '</div>';
    } else if (day.scanCount > 0) {
        content += '<div class="tooltip-no-issues">No issues found</div>';
    }

    tooltip.innerHTML = content;
    tooltip.style.display = 'block';
    positionTooltip(event, tooltip);
}

function positionTooltip(event, tooltip) {
    const rect = event.target.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();

    let left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
    let top = rect.top - tooltipRect.height - 8;

    if (left < 5) left = 5;
    if (left + tooltipRect.width > window.innerWidth - 5) {
        left = window.innerWidth - tooltipRect.width - 5;
    }
    if (top < 5) {
        top = rect.bottom + 8;
    }

    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
}

function getRelativeTime(date) {
    const now = new Date();
    now.setHours(0, 0, 0, 0);
    const target = new Date(date);
    target.setHours(0, 0, 0, 0);

    const diffMs = target - now;
    const diffDays = Math.round(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'today';
    if (diffDays === 1) return 'tomorrow';
    if (diffDays < 7) return `in ${diffDays} days`;
    if (diffDays < 14) return 'in 1 week';
    if (diffDays < 30) return `in ${Math.round(diffDays / 7)} weeks`;
    return `in ${Math.round(diffDays / 30)} month${Math.round(diffDays / 30) > 1 ? 's' : ''}`;
}

function hideHeatmapTooltip(tooltip) {
    tooltip.style.display = 'none';
}

// --- Compare selection ---

// Track up to two selected scan cells: [{ element, scanId, dateLabel }]
let selectedCells = [];

function onHeatmapCellClick(cell, scanId, dateLabel) {
    // Clicking an already-selected cell deselects it
    const existingIdx = selectedCells.findIndex(s => s.scanId === scanId);
    if (existingIdx !== -1) {
        cell.classList.remove('selected');
        selectedCells.splice(existingIdx, 1);
        updateSelectionPill();
        return;
    }

    // Two already selected: start a fresh selection from this cell
    if (selectedCells.length >= 2) {
        selectedCells.forEach(s => s.element.classList.remove('selected'));
        selectedCells = [];
    }

    cell.classList.add('selected');
    selectedCells.push({ element: cell, scanId, dateLabel });
    updateSelectionPill();

    if (selectedCells.length === 2) {
        loadComparison(selectedCells[0].scanId, selectedCells[1].scanId);
    }
}

function updateSelectionPill() {
    const pill = document.getElementById('selectionPill');
    const pillText = document.getElementById('selectionPillText');
    if (!pill || !pillText) return;

    if (selectedCells.length === 0) {
        pill.style.display = 'none';
    } else if (selectedCells.length === 1) {
        pill.style.display = '';
        pillText.textContent = selectedCells[0].dateLabel + ' selected';
    } else {
        pill.style.display = '';
        pillText.textContent = selectedCells[0].dateLabel + ' & ' + selectedCells[1].dateLabel + ' selected';
    }
}

async function loadComparison(id1, id2) {
    const region = document.getElementById('comparisonRegion');
    if (!region) return;

    region.innerHTML = '<div class="text-center py-5 text-muted"><i class="fas fa-spinner fa-spin fa-2x"></i></div>';

    try {
        const res = await fetch(`/Scans/GetComparison?from=${encodeURIComponent(id1)}&to=${encodeURIComponent(id2)}`);
        if (!res.ok) throw new Error('Failed to load comparison');
        region.innerHTML = await res.text();
    } catch (err) {
        console.error('Compare fetch error:', err);
        region.innerHTML = '<div class="text-center py-4 text-muted">Failed to load comparison. Please try again.</div>';
    }
}

function restoreInitialSelection() {
    try {
        const el = document.getElementById('initial-comparison');
        if (!el) return;
        const data = JSON.parse(el.textContent);
        if (!data.baselineId || !data.latestId) return;

        // Mark the pre-rendered pair as selected so the heatmap matches the server-rendered diff
        [data.baselineId, data.latestId].forEach(id => {
            const cell = document.querySelector(`[data-scan-id="${CSS.escape(id)}"]`);
            if (cell) {
                cell.classList.add('selected');
                selectedCells.push({ element: cell, scanId: id, dateLabel: cell.dataset.dateLabel || id });
            }
        });
        updateSelectionPill();
    } catch (e) {
        console.warn('Could not restore initial selection', e);
    }
}

// Live status polling — refreshes the #liveScanStatus fragment every 10s
// ponytail: polls unconditionally while page is open; gate to running-only in Pass 2 if chatty
function initLiveStatusPolling() {
    const container = document.getElementById('liveScanStatus');
    if (!container) return;

    let inFlight = false;

    async function poll() {
        if (inFlight || document.hidden) return;
        inFlight = true;
        try {
            const res = await fetch('/Scans/LiveStatus', { cache: 'no-store' });
            if (res.ok) {
                container.innerHTML = await res.text();
            }
        } catch (err) {
            console.error('Live status poll failed:', err);
        } finally {
            inFlight = false;
        }
    }

    setInterval(poll, 10_000);
}
