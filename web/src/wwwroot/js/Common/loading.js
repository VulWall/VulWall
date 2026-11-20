// Global Loading Bar
// Shows a progress bar at the top of the page during navigation and form submissions
(function () {
    const bar = document.getElementById('loadingBar');
    if (!bar) return;

    let active = false;

    function start() {
        if (active) return;
        active = true;
        bar.classList.remove('done');
        // Force reflow to restart animation
        bar.offsetWidth;
        bar.classList.add('active');
    }

    function isNavigatingAway(anchor) {
        if (!anchor || !anchor.href) return false;
        // Skip javascript:, mailto:, tel:, #hash links
        if (/^(javascript|mailto|tel):/.test(anchor.href)) return false;
        if (anchor.getAttribute('href')?.startsWith('#')) return false;
        // Skip links that open in new tab
        if (anchor.target === '_blank') return false;
        // Skip download links
        if (anchor.hasAttribute('download')) return false;
        return true;
    }

    // Intercept link clicks
    document.addEventListener('click', function (e) {
        var anchor = e.target.closest('a');
        if (anchor && isNavigatingAway(anchor) && !e.defaultPrevented) {
            start();
        }
    });

    // Intercept form submissions
    document.addEventListener('submit', function () {
        start();
    });

    // Catch all navigation including programmatic (window.location.href = ...)
    window.addEventListener('beforeunload', function () {
        start();
    });

    // Reset the bar when navigating back via cache
    window.addEventListener('pageshow', function (e) {
        if (e.persisted) {
            bar.classList.remove('active');
            bar.classList.remove('done');
            active = false;
        }
    });
})();