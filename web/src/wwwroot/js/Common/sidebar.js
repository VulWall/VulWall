(function () {
    function init() {
        var offcanvasEl = document.getElementById("sidebarOffcanvas");
        if (!offcanvasEl) return;

        // Close the offcanvas when a nav link is clicked (mobile only)
        var navLinks = offcanvasEl.querySelectorAll(".nav-link");
        navLinks.forEach(function (link) {
            link.addEventListener("click", function () {
                var instance = bootstrap.Offcanvas.getInstance(offcanvasEl);
                if (instance) {
                    instance.hide();
                }
            });
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();

// ---- Next-scan countdown widget ----
(function () {
    var dataEl = document.getElementById("next-scan-data");
    if (!dataEl) return;

    var nextUtc, periodStartUtc;
    try {
        var data = JSON.parse(dataEl.textContent);
        nextUtc = new Date(data.nextUtc).getTime();
        periodStartUtc = new Date(data.periodStartUtc).getTime();
    } catch (e) {
        return;
    }

    var $time  = document.querySelector("[data-next-scan-countdown]");
    var $clock = document.querySelector("[data-next-scan-clock]");
    var $fill  = document.querySelector("[data-next-scan-fill]");
    if (!$time || !$clock || !$fill) return;

    // Set the scheduled day and time once (doesn't change), in the browser's locale and time zone
    $clock.textContent = new Date(nextUtc).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });

    function pad(n) { return String(n).padStart(2, "0"); }

    function fmtCountdown(ms) {
        if (ms <= 0) return "Scan due";
        var t = Math.floor(ms / 1000);
        var d = Math.floor(t / 86400);
        var h = Math.floor((t % 86400) / 3600);
        var m = Math.floor((t % 3600) / 60);
        var s = t % 60;
        if (d > 0) return d + "d " + h + "h " + pad(m) + "m";
        if (h > 0) return h + "h " + pad(m) + "m " + pad(s) + "s";
        return m + "m " + pad(s) + "s";
    }

    function tick() {
        var now = Date.now();
        var remaining = nextUtc - now;
        var period = nextUtc - periodStartUtc;
        var elapsed = now - periodStartUtc;
        var pct = period > 0 ? Math.max(0, Math.min(100, (elapsed / period) * 100)) : 0;

        $time.textContent = fmtCountdown(remaining);
        $fill.style.width = pct.toFixed(1) + "%";

        if (remaining <= 0) {
            clearInterval(interval);
        }
    }

    // Render at once, then every second: no placeholder dash on page load.
    var interval = setInterval(tick, 1000);
    tick();
})();
