(function () {
    const KEY  = "theme";
    const root = document.documentElement;
    let themeToggleBtn = null;
    let sunIcon = null;
    let moonIcon = null;

    function applyTheme(theme) {
        if (theme !== "dark" && theme !== "light") return;
        root.setAttribute("data-bs-theme", theme);
        root.style.colorScheme = theme;

        if (!themeToggleBtn) {
            themeToggleBtn = document.getElementById("themeToggle");
            if (themeToggleBtn) {
                sunIcon = themeToggleBtn.querySelector('.theme-icon-light');
                moonIcon = themeToggleBtn.querySelector('.theme-icon-dark');
            }
        }

        if (themeToggleBtn) {
            themeToggleBtn.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");

            // Toggle sun/moon icons using classList
            if (sunIcon && moonIcon) {
                sunIcon.classList.toggle('d-none', theme !== 'dark');
                moonIcon.classList.toggle('d-none', theme === 'dark');
            }
        }

        try {
            localStorage.setItem(KEY, theme);
        } catch (e) {
            if (console && console.warn) {
                console.warn('Failed to save theme preference:', e);
            }
        }
    }

    function init() {
        applyTheme(root.getAttribute("data-bs-theme") || "light");

        if (themeToggleBtn) {
            themeToggleBtn.addEventListener("click", () => {
                const next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
                applyTheme(next);
            });
        }
    }
    
    window.addEventListener("storage", (e) => {
        if (e.key === KEY && e.newValue) applyTheme(e.newValue);
    });

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
