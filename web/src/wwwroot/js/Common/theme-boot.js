/**
 * Theme initialization script
 * Runs immediately to prevent flash of wrong theme
 * Priority: User's saved preference > Browser preference > Light (default)
 */
(function () {
    const STORAGE_KEY = "theme";
    const root = document.documentElement;

    function getBrowserPreference() {
        if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
            return "dark";
        }
        if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
            return "light";
        }
        return "light"; // Default fallback
    }

    function getTheme() {
        try {
            // Check if user has explicitly chosen a theme
            const saved = localStorage.getItem(STORAGE_KEY);
            if (saved === "dark" || saved === "light") {
                return saved;
            }

            // No saved preference, use browser/system preference
            return getBrowserPreference();
        } catch (e) {
            // localStorage might be blocked (private browsing, etc)
            return getBrowserPreference();
        }
    }

    const theme = getTheme();
    root.setAttribute("data-bs-theme", theme);
    root.style.colorScheme = theme;
})();
