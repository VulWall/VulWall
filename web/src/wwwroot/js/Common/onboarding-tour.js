/**
 * VulWall Onboarding Tour
 * A lightweight, accessible tour system for first-time users
 */

const TOUR_STORAGE_KEY = 'vulwall_tour_completed';

const tourSteps = [
    {
        id: 'welcome',
        type: 'modal',
        title: 'Welcome to VulWall!',
        description: "Let's take a quick tour to help you get started with your security dashboard."
    },
    {
        id: 'sidebar',
        target: '[data-tour="sidebar"]',
        position: 'right',
        title: 'Navigation',
        icon: 'fa-compass',
        description: 'Access all sections from here: Dashboard, Assets, Scans, Discoveries, Recommendations, Reports, and Settings.'
    },
    {
        id: 'security-score',
        target: '[data-tour="security-score"]',
        position: 'bottom',
        title: 'Security score',
        icon: 'fa-shield-alt',
        description: 'Your overall security health indicator. Higher scores mean better security posture across all your assets.'
    },
    {
        id: 'discovered-assets',
        target: '[data-tour="discovered-assets"]',
        position: 'bottom',
        title: 'Discovered assets',
        icon: 'fa-eye',
        description: 'Verified discoveries from your latest scan: domains, subdomains, IPs, open ports, and running services.'
    },
    {
        id: 'critical-issues',
        target: '[data-tour="critical-issues"]',
        position: 'bottom',
        title: 'Critical & high issues',
        icon: 'fa-exclamation-triangle',
        description: 'Priority vulnerabilities that need immediate attention. Click to see remediation steps.'
    },
    {
        id: 'fix-now',
        target: '[data-tour="fix-now"]',
        position: 'top',
        title: 'Fix now',
        icon: 'fa-wrench',
        description: 'Your most critical vulnerabilities and how to fix them. Set an AI API key (AI_API_KEY) and AI writes more detailed guidance.'
    },
    {
        id: 'timeline',
        target: '[data-tour="timeline"]',
        position: 'top',
        title: 'Security timeline',
        icon: 'fa-chart-line',
        description: 'Track your security posture over time. See trends in vulnerabilities and score changes.'
    },
    {
        id: 'recent-scans',
        target: '[data-tour="recent-scans"]',
        position: 'top',
        title: 'Recent scans',
        icon: 'fa-satellite-dish',
        description: 'View your latest scan activities and their results at a glance.'
    },
    {
        id: 'theme-controls',
        target: '#themeToggle',
        position: 'left',
        title: 'Theme & controls',
        icon: 'fa-adjust',
        description: 'Toggle between light and dark themes. Your preference is saved automatically.'
    }
];

class OnboardingTour {
    constructor() {
        this.currentStep = 0;
        this.isActive = false;
        this.backdrop = null;
        this.tooltip = null;
        this.highlightedElement = null;
        this.tourConfig = OnboardingTour.loadTourConfig();
    }

    static loadTourConfig() {
        try {
            const el = document.getElementById('tour-config');
            return el ? JSON.parse(el.textContent) : {};
        } catch (error) {
            console.warn('Failed to parse tour config:', error);
            return {};
        }
    }

    /**
     * Check if tour should be shown
     */
    shouldShowTour() {
        // Check localStorage first for fast response
        if (localStorage.getItem(TOUR_STORAGE_KEY) === 'true') {
            return false;
        }

        // Check server-side state from cached tour config
        const tourCompleted = this.tourConfig.tourCompleted === true;
        if (tourCompleted) {
            // Sync to localStorage for future fast checks
            localStorage.setItem(TOUR_STORAGE_KEY, 'true');
            return false;
        }

        return true;
    }

    /**
     * Start the tour
     */
    start() {
        if (this.isActive) return;

        this.isActive = true;
        this.currentStep = 0;
        this.createBackdrop();
        this.renderStep();
        this.bindKeyboardEvents();

        document.body.style.overflow = 'hidden';
    }

    /**
     * Create the backdrop element
     */
    createBackdrop() {
        this.backdrop = document.createElement('div');
        this.backdrop.className = 'tour-backdrop';
        document.body.appendChild(this.backdrop);

        // Fade in backdrop
        requestAnimationFrame(() => {
            this.backdrop.classList.add('active');
        });
    }

    /**
     * Render the current step
     */
    renderStep() {
        const step = tourSteps[this.currentStep];

        // Remove any existing tooltip
        this.cleanup();

        if (step.type === 'modal') {
            this.renderWelcomeModal(step);
        } else {
            this.renderTooltip(step);
        }
    }

    /**
     * Render welcome modal (first step)
     */
    renderWelcomeModal(step) {
        const modal = document.createElement('div');
        modal.className = 'tour-welcome-modal';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'tour-welcome-title');

        modal.innerHTML = `
            <div class="tour-welcome-header">
                <div class="tour-welcome-icon">
                    <i class="fas fa-rocket"></i>
                </div>
                <h2 class="tour-welcome-title" id="tour-welcome-title">${step.title}</h2>
                <p class="tour-welcome-subtitle">${step.description}</p>
            </div>
            <div class="tour-welcome-content">
                <ul class="tour-welcome-features">
                    <li><i class="fas fa-check"></i> Monitor your domains and IPs</li>
                    <li><i class="fas fa-check"></i> Scans on the schedule you choose</li>
                    <li><i class="fas fa-check"></i> Fix guidance, with optional AI help</li>
                    <li><i class="fas fa-check"></i> Generate security reports</li>
                </ul>
                <div class="tour-welcome-actions">
                    <button class="tour-btn tour-btn-skip" data-action="skip">Skip tour</button>
                    <button class="tour-btn tour-btn-next" data-action="next">
                        <i class="fas fa-play me-1"></i>Start tour
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        this.tooltip = modal;

        // Bind click events
        modal.querySelector('[data-action="skip"]').addEventListener('click', () => this.endTour());
        modal.querySelector('[data-action="next"]').addEventListener('click', () => this.nextStep());

        // Focus the start button
        modal.querySelector('[data-action="next"]').focus();
    }

    /**
     * Render tooltip for element-targeted steps
     */
    renderTooltip(step) {
        const target = document.querySelector(step.target);

        if (!target) {
            // Skip to next step if target not found
            this.nextStep();
            return;
        }

        // Highlight target element
        this.highlightElement(target);

        // Create tooltip
        const tooltip = document.createElement('div');
        tooltip.className = 'tour-tooltip';
        tooltip.setAttribute('role', 'dialog');
        tooltip.setAttribute('aria-modal', 'true');
        tooltip.setAttribute('data-position', step.position);

        const isLastStep = this.currentStep === tourSteps.length - 1;

        tooltip.innerHTML = `
            <div class="tour-header">
                <h3 class="tour-title">
                    <i class="fas ${step.icon}"></i>
                    ${step.title}
                </h3>
            </div>
            <div class="tour-content">
                <p class="tour-description">${step.description}</p>
            </div>
            <div class="tour-footer">
                <div class="tour-progress">
                    ${this.renderProgressDots()}
                    <span class="tour-step-counter">${this.currentStep}/${tourSteps.length - 1}</span>
                </div>
                <div class="tour-nav">
                    <button class="tour-btn tour-btn-skip" data-action="skip">Skip</button>
                    ${this.currentStep > 1 ? '<button class="tour-btn tour-btn-prev" data-action="prev"><i class="fas fa-chevron-left"></i></button>' : ''}
                    <button class="tour-btn ${isLastStep ? 'tour-btn-finish' : 'tour-btn-next'}" data-action="${isLastStep ? 'finish' : 'next'}">
                        ${isLastStep ? '<i class="fas fa-check me-1"></i>Done' : 'Next<i class="fas fa-chevron-right ms-1"></i>'}
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(tooltip);
        this.tooltip = tooltip;

        // Position the tooltip
        this.positionTooltip(tooltip, target, step.position);

        // Bind click events
        tooltip.querySelector('[data-action="skip"]').addEventListener('click', () => this.endTour());
        const prevBtn = tooltip.querySelector('[data-action="prev"]');
        if (prevBtn) prevBtn.addEventListener('click', () => this.prevStep());

        const nextBtn = tooltip.querySelector('[data-action="next"]');
        const finishBtn = tooltip.querySelector('[data-action="finish"]');
        if (nextBtn) nextBtn.addEventListener('click', () => this.nextStep());
        if (finishBtn) finishBtn.addEventListener('click', () => this.endTour());

        // Focus next/finish button
        (nextBtn || finishBtn).focus();
    }

    /**
     * Render progress dots
     */
    renderProgressDots() {
        return tourSteps.slice(1).map((_, index) => {
            const stepIndex = index + 1;
            let className = 'tour-dot';
            if (stepIndex < this.currentStep) className += ' completed';
            else if (stepIndex === this.currentStep) className += ' active';
            return `<span class="${className}"></span>`;
        }).join('');
    }

    /**
     * Highlight target element
     */
    highlightElement(element) {
        if (this.highlightedElement) {
            this.highlightedElement.removeAttribute('data-tour-highlight');
        }

        element.setAttribute('data-tour-highlight', 'true');
        this.highlightedElement = element;

        // Scroll element into view if needed
        element.scrollIntoView({
            behavior: 'smooth',
            block: 'center',
            inline: 'center'
        });
    }

    /**
     * Position tooltip relative to target
     */
    positionTooltip(tooltip, target, position) {
        const targetRect = target.getBoundingClientRect();
        const tooltipRect = tooltip.getBoundingClientRect();
        const padding = 16;
        const arrowOffset = 12;

        let top, left;

        switch (position) {
            case 'top':
                top = targetRect.top - tooltipRect.height - padding - arrowOffset;
                left = targetRect.left + (targetRect.width / 2) - (tooltipRect.width / 2);
                break;
            case 'bottom':
                top = targetRect.bottom + padding + arrowOffset;
                left = targetRect.left + (targetRect.width / 2) - (tooltipRect.width / 2);
                break;
            case 'left':
                top = targetRect.top + (targetRect.height / 2) - (tooltipRect.height / 2);
                left = targetRect.left - tooltipRect.width - padding - arrowOffset;
                break;
            case 'right':
                top = targetRect.top + (targetRect.height / 2) - (tooltipRect.height / 2);
                left = targetRect.right + padding + arrowOffset;
                break;
        }

        // Keep tooltip within viewport
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        if (left < padding) left = padding;
        if (left + tooltipRect.width > viewportWidth - padding) {
            left = viewportWidth - tooltipRect.width - padding;
        }
        if (top < padding) top = padding;
        if (top + tooltipRect.height > viewportHeight - padding) {
            top = viewportHeight - tooltipRect.height - padding;
        }

        tooltip.style.top = `${top}px`;
        tooltip.style.left = `${left}px`;
    }

    /**
     * Go to next step
     */
    nextStep() {
        if (this.currentStep < tourSteps.length - 1) {
            this.currentStep++;
            this.renderStep();
        } else {
            this.endTour();
        }
    }

    /**
     * Go to previous step
     */
    prevStep() {
        if (this.currentStep > 1) {
            this.currentStep--;
            this.renderStep();
        }
    }

    /**
     * End the tour
     */
    endTour() {
        this.isActive = false;

        // Save completion to localStorage immediately
        localStorage.setItem(TOUR_STORAGE_KEY, 'true');

        // Save to server asynchronously
        this.saveCompletionToServer();

        // Cleanup UI
        this.fullCleanup();

        document.body.style.overflow = '';
        this.unbindKeyboardEvents();
    }

    /**
     * Save tour completion to server
     */
    async saveCompletionToServer() {
        try {
            const token = document.querySelector('input[name="__RequestVerificationToken"]')?.value;

            await fetch('/Settings/CompleteTour', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'RequestVerificationToken': token || ''
                }
            });
        } catch (error) {
            console.warn('Failed to save tour completion to server:', error);
        }
    }

    /**
     * Cleanup tooltip and highlight
     */
    cleanup() {
        if (this.tooltip) {
            this.tooltip.remove();
            this.tooltip = null;
        }
        if (this.highlightedElement) {
            this.highlightedElement.removeAttribute('data-tour-highlight');
            this.highlightedElement = null;
        }
    }

    /**
     * Full cleanup including backdrop
     */
    fullCleanup() {
        this.cleanup();
        if (this.backdrop) {
            this.backdrop.classList.remove('active');
            setTimeout(() => {
                this.backdrop?.remove();
                this.backdrop = null;
            }, 300);
        }
    }

    /**
     * Bind keyboard events
     */
    bindKeyboardEvents() {
        this.keyHandler = (e) => {
            if (!this.isActive) return;

            switch (e.key) {
                case 'Escape':
                    e.preventDefault();
                    this.endTour();
                    break;
                case 'ArrowRight':
                case 'Enter':
                    e.preventDefault();
                    if (this.currentStep === tourSteps.length - 1) {
                        this.endTour();
                    } else {
                        this.nextStep();
                    }
                    break;
                case 'ArrowLeft':
                    e.preventDefault();
                    this.prevStep();
                    break;
            }
        };

        document.addEventListener('keydown', this.keyHandler);
    }

    /**
     * Unbind keyboard events
     */
    unbindKeyboardEvents() {
        if (this.keyHandler) {
            document.removeEventListener('keydown', this.keyHandler);
            this.keyHandler = null;
        }
    }
}

// Initialize tour on Dashboard page
function initTour() {
    // Only auto-start on Dashboard page
    const isDashboard = window.location.pathname === '/' ||
                        window.location.pathname.toLowerCase() === '/dashboard' ||
                        window.location.pathname.toLowerCase() === '/dashboard/index';

    if (!isDashboard) return;

    const tour = new OnboardingTour();

    if (tour.shouldShowTour()) {
        // Small delay to ensure page is fully loaded
        setTimeout(() => tour.start(), 500);
    }
}

// Export for external use
window.VulWallTour = OnboardingTour;

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTour);
} else {
    initTour();
}
