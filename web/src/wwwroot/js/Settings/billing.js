(function () {
    'use strict';

    const hash = window.location.hash;
    if (hash) {
        const tabId = hash.replace('#', '') + '-tab';
        const tabButton = document.getElementById(tabId);
        if (tabButton) {
            const tab = new bootstrap.Tab(tabButton);
            tab.show();
        }
    }

    const stripePublishableKeyElement = document.getElementById('stripe-publishable-key');
    if (!stripePublishableKeyElement) {
        console.log('Stripe publishable key not found - billing features disabled');
        return;
    }

    const stripePublishableKey = stripePublishableKeyElement.value;
    if (!stripePublishableKey || stripePublishableKey.includes('REPLACE')) {
        console.warn('Stripe publishable key not configured');
        return;
    }

    const stripe = Stripe(stripePublishableKey);
    const STRIPE_APPEARANCE = {
        theme: 'stripe',
        variables: {
            colorPrimary: '#F47D17',
            colorBackground: '#FBFBFD',
            colorText: '#212C5E',
            fontFamily: 'system-ui, sans-serif',
            borderRadius: '8px'
        }
    };
    let elements;
    let clientSecret;
    let selectedPlan = null;
    let selectedBillingInterval = 'month';

    function showErrorModal(message) {
        const messageEl = document.getElementById('errorModalMessage');
        if (messageEl) messageEl.textContent = message;
        const modalEl = document.getElementById('errorModal');
        if (modalEl) {
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        }
    }

    function getRawPlansData() {
        const plansDataElement = document.getElementById('plans-data');
        return plansDataElement ? JSON.parse(plansDataElement.textContent) : {};
    }

    function getPlansData() {
        const raw = getRawPlansData();
        return raw.plans || raw;
    }

    // Spinner markup used while a billing action is in flight.
    const loadingHtml = text => `<span class="spinner-border spinner-border-sm me-2"></span>${text}`;

    // Event delegation for all billing/plan buttons
    document.addEventListener('click', async (e) => {
        const target = e.target.closest('button, a');
        if (!target) return;

        // Billing interval toggle — must use delegation because the partial loads via AJAX
        if (target.dataset.interval) {
            const toggle = target.closest('#billing-interval-toggle');
            if (toggle) {
                selectedBillingInterval = target.dataset.interval;
                toggle.querySelectorAll('button').forEach(b => {
                    b.classList.remove('btn-primary', 'active');
                    b.classList.add('btn-outline-primary');
                });
                target.classList.remove('btn-outline-primary');
                target.classList.add('btn-primary', 'active');

                document.querySelectorAll('.plan-price').forEach(el => {
                    const monthlyPrice = el.dataset.monthlyPrice;
                    const annualPrice = el.dataset.annualPrice;
                    const amountEl = el.querySelector('.plan-price-amount');
                    const periodEl = el.querySelector('.plan-price-period');
                    const annualNote = el.closest('.mb-3')?.querySelector('.plan-price-annual-note');
                    if (!amountEl || !periodEl) return;

                    if (selectedBillingInterval === 'year') {
                        amountEl.textContent = `€${Math.round(annualPrice / 12)}`;
                        periodEl.textContent = '/mo';
                        if (annualNote) annualNote.style.display = 'block';
                    } else {
                        amountEl.textContent = `€${monthlyPrice}`;
                        periodEl.textContent = '/month';
                        if (annualNote) annualNote.style.display = 'none';
                    }
                });

                updateCurrentPlanButton();
                return;
            }
        }

        if (target.id === 'cancel-subscription-btn' || target.id === 'cancel-subscription-btn-plans') {
            e.preventDefault();
            const modal = new bootstrap.Modal(document.getElementById('cancelSubscriptionModal'));
            modal.show();
        }
        else if (target.id === 'cancelSubscriptionModalConfirm') {
            const modal = bootstrap.Modal.getInstance(document.getElementById('cancelSubscriptionModal'));
            modal?.hide();
            await handleCancelSubscription();
        }
        else if (target.id === 'reactivate-subscription-btn' || target.id === 'reactivate-subscription-btn-plans') {
            e.preventDefault();
            const modal = new bootstrap.Modal(document.getElementById('reactivateSubscriptionModal'));
            modal.show();
        }
        else if (target.id === 'reactivateSubscriptionModalConfirm') {
            const modal = bootstrap.Modal.getInstance(document.getElementById('reactivateSubscriptionModal'));
            modal?.hide();
            await handleReactivateSubscription();
        }
        else if (target.id === 'cancel-incomplete-subscription-btn') {
            e.preventDefault();
            const modal = new bootstrap.Modal(document.getElementById('cancelIncompleteSubscriptionModal'));
            modal.show();
        }
        else if (target.id === 'cancelIncompleteSubscriptionModalConfirm') {
            const modal = bootstrap.Modal.getInstance(document.getElementById('cancelIncompleteSubscriptionModal'));
            modal?.hide();
            await handleCancelIncompleteSubscription();
        }
        else if (target.id === 'complete-payment-btn' || target.id === 'complete-payment-btn-plan') {
            e.preventDefault();
            await handleCompletePaymentClick(target);
        }
        else if (target.classList.contains('subscribe-btn')) {
            e.preventDefault();
            const planName = target.dataset.plan;
            if (planName && planName !== 'Free') {
                await handleSubscribeClick(target, planName);
            }
        }
        else if (target.classList.contains('change-plan-btn')) {
            e.preventDefault();
            const planName = target.dataset.plan;
            await handlePlanChangeClick(target, planName);
        }
        else if (target.id === 'planChangeModalConfirm') {
            const modal = bootstrap.Modal.getInstance(document.getElementById('planChangeModal'));
            modal?.hide();
            const btn = target.dataset.button && document.querySelector(target.dataset.button);
            const planName = target.dataset.planName;
            if (btn && planName) {
                await executePlanChange(btn, planName);
            }
        }
        else if (target.id === 'cancel-payment') {
            hidePaymentForm();
        }
    });

    document.addEventListener('submit', async (e) => {
        if (e.target.id === 'payment-form') {
            e.preventDefault();
            await handlePaymentSubmit();
        }
    });

    async function handleCancelSubscription() {
        const btn = document.getElementById('cancel-subscription-btn') || document.getElementById('cancel-subscription-btn-plans');
        const form = document.getElementById('cancel-subscription-form') || document.getElementById('cancel-subscription-form-plans');
        if (!btn || !form) return;

        try {
            VW.setButtonLoading(btn, loadingHtml('Cancelling...'), true);
            await VW.postJson('/Payments/CancelSubscription', form, {});
            window.location.hash = 'billing';
            window.location.reload();
        } catch (error) {
            console.error('Error:', error);
            showErrorModal(error.message);
            VW.setButtonLoading(btn, '', false);
        }
    }

    async function handleReactivateSubscription() {
        const btn = document.getElementById('reactivate-subscription-btn') || document.getElementById('reactivate-subscription-btn-plans');
        const form = document.getElementById('reactivate-subscription-form') || document.getElementById('reactivate-subscription-form-plans');
        if (!btn || !form) return;

        try {
            VW.setButtonLoading(btn, loadingHtml('Reactivating...'), true);
            await VW.postJson('/Payments/ReactivateSubscription', form, {});
            window.location.hash = 'billing';
            window.location.reload();
        } catch (error) {
            console.error('Error:', error);
            showErrorModal(error.message);
            VW.setButtonLoading(btn, '', false);
        }
    }

    async function handleCancelIncompleteSubscription() {
        const btn = document.getElementById('cancel-incomplete-subscription-btn');
        const form = document.getElementById('incomplete-subscription-actions-form');
        if (!btn || !form) return;

        try {
            VW.setButtonLoading(btn, loadingHtml('Cancelling...'), true);
            await VW.postJson('/Payments/CancelSubscription', form, {});
            window.location.hash = 'billing';
            window.location.reload();
        } catch (error) {
            console.error('Error:', error);
            showErrorModal(error.message);
            VW.setButtonLoading(btn, '', false);
        }
    }

    async function handleSubscribeClick(btn, planName) {
        const plansData = getPlansData();
        selectedPlan = plansData.find(p => p.name === planName);
        if (!selectedPlan) {
            showErrorModal('Plan not found.');
            return;
        }

        try {
            VW.setButtonLoading(btn, loadingHtml('Loading...'), true);

            const form = btn.closest('form');
            if (!form) throw new Error('Form not found');

            const response = await VW.postJson('/Payments/CreateSubscription', form, {
                planName,
                billingInterval: selectedBillingInterval
            });
            const data = await response.json();
            clientSecret = data.clientSecret;

            elements = stripe.elements({ clientSecret, appearance: STRIPE_APPEARANCE });
            const paymentElement = elements.create('payment', { layout: 'tabs' });
            paymentElement.mount('#payment-element');

            updatePaymentSection(selectedPlan);
            showPaymentForm();
        } catch (error) {
            console.error('Error:', error);
            showErrorModal(error.message);
            VW.setButtonLoading(btn, '', false);
        }
    }

    async function handlePlanChangeClick(btn, planName) {
        const plansData = getPlansData();
        selectedPlan = plansData.find(p => p.name === planName);
        if (!selectedPlan) {
            showErrorModal('Plan not found.');
            return;
        }

        const modal = document.getElementById('planChangeModal');
        const confirmBtn = document.getElementById('planChangeModalConfirm');

        let title, message;
        if (planName === 'Free') {
            title = 'Downgrade to Free Plan';
            message = `
                <p class="mb-3">Your subscription will be canceled and you'll return to the Free plan at the end of your current billing period.</p>
                <div class="alert alert-info mb-0">
                    <i class="fa-solid fa-info-circle me-2"></i>
                    <strong>Note:</strong> You won't be charged again.
                </div>
            `;
        } else {
            const isAnnual = selectedBillingInterval === 'year';
            const price = isAnnual ? selectedPlan.annualPrice : selectedPlan.price;
            const period = isAnnual ? 'year' : 'month';
            title = `Change to ${selectedPlan.displayName}`;
            message = `
                <p class="mb-3">Change your plan to <strong>${selectedPlan.displayName}</strong> (€${price}/${period})?</p>
                <div class="alert alert-info mb-0">
                    <i class="fa-solid fa-info-circle me-2"></i>
                    <strong>Note:</strong> The change will take effect at the end of your current billing period.
                </div>
            `;
        }

        modal.querySelector('.modal-title').textContent = title;
        document.getElementById('planChangeContent').innerHTML = message;
        confirmBtn.dataset.button = `[data-plan="${planName}"]`;
        confirmBtn.dataset.planName = planName;

        new bootstrap.Modal(modal).show();
    }

    async function executePlanChange(btn, planName) {
        const plansData = getPlansData();
        selectedPlan = plansData.find(p => p.name === planName);
        if (!selectedPlan) {
            showErrorModal('Plan not found.');
            return;
        }

        try {
            VW.setButtonLoading(btn, loadingHtml('Processing...'), true);

            const form = btn.closest('form');
            if (!form) throw new Error('Form not found');

            await VW.postJson('/Payments/ChangeSubscriptionPlan', form, {
                planName,
                billingInterval: selectedBillingInterval
            });
            window.location.hash = 'plans';
            window.location.reload();
        } catch (error) {
            console.error('Error:', error);
            showErrorModal(error.message);
            VW.setButtonLoading(btn, '', false);
        }
    }

    async function handleCompletePaymentClick(button) {
        try {
            VW.setButtonLoading(button, loadingHtml('Loading...'), true);

            const form = button.closest('form');
            if (!form) throw new Error('Form not found');

            const response = await VW.postJson('/Payments/ResumeIncompleteSubscription', form, {});
            const data = await response.json();
            clientSecret = data.clientSecret;

            elements = stripe.elements({ clientSecret, appearance: STRIPE_APPEARANCE });
            const paymentElement = elements.create('payment', { layout: 'tabs' });
            paymentElement.mount('#payment-element');

            const paymentDescription = document.getElementById('payment-description');
            const buttonText = document.getElementById('button-text');
            if (paymentDescription) paymentDescription.textContent = 'Complete your payment to activate your subscription';
            if (buttonText) buttonText.textContent = 'Complete Payment';

            showPaymentForm();

            const plansTab = document.getElementById('plans-tab');
            if (plansTab) plansTab.click();
        } catch (error) {
            console.error('Error:', error);
            showErrorModal(error.message);
            VW.setButtonLoading(button, '', false);
        }
    }

    function updatePaymentSection(plan) {
        const paymentDescription = document.getElementById('payment-description');
        const buttonText = document.getElementById('button-text');
        const isAnnual = selectedBillingInterval === 'year';
        const price = isAnnual ? plan.annualPrice : plan.price;
        const period = isAnnual ? 'year' : 'month';

        if (paymentDescription && plan) {
            paymentDescription.textContent = `Enter your card details to start your €${price}/${period} subscription`;
        }
        if (buttonText && plan) {
            buttonText.textContent = `Pay €${price}/${period}`;
        }
    }

    async function handlePaymentSubmit() {
        const submitBtn = document.getElementById('submit-payment');
        const buttonText = document.getElementById('button-text');
        const spinner = document.getElementById('spinner');
        const paymentMessage = document.getElementById('payment-message');

        if (submitBtn) submitBtn.disabled = true;
        if (spinner) spinner.style.display = 'inline-block';
        if (buttonText) buttonText.textContent = 'Processing...';
        if (paymentMessage) paymentMessage.style.display = 'none';

        try {
            const { error } = await stripe.confirmPayment({
                elements,
                confirmParams: {
                    return_url: window.location.origin + '/Account/Index'
                },
                redirect: 'if_required'
            });

            if (error) {
                if (paymentMessage) {
                    paymentMessage.textContent = error.message;
                    paymentMessage.className = 'alert alert-danger mt-3';
                    paymentMessage.style.display = 'block';
                }
                if (submitBtn) submitBtn.disabled = false;
                if (spinner) spinner.style.display = 'none';
                if (buttonText && selectedPlan) {
                    const isAnnual = selectedBillingInterval === 'year';
                    const price = isAnnual ? selectedPlan.annualPrice : selectedPlan.price;
                    const period = isAnnual ? 'year' : 'month';
                    buttonText.textContent = `Pay €${price}/${period}`;
                }
            } else {
                if (paymentMessage) {
                    paymentMessage.textContent = 'Payment successful! Updating your subscription...';
                    paymentMessage.className = 'alert alert-success mt-3';
                    paymentMessage.style.display = 'block';
                }
                await new Promise(resolve => setTimeout(resolve, 3000));
                window.location.hash = 'billing';
                window.location.reload();
            }
        } catch (error) {
            console.error('Payment error:', error);
            if (paymentMessage) {
                paymentMessage.textContent = 'An unexpected error occurred. Please try again.';
                paymentMessage.className = 'alert alert-danger mt-3';
                paymentMessage.style.display = 'block';
            }
            if (submitBtn) submitBtn.disabled = false;
            if (spinner) spinner.style.display = 'none';
        }
    }

    function updateCurrentPlanButton() {
        const raw = getRawPlansData();
        const currentPlanName = raw.currentPlanName;
        const currentBillingInterval = raw.currentBillingInterval || 'month';

        if (!currentPlanName || currentPlanName === 'Free') return;

        const plansData = raw.plans || [];
        const currentPlanData = plansData.find(p => p.name === currentPlanName);
        if (!currentPlanData) return;

        // Find the card that has the "Current Plan" header (bg-primary card-header)
        const currentPlanHeader = document.querySelector('.card-header.bg-primary.text-white');
        if (!currentPlanHeader) return;
        const currentCard = currentPlanHeader.closest('.card');
        if (!currentCard) return;

        const buttonContainer = currentCard.querySelector('.card-body');
        if (!buttonContainer) return;

        // Find the existing current-plan button or the switch-interval button we may have inserted
        const existingDisabledBtn = buttonContainer.querySelector('button.btn-outline-secondary[disabled]');
        const existingSwitchBtn = buttonContainer.querySelector('.switch-interval-btn');

        if (selectedBillingInterval !== currentBillingInterval) {
            // User selected a different interval than their current one — show switch button
            const isAnnual = selectedBillingInterval === 'year';
            const label = isAnnual
                ? 'Switch to Annual — Save 2 months'
                : 'Switch to Monthly';

            if (existingSwitchBtn) {
                // Already showing the switch button, just update text
                existingSwitchBtn.innerHTML = `<i class="fa-solid fa-arrow-right-arrow-left me-2"></i>${label}`;
            } else if (existingDisabledBtn) {
                // Replace the disabled "Current Plan" button with a change-plan form
                const form = document.createElement('form');
                form.className = 'change-plan-form';
                form.method = 'post';

                // Copy an antiforgery token from another form on the page
                const existingToken = document.querySelector('input[name="__RequestVerificationToken"]');
                if (existingToken) {
                    const tokenInput = document.createElement('input');
                    tokenInput.type = 'hidden';
                    tokenInput.name = '__RequestVerificationToken';
                    tokenInput.value = existingToken.value;
                    form.appendChild(tokenInput);
                }

                const planInput = document.createElement('input');
                planInput.type = 'hidden';
                planInput.name = 'planName';
                planInput.value = currentPlanName;
                form.appendChild(planInput);

                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-primary btn-lg w-100 change-plan-btn switch-interval-btn';
                btn.dataset.plan = currentPlanName;
                btn.innerHTML = `<i class="fa-solid fa-arrow-right-arrow-left me-2"></i>${label}`;
                form.appendChild(btn);

                existingDisabledBtn.replaceWith(form);
            }
        } else {
            // Back to the current interval — restore the disabled "Current Plan" button
            if (existingSwitchBtn) {
                const form = existingSwitchBtn.closest('form.change-plan-form');
                const disabledBtn = document.createElement('button');
                disabledBtn.type = 'button';
                disabledBtn.className = 'btn btn-outline-secondary btn-lg w-100';
                disabledBtn.disabled = true;
                disabledBtn.innerHTML = '<i class="fa-solid fa-check-circle me-2"></i>Current Plan';

                if (form) {
                    form.replaceWith(disabledBtn);
                } else {
                    existingSwitchBtn.replaceWith(disabledBtn);
                }
            }
        }
    }

    function showPaymentForm() {
        const plansContainer = document.querySelector('.plans-container');
        const paymentSection = document.getElementById('payment-section');
        if (plansContainer) plansContainer.style.display = 'none';
        if (paymentSection) paymentSection.style.display = 'block';
    }

    function hidePaymentForm() {
        const paymentSection = document.getElementById('payment-section');
        const plansContainer = document.querySelector('.plans-container');
        if (paymentSection) paymentSection.style.display = 'none';
        if (plansContainer) plansContainer.style.display = 'block';
    }
})();