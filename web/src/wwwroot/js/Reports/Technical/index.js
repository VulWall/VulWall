// Technical Report — client-side interactions

document.addEventListener('DOMContentLoaded', () => {
    initAccordion();
    initRoadmapDeeplink();
});

function initAccordion() {
    const list = document.getElementById('findingsList');
    if (!list) return;

    list.addEventListener('click', e => {
        const head = e.target.closest('.tr-accordion-head');
        if (!head) return;
        const card = head.closest('.tr-accordion');
        if (!card) return;
        card.dataset.open = card.dataset.open === 'true' ? 'false' : 'true';
        head.setAttribute('aria-expanded', card.dataset.open);
    });

    document.getElementById('trExpandAll')?.addEventListener('click', () => {
        list.querySelectorAll('.tr-accordion').forEach(c => {
            c.dataset.open = 'true';
            c.querySelector('.tr-accordion-head')?.setAttribute('aria-expanded', 'true');
        });
    });

    document.getElementById('trCollapseAll')?.addEventListener('click', () => {
        list.querySelectorAll('.tr-accordion').forEach(c => {
            c.dataset.open = 'false';
            c.querySelector('.tr-accordion-head')?.setAttribute('aria-expanded', 'false');
        });
    });
}

function initRoadmapDeeplink() {
    document.querySelectorAll('.tr-roadmap-item[data-finding-type]').forEach(item => {
        item.addEventListener('click', () => {
            const type = item.dataset.findingType;
            const card = type
                ? document.querySelector(`.tr-accordion[data-finding-type="${CSS.escape(type)}"]`)
                : null;
            if (card) {
                card.dataset.open = 'true';
                const head = card.querySelector('.tr-accordion-head');
                if (head) head.setAttribute('aria-expanded', 'true');
                card.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
}
