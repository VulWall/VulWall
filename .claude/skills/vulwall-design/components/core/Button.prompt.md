Cobalt-primary button family — use for every clickable action; pick the variant by intent, not by color.

```jsx
<Button variant="primary" icon="fas fa-bolt" onClick={rescan}>Rescan now</Button>
<Button variant="accent">Upgrade</Button>
<Button variant="secondary">Export</Button>
<Button variant="ghost">View report</Button>
<Button variant="danger" size="sm">Delete domain</Button>
```

Variants: `primary` (cobalt, main CTA) · `accent` (orange fill, **dark text** — for Upgrade/highlight only) · `secondary` (white + neutral border) · `ghost` (text-only cobalt) · `danger` (red, destructive). Sizes: `sm` · `md` · `lg`. Never put white text on the accent (orange) variant — it fails AA; the component already uses gunmetal text.
