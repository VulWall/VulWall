# NightWatch Dashboard — UI kit

A high-fidelity, interactive recreation of the VulWall **NightWatch** scan dashboard, built entirely from the design system's own components and tokens.

Open **`index.html`** for the click-through. It is a faithful cosmetic recreation of the product (ASP.NET MVC + Bootstrap 5 in production) — not production code.

## What's interactive
- **Sidebar nav** — switch between Overview, Findings, Assets (Reports/Scanners are stubbed, as in a recreation).
- **Light / dark** — the toggle flips `data-bs-theme` on `<html>`; every token re-themes.
- **Rescan now** — queues a toast.
- **Findings** — filter chips by severity; click any row to open the detail.
- **Finding detail** — full finding with AI recommendation, numbered fix steps, and a details panel.

## Files
| File | Surface |
|---|---|
| `index.html` | Entry — loads React, the DS bundle, Font Awesome, and the screens |
| `App.jsx` | Shell + view routing + theme/toast state |
| `Sidebar.jsx` | Navy→cobalt gradient sidebar, nav, upgrade prompt, theme toggle |
| `Overview.jsx` | Header, score ring + stat row, top findings; exports `PageHeader` |
| `Findings.jsx` | Severity filter chips + scannable finding rows |
| `Assets.jsx` | Discovered-hosts table with status + tech |
| `FindingDetail.jsx` | Finding detail, AI recommendation, fix steps |
| `data.jsx` | Shared fake scan data (`FINDINGS`, `ASSETS`) |

## Components used (from `window.VulWallDesignSystem_2af3fe`)
`Button`, `SeverityBadge`, `StatusPill`, `ScoreRing`, `StatCard`, `FindingCard` — composed, never re-implemented.

> Reference for fidelity: `web/` in this repository (the Dashboard, Discoveries, Recommendations, and Reports verticals).
