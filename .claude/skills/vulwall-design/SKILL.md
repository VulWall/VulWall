---
name: vulwall-design
description: Use this skill to generate well-branded interfaces and assets for VulWall and its NightWatch external-attack-surface scanner — production code or throwaway prototypes, mocks, slides, and marketing. Contains the full brand guide, design tokens (colors, severity scale, type, spacing), webfonts, logo assets, 9 React UI components, and an interactive dashboard UI kit.
license: Proprietary — VulWall brand assets.
user-invocable: true
---

# VulWall Design System

VulWall helps SMEs find and fix vulnerabilities in their external attack surface. **NightWatch** is the flagship product: an always-on scanner that discovers subdomains/ports, runs vuln scans, profiles tech, checks email security, and enriches findings with AI — then surfaces a **prioritized, plain-English vulnerability dashboard**. Design tone: a calm, competent security expert — clarity over completeness, calm over alarm.

## How to use this skill

1. **Read `README.md` first** — it is the full brand guide (content fundamentals, visual foundations, iconography, asset index). This SKILL.md is the quick-reference; README is the deep dive.
2. **For visual artifacts** (slides, mocks, throwaway prototypes): link `styles.css`, pull in logos from `assets/`, follow the brand rules below, and output static HTML for the user to view. Copy assets out rather than hot-linking.
3. **For production / React work**: link `styles.css` for tokens, load the component bundle, and compose the components in `components/`. Read a component's `.prompt.md` + `.d.ts` for its API.
4. **If invoked with no brief**: ask what they want to build, ask a few design questions, then act as an expert VulWall designer.

### Wiring it up (HTML / prototype)
```html
<!-- 1. tokens + webfonts (one file reaches everything) -->
<link rel="stylesheet" href="styles.css">
<!-- 2. icons: Font Awesome 6 solid -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<!-- 3. components (React UMD + the compiled bundle) -->
<script src="https://unpkg.com/react@18.3.1/umd/react.development.js"></script>
<script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js"></script>
<script src="_ds_bundle.js"></script>
<script>const { Button, FindingCard, ScanHeatmap } = window.VulWallDesignSystem_2af3fe;</script>
```
The components are exposed on `window.VulWallDesignSystem_2af3fe`. (In production you'd import the `.jsx` sources directly instead of the prebuilt bundle.) Toggle dark mode with `document.documentElement.setAttribute('data-bs-theme','dark')`.

## Map
- `README.md` — full brand guide: context, content fundamentals, visual foundations, iconography, asset index.
- `styles.css` — the single global entry point. Link this one file; it `@import`s every token + webfont.
- `tokens/` — `colors.css`, `severity.css`, `typography.css`, `spacing.css`, `fonts.css`.
- `assets/` — `logo-mark.svg` (on light), `logo-mark-white.png` + `logo-wordmark-white.png` (on dark).
- `guidelines/` — foundation specimen cards (Colors, Severity, Type, Spacing, Brand) — open in a browser to see the system rendered.
- `components/core/` — `Button`, `SeverityBadge`, `StatusPill`, `Card`, `Input`.
- `components/scan/` — `ScoreRing`, `StatCard`, `FindingCard`, `ScanHeatmap`.
- `ui_kits/dashboard/` — interactive NightWatch dashboard recreation (`index.html`): sidebar, overview, findings, assets, finding detail, light/dark, scan-activity heatmap.

## Component API (`window.VulWallDesignSystem_2af3fe`)

| Component | Key props | Purpose |
|---|---|---|
| `Button` | `variant` (primary·accent·secondary·ghost·danger), `size` (sm·md·lg), `icon`, `disabled` | All clickable actions. Pick variant by intent. |
| `SeverityBadge` | `level` (critical·high·medium·low·info), `label` | Finding-severity pill with a colored dot. |
| `StatusPill` | `tone` (secure·scanning·resolved·open·neutral), `pulse` | Asset/finding status pill. `pulse` for scanning. |
| `Card` | `padding`, `interactive` | Base white surface (border + soft shadow, 12px radius). |
| `Input` | `label`, `prefix` (mono, e.g. `https://`), `error`, `invalid` | Text field with focus ring + error state. |
| `ScoreRing` | `score`, `max`, `size`, `label` | Circular security-score gauge; arc color follows the score (green/amber/red). |
| `StatCard` | `value`, `label`, `tone`, `icon` | Compact KPI card for the stat row. |
| `FindingCard` | `level`, `title`, `description`, `cve`, `host`, `port`, `onFix`, `onMute` | The core finding unit: severity accent + pill, mono CVE/host, plain-English title/body, actions. |
| `ScanHeatmap` | `weeks`, `data`, `legend` | GitHub-contributions-style scan-activity calendar; each cell is a day colored by worst severity, with a hover tooltip. |

```jsx
<FindingCard level="high" cve="CVE-2024-3094" host="api.acme.com" port="443"
  title="Outdated OpenSSL exposes the API to a known RCE"
  description="The host advertises OpenSSL 3.0.6, vulnerable to RCE. Upgrade to 3.0.7 or later."
  onFix={() => {}} onMute={() => {}} />
<ScanHeatmap weeks={26} />
```

## Token quick reference (all are CSS custom properties from `styles.css`)
- **Brand:** `--brand-dark-blue #212C5E` · `--brand-blue #0056A1` · `--brand-very-dark #101827` · `--brand-orange #F47D17` · `--brand-off-white #FBFBFD` · `--brand-gradient` (navy→cobalt).
- **Action:** `--vw-primary` (cobalt) · `--vw-secondary` (slate) · `--vw-success #067647` · `--vw-danger` · `--vw-info`. Orange accent: `--accent-orange`, `--accent-orange-on` (dark text for ON orange), `--accent-orange-text #B45309` (orange AS text).
- **Severity** (per band: text / `-bg` / `-border` / `-solid`): `--severity-critical|high|medium|low|info-*`. Use `-solid` for dots & heatmap cells.
- **Neutrals:** `--vw-gray-0…900` (navy-tuned slate). Semantic: `--app-bg`, `--surface-card`, `--border-default`, `--text-heading/body/muted/faint`.
- **Type:** `--font-display` (Chakra Petch), `--font-primary` (Inter), `--font-mono` (JetBrains Mono); scale `--text-display-lg…xs`.
- **Shape:** `--radius-sm/md/lg/xl/pill`; `--shadow-xs/sm/card/lg/focus`; spacing `--space-1…20` (4px base).
- **Themes:** default is light on `:root`; dark is the `[data-bs-theme="dark"]` scope.

## Non-negotiable brand rules
- **Cobalt `#0056A1` is the only interactive color.** Orange `#F47D17` is an **accent only** — never body text, never severity, never charts. On orange fills always use **gunmetal `#101827` text** (white-on-orange fails AA); for orange *as text* use `#B45309`.
- **Severity has its own ramp** (maroon → red → amber → gold → slate), fully decoupled from brand orange. Bands: Critical · High · Medium · Low · Info.
- **Three type roles:** Chakra Petch (display/wordmark, sparingly), Inter (all UI/body), JetBrains Mono (scan data — ports, CVEs, hosts, timestamps).
- **Cards:** white, 12px radius, hairline `--border-default` border **and** soft navy shadow. Finding cards add a 4px severity-colored left accent — the only place a colored left-border is used.
- **Backgrounds are flat.** The only gradient is the brand navy→cobalt (sidebar/hero). No textures, no decorative imagery.
- **Motion:** calm, 0.2s ease, no bounce/looping. Hover lifts 1px + cobalt shadow; press settles to the darker `-active` step; focus always shows a cobalt ring.
- **Icons:** Font Awesome 6 solid only (`<i class="fas fa-…">`). Status = colored dots. **No emoji, ever.** No Unicode pictographs.
- **Voice:** calm, plain-English security expert. Address the user as "you". Translate scanner jargon into outcomes and fixes. Sentence case for headings/buttons; UPPERCASE only for the wordmark and solid severity chips. Never alarmist.

## Author and license

The VulWall logo, colour palette and design system were designed by [Reyhaneh Kamali](https://reyhane.pro/), UI/UX Designer. The VulWall name and logo are trademarks of Moji Tajik. The logo and brand assets are © 2026 Moji Tajik, designed by Reyhaneh Kamali (https://reyhane.pro/), and are not covered by the MIT License. That covers `assets/`, this brand guide (`README.md`) and `guidelines/`. The tokens and CSS that implement the design in `web/` and `site/` are code under the MIT License.

## Source & provenance
Reverse-engineered from the real product: `web/` in this repository (canonical tokens from `site.css`; the `ScanHeatmap` from `Scans/index.css`). Explore it for production fidelity. Webfonts are Google-hosted (Inter + JetBrains Mono match the product; Chakra Petch is the display face) — swap in pinned/local fonts for offline use.
