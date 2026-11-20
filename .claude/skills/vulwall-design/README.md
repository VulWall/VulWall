# VulWall Design System

A security-first design system for **VulWall** — and its flagship product, **NightWatch**.

---

## 1 · Company & product context

**VulWall** is a security startup that helps companies find and fix vulnerabilities in their **external attack surface** — everything exposed to the public internet.

**NightWatch** is the core product: an always-on, automated external scanner. Point it at your domain and it:

- **Discovers** subdomains and open ports
- **Scans** for vulnerabilities (Nuclei, testssl, Nikto)
- **Profiles** the web technologies in use
- **Checks** email security (SPF, DMARC, DKIM)
- **Enriches** findings with AI (Anthropic Claude) so each one comes with a plain-English explanation and a fix

The output is a **prioritized vulnerability dashboard** — not a raw dump of scanner noise, but actionable findings ranked by real-world risk.

**Who it's for:** SMEs (small / medium businesses) that don't have a dedicated security team but still need to know if they're exposed.

**The differentiator:** most enterprise security tools are complex and expensive. VulWall is the *accessible* version — plug in your domain, get a clear picture, know what actually matters.

This positioning drives every design decision in this system: **clarity over completeness, calm over alarm, and a hard separation between "this is our brand" and "this is a risk."**

### Products represented in this system

| Product | Surface | Status in this DS |
|---|---|---|
| **NightWatch Dashboard** | Web app (ASP.NET MVC + Bootstrap 5) | UI kit included → `ui_kits/dashboard/` |

---

## 2 · Sources

This design system was reverse-engineered from real VulWall product code and brand assets. The reader may not have access to these, but they are recorded here so the system can be regenerated and extended:

- **This repository — `web/`** — the dashboard codebase. The canonical token system comes from `web/src/wwwroot/css/Common/site.css` and `vulwall-tokens.css`; component conventions from `web/CLAUDE.md`. Brand raster logos from `web/src/wwwroot/img/`.
- **This repository — `scanner/`** — the scanning engine. It wraps community tools such as `nuclei`, `testssl.sh` and `retire.js`.
- **Brand assets:** the blue-gradient logomark (→ `assets/logo-mark.svg`) and the white logomark and wordmark PNGs in `assets/`.

> **Reader tip:** to build new VulWall designs with maximum fidelity, browse `web/` in this repository — its Razor views and page CSS show exactly how these tokens and components compose in production.

---

## 3 · Content fundamentals

How VulWall writes. The voice is **a calm, competent security expert talking to a smart non-specialist** — never a fear-mongering vendor, never a condescending one.

- **Voice:** plain-English and direct. The product's own tagline for findings is *"Plain-English findings, ranked by what actually matters."* Translate scanner jargon into outcomes: not *"TLS 1.0 enabled"* but *"Your site still allows an outdated encryption standard attackers can break."*
- **Person:** address the user as **you / your** ("your perimeter", "your API"). VulWall refers to itself as **we** sparingly. Findings are about *your* attack surface.
- **Tone:** reassuring authority. Lead with what to do, not how scared to be. *"Upgrade to 3.0.7 or later — your provider's package mirror already has it."*
- **Casing:** Sentence case for headings and buttons ("Run scan", "How to fix", "View report"). **UPPERCASE** is reserved for two things only: the wordmark (VULWALL) and severity band labels on solid chips (CRITICAL, HIGH). Eyebrow/section labels use uppercase with wide letter-spacing.
- **Severity language:** the five bands are always **Critical · High · Medium · Low · Info** — capitalized as proper nouns, never invented synonyms.
- **Numbers & data:** monospace for anything technical — ports (`tcp/443`), CVEs (`CVE-2024-3094`), hostnames (`api.acme.com`), timestamps. This makes scan data scannable and signals "machine truth".
- **Emoji:** **none.** This is a security product; emoji would undercut the authority. Status is shown with colored dots, icons, and severity pills instead.
- **Buttons / CTAs:** verb-first and short — "Run scan", "Rescan now", "Export", "How to fix", "Mute", "Upgrade".
- **Vibe in one line:** *Find what attackers see — before they do.* Confident, never alarmist.

### Examples (lifted / styled from product)

> **Heading:** "What we found on your perimeter"
> **Finding title:** "Outdated OpenSSL exposes the API to a known RCE"
> **Finding body:** "The host advertises OpenSSL 3.0.6, which is vulnerable to a remote code execution flaw. Upgrade to 3.0.7 or later."
> **Status line:** "Last scan 4 hours ago · 12 scanners · 7 assets"
> **Empty / good state:** "Secure" · "Resolved" · "Passed"

---

## 4 · Visual foundations

The system's look: **dark, technical chrome wrapped around calm, light work surfaces.** A security operations feel without the neon-hacker cliché.

### Color
- **Brand palette (5 hues, from the logobook):** Delft navy `#212C5E`, Cobalt blue `#0056A1`, Gunmetal `#101827`, Orange `#F47D17`, Ghost `#FBFBFD`.
- **Navy carries trust and structure** (headings, sidebar, dark chrome). **Cobalt is the single interactive color** (primary buttons, links, focus rings). **Orange is an accent only** — highlights, upgrade CTAs, the active-nav tick — and **never** body text or severity.
- **Orange contrast rule:** white-on-orange is only 2.7:1 (fails AA). Always put **gunmetal `#101827` text on orange fills** (7.8:1), or use the darkened `#B45309` for orange *as text*.
- **Neutrals are a navy-tuned slate ramp** (`--vw-gray-50…900`), not generic gray — borders, dividers, secondary text and table chrome all draw from it so the UI stays cool and coherent.
- **Severity has its own decoupled ramp:** maroon → red → amber → gold → slate (Critical/High/Medium/Low/Info). It deliberately shares no hue with brand orange, so "warning" never reads as "brand". The only green in the system is success `#067647` (Secure / Passed / Resolved).

### Typography
- **Three roles.** **Chakra Petch** (geometric, slightly technical) for the wordmark and rare hero headlines — used sparingly. **Inter** does all UI and body work. **JetBrains Mono** carries technical scan data (ports, CVEs, fingerprints, timestamps).
- Headings are navy and tight (`letter-spacing: -0.02em`); body is slate at 1.6 line-height; mono is used inline at the same size as surrounding text.

### Surfaces, cards & elevation
- **Cards:** white (`--surface-card`), `12px` radius, a `1px` `#E4E9F0` border **and** a soft navy-tinted shadow (`0 8px 24px rgba(16,24,40,.06)`) — both, not one or the other. Larger panels (modals, the dashboard frame) use `16px` radius and a deeper `0 16px 48px` shadow.
- **Finding cards** add a `4px` left border in the finding's severity-solid color — the one place a colored left-accent is used, and only there.
- **Backgrounds:** flat. App background is Ghost `#FBFBFD`; the only gradient in the system is the **brand navy→cobalt diagonal**, used for the sidebar and hero surfaces. No textures, no patterns, no decorative imagery. A single faint radial navy glow may sit behind a dark hero.
- **Dark theme:** near-black `#0F1419` app background, `#1A1F2E` cards, `#2D3748` borders; severity tints become translucent rgba washes with lighter text.

### Borders, radius & shape
- Radii: `6px` (tags/small) · `8px` (buttons/inputs) · `12px` (cards) · `16px` (panels) · `999px` (badges & status pills). Status and severity are **always pills**; structural surfaces are softly rounded rectangles.
- Borders are `1px`, color `--vw-gray-200`; focused inputs go to a `2px` cobalt border plus a `3px` cobalt glow ring.

### Motion, hover & press
- **Calm and quick:** `0.2s ease` transitions, no bounce, no decorative looping animation. Honors `prefers-reduced-motion`.
- **Hover:** primary buttons lift `1px` (`translateY(-1px)`) and gain a soft cobalt shadow; sidebar links nudge `4px` right and pick up a faint orange wash. Secondary/ghost controls darken one step.
- **Press:** return to `translateY(0)` and the `-active` (darker) color step — settle down, don't shrink.
- **Focus:** always visible — a cobalt ring (`--shadow-focus`) for accessibility, never removed.

### Transparency & blur
- Used sparingly: translucent severity washes in dark mode, the faint orange sidebar-hover tint, and rgba overlays on modals. No glassmorphism / heavy backdrop-blur.

---

## 5 · Iconography

- **The product uses Font Awesome 6 (free, solid) exclusively** — its `CLAUDE.md` mandates *"Always use FontAwesome icons — never use inline SVG icons,"* loaded globally in the layout. This design system follows that: cards, components, and UI kits load Font Awesome from CDN (`cdnjs`) and use `<i class="fas fa-…"></i>`.
- **Common glyphs in the product UI:** `fa-shield-halved` (security/brand), `fa-magnifying-glass` / `fa-radar` (scan), `fa-triangle-exclamation` (findings), `fa-server` / `fa-globe` (assets), `fa-circle-check` (passed/secure), `fa-arrow-up-right-from-square` (export/links), `fa-gear` (settings), `fa-sun` / `fa-moon` (theme toggle), `fa-bolt` (rescan).
- **Status is shown with colored dots, not icons** — a `6px` `border-radius:50%` dot in the severity-solid or status color, inside a pill. This is the system's most distinctive small motif.
- **The logomark** is a custom geometric "V" (interlocking chevrons forming a shield/triangle) — see `assets/`. It is **not** part of the icon set; treat it as the brand mark only.
- **No emoji, ever.** No Unicode pictographs as icons. If a needed glyph isn't in Font Awesome free, substitute the closest Font Awesome solid icon rather than reaching for emoji or hand-drawn SVG.

> **Substitution flag:** the product loads Font Awesome globally from its own bundle; here we link Font Awesome 6 free from cdnjs. If you adopt this system in production you should pin the same Font Awesome version your app ships to avoid glyph drift.

---

## 6 · Assets

In `assets/`:

| File | What | Use on |
|---|---|---|
| `logo-mark.svg` | Blue-gradient logomark (the "V" shield) | Light backgrounds |
| `logo-mark-white.png` | White logomark | Dark backgrounds / sidebar |
| `logo-wordmark-white.png` | White full wordmark (mark + VULWALL) | Dark backgrounds |

The wordmark text is set in Chakra Petch; when recreating it live (not as an image) use `font-family: var(--font-display)`, weight 600, `letter-spacing: 0.02em`, uppercase.

---

## 7 · Index / manifest

Root files:
- **`styles.css`** — the global entry point. Consumers link this one file. `@import` lines only.
- **`tokens/`** — `fonts.css`, `colors.css`, `severity.css`, `typography.css`, `spacing.css`. All CSS custom properties live here; both base values and semantic aliases.
- **`assets/`** — logos (see §6).
- **`guidelines/`** — foundation specimen cards (the Design System tab: Colors, Severity, Type, Spacing, Brand).
- **`components/`** — reusable React UI primitives (see below).
- **`ui_kits/dashboard/`** — high-fidelity NightWatch dashboard recreation.
- **`SKILL.md`** — Agent-Skills-compatible entry point.

**Components** (`window.VulWallDesignSystem_2af3fe.<Name>`):
- `Button`, `SeverityBadge`, `StatusPill`, `Card`, `Input`, `ScoreRing`, `StatCard`, `FindingCard`, `ScanHeatmap`

**UI kits:**
- `ui_kits/dashboard/` — NightWatch scan dashboard: sidebar shell, overview with score + stats, findings list, finding detail. Interactive click-through in `index.html`.

---

*Built from VulWall product code and brand assets. Severity-vs-brand color separation, the navy-tuned neutral ramp, and the orange-contrast rules are intentional corrections carried over from the product's own `vulwall-tokens.css` patch.*
