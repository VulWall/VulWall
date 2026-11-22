# Claude Code Context for VulWall Project

## Project Overview
VulWall is an open-source (MIT), self-hosted security scanner with automated asset discovery, continuous vulnerability monitoring, and optional AI-powered security recommendations. This `web/` app is the UI; the Go scanner lives in `../scanner/`. The two share one MongoDB database and nothing else (see "Scanner Link" below).

## Design Skill — MANDATORY for all UI/UX work

**Before writing or modifying any frontend code (Razor views, CSS, JS), invoke the `vulwall-design` skill.**

```
/vulwall-design
```

This skill encodes the brand tokens, severity ramp, CSP constraints, dark-mode requirements, component patterns, and quality gate for all VulWall frontend surfaces. It must be applied to every UI change — new pages, component updates, CSS edits, report redesigns, and design handoff implementations.


## Brand Colors

| Color Name       | Hex Code |
| ---------------- | -------- |
| Dark Blue        | #212C5E  |
| Blue             | #0056A1  |
| Very Dark Blue   | #101827  |
| Orange           | #F47D17  |
| Off White        | #FBFBFD  |
| Gradient (Start) | #212C5E  |
| Gradient (End)   | #0056A1  |


## Key Technologies
- **Backend**: .NET 11.0, C#
- **Frontend**: ASP.NET Core MVC with Razor Views
- **Database**: MongoDB
- **Auth**: Local cookie authentication (single admin, BCrypt)
- **AI**: Anthropic Claude, optional (`ANTHROPIC_API_KEY`)
- **Architecture**: Vertical Slice Architecture for Dashboard

## Project Structure
```
web/
├── Dockerfile                      # Build context = web/
├── src/
│   ├── VulWall.Dashboard.csproj
│   ├── Program.cs
│   ├── wwwroot/                    # Static files (css/js/images with Bootstrap)
│   │   ├── css/
│   │   │   ├── {Page}/             # Page-specific styles
│   │   │   └── Common/             # Shared styles
│   │   └── js/
│   │       ├── {Page}/             # Page-specific scripts
│   │       └── Common/             # Shared scripts
│   ├── Common/                     # Shared logic (contracts, common views)
│   ├── Data/                       # Repositories and MongoDB entities
│   ├── Extensions/                 # Extension methods for project setup
│   └── Verticals/                  # Vertical slice architecture
│       └── {VerticalName}/
│           ├── {VerticalName}Controller.cs  # MVC controller
│           ├── Services/           # Business logic (each in separate directory)
│           ├── Models/             # View models and DTOs
│           └── Views/              # Razor views
│               ├── {ActionName}.cshtml  # Action views
│               ├── Partials/            # Partial views (_PartialName.cshtml)
│               ├── _ViewImports.cshtml
│               └── _ViewStart.cshtml
```

## Design Patterns & Conventions

### View Organization
* Each vertical has its own Views folder: `Verticals/{VerticalName}/Views/`
* Action views are placed directly in Views folder: `{ActionName}.cshtml` (e.g., Index.cshtml, Add.cshtml)
* Partial views go in `Views/Partials/` subdirectory and start with underscore: `_PartialName.cshtml`
* Every Views folder must have `_ViewImports.cshtml` and `_ViewStart.cshtml`
* Reference partials using: `<partial name="~/{VerticalName}/Views/Partials/_PartialName.cshtml" />`

### CSS/JS Organization
* Page-specific styles: `wwwroot/css/{Page}/{CssFile}.css`
* Page-specific scripts: `wwwroot/js/{Page}/{JsFile}.js`
* Shared styles across multiple pages: `wwwroot/css/Common/{CssFile}.css`
* Shared scripts across multiple pages: `wwwroot/js/Common/{JsFile}.js`
* **Never put CSS/JS inline in views** - always use external files
* Reference styles in views: `<link rel="stylesheet" href="~/css/{Page}/{CssFile}.css" />`
* Reference scripts in views: `<script type="module" src="~/js/{Page}/{JsFile}.js"></script>`

### Content Security Policy (CSP) — CRITICAL
The Dashboard enforces a strict CSP with `script-src 'self'` (no `'unsafe-inline'`). **Every new script must comply:**

* **No inline `<script>` blocks in views.** CSP will block them silently — the browser console will show a violation but the feature will simply not work.
* **Pass server data to JS via JSON blocks:** `<script id="my-data" type="application/json">@Html.Raw(JsonSerializer.Serialize(Model.Data))</script>` — these are not executable and are not restricted by CSP.
* **Read JSON blocks in external JS:** `JSON.parse(document.getElementById('my-data')?.textContent || '{}')` — always wrap in try-catch for resilience.
* **Place JSON blocks before the `<script>` tags that consume them** in the view.
* **No external hosts.** Self-hosted installs must work offline: vendor third-party scripts, styles and images into `wwwroot/lib/` (or `wwwroot/images/`) and keep the CSP in `Extensions/WebApplicationExtensions.cs` at `'self'`.
* **No `eval()`, `new Function()`, or `setTimeout('string')`** — these require `'unsafe-eval'` which we do not allow.

### UI Components
* Make generic components that can be used across verticals (buttons, dropdowns, modals should all have consistent styling)
* Use Bootstrap 5 for styling (comes with .NET MVC projects by default)
* Reusable components go in `Common/Views/` as partials

### Icons
* **Always use FontAwesome icons** - Never use inline SVG icons
* FontAwesome is included in the layout file globally
* Use FontAwesome icon classes: `<i class="fas fa-icon-name"></i>`

## Vertical Slice Architecture

### Core Principles
* **Write Isolation**: Each vertical owns and manages its business logic
* **Clear Ownership**: Each domain area has a single owner vertical
* **Operation Responsibility**: Vertical handles all operations for its domain
* **No Cross-Vertical Direct Access**: Verticals must not access each other's internal services, logic, or repositories directly
* **Cross-vertical communication**: Only via Common types/interfaces

### Vertical Structure
Each vertical is self-contained and includes:
* **Controllers**: MVC controllers for handling HTTP requests
* **Services**: Business logic organized in subdirectories (e.g., `Services/ReportGeneration/`)
* **Models**: View models and DTOs specific to the vertical
* **Views**: Razor views and partials
* The vertical is the sole owner of its domain logic and operations

### Available Verticals
* **Account**: First-run `/setup`, `/login`, `/logout` (local admin account)
* **Assets**: Asset management (domains, IPs); assets are enabled on add, no ownership verification. Adding records the asset at once (`$addToSet asset_ids`, only on discoveries that already have `asset_ids`; a failure is logged, not shown) on the discoveries earlier scans found for it: its own host, the IPs that host resolves to now and their ports, or an IP and its ports (stored as Go's `net.IP.String()` prints it, `DiscoveryIds.CanonicalIp`), by the scanner's ids (`DiscoveryIds`, a port of `scanner/src/internal/shared/ids.go`; keep both and their shared test vectors in step). Disabling hides the asset's data (`IAssetScopeFilter`, from `discoveries.asset_ids`) and writes nothing; enable and disable are a conditional `$set`. Deleting marks the asset `deleting` (never cleared: the asset can then only be deleted again, the toggle is refused, the scope and the scanner treat it as disabled), removes its id and the ids of assets that no longer exist from `asset_ids`, deletes the discoveries left with no owner, with their findings, suppressions and scan coverage, and deletes the asset last, only while marked (`AssetsService.DeleteAssetAsync`; see `scanner/docs/DATABASE.md`). Never delete "every discovery that contains the asset id": the scanner only adds owners, and DNS under one asset can add it to another asset's discoveries. Dismissing an issue needs a visible discovery that exists in the org
* **Dashboard**: Main overview, metrics, charts, recent scans
* **Discoveries**: Discovered assets, ports, services from scans
* **Recommendations**: AI-powered security recommendations for findings
* **Reports**: Report generation (Summary, Technical)
* **Scans**: Scan history, results, findings overview
* **Settings**: Company details and logo, password, scan schedule
* **About**: Data for the About dialog (`Common/Views/_AboutDialog.cshtml`, opened from the About button in the sidebar): `GET /about/info` (versions from the scanner's `system_info` document, plus a copy-paste system info text with versions and counts only). The update status in the dialog and the dot on the sidebar About button come from `UpdateCheckState` (Common singleton), which only `UpdateCheckPoller` (About, hosted service) writes: GitHub latest-release check 10 s after start, then every 6 h, failures retried after 15 min doubling to 6 h and keeping the last answer; `UPDATE_CHECK=false` turns it off. Page loads never call GitHub. `_Layout` renders the sidebar (and so the badge) for signed-in users only, because the anonymous error pages use the same layout.

### Common Layer (Shared Across Verticals)
The Common layer contains **only** types needed for cross-vertical communication:
* ✅ DTOs (e.g., VerificationRequest, VerificationResponse)
* ✅ Shared view models and data transfer objects
* ✅ Enums, interfaces, constants (non-secret)
* ✅ Shared views and UI components (in `Common/Views/`)

**Internal Only (per vertical) - NOT in Common:**
* ❌ Business logic
* ❌ Secret keys or sensitive configuration
* ❌ Internal models/entities
* ❌ Implementation details

### Data Layer
* Database entities and contracts are in `Data/` folder
* Repositories provide data access abstraction
* MongoDB is used as the database

## Reports Implementation

### Report Types
VulWall supports multiple report types, each with its own view and styling:
* **Summary Report**: High-level security overview for executives/management
* **Technical Report**: Detailed vulnerability findings for technical teams

### Report Generation Architecture
Reports use **server-side rendering** with the following components:

1. **ReportGenerationService**: Orchestrates report generation
   - Aggregates data from findings, discoveries, and scans
   - Builds view models for each report type
   - Located in `Reports/Services/ReportGeneration/`

2. **Report Builders**:
   - `SummaryReportBuilder`: Builds summary report view models
   - `TechnicalReportBuilder`: Builds technical report view models
   - `FindingsAggregator`: Aggregates and groups findings data
   - `VulnerabilitySummaryBuilder`: Creates vulnerability summaries

3. **Data Flow**:
   ```
   Controller → ReportGenerationService → Builders → ViewModel → Razor View → Partials
   ```

### CSS/JS Organization for Reports
For pages with multiple report variants, organize assets by report type:
```
wwwroot/
├── css/
│   └── Reports/
│       ├── index.css          # Report management page
│       ├── Summary/
│       │   └── index.css      # Summary report styles
│       └── Technical/
│           └── index.css      # Technical report styles
└── js/
    └── Reports/
        ├── index.js           # Report management (scan scope, context strip)
        ├── template-cards.js  # Report type cards (Preview)
        └── Technical/
            └── index.js       # Technical report interactions (navigation, etc.)
```

### Report Views Organization
```
Reports/Views/
├── Index.cshtml                              # Report management page
├── Summary.cshtml                            # Summary report view
├── Technical.cshtml                          # Technical report view
└── Partials/                                # Shared report components
    ├── _SummaryHeader.cshtml
    ├── _SummaryExecutiveSummary.cshtml
    ├── _SummaryTopFindings.cshtml
    ├── _SummaryAssetOverview.cshtml
    ├── _SummaryFooter.cshtml
    ├── _TechnicalHeader.cshtml
    ├── _TechnicalNavigation.cshtml
    ├── _TechnicalExecutiveSummary.cshtml
    ├── _TechnicalAssetDiscovery.cshtml
    ├── _TechnicalVulnerabilities.cshtml
    ├── _TechnicalDetails.cshtml
    ├── _TechnicalCompliance.cshtml
    ├── _TechnicalFooter.cshtml
    ├── _RemediationRoadmap.cshtml           # Shared by both reports
    ├── _ScanCoverage.cshtml
    └── _FindingCard.cshtml
```

### Server-Side Rendering Approach
Reports are fully rendered on the server:
1. **Controller** calls `ReportGenerationService` to build view models
2. **View Models** contain all necessary data (findings, assets, statistics)
3. **Razor Views** render HTML using strongly-typed models
4. **Partials** compose reusable report sections
5. **Client-side JS** only handles interactions (navigation, print, etc.)

### Dark Theme Requirements
All custom CSS **must** support dark theme using `[data-bs-theme="dark"]` selectors:
```css
/* Light theme (default) */
.section {
    background: var(--bs-body-bg, white);
    border: 1px solid var(--vw-gray-200);
}

/* Dark theme */
[data-bs-theme="dark"] .section {
    background: #1a1f2e;
    border-color: #2d3748;
}
```

Common dark theme backgrounds:
* Cards/Sections: `#1a1f2e`
* Nested elements: `#1f2937`
* Hover states: `#2d3748`

### Brand Color Usage in CSS
Always use CSS variables from `site.css` instead of hardcoded colors:

**Primary Colors:**
* `var(--brand-blue)` - Main blue (#0056A1)
* `var(--brand-dark-blue)` - Dark blue (#212C5E)
* `var(--brand-orange)` - Orange accent (#F47D17)
* `var(--brand-off-white)` - Off white (#FBFBFD)

**Severity Colors** (own ramp, fully decoupled from brand orange — defined in `Common/site.css`):
* `var(--severity-critical)` - Critical — deep maroon `#911D14` (NOT red, NOT orange)
* `var(--severity-critical-bg)` - Critical tint background
* `var(--severity-high)` - High — red `#D92D20` (was orange `#F97316` — corrected)
* `var(--severity-high-bg)` - High tint background
* `var(--severity-medium)` - Medium — dark amber `#B54708`
* `var(--severity-medium-bg)` - Medium tint background
* `var(--severity-low)` - Low — gold `#A16207` (was blue `#3B82F6` — corrected)
* `var(--severity-low-bg)` - Low tint background
* `var(--severity-info)` - Info/None band — slate `#475569`
* `var(--severity-info-bg)` - Info tint background

⚠️ NEVER use brand orange (`#F47D17`) for severity. Orange = accent only. Severity has its own maroon→red→amber→gold→slate ramp.

**Neutral Colors:**
* `var(--vw-gray-50)` through `var(--vw-gray-900)` - Grayscale palette

**Semantic Colors:**
* `var(--vw-success)`, `var(--vw-warning)`, `var(--vw-danger)`, `var(--vw-info)`

### CSS Best Practices
* ✅ Use CSS variables from `site.css` for all colors
* ✅ Leverage Bootstrap's existing styles (buttons, badges, tables)
* ✅ Always include dark theme variants
* ✅ Use `var(--card-shadow)` for consistent shadows
* ❌ Don't duplicate Bootstrap/site.css styles
* ❌ Don't hardcode colors - use variables
* ❌ Don't forget dark theme support

### Available Button Variants
VulWall provides customized Bootstrap button styles. Use these existing variants:

**Solid Buttons:**
- `.btn-primary` - Primary blue button (main CTAs)
- `.btn-secondary` - Secondary slate/neutral button (NOT orange — use `.btn-accent` for orange CTA)
- `.btn-success` - Success green button
- `.btn-warning` - Warning yellow button
- `.btn-danger` - Danger red button

**Outline Buttons:**
- `.btn-outline-primary` - Primary outline
- `.btn-outline-secondary` - Secondary outline
- `.btn-outline-success` - Success outline
- `.btn-outline-danger` - Danger outline
- `.btn-outline-warning` - Warning outline

**Other Buttons:**
- `.btn-link` - Link-style button
- `.btn-icon` - Icon-only button (2.5rem square)

**Removed Button Variants** (not in use, removed for bundle size):
- ❌ `.btn-info` / `.btn-outline-info` - If needed for future features, add back to site.css

**Button Sizes:**
- `.btn-sm` - Small button
- `.btn-lg` - Large button
- Default - Standard size

### Available Badge Variants

**Standard Badges:**
- `.badge-primary` - Blue badge (softer semi-transparent in dark mode)
- `.badge-secondary` - Orange accent badge (light: orange tint bg + amber text; dark: slate via `--vw-secondary`)
- `.badge-success` - Green badge (light background, dark text)
- `.badge-warning` - Yellow badge (light background, dark text)
- `.badge-danger` - Red badge (light background, dark text)
- `.badge-light` - Light gray badge
- `.badge-dark` - Dark badge

All badges automatically adapt to dark mode with softer, semi-transparent backgrounds and lighter text colors for better readability.

**Severity Badges** (use `.sev-badge` system — pill with dot indicator):
- `.sev-badge.sev-critical` - Critical severity (maroon)
- `.sev-badge.sev-high` - High severity (red)
- `.sev-badge.sev-medium` - Medium severity (dark amber)
- `.sev-badge.sev-low` - Low severity (gold)
- `.sev-badge.sev-info` - Info/None band (slate)

Usage: `<span class="sev-badge sev-high">High</span>`

**Removed Badge Variants** (not in use):
- ❌ `.badge-brand`, `.badge-info` - If needed, add back to site.css

**If You Need These:**
1. Check if Bootstrap provides the functionality natively
2. If custom styling is needed, add to `site.css` with dark theme support
3. Follow the existing pattern for component styling

## Reusable Components

### Confirmation Modal
A reusable confirmation modal component is available at `Common/Views/_ConfirmationModal.cshtml`.

**Features:**
- Customizable header with icon and styling (danger, warning, success, info)
- Dynamic message and details list
- Optional footer message
- Dynamic content area for additional elements
- Consistent styling across all modals

**Usage Example:**
```cshtml
@{
    var modalModel = new ConfirmationModalModel
    {
        ModalId = "myModal",
        Title = "Confirm Action",
        Message = "Are you sure you want to proceed?",
        MessageBold = true,
        ConfirmButtonText = "Confirm",
        ConfirmButtonStyle = "danger",
        ConfirmButtonIcon = "fas fa-check",
        HeaderStyle = "warning",
        Icon = "fas fa-exclamation-triangle",
        Details = new List<string> { "Detail 1", "Detail 2" },
        DetailsTitle = "Important:",
        DetailsIcon = "fas fa-info-circle",
        DetailsStyle = "info",
        DynamicContentId = "myDynamicContent" // Optional
    };
}
<partial name="~/Common/Views/_ConfirmationModal.cshtml" model="modalModel" />
```

**JavaScript Integration:**
- Confirm button ID: `{ModalId}Confirm` (e.g., `myModalConfirm`)
- Access modal via Bootstrap: `new bootstrap.Modal(document.getElementById('myModal'))`
- Use `DynamicContentId` to inject dynamic content from JavaScript

### Other Common Components
- `_ConfirmationModal.cshtml`: Reusable confirmation dialogs
- `_Layout.cshtml`: Main application layout with sidebar, header, theme toggle
- `_Sidebar.cshtml`: Navigation sidebar with active state management

## Code Quality Standards

### Comments
- **Remove obvious comments** that just repeat what the code does
- **Keep important comments** that explain:
  - Business rules and logic
  - Complex algorithms
  - Security considerations
  - TODOs for future work
  - Non-obvious technical decisions
- Follow "explain WHY, not WHAT" principle

### Code Organization
- Keep controllers lean - move complex logic to services
- Use clear, descriptive variable names
- Avoid deeply nested code - extract methods when needed
- Follow consistent naming conventions

### Lean Controller Pattern
Controllers should only handle HTTP concerns. All business logic must be extracted into dedicated services.

**Controller Responsibilities (DO):**
- Receive HTTP requests and validate input
- Call service methods
- Handle HTTP responses (status codes, redirects, TempData)
- Return views with view models

**Controller Should NOT:**
- Query repositories directly (except simple lookups)
- Contain mapping logic
- Contain business rules or calculations
- Have private helper methods with logic

**Service Location:**
```
{VerticalName}/Services/{ServiceName}.cs
```

**Service Registration:**
Services are registered in `Extensions/ServiceCollectionExtensions.cs`:
```csharp
private static IServiceCollection Add{Vertical}Services(this IServiceCollection services)
{
    services.AddScoped<{ServiceName}>();
    return services;
}
```

**Example - Before (Fat Controller):**
```csharp
public class ScansController(ScansRepository scansRepository, FindingsRepository findingsRepository) : Controller
{
    public async Task<IActionResult> Index()
    {
        var scans = await scansRepository.GetAllAsync();
        var allFindings = await findingsRepository.GetAllAsync();
        var scanItems = scans.Select(scan => MapScanToViewModel(scan, allFindings)).ToList();

        var model = new IndexViewModel
        {
            Scans = scanItems,
            TotalScans = scanItems.Count,
            // ... more logic
        };
        return View(model);
    }

    private ScanItemViewModel MapScanToViewModel(Scan scan, IEnumerable<Finding> findings)
    {
        // Complex mapping logic...
    }
}
```

**Example - After (Lean Controller):**
```csharp
// Controller - only HTTP concerns
public class ScansController(ScansService scansService) : Controller
{
    public async Task<IActionResult> Index()
    {
        var model = await scansService.GetIndexViewModelAsync();
        return View(model);
    }
}

// Service - all business logic
public class ScansService(ScansRepository scansRepository, FindingsRepository findingsRepository)
{
    public async Task<IndexViewModel> GetIndexViewModelAsync()
    {
        var scans = await scansRepository.GetAllAsync();
        var allFindings = await findingsRepository.GetAllAsync();
        var scanItems = scans.Select(scan => MapScanToViewModel(scan, allFindings)).ToList();

        return new IndexViewModel
        {
            Scans = scanItems,
            TotalScans = scanItems.Count,
            // ...
        };
    }

    private static ScanItemViewModel MapScanToViewModel(Scan scan, IEnumerable<Finding> findings)
    {
        // Complex mapping logic...
    }
}
```

**Existing Services by Vertical:**
| Vertical | Service | Purpose |
|----------|---------|---------|
| Account | `AccountService` | Admin setup, password hashing, credential check |
| Assets | `AssetsService` | Asset CRUD; delete removes the data only that asset owns |
| Dashboard | `DashboardService` | Metrics, charts, recent scans |
| Discoveries | `DiscoveriesService` | Discovery data aggregation |
| Recommendations | `RecommendationsService` | Finding recommendations |
| Reports | `ReportsService` | Report index scan selector |
| Reports | `ReportGenerationService` | Report building |
| Reports | `ExecutiveSummaryProcessor` / `ExecutiveSummaryPoller` | Background AI executive summaries for finished scans |
| Scans | `ScansService` | Scan data aggregation |
| Settings | `SettingsService` | Company info, logo, scan schedule, tour state |
| About | `AboutService` | Versions and the system info text |
| About | `UpdateCheckService` | GitHub latest-release check (typed `HttpClient`) |
| About | `UpdateCheckPoller` | Background update check, writes `UpdateCheckState` |

## Authentication & Authorization

- **Local cookie authentication** (`AddLocalAuthentication` in `Extensions/ServiceCollectionExtensions.cs`, `Verticals/Account/`).
- One admin per install, stored in the `users` collection under the fixed `_id` `"admin"` with a BCrypt hash. The fixed id makes first-run setup safe against concurrent submissions.
- `/setup` is reachable only while no admin exists (afterwards it redirects to `/login`) and only with the setup token (`SetupToken` singleton: `SETUP_TOKEN`, which `install.sh` generates into `.env`, or random per process; logged once at startup as `First-run setup: open http://localhost:<port>/setup?token=<token>`). A missing or wrong token gets 404 on GET and POST. `/login` without an admin renders `SetupPending`, which never shows the token. `/login` is rate-limited per IP (5 / 15 min) and account-wide (`login:admin`, 20 / 15 min) with `IpRateLimiterService.TryReserveAttempt`, which reserves the attempt before the BCrypt check; success resets. BCrypt verifies go through `BcryptGate` (one per core). `/logout` is a POST.
- Claims: `NameIdentifier` (user id), `Email`, `Name` (email). `triggered_by` reads these.
- Session revocation: the cookie carries `vulwall:security_stamp`; `OnValidatePrincipal` compares it with `users.security_stamp` (cached 30s, cleared on rotation) and rejects mismatches or a missing admin. Logout and the Settings "Change password" form (`POST /account/password`, Account vertical) rotate the stamp.
- All controller actions require `[Authorize]` unless explicitly public. Antiforgery is validated on every POST (global `AutoValidateAntiforgeryTokenAttribute`).
- Cookie `Secure` flag, HSTS and the HTTPS redirect follow `SECURE_COOKIES` (default `false` so plain `http://localhost` works).
- A hosted fork that needs SSO plugs an OIDC handler into `AddLocalAuthentication` and replaces `AccountController`; keep the rest of the app independent of the auth scheme.

## Database Patterns

### Repository Pattern
- All data access goes through repositories in `Data/Repositories/`
- Base classes: `BaseMongoRepository<T>`, `OrgScopedRepository<T>`
- Organization-scoped repositories automatically filter by the current organization
- Never call `UpdateAsync` (a full `ReplaceOne`) on documents the scanner also writes (`scans`, `findings`, `discoveries`): it drops fields the C# entity does not map. Use a `$set` partial update.

### Entities
- Located in `Data/Entities/`
- Implement `IOrganizationEntity` for org-scoped data
- MongoDB BsonElement attributes for field mapping

## Common Services

### Organization Context
- A self-hosted install has exactly one organization. `DefaultOrganization.EnsureExistsAsync` creates it at startup ("My Organization", random weekly `scan_settings.scan_cron`, `enabled: true`); `/setup` renames it.
- Scan schedule: Settings → Scan schedule (`ScanScheduleCron`) turns Off / Daily / Weekly / Monthly plus a local time and the browser's time zone (a hidden field that `js/Settings/index.js` fills from `Intl`; missing or unknown = the saved zone, else UTC) into a 5-field UTC `scan_settings.scan_cron`; Off sets `enabled: false` and keeps the cron. `scan_settings.timezone` is web-only (form display). Read the cron through `ScanSettings.ActiveCron` (null when off) everywhere a next scan is shown. The scanner reloads organizations every 5 minutes.
- `IOrganizationContext` always resolves that organization for an authenticated user. There is no org switching.
- Used by org-scoped repositories. Background jobs have no `HttpContext`: they use the `*PublicRepository` classes instead.

### Scanner Link
- **Trigger**: `ScanTriggerService` (Common) inserts a `scans` document with `status: "queued"`, `type: "requested"` and a string UUID `_id`. The scanner picks it up. There is no HTTP call to the scanner.
- **In progress**: a scan for the org with status `queued` (any age: the scanner always claims it eventually), or `pending`/`running` started in the last 24 hours (`started_at`, which the scanner sets when it claims or inserts a scan; `created_at` for scans without it) (`ScanTriggerService.InProgressPredicate`). Use it for every "scan running" check. Enabling, disabling and deleting assets is refused while a scan is in progress.
- **Scan now**: `ScanTriggerService.TriggerAsync` queues a scan only when none is in progress (`Started`); while a scan is queued, pending or running it inserts nothing (`Busy`), and every "Scan now" button (Scans, Overview, Discoveries, the dialog after adding an asset) is disabled with `ScanTriggerService.BusyMessage`. The web app never queues a scan behind a running one; the scanner does, when the schedule fires during a scan (a queued `type: "scheduled"` scan, shown as `ScanNowStateText.QueuedAfterCurrent`). Adding an asset never starts a scan. The unique partial index `org_id_1_queued_unique` (`MongoDbIndexManager`, `{org_id: 1}` where `status: "queued"`) keeps it to one queued scan per org under concurrent requests; a duplicate-key error reads as `Busy`. The scanner starts the oldest queued scan once nothing else runs and reads the assets at that moment.
- **Completion**: the scanner sets `status: "done"` (`"completed"` is also read as `Done`). `ExecutiveSummaryPoller` checks every 30s, claims each finished scan atomically (`executive_summary_status`: `processing` → `done` | `skipped` | `failed`) and writes `executive_summary` when `ANTHROPIC_API_KEY` is set. `failed` is retried up to 3 attempts (`executive_summary_attempts`, backoff 5 then 30 min from `executive_summary_claimed_at`); `skipped` is claimed again once AI is enabled (within the 7-day window). Scans with scan `status: "failed"` (including `status_reason: "interrupted_by_restart"`) never get a summary. There is no webhook.

### AI Services
- `AnthropicAIService`: Anthropic Claude AI integration for security recommendations
- Located in `Common/Services/AIServices/`
- Prompts stored in `Prompts/` directory

## Environment Configuration

- Use `EnvLoader` utility to load environment variables (`Common/Utils/ServiceSettings.cs`)
- Never commit secrets to version control; `src/Properties/launchSettings.json` is git-ignored (copy `launchSettings.example.json`)
- Variables: `MONGO_URI`, `MONGO_DB`, `PORT`, `ANTHROPIC_API_KEY` (optional), `DEFAULT_AI_MODEL` (the root compose file sets it from `ANTHROPIC_MODEL`, with the default filled in, because `EnvLoader` uses a set but empty value as-is), `SECURE_COOKIES`, `TRUSTED_PROXIES`, `SETUP_TOKEN`, `UPDATE_CHECK` (default `true`; unset, empty, `true`, `1`, `yes` or `on` keeps the background GitHub update check on; any other value turns it off, and a value that is not `false`, `0`, `no` or `off` logs a warning at start), `DATA_PROTECTION_KEYS_DIR` (image: `/data/keys` on the web-only `web-keys` volume; keys are deliberately not in MongoDB, which the scanner shares), `VULWALL_VERSION` (shown in the About dialog; a Dockerfile build arg, release images pass the tag, default `dev`; the root compose file passes `VULWALL_BUILD_VERSION`, which the root `make build`/`make up` set to `dev (<short commit>)`). See `README.md`.

## Testing

- `dotnet test` from `web/`. Tests that touch MongoDB use `MongoFixture` (EphemeralMongo starts a throwaway `mongod`; the binary is downloaded on first run) and `[Collection(MongoCollection.Name)]`, with one fresh database per test.

## Frontend JavaScript Architecture

### Theme System
VulWall implements a persistent theme system with light/dark mode support.

**Files:**
- `wwwroot/js/Common/theme-boot.js` - Loaded in `<head>` to prevent FOUC (Flash of Unstyled Content)
- `wwwroot/js/Common/site.js` - Theme toggle functionality with event handlers

**Implementation:**
- Theme preference stored in `localStorage` with key `"theme"`
- Syncs across browser tabs using `storage` event
- Uses Bootstrap's `data-bs-theme` attribute
- Optimized with cached DOM references for performance
- Icon toggling uses `classList` for better performance

**Theme Toggle:**
```javascript
// Icons automatically toggle based on theme
<button id="themeToggle">
    <i class="fas fa-sun theme-icon-light"></i>
    <i class="fas fa-moon theme-icon-dark"></i>
</button>
```

### JavaScript Organization Best Practices

**Module Pattern:**
- Use ES6 modules (`type="module"` in script tags)
- Export functions for reusability
- Keep related functionality together

**Performance:**
- Cache DOM queries in variables
- Use event delegation for dynamic elements
- Prefer `classList` over inline style manipulation
- Use `requestAnimationFrame` for animations

**Error Handling:**
- Always wrap `localStorage` operations in try-catch
- Provide console warnings for debugging
- Graceful degradation when features unavailable

**Example Module Structure:**
```javascript
// myFeature.js
export function initializeFeature() {
    const element = document.getElementById('myElement');
    if (!element) return; // Graceful exit if element doesn't exist

    element.addEventListener('click', handleClick);
}

function handleClick(e) {
    // Event handler logic
}
```
