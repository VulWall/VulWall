# VulWall Component System

## Overview
VulWall uses Bootstrap 5 as its base component library with custom VulWall brand color overrides. All Bootstrap classes work out of the box with VulWall styling.

## Brand Colors

| Color Name       | Hex Code | CSS Variable              |
|------------------|----------|---------------------------|
| Dark Blue        | #212C5E  | `--brand-dark-blue`       |
| Blue             | #0056A1  | `--brand-blue`            |
| Very Dark Blue   | #101827  | `--brand-very-dark`       |
| Orange           | #F47D17  | `--brand-orange`          |
| Off White        | #FBFBFD  | `--brand-off-white`       |

## Semantic Colors

| Purpose   | Variable              | Color   |
|-----------|-----------------------|---------|
| Primary   | `--vw-primary`        | #0056A1 (Blue) - VulWall Main Brand Color |
| Secondary | `--vw-secondary`      | #334155 (Slate) - Neutral actions (NOT orange) |
| Success   | `--vw-success`        | #067647 (Green) |
| Warning   | `--vw-warning`        | #F59E0B (Amber) |
| Danger    | `--vw-danger`         | #DC2626 (Red) |
| Info      | `--vw-info`           | #2563EB (Blue — nudged off brand blue) |

---

## Components

### Buttons

#### Standard Buttons
```html
<!-- Primary CTA - Blue (VulWall Main Brand Color) -->
<button class="btn btn-primary">Save Changes</button>

<!-- Secondary - Slate/neutral for Cancel/Back actions -->
<button class="btn btn-secondary">Cancel</button>

<!-- Success -->
<button class="btn btn-success">Approve</button>

<!-- Warning -->
<button class="btn btn-warning">Review</button>

<!-- Danger -->
<button class="btn btn-danger">Delete</button>

<!-- Info -->
<button class="btn btn-info">Learn More</button>
```

#### Outline Buttons
```html
<button class="btn btn-outline-primary">Primary Outline</button>
<button class="btn btn-outline-secondary">Secondary Outline</button>
<button class="btn btn-outline-success">Success Outline</button>
<button class="btn btn-outline-danger">Danger Outline</button>
```

#### Button Sizes
```html
<button class="btn btn-primary btn-sm">Small</button>
<button class="btn btn-primary">Default</button>
<button class="btn btn-primary btn-lg">Large</button>
```

#### Link Button
```html
<button class="btn btn-link">Link Style</button>
```

#### Disabled State
```html
<button class="btn btn-primary" disabled>Disabled</button>
<button class="btn btn-primary disabled">Disabled</button>
```

---

### Badges

#### Standard Badges
```html
<span class="badge badge-primary">Primary</span>
<span class="badge badge-secondary">Secondary</span>
<span class="badge badge-success">Active</span>
<span class="badge badge-warning">Pending</span>
<span class="badge badge-danger">Failed</span>
<span class="badge badge-info">Info</span>
```

#### Pill Badges
```html
<span class="badge badge-primary rounded-pill">5</span>
<span class="badge badge-success rounded-pill">New</span>
```

#### Background Variants
```html
<span class="badge bg-primary">Primary</span>
<span class="badge bg-success">Success</span>
```

---

### Alerts

```html
<!-- Info Alert -->
<div class="alert alert-info" role="alert">
    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"/>
    </svg>
    <div>
        <strong>Information</strong>
        <p>This is an informational message.</p>
    </div>
</div>

<!-- Success Alert -->
<div class="alert alert-success" role="alert">
    <strong>Success!</strong> Your changes have been saved.
</div>

<!-- Warning Alert -->
<div class="alert alert-warning" role="alert">
    <strong>Warning!</strong> Please review before proceeding.
</div>

<!-- Danger Alert -->
<div class="alert alert-danger" role="alert">
    <strong>Error!</strong> Something went wrong.
</div>
```

---

### Forms

#### Text Input
```html
<div class="mb-3">
    <label for="email" class="form-label">Email address</label>
    <input type="email" class="form-control" id="email" placeholder="name@example.com">
    <div class="form-text">We'll never share your email.</div>
</div>
```

#### Select
```html
<div class="mb-3">
    <label for="country" class="form-label">Country</label>
    <select class="form-select" id="country">
        <option selected>Choose...</option>
        <option value="1">USA</option>
        <option value="2">UK</option>
    </select>
</div>
```

#### Validation States
```html
<!-- Valid -->
<input type="text" class="form-control is-valid" placeholder="Valid input">
<div class="valid-feedback">Looks good!</div>

<!-- Invalid -->
<input type="text" class="form-control is-invalid" placeholder="Invalid input">
<div class="invalid-feedback">Please provide a valid input.</div>
```

---

### Cards

```html
<div class="card">
    <div class="card-header">
        Featured
    </div>
    <div class="card-body">
        <h5 class="card-title">Card Title</h5>
        <p class="card-text">Card content goes here.</p>
        <button class="btn btn-primary">Action</button>
    </div>
    <div class="card-footer text-muted">
        2 days ago
    </div>
</div>
```

---

### Progress Bars

```html
<div class="progress">
    <div class="progress-bar" role="progressbar" style="width: 75%"></div>
</div>

<!-- Colored variants -->
<div class="progress">
    <div class="progress-bar bg-success" style="width: 50%"></div>
</div>
<div class="progress">
    <div class="progress-bar bg-warning" style="width: 60%"></div>
</div>
<div class="progress">
    <div class="progress-bar bg-danger" style="width: 80%"></div>
</div>
```

---

### Pagination

```html
<nav>
    <ul class="pagination">
        <li class="page-item disabled">
            <a class="page-link" href="#" tabindex="-1">Previous</a>
        </li>
        <li class="page-item"><a class="page-link" href="#">1</a></li>
        <li class="page-item active"><a class="page-link" href="#">2</a></li>
        <li class="page-item"><a class="page-link" href="#">3</a></li>
        <li class="page-item">
            <a class="page-link" href="#">Next</a>
        </li>
    </ul>
</nav>
```

---

### Modals

```html
<div class="modal fade" id="exampleModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Modal Title</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <p>Modal body text goes here.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary">Save changes</button>
            </div>
        </div>
    </div>
</div>
```

---

### Dropdowns

```html
<div class="dropdown">
    <button class="btn btn-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
        Dropdown
    </button>
    <ul class="dropdown-menu">
        <li><a class="dropdown-item" href="#">Action</a></li>
        <li><a class="dropdown-item" href="#">Another action</a></li>
        <li><hr class="dropdown-divider"></li>
        <li><a class="dropdown-item" href="#">Something else</a></li>
    </ul>
</div>
```

---

### Tables

```html
<!-- Basic Table -->
<table class="table">
    <thead>
        <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Status</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>John Doe</td>
            <td>john@example.com</td>
            <td><span class="badge badge-success">Active</span></td>
        </tr>
    </tbody>
</table>

<!-- Striped Table -->
<table class="table table-striped">
    <!-- ... -->
</table>

<!-- Hoverable Table -->
<table class="table table-hover">
    <!-- ... -->
</table>
```

---

## Severity/Status Badges

For vulnerability severity levels:

```html
<span class="badge" style="background-color: var(--severity-critical-bg); color: var(--severity-critical);">Critical</span>
<span class="badge" style="background-color: var(--severity-high-bg); color: var(--severity-high);">High</span>
<span class="badge" style="background-color: var(--severity-medium-bg); color: var(--severity-medium);">Medium</span>
<span class="badge" style="background-color: var(--severity-low-bg); color: var(--severity-low);">Low</span>
```

---

## Using CSS Variables Directly

You can use VulWall CSS variables in your custom components:

```html
<button style="background-color: var(--vw-primary); color: white;">
    Custom Button
</button>

<div style="color: var(--brand-dark-blue);">
    Custom Text
</div>
```

---

## Dark Mode Support

The component system includes dark mode support through `data-bs-theme` attribute:

```html
<html data-bs-theme="dark">
    <!-- Your content -->
</html>
```

Toggle between light and dark:
```javascript
document.documentElement.setAttribute('data-bs-theme', 'dark');
document.documentElement.setAttribute('data-bs-theme', 'light');
```

---

## Best Practices

1. **Primary Actions**: Use `btn-primary` (Blue) for main CTAs like "Save", "Submit", "Add Asset"
2. **Secondary Actions**: Use `btn-secondary` (Slate) for "Cancel", "Back", alternative actions. Use `.btn-accent` for orange accent CTAs.
3. **Destructive Actions**: Use `btn-danger` for "Delete", "Remove"
4. **Success Indicators**: Use `badge-success` for "Active", "Verified", "Completed"
5. **Warnings**: Use `badge-warning` for "Pending", "Review Required"
6. **Errors**: Use `badge-danger` for "Failed", "Error", "Blocked"

---

## Complete Color Reference

### All CSS Variables

```css
/* Brand Colors */
--brand-dark-blue: #212C5E
--brand-blue: #0056A1
--brand-very-dark: #101827
--brand-orange: #F47D17
--brand-off-white: #FBFBFD

/* Semantic Colors */
--vw-primary: #0056A1         /* Blue - VulWall Main Brand Color */
--vw-primary-hover: #004580
--vw-primary-active: #003A6D
--vw-secondary: #334155       /* Slate - Neutral (patch: was orange, now slate) */
--vw-secondary-hover: #1E293B
--vw-secondary-active: #0F172A
--vw-success: #067647
--vw-success-hover: #059669
--vw-success-light: #D1FAE5
--vw-success-dark: #065F46
--vw-warning: #F59E0B
--vw-warning-hover: #D97706
--vw-warning-light: #FEF3C7
--vw-warning-dark: #92400E
--vw-danger: #DC2626
--vw-danger-hover: #B91C1C
--vw-danger-light: #FEE2E2
--vw-danger-dark: #7F1D1D
--vw-info: #2563EB
--vw-info-hover: #1D4ED8
--vw-info-light: #DBEAFE
--vw-info-dark: #1E40AF

/* Severity Colors — own ramp, decoupled from brand orange (defined in Common/site.css) */
/* NEVER use brand orange for severity. Ramp: maroon→red→amber→gold→slate */
--severity-critical: #911D14     /* deep maroon */
--severity-critical-bg: #FEF3F2
--severity-high: #D92D20         /* red (was #F97316 orange — corrected) */
--severity-high-bg: #FEF3F2
--severity-medium: #B54708       /* dark amber */
--severity-medium-bg: #FFFAEB
--severity-low: #A16207          /* gold (was #3B82F6 blue — corrected) */
--severity-low-bg: #FEFBE8
--severity-info: #475569         /* slate — Info/None band */
--severity-info-bg: #F8FAFC

/* Gray Scale */
--vw-gray-50: #F9FAFB
--vw-gray-100: #F3F4F6
--vw-gray-200: #E5E7EB
--vw-gray-300: #D1D5DB
--vw-gray-400: #9CA3AF
--vw-gray-500: #6B7280
--vw-gray-600: #4B5563
--vw-gray-700: #374151
--vw-gray-800: #1F2937
--vw-gray-900: #111827
```
