Scan-activity heatmap — the GitHub-contributions-style calendar from the NightWatch Scans page. Each cell is one day, colored by the **worst severity** found in that day's scans; future days can be `scheduled` (striped) or out-of-range.

```jsx
<ScanHeatmap weeks={26} />
```

Pass `data` as an array of week columns (each a 7-element Sun→Sat array of `{ date, scans, sev, counts }`) to drive it with real scan history; omit it for the built-in sample. Cell colors come straight from the `--severity-*-solid` tokens (no-scan = gray, none = success green). Hovering a cell shows a tooltip with the per-severity breakdown. `legend` toggles the scale below.
