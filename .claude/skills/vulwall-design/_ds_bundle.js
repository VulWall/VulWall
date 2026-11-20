/* @ds-bundle: {"format":3,"namespace":"VulWallDesignSystem_2af3fe","components":[{"name":"Button","sourcePath":"components/core/Button.jsx"},{"name":"Card","sourcePath":"components/core/Card.jsx"},{"name":"Input","sourcePath":"components/core/Input.jsx"},{"name":"SeverityBadge","sourcePath":"components/core/SeverityBadge.jsx"},{"name":"StatusPill","sourcePath":"components/core/StatusPill.jsx"},{"name":"FindingCard","sourcePath":"components/scan/FindingCard.jsx"},{"name":"ScanHeatmap","sourcePath":"components/scan/ScanHeatmap.jsx"},{"name":"ScoreRing","sourcePath":"components/scan/ScoreRing.jsx"},{"name":"StatCard","sourcePath":"components/scan/StatCard.jsx"}],"sourceHashes":{"components/core/Button.jsx":"e3a4c0f005f7","components/core/Card.jsx":"1c85d5af5648","components/core/Input.jsx":"c42df71740e1","components/core/SeverityBadge.jsx":"0a0ed1f3cee0","components/core/StatusPill.jsx":"3be0d14052b4","components/scan/FindingCard.jsx":"cfd7a30d7df0","components/scan/ScanHeatmap.jsx":"60abcb5fb261","components/scan/ScoreRing.jsx":"0f7cde50148a","components/scan/StatCard.jsx":"4723af3e6200","ui_kits/dashboard/App.jsx":"c5dbbbad82ba","ui_kits/dashboard/Assets.jsx":"4c8124969cea","ui_kits/dashboard/FindingDetail.jsx":"519fc54d0800","ui_kits/dashboard/Findings.jsx":"e023ae9416e7","ui_kits/dashboard/Overview.jsx":"16bb51b70494","ui_kits/dashboard/Sidebar.jsx":"9bb1fdd1cfd4","ui_kits/dashboard/data.jsx":"e5a860df5ed7"},"inlinedExternals":[],"unexposedExports":[]} */

(() => {

const __ds_ns = (window.VulWallDesignSystem_2af3fe = window.VulWallDesignSystem_2af3fe || {});

const __ds_scope = {};

(__ds_ns.__errors = __ds_ns.__errors || []);

// components/core/Button.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const CSS = `
.vw-btn {
  font-family: var(--font-primary);
  font-weight: 600;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  line-height: 1;
  transition: all var(--dur-normal) var(--ease-standard);
  white-space: nowrap;
  text-decoration: none;
}
.vw-btn:focus-visible { outline: none; box-shadow: var(--shadow-focus); }
.vw-btn-md { padding: 10px 18px; font-size: 14px; }
.vw-btn-sm { padding: 7px 13px; font-size: 13px; border-radius: var(--radius-sm); }
.vw-btn-lg { padding: 13px 26px; font-size: 16px; }

.vw-btn-primary { background: var(--vw-primary); border-color: var(--vw-primary); color: var(--brand-off-white); }
.vw-btn-primary:hover { background: var(--vw-primary-hover); border-color: var(--vw-primary-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,86,161,.25); }
.vw-btn-primary:active { background: var(--vw-primary-active); transform: translateY(0); }

.vw-btn-accent { background: var(--accent-orange); border-color: var(--accent-orange); color: var(--accent-orange-on); }
.vw-btn-accent:hover { background: var(--accent-orange-hover); border-color: var(--accent-orange-hover); transform: translateY(-1px); }
.vw-btn-accent:active { transform: translateY(0); }

.vw-btn-secondary { background: var(--surface-card); border-color: var(--border-strong); color: var(--text-heading); }
.vw-btn-secondary:hover { background: var(--vw-gray-50); border-color: var(--vw-gray-400); }

.vw-btn-ghost { background: transparent; border-color: transparent; color: var(--vw-primary); }
.vw-btn-ghost:hover { background: var(--vw-gray-100); }

.vw-btn-danger { background: var(--vw-danger); border-color: var(--vw-danger); color: #fff; }
.vw-btn-danger:hover { background: var(--vw-danger-hover); border-color: var(--vw-danger-hover); transform: translateY(-1px); }

.vw-btn:disabled { background: var(--vw-gray-200); border-color: var(--vw-gray-200); color: var(--vw-gray-400); cursor: not-allowed; transform: none; box-shadow: none; }
`;
function useInjectCSS(id, css) {
  React.useEffect(() => {
    if (document.getElementById(id)) return;
    const el = document.createElement('style');
    el.id = id;
    el.textContent = css;
    document.head.appendChild(el);
  }, [id, css]);
}

/**
 * VulWall primary button. Cobalt = primary action; orange accent reserved
 * for upgrade/highlight; neutral/ghost for secondary; danger for destructive.
 */
function Button({
  variant = 'primary',
  size = 'md',
  icon,
  children,
  disabled = false,
  onClick,
  type = 'button',
  style,
  ...rest
}) {
  useInjectCSS('vw-btn-css', CSS);
  return /*#__PURE__*/React.createElement("button", _extends({
    type: type,
    className: `vw-btn vw-btn-${size} vw-btn-${variant}`,
    disabled: disabled,
    onClick: onClick,
    style: style
  }, rest), icon ? /*#__PURE__*/React.createElement("i", {
    className: icon,
    "aria-hidden": "true"
  }) : null, children);
}
Object.assign(__ds_scope, { Button });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Button.jsx", error: String((e && e.message) || e) }); }

// components/core/Card.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/** Base surface card — white, soft navy shadow + hairline border, 12px radius. */
function Card({
  children,
  padding = 20,
  interactive = false,
  style,
  ...rest
}) {
  const [hover, setHover] = React.useState(false);
  return /*#__PURE__*/React.createElement("div", _extends({
    onMouseEnter: () => interactive && setHover(true),
    onMouseLeave: () => interactive && setHover(false),
    style: {
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      boxShadow: hover ? 'var(--shadow-lg)' : 'var(--shadow-card)',
      padding: typeof padding === 'number' ? `${padding}px` : padding,
      transition: 'box-shadow var(--dur-normal) var(--ease-standard), transform var(--dur-normal) var(--ease-standard)',
      transform: hover ? 'translateY(-2px)' : 'none',
      cursor: interactive ? 'pointer' : 'default',
      ...style
    }
  }, rest), children);
}
Object.assign(__ds_scope, { Card });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Card.jsx", error: String((e && e.message) || e) }); }

// components/core/Input.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const CSS = `
.vw-input-wrap { display:flex; flex-direction:column; gap:6px; font-family:var(--font-primary); }
.vw-input-label { font-size:13px; font-weight:500; color:var(--text-heading); }
.vw-input-field { display:flex; align-items:center; gap:8px; background:var(--surface-card);
  border:1px solid var(--border-strong); border-radius:var(--radius-md); padding:9px 13px;
  transition:border-color var(--dur-normal) var(--ease-standard), box-shadow var(--dur-normal) var(--ease-standard); }
.vw-input-field:focus-within { border-color:var(--border-focus); box-shadow:var(--shadow-focus); }
.vw-input-field.is-invalid { border-color:var(--vw-danger); background:var(--vw-danger-bg); }
.vw-input-prefix { font-family:var(--font-mono); font-size:13px; color:var(--text-faint); }
.vw-input-el { flex:1; border:none; outline:none; background:transparent; font-family:var(--font-primary);
  font-size:15px; color:var(--text-body); min-width:0; }
.vw-input-el::placeholder { color:var(--text-faint); }
.vw-input-err { font-size:12px; color:var(--vw-danger); }
`;
function useInjectCSS(id, css) {
  React.useEffect(() => {
    if (document.getElementById(id)) return;
    const el = document.createElement('style');
    el.id = id;
    el.textContent = css;
    document.head.appendChild(el);
  }, [id, css]);
}

/** Text input with optional label, mono prefix (e.g. https://), and error state. */
function Input({
  label,
  prefix,
  error,
  invalid = false,
  value,
  placeholder,
  onChange,
  type = 'text',
  style,
  ...rest
}) {
  useInjectCSS('vw-input-css', CSS);
  return /*#__PURE__*/React.createElement("label", {
    className: "vw-input-wrap",
    style: style
  }, label ? /*#__PURE__*/React.createElement("span", {
    className: "vw-input-label"
  }, label) : null, /*#__PURE__*/React.createElement("span", {
    className: `vw-input-field${invalid || error ? ' is-invalid' : ''}`
  }, prefix ? /*#__PURE__*/React.createElement("span", {
    className: "vw-input-prefix"
  }, prefix) : null, /*#__PURE__*/React.createElement("input", _extends({
    className: "vw-input-el",
    type: type,
    value: value,
    placeholder: placeholder,
    onChange: onChange
  }, rest))), error ? /*#__PURE__*/React.createElement("span", {
    className: "vw-input-err"
  }, error) : null);
}
Object.assign(__ds_scope, { Input });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Input.jsx", error: String((e && e.message) || e) }); }

// components/core/SeverityBadge.jsx
try { (() => {
const LEVELS = {
  critical: {
    label: 'Critical',
    bg: 'var(--severity-critical-bg)',
    bd: 'var(--severity-critical-border)',
    fg: 'var(--severity-critical)',
    dot: 'var(--severity-critical-solid)'
  },
  high: {
    label: 'High',
    bg: 'var(--severity-high-bg)',
    bd: 'var(--severity-high-border)',
    fg: 'var(--severity-high)',
    dot: 'var(--severity-high-solid)'
  },
  medium: {
    label: 'Medium',
    bg: 'var(--severity-medium-bg)',
    bd: 'var(--severity-medium-border)',
    fg: 'var(--severity-medium)',
    dot: 'var(--severity-medium-solid)'
  },
  low: {
    label: 'Low',
    bg: 'var(--severity-low-bg)',
    bd: 'var(--severity-low-border)',
    fg: 'var(--severity-low)',
    dot: 'var(--severity-low-solid)'
  },
  info: {
    label: 'Info',
    bg: 'var(--severity-info-bg)',
    bd: 'var(--severity-info-border)',
    fg: 'var(--severity-info)',
    dot: 'var(--severity-info-solid)'
  }
};

/**
 * Severity pill — tint background, readable text, solid status dot.
 * Uses the dedicated severity ramp (never brand orange).
 */
function SeverityBadge({
  level = 'info',
  label,
  style
}) {
  const s = LEVELS[level] || LEVELS.info;
  return /*#__PURE__*/React.createElement("span", {
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      fontFamily: 'var(--font-primary)',
      fontSize: '12px',
      fontWeight: 600,
      lineHeight: 1,
      padding: '4px 11px',
      borderRadius: 'var(--radius-pill)',
      background: s.bg,
      border: `1px solid ${s.bd}`,
      color: s.fg,
      ...style
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: '6px',
      height: '6px',
      borderRadius: '50%',
      background: s.dot
    }
  }), label || s.label);
}
Object.assign(__ds_scope, { SeverityBadge });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/SeverityBadge.jsx", error: String((e && e.message) || e) }); }

// components/core/StatusPill.jsx
try { (() => {
const TONES = {
  secure: {
    label: 'Secure',
    bg: 'var(--vw-success-bg)',
    bd: 'var(--vw-success-border)',
    fg: 'var(--vw-success)',
    dot: 'var(--vw-success)'
  },
  scanning: {
    label: 'Scanning',
    bg: 'var(--vw-info-bg)',
    bd: 'var(--vw-info-border)',
    fg: 'var(--vw-primary)',
    dot: 'var(--vw-primary)'
  },
  resolved: {
    label: 'Resolved',
    bg: 'var(--vw-gray-50)',
    bd: 'var(--border-default)',
    fg: 'var(--text-muted)',
    dot: 'var(--vw-gray-400)'
  },
  open: {
    label: 'Open',
    bg: 'var(--severity-high-bg)',
    bd: 'var(--severity-high-border)',
    fg: 'var(--vw-danger-hover)',
    dot: 'var(--vw-danger)'
  },
  neutral: {
    label: 'Status',
    bg: 'var(--vw-gray-50)',
    bd: 'var(--border-default)',
    fg: 'var(--text-body)',
    dot: 'var(--vw-gray-400)'
  }
};

/** Status pill — secure / scanning / resolved / open. Pulsing dot when scanning. */
function StatusPill({
  tone = 'neutral',
  label,
  pulse = false,
  style
}) {
  const t = TONES[tone] || TONES.neutral;
  return /*#__PURE__*/React.createElement("span", {
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      fontFamily: 'var(--font-primary)',
      fontSize: '12px',
      fontWeight: 600,
      lineHeight: 1,
      padding: '4px 11px',
      borderRadius: 'var(--radius-pill)',
      background: t.bg,
      border: `1px solid ${t.bd}`,
      color: t.fg,
      ...style
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: '6px',
      height: '6px',
      borderRadius: '50%',
      background: t.dot,
      animation: pulse ? 'vw-pulse 1.4s var(--ease-standard) infinite' : 'none'
    }
  }), label || t.label, /*#__PURE__*/React.createElement("style", null, `@keyframes vw-pulse { 0%,100%{opacity:1} 50%{opacity:.35} }`));
}
Object.assign(__ds_scope, { StatusPill });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/StatusPill.jsx", error: String((e && e.message) || e) }); }

// components/scan/FindingCard.jsx
try { (() => {
const SOLID = {
  critical: 'var(--severity-critical-solid)',
  high: 'var(--severity-high-solid)',
  medium: 'var(--severity-medium-solid)',
  low: 'var(--severity-low-solid)',
  info: 'var(--severity-info-solid)'
};

/**
 * Vulnerability finding card. Severity-colored left accent + pill, mono meta
 * (CVE / host), plain-English title & body, and primary/secondary actions.
 */
function FindingCard({
  level = 'high',
  title,
  description,
  cve,
  host,
  port,
  onFix,
  onMute,
  style
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderLeft: `4px solid ${SOLID[level] || SOLID.info}`,
      borderRadius: 'var(--radius-lg)',
      boxShadow: 'var(--shadow-card)',
      padding: '18px 20px',
      fontFamily: 'var(--font-primary)',
      ...style
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'flex-start',
      justifyContent: 'space-between',
      gap: '16px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
      flexWrap: 'wrap',
      marginBottom: '8px'
    }
  }, /*#__PURE__*/React.createElement(__ds_scope.SeverityBadge, {
    level: level
  }), cve ? /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-mono)',
      fontSize: '12px',
      color: 'var(--text-muted)'
    }
  }, cve) : null, cve && (host || port) ? /*#__PURE__*/React.createElement("span", {
    style: {
      color: 'var(--text-faint)'
    }
  }, "\xB7") : null, host ? /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-mono)',
      fontSize: '12px',
      color: 'var(--text-muted)'
    }
  }, host, port ? `:${port}` : '') : null), /*#__PURE__*/React.createElement("h4", {
    style: {
      fontSize: '17px',
      fontWeight: 600,
      color: 'var(--text-heading)',
      margin: '0 0 6px'
    }
  }, title), description ? /*#__PURE__*/React.createElement("p", {
    style: {
      fontSize: '14px',
      color: 'var(--text-body)',
      lineHeight: 1.6,
      margin: 0
    }
  }, description) : null), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '8px',
      flexShrink: 0
    }
  }, onFix ? /*#__PURE__*/React.createElement(__ds_scope.Button, {
    variant: "primary",
    size: "sm",
    onClick: onFix
  }, "How to fix") : null, onMute ? /*#__PURE__*/React.createElement(__ds_scope.Button, {
    variant: "secondary",
    size: "sm",
    onClick: onMute
  }, "Mute") : null)));
}
Object.assign(__ds_scope, { FindingCard });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/scan/FindingCard.jsx", error: String((e && e.message) || e) }); }

// components/scan/ScanHeatmap.jsx
try { (() => {
const CSS = `
.vw-hm-wrap { overflow-x: auto; padding-bottom: 6px; scrollbar-width: thin; }
.vw-hm-wrap::-webkit-scrollbar { height: 8px; }
.vw-hm-wrap::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 4px; }
.vw-hm-months { position: relative; height: 18px; margin-left: 34px; margin-bottom: 4px; min-width: fit-content; }
.vw-hm-month { position: absolute; font-size: 11px; font-weight: 500; color: var(--text-muted); }
.vw-hm-main { display: flex; gap: 8px; min-width: fit-content; }
.vw-hm-days { display: flex; flex-direction: column; gap: 4px; padding-top: 2px; }
.vw-hm-day { height: 14px; line-height: 14px; font-size: 11px; color: var(--text-muted); width: 30px; }
.vw-hm-weeks { display: flex; gap: 4px; }
.vw-hm-week { display: flex; flex-direction: column; gap: 4px; }
.vw-hm-cell { width: 14px; height: 14px; border-radius: 2px; cursor: pointer; transition: outline .15s var(--ease-standard); outline: 2px solid transparent; outline-offset: -1px; }
.vw-hm-cell:hover.vw-hm-has { outline-color: var(--vw-primary); }
.vw-hm-out { background: transparent !important; cursor: default; }
.vw-hm-noscan { background: var(--vw-gray-200); }
.vw-hm-sev-none     { background: var(--vw-success); }
.vw-hm-sev-low      { background: var(--severity-low-solid); }
.vw-hm-sev-medium   { background: var(--severity-medium-solid); }
.vw-hm-sev-high     { background: var(--severity-high-solid); }
.vw-hm-sev-critical { background: var(--severity-critical-solid); }
.vw-hm-scheduled { background: repeating-linear-gradient(45deg, var(--vw-primary), var(--vw-primary) 2px, transparent 2px, transparent 4px); opacity: .6; }
.vw-hm-legend { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-muted); font-family: var(--font-primary); margin-top: 12px; }
.vw-hm-legend .vw-hm-cell { cursor: default; }
`;
function useInjectCSS(id, css) {
  React.useEffect(() => {
    if (document.getElementById(id)) return;
    const el = document.createElement('style');
    el.id = id;
    el.textContent = css;
    document.head.appendChild(el);
  }, [id, css]);
}
const SEV_ORDER = ['none', 'low', 'medium', 'high', 'critical'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DAY_LABELS = ['', 'Mon', '', 'Wed', '', 'Fri', ''];

// Deterministic pseudo-random so the preview is stable across renders.
function seeded(i) {
  const x = Math.sin(i * 99.13) * 10000;
  return x - Math.floor(x);
}
function genWeeks(numWeeks) {
  const today = new Date();
  const end = new Date(today);
  // Walk back to the most recent Saturday so columns align to weeks.
  end.setDate(end.getDate() + (6 - end.getDay()));
  const cells = [];
  const totalDays = numWeeks * 7;
  for (let i = totalDays - 1; i >= 0; i--) {
    const d = new Date(end);
    d.setDate(end.getDate() - i);
    const future = d > today;
    const r = seeded(i + 7);
    let cell;
    if (future) {
      cell = i % 7 === 2 ? {
        date: d,
        scheduled: true
      } : {
        date: d,
        out: true
      };
    } else if (r < 0.45) {
      cell = {
        date: d,
        scans: 0,
        sev: null
      };
    } else {
      const sevRoll = seeded(i * 1.7);
      const sev = sevRoll > 0.93 ? 'critical' : sevRoll > 0.82 ? 'high' : sevRoll > 0.62 ? 'medium' : sevRoll > 0.4 ? 'low' : 'none';
      const counts = {};
      SEV_ORDER.forEach(s => {
        counts[s] = 0;
      });
      const worstIdx = SEV_ORDER.indexOf(sev);
      counts[sev] = 1 + Math.floor(seeded(i * 3.1) * 3);
      if (worstIdx > 0 && seeded(i * 5.5) > 0.5) counts[SEV_ORDER[worstIdx - 1]] = 1 + Math.floor(seeded(i) * 2);
      cell = {
        date: d,
        scans: 1 + Math.floor(seeded(i * 2.2) * 4),
        sev,
        counts
      };
    }
    cells.push(cell);
  }
  // Chunk into weeks (columns of 7, Sunday→Saturday).
  const weeks = [];
  for (let w = 0; w < numWeeks; w++) weeks.push(cells.slice(w * 7, w * 7 + 7));
  return weeks;
}
function cellClass(c) {
  if (c.out) return 'vw-hm-cell vw-hm-out';
  if (c.scheduled) return 'vw-hm-cell vw-hm-scheduled vw-hm-has';
  if (c.scans === 0) return 'vw-hm-cell vw-hm-noscan vw-hm-has';
  return `vw-hm-cell vw-hm-sev-${c.sev} vw-hm-has`;
}
const SEV_LABEL = {
  none: 'No issues',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical'
};
const SEV_VAR = {
  critical: 'var(--severity-critical)',
  high: 'var(--severity-high)',
  medium: 'var(--severity-medium)',
  low: 'var(--severity-low)'
};

/**
 * Scan-activity heatmap — GitHub-contributions-style calendar where each cell
 * is a day colored by the worst severity found in that day's scans.
 */
function ScanHeatmap({
  weeks = 26,
  data,
  legend = true,
  style
}) {
  useInjectCSS('vw-hm-css', CSS);
  const grid = React.useMemo(() => data || genWeeks(weeks), [data, weeks]);
  const [tip, setTip] = React.useState(null);

  // Month labels: place above the first week whose first day starts a new month.
  const monthMarks = [];
  let lastMonth = -1;
  grid.forEach((wk, wi) => {
    const first = wk.find(c => c && c.date);
    if (!first) return;
    const m = first.date.getMonth();
    if (m !== lastMonth) {
      monthMarks.push({
        label: MONTHS[m],
        left: wi * 18
      });
      lastMonth = m;
    }
  });
  function fmt(d) {
    return d.toLocaleDateString('en-US', {
      weekday: 'short',
      month: 'short',
      day: 'numeric'
    });
  }
  return /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: 'var(--font-primary)',
      ...style
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-hm-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-hm-months",
    style: {
      width: grid.length * 18
    }
  }, monthMarks.map((m, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    className: "vw-hm-month",
    style: {
      left: m.left
    }
  }, m.label))), /*#__PURE__*/React.createElement("div", {
    className: "vw-hm-main"
  }, /*#__PURE__*/React.createElement("div", {
    className: "vw-hm-days"
  }, DAY_LABELS.map((d, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "vw-hm-day"
  }, d))), /*#__PURE__*/React.createElement("div", {
    className: "vw-hm-weeks"
  }, grid.map((wk, wi) => /*#__PURE__*/React.createElement("div", {
    key: wi,
    className: "vw-hm-week"
  }, wk.map((c, di) => /*#__PURE__*/React.createElement("div", {
    key: di,
    className: cellClass(c),
    onMouseEnter: e => !c.out && setTip({
      c,
      x: e.clientX,
      y: e.clientY
    }),
    onMouseMove: e => !c.out && setTip(t => t ? {
      ...t,
      x: e.clientX,
      y: e.clientY
    } : t),
    onMouseLeave: () => setTip(null)
  }))))))), legend ? /*#__PURE__*/React.createElement("div", {
    className: "vw-hm-legend"
  }, /*#__PURE__*/React.createElement("span", null, "Less"), /*#__PURE__*/React.createElement("span", {
    className: "vw-hm-cell vw-hm-sev-none"
  }), /*#__PURE__*/React.createElement("span", {
    className: "vw-hm-cell vw-hm-sev-low"
  }), /*#__PURE__*/React.createElement("span", {
    className: "vw-hm-cell vw-hm-sev-medium"
  }), /*#__PURE__*/React.createElement("span", {
    className: "vw-hm-cell vw-hm-sev-high"
  }), /*#__PURE__*/React.createElement("span", {
    className: "vw-hm-cell vw-hm-sev-critical"
  }), /*#__PURE__*/React.createElement("span", null, "More severe"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: '14px',
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px'
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "vw-hm-cell vw-hm-scheduled"
  }), "Scheduled")) : null, tip ? /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'fixed',
      left: tip.x + 14,
      top: tip.y + 14,
      zIndex: 1050,
      pointerEvents: 'none',
      minWidth: '180px',
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderRadius: '6px',
      padding: '10px 12px',
      boxShadow: 'var(--shadow-lg)',
      fontFamily: 'var(--font-primary)'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      fontSize: '13px',
      color: 'var(--text-heading)',
      marginBottom: '5px'
    }
  }, fmt(tip.c.date)), tip.c.scheduled ? /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '13px',
      color: 'var(--vw-primary)',
      fontWeight: 500,
      display: 'flex',
      alignItems: 'center',
      gap: '6px'
    }
  }, /*#__PURE__*/React.createElement("i", {
    className: "fas fa-clock"
  }), "Scan scheduled") : tip.c.scans === 0 ? /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '13px',
      color: 'var(--text-muted)'
    }
  }, "No scans") : /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '12px',
      color: 'var(--text-muted)',
      marginBottom: '6px'
    }
  }, tip.c.scans, " scan", tip.c.scans > 1 ? 's' : ''), tip.c.sev === 'none' ? /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '13px',
      color: 'var(--vw-success)',
      fontWeight: 500,
      borderTop: '1px solid var(--border-default)',
      paddingTop: '6px'
    }
  }, "No issues found") : /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '5px',
      borderTop: '1px solid var(--border-default)',
      paddingTop: '6px'
    }
  }, SEV_ORDER.slice().reverse().filter(s => s !== 'none' && tip.c.counts && tip.c.counts[s] > 0).map(s => /*#__PURE__*/React.createElement("div", {
    key: s,
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      fontSize: '13px',
      color: 'var(--text-body)'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: '10px',
      height: '10px',
      borderRadius: '50%',
      background: SEV_VAR[s]
    }
  }), tip.c.counts[s], " ", SEV_LABEL[s]))))) : null);
}
Object.assign(__ds_scope, { ScanHeatmap });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/scan/ScanHeatmap.jsx", error: String((e && e.message) || e) }); }

// components/scan/ScoreRing.jsx
try { (() => {
/** Security score ring (0–100). Color band follows the score, not brand orange. */
function ScoreRing({
  score = 72,
  max = 100,
  size = 120,
  label
}) {
  const r = 50,
    c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(1, score / max));
  const offset = c * (1 - pct);
  // Score color: high=green, mid=amber, low=red — uses severity-solid hues.
  const color = pct >= 0.8 ? 'var(--vw-success)' : pct >= 0.5 ? 'var(--severity-medium-solid)' : 'var(--severity-high-solid)';
  return /*#__PURE__*/React.createElement("svg", {
    width: size,
    height: size,
    viewBox: "0 0 120 120",
    style: {
      display: 'block'
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "60",
    cy: "60",
    r: r,
    fill: "none",
    stroke: "var(--vw-gray-100)",
    strokeWidth: "14"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "60",
    cy: "60",
    r: r,
    fill: "none",
    stroke: color,
    strokeWidth: "14",
    strokeLinecap: "round",
    strokeDasharray: c,
    strokeDashoffset: offset,
    transform: "rotate(-90 60 60)",
    style: {
      transition: 'stroke-dashoffset 0.6s var(--ease-standard)'
    }
  }), /*#__PURE__*/React.createElement("text", {
    x: "60",
    y: label ? 55 : 67,
    textAnchor: "middle",
    fontFamily: "var(--font-primary)",
    fontSize: "30",
    fontWeight: "700",
    fill: "var(--text-heading)"
  }, score), label ? /*#__PURE__*/React.createElement("text", {
    x: "60",
    y: "76",
    textAnchor: "middle",
    fontFamily: "var(--font-primary)",
    fontSize: "11",
    fontWeight: "500",
    fill: "var(--text-faint)"
  }, label) : /*#__PURE__*/React.createElement("text", {
    x: "60",
    y: "82",
    textAnchor: "middle",
    fontFamily: "var(--font-primary)",
    fontSize: "11",
    fontWeight: "500",
    fill: "var(--text-faint)"
  }, "/ ", max));
}
Object.assign(__ds_scope, { ScoreRing });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/scan/ScoreRing.jsx", error: String((e && e.message) || e) }); }

// components/scan/StatCard.jsx
try { (() => {
const TONES = {
  critical: 'var(--severity-critical-solid)',
  high: 'var(--severity-high-solid)',
  medium: 'var(--severity-medium-solid)',
  low: 'var(--severity-low-solid)',
  passed: 'var(--vw-success)',
  neutral: 'var(--text-heading)'
};

/** Single metric card — big number + label, color-keyed to a severity/status tone. */
function StatCard({
  value,
  label,
  tone = 'neutral',
  icon,
  style
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      boxShadow: 'var(--shadow-card)',
      padding: '16px 18px',
      fontFamily: 'var(--font-primary)',
      ...style
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px'
    }
  }, icon ? /*#__PURE__*/React.createElement("i", {
    className: icon,
    style: {
      color: TONES[tone],
      fontSize: '14px'
    },
    "aria-hidden": "true"
  }) : null, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '28px',
      fontWeight: 700,
      color: TONES[tone],
      lineHeight: 1
    }
  }, value)), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '13px',
      color: 'var(--text-muted)',
      marginTop: '6px'
    }
  }, label));
}
Object.assign(__ds_scope, { StatCard });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/scan/StatCard.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/App.jsx
try { (() => {
// NightWatch dashboard — app shell + simple view routing.
const {
  useState: useAppState
} = React;
function App() {
  const [view, setView] = useAppState('overview'); // overview | findings | assets | reports | scanners
  const [findingId, setFindingId] = useAppState(null);
  const [theme, setTheme] = useAppState('light');
  const [toast, setToast] = useAppState(null);
  function navigate(v) {
    setFindingId(null);
    setView(v);
  }
  function openFinding(id) {
    setFindingId(id);
  }
  function toggleTheme() {
    const next = theme === 'light' ? 'dark' : 'light';
    setTheme(next);
    document.documentElement.setAttribute('data-bs-theme', next);
  }
  function rescan() {
    setToast('Scan queued — NightWatch is checking your perimeter.');
    setTimeout(() => setToast(null), 2600);
  }
  let body;
  if (findingId != null) {
    body = /*#__PURE__*/React.createElement(window.FindingDetail, {
      id: findingId,
      onBack: () => setFindingId(null)
    });
  } else if (view === 'overview') {
    body = /*#__PURE__*/React.createElement(window.Overview, {
      onOpenFinding: openFinding,
      onRescan: rescan
    });
  } else if (view === 'findings') {
    body = /*#__PURE__*/React.createElement(window.Findings, {
      onOpenFinding: openFinding
    });
  } else if (view === 'assets') {
    body = /*#__PURE__*/React.createElement(window.Assets, null);
  } else {
    body = /*#__PURE__*/React.createElement("div", {
      style: {
        textAlign: 'center',
        padding: '80px 20px',
        color: 'var(--text-faint)'
      }
    }, /*#__PURE__*/React.createElement("i", {
      className: "fas fa-screwdriver-wrench",
      style: {
        fontSize: '32px',
        marginBottom: '14px'
      }
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: '15px'
      }
    }, "This section is part of the full product."));
  }
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      minHeight: '100vh',
      background: 'var(--app-bg)'
    }
  }, /*#__PURE__*/React.createElement(window.Sidebar, {
    active: findingId != null ? 'findings' : view,
    onNavigate: navigate,
    theme: theme,
    onToggleTheme: toggleTheme
  }), /*#__PURE__*/React.createElement("main", {
    style: {
      flex: 1,
      minWidth: 0,
      padding: '30px 34px',
      overflowX: 'hidden'
    }
  }, body), toast ? /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'fixed',
      bottom: '24px',
      left: '50%',
      transform: 'translateX(-50%)',
      background: 'var(--surface-inverse)',
      color: '#fff',
      padding: '12px 20px',
      borderRadius: 'var(--radius-md)',
      boxShadow: 'var(--shadow-lg)',
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
      fontSize: '14px',
      fontFamily: 'var(--font-primary)',
      zIndex: 100
    }
  }, /*#__PURE__*/React.createElement("i", {
    className: "fas fa-radar",
    style: {
      color: 'var(--accent-orange)'
    }
  }), toast) : null);
}

// Expose only — index.html does the single, deterministic mount. (No top-level
// side-effect here: this file is also swept into _ds_bundle.js, and a mount at
// module-eval time would run twice and double-create the React root.)
Object.assign(window, {
  App
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/App.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/Assets.jsx
try { (() => {
// Assets screen — discovered hosts with status + tech.
const {
  StatusPill,
  Button: BtnA
} = window.VulWallDesignSystem_2af3fe;
function Assets() {
  const assets = window.ASSETS;
  return /*#__PURE__*/React.createElement("div", null, window.PageHeader ? /*#__PURE__*/React.createElement(window.PageHeader, {
    title: "Assets",
    subtitle: `${assets.length} discovered hosts · 1 apex domain`,
    action: /*#__PURE__*/React.createElement(BtnA, {
      variant: "primary",
      icon: "fas fa-plus"
    }, "Add asset")
  }) : null, /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      boxShadow: 'var(--shadow-card)',
      overflow: 'hidden'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '2fr 1.2fr 1fr 1.4fr 0.8fr',
      gap: '12px',
      padding: '12px 18px',
      borderBottom: '1px solid var(--border-default)',
      background: 'var(--surface-sunken)',
      fontSize: '11px',
      fontWeight: 600,
      letterSpacing: 'var(--tracking-wider)',
      color: 'var(--text-faint)',
      textTransform: 'uppercase'
    }
  }, /*#__PURE__*/React.createElement("span", null, "Host"), /*#__PURE__*/React.createElement("span", null, "Type"), /*#__PURE__*/React.createElement("span", null, "Status"), /*#__PURE__*/React.createElement("span", null, "Technology"), /*#__PURE__*/React.createElement("span", {
    style: {
      textAlign: 'right'
    }
  }, "Findings")), assets.map((a, i) => /*#__PURE__*/React.createElement("div", {
    key: a.host,
    style: {
      display: 'grid',
      gridTemplateColumns: '2fr 1.2fr 1fr 1.4fr 0.8fr',
      gap: '12px',
      alignItems: 'center',
      padding: '14px 18px',
      borderBottom: i < assets.length - 1 ? '1px solid var(--border-default)' : 'none',
      fontFamily: 'var(--font-primary)'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-mono)',
      fontSize: '13px',
      color: 'var(--text-heading)',
      fontWeight: 500
    }
  }, a.host), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      color: 'var(--text-muted)'
    }
  }, a.type), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement(StatusPill, {
    tone: a.status,
    pulse: a.status === 'scanning'
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      color: 'var(--text-body)'
    }
  }, a.tech), /*#__PURE__*/React.createElement("span", {
    style: {
      textAlign: 'right',
      fontSize: '14px',
      fontWeight: 700,
      color: a.findings > 0 ? 'var(--severity-high)' : 'var(--vw-success)'
    }
  }, a.findings)))));
}
Object.assign(window, {
  Assets
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/Assets.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/FindingDetail.jsx
try { (() => {
// Finding detail panel — full finding + AI recommendation + fix steps.
const {
  SeverityBadge: SevD,
  Button: BtnD,
  StatusPill: PillD
} = window.VulWallDesignSystem_2af3fe;
function MetaRow({
  label,
  value,
  mono
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      gap: '12px',
      padding: '9px 0',
      borderBottom: '1px solid var(--border-default)'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      color: 'var(--text-muted)'
    }
  }, label), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      color: 'var(--text-heading)',
      fontWeight: 500,
      fontFamily: mono ? 'var(--font-mono)' : 'var(--font-primary)'
    }
  }, value));
}
function FindingDetail({
  id,
  onBack
}) {
  const f = window.FINDINGS.find(x => x.id === id) || window.FINDINGS[0];
  const steps = ['Identify the affected host and the running service version.', 'Apply the vendor patch or configuration change described below.', 'Re-run a targeted scan to confirm the finding is resolved.'];
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("button", {
    onClick: onBack,
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '8px',
      background: 'none',
      border: 'none',
      cursor: 'pointer',
      color: 'var(--text-link)',
      fontSize: '13px',
      fontWeight: 600,
      fontFamily: 'var(--font-primary)',
      padding: 0,
      marginBottom: '16px'
    }
  }, /*#__PURE__*/React.createElement("i", {
    className: "fas fa-arrow-left"
  }), " Back to findings"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '1.7fr 1fr',
      gap: '18px',
      alignItems: 'start'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
      marginBottom: '12px',
      flexWrap: 'wrap'
    }
  }, /*#__PURE__*/React.createElement(SevD, {
    level: f.level
  }), f.cve ? /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-mono)',
      fontSize: '12px',
      color: 'var(--text-muted)'
    }
  }, f.cve) : null), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: '22px',
      fontWeight: 700,
      color: 'var(--text-heading)',
      margin: '0 0 12px',
      lineHeight: 1.25,
      fontFamily: 'var(--font-primary)'
    }
  }, f.title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontSize: '15px',
      color: 'var(--text-body)',
      lineHeight: 1.65,
      margin: '0 0 22px'
    }
  }, f.description), /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'var(--vw-info-bg)',
      border: '1px solid var(--vw-info-border)',
      borderRadius: 'var(--radius-lg)',
      padding: '16px 18px',
      marginBottom: '20px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      marginBottom: '8px'
    }
  }, /*#__PURE__*/React.createElement("i", {
    className: "fas fa-wand-magic-sparkles",
    style: {
      color: 'var(--vw-primary)'
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      fontWeight: 700,
      color: 'var(--vw-primary)',
      letterSpacing: '0.01em'
    }
  }, "AI recommendation")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontSize: '14px',
      color: 'var(--text-body)',
      lineHeight: 1.6,
      margin: 0
    }
  }, "This finding is exploitable from the public internet and should be fixed first. The change is low-risk and reversible; most teams resolve it within an hour.")), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontSize: '15px',
      fontWeight: 600,
      color: 'var(--text-heading)',
      margin: '0 0 12px',
      fontFamily: 'var(--font-primary)'
    }
  }, "How to fix"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
      marginBottom: '22px'
    }
  }, steps.map((s, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: 'flex',
      gap: '12px',
      alignItems: 'flex-start'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      flexShrink: 0,
      width: '22px',
      height: '22px',
      borderRadius: '50%',
      background: 'var(--vw-primary)',
      color: '#fff',
      fontSize: '12px',
      fontWeight: 700,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center'
    }
  }, i + 1), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '14px',
      color: 'var(--text-body)',
      lineHeight: 1.5,
      paddingTop: '2px'
    }
  }, s)))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '10px'
    }
  }, /*#__PURE__*/React.createElement(BtnD, {
    variant: "primary",
    icon: "fas fa-check"
  }, "Mark resolved"), /*#__PURE__*/React.createElement(BtnD, {
    variant: "secondary"
  }, "Mute finding"))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      boxShadow: 'var(--shadow-card)',
      padding: '18px 20px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '11px',
      fontWeight: 600,
      letterSpacing: 'var(--tracking-wider)',
      color: 'var(--text-faint)',
      marginBottom: '6px'
    }
  }, "DETAILS"), /*#__PURE__*/React.createElement(MetaRow, {
    label: "Affected host",
    value: f.host,
    mono: true
  }), f.port ? /*#__PURE__*/React.createElement(MetaRow, {
    label: "Port",
    value: `tcp/${f.port}`,
    mono: true
  }) : null, /*#__PURE__*/React.createElement(MetaRow, {
    label: "Severity",
    value: f.level.charAt(0).toUpperCase() + f.level.slice(1)
  }), /*#__PURE__*/React.createElement(MetaRow, {
    label: "Detected by",
    value: "Nuclei"
  }), /*#__PURE__*/React.createElement(MetaRow, {
    label: "First seen",
    value: "4 hours ago"
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      gap: '12px',
      padding: '9px 0'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      color: 'var(--text-muted)'
    }
  }, "Status"), /*#__PURE__*/React.createElement(PillD, {
    tone: "open"
  })))));
}
Object.assign(window, {
  FindingDetail
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/FindingDetail.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/Findings.jsx
try { (() => {
// Findings list screen — filter chips + scannable rows.
const {
  SeverityBadge: SevF,
  Button: BtnF
} = window.VulWallDesignSystem_2af3fe;
const {
  useState: useStateF
} = React;
function FilterChip({
  label,
  count,
  active,
  onClick
}) {
  return /*#__PURE__*/React.createElement("button", {
    onClick: onClick,
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '7px',
      cursor: 'pointer',
      padding: '7px 14px',
      borderRadius: 'var(--radius-pill)',
      fontFamily: 'var(--font-primary)',
      fontSize: '13px',
      fontWeight: 600,
      border: `1px solid ${active ? 'var(--vw-primary)' : 'var(--border-default)'}`,
      background: active ? 'var(--vw-primary)' : 'var(--surface-card)',
      color: active ? '#fff' : 'var(--text-body)',
      transition: 'all 0.2s var(--ease-standard)'
    }
  }, label, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '12px',
      opacity: 0.8
    }
  }, count));
}
function FindingRow({
  f,
  onOpen
}) {
  const [hover, setHover] = useStateF(false);
  return /*#__PURE__*/React.createElement("button", {
    onClick: () => onOpen(f.id),
    onMouseEnter: () => setHover(true),
    onMouseLeave: () => setHover(false),
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '14px',
      width: '100%',
      textAlign: 'left',
      cursor: 'pointer',
      border: 'none',
      borderBottom: '1px solid var(--border-default)',
      background: hover ? 'var(--vw-gray-50)' : 'var(--surface-card)',
      padding: '14px 18px',
      fontFamily: 'var(--font-primary)',
      transition: 'background 0.15s var(--ease-standard)'
    }
  }, /*#__PURE__*/React.createElement(SevF, {
    level: f.level
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '14px',
      color: 'var(--text-heading)',
      fontWeight: 500,
      flex: 1,
      minWidth: 0,
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap'
    }
  }, f.title), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-mono)',
      fontSize: '12px',
      color: 'var(--text-faint)',
      flexShrink: 0
    }
  }, f.cve || f.host), /*#__PURE__*/React.createElement("i", {
    className: "fas fa-chevron-right",
    style: {
      color: 'var(--text-faint)',
      fontSize: '12px'
    }
  }));
}
function Findings({
  onOpenFinding
}) {
  const all = window.FINDINGS;
  const [filter, setFilter] = useStateF('all');
  const counts = {
    all: all.length
  };
  ['critical', 'high', 'medium', 'low', 'info'].forEach(l => {
    counts[l] = all.filter(f => f.level === l).length;
  });
  const shown = filter === 'all' ? all : all.filter(f => f.level === filter);
  return /*#__PURE__*/React.createElement("div", null, window.PageHeader ? /*#__PURE__*/React.createElement(window.PageHeader, {
    title: "Findings",
    subtitle: `${all.length} open findings across 7 assets`,
    action: /*#__PURE__*/React.createElement(BtnF, {
      variant: "secondary",
      icon: "fas fa-arrow-up-right-from-square"
    }, "Export")
  }) : null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexWrap: 'wrap',
      gap: '8px',
      marginBottom: '16px'
    }
  }, /*#__PURE__*/React.createElement(FilterChip, {
    label: "All",
    count: counts.all,
    active: filter === 'all',
    onClick: () => setFilter('all')
  }), /*#__PURE__*/React.createElement(FilterChip, {
    label: "Critical",
    count: counts.critical,
    active: filter === 'critical',
    onClick: () => setFilter('critical')
  }), /*#__PURE__*/React.createElement(FilterChip, {
    label: "High",
    count: counts.high,
    active: filter === 'high',
    onClick: () => setFilter('high')
  }), /*#__PURE__*/React.createElement(FilterChip, {
    label: "Medium",
    count: counts.medium,
    active: filter === 'medium',
    onClick: () => setFilter('medium')
  }), /*#__PURE__*/React.createElement(FilterChip, {
    label: "Low",
    count: counts.low,
    active: filter === 'low',
    onClick: () => setFilter('low')
  }), /*#__PURE__*/React.createElement(FilterChip, {
    label: "Info",
    count: counts.info,
    active: filter === 'info',
    onClick: () => setFilter('info')
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      boxShadow: 'var(--shadow-card)',
      overflow: 'hidden'
    }
  }, shown.map((f, i) => /*#__PURE__*/React.createElement(FindingRow, {
    key: f.id,
    f: f,
    onOpen: onOpenFinding
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 0
    }
  })));
}
Object.assign(window, {
  Findings
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/Findings.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/Overview.jsx
try { (() => {
// Overview screen — header, score + stat row, top findings.
const {
  ScoreRing: ScoreRingO,
  StatCard: StatCardO,
  FindingCard: FindingCardO,
  Button: ButtonO,
  ScanHeatmap: ScanHeatmapO
} = window.VulWallDesignSystem_2af3fe;
function PageHeader({
  title,
  subtitle,
  action
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'flex-start',
      justifyContent: 'space-between',
      gap: '16px',
      marginBottom: '22px',
      flexWrap: 'wrap'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: '24px',
      fontWeight: 700,
      color: 'var(--text-heading)',
      margin: 0,
      fontFamily: 'var(--font-primary)'
    }
  }, title), subtitle ? /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '13px',
      color: 'var(--text-muted)',
      marginTop: '4px'
    }
  }, subtitle) : null), action);
}
function Overview({
  onOpenFinding,
  onRescan
}) {
  const top = window.FINDINGS.slice(0, 4);
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(PageHeader, {
    title: "acme.com",
    subtitle: "Last scan 4 hours ago \xB7 12 scanners \xB7 7 assets",
    action: /*#__PURE__*/React.createElement(ButtonO, {
      variant: "primary",
      icon: "fas fa-bolt",
      onClick: onRescan
    }, "Rescan now")
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '1.3fr 1fr 1fr 1fr',
      gap: '14px',
      marginBottom: '22px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      boxShadow: 'var(--shadow-card)',
      padding: '18px 20px',
      display: 'flex',
      alignItems: 'center',
      gap: '16px'
    }
  }, /*#__PURE__*/React.createElement(ScoreRingO, {
    score: 72,
    label: "/ 100",
    size: 92
  }), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '13px',
      color: 'var(--text-muted)'
    }
  }, "Security score"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '15px',
      color: 'var(--severity-medium)',
      fontWeight: 600,
      marginTop: '3px'
    }
  }, "Needs attention"))), /*#__PURE__*/React.createElement(StatCardO, {
    value: "2",
    label: "Critical",
    tone: "critical",
    icon: "fas fa-circle-exclamation"
  }), /*#__PURE__*/React.createElement(StatCardO, {
    value: "5",
    label: "High",
    tone: "high",
    icon: "fas fa-triangle-exclamation"
  }), /*#__PURE__*/React.createElement(StatCardO, {
    value: "23",
    label: "Passed",
    tone: "passed",
    icon: "fas fa-circle-check"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: '12px'
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontSize: '17px',
      fontWeight: 600,
      color: 'var(--text-heading)',
      margin: 0,
      fontFamily: 'var(--font-primary)'
    }
  }, "Scan activity"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      color: 'var(--text-faint)'
    }
  }, "Last 6 months \xB7 worst severity per day")), /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'var(--surface-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      boxShadow: 'var(--shadow-card)',
      padding: '18px 20px',
      marginBottom: '24px'
    }
  }, /*#__PURE__*/React.createElement(ScanHeatmapO, {
    weeks: 26
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: '12px'
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontSize: '17px',
      fontWeight: 600,
      color: 'var(--text-heading)',
      margin: 0,
      fontFamily: 'var(--font-primary)'
    }
  }, "Top findings"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      color: 'var(--text-faint)'
    }
  }, "Ranked by real-world risk")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '12px'
    }
  }, top.map(f => /*#__PURE__*/React.createElement(FindingCardO, {
    key: f.id,
    level: f.level,
    title: f.title,
    description: f.description,
    cve: f.cve,
    host: f.host,
    port: f.port,
    onFix: () => onOpenFinding(f.id),
    onMute: () => {}
  }))));
}
Object.assign(window, {
  Overview,
  PageHeader
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/Overview.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/Sidebar.jsx
try { (() => {
// NightWatch dashboard — navy→cobalt gradient sidebar.
const {
  useState
} = React;
function NavItem({
  icon,
  label,
  active,
  onClick
}) {
  const [hover, setHover] = useState(false);
  return /*#__PURE__*/React.createElement("button", {
    onClick: onClick,
    onMouseEnter: () => setHover(true),
    onMouseLeave: () => setHover(false),
    style: {
      position: 'relative',
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      width: '100%',
      textAlign: 'left',
      border: 'none',
      cursor: 'pointer',
      padding: '10px 14px',
      borderRadius: '12px',
      fontFamily: 'var(--font-primary)',
      fontSize: '14px',
      fontWeight: active ? 600 : 500,
      color: active || hover ? '#FBFBFD' : 'rgba(251,251,253,0.72)',
      background: active ? 'rgba(244,125,23,0.22)' : hover ? 'rgba(244,125,23,0.12)' : 'transparent',
      transform: hover && !active ? 'translateX(4px)' : 'none',
      transition: 'all 0.2s var(--ease-standard)'
    }
  }, active ? /*#__PURE__*/React.createElement("span", {
    style: {
      position: 'absolute',
      left: '-14px',
      top: '50%',
      transform: 'translateY(-50%)',
      width: '4px',
      height: '60%',
      background: 'var(--accent-orange)',
      borderRadius: '0 4px 4px 0'
    }
  }) : null, /*#__PURE__*/React.createElement("i", {
    className: icon,
    style: {
      width: '18px',
      textAlign: 'center',
      fontSize: '15px'
    },
    "aria-hidden": "true"
  }), label);
}
function Sidebar({
  active,
  onNavigate,
  theme,
  onToggleTheme
}) {
  const nav = [{
    id: 'overview',
    icon: 'fas fa-gauge-high',
    label: 'Overview'
  }, {
    id: 'findings',
    icon: 'fas fa-triangle-exclamation',
    label: 'Findings'
  }, {
    id: 'assets',
    icon: 'fas fa-server',
    label: 'Assets'
  }, {
    id: 'reports',
    icon: 'fas fa-file-shield',
    label: 'Reports'
  }, {
    id: 'scanners',
    icon: 'fas fa-radar',
    label: 'Scanners'
  }];
  return /*#__PURE__*/React.createElement("aside", {
    style: {
      width: '260px',
      flexShrink: 0,
      background: 'var(--brand-gradient)',
      padding: '22px 18px',
      display: 'flex',
      flexDirection: 'column',
      gap: '6px',
      minHeight: '100%'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '11px',
      padding: '0 8px 18px',
      borderBottom: '1px solid rgba(255,255,255,0.12)',
      marginBottom: '14px'
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/logo-mark-white.png",
    alt: "",
    style: {
      width: '26px',
      height: 'auto'
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-display)',
      fontSize: '17px',
      fontWeight: 600,
      color: '#fff',
      letterSpacing: '0.04em'
    }
  }, "VULWALL")), nav.map(n => /*#__PURE__*/React.createElement(NavItem, {
    key: n.id,
    icon: n.icon,
    label: n.label,
    active: active === n.id,
    onClick: () => onNavigate(n.id)
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 'auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '12px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '14px',
      background: 'rgba(255,255,255,0.06)',
      border: '1px solid rgba(255,255,255,0.12)',
      borderRadius: '12px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '12px',
      color: 'rgba(251,251,253,0.65)',
      marginBottom: '6px'
    }
  }, "Next scan"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: 'var(--font-mono)',
      fontSize: '14px',
      color: '#E4E9F0'
    }
  }, "in 3h 12m")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '14px',
      background: 'linear-gradient(135deg, rgba(244,125,23,0.16), rgba(244,125,23,0.05))',
      border: '1px solid rgba(244,125,23,0.3)',
      borderRadius: '12px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      marginBottom: '8px'
    }
  }, /*#__PURE__*/React.createElement("i", {
    className: "fas fa-bolt",
    style: {
      color: 'var(--accent-orange)'
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '13px',
      fontWeight: 600,
      color: '#fff'
    }
  }, "Free plan")), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '12px',
      color: 'rgba(251,251,253,0.7)',
      lineHeight: 1.5,
      marginBottom: '10px'
    }
  }, "Scan more assets & get AI fixes."), /*#__PURE__*/React.createElement("button", {
    style: {
      width: '100%',
      background: 'var(--accent-orange)',
      color: 'var(--accent-orange-on)',
      border: 'none',
      borderRadius: '8px',
      padding: '8px',
      fontSize: '13px',
      fontWeight: 700,
      cursor: 'pointer',
      fontFamily: 'var(--font-primary)'
    }
  }, "Upgrade")), /*#__PURE__*/React.createElement("button", {
    onClick: onToggleTheme,
    style: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '8px',
      background: 'transparent',
      border: '1px solid rgba(251,251,253,0.2)',
      color: 'rgba(251,251,253,0.85)',
      borderRadius: '8px',
      padding: '9px',
      fontSize: '13px',
      cursor: 'pointer',
      fontFamily: 'var(--font-primary)'
    }
  }, /*#__PURE__*/React.createElement("i", {
    className: theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon'
  }), theme === 'dark' ? 'Light mode' : 'Dark mode')));
}
Object.assign(window, {
  Sidebar
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/Sidebar.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/data.jsx
try { (() => {
// Shared fake scan data for the NightWatch dashboard kit.
const FINDINGS = [{
  id: 1,
  level: 'critical',
  title: 'Exposed admin panel reachable on :8080',
  cve: null,
  host: 'api.acme.com',
  port: '8080',
  description: 'An administrative login panel is publicly reachable with no IP allow-listing. Restrict it to your VPN or office IPs, or put it behind SSO.'
}, {
  id: 2,
  level: 'critical',
  title: 'Database port open to the public internet',
  cve: null,
  host: 'db.acme.com',
  port: '5432',
  description: 'PostgreSQL is listening on a public interface. Close the port at the firewall and connect only over a private network.'
}, {
  id: 3,
  level: 'high',
  title: 'Outdated OpenSSL exposes the API to a known RCE',
  cve: 'CVE-2024-3094',
  host: 'api.acme.com',
  port: '443',
  description: 'The host advertises OpenSSL 3.0.6, which is vulnerable to a remote code execution flaw. Upgrade to 3.0.7 or later — your provider\u2019s package mirror already has it.'
}, {
  id: 4,
  level: 'high',
  title: 'SPF record allows any sender to spoof your domain',
  cve: null,
  host: 'acme.com',
  port: null,
  description: 'Your SPF record ends in +all, which lets anyone send mail as your domain. Change it to -all and publish a DMARC policy of quarantine or reject.'
}, {
  id: 5,
  level: 'medium',
  title: 'Missing Content-Security-Policy header',
  cve: null,
  host: 'www.acme.com',
  port: '443',
  description: 'No CSP header is set, leaving the site more exposed to cross-site scripting. Add a restrictive policy starting from default-src \u2018self\u2019.'
}, {
  id: 6,
  level: 'medium',
  title: 'TLS 1.0 still accepted on the marketing site',
  cve: null,
  host: 'www.acme.com',
  port: '443',
  description: 'An outdated encryption standard is still allowed. Disable TLS 1.0/1.1 and require TLS 1.2 or higher.'
}, {
  id: 7,
  level: 'low',
  title: 'Server version disclosed in HTTP headers',
  cve: null,
  host: 'www.acme.com',
  port: '443',
  description: 'The Server header reveals the exact nginx version, helping attackers target known bugs. Suppress or genericize the header.'
}, {
  id: 8,
  level: 'info',
  title: 'New subdomain discovered: staging.acme.com',
  cve: null,
  host: 'staging.acme.com',
  port: null,
  description: 'NightWatch found a subdomain not previously in your asset list. Confirm it is yours and whether it should be publicly reachable.'
}];
const ASSETS = [{
  host: 'acme.com',
  type: 'Apex domain',
  status: 'secure',
  findings: 1,
  tech: 'Cloudflare'
}, {
  host: 'www.acme.com',
  type: 'Subdomain',
  status: 'open',
  findings: 3,
  tech: 'nginx · React'
}, {
  host: 'api.acme.com',
  type: 'Subdomain',
  status: 'open',
  findings: 2,
  tech: '.NET · Kestrel'
}, {
  host: 'db.acme.com',
  type: 'Subdomain',
  status: 'open',
  findings: 1,
  tech: 'PostgreSQL'
}, {
  host: 'staging.acme.com',
  type: 'Subdomain',
  status: 'scanning',
  findings: 0,
  tech: 'Unknown'
}, {
  host: 'mail.acme.com',
  type: 'Subdomain',
  status: 'secure',
  findings: 0,
  tech: 'Google Workspace'
}];
Object.assign(window, {
  FINDINGS,
  ASSETS
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/data.jsx", error: String((e && e.message) || e) }); }

__ds_ns.Button = __ds_scope.Button;

__ds_ns.Card = __ds_scope.Card;

__ds_ns.Input = __ds_scope.Input;

__ds_ns.SeverityBadge = __ds_scope.SeverityBadge;

__ds_ns.StatusPill = __ds_scope.StatusPill;

__ds_ns.FindingCard = __ds_scope.FindingCard;

__ds_ns.ScanHeatmap = __ds_scope.ScanHeatmap;

__ds_ns.ScoreRing = __ds_scope.ScoreRing;

__ds_ns.StatCard = __ds_scope.StatCard;

})();
