import React from 'react';

const LEVELS = {
  critical: { label: 'Critical', bg: 'var(--severity-critical-bg)', bd: 'var(--severity-critical-border)', fg: 'var(--severity-critical)', dot: 'var(--severity-critical-solid)' },
  high:     { label: 'High',     bg: 'var(--severity-high-bg)',     bd: 'var(--severity-high-border)',     fg: 'var(--severity-high)',     dot: 'var(--severity-high-solid)' },
  medium:   { label: 'Medium',   bg: 'var(--severity-medium-bg)',   bd: 'var(--severity-medium-border)',   fg: 'var(--severity-medium)',   dot: 'var(--severity-medium-solid)' },
  low:      { label: 'Low',      bg: 'var(--severity-low-bg)',      bd: 'var(--severity-low-border)',      fg: 'var(--severity-low)',      dot: 'var(--severity-low-solid)' },
  info:     { label: 'Info',     bg: 'var(--severity-info-bg)',     bd: 'var(--severity-info-border)',     fg: 'var(--severity-info)',     dot: 'var(--severity-info-solid)' },
};

/**
 * Severity pill — tint background, readable text, solid status dot.
 * Uses the dedicated severity ramp (never brand orange).
 */
export function SeverityBadge({ level = 'info', label, style }) {
  const s = LEVELS[level] || LEVELS.info;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '6px',
      fontFamily: 'var(--font-primary)', fontSize: '12px', fontWeight: 600, lineHeight: 1,
      padding: '4px 11px', borderRadius: 'var(--radius-pill)',
      background: s.bg, border: `1px solid ${s.bd}`, color: s.fg, ...style,
    }}>
      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: s.dot }}></span>
      {label || s.label}
    </span>
  );
}
