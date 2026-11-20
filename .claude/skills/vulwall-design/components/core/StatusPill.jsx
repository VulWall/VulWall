import React from 'react';

const TONES = {
  secure:   { label: 'Secure',   bg: 'var(--vw-success-bg)', bd: 'var(--vw-success-border)', fg: 'var(--vw-success)', dot: 'var(--vw-success)' },
  scanning: { label: 'Scanning', bg: 'var(--vw-info-bg)',    bd: 'var(--vw-info-border)',    fg: 'var(--vw-primary)', dot: 'var(--vw-primary)' },
  resolved: { label: 'Resolved', bg: 'var(--vw-gray-50)',    bd: 'var(--border-default)',    fg: 'var(--text-muted)', dot: 'var(--vw-gray-400)' },
  open:     { label: 'Open',     bg: 'var(--severity-high-bg)', bd: 'var(--severity-high-border)', fg: 'var(--vw-danger-hover)', dot: 'var(--vw-danger)' },
  neutral:  { label: 'Status',   bg: 'var(--vw-gray-50)',    bd: 'var(--border-default)',    fg: 'var(--text-body)',  dot: 'var(--vw-gray-400)' },
};

/** Status pill — secure / scanning / resolved / open. Pulsing dot when scanning. */
export function StatusPill({ tone = 'neutral', label, pulse = false, style }) {
  const t = TONES[tone] || TONES.neutral;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '6px',
      fontFamily: 'var(--font-primary)', fontSize: '12px', fontWeight: 600, lineHeight: 1,
      padding: '4px 11px', borderRadius: 'var(--radius-pill)',
      background: t.bg, border: `1px solid ${t.bd}`, color: t.fg, ...style,
    }}>
      <span style={{
        width: '6px', height: '6px', borderRadius: '50%', background: t.dot,
        animation: pulse ? 'vw-pulse 1.4s var(--ease-standard) infinite' : 'none',
      }}></span>
      {label || t.label}
      <style>{`@keyframes vw-pulse { 0%,100%{opacity:1} 50%{opacity:.35} }`}</style>
    </span>
  );
}
