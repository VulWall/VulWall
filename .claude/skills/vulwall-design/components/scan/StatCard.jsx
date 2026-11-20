import React from 'react';

const TONES = {
  critical: 'var(--severity-critical-solid)',
  high: 'var(--severity-high-solid)',
  medium: 'var(--severity-medium-solid)',
  low: 'var(--severity-low-solid)',
  passed: 'var(--vw-success)',
  neutral: 'var(--text-heading)',
};

/** Single metric card — big number + label, color-keyed to a severity/status tone. */
export function StatCard({ value, label, tone = 'neutral', icon, style }) {
  return (
    <div style={{
      background: 'var(--surface-card)', border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-card)', padding: '16px 18px',
      fontFamily: 'var(--font-primary)', ...style,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        {icon ? <i className={icon} style={{ color: TONES[tone], fontSize: '14px' }} aria-hidden="true"></i> : null}
        <span style={{ fontSize: '28px', fontWeight: 700, color: TONES[tone], lineHeight: 1 }}>{value}</span>
      </div>
      <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '6px' }}>{label}</div>
    </div>
  );
}
