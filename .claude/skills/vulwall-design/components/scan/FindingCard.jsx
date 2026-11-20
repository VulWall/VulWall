import React from 'react';
import { SeverityBadge } from '../core/SeverityBadge.jsx';
import { Button } from '../core/Button.jsx';

const SOLID = {
  critical: 'var(--severity-critical-solid)',
  high: 'var(--severity-high-solid)',
  medium: 'var(--severity-medium-solid)',
  low: 'var(--severity-low-solid)',
  info: 'var(--severity-info-solid)',
};

/**
 * Vulnerability finding card. Severity-colored left accent + pill, mono meta
 * (CVE / host), plain-English title & body, and primary/secondary actions.
 */
export function FindingCard({
  level = 'high', title, description, cve, host, port,
  onFix, onMute, style,
}) {
  return (
    <div style={{
      background: 'var(--surface-card)', border: '1px solid var(--border-default)',
      borderLeft: `4px solid ${SOLID[level] || SOLID.info}`, borderRadius: 'var(--radius-lg)',
      boxShadow: 'var(--shadow-card)', padding: '18px 20px', fontFamily: 'var(--font-primary)', ...style,
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', marginBottom: '8px' }}>
            <SeverityBadge level={level} />
            {cve ? <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{cve}</span> : null}
            {(cve && (host || port)) ? <span style={{ color: 'var(--text-faint)' }}>·</span> : null}
            {host ? <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{host}{port ? `:${port}` : ''}</span> : null}
          </div>
          <h4 style={{ fontSize: '17px', fontWeight: 600, color: 'var(--text-heading)', margin: '0 0 6px' }}>{title}</h4>
          {description ? <p style={{ fontSize: '14px', color: 'var(--text-body)', lineHeight: 1.6, margin: 0 }}>{description}</p> : null}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', flexShrink: 0 }}>
          {onFix ? <Button variant="primary" size="sm" onClick={onFix}>How to fix</Button> : null}
          {onMute ? <Button variant="secondary" size="sm" onClick={onMute}>Mute</Button> : null}
        </div>
      </div>
    </div>
  );
}
