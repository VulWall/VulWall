import React from 'react';

/** Security score ring (0–100). Color band follows the score, not brand orange. */
export function ScoreRing({ score = 72, max = 100, size = 120, label }) {
  const r = 50, c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(1, score / max));
  const offset = c * (1 - pct);
  // Score color: high=green, mid=amber, low=red — uses severity-solid hues.
  const color = pct >= 0.8 ? 'var(--vw-success)'
    : pct >= 0.5 ? 'var(--severity-medium-solid)'
    : 'var(--severity-high-solid)';
  return (
    <svg width={size} height={size} viewBox="0 0 120 120" style={{ display: 'block' }}>
      <circle cx="60" cy="60" r={r} fill="none" stroke="var(--vw-gray-100)" strokeWidth="14" />
      <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
        strokeDasharray={c} strokeDashoffset={offset} transform="rotate(-90 60 60)"
        style={{ transition: 'stroke-dashoffset 0.6s var(--ease-standard)' }} />
      <text x="60" y={label ? 55 : 67} textAnchor="middle" fontFamily="var(--font-primary)" fontSize="30" fontWeight="700" fill="var(--text-heading)">{score}</text>
      {label
        ? <text x="60" y="76" textAnchor="middle" fontFamily="var(--font-primary)" fontSize="11" fontWeight="500" fill="var(--text-faint)">{label}</text>
        : <text x="60" y="82" textAnchor="middle" fontFamily="var(--font-primary)" fontSize="11" fontWeight="500" fill="var(--text-faint)">/ {max}</text>}
    </svg>
  );
}
