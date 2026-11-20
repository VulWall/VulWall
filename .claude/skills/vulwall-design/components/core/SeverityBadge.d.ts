import * as React from 'react';

export interface SeverityBadgeProps {
  /** Severity band. @default 'info' */
  level?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Override the displayed label (defaults to the capitalized level name). */
  label?: string;
  style?: React.CSSProperties;
}

/** Severity pill with a colored status dot, drawn from the dedicated severity ramp. */
export function SeverityBadge(props: SeverityBadgeProps): JSX.Element;
