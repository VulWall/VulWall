import * as React from 'react';

export interface StatusPillProps {
  /** Status tone. @default 'neutral' */
  tone?: 'secure' | 'scanning' | 'resolved' | 'open' | 'neutral';
  /** Override the displayed label. */
  label?: string;
  /** Pulse the status dot (use with `scanning`). @default false */
  pulse?: boolean;
  style?: React.CSSProperties;
}

/** Asset/finding status pill with a colored dot. */
export function StatusPill(props: StatusPillProps): JSX.Element;
