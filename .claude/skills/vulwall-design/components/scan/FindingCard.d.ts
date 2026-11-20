import * as React from 'react';

export interface FindingCardProps {
  /** Severity band — sets the left accent and pill. @default 'high' */
  level?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Plain-English finding title. */
  title?: string;
  /** Plain-English explanation + fix guidance. */
  description?: string;
  /** CVE id, shown in mono (e.g. "CVE-2024-3094"). */
  cve?: string;
  /** Affected host, shown in mono. */
  host?: string;
  /** Affected port, appended to host. */
  port?: string | number;
  /** Click handler for the primary "How to fix" action (omit to hide). */
  onFix?: () => void;
  /** Click handler for the secondary "Mute" action (omit to hide). */
  onMute?: () => void;
  style?: React.CSSProperties;
}

export function FindingCard(props: FindingCardProps): JSX.Element;
