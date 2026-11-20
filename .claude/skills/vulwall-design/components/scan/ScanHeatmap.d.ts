import * as React from 'react';

export interface ScanHeatmapDay {
  date: Date;
  /** Number of scans that day. 0 = ran but nothing; omit/undefined with `out` for empty. */
  scans?: number;
  /** Worst severity found that day. */
  sev?: 'none' | 'low' | 'medium' | 'high' | 'critical' | null;
  /** Per-severity counts for the tooltip breakdown. */
  counts?: Record<string, number>;
  /** Future day with a scan scheduled (striped cell). */
  scheduled?: boolean;
  /** Out-of-range future day (transparent, non-interactive). */
  out?: boolean;
}

export interface ScanHeatmapProps {
  /** Number of week columns to show when `data` is omitted. @default 26 */
  weeks?: number;
  /** Explicit grid: an array of week columns, each a 7-cell (Sun→Sat) array. Omit to use built-in sample data. */
  data?: ScanHeatmapDay[][];
  /** Show the severity legend below the grid. @default true */
  legend?: boolean;
  style?: React.CSSProperties;
}

/**
 * Scan-activity calendar heatmap (GitHub-contributions style); each cell is a
 * day colored by the worst severity found, with a hover tooltip breakdown.
 * @startingPoint section="Scan" subtitle="Scan-activity calendar heatmap" viewport="760x220"
 */
export function ScanHeatmap(props: ScanHeatmapProps): JSX.Element;
