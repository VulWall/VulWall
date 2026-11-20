import * as React from 'react';

export interface ScoreRingProps {
  /** Score value. @default 72 */
  score?: number;
  /** Maximum score. @default 100 */
  max?: number;
  /** Pixel diameter. @default 120 */
  size?: number;
  /** Caption under the number (e.g. "/ 100" by default, or a status word). */
  label?: string;
}

/** Circular security-score gauge; arc color follows the score (green/amber/red). */
export function ScoreRing(props: ScoreRingProps): JSX.Element;
