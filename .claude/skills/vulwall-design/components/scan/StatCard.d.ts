import * as React from 'react';

export interface StatCardProps {
  /** The metric value (number or short string). */
  value?: React.ReactNode;
  /** Caption beneath the value. */
  label?: string;
  /** Color key for the value. @default 'neutral' */
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'passed' | 'neutral';
  /** Optional Font Awesome icon class. */
  icon?: string;
  style?: React.CSSProperties;
}

/** Compact KPI card used in the dashboard stat row. */
export function StatCard(props: StatCardProps): JSX.Element;
