import * as React from 'react';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Inner padding in px, or any CSS padding string. @default 20 */
  padding?: number | string;
  /** Lift + deepen shadow on hover (use for clickable cards). @default false */
  interactive?: boolean;
  children?: React.ReactNode;
}

/** Base surface card. */
export function Card(props: CardProps): JSX.Element;
