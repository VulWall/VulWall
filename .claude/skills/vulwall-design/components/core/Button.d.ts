import * as React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Visual style. `primary` = cobalt CTA, `accent` = orange (dark text), `secondary` = neutral outline, `ghost` = text-only, `danger` = destructive. */
  variant?: 'primary' | 'accent' | 'secondary' | 'ghost' | 'danger';
  /** Size. @default 'md' */
  size?: 'sm' | 'md' | 'lg';
  /** Optional Font Awesome icon class, e.g. "fas fa-bolt". */
  icon?: string;
  children?: React.ReactNode;
}

export function Button(props: ButtonProps): JSX.Element;
