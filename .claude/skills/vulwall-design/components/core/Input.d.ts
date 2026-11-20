import * as React from 'react';

export interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'prefix'> {
  /** Field label rendered above the input. */
  label?: string;
  /** Monospace prefix shown inside the field, e.g. "https://". */
  prefix?: string;
  /** Error message; presence also styles the field invalid. */
  error?: string;
  /** Force the invalid style without a message. @default false */
  invalid?: boolean;
}

/** Text input with label, mono prefix, focus ring, and error state. */
export function Input(props: InputProps): JSX.Element;
