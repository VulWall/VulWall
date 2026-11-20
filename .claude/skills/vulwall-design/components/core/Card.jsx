import React from 'react';

/** Base surface card — white, soft navy shadow + hairline border, 12px radius. */
export function Card({ children, padding = 20, interactive = false, style, ...rest }) {
  const [hover, setHover] = React.useState(false);
  return (
    <div
      onMouseEnter={() => interactive && setHover(true)}
      onMouseLeave={() => interactive && setHover(false)}
      style={{
        background: 'var(--surface-card)',
        border: '1px solid var(--border-default)',
        borderRadius: 'var(--radius-lg)',
        boxShadow: hover ? 'var(--shadow-lg)' : 'var(--shadow-card)',
        padding: typeof padding === 'number' ? `${padding}px` : padding,
        transition: 'box-shadow var(--dur-normal) var(--ease-standard), transform var(--dur-normal) var(--ease-standard)',
        transform: hover ? 'translateY(-2px)' : 'none',
        cursor: interactive ? 'pointer' : 'default',
        ...style,
      }}
      {...rest}
    >
      {children}
    </div>
  );
}
