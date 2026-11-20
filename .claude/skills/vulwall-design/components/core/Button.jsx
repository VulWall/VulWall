import React from 'react';

const CSS = `
.vw-btn {
  font-family: var(--font-primary);
  font-weight: 600;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  line-height: 1;
  transition: all var(--dur-normal) var(--ease-standard);
  white-space: nowrap;
  text-decoration: none;
}
.vw-btn:focus-visible { outline: none; box-shadow: var(--shadow-focus); }
.vw-btn-md { padding: 10px 18px; font-size: 14px; }
.vw-btn-sm { padding: 7px 13px; font-size: 13px; border-radius: var(--radius-sm); }
.vw-btn-lg { padding: 13px 26px; font-size: 16px; }

.vw-btn-primary { background: var(--vw-primary); border-color: var(--vw-primary); color: var(--brand-off-white); }
.vw-btn-primary:hover { background: var(--vw-primary-hover); border-color: var(--vw-primary-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,86,161,.25); }
.vw-btn-primary:active { background: var(--vw-primary-active); transform: translateY(0); }

.vw-btn-accent { background: var(--accent-orange); border-color: var(--accent-orange); color: var(--accent-orange-on); }
.vw-btn-accent:hover { background: var(--accent-orange-hover); border-color: var(--accent-orange-hover); transform: translateY(-1px); }
.vw-btn-accent:active { transform: translateY(0); }

.vw-btn-secondary { background: var(--surface-card); border-color: var(--border-strong); color: var(--text-heading); }
.vw-btn-secondary:hover { background: var(--vw-gray-50); border-color: var(--vw-gray-400); }

.vw-btn-ghost { background: transparent; border-color: transparent; color: var(--vw-primary); }
.vw-btn-ghost:hover { background: var(--vw-gray-100); }

.vw-btn-danger { background: var(--vw-danger); border-color: var(--vw-danger); color: #fff; }
.vw-btn-danger:hover { background: var(--vw-danger-hover); border-color: var(--vw-danger-hover); transform: translateY(-1px); }

.vw-btn:disabled { background: var(--vw-gray-200); border-color: var(--vw-gray-200); color: var(--vw-gray-400); cursor: not-allowed; transform: none; box-shadow: none; }
`;

function useInjectCSS(id, css) {
  React.useEffect(() => {
    if (document.getElementById(id)) return;
    const el = document.createElement('style');
    el.id = id; el.textContent = css;
    document.head.appendChild(el);
  }, [id, css]);
}

/**
 * VulWall primary button. Cobalt = primary action; orange accent reserved
 * for upgrade/highlight; neutral/ghost for secondary; danger for destructive.
 */
export function Button({
  variant = 'primary',
  size = 'md',
  icon,
  children,
  disabled = false,
  onClick,
  type = 'button',
  style,
  ...rest
}) {
  useInjectCSS('vw-btn-css', CSS);
  return (
    <button
      type={type}
      className={`vw-btn vw-btn-${size} vw-btn-${variant}`}
      disabled={disabled}
      onClick={onClick}
      style={style}
      {...rest}
    >
      {icon ? <i className={icon} aria-hidden="true"></i> : null}
      {children}
    </button>
  );
}
