import React from 'react';

const CSS = `
.vw-input-wrap { display:flex; flex-direction:column; gap:6px; font-family:var(--font-primary); }
.vw-input-label { font-size:13px; font-weight:500; color:var(--text-heading); }
.vw-input-field { display:flex; align-items:center; gap:8px; background:var(--surface-card);
  border:1px solid var(--border-strong); border-radius:var(--radius-md); padding:9px 13px;
  transition:border-color var(--dur-normal) var(--ease-standard), box-shadow var(--dur-normal) var(--ease-standard); }
.vw-input-field:focus-within { border-color:var(--border-focus); box-shadow:var(--shadow-focus); }
.vw-input-field.is-invalid { border-color:var(--vw-danger); background:var(--vw-danger-bg); }
.vw-input-prefix { font-family:var(--font-mono); font-size:13px; color:var(--text-faint); }
.vw-input-el { flex:1; border:none; outline:none; background:transparent; font-family:var(--font-primary);
  font-size:15px; color:var(--text-body); min-width:0; }
.vw-input-el::placeholder { color:var(--text-faint); }
.vw-input-err { font-size:12px; color:var(--vw-danger); }
`;

function useInjectCSS(id, css) {
  React.useEffect(() => {
    if (document.getElementById(id)) return;
    const el = document.createElement('style');
    el.id = id; el.textContent = css;
    document.head.appendChild(el);
  }, [id, css]);
}

/** Text input with optional label, mono prefix (e.g. https://), and error state. */
export function Input({ label, prefix, error, invalid = false, value, placeholder, onChange, type = 'text', style, ...rest }) {
  useInjectCSS('vw-input-css', CSS);
  return (
    <label className="vw-input-wrap" style={style}>
      {label ? <span className="vw-input-label">{label}</span> : null}
      <span className={`vw-input-field${invalid || error ? ' is-invalid' : ''}`}>
        {prefix ? <span className="vw-input-prefix">{prefix}</span> : null}
        <input className="vw-input-el" type={type} value={value} placeholder={placeholder} onChange={onChange} {...rest} />
      </span>
      {error ? <span className="vw-input-err">{error}</span> : null}
    </label>
  );
}
