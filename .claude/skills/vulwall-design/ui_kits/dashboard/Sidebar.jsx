// NightWatch dashboard — navy→cobalt gradient sidebar.
const { useState } = React;

function NavItem({ icon, label, active, onClick }) {
  const [hover, setHover] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        position: 'relative', display: 'flex', alignItems: 'center', gap: '12px',
        width: '100%', textAlign: 'left', border: 'none', cursor: 'pointer',
        padding: '10px 14px', borderRadius: '12px', fontFamily: 'var(--font-primary)',
        fontSize: '14px', fontWeight: active ? 600 : 500,
        color: active || hover ? '#FBFBFD' : 'rgba(251,251,253,0.72)',
        background: active ? 'rgba(244,125,23,0.22)' : hover ? 'rgba(244,125,23,0.12)' : 'transparent',
        transform: hover && !active ? 'translateX(4px)' : 'none',
        transition: 'all 0.2s var(--ease-standard)',
      }}
    >
      {active ? <span style={{ position: 'absolute', left: '-14px', top: '50%', transform: 'translateY(-50%)', width: '4px', height: '60%', background: 'var(--accent-orange)', borderRadius: '0 4px 4px 0' }}></span> : null}
      <i className={icon} style={{ width: '18px', textAlign: 'center', fontSize: '15px' }} aria-hidden="true"></i>
      {label}
    </button>
  );
}

function Sidebar({ active, onNavigate, theme, onToggleTheme }) {
  const nav = [
    { id: 'overview', icon: 'fas fa-gauge-high', label: 'Overview' },
    { id: 'findings', icon: 'fas fa-triangle-exclamation', label: 'Findings' },
    { id: 'assets', icon: 'fas fa-server', label: 'Assets' },
    { id: 'reports', icon: 'fas fa-file-shield', label: 'Reports' },
    { id: 'scanners', icon: 'fas fa-radar', label: 'Scanners' },
  ];
  return (
    <aside style={{
      width: '260px', flexShrink: 0, background: 'var(--brand-gradient)',
      padding: '22px 18px', display: 'flex', flexDirection: 'column', gap: '6px',
      minHeight: '100%',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '11px', padding: '0 8px 18px', borderBottom: '1px solid rgba(255,255,255,0.12)', marginBottom: '14px' }}>
        <img src="../../assets/logo-mark-white.png" alt="" style={{ width: '26px', height: 'auto' }} />
        <span style={{ fontFamily: 'var(--font-display)', fontSize: '17px', fontWeight: 600, color: '#fff', letterSpacing: '0.04em' }}>VULWALL</span>
      </div>
      {nav.map(n => (
        <NavItem key={n.id} icon={n.icon} label={n.label} active={active === n.id} onClick={() => onNavigate(n.id)} />
      ))}

      <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div style={{ padding: '14px', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '12px' }}>
          <div style={{ fontSize: '12px', color: 'rgba(251,251,253,0.65)', marginBottom: '6px' }}>Next scan</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: '#E4E9F0' }}>in 3h 12m</div>
        </div>
        <div style={{ padding: '14px', background: 'linear-gradient(135deg, rgba(244,125,23,0.16), rgba(244,125,23,0.05))', border: '1px solid rgba(244,125,23,0.3)', borderRadius: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <i className="fas fa-bolt" style={{ color: 'var(--accent-orange)' }}></i>
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Free plan</span>
          </div>
          <div style={{ fontSize: '12px', color: 'rgba(251,251,253,0.7)', lineHeight: 1.5, marginBottom: '10px' }}>Scan more assets &amp; get AI fixes.</div>
          <button style={{ width: '100%', background: 'var(--accent-orange)', color: 'var(--accent-orange-on)', border: 'none', borderRadius: '8px', padding: '8px', fontSize: '13px', fontWeight: 700, cursor: 'pointer', fontFamily: 'var(--font-primary)' }}>Upgrade</button>
        </div>
        <button
          onClick={onToggleTheme}
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', background: 'transparent', border: '1px solid rgba(251,251,253,0.2)', color: 'rgba(251,251,253,0.85)', borderRadius: '8px', padding: '9px', fontSize: '13px', cursor: 'pointer', fontFamily: 'var(--font-primary)' }}
        >
          <i className={theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon'}></i>
          {theme === 'dark' ? 'Light mode' : 'Dark mode'}
        </button>
      </div>
    </aside>
  );
}

Object.assign(window, { Sidebar });
