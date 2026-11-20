// Assets screen — discovered hosts with status + tech.
const { StatusPill, Button: BtnA } = window.VulWallDesignSystem_2af3fe;

function Assets() {
  const assets = window.ASSETS;
  return (
    <div>
      {window.PageHeader ? <window.PageHeader title="Assets" subtitle={`${assets.length} discovered hosts · 1 apex domain`} action={<BtnA variant="primary" icon="fas fa-plus">Add asset</BtnA>} /> : null}
      <div style={{ background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-card)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 1fr 1.4fr 0.8fr', gap: '12px', padding: '12px 18px', borderBottom: '1px solid var(--border-default)', background: 'var(--surface-sunken)', fontSize: '11px', fontWeight: 600, letterSpacing: 'var(--tracking-wider)', color: 'var(--text-faint)', textTransform: 'uppercase' }}>
          <span>Host</span><span>Type</span><span>Status</span><span>Technology</span><span style={{ textAlign: 'right' }}>Findings</span>
        </div>
        {assets.map((a, i) => (
          <div key={a.host} style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 1fr 1.4fr 0.8fr', gap: '12px', alignItems: 'center', padding: '14px 18px', borderBottom: i < assets.length - 1 ? '1px solid var(--border-default)' : 'none', fontFamily: 'var(--font-primary)' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-heading)', fontWeight: 500 }}>{a.host}</span>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{a.type}</span>
            <span><StatusPill tone={a.status} pulse={a.status === 'scanning'} /></span>
            <span style={{ fontSize: '13px', color: 'var(--text-body)' }}>{a.tech}</span>
            <span style={{ textAlign: 'right', fontSize: '14px', fontWeight: 700, color: a.findings > 0 ? 'var(--severity-high)' : 'var(--vw-success)' }}>{a.findings}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

Object.assign(window, { Assets });
