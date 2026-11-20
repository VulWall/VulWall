// Finding detail panel — full finding + AI recommendation + fix steps.
const { SeverityBadge: SevD, Button: BtnD, StatusPill: PillD } = window.VulWallDesignSystem_2af3fe;

function MetaRow({ label, value, mono }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', padding: '9px 0', borderBottom: '1px solid var(--border-default)' }}>
      <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{label}</span>
      <span style={{ fontSize: '13px', color: 'var(--text-heading)', fontWeight: 500, fontFamily: mono ? 'var(--font-mono)' : 'var(--font-primary)' }}>{value}</span>
    </div>
  );
}

function FindingDetail({ id, onBack }) {
  const f = window.FINDINGS.find(x => x.id === id) || window.FINDINGS[0];
  const steps = [
    'Identify the affected host and the running service version.',
    'Apply the vendor patch or configuration change described below.',
    'Re-run a targeted scan to confirm the finding is resolved.',
  ];
  return (
    <div>
      <button onClick={onBack} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-link)', fontSize: '13px', fontWeight: 600, fontFamily: 'var(--font-primary)', padding: 0, marginBottom: '16px' }}>
        <i className="fas fa-arrow-left"></i> Back to findings
      </button>

      <div style={{ display: 'grid', gridTemplateColumns: '1.7fr 1fr', gap: '18px', alignItems: 'start' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px', flexWrap: 'wrap' }}>
            <SevD level={f.level} />
            {f.cve ? <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{f.cve}</span> : null}
          </div>
          <h1 style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-heading)', margin: '0 0 12px', lineHeight: 1.25, fontFamily: 'var(--font-primary)' }}>{f.title}</h1>
          <p style={{ fontSize: '15px', color: 'var(--text-body)', lineHeight: 1.65, margin: '0 0 22px' }}>{f.description}</p>

          <div style={{ background: 'var(--vw-info-bg)', border: '1px solid var(--vw-info-border)', borderRadius: 'var(--radius-lg)', padding: '16px 18px', marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <i className="fas fa-wand-magic-sparkles" style={{ color: 'var(--vw-primary)' }}></i>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--vw-primary)', letterSpacing: '0.01em' }}>AI recommendation</span>
            </div>
            <p style={{ fontSize: '14px', color: 'var(--text-body)', lineHeight: 1.6, margin: 0 }}>This finding is exploitable from the public internet and should be fixed first. The change is low-risk and reversible; most teams resolve it within an hour.</p>
          </div>

          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-heading)', margin: '0 0 12px', fontFamily: 'var(--font-primary)' }}>How to fix</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginBottom: '22px' }}>
            {steps.map((s, i) => (
              <div key={i} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                <span style={{ flexShrink: 0, width: '22px', height: '22px', borderRadius: '50%', background: 'var(--vw-primary)', color: '#fff', fontSize: '12px', fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{i + 1}</span>
                <span style={{ fontSize: '14px', color: 'var(--text-body)', lineHeight: 1.5, paddingTop: '2px' }}>{s}</span>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <BtnD variant="primary" icon="fas fa-check">Mark resolved</BtnD>
            <BtnD variant="secondary">Mute finding</BtnD>
          </div>
        </div>

        <div style={{ background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-card)', padding: '18px 20px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, letterSpacing: 'var(--tracking-wider)', color: 'var(--text-faint)', marginBottom: '6px' }}>DETAILS</div>
          <MetaRow label="Affected host" value={f.host} mono />
          {f.port ? <MetaRow label="Port" value={`tcp/${f.port}`} mono /> : null}
          <MetaRow label="Severity" value={f.level.charAt(0).toUpperCase() + f.level.slice(1)} />
          <MetaRow label="Detected by" value="Nuclei" />
          <MetaRow label="First seen" value="4 hours ago" />
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', padding: '9px 0' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Status</span>
            <PillD tone="open" />
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { FindingDetail });
