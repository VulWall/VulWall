// Overview screen — header, score + stat row, top findings.
const { ScoreRing: ScoreRingO, StatCard: StatCardO, FindingCard: FindingCardO, Button: ButtonO, ScanHeatmap: ScanHeatmapO } = window.VulWallDesignSystem_2af3fe;

function PageHeader({ title, subtitle, action }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', marginBottom: '22px', flexWrap: 'wrap' }}>
      <div>
        <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-heading)', margin: 0, fontFamily: 'var(--font-primary)' }}>{title}</h1>
        {subtitle ? <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>{subtitle}</div> : null}
      </div>
      {action}
    </div>
  );
}

function Overview({ onOpenFinding, onRescan }) {
  const top = window.FINDINGS.slice(0, 4);
  return (
    <div>
      <PageHeader
        title="acme.com"
        subtitle="Last scan 4 hours ago · 12 scanners · 7 assets"
        action={<ButtonO variant="primary" icon="fas fa-bolt" onClick={onRescan}>Rescan now</ButtonO>}
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr 1fr 1fr', gap: '14px', marginBottom: '22px' }}>
        <div style={{ background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-card)', padding: '18px 20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <ScoreRingO score={72} label="/ 100" size={92} />
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Security score</div>
            <div style={{ fontSize: '15px', color: 'var(--severity-medium)', fontWeight: 600, marginTop: '3px' }}>Needs attention</div>
          </div>
        </div>
        <StatCardO value="2" label="Critical" tone="critical" icon="fas fa-circle-exclamation" />
        <StatCardO value="5" label="High" tone="high" icon="fas fa-triangle-exclamation" />
        <StatCardO value="23" label="Passed" tone="passed" icon="fas fa-circle-check" />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
        <h2 style={{ fontSize: '17px', fontWeight: 600, color: 'var(--text-heading)', margin: 0, fontFamily: 'var(--font-primary)' }}>Scan activity</h2>
        <span style={{ fontSize: '13px', color: 'var(--text-faint)' }}>Last 6 months · worst severity per day</span>
      </div>
      <div style={{ background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-card)', padding: '18px 20px', marginBottom: '24px' }}>
        <ScanHeatmapO weeks={26} />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
        <h2 style={{ fontSize: '17px', fontWeight: 600, color: 'var(--text-heading)', margin: 0, fontFamily: 'var(--font-primary)' }}>Top findings</h2>
        <span style={{ fontSize: '13px', color: 'var(--text-faint)' }}>Ranked by real-world risk</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {top.map(f => (
          <FindingCardO key={f.id} level={f.level} title={f.title} description={f.description}
            cve={f.cve} host={f.host} port={f.port}
            onFix={() => onOpenFinding(f.id)} onMute={() => {}} />
        ))}
      </div>
    </div>
  );
}

Object.assign(window, { Overview, PageHeader });
