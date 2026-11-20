// Findings list screen — filter chips + scannable rows.
const { SeverityBadge: SevF, Button: BtnF } = window.VulWallDesignSystem_2af3fe;
const { useState: useStateF } = React;

function FilterChip({ label, count, active, onClick }) {
  return (
    <button onClick={onClick} style={{
      display: 'inline-flex', alignItems: 'center', gap: '7px', cursor: 'pointer',
      padding: '7px 14px', borderRadius: 'var(--radius-pill)', fontFamily: 'var(--font-primary)',
      fontSize: '13px', fontWeight: 600,
      border: `1px solid ${active ? 'var(--vw-primary)' : 'var(--border-default)'}`,
      background: active ? 'var(--vw-primary)' : 'var(--surface-card)',
      color: active ? '#fff' : 'var(--text-body)',
      transition: 'all 0.2s var(--ease-standard)',
    }}>
      {label}
      <span style={{ fontSize: '12px', opacity: 0.8 }}>{count}</span>
    </button>
  );
}

function FindingRow({ f, onOpen }) {
  const [hover, setHover] = useStateF(false);
  return (
    <button
      onClick={() => onOpen(f.id)}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: '14px', width: '100%', textAlign: 'left',
        cursor: 'pointer', border: 'none', borderBottom: '1px solid var(--border-default)',
        background: hover ? 'var(--vw-gray-50)' : 'var(--surface-card)',
        padding: '14px 18px', fontFamily: 'var(--font-primary)',
        transition: 'background 0.15s var(--ease-standard)',
      }}
    >
      <SevF level={f.level} />
      <span style={{ fontSize: '14px', color: 'var(--text-heading)', fontWeight: 500, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-faint)', flexShrink: 0 }}>{f.cve || f.host}</span>
      <i className="fas fa-chevron-right" style={{ color: 'var(--text-faint)', fontSize: '12px' }}></i>
    </button>
  );
}

function Findings({ onOpenFinding }) {
  const all = window.FINDINGS;
  const [filter, setFilter] = useStateF('all');
  const counts = { all: all.length };
  ['critical', 'high', 'medium', 'low', 'info'].forEach(l => { counts[l] = all.filter(f => f.level === l).length; });
  const shown = filter === 'all' ? all : all.filter(f => f.level === filter);

  return (
    <div>
      {window.PageHeader ? <window.PageHeader title="Findings" subtitle={`${all.length} open findings across 7 assets`} action={<BtnF variant="secondary" icon="fas fa-arrow-up-right-from-square">Export</BtnF>} /> : null}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '16px' }}>
        <FilterChip label="All" count={counts.all} active={filter === 'all'} onClick={() => setFilter('all')} />
        <FilterChip label="Critical" count={counts.critical} active={filter === 'critical'} onClick={() => setFilter('critical')} />
        <FilterChip label="High" count={counts.high} active={filter === 'high'} onClick={() => setFilter('high')} />
        <FilterChip label="Medium" count={counts.medium} active={filter === 'medium'} onClick={() => setFilter('medium')} />
        <FilterChip label="Low" count={counts.low} active={filter === 'low'} onClick={() => setFilter('low')} />
        <FilterChip label="Info" count={counts.info} active={filter === 'info'} onClick={() => setFilter('info')} />
      </div>
      <div style={{ background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-card)', overflow: 'hidden' }}>
        {shown.map((f, i) => <FindingRow key={f.id} f={f} onOpen={onOpenFinding} />)}
        <div style={{ height: 0 }}></div>
      </div>
    </div>
  );
}

Object.assign(window, { Findings });
