import React from 'react';

const CSS = `
.vw-hm-wrap { overflow-x: auto; padding-bottom: 6px; scrollbar-width: thin; }
.vw-hm-wrap::-webkit-scrollbar { height: 8px; }
.vw-hm-wrap::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 4px; }
.vw-hm-months { position: relative; height: 18px; margin-left: 34px; margin-bottom: 4px; min-width: fit-content; }
.vw-hm-month { position: absolute; font-size: 11px; font-weight: 500; color: var(--text-muted); }
.vw-hm-main { display: flex; gap: 8px; min-width: fit-content; }
.vw-hm-days { display: flex; flex-direction: column; gap: 4px; padding-top: 2px; }
.vw-hm-day { height: 14px; line-height: 14px; font-size: 11px; color: var(--text-muted); width: 30px; }
.vw-hm-weeks { display: flex; gap: 4px; }
.vw-hm-week { display: flex; flex-direction: column; gap: 4px; }
.vw-hm-cell { width: 14px; height: 14px; border-radius: 2px; cursor: pointer; transition: outline .15s var(--ease-standard); outline: 2px solid transparent; outline-offset: -1px; }
.vw-hm-cell:hover.vw-hm-has { outline-color: var(--vw-primary); }
.vw-hm-out { background: transparent !important; cursor: default; }
.vw-hm-noscan { background: var(--vw-gray-200); }
.vw-hm-sev-none     { background: var(--vw-success); }
.vw-hm-sev-low      { background: var(--severity-low-solid); }
.vw-hm-sev-medium   { background: var(--severity-medium-solid); }
.vw-hm-sev-high     { background: var(--severity-high-solid); }
.vw-hm-sev-critical { background: var(--severity-critical-solid); }
.vw-hm-scheduled { background: repeating-linear-gradient(45deg, var(--vw-primary), var(--vw-primary) 2px, transparent 2px, transparent 4px); opacity: .6; }
.vw-hm-legend { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-muted); font-family: var(--font-primary); margin-top: 12px; }
.vw-hm-legend .vw-hm-cell { cursor: default; }
`;

function useInjectCSS(id, css) {
  React.useEffect(() => {
    if (document.getElementById(id)) return;
    const el = document.createElement('style');
    el.id = id; el.textContent = css;
    document.head.appendChild(el);
  }, [id, css]);
}

const SEV_ORDER = ['none', 'low', 'medium', 'high', 'critical'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DAY_LABELS = ['', 'Mon', '', 'Wed', '', 'Fri', ''];

// Deterministic pseudo-random so the preview is stable across renders.
function seeded(i) {
  const x = Math.sin(i * 99.13) * 10000;
  return x - Math.floor(x);
}

function genWeeks(numWeeks) {
  const today = new Date();
  const end = new Date(today);
  // Walk back to the most recent Saturday so columns align to weeks.
  end.setDate(end.getDate() + (6 - end.getDay()));
  const cells = [];
  const totalDays = numWeeks * 7;
  for (let i = totalDays - 1; i >= 0; i--) {
    const d = new Date(end);
    d.setDate(end.getDate() - i);
    const future = d > today;
    const r = seeded(i + 7);
    let cell;
    if (future) {
      cell = (i % 7 === 2) ? { date: d, scheduled: true } : { date: d, out: true };
    } else if (r < 0.45) {
      cell = { date: d, scans: 0, sev: null };
    } else {
      const sevRoll = seeded(i * 1.7);
      const sev = sevRoll > 0.93 ? 'critical' : sevRoll > 0.82 ? 'high' : sevRoll > 0.62 ? 'medium' : sevRoll > 0.4 ? 'low' : 'none';
      const counts = {};
      SEV_ORDER.forEach(s => { counts[s] = 0; });
      const worstIdx = SEV_ORDER.indexOf(sev);
      counts[sev] = 1 + Math.floor(seeded(i * 3.1) * 3);
      if (worstIdx > 0 && seeded(i * 5.5) > 0.5) counts[SEV_ORDER[worstIdx - 1]] = 1 + Math.floor(seeded(i) * 2);
      cell = { date: d, scans: 1 + Math.floor(seeded(i * 2.2) * 4), sev, counts };
    }
    cells.push(cell);
  }
  // Chunk into weeks (columns of 7, Sunday→Saturday).
  const weeks = [];
  for (let w = 0; w < numWeeks; w++) weeks.push(cells.slice(w * 7, w * 7 + 7));
  return weeks;
}

function cellClass(c) {
  if (c.out) return 'vw-hm-cell vw-hm-out';
  if (c.scheduled) return 'vw-hm-cell vw-hm-scheduled vw-hm-has';
  if (c.scans === 0) return 'vw-hm-cell vw-hm-noscan vw-hm-has';
  return `vw-hm-cell vw-hm-sev-${c.sev} vw-hm-has`;
}

const SEV_LABEL = { none: 'No issues', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
const SEV_VAR = { critical: 'var(--severity-critical)', high: 'var(--severity-high)', medium: 'var(--severity-medium)', low: 'var(--severity-low)' };

/**
 * Scan-activity heatmap — GitHub-contributions-style calendar where each cell
 * is a day colored by the worst severity found in that day's scans.
 */
export function ScanHeatmap({ weeks = 26, data, legend = true, style }) {
  useInjectCSS('vw-hm-css', CSS);
  const grid = React.useMemo(() => data || genWeeks(weeks), [data, weeks]);
  const [tip, setTip] = React.useState(null);

  // Month labels: place above the first week whose first day starts a new month.
  const monthMarks = [];
  let lastMonth = -1;
  grid.forEach((wk, wi) => {
    const first = wk.find(c => c && c.date);
    if (!first) return;
    const m = first.date.getMonth();
    if (m !== lastMonth) { monthMarks.push({ label: MONTHS[m], left: wi * 18 }); lastMonth = m; }
  });

  function fmt(d) { return d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' }); }

  return (
    <div style={{ fontFamily: 'var(--font-primary)', ...style }}>
      <div className="vw-hm-wrap">
        <div className="vw-hm-months" style={{ width: grid.length * 18 }}>
          {monthMarks.map((m, i) => <span key={i} className="vw-hm-month" style={{ left: m.left }}>{m.label}</span>)}
        </div>
        <div className="vw-hm-main">
          <div className="vw-hm-days">
            {DAY_LABELS.map((d, i) => <div key={i} className="vw-hm-day">{d}</div>)}
          </div>
          <div className="vw-hm-weeks">
            {grid.map((wk, wi) => (
              <div key={wi} className="vw-hm-week">
                {wk.map((c, di) => (
                  <div
                    key={di}
                    className={cellClass(c)}
                    onMouseEnter={(e) => !c.out && setTip({ c, x: e.clientX, y: e.clientY })}
                    onMouseMove={(e) => !c.out && setTip(t => t ? { ...t, x: e.clientX, y: e.clientY } : t)}
                    onMouseLeave={() => setTip(null)}
                  ></div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>

      {legend ? (
        <div className="vw-hm-legend">
          <span>Less</span>
          <span className="vw-hm-cell vw-hm-sev-none"></span>
          <span className="vw-hm-cell vw-hm-sev-low"></span>
          <span className="vw-hm-cell vw-hm-sev-medium"></span>
          <span className="vw-hm-cell vw-hm-sev-high"></span>
          <span className="vw-hm-cell vw-hm-sev-critical"></span>
          <span>More severe</span>
          <span style={{ marginLeft: '14px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
            <span className="vw-hm-cell vw-hm-scheduled"></span>Scheduled
          </span>
        </div>
      ) : null}

      {tip ? (
        <div style={{
          position: 'fixed', left: tip.x + 14, top: tip.y + 14, zIndex: 1050, pointerEvents: 'none',
          minWidth: '180px', background: 'var(--surface-card)', border: '1px solid var(--border-default)',
          borderRadius: '6px', padding: '10px 12px', boxShadow: 'var(--shadow-lg)', fontFamily: 'var(--font-primary)',
        }}>
          <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-heading)', marginBottom: '5px' }}>{fmt(tip.c.date)}</div>
          {tip.c.scheduled ? (
            <div style={{ fontSize: '13px', color: 'var(--vw-primary)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '6px' }}>
              <i className="fas fa-clock"></i>Scan scheduled
            </div>
          ) : tip.c.scans === 0 ? (
            <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>No scans</div>
          ) : (
            <div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px' }}>{tip.c.scans} scan{tip.c.scans > 1 ? 's' : ''}</div>
              {tip.c.sev === 'none' ? (
                <div style={{ fontSize: '13px', color: 'var(--vw-success)', fontWeight: 500, borderTop: '1px solid var(--border-default)', paddingTop: '6px' }}>No issues found</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', borderTop: '1px solid var(--border-default)', paddingTop: '6px' }}>
                  {SEV_ORDER.slice().reverse().filter(s => s !== 'none' && tip.c.counts && tip.c.counts[s] > 0).map(s => (
                    <div key={s} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-body)' }}>
                      <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: SEV_VAR[s] }}></span>
                      {tip.c.counts[s]} {SEV_LABEL[s]}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}
