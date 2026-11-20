// NightWatch dashboard — app shell + simple view routing.
const { useState: useAppState } = React;

function App() {
  const [view, setView] = useAppState('overview');     // overview | findings | assets | reports | scanners
  const [findingId, setFindingId] = useAppState(null);
  const [theme, setTheme] = useAppState('light');
  const [toast, setToast] = useAppState(null);

  function navigate(v) { setFindingId(null); setView(v); }
  function openFinding(id) { setFindingId(id); }
  function toggleTheme() {
    const next = theme === 'light' ? 'dark' : 'light';
    setTheme(next);
    document.documentElement.setAttribute('data-bs-theme', next);
  }
  function rescan() {
    setToast('Scan queued — NightWatch is checking your perimeter.');
    setTimeout(() => setToast(null), 2600);
  }

  let body;
  if (findingId != null) {
    body = <window.FindingDetail id={findingId} onBack={() => setFindingId(null)} />;
  } else if (view === 'overview') {
    body = <window.Overview onOpenFinding={openFinding} onRescan={rescan} />;
  } else if (view === 'findings') {
    body = <window.Findings onOpenFinding={openFinding} />;
  } else if (view === 'assets') {
    body = <window.Assets />;
  } else {
    body = (
      <div style={{ textAlign: 'center', padding: '80px 20px', color: 'var(--text-faint)' }}>
        <i className="fas fa-screwdriver-wrench" style={{ fontSize: '32px', marginBottom: '14px' }}></i>
        <div style={{ fontSize: '15px' }}>This section is part of the full product.</div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--app-bg)' }}>
      <window.Sidebar active={findingId != null ? 'findings' : view} onNavigate={navigate} theme={theme} onToggleTheme={toggleTheme} />
      <main style={{ flex: 1, minWidth: 0, padding: '30px 34px', overflowX: 'hidden' }}>
        {body}
      </main>
      {toast ? (
        <div style={{ position: 'fixed', bottom: '24px', left: '50%', transform: 'translateX(-50%)', background: 'var(--surface-inverse)', color: '#fff', padding: '12px 20px', borderRadius: 'var(--radius-md)', boxShadow: 'var(--shadow-lg)', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '14px', fontFamily: 'var(--font-primary)', zIndex: 100 }}>
          <i className="fas fa-radar" style={{ color: 'var(--accent-orange)' }}></i>{toast}
        </div>
      ) : null}
    </div>
  );
}

// Expose only — index.html does the single, deterministic mount. (No top-level
// side-effect here: this file is also swept into _ds_bundle.js, and a mount at
// module-eval time would run twice and double-create the React root.)
Object.assign(window, { App });
