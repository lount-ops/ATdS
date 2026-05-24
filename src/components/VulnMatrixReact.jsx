/**
 * src/pages/VulnMatrixReact.jsx
 *
 * fetches /api/vulns.json on mount (served by src/pages/api/vulns.json.js).
 * every load reflects the latest snyk harvest + npm audit merge.
 *
 * requires react to be configured in your astro project:
 *   npx astro add react
 */

import { useState, useEffect, useCallback } from 'react';

// constants

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
const API_URL   = '/api/vulns.json';

// helper

function daysAgo(isoDate) {
  if (!isoDate) return '—';
  const diff = Math.round((Date.now() - new Date(isoDate)) / 86_400_000);
  if (diff === 0) return 'today';
  if (diff === 1) return '1d ago';
  return `${diff}d ago`;
}

function severityRank(s) {
  return SEV_ORDER[s] ?? 4;
}

// sub-component-gruppo

function SevBadge({ severity }) {
  const styles = {
    critical: { background: '#3d0f0f', color: '#ff6b6b', border: '1px solid #7a1f1f' },
    high:     { background: '#2d1a00', color: '#ffaa33', border: '1px solid #6b3f00' },
    medium:   { background: '#0d1f35', color: '#5ba3f5', border: '1px solid #1a3f6b' },
    low:      { background: '#0d2210', color: '#4ecb6e', border: '1px solid #1a5c2a' },
    none:     { background: '#1a1a1a', color: '#666',    border: '1px solid #333' },
  };
  const s = styles[severity] ?? styles.none;
  return (
    <span style={{
      ...s,
      fontSize: '10px',
      fontWeight: 600,
      padding: '2px 8px',
      borderRadius: '3px',
      fontFamily: 'inherit',
      letterSpacing: '0.05em',
      textTransform: 'uppercase',
    }}>
      {severity ?? 'none'}
    </span>
  );
}

function StatusBadge({ status }) {
  const styles = {
    patched:  { background: '#0d2210', color: '#4ecb6e', border: '1px solid #1a5c2a' },
    pending:  { background: '#2d1a00', color: '#ffaa33', border: '1px solid #6b3f00' },
    'no-fix': { background: '#3d0f0f', color: '#ff6b6b', border: '1px solid #7a1f1f' },
    ignored:  { background: '#1a1a1a', color: '#888',    border: '1px solid #333' },
    ok:       { background: '#0a1f10', color: '#2ecc71', border: '1px solid #145a20' },
  };
  const s = styles[status] ?? styles.ignored;
  return (
    <span style={{
      ...s,
      fontSize: '10px',
      fontWeight: 500,
      padding: '2px 8px',
      borderRadius: '3px',
      fontFamily: 'inherit',
    }}>
      {status ?? '—'}
    </span>
  );
}

function SourceBadge({ source }) {
  const isSnyk   = source?.includes('Snyk');
  const isNpm    = source?.includes('npm');
  const isBoth   = isSnyk && isNpm;
  const color    = isBoth ? '#c084fc' : isSnyk ? '#5ba3f5' : '#4ecb6e';
  const border   = isBoth ? '#6d28d9' : isSnyk ? '#1a3f6b' : '#1a5c2a';
  const bg       = isBoth ? '#1a0f2e' : isSnyk ? '#0d1f35' : '#0d2210';
  return (
    <span style={{
      background: bg, color, border: `1px solid ${border}`,
      fontSize: '10px', fontWeight: 500, padding: '2px 7px',
      borderRadius: '3px', fontFamily: 'inherit',
    }}>
      {source ?? '—'}
    </span>
  );
}

// transitive depth indicator — blank for direct deps, flagged for transitive
function DepthBadge({ depth }) {
  if (!depth || depth === 0) return null;
  return (
    <span title={`Transitive dependency — ${depth} hop${depth > 1 ? 's' : ''} from your direct deps`}
      style={{
        background: '#1f1500', color: '#f59e0b', border: '1px solid #78350f',
        fontSize: '9px', fontWeight: 600, padding: '1px 5px',
        borderRadius: '3px', marginLeft: '5px', fontFamily: 'inherit',
        cursor: 'default',
      }}>
      ↳{depth}
    </span>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: '#0f0f0f',
      border: '1px solid #222',
      borderRadius: '4px',
      padding: '10px 16px',
      minWidth: '90px',
    }}>
      <div style={{ fontSize: '11px', color: '#555', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '4px' }}>
        {label}
      </div>
      <div style={{ fontSize: '26px', fontWeight: 700, color: color ?? '#ccc', fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </div>
    </div>
  );
}

function SortHeader({ col, label, sortCol, sortDir, onSort, style }) {
  const active = sortCol === col;
  return (
    <th onClick={() => onSort(col)} style={{
      ...style,
      background: '#0a0a0a',
      padding: '8px 10px',
      textAlign: 'left',
      fontSize: '10px',
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.1em',
      color: active ? '#5ba3f5' : '#444',
      borderBottom: '1px solid #222',
      cursor: 'pointer',
      userSelect: 'none',
      whiteSpace: 'nowrap',
    }}>
      {label}
      {active && <span style={{ marginLeft: '4px', opacity: 0.8 }}>{sortDir === 1 ? '↑' : '↓'}</span>}
    </th>
  );
}

// main

export default function VulnMatrixReact() {
  const [data,      setData]      = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);
  const [lastFetch, setLastFetch] = useState(null);

  // filter state
  const [search,    setSearch]    = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [stFilter,  setStFilter]  = useState('');
  const [srcFilter, setSrcFilter] = useState('');

  // sort state — default: severity ascending (critical first)
  const [sortCol,   setSortCol]   = useState('severity');
  const [sortDir,   setSortDir]   = useState(1);

  // fetch

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(API_URL, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${API_URL}`);
      const json = await res.json();
      if (json.error) throw new Error(json.error);
      setData(Array.isArray(json) ? json : []);
      setLastFetch(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // sort & filter, and rock and roll. the spell yer under...
	// will slowly rob you of your matching soul

  function handleSort(col) {
    setSortDir(prev => sortCol === col ? prev * -1 : 1);
    setSortCol(col);
  }

  const visible = data
    .filter(r => {
      if (search && !r.pkg?.toLowerCase().includes(search.toLowerCase())
                 && !r.cve?.toLowerCase().includes(search.toLowerCase())
                 && !r.title?.toLowerCase().includes(search.toLowerCase())) return false;
      if (sevFilter && r.severity !== sevFilter) return false;
      if (stFilter  && r.status   !== stFilter)  return false;
      if (srcFilter) {
        if (srcFilter === 'Snyk'     && !r.source?.includes('Snyk')) return false;
        if (srcFilter === 'npm'      && !r.source?.includes('npm'))  return false;
        if (srcFilter === 'both'     && r.source !== 'Snyk+npm')     return false;
      }
      return true;
    })
    .sort((a, b) => {
      let av = a[sortCol], bv = b[sortCol];
      if (sortCol === 'severity') {
        return (severityRank(av) - severityRank(bv)) * sortDir;
      }
      if (sortCol === 'depth' || sortCol === 'cvss') {
        return ((Number(av) || 0) - (Number(bv) || 0)) * sortDir;
      }
      return String(av ?? '').localeCompare(String(bv ?? '')) * sortDir;
    });

  // derived stats (not filtered view)

  const stats = {
    critical:    data.filter(r => r.severity === 'critical' && r.status !== 'patched').length,
    high:        data.filter(r => r.severity === 'high'     && r.status !== 'patched').length,
    pending:     data.filter(r => r.status === 'pending').length,
    transitive:  data.filter(r => (r.depth ?? 0) > 0).length,
  };

  // styles — all inline so the component is TailwindCSS/daisyUI independant.

  const wrap = {
    fontFamily: '"Berkeley Mono", "JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
    background: '#080808',
    color: '#c9c9c9',
    borderRadius: '6px',
    border: '1px solid #1e1e1e',
    padding: '20px',
    minHeight: '200px',
  };

  const inputStyle = {
    background: '#0f0f0f',
    border: '1px solid #2a2a2a',
    borderRadius: '3px',
    color: '#ccc',
    fontFamily: 'inherit',
    fontSize: '12px',
    padding: '5px 10px',
    outline: 'none',
  };

  const thBase = { padding: '8px 10px', whiteSpace: 'nowrap' };

  // Render

  if (loading) return (
    <div style={{ ...wrap, display: 'flex', alignItems: 'center', gap: '12px', color: '#444' }}>
      <span style={{ fontSize: '20px', animation: 'spin 1s linear infinite' }}>⟳</span>
      <span style={{ fontSize: '13px' }}>fetching /api/vulns.json …</span>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  if (error) return (
    <div style={{ ...wrap, borderColor: '#5c1010' }}>
      <div style={{ color: '#ff6b6b', fontSize: '13px', marginBottom: '8px' }}>
        ✗ Failed to load vulnerability data
      </div>
      <div style={{ color: '#555', fontSize: '11px', marginBottom: '16px' }}>{error}</div>
      <div style={{ fontSize: '11px', color: '#444', lineHeight: '1.6' }}>
        Check that:<br />
        • <code style={{ color: '#888' }}>snyk-harvest.zsh</code> has run and written <code style={{ color: '#888' }}>vulns.json</code><br />
        • <code style={{ color: '#888' }}>src/pages/api/vulns.json.js</code> exists in your project<br />
        • Your Astro adapter supports server-side rendering
      </div>
      <button onClick={fetchData} style={{
        marginTop: '16px', background: '#1a0a0a', border: '1px solid #5c1010',
        color: '#ff6b6b', fontFamily: 'inherit', fontSize: '12px',
        padding: '6px 14px', borderRadius: '3px', cursor: 'pointer',
      }}>
        retry
      </button>
    </div>
  );

  return (
    <div style={wrap}>

      {/* ── header ── */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: '16px', marginBottom: '16px' }}>
        <span style={{ fontSize: '13px', fontWeight: 700, color: '#5ba3f5', letterSpacing: '0.05em' }}>
          VULN MATRIX
        </span>
        <span style={{ fontSize: '11px', color: '#333' }}>
          {data.length} packages · last fetch {lastFetch ? lastFetch.toLocaleTimeString() : '—'}
        </span>
        <button onClick={fetchData} title="Refresh" style={{
          marginLeft: 'auto', background: 'transparent', border: '1px solid #222',
          color: '#444', fontFamily: 'inherit', fontSize: '11px',
          padding: '3px 10px', borderRadius: '3px', cursor: 'pointer',
        }}>
          ↺ refresh
        </button>
      </div>

      {/* ── stat row ── */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
        <StatCard label="critical open" value={stats.critical}   color="#ff6b6b" />
        <StatCard label="high open"     value={stats.high}       color="#ffaa33" />
        <StatCard label="pending fix"   value={stats.pending}    color="#5ba3f5" />
        <StatCard label="transitive"    value={stats.transitive} color="#c084fc" />
      </div>

      {/* ── filters ── */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '14px', alignItems: 'center' }}>
        <input
          style={{ ...inputStyle, flex: 1, minWidth: '160px' }}
          placeholder="search pkg · CVE · title…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select style={inputStyle} value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">all severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="none">none</option>
        </select>
        <select style={inputStyle} value={stFilter} onChange={e => setStFilter(e.target.value)}>
          <option value="">all statuses</option>
          <option value="pending">pending</option>
          <option value="patched">patched</option>
          <option value="no-fix">no fix</option>
          <option value="ignored">ignored</option>
          <option value="ok">ok</option>
        </select>
        <select style={inputStyle} value={srcFilter} onChange={e => setSrcFilter(e.target.value)}>
          <option value="">all sources</option>
          <option value="Snyk">Snyk only</option>
          <option value="npm">npm only</option>
          <option value="both">both (Snyk+npm)</option>
        </select>
      </div>

      {/* ── table ── */}
      <div style={{ overflowX: 'auto', border: '1px solid #1a1a1a', borderRadius: '4px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
          <thead>
            <tr>
              <SortHeader col="pkg"      label="package"    sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '22%' }} />
              <SortHeader col="current"  label="installed"  sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '9%' }} />
              <SortHeader col="patched"  label="fix ver"    sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '9%' }} />
              <SortHeader col="cve"      label="CVE"        sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '16%' }} />
              <SortHeader col="severity" label="severity"   sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '10%' }} />
              <SortHeader col="status"   label="status"     sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '10%' }} />
              <SortHeader col="depth"    label="depth"      sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '8%' }} />
              <SortHeader col="source"   label="source"     sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '10%' }} />
              <SortHeader col="audited"  label="audited"    sortCol={sortCol} sortDir={sortDir} onSort={handleSort} style={{ ...thBase, width: '8%' }} />
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ padding: '2rem', textAlign: 'center', color: '#333', fontSize: '13px' }}>
                  {data.length === 0 ? 'no vulnerability data — run snyk-harvest.zsh first' : 'no packages match current filters'}
                </td>
              </tr>
            ) : visible.map((row, i) => (
              <tr key={row.pkg + i} style={{
                borderBottom: '1px solid #161616',
                background: i % 2 === 0 ? 'transparent' : '#0b0b0b',
              }}
                onMouseEnter={e => e.currentTarget.style.background = '#111'}
                onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : '#0b0b0b'}
              >
                {/* package */}
                <td style={{ padding: '7px 10px', fontWeight: 600, color: '#ddd' }}>
                  {row.pkg}
                  <DepthBadge depth={row.depth} />
                </td>

                {/* installed ver */}
                <td style={{ padding: '7px 10px', color: '#555', fontVariantNumeric: 'tabular-nums' }}>
                  {row.current ?? '—'}
                </td>

                {/* fix ver */}
                <td style={{ padding: '7px 10px', color: row.patched && row.patched !== '—' ? '#4ecb6e' : '#444', fontVariantNumeric: 'tabular-nums' }}>
                  {row.patched ?? '—'}
                </td>

                {/* cve linked to nvd */}
                <td style={{ padding: '7px 10px' }}>
                  {row.cve && row.cve !== '—' ? (
                    row.cve.startsWith('CVE-') ? (
                      <a href={`https://nvd.nist.gov/vuln/detail/${row.cve}`}
                        target="_blank" rel="noopener noreferrer"
                        title={row.title}
                        style={{ color: '#5ba3f5', textDecoration: 'none', fontSize: '11px' }}
                        onMouseEnter={e => e.target.style.textDecoration = 'underline'}
                        onMouseLeave={e => e.target.style.textDecoration = 'none'}
                      >
                        {row.cve}
                      </a>
                    ) : (
                      /* link to snyk advisory */
                      <a href={`https://security.snyk.io/vuln/${row.cve}`}
                        target="_blank" rel="noopener noreferrer"
                        title={row.title}
                        style={{ color: '#8b5cf6', textDecoration: 'none', fontSize: '11px' }}
                        onMouseEnter={e => e.target.style.textDecoration = 'underline'}
                        onMouseLeave={e => e.target.style.textDecoration = 'none'}
                      >
                        {row.cve}
                      </a>
                    )
                  ) : (
                    <span style={{ color: '#333' }}>—</span>
                  )}
                </td>

                {/* sev */}
                <td style={{ padding: '7px 10px' }}>
                  <SevBadge severity={row.severity} />
                </td>

                {/* status */}
                <td style={{ padding: '7px 10px' }}>
                  <StatusBadge status={row.status} />
                </td>

                {/* depth */}
                <td style={{ padding: '7px 10px', color: '#444', fontSize: '11px', textAlign: 'center' }}>
                  {(row.depth ?? 0) === 0
                    ? <span style={{ color: '#2a2a2a' }}>direct</span>
                    : <span style={{ color: '#f59e0b' }}>↳ {row.depth}</span>
                  }
                </td>

                {/* source */}
                <td style={{ padding: '7px 10px' }}>
                  <SourceBadge source={row.source} />
                </td>

                {/* audited */}
                <td style={{ padding: '7px 10px', color: '#444', fontSize: '11px' }}>
                  {daysAgo(row.audited)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── footer ── */}
      <div style={{ marginTop: '10px', fontSize: '10px', color: '#2a2a2a', display: 'flex', justifyContent: 'space-between' }}>
        <span>↳ depth = transitive hops · CVEs link to NVD · Snyk IDs link to security.snyk.io</span>
        <span>{visible.length} / {data.length} shown</span>
      </div>

    </div>
  );
}
