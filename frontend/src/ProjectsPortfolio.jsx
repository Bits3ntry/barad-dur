import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, Drawer, EmptyState, ErrorBanner, Loading, PageHeader, Stat } from './ui'

/* Three levels, because a repository is not what anyone reports on:
     group (Aurea) -> project (backend) -> version (1923bba)
   Accounting rule everywhere: the version selected for that project, otherwise
   its latest. Summing every historical version would double-count components
   and inflate findings, so group totals count one version per project. */

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

function SeverityStrip({ counts }) {
  const shown = SEVERITIES.filter((severity) => counts[severity] > 0)
  if (!shown.length) return <span className="pill">clean</span>
  return (
    <div className="row" style={{ gap: 4 }}>
      {shown.map((severity) => (
        <span key={severity} className={`sev sev-${severity.toLowerCase()}`}>
          {severity[0]}{counts[severity]}
        </span>
      ))}
    </div>
  )
}

function blankTotals() {
  return { components: 0, findings: 0, kev: 0,
    by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 } }
}

function addRow(totals, row) {
  totals.components += row.components.total
  totals.findings += row.findings.total
  totals.kev += row.findings.kev
  for (const severity of SEVERITIES) {
    totals.by_severity[severity] += row.findings.by_severity[severity]
  }
  return totals
}

function VersionDetail({ row, onClose, onNavigate }) {
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    setFindings(null)
    api.get(`/api/v1/findings?project=${encodeURIComponent(row.project)}`
      + `&version=${encodeURIComponent(row.version)}`)
      .then((response) => setFindings(response.data || []))
      .catch((e) => setError(String(e.message || e)))
  }, [row.project, row.version])

  const worst = findings
    ? [...findings].sort((a, b) => SEVERITIES.indexOf(a.severity || 'UNKNOWN')
      - SEVERITIES.indexOf(b.severity || 'UNKNOWN')).slice(0, 25)
    : []

  return (
    <Drawer open title={`${row.project_name} · ${row.version}`} onClose={onClose}>
      <div className="stack">
        <div className="metrics">
          <Stat label="components" value={row.components.total} />
          <Stat label="vulnerable" value={row.findings.vulnerable_components}
            tone={row.findings.vulnerable_components ? 'warn' : ''} />
          <Stat label="findings" value={row.findings.total} />
          <Stat label="known exploited" value={row.findings.kev}
            tone={row.findings.kev ? 'bad' : ''} />
        </div>

        <Card title="Severity of this version">
          <SeverityStrip counts={row.findings.by_severity} />
        </Card>

        <Card title="Licenses">
          <div className="row">
            {row.licenses.top.map((entry) => (
              <span className="pill" key={entry.license}>
                {entry.license} · {entry.count}
              </span>
            ))}
          </div>
          <p className="muted" style={{ marginTop: 8 }}>
            {row.licenses.distinct} distinct licenses across {row.components.total} components
          </p>
        </Card>

        <Card title="Components with most findings">
          {row.top_components.length ? (
            <table>
              <thead>
                <tr><th>component</th><th>version</th><th>license</th><th>findings</th></tr>
              </thead>
              <tbody>
                {row.top_components.map((component) => (
                  <tr key={`${component.purl || component.name}-${component.version}`}>
                    <td className="mono">{component.name}</td>
                    <td>{component.version || '—'}</td>
                    <td className="muted">{component.license || '—'}</td>
                    <td>
                      <span className={component.findings ? 'sev sev-high' : 'muted'}>
                        {component.findings}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">No component in this version carries a finding.</p>}
        </Card>

        <Card title="Findings (worst first)"
          actions={<button className="mini" onClick={() => onNavigate && onNavigate('findings')}>
            open findings
          </button>}>
          {error && <ErrorBanner error={error} />}
          {!findings && !error && <Loading rows={3} />}
          {findings && !findings.length && <p className="muted">No open findings for this version.</p>}
          {worst.map((finding) => (
            <div className="occ-row" key={finding.id}>
              <span className={`sev sev-${(finding.severity || 'unknown').toLowerCase()}`}>
                {finding.severity || 'unknown'}
              </span>{' '}
              <span className="mono">{finding.cve_id || finding.rule_id || finding.kind}</span>
              <div className="muted" style={{ fontSize: 12 }}>
                {finding.component_purl || ''}
                {finding.title ? ` · ${finding.title}` : ''}
              </div>
            </div>
          ))}
          {findings && findings.length > worst.length && (
            <p className="muted">+{findings.length - worst.length} more — see Findings.</p>
          )}
        </Card>

        <p className="muted">
          Last SBOM: {row.last_import
            ? `${new Date(row.last_import.imported_at).toLocaleString()} (${row.last_import.source})`
            : 'never imported'}
          {row.is_latest ? ' · latest version' : ''}
        </p>
      </div>
    </Drawer>
  )
}

function GroupCard({ group, rows, selection, onSelect, onOpen, collapsed, onToggle,
                     onScan, scanning }) {
  const [expanded, setExpanded] = useState(null)

  // One row per project: the version picked for it, else the latest.
  const chosen = useMemo(() => {
    const byProject = new Map()
    for (const row of rows) {
      if (!byProject.has(row.project)) byProject.set(row.project, [])
      byProject.get(row.project).push(row)
    }
    return [...byProject.entries()].map(([project, versions]) => {
      const wanted = selection[project]
      const row = versions.find((entry) => entry.version === wanted)
        || versions.find((entry) => entry.is_latest)
        || versions[0]
      return { project, versions, row }
    }).sort((a, b) => a.project.localeCompare(b.project))
  }, [rows, selection])

  const totals = useMemo(
    () => chosen.reduce((acc, entry) => addRow(acc, entry.row), blankTotals()),
    [chosen])

  return (
    <Card title={`${group} · ${chosen.length} project${chosen.length === 1 ? '' : 's'}`}
      actions={(
        <div className="row">
          <span className="count">
            {collapsed ? `${totals.components} components · ${totals.findings} findings` : 'counted at latest or selected version'}
          </span>
          <button className="mini" onClick={onToggle}
            aria-expanded={!collapsed}
            title={collapsed ? 'expand this group' : 'collapse this group'}>
            {collapsed ? '▸ show' : '▾ hide'}
          </button>
        </div>
      )}>
      <div style={{ display: collapsed ? 'none' : 'block' }}>
      <div className="metrics" style={{ marginBottom: 12 }}>
        <Stat label="components" value={totals.components} />
        <Stat label="findings" value={totals.findings} />
        <Stat label="critical" value={totals.by_severity.CRITICAL}
          tone={totals.by_severity.CRITICAL ? 'bad' : ''} />
        <Stat label="high" value={totals.by_severity.HIGH}
          tone={totals.by_severity.HIGH ? 'warn' : ''} />
        <Stat label="known exploited" value={totals.kev} tone={totals.kev ? 'bad' : ''} />
      </div>

      <table>
        <thead>
          <tr>
            <th>project</th><th>version</th><th>components</th><th>severity</th>
            <th>findings</th><th>kev</th><th></th>
          </tr>
        </thead>
        <tbody>
          {chosen.map(({ project, versions, row }) => (
            <React.Fragment key={project}>
              <tr className="clickable" onClick={() => onOpen(row)}>
                <td className="title">{project}</td>
                <td onClick={(event) => event.stopPropagation()}>
                  {versions.length > 1 ? (
                    <select value={row.version} aria-label={`version for ${project}`}
                      onChange={(event) => onSelect(project, event.target.value)}>
                      {versions.map((entry) => (
                        <option key={entry.version} value={entry.version}>
                          {entry.version}{entry.is_latest ? ' · latest' : ''}
                        </option>
                      ))}
                    </select>
                  ) : <span className="mono">{row.version}</span>}
                </td>
                <td className="num">{row.components.total}</td>
                <td>
                  {row.findings.total === 0 && row.components.total > 0
                    ? <span className="sev sev-medium" title="inventory imported, advisories not matched yet">
                      not scanned
                    </span>
                    : <SeverityStrip counts={row.findings.by_severity} />}
                </td>
                <td className="num">{row.findings.total}</td>
                <td className="num">
                  {row.findings.kev
                    ? <span className="sev sev-critical">{row.findings.kev}</span>
                    : <span className="muted">0</span>}
                </td>
                <td>
                  <div className="row">
                    {versions.length > 1 && (
                      <button className="mini" onClick={(event) => {
                        event.stopPropagation()
                        setExpanded(expanded === project ? null : project)
                      }}>
                        {expanded === project ? 'hide versions' : `${versions.length} versions`}
                      </button>
                    )}
                    <button className="mini" onClick={(event) => {
                      event.stopPropagation(); onOpen(row)
                    }}>open</button>
                  </div>
                </td>
              </tr>
              {expanded === project && (
                <tr className="detail-row"><td colSpan={7}>
                  <div className="detail">
                    <table>
                      <thead>
                        <tr><th>version</th><th>components</th><th>findings</th>
                          <th>kev</th><th>last sbom</th><th></th></tr>
                      </thead>
                      <tbody>
                        {versions.map((entry) => (
                          <tr key={entry.version}
                            className={entry.version === row.version ? 'selected' : ''}>
                            <td className="mono">{entry.version}
                              {entry.is_latest && <span className="muted"> · latest</span>}</td>
                            <td className="num">{entry.components.total}</td>
                            <td className="num">{entry.findings.total}</td>
                            <td className="num">{entry.findings.kev || '—'}</td>
                            <td className="muted">
                              {entry.last_import
                                ? new Date(entry.last_import.imported_at).toLocaleDateString()
                                : '—'}
                            </td>
                            <td>
                              <div className="row">
                                <button className="mini"
                                  onClick={() => onSelect(project, entry.version)}>
                                  {entry.version === row.version ? 'counting this' : 'count this'}
                                </button>
                                <button className="mini" disabled={!onScan}
                                  onClick={() => onScan(project, entry.version)}>
                                  {scanning === `${project}@${entry.version}` ? 'scanning…' : 'scan OSV'}
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      </div>
    </Card>
  )
}

export default function ProjectsPortfolio({ onNavigate }) {
  const [rows, setRows] = useState(null)
  const [latestTotals, setLatestTotals] = useState(null)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  const [selection, setSelection] = useState({})
  const [open, setOpen] = useState(null)
  // Collapsing is a reading preference, so it survives a reload.
  const [scanning, setScanning] = useState('')

  const [collapsed, setCollapsed] = useState(() => {
    try {
      return new Set(JSON.parse(localStorage.getItem('barad.projects.collapsed') || '[]'))
    } catch { return new Set() }
  })

  function rememberCollapsed(next) {
    setCollapsed(next)
    localStorage.setItem('barad.projects.collapsed', JSON.stringify([...next]))
  }

  function toggleGroup(group) {
    const next = new Set(collapsed)
    if (next.has(group)) next.delete(group); else next.add(group)
    rememberCollapsed(next)
  }

  function load() {
    setError('')
    api.get('/api/v1/inventory/portfolio')
      .then((response) => {
        setRows(response.data || [])
        setLatestTotals(response.latest_totals || response.totals || null)
      })
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(load, [])

  async function scanVersion(project, version) {
    setScanning(`${project}@${version}`)
    setError('')
    try {
      await api.post(`/api/v1/analyze?project=${encodeURIComponent(project)}`
        + `&version=${encodeURIComponent(version)}`)
      load()
    } catch (problem) {
      setError(String(problem.message || problem))
    }
    setScanning('')
  }

  const groups = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    const byGroup = new Map()
    for (const row of rows || []) {
      if (needle && !`${row.group} ${row.project_name}`.toLowerCase().includes(needle)) continue
      if (!byGroup.has(row.group)) byGroup.set(row.group, [])
      byGroup.get(row.group).push(row)
    }
    // Ungrouped last: it is the "not filed yet" bucket, not a product.
    return [...byGroup.entries()].sort(([left], [right]) => {
      if (left === 'ungrouped') return 1
      if (right === 'ungrouped') return -1
      return left.localeCompare(right)
    })
  }, [rows, filter])

  if (!rows) {
    return (
      <div className="stack">
        <PageHeader title="Projects" subtitle="Loading the portfolio…" />
        <Card>{error ? <ErrorBanner error={error} onRetry={load} /> : <Loading rows={5} />}</Card>
      </div>
    )
  }

  return (
    <div className="stack">
      <PageHeader
        title="Projects"
        subtitle={latestTotals
          ? `${groups.length} groups · ${latestTotals.projects} projects · `
            + `${latestTotals.components} components · ${latestTotals.findings} findings`
          : 'Portfolio'}
        actions={(
          <>
            <input placeholder="filter group or project" value={filter}
              onChange={(event) => setFilter(event.target.value)} style={{ minWidth: 200 }} />
            <button onClick={() => rememberCollapsed(
              collapsed.size === groups.length
                ? new Set()
                : new Set(groups.map(([group]) => group)))}>
              {collapsed.size === groups.length ? 'expand all' : 'collapse all'}
            </button>
            <button onClick={load}>refresh</button>
          </>
        )}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      {!groups.length && (
        <EmptyState title="No project versions yet"
          hint="Ingest an SBOM: the project and version are created from it." />
      )}

      {groups.map(([group, groupRows]) => (
        <GroupCard key={group} group={group} rows={groupRows}
          selection={selection}
          collapsed={collapsed.has(group)}
          onToggle={() => toggleGroup(group)}
          scanning={scanning}
          onScan={scanVersion}
          onSelect={(project, version) => setSelection((current) => ({
            ...current, [project]: version }))}
          onOpen={setOpen} />
      ))}

      {open && <VersionDetail row={open} onClose={() => setOpen(null)} onNavigate={onNavigate} />}
    </div>
  )
}
