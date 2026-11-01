import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, Drawer, EmptyState, ErrorBanner, Loading, PageHeader, Stat } from './ui'

/* Portfolio = the Dependency-Track view the console was missing: every
   project version with its own component inventory, license mix and severity
   vector, grouped by project so "which project does this belong to" answers
   itself. */

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
        </p>
      </div>
    </Drawer>
  )
}

export default function Projects({ onNavigate }) {
  const [rows, setRows] = useState(null)
  const [totals, setTotals] = useState(null)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  const [open, setOpen] = useState(null)

  function load() {
    setError('')
    api.get('/api/v1/inventory/portfolio')
      .then((response) => { setRows(response.data || []); setTotals(response.totals) })
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(load, [])

  const groups = useMemo(() => {
    const byProject = new Map()
    for (const row of rows || []) {
      if (filter && !row.project_name.toLowerCase().includes(filter.toLowerCase())) continue
      if (!byProject.has(row.project)) byProject.set(row.project, { name: row.project_name, versions: [] })
      byProject.get(row.project).versions.push(row)
    }
    return [...byProject.values()].sort((a, b) => a.name.localeCompare(b.name))
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
        subtitle={totals
          ? `${totals.versions} versions · ${totals.components} components · ${totals.findings} findings`
          : 'Portfolio'}
        actions={(
          <>
            <input placeholder="filter projects" value={filter}
              onChange={(event) => setFilter(event.target.value)} style={{ minWidth: 180 }} />
            <button onClick={load}>refresh</button>
          </>
        )}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      {totals && (
        <Card>
          <div className="metrics">
            <Stat label="projects" value={groups.length} />
            <Stat label="versions" value={totals.versions} />
            <Stat label="components" value={totals.components} />
            <Stat label="findings" value={totals.findings} />
            <Stat label="critical" value={totals.by_severity.CRITICAL}
              tone={totals.by_severity.CRITICAL ? 'bad' : ''} />
            <Stat label="high" value={totals.by_severity.HIGH}
              tone={totals.by_severity.HIGH ? 'warn' : ''} />
            <Stat label="known exploited" value={totals.kev} tone={totals.kev ? 'bad' : ''} />
          </div>
        </Card>
      )}

      {!groups.length && (
        <EmptyState title="No project versions yet"
          hint="Ingest an SBOM: the project and version are created from it." />
      )}

      {groups.map((group) => (
        <Card key={group.name}
          title={`${group.name} · ${group.versions.length} version${group.versions.length === 1 ? '' : 's'}`}>
          <table>
            <thead>
              <tr>
                <th>version</th><th>components</th><th>severity</th>
                <th>findings</th><th>kev</th><th>last sbom</th><th></th>
              </tr>
            </thead>
            <tbody>
              {group.versions.map((row) => (
                <tr key={row.version_id} className="clickable" onClick={() => setOpen(row)}>
                  <td className="mono">{row.version}</td>
                  <td className="num">{row.components.total}</td>
                  <td><SeverityStrip counts={row.findings.by_severity} /></td>
                  <td className="num">{row.findings.total}</td>
                  <td>
                    {row.findings.kev
                      ? <span className="sev sev-critical">{row.findings.kev}</span>
                      : <span className="muted">0</span>}
                  </td>
                  <td className="muted">
                    {row.last_import ? new Date(row.last_import.imported_at).toLocaleDateString() : '—'}
                  </td>
                  <td>
                    <button className="mini" onClick={(event) => {
                      event.stopPropagation()
                      setOpen(row)
                    }}>open</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ))}

      {open && <VersionDetail row={open} onClose={() => setOpen(null)} onNavigate={onNavigate} />}
    </div>
  )
}
