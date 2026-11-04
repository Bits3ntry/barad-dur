import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, Loading, PageHeader, Tabs } from './ui'

/* Supply chain reads a BOM as a document about a build, not as a project tab.
   The index answers "which builds have a BOM"; opening one answers "what does
   this build ship and what is wrong with it" — the Dependency-Track screen,
   with this console's calm. Tabs that have no data source yet say so instead of
   showing an empty table that looks like a clean result. */

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

function relative(iso) {
  if (!iso) return 'never'
  const ms = Date.now() - new Date(iso).getTime()
  if (!Number.isFinite(ms)) return 'never'
  const minutes = Math.round(ms / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  return days === 1 ? 'yesterday' : `${days}d ago`
}

function SeverityVector({ counts }) {
  const total = SEVERITIES.reduce((sum, key) => sum + (counts?.[key] || 0), 0)
  if (!total) return <span className="sbom-clean">no findings</span>
  return (
    <div className="sbom-vector">
      {SEVERITIES.map((severity) => (
        <div className={`sbom-count sev-${severity.toLowerCase()}`} key={severity}>
          <span className={`sbom-count-value ${(counts?.[severity] ?? 0) === 0 ? 'is-zero' : ''}`}>
            {counts?.[severity] ?? 0}
          </span>
          <span className="sbom-count-label">{severity.toLowerCase()}</span>
        </div>
      ))}
    </div>
  )
}

function severityClass(value) {
  const key = (value || 'UNKNOWN').toLowerCase()
  return SEVERITIES.includes((value || 'UNKNOWN').toUpperCase()) ? `sev-${key}` : 'sev-unknown'
}

export default function Sbom({ focus = {}, onOpen, onBack }) {
  const [index, setIndex] = useState(null)
  const [error, setError] = useState('')

  const projectSlug = focus.projectSlug || ''
  const version = focus.version || ''

  useEffect(() => {
    setError('')
    api.get('/api/v1/sbom/index')
      .then((r) => setIndex(r))
      .catch((e) => setError(String(e.message || e)))
  }, [])

  if (error) return <div className="banner banner-error">{error}</div>
  if (projectSlug && version) {
    return <BomView project={projectSlug} version={version} onBack={onBack} />
  }
  if (index === null) return <Card><Loading rows={4} /></Card>

  const rows = index.data || []
  const totals = index.totals || {}

  return (
    <div className="stack">
      <PageHeader
        title="SBOMs"
        subtitle="Every build with a bill of materials, whichever project it belongs to. A BOM is a document about a version — this is the way in that does not start at Projects." />

      {!rows.length && (
        <Card>
          <EmptyState title="No BOMs yet"
            hint="Import one from the CLI or CI (`barad sbom`), or from a version inside a project. It attaches to that version, and appears here." />
        </Card>
      )}

      {rows.length > 0 && (
        <>
          <Card tight>
            <div className="sbom-totals">
              <div><strong>{totals.boms}</strong> builds</div>
              <div><strong>{totals.components}</strong> components</div>
              <div><strong>{totals.findings}</strong> findings</div>
              <div><strong>{totals.kev}</strong> in KEV</div>
              <SeverityVector counts={totals.by_severity} />
            </div>
          </Card>

          <Card tight>
            <table className="sbom-index">
              <thead>
                <tr>
                  <th>project</th><th>version</th><th>components</th>
                  <th>findings</th><th>kev</th><th>severity</th><th>last import</th><th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.project.slug}:${row.version}`}>
                    <td className="title">{row.project.name}</td>
                    <td className="mono">
                      {row.version}
                      {row.is_latest ? <span className="pill sbom-latest">latest</span> : null}
                    </td>
                    <td>
                      {row.components}
                      <span className="muted sbom-sub">{row.direct} direct</span>
                    </td>
                    <td>{row.findings.total}</td>
                    <td>{row.findings.kev ? <span className="pill sev-critical">{row.findings.kev}</span>
                      : <span className="muted">0</span>}</td>
                    <td>
                      <SeverityVector counts={row.findings.by_severity} />
                    </td>
                    <td className="muted">{relative(row.last_import_at)}</td>
                    <td className="sbom-open">
                      <button className="mini"
                        onClick={() => onOpen && onOpen(row.project.slug, row.version)}>
                        open ›
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}
    </div>
  )
}

/* ── one build ─────────────────────────────────────────────────────────────── */

function BomView({ project, version, onBack }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState('overview')
  const [severity, setSeverity] = useState('')
  const [needle, setNeedle] = useState('')

  useEffect(() => {
    setData(null)
    setError('')
    api.get(`/api/v1/sbom/version?project=${encodeURIComponent(project)}&version=${encodeURIComponent(version)}`)
      .then((r) => setData(r.data))
      .catch((e) => setError(String(e.message || e)))
  }, [project, version])

  const vulnerabilities = useMemo(() => {
    const rows = data?.vulnerabilities || []
    const text = needle.trim().toLowerCase()
    return rows.filter((row) => {
      if (severity && row.severity !== severity) return false
      if (!text) return true
      return `${row.component || ''} ${row.vulnerability || ''} ${row.title || ''}`
        .toLowerCase().includes(text)
    })
  }, [data, severity, needle])

  if (error) return <div className="banner banner-error">{error}</div>
  if (!data) return <Card><Loading rows={5} /></Card>

  const licenses = Object.entries(data.licenses || {}).sort((a, b) => b[1] - a[1])
  const latestImport = data.imports?.[0]

  return (
    <div className="stack">
      <div className="sbom-head">
        <div>
          <p className="project-crumb" style={{ marginBottom: 6 }}>
            <button onClick={onBack}>‹ SBOMs</button>
          </p>
          <h1 className="page-title">{data.project.name} <span className="mono sbom-version">{data.version}</span></h1>
          <p className="page-sub">
            {data.components} components
            {data.direct ? ` · ${data.direct} direct` : ''} ·{' '}
            {latestImport ? `last import ${relative(latestImport.at)}` : 'no import recorded'}
            {latestImport?.filename ? ` · ${latestImport.filename}` : ''}
          </p>
        </div>
        <SeverityVector counts={data.findings?.by_severity} />
      </div>

      <Tabs
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'components', label: `Components (${data.components})` },
          { id: 'vulnerabilities', label: `Audit vulnerabilities (${data.findings?.total || 0})` },
          { id: 'graph', label: 'Dependency graph' },
          { id: 'policy', label: 'Policy violations' },
          { id: 'code', label: 'Code findings' },
        ]}
        active={tab}
        onChange={setTab} />

      {tab === 'overview' && (
        <div className="sbom-overview">
          <Card title="Where to start">
            {data.component_rows?.filter((row) => row.findings > 0).length ? (
              <ul className="sbom-top">
                {data.component_rows.filter((row) => row.findings > 0).slice(0, 8).map((row) => (
                  <li key={`${row.name}@${row.version}`}>
                    <button className="sbom-drill"
                      title="Show this component's findings"
                      onClick={() => { setNeedle(row.name); setSeverity(''); setTab('vulnerabilities') }}>
                      <span className="mono">{row.name}</span>
                      <span className="muted mono">{row.version}</span>
                      <span className={`pill ${severityClass(row.worst)}`}
                        title="Worst severity of this component's findings, not a count">
                        {(row.worst || 'unknown').toLowerCase()}
                      </span>
                      <span className="muted">
                        {row.findings} finding{row.findings === 1 ? '' : 's'}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted" style={{ margin: 0 }}>
                No finding is attached to this version yet. An SBOM is an inventory, not a
                verdict: analysing it is what turns components into findings.
              </p>
            )}
          </Card>

          <Card title="Licenses">
            {licenses.length ? (
              <ul className="sbom-licenses">
                {licenses.slice(0, 10).map(([name, count]) => (
                  <li key={name}>
                    <span className="mono">{name}</span>
                    <span className="muted">{count}</span>
                  </li>
                ))}
              </ul>
            ) : <p className="muted" style={{ margin: 0 }}>No license declared in this BOM.</p>}
          </Card>

          <Card title="Imports">
            {data.imports?.length ? (
              <ul className="sbom-imports">
                {data.imports.map((row) => (
                  <li key={row.id}>
                    <span className="pill">{row.source}</span>
                    <span className="mono">{row.filename || 'no filename recorded'}</span>
                    <span className="muted">{row.components_received} components</span>
                    <span className="muted">{relative(row.at)}</span>
                  </li>
                ))}
              </ul>
            ) : <p className="muted" style={{ margin: 0 }}>Components exist without an import row.</p>}
          </Card>
        </div>
      )}

      {tab === 'components' && (
        <Card tight>
          <table className="sbom-components">
            <thead>
              <tr>
                <th>component</th><th>version</th><th>license</th>
                <th>scope</th><th>findings</th><th>worst</th>
              </tr>
            </thead>
            <tbody>
              {(data.component_rows || []).map((row) => (
                <tr key={`${row.purl || row.name}@${row.version}`}>
                  <td className="title mono">{row.name}</td>
                  <td className="mono muted">{row.version}</td>
                  <td className="muted">{row.license || '—'}</td>
                  <td className="muted">{row.direct ? 'direct' : 'transitive'}</td>
                  <td>{row.findings || <span className="muted">0</span>}</td>
                  <td>{row.worst
                    ? <span className={`pill ${severityClass(row.worst)}`}>{row.worst.toLowerCase()}</span>
                    : <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {tab === 'vulnerabilities' && (
        <>
          <div className="sbom-filters">
            <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="">any severity</option>
              {SEVERITIES.map((value) => <option key={value} value={value}>{value.toLowerCase()}</option>)}
            </select>
            <input placeholder="component or CVE" value={needle}
              onChange={(event) => setNeedle(event.target.value)} />
            <span className="muted">
              {vulnerabilities.length} of {(data.vulnerabilities || []).length} shown
            </span>
          </div>
          <Card tight>
            {vulnerabilities.length ? (
              <table className="sbom-vulns">
                <thead>
                  <tr>
                    <th>component</th><th>version</th><th>vulnerability</th>
                    <th>severity</th><th>kev</th><th>analyzer</th>
                    <th>attributed on</th><th>analysis</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerabilities.map((row) => (
                    <tr key={row.finding_id}>
                      <td className="title mono">{row.component || '—'}</td>
                      <td className="mono muted">{row.component_version || '—'}</td>
                      <td className="mono">
                        {row.url ? <a href={row.url} target="_blank" rel="noreferrer">{row.vulnerability}</a>
                          : row.vulnerability || row.title || '—'}
                      </td>
                      <td><span className={`pill ${severityClass(row.severity)}`}>{row.severity.toLowerCase()}</span></td>
                      <td>{row.kev ? <span className="pill sev-critical">KEV</span> : <span className="muted">—</span>}</td>
                      <td className="muted">{row.analyzer}</td>
                      <td className="muted">{relative(row.attributed_on)}</td>
                      <td className="muted">
                        {row.analysis}
                        {row.suppressed ? <span className="pill">suppressed</span> : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="muted" style={{ margin: 0 }}>
                {(data.vulnerabilities || []).length
                  ? 'Nothing matches this filter.'
                  : 'No findings attached to this version yet. Import a BOM and analyse it — an inventory alone has no vulnerabilities.'}
              </p>
            )}
          </Card>
        </>
      )}

      {tab === 'graph' && (
        <Card>
          <EmptyState title="Dependency graph — not built yet"
            hint="The data is already here: version_components carries parent_purl, so the edges exist. What is missing is the drawing — the same force layout the project runtime graph uses, fed by those edges." />
        </Card>
      )}

      {tab === 'policy' && (
        <Card>
          <EmptyState title="Policy violations — no policy engine yet"
            hint="Nothing to evaluate against: the rules that would say “no GPL in production” or “no CRITICAL in a public build” do not exist in this platform. This tab is where they will land." />
        </Card>
      )}

      {tab === 'code' && (
        <Card>
          <EmptyState title="Code findings — not connected yet"
            hint="OpenGrep and gitleaks will report per version, and their findings will read next to the dependency ones: same build, same table, different analyzer." />
        </Card>
      )}
    </div>
  )
}
