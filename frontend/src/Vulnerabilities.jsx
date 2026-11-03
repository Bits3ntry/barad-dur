import React, { useEffect, useState } from 'react'
import { api } from './api'
import { EmptyState, ErrorBanner, PageHeader, SeverityBadge, Table } from './ui'

/* Vulnerabilities is an aggregate over findings this organization actually has,
   not a catalog browser. Every number links back to concrete finding ids, and
   anything v0 cannot know (version ranges, exploit availability) says unknown
   with the reason instead of rendering a zero. */

const EMPTY_FILTERS = { q: '', severity: '', kev: false, project: '' }

function EnrichmentCell({ enrichment }) {
  const kev = enrichment.kev
  const epss = enrichment.epss
  return (
    <div className="stack" style={{ gap: 2 }}>
      <span className={kev.listed ? 'sev sev-high' : 'muted'}>
        {kev.listed ? `KEV · added ${kev.date_added || 'date unknown'}` : 'KEV not listed'}
      </span>
      <span className="muted" style={{ fontSize: 11.5 }}>
        {epss.known
          ? `EPSS ${Math.round(Number(epss.score) * 100)}%ile ${epss.percentile}`
          : 'EPSS unknown'}
      </span>
      <span className="muted" style={{ fontSize: 11.5 }}>
        {commissioned(kev, epss)}
      </span>
    </div>
  )
}

function commissioned(kev, epss) {
  if (!kev.known && !epss.known) return 'no enrichment source connected'
  const stamp = kev.known ? kev.fetched_at : epss.fetched_at
  return stamp ? `enriched ${new Date(stamp).toLocaleDateString()}` : 'enrichment date unknown'
}

export default function Vulnerabilities({ onNavigate }) {
  const [filters, setFilters] = useState({ ...EMPTY_FILTERS })
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [projects, setProjects] = useState([])
  const [openCve, setOpenCve] = useState('')
  const [detail, setDetail] = useState(null)
  const [selected, setSelected] = useState([])
  const [preview, setPreview] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => { load() }, [])
  useEffect(() => {
    api.get('/api/v1/projects').then((r) => setProjects(r.data || [])).catch(() => setProjects([]))
  }, [])

  function load() {
    const params = new URLSearchParams()
    if (filters.q.trim()) params.set('q', filters.q.trim())
    if (filters.severity) params.set('severity', filters.severity)
    if (filters.kev) params.set('kev_only', 'true')
    if (filters.project) params.set('project', filters.project)
    api.get(`/api/v1/vulnerabilities${params.toString() ? '?' + params : ''}`)
      .then((r) => { setRows(r.data || []); setTotal(r.total || 0) })
      .catch((e) => setError(String(e.message || e)))
  }

  async function toggle(cveId) {
    setPreview(null)
    setSelected([])
    if (openCve === cveId) { setOpenCve(''); setDetail(null); return }
    setOpenCve(cveId)
    try {
      const { data } = await api.get(`/api/v1/vulnerabilities/${encodeURIComponent(cveId)}`)
      setDetail(data)
      setSelected(data.findings_detail
        .filter((row) => row.status !== 'resolved').map((row) => row.id))
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function previewBulk() {
    if (!detail || !selected.length) return
    setBusy(true)
    try {
      const result = await api.post(
        `/api/v1/vulnerabilities/${encodeURIComponent(detail.cve_id)}/bulk-preview`,
        { finding_ids: selected, status: 'resolved' })
      setPreview(result.data)
    } catch (e) {
      setError(String(e.message || e))
    }
    setBusy(false)
  }

  async function applyBulk() {
    if (!detail || !preview) return
    setBusy(true)
    try {
      const result = await api.post(
        `/api/v1/vulnerabilities/${encodeURIComponent(detail.cve_id)}/bulk-status?actor=console`,
        { finding_ids: selected, status: 'resolved' })
      setNotice(`${result.data.changed} finding(s) resolved on ${detail.cve_id}`
        + (result.data.skipped.length ? `, ${result.data.skipped.length} skipped` : ''))
      setPreview(null)
      setSelected([])
      setDetail(null)
      setOpenCve('')
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
    setBusy(false)
  }

  return (
    <div className="stack">
      <PageHeader
        title="Vulnerabilities"
        subtitle={`${total} CVE${total === 1 ? '' : 's'} affecting this inventory · grouped from findings, never from the catalog`}
      />

      <div className="toolbar">
        <input placeholder="search CVE id…" value={filters.q}
          onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && load()} />
        <select value={filters.severity}
          onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}>
          <option value="">any severity</option>
          <option value="CRITICAL">critical</option>
          <option value="HIGH">high</option>
          <option value="MEDIUM">medium</option>
          <option value="LOW">low</option>
          <option value="UNKNOWN">unknown</option>
        </select>
        <select value={filters.project}
          onChange={(e) => setFilters((f) => ({ ...f, project: e.target.value }))}>
          <option value="">every project</option>
          {projects.map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}
        </select>
        <label className="check">
          <input type="checkbox" checked={filters.kev}
            onChange={(e) => setFilters((f) => ({ ...f, kev: e.target.checked }))} />
          <span>KEV only</span>
        </label>
        <button onClick={load}>apply</button>
      </div>

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {rows.length ? (
        <Table head={['CVE', 'severity', 'priority', 'findings', 'assets', 'projects', 'enrichment', '']}>
          {rows.map((row) => (
            <React.Fragment key={row.cve_id}>
              <tr className={openCve === row.cve_id ? 'selected' : ''}>
                <td className="title mono">{row.cve_id}
                  {row.title && (
                    <div className="muted" style={{ fontSize: 11.5 }}>{row.title}</div>
                  )}
                </td>
                <td><SeverityBadge severity={row.severity} /></td>
                <td>{row.priority || <span className="muted">unclassified</span>}</td>
                <td>
                  {row.findings}
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {row.open_findings} open
                  </div>
                </td>
                <td>
                  {row.assets.count}
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {row.assets.coverage === 'complete' ? 'linked' : 'no linked asset'}
                  </div>
                </td>
                <td className="muted">
                  {row.projects.map((p) => p.slug).join(', ') || '—'}
                </td>
                <td><EnrichmentCell enrichment={row.enrichment} /></td>
                <td>
                  <button className="mini" onClick={() => toggle(row.cve_id)}>
                    {openCve === row.cve_id ? 'hide' : 'open'}
                  </button>
                </td>
              </tr>
              {openCve === row.cve_id && detail && (
                <tr className="detail-row"><td colSpan={8}>
                  <div className="detail">
                    <dl>
                      <dt>findings behind this CVE</dt>
                      <dd>
                        <Table head={['', 'finding', 'project', 'version', 'component', 'severity', 'status', 'assignee']}>
                          {detail.findings_detail.map((finding) => (
                            <tr key={finding.id}>
                              <td>
                                <input type="checkbox"
                                  checked={selected.includes(finding.id)}
                                  disabled={finding.status === 'suppressed'}
                                  onChange={(e) => setSelected((current) => (
                                    e.target.checked
                                      ? [...current, finding.id]
                                      : current.filter((id) => id !== finding.id)
                                  ))} />
                              </td>
                              <td className="mono">{finding.id.slice(0, 8)}</td>
                              <td>{finding.project || '—'}</td>
                              <td>{finding.version || <span className="muted">unknown</span>}</td>
                              <td className="mono muted">{finding.component || '—'}</td>
                              <td><SeverityBadge severity={finding.severity} /></td>
                              <td>
                                <span className={finding.status === 'open' ? 'pill' : 'muted'}>
                                  {finding.status}
                                </span>
                              </td>
                              <td className="muted">{finding.assignee || 'unassigned'}</td>
                            </tr>
                          ))}
                        </Table>
                        {onNavigate && (
                          <button className="mini"
                            onClick={() => onNavigate('findings')}>
                            open the global findings list
                          </button>
                        )}
                      </dd>
                      <dt>versions</dt>
                      <dd className="muted">
                        {detail.versions_known
                          ? `affected ${detail.affected_versions.join(', ') || '—'}`
                            + ` · fixed ${detail.fixed_versions.join(', ') || '—'}`
                          : detail.versions_reason}
                      </dd>
                      <dt>grouped action</dt>
                      <dd>
                        <div className="row">
                          <button className="mini" disabled={!selected.length || busy}
                            onClick={previewBulk}>
                            preview resolve {selected.length} finding(s)
                          </button>
                          {preview && (
                            <button className="mini" disabled={busy || !preview.would_change}
                              onClick={applyBulk}>
                              apply to {preview.would_change}
                            </button>
                          )}
                        </div>
                        {preview && (
                          <div className="muted" style={{ marginTop: 6 }}>
                            would change {preview.would_change} · unchanged {preview.unchanged}
                            {' · '}skipped {preview.skipped.length}
                            {preview.skipped.map((row) => (
                              <div key={row.finding_id} className="occ-row">
                                {row.finding_id.slice(0, 8)}: {row.reason}
                              </div>
                            ))}
                            <div>{preview.requires}</div>
                          </div>
                        )}
                      </dd>
                    </dl>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </Table>
      ) : (
        !error && <EmptyState title="No CVE affects this inventory yet"
          hint="This list fills from findings that carry an advisory. Importing an SBOM alone does not create CVEs — run the analysis that matches a version against advisories." />
      )}
    </div>
  )
}
