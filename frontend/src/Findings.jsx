import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Dialog, EmptyState, ErrorBanner, Input, Loading, PageHeader, Pager,
         Table, Drawer, Tabs, StatusBadge, serverPager } from './ui'
import { VexSection } from './Vex'

const tabs = [
  { id: 'overview', label: 'Overview' },
  { id: 'occurrences', label: 'Occurrences' },
  { id: 'history', label: 'History' },
  { id: 'remediation', label: 'Remediation' },
  { id: 'related', label: 'Related' },
]

function Occurrences({ occurrences }) {
  if (!occurrences) return null
  return (
    <dl>
      <dt>occurrences ({occurrences.length})</dt>
      <dd>
        {occurrences.length === 0 && <span className="muted">no sightings recorded yet</span>}
        {occurrences.map((o) => (
          <div key={o.id} className="occ-row">
            {new Date(o.seen_at).toLocaleString()} · tool {o.tool || '—'} ·
            source {o.source || '—'} · version {o.project_version_id ? o.project_version_id.slice(0, 8) : '—'}
            {o.ci_run_id && <> · <a href={`#ci-run-${o.ci_run_id}`}>CI run {o.ci_run_id.slice(0, 8)}</a></>}
            {o.evidence && <div className="muted">{o.evidence}</div>}
          </div>
        ))}
      </dd>
    </dl>
  )
}

function slaCell(deadline) {
  if (!deadline) return <span className="muted">no policy</span>
  const days = Math.floor((new Date(deadline) - new Date()) / 86400000)
  const cls = days < 0 ? 'sev-critical' : days <= 2 ? 'sev-high' : 'muted'
  return <span className={cls}>{days < 0 ? `${-days}d overdue` : `${days}d left`}</span>
}

const PER_PAGE = 25

export default function Findings({ projects, focusId, onOpenAnalysis }) {
  const [state, setState] = useState({
    rows: [], total: 0, error: '', loading: false,
    project: '', version: '', includeSuppressed: false, kind: '',
    detail: null, history: [], assignee: '',
  })
  const [bump, setBump] = useState(0)
  const [createOpen, setCreateOpen] = useState(false)
  const [createError, setCreateError] = useState('')
  const [draft, setDraft] = useState({
    kind: 'code-weakness', title: '', severity: 'HIGH', path: '', line: '',
    cwe: '', impact: '', recommendation: '', reproduction: '', assignee: '',
  })
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('overview')
  const [offset, setOffset] = useState(0)
  const pager = serverPager(state.total, PER_PAGE, offset, setOffset)

  // Deep link from the analysis viewer (#findings::<id>): open that drawer once
  // the row exists in the list.
  useEffect(() => {
    if (!focusId || !state.rows.length) return
    const row = state.rows.find((item) => item.id === focusId)
    if (row && state.detail?.id !== focusId) openDetail(row)
  }, [focusId, state.rows.length])

  useEffect(() => {
    if (!projects.length) return
    if (!state.project) {
      setState((s) => ({ ...s, project: projects[0].name }))
      return
    }
    if (!state.version && projects[0].versions?.length) {
      setState((s) => ({ ...s, version: projects[0].versions[0] }))
    }
  }, [projects])

  // A filter is a new question, so it starts on the first page; changing page
  // keeps the question. The reset keys off the filters themselves, because a
  // page change is also an offset change and must not snap back to page one.
  const filters = `${state.project}|${state.version}|${state.kind}|${state.includeSuppressed}|${bump}`
  const lastFilters = React.useRef(filters)

  // Ordering is the platform's: the list is paginated, and a sort applied to the
  // page would only reorder the slice it can see.
  useEffect(() => {
    if (lastFilters.current !== filters) {
      lastFilters.current = filters
      if (offset !== 0) { setOffset(0); return }
    }
    const params = new URLSearchParams()
    if (state.project) params.set('project', state.project)
    if (state.version) params.set('version', state.version)
    if (state.kind) params.set('kind', state.kind)
    if (state.includeSuppressed) params.set('include_suppressed', 'true')
    params.set('sort', 'severity')
    params.set('limit', PER_PAGE)
    params.set('offset', offset)
    setState((s) => ({ ...s, loading: true, error: '' }))
    api.get(`/api/v1/findings?${params.toString()}`)
      .then((data) => setState((s) => ({ ...s, rows: data.data, total: data.total, loading: false })))
      .catch((error) => setState((s) => ({ ...s, loading: false, error: String(error.message || error) })))
  }, [filters, offset])

  const project = projects.find((p) => p.name === state.project)

  async function openDetail(finding) {
    if (state.detail?.id === finding.id) {
      setState((s) => ({ ...s, detail: null }))
      setDrawerOpen(false)
      setJiraOpen(false)
      setJiraResult('')
      return
    }
    setDrawerOpen(true)
    setJiraOpen(false)
    setJiraResult('')
    try {
      const { data } = await api.get(`/api/v1/findings/${finding.id}`)
      const enriched = { ...data }
      if (data.cve_id) {
        const [kev, epss] = await Promise.all([
          api.get(`/api/v1/intel/kev/${data.cve_id}`).catch(() => null),
          api.get(`/api/v1/intel/epss/${data.cve_id}`).catch(() => null),
        ])
        if (kev?.known_exploited) enriched.kev = kev.data
        if (epss?.data) enriched.epss = epss.data
      }
      // Occurrence history (BL-040) rides the same detail fetch.
      try {
        enriched.occurrences =
          (await api.get(`/api/v1/findings/${finding.id}/occurrences`)).data
      } catch { /* report only the primary failure */ }
      let history = []
      try {
        history = (await api.get(`/api/v1/findings/${finding.id}/history`)).data
      } catch { /* the timeline is additive; the detail still renders */ }
      setState((s) => ({ ...s, detail: enriched, history,
        assignee: enriched.assignee || '' }))
    } catch (error) {
      setState((s) => ({ ...s, error: String(error.message || error) }))
    }
  }

  async function assign(row) {
    try {
      await api.patch(`/api/v1/findings/${row.id}/assignee`,
        { assignee: state.assignee.trim(), actor: 'console' })
      setBump((n) => n + 1)
      openDetail(row)
    } catch (error) {
      setState((s) => ({ ...s, error: String(error.message || error) }))
    }
  }

  async function createTask(row) {
    const title = state.taskTitle?.trim()
    if (!title) return
    const task = (await api.post('/api/v1/remediation/tasks', { title, actor: 'console' })).data
    await api.post(`/api/v1/remediation/tasks/${task.id}/findings`,
      { finding_id: row.id, actor: 'console' })
    setState((s) => ({ ...s, taskTitle: '' }))
    setBump((n) => n + 1)
  }

  const [jiraKey, setJiraKey] = useState('')
  const [jiraOpen, setJiraOpen] = useState(false)
  const [jiraResult, setJiraResult] = useState('')

  async function linkJira(row) {
    setJiraKey('')
    setJiraResult('')
    setJiraOpen(true)
  }

  async function confirmLinkJira() {
    const projectKey = jiraKey.trim()
    if (!projectKey) { setJiraResult('Project key is required.'); return }
    try {
      const result = await api.post('/api/v1/jira/links',
        { finding_id: state.detail?.id, project_key: projectKey, actor: 'console' })
      setJiraResult(result.data?.issue_key || 'queued (Jira not configured)')
      setJiraKey('')
      setJiraOpen(false)
    } catch (e) {
      setJiraResult(String(e.message || e))
    }
  }

  const [disposeReason, setDisposeReason] = useState('')
  const [disposeOpen, setDisposeOpen] = useState(false)
  const [disposeStatus, setDisposeStatus] = useState('')

  async function dispose(status) {
    setDisposeStatus(status)
    setDisposeReason('')
    setDisposeOpen(true)
  }

  async function confirmDispose() {
    const status = disposeStatus
    const reason = disposeReason.trim()
    try {
      await api.patch(`/api/v1/findings/${state.detail?.id}/status`,
        { status, reason: reason || 'console action', actor: 'console' })
      setState((s) => ({ ...s, detail: null }))
      setBump((n) => n + 1)
      setDisposeOpen(false)
      setDisposeReason('')
    } catch (error) {
      setState((s) => ({ ...s, error: String(error.message || error) }))
    }
  }

  async function createFinding() {
    setCreateError('')
    try {
      await api.post('/api/v1/findings', {
        project: state.project,
        kind: draft.kind,
        title: draft.title.trim(),
        severity: draft.severity,
        path: draft.path.trim() || undefined,
        line: draft.line ? Number(draft.line) : undefined,
        cwe: draft.cwe.trim() || undefined,
        impact: draft.impact.trim() || undefined,
        recommendation: draft.recommendation.trim() || undefined,
        reproduction: draft.reproduction.trim() || undefined,
        assignee: draft.assignee.trim() || undefined,
        actor: 'console',
      })
      setCreateOpen(false)
      setDraft({ kind: 'code-weakness', title: '', severity: 'HIGH', path: '', line: '',
        cwe: '', impact: '', recommendation: '', reproduction: '', assignee: '' })
      setBump((n) => n + 1)
    } catch (error) {
      setCreateError(String(error.message || error))
    }
  }

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle={state.error
          ? 'not loaded — the server rejected the request'
          : `${state.total} ${state.total === 1 ? 'finding' : 'findings'} in scope`}
        actions={(
          <div className="row">
            <button onClick={() => setBump((n) => n + 1)}>refresh</button>
            <button className="primary-action" onClick={() => setCreateOpen(true)}>new finding</button>
          </div>
        )}
      />
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <select value={state.project} onChange={(e) => setState((s) => ({ ...s, project: e.target.value, version: '' }))}>
          {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
        <select
          value={state.version}
          onChange={(e) => setState((s) => ({ ...s, version: e.target.value }))}
          disabled={!(project?.versions?.length)}
        >
          {(project?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <select value={state.kind} onChange={(e) => setState((s) => ({ ...s, kind: e.target.value }))}>
          <option value="">all kinds</option>
          <option value="vulnerability">vulnerability</option>
          <option value="secret">secret</option>
          <option value="misconfiguration">misconfiguration</option>
          <option value="code-weakness">code-weakness</option>
        </select>
        <label className="check">
          <input
            type="checkbox"
            checked={state.includeSuppressed}
            onChange={(e) => setState((s) => ({ ...s, includeSuppressed: e.target.checked }))}
          />
          include suppressed
        </label>
        <span className="row-end">
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit="findings" />
        </span>
      </div>
      {state.error && <ErrorBanner error={state.error} onRetry={() => setBump((n) => n + 1)} />}
      {state.loading && !state.rows.length && <Loading rows={6} />}
      <Table head={['prio', 'sev', 'kind', 'title', 'rule / cve', 'path', 'sla', 'status']}
        empty={!state.loading && !state.error && (
          <EmptyState title="No findings for this selection"
            hint="Widen the filters, or ingest a scan to produce findings." />
        )}>
          {state.rows.map((row) => (
            <React.Fragment key={row.id}>
              <tr className={state.detail?.id === row.id ? 'selected' : ''} onClick={() => openDetail(row)}>
                <td><span className={`prio prio-${(row.priority || 'p3').toLowerCase()}`}>{row.priority || 'P3'}</span></td>
                <td><span className={`sev sev-${(row.severity || 'NONE').toLowerCase()}`}>{row.severity || '—'}</span></td>
                <td>{row.kind}</td>
                <td className="title">{row.title}</td>
                <td>{row.cve_id || row.rule_id || row.source_id || '—'}</td>
                <td>{row.path || row.component_purl || '—'}</td>
                <td>{slaCell(row.sla_deadline)}</td>
                <td><span className={`status st-${row.status}`}>{row.status}</span></td>
              </tr>
              {state.detail?.id === row.id && (
                <tr className="detail-row"><td colSpan={8}>
                  <Drawer open={drawerOpen} title={row.title} onClose={() => setDrawerOpen(false)}>
                    {state.detail && (
                      <>
                        <Tabs tabs={tabs} active={activeTab} onChange={setActiveTab} />
                        <div className="detail">
                          {activeTab === 'overview' && (
                            <>
                              <dl>
                                <dt>source</dt><dd>{state.detail.source_id || row.source} {state.detail.cve_id ? `(alias ${state.detail.cve_id})` : ''}</dd>
                                <dt>tool</dt><dd>{state.detail.tool || '—'}</dd>
                                <dt>location</dt><dd>{state.detail.path || '—'}{state.detail.line ? `:${state.detail.line}` : ''}</dd>
                                <dt>component</dt><dd>{state.detail.component_purl || '—'}</dd>
                                <dt>owner</dt>
                                <dd>
                                  {state.detail.assignee || <span className="muted">unassigned</span>}
                                  {' '}
                                  <input placeholder="assign to…" value={state.assignee}
                                    onChange={(e) => setState((s) => ({ ...s, assignee: e.target.value }))} />
                                  {' '}
                                  <button className="mini" onClick={() => assign(row)}>assign</button>
                                </dd>
                                <dt>cwe</dt><dd>{state.detail.cwe || '—'}</dd>
                                <dt>impact</dt><dd>{state.detail.impact || '—'}</dd>
                                <dt>reproduction</dt><dd>{state.detail.reproduction || '—'}</dd>
                                <dt>recommendation</dt><dd>{state.detail.recommendation || '—'}</dd>
                                <dt>detail</dt><dd>{state.detail.detail || '—'}</dd>
                                <dt>reason</dt><dd>{state.detail.status_reason || '—'}</dd>
                                <dt>priority</dt><dd>{state.detail.priority || 'P3'} — {state.detail.priority_reason || 'severity fallback'}</dd>
                                <dt>sla</dt><dd>{slaCell(state.detail.sla_deadline)}</dd>
                                <dt>url</dt><dd>{state.detail.source_url && <a href={state.detail.source_url} target="_blank" rel="noreferrer">{state.detail.source_url}</a>}</dd>
                              </dl>
                              {state.detail.kev
                                ? <span className="sev sev-critical">CISA KEV — exploited in the wild (since {state.detail.kev.date_added})</span>
                                : <span className="muted">not in KEV</span>}
                              {state.detail.epss && <span className="pill">EPSS {state.detail.epss.epss}</span>}
                              <VexSection findingId={row.id} />
                              <div className="bar">
                                <input placeholder="remediation task title (creates + links)"
                                  value={state.taskTitle || ''}
                                  onChange={(e) => setState((s) => ({ ...s, taskTitle: e.target.value }))} />
                                <button onClick={() => createTask(row)}>create task</button>
                              </div>
                            </>
                          )}
                          {activeTab === 'occurrences' && <Occurrences occurrences={state.detail.occurrences} />}
                          {activeTab === 'history' && (
                            state.history.length ? (
                              <div className="stack">
                                {state.history.map((event) => (
                                  <div key={event.ref} className="occ-row">
                                    <span className="muted">
                                      {new Date(event.at).toLocaleString()}
                                    </span>
                                    {' · '}
                                    <strong>{event.action}</strong>
                                    {' · '}
                                    {event.actor || 'system'}
                                    {event.detail && (
                                      <div className="muted" style={{ fontSize: 11.5 }}>
                                        {event.detail}
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <span className="muted">
                                nothing has happened to this finding yet
                              </span>
                            )
                          )}
                          {activeTab === 'remediation' && (
                            <div className="bar">
                              {state.detail.status !== 'open' && <button className="mini" onClick={() => dispose('open')}>reopen</button>}
                              <button className="mini btn-danger" onClick={() => dispose('resolved')}>mark resolved</button>
                              <button className="mini btn-danger" onClick={() => dispose('acknowledged')}>acknowledge</button>
                            </div>
                          )}
                          {state.detail.analysis_run && (
                            <p className="muted" style={{ marginTop: 8 }}>
                              last evaluated by {state.detail.analysis_run.tool}{' '}
                              {state.detail.analysis_run.revision
                                ? `@ ${state.detail.analysis_run.revision.slice(0, 10)}` : ''}
                              {state.detail.analysis_run.branch
                                ? ` on ${state.detail.analysis_run.branch}` : ''}
                              {state.detail.analysis_run.pull_request
                                ? ` · PR ${state.detail.analysis_run.pull_request}` : ''}
                              {' '}
                              <button className="mini" onClick={() => onOpenAnalysis?.({
                                runId: state.detail.analysis_run.id,
                                path: state.detail.path,
                                line: state.detail.line,
                              })}>open in analysis</button>
                            </p>
                          )}
                          {activeTab === 'related' && (
                            <div className="detail">
                              <p className="muted">Jira link: <button className="mini" onClick={() => setJiraOpen(true)}>link</button></p>
                              {jiraResult && <p className={`muted ${jiraResult.startsWith('queued') ? 'ok' : 'error'}`}>{jiraResult}</p>}
                            </div>
                          )}
                          <Dialog open={jiraOpen} title="Link finding to Jira"
                            onClose={() => setJiraOpen(false)}
                            confirmLabel="Link" onConfirm={confirmLinkJira}>
                            <Input label="Jira project key (e.g. SEC)" value={jiraKey}
                              onChange={(v) => setJiraKey(v)} placeholder="SEC" />
                          </Dialog>
                        </div>
                      </>
                    )}
                  </Drawer>
                </td></tr>
              )}
            </React.Fragment>
          ))}
      </Table>
      {pager.pages > 1 && (
        <div className="row row-end" style={{ marginTop: 10 }}>
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit="findings" />
        </div>
      )}

      <Dialog open={createOpen} title="Record a finding"
        onClose={() => setCreateOpen(false)} confirmLabel="create"
        onConfirm={createFinding} size="normal">
        {createError && <ErrorBanner error={createError} />}
        <Input label="Title" value={draft.title}
          onChange={(v) => setDraft((d) => ({ ...d, title: v }))}
          placeholder="IDOR on invoice export" />
        <div className="row">
          <label className="field">
            <span>Kind</span>
            <select value={draft.kind}
              onChange={(e) => setDraft((d) => ({ ...d, kind: e.target.value }))}>
              <option value="code-weakness">code weakness</option>
              <option value="misconfiguration">misconfiguration</option>
              <option value="secret">secret</option>
            </select>
          </label>
          <label className="field">
            <span>Severity</span>
            <select value={draft.severity}
              onChange={(e) => setDraft((d) => ({ ...d, severity: e.target.value }))}>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((v) => <option key={v}>{v}</option>)}
            </select>
          </label>
        </div>
        <div className="row">
          <Input label="Path" value={draft.path}
            onChange={(v) => setDraft((d) => ({ ...d, path: v }))} placeholder="app/api/invoices.py" />
          <Input label="Line" value={draft.line}
            onChange={(v) => setDraft((d) => ({ ...d, line: v }))} placeholder="42" />
          <Input label="CWE" value={draft.cwe}
            onChange={(v) => setDraft((d) => ({ ...d, cwe: v }))} placeholder="CWE-639" />
        </div>
        <Input label="Impact" value={draft.impact}
          onChange={(v) => setDraft((d) => ({ ...d, impact: v }))}
          placeholder="one tenant can read another tenant's invoices" />
        <Input label="Reproduction" value={draft.reproduction}
          onChange={(v) => setDraft((d) => ({ ...d, reproduction: v }))}
          placeholder="GET /invoices/123 with another tenant session" />
        <Input label="Recommendation" value={draft.recommendation}
          onChange={(v) => setDraft((d) => ({ ...d, recommendation: v }))}
          placeholder="authorize by tenant before serializing" />
        <Input label="Assignee" value={draft.assignee}
          onChange={(v) => setDraft((d) => ({ ...d, assignee: v }))} placeholder="ana@bitsentry.xyz" />
        <p className="muted" style={{ margin: 0 }}>
          A finding without a CVE stays in Findings; it never invents an advisory.
        </p>
      </Dialog>
    </div>
  )
}
