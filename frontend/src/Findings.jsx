import React, { useEffect, useState } from 'react'
import { api } from './api'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', null]

export default function Findings({ projects }) {
  const [state, setState] = useState({
    rows: [], total: 0, error: '', loading: false,
    project: '', version: '', includeSuppressed: false, kind: '',
    detail: null,
  })
  const [bump, setBump] = useState(0)

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

  useEffect(() => {
    const params = new URLSearchParams()
    if (state.project) params.set('project', state.project)
    if (state.version) params.set('version', state.version)
    if (state.kind) params.set('kind', state.kind)
    if (state.includeSuppressed) params.set('include_suppressed', 'true')
    const query = params.toString() ? `?${params.toString()}` : ''
    setState((s) => ({ ...s, loading: true, error: '' }))
    api.get(`/api/v1/findings${query}`)
      .then((data) => setState((s) => ({ ...s, rows: data.data, total: data.total, loading: false })))
      .catch((error) => setState((s) => ({ ...s, loading: false, error: String(error.message || error) })))
  }, [state.project, state.version, state.kind, state.includeSuppressed, bump])

  const project = projects.find((p) => p.name === state.project)

  async function openDetail(finding) {
    if (state.detail?.id === finding.id) {
      setState((s) => ({ ...s, detail: null }))
      return
    }
    try {
      const { data } = await api.get(`/api/v1/findings/${finding.id}`)
      setState((s) => ({ ...s, detail: data }))
    } catch (error) {
      setState((s) => ({ ...s, error: String(error.message || error) }))
    }
  }

  async function dispose(status) {
    const { id } = state.detail
    try {
      const reason = window.prompt(`Reason for ${status}:`) || ''
      await api.patch(`/api/v1/findings/${id}/status`, { status, reason, actor: 'console' })
      setState((s) => ({ ...s, detail: null }))
      setBump((n) => n + 1)
    } catch (error) {
      setState((s) => ({ ...s, error: String(error.message || error) }))
    }
  }

  return (
    <div>
      <div className="bar">
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
        <span className="count">{state.loading ? 'loading…' : `${state.total} findings`}</span>
        <button onClick={() => setBump((n) => n + 1)}>refresh</button>
      </div>
      {state.error && <p className="error">{state.error}</p>}
      <table>
        <thead>
          <tr><th>sev</th><th>kind</th><th>title</th><th>rule / cve</th><th>path</th><th>status</th></tr>
        </thead>
        <tbody>
          {[...state.rows].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)).map((row) => (
            <React.Fragment key={row.id}>
              <tr className={state.detail?.id === row.id ? 'selected' : ''} onClick={() => openDetail(row)}>
                <td><span className={`sev sev-${(row.severity || 'NONE').toLowerCase()}`}>{row.severity || '—'}</span></td>
                <td>{row.kind}</td>
                <td className="title">{row.title}</td>
                <td>{row.cve_id || row.rule_id || row.source_id || '—'}</td>
                <td>{row.path || row.component_purl || '—'}</td>
                <td><span className={`status st-${row.status}`}>{row.status}</span></td>
              </tr>
              {state.detail?.id === row.id && (
                <tr className="detail-row"><td colSpan={6}>
                  <div className="detail">
                    <dl>
                      <dt>source</dt><dd>{state.detail.source_id || row.source} {state.detail.cve_id ? `(alias ${state.detail.cve_id})` : ''}</dd>
                      <dt>tool</dt><dd>{state.detail.tool || '—'}</dd>
                      <dt>location</dt><dd>{state.detail.path || '—'}{state.detail.line ? `:${state.detail.line}` : ''}</dd>
                      <dt>component</dt><dd>{state.detail.component_purl || '—'}</dd>
                      <dt>detail</dt><dd>{state.detail.detail || '—'}</dd>
                      <dt>reason</dt><dd>{state.detail.status_reason || '—'}</dd>
                      <dt>url</dt><dd>{state.detail.source_url && <a href={state.detail.source_url} target="_blank" rel="noreferrer">{state.detail.source_url}</a>}</dd>
                    </dl>
                    <div className="actions">
                      <button onClick={() => dispose('acknowledged')}>acknowledge</button>
                      <button onClick={() => dispose('resolved')}>mark resolved</button>
                      {state.detail.status !== 'open' && <button onClick={() => dispose('open')}>reopen</button>}
                    </div>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      {!state.rows.length && !state.loading && !state.error && <p className="empty">No findings for this selection.</p>}
    </div>
  )
}
