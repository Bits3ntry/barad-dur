import React, { useEffect, useState } from 'react'
import { api } from './api'
import { PageHeader } from './ui'

export default function Licenses({ projects }) {
  const [policies, setPolicies] = useState([])
  const [exceptions, setExceptions] = useState([])
  const [form, setForm] = useState({
    name: '', allow_list: '', deny_list: '', unknown_action: 'warn',
    scope_type: 'org', scope_id: '',
  })
  const [evalState, setEvalState] = useState({ project: '', version: '', result: null, error: '' })
  const [exForm, setExForm] = useState({ component_identity: '', license_id: '', reason: '', approved_by: 'console' })
  const [error, setError] = useState('')

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/license-policies').then((r) => setPolicies(r.data)).catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/license-exceptions').then((r) => setExceptions(r.data)).catch(() => {})
  }

  async function createPolicy() {
    try {
      await api.post('/api/v1/license-policies', {
        ...form,
        scope_id: form.scope_type === 'project' ? form.scope_id : undefined,
        actor: 'console',
      })
      setForm((f) => ({ ...f, name: '', allow_list: '', deny_list: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function evaluate() {
    setEvalState((s) => ({ ...s, error: '', result: null }))
    try {
      const { data } = await api.post('/api/v1/license-policies/evaluate', {
        project: evalState.project, version: evalState.version })
      setEvalState((s) => ({ ...s, result: data }))
    } catch (e) {
      setEvalState((s) => ({ ...s, error: String(e.message || e) }))
    }
  }

  async function togglePolicy(policy) {
    const next = policy.status === 'active' ? 'disabled' : 'active'
    await api.post(`/api/v1/license-policies/${policy.id}/status?status=${next}&actor=console`, {})
    load()
  }

  async function createException() {
    try {
      await api.post('/api/v1/license-exceptions', { ...exForm, expires_in_days: 90 })
      setExForm((f) => ({ ...f, component_identity: '', license_id: '', reason: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  const project = projects.find((p) => p.name === evalState.project)
  const counts = evalState.result?.counts

  return (
    <div className="stack">
      <PageHeader title="License compliance" />
      <div className="toolbar">
        <select value={evalState.project}
          onChange={(e) => setEvalState((s) => ({ ...s, project: e.target.value, version: '' }))}>
          <option value="">select project…</option>
          {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
        <select value={evalState.version}
          onChange={(e) => setEvalState((s) => ({ ...s, version: e.target.value }))}
          disabled={!(project?.versions?.length)}>
          {(project?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <button onClick={evaluate} disabled={!evalState.project || !evalState.version}>evaluate licenses</button>
        <span className="count">{policies.length} policies</span>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      {evalState.error && <div className="banner banner-error">{evalState.error}</div>}
      {counts && (
        <>
          <div className="toolbar">
            <span className="pill">policy: {evalState.result.policy?.name || 'none'}</span>
            <span className="pill">{counts.components} components</span>
            <span className={`pill ${counts.denied ? 'sev sev-critical' : ''}`}>{counts.denied} denied</span>
            <span className="pill">{counts.unknown} unknown</span>
            <span className="pill">{counts.excepted} excepted</span>
            <span className="pill">{counts.unlicensed} unlicensed</span>
          </div>
          <table>
            <thead><tr><th>component</th><th>version</th><th>license</th><th>verdict</th><th>reason</th></tr></thead>
            <tbody>
              {evalState.result.results.map((row, index) => (
                <tr key={`${row.identity_key}-${row.license}-${index}`} className={row.verdict === 'denied' ? '' : 'muted-row'}>
                  <td className="title">{row.component || '—'}</td>
                  <td>{row.version || '—'}</td>
                  <td>{row.license || '—'}</td>
                  <td>
                    <span className={`status st-${row.verdict === 'denied' ? 'open' : row.verdict === 'excepted' ? 'acknowledged' : 'resolved'}`}>
                      {row.verdict}
                    </span>
                  </td>
                  <td className="muted">{row.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      <h2 className="section">license policies</h2>
      <table>
        <thead><tr><th>name</th><th>scope</th><th>allow</th><th>deny</th><th>status</th><th></th></tr></thead>
        <tbody>
          {policies.map((p) => (
            <tr key={p.id} className={p.status === 'disabled' ? 'muted-row' : ''}>
              <td className="title">{p.name}</td>
              <td>{p.scope_type}</td>
              <td>{p.allow_list || '—'}</td>
              <td>{p.deny_list || '—'}</td>
              <td><span className={`status st-${p.status}`}>{p.status}</span></td>
              <td><button onClick={() => togglePolicy(p)}>{p.status === 'active' ? 'disable' : 'enable'}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="card">
        <input placeholder="policy name" value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
        <select value={form.scope_type} onChange={(e) => setForm((f) => ({ ...f, scope_type: e.target.value }))}>
          <option value="org">organization-wide</option>
          <option value="project">project-specific</option>
        </select>
        {form.scope_type === 'project' && (
          <select value={form.scope_id} onChange={(e) => setForm((f) => ({ ...f, scope_id: e.target.value }))}>
            <option value="">select project…</option>
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        )}
        <input placeholder="allow list (comma SPDX ids)" value={form.allow_list}
          onChange={(e) => setForm((f) => ({ ...f, allow_list: e.target.value }))} />
        <input placeholder="deny list (comma SPDX ids)" value={form.deny_list}
          onChange={(e) => setForm((f) => ({ ...f, deny_list: e.target.value }))} />
        <select value={form.unknown_action} onChange={(e) => setForm((f) => ({ ...f, unknown_action: e.target.value }))}>
          <option value="warn">unknown: warn</option>
          <option value="allow">unknown: allow</option>
          <option value="deny">unknown: deny</option>
        </select>
        <button onClick={createPolicy}>create policy</button>
      </div>
      <h2 className="section">exceptions</h2>
      <table>
        <thead><tr><th>component identity</th><th>license</th><th>approved by</th><th>expires</th><th>reason</th></tr></thead>
        <tbody>
          {exceptions.map((x) => (
            <tr key={x.id}>
              <td className="muted">{x.component_identity}</td>
              <td>{x.license_id}</td>
              <td>{x.approved_by}</td>
              <td>{x.expires_at ? new Date(x.expires_at).toLocaleDateString() : 'never'}</td>
              <td>{x.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="toolbar">
        <input placeholder="component identity key" value={exForm.component_identity}
          onChange={(e) => setExForm((f) => ({ ...f, component_identity: e.target.value }))} />
        <input placeholder="license id" value={exForm.license_id}
          onChange={(e) => setExForm((f) => ({ ...f, license_id: e.target.value }))} />
        <input placeholder="reason" value={exForm.reason}
          onChange={(e) => setExForm((f) => ({ ...f, reason: e.target.value }))} />
        <input placeholder="approved_by" value={exForm.approved_by}
          onChange={(e) => setExForm((f) => ({ ...f, approved_by: e.target.value }))} />
        <button onClick={createException}>create exception</button>
      </div>
      {!policies.length && !error && <p className="empty">No license policies yet.</p>}
    </div>
  )
}
