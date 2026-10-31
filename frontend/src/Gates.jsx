import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function Gates({ projects }) {
  const [policies, setPolicies] = useState([])
  const [form, setForm] = useState({
    name: '', scope_type: 'org', scope_id: '', max_severity: 'HIGH',
    block_kev: false, block_license_denied: false,
  })
  const [evalState, setEvalState] = useState({ project: '', version: '', result: null, error: '' })
  const [error, setError] = useState('')

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/gate-policies').then((r) => setPolicies(r.data)).catch((e) => setError(String(e.message || e)))
  }

  async function create() {
    try {
      await api.post('/api/v1/gate-policies', {
        ...form,
        scope_id: form.scope_type === 'project' ? form.scope_id : undefined,
        actor: 'console',
      })
      setForm((f) => ({ ...f, name: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function evaluate() {
    setEvalState((s) => ({ ...s, error: '', result: null }))
    try {
      const body = { project: evalState.project }
      if (evalState.version) body.version = evalState.version
      const { data } = await api.post('/api/v1/gates/evaluate', body)
      setEvalState((s) => ({ ...s, result: data }))
    } catch (e) {
      setEvalState((s) => ({ ...s, error: String(e.message || e) }))
    }
  }

  const project = projects.find((p) => p.name === evalState.project)
  const result = evalState.result

  return (
    <div>
      <div className="bar">
        <select value={evalState.project}
          onChange={(e) => setEvalState((s) => ({ ...s, project: e.target.value, version: '' }))}>
          <option value="">select project…</option>
          {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
        <select value={evalState.version}
          onChange={(e) => setEvalState((s) => ({ ...s, version: e.target.value }))}
          disabled={!(project?.versions?.length)}>
          <option value="">all versions</option>
          {(project?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <button onClick={evaluate} disabled={!evalState.project}>evaluate gate</button>
        <span className="count">{policies.length} gate policies</span>
      </div>
      {error && <p className="error">{error}</p>}
      {evalState.error && <p className="error">{evalState.error}</p>}
      {result && (
        <>
          <div className="bar">
            <span className={`pill ${result.verdict === 'fail' ? 'sev sev-critical' : 'ok'}`}>
              verdict: {result.verdict}
            </span>
            <span className="pill">policy: {result.policy?.name || 'default (HIGH)'}</span>
            <span className="pill">policy v{result.policy_version}</span>
          </div>
          <table>
            <thead><tr><th>rule</th><th>status</th><th>detail</th><th>findings</th></tr></thead>
            <tbody>
              {result.rules.map((rule) => (
                <tr key={rule.rule}>
                  <td className="title">{rule.rule}</td>
                  <td><span className={rule.status === 'fail' ? 'sev sev-critical' : 'ok'}>{rule.status}</span></td>
                  <td>{rule.detail}</td>
                  <td className="muted">
                    {(rule.findings || []).slice(0, 4).map((f, index) => (
                      <div key={`${rule.rule}-${index}`}>
                        {f.title || f.component} {f.severity ? `(${f.severity})` : ''} {f.license ? `— ${f.license}` : ''}
                      </div>
                    ))}
                    {(rule.findings || []).length > 4 && <div>… {rule.findings.length - 4} more</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      <h2 className="section">gate policies</h2>
      <table>
        <thead><tr><th>name</th><th>scope</th><th>max severity</th><th>KEV block</th><th>license block</th><th>status</th></tr></thead>
        <tbody>
          {policies.map((p) => (
            <tr key={p.id}>
              <td className="title">{p.name}</td>
              <td>{p.scope_type}</td>
              <td>{p.max_severity}</td>
              <td>{p.block_kev ? 'yes' : 'no'}</td>
              <td>{p.block_license_denied ? 'yes' : 'no'}</td>
              <td><span className={`status st-${p.status}`}>{p.status}</span></td>
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
        <select value={form.max_severity} onChange={(e) => setForm((f) => ({ ...f, max_severity: e.target.value }))}>
          <option value="CRITICAL">block at CRITICAL</option>
          <option value="HIGH">block at HIGH+</option>
          <option value="MEDIUM">block at MEDIUM+</option>
          <option value="LOW">block at LOW+</option>
        </select>
        <label className="check"><input type="checkbox" checked={form.block_kev}
          onChange={(e) => setForm((f) => ({ ...f, block_kev: e.target.checked }))} /> block KEV exposure</label>
        <label className="check"><input type="checkbox" checked={form.block_license_denied}
          onChange={(e) => setForm((f) => ({ ...f, block_license_denied: e.target.checked }))} /> block denied licenses</label>
        <button onClick={create}>create policy</button>
      </div>
      {!policies.length && !error && <p className="empty">No gate policies — evaluation uses the default HIGH threshold.</p>}
    </div>
  )
}
