import React, { useEffect, useState } from 'react'
import { api } from './api'
import { PageHeader } from './ui'

const CAPABILITIES = ['passive_discovery', 'active_verification',
  'vulnerability_analysis', 'intrusive_testing']

function parseTargets(text) {
  return text.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const [type, ...rest] = line.split('=')
    return { type: (type || '').trim(), value: rest.join('=').trim() }
  }).filter((t) => t.type && t.value)
}

function targetLines(targets) {
  return (targets || []).map((t) => `${t.type}=${t.value}`).join('\n')
}

export default function Grants() {
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState({
    status: '', principal: '', capability: '', tool: '', target: '', expired: '',
  })
  const [form, setForm] = useState({
    principal: '', capability: 'passive_discovery', targets: 'domain=staging.company.org\n',
    issued_by: 'console', justification: '', hours: 168, environment: '', tools: '',
  })
  const [sim, setSim] = useState({ capability: 'intrusive_testing', type: 'domain', value: '', tool: '', environment: '' })
  const [simResult, setSimResult] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => { load() }, [filters])

  function load() {
    setError('')
    const params = new URLSearchParams()
    for (const [k, v] of Object.entries(filters)) if (v) params.set(k, v)
    api.get(`/api/v1/authorization/grants${params.toString() ? '?' + params : ''}`)
      .then((r) => { setRows(r.data); setTotal(r.total) })
      .catch((e) => setError(String(e.message || e)))
  }

  async function create() {
    try {
      await api.post('/api/v1/authorization/grants', {
        principal: form.principal.trim(),
        capabilities: [form.capability],
        targets: parseTargets(form.targets),
        issued_by: form.issued_by.trim() || 'console',
        justification: form.justification.trim() || 'created from console',
        hours: Number(form.hours) || 168,
        environment: form.environment.trim() || undefined,
        tools: form.tools.trim() ? form.tools.split(',').map((t) => t.trim()) : undefined,
      })
      setForm((f) => ({ ...f, principal: '', justification: '' }))
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function revoke(g) {
    const ok = window.confirm(`Revoke grant ${g.id} for ${g.principal}? This is audited and cannot be undone silently.`)
    if (!ok) return
    try {
      await api.post(`/api/v1/authorization/grants/${g.id}/revoke`,
        { reason: 'revoked from console', actor: 'console' })
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function simulate() {
    setSimResult('…')
    try {
      const body = { principal: form.principal.trim() || 'simulated-principal',
        capability: sim.capability,
        targets: [{ type: sim.type, value: sim.value.trim() }] }
      if (sim.tool.trim()) body.tool = sim.tool.trim()
      if (sim.environment.trim()) body.environment = sim.environment.trim()
      const result = await api.post('/api/v1/authorization/authorize', body)
      setSimResult(result)
    } catch (e) {
      setSimResult({ decision: 'error', reason: String(e.message || e) })
    }
  }

  return (
    <div className="stack">
      <PageHeader title="Authorization grants" />
      <div className="toolbar">
        <select value={filters.status} onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}>
          <option value="">any status</option>
          <option value="active">active</option>
          <option value="revoked">revoked</option>
        </select>
        <input placeholder="principal…" value={filters.principal}
          onChange={(e) => setFilters((f) => ({ ...f, principal: e.target.value }))} />
        <select value={filters.capability} onChange={(e) => setFilters((f) => ({ ...f, capability: e.target.value }))}>
          <option value="">any capability</option>
          {CAPABILITIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <input placeholder="tool…" value={filters.tool}
          onChange={(e) => setFilters((f) => ({ ...f, tool: e.target.value }))} />
        <input placeholder="target…" value={filters.target}
          onChange={(e) => setFilters((f) => ({ ...f, target: e.target.value }))} />
        <select value={filters.expired} onChange={(e) => setFilters((f) => ({ ...f, expired: e.target.value }))}>
          <option value="">any expiry</option>
          <option value="false">not expired</option>
          <option value="true">expired</option>
        </select>
        <span className="count">{total} grants</span>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      <table>
        <thead>
          <tr><th>principal</th><th>capability</th><th>targets</th><th>env/tool</th>
              <th>valid until</th><th>status</th><th>justification / issuer</th><th></th></tr>
        </thead>
        <tbody>
          {rows.map((g) => (
            <tr key={g.id} className={g.status === 'revoked' ? 'muted-row' : ''}>
              <td>{g.principal}</td>
              <td>{(g.capabilities || []).map((c) => <span key={c} className="pill">{c}</span>)}</td>
              <td className="title">{targetLines(g.targets)}</td>
              <td>{g.environment || '—'} / {(g.tools || []).join(', ') || '—'}</td>
              <td className="muted">{new Date(g.valid_until).toLocaleString()}</td>
              <td><span className={`status st-${g.status}`}>{g.status}</span></td>
              <td className="muted">
                {g.justification} <br />by {g.issued_by} · policy v{g.policy_version}
              </td>
              <td>
                {g.status === 'active' &&
                  <button onClick={() => revoke(g)}>revoke</button>}
                {g.status === 'revoked' &&
                  <span className="muted">by {g.revoked_by || '—'}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!rows.length && !error && <p className="empty">No grants for these filters.</p>}
      <h2 className="section">issue a grant</h2>
      {!error && (
        <div className="card">
          <input placeholder="principal (who will run)" value={form.principal}
            onChange={(e) => setForm((f) => ({ ...f, principal: e.target.value }))} />
          <select value={form.capability} onChange={(e) => setForm((f) => ({ ...f, capability: e.target.value }))}>
            {CAPABILITIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <textarea placeholder="targets, one per line: type=value" rows="3"
            value={form.targets}
            onChange={(e) => setForm((f) => ({ ...f, targets: e.target.value }))} />
          <input placeholder="issued_by (you)" value={form.issued_by}
            onChange={(e) => setForm((f) => ({ ...f, issued_by: e.target.value }))} />
          <input placeholder="justification (audited)" value={form.justification}
            onChange={(e) => setForm((f) => ({ ...f, justification: e.target.value }))} />
          <div className="toolbar">
            <label>hours <input type="number" value={form.hours} style={{ width: 70 }}
              onChange={(e) => setForm((f) => ({ ...f, hours: e.target.value }))} /></label>
            <input placeholder="environment (optional)" value={form.environment}
              onChange={(e) => setForm((f) => ({ ...f, environment: e.target.value }))} />
            <input placeholder="tools, comma separated (optional)" value={form.tools}
              onChange={(e) => setForm((f) => ({ ...f, tools: e.target.value }))} />
          </div>
          <button onClick={create}>issue grant</button>
          <p className="hint">
            Invasive capabilities cannot be self-authorized (issued_by must
            differ from principal); the backend enforces this.
          </p>
        </div>
      )}
      <h2 className="section">authorize() simulator</h2>
      <div className="toolbar">
        <select value={sim.capability} onChange={(e) => setSim((s) => ({ ...s, capability: e.target.value }))}>
          {CAPABILITIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={sim.type} onChange={(e) => setSim((s) => ({ ...s, type: e.target.value }))}>
          <option value="domain">domain</option>
          <option value="wildcard_domain">wildcard_domain</option>
          <option value="ip">ip</option>
          <option value="url">url</option>
          <option value="repository">repository</option>
          <option value="service">service</option>
        </select>
        <input placeholder="target value" value={sim.value}
          onChange={(e) => setSim((s) => ({ ...s, value: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && simulate()} />
        <input placeholder="tool (optional)" value={sim.tool}
          onChange={(e) => setSim((s) => ({ ...s, tool: e.target.value }))} />
        <input placeholder="environment (optional)" value={sim.environment}
          onChange={(e) => setSim((s) => ({ ...s, environment: e.target.value }))} />
        <button onClick={simulate}>simulate</button>
      </div>
      {simResult && simResult !== '…' && (
        <div className="detail">
          <dl>
            <dt>decision</dt>
            <dd><span className={simResult.decision === 'allow' ? 'ok' : 'sev sev-critical'}>
              {simResult.decision}</span></dd>
            <dt>reason</dt><dd>{simResult.reason}</dd>
            <dt>policy</dt><dd>v{simResult.policy_version} — evaluated {simResult.evaluated_at}</dd>
          </dl>
        </div>
      )}
    </div>
  )
}
