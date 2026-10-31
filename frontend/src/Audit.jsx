import React, { useEffect, useState } from 'react'
import { api } from './api'

const ACTIONS = ['', 'authorization.', 'member.', 'remediation.', 'asset.',
  'easm.', 'vex.', 'intel.', 'suppression.', 'finding.']

export default function Audit() {
  const [state, setState] = useState({ rows: [], total: 0, chain_ok: null,
    actor: '', action: '', since: '', until: '', q: '' })
  const [error, setError] = useState('')

  useEffect(() => { load() }, [state.actor, state.action, state.since, state.until, state.q])

  function load() {
    setError('')
    const params = new URLSearchParams()
    if (state.actor) params.set('actor', state.actor)
    if (state.action) params.set('action', state.action)
    if (state.since) params.set('since', new Date(state.since).toISOString())
    if (state.until) params.set('until', new Date(state.until).toISOString())
    if (state.q) params.set('q', state.q)
    api.get(`/api/v1/audit${params.toString() ? '?' + params : ''}`)
      .then((r) => setState((s) => ({ ...s, rows: r.data, total: r.total, chain_ok: r.chain_ok })))
      .catch((e) => setError(String(e.message || e)))
  }

  return (
    <div>
      <div className="bar">
        <input placeholder="actor…" value={state.actor}
          onChange={(e) => setState((s) => ({ ...s, actor: e.target.value }))} />
        <select value={state.action} onChange={(e) => setState((s) => ({ ...s, action: e.target.value }))}>
          {ACTIONS.map((a) => <option key={a} value={a}>{a || 'any action'}</option>)}
        </select>
        <input type="date" value={state.since}
          onChange={(e) => setState((s) => ({ ...s, since: e.target.value }))} />
        <input type="date" value={state.until}
          onChange={(e) => setState((s) => ({ ...s, until: e.target.value }))} />
        <input placeholder="search detail…" value={state.q}
          onChange={(e) => setState((s) => ({ ...s, q: e.target.value }))} />
        <span className={`audit-chip ${state.chain_ok ? 'ok' : 'sev sev-critical'}`}>
          {state.chain_ok === null ? 'checking…' : state.chain_ok ? 'chain verified' : 'CHAIN BROKEN'}
        </span>
        <span className="count">{state.total} entries</span>
      </div>
      {error && <p className="error">{error}</p>}
      <table>
        <thead>
          <tr><th>#</th><th>at</th><th>actor</th><th>action</th><th>detail (reason / policy)</th><th>hash</th></tr>
        </thead>
        <tbody>
          {state.rows.map((r) => (
            <tr key={r.position}>
              <td>{r.position}</td>
              <td>{new Date(r.at).toLocaleString()}</td>
              <td>{r.actor}</td>
              <td>{r.action}</td>
              <td>
                {r.detail || '—'}
                {r.detail && /\[policy v\d+\]/.test(r.detail) &&
                  <span className="pill">{(r.detail.match(/\[policy v(\d+)\]/) || [])[1] && 'policy'}</span>}
              </td>
              <td className="muted">{r.hash.slice(0, 10)}…</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!state.rows.length && !error && <p className="empty">No audit entries for these filters.</p>}
    </div>
  )
}
