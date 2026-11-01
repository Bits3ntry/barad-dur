import React, { useEffect, useState } from 'react'
import { api } from './api'
import { PageHeader } from './ui'

export default function Regression() {
  const [tests, setTests] = useState([])
  const [runs, setRuns] = useState({})
  const [error, setError] = useState('')
  const [reintroduced, setReintroduced] = useState(false)
  const [reintroducedMsg, setReintroducedMsg] = useState('')
  const [form, setForm] = useState({
    name: '', url: '', method: 'GET', suite: 'default',
    expectStatus: 403, bodyMustNotContain: '',
  })

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/regression/tests')
      .then((r) => setTests(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  async function createTest() {
    const assertions = [{ type: 'status_equals', value: Number(form.expectStatus) }]
    if (form.bodyMustNotContain) {
      assertions.push({ type: 'body_not_contains', value: form.bodyMustNotContain })
    }
    try {
      await api.post('/api/v1/regression/tests', {
        name: form.name, url: form.url, method: form.method, suite: form.suite,
        assertions, actor: 'console',
      })
      setForm((f) => ({ ...f, name: '', url: '', bodyMustNotContain: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function run(row) {
    try {
      const result = await api.post(`/api/v1/regression/tests/${row.id}/run`,
        { actor: 'console', principal: 'console', environment: 'lab' })
      await history(row)
      if (result.reintroduced) {
        setReintroduced(true)
        setReintroducedMsg('REGRESSION: this check passed before and now fails.')
      } else {
        setReintroduced(false)
        setReintroducedMsg('')
      }
    } catch (e) { setError(String(e.message || e)) }
  }

  async function history(row) {
    try {
      const r = await api.get(`/api/v1/regression/tests/${row.id}/runs`)
      setRuns((s) => ({ ...s, [row.id]: r.data }))
    } catch (e) { setError(String(e.message || e)) }
  }

  return (
    <div className="stack">
      <PageHeader title="Security regression" />
      <div className="toolbar">
        <span className="count">{tests.length} checks</span>
        <button onClick={load}>refresh</button>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      <table>
        <thead><tr><th>check</th><th>suite</th><th>method</th><th>target</th><th>last run</th><th></th></tr></thead>
        <tbody>
          {tests.map((row) => (
            <React.Fragment key={row.id}>
              <tr>
                <td className="title">{row.name}</td>
                <td><span className="pill">{row.suite}</span></td>
                <td>{row.method}</td>
                <td className="muted">{row.url}</td>
                <td>
                  {row.last_run
                    ? <span className={`status st-${row.last_run.result}`}>
                        {row.last_run.result}{row.last_run.reintroduced ? ' (reintroduced)' : ''}
                      </span>
                    : <span className="muted">never</span>}
                </td>
                <td>
                  <button className="mini" onClick={() => run(row)}>run</button>{' '}
                  <button className="mini" onClick={() => history(row)}>history</button>
                </td>
              </tr>
              {runs[row.id] && (
                <tr className="detail-row"><td colSpan={6}>
                  <div className="detail">
                    <dl>
                      <dt>runs ({runs[row.id].length})</dt>
                      <dd>
                        {runs[row.id].map((r) => (
                          <div key={r.id} className="occ-row">
                            {new Date(r.ran_at).toLocaleString()} — {' '}
                            <span className={`status st-${r.result}`}>{r.result}</span>{' '}
                            HTTP {r.http_status ?? '—'} · {r.latency_ms}ms
                            {r.reintroduced && <strong className="error"> reintroduced</strong>}
                            {r.error && <span className="muted"> · {r.error}</span>}
                          </div>
                        ))}
                      </dd>
                    </dl>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      {!tests.length && !error && <p className="empty">No regression checks yet.</p>}
      <h2 className="section">new regression check</h2>
      <p className="muted small">
        Execution requires an active authorization grant for the target
        (capability active_verification); mutating methods also need
        intrusive_testing.
      </p>
      <div className="card">
        <input placeholder="check name" value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
        <input placeholder="https://target/path" value={form.url} style={{ minWidth: 320 }}
          onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} />
        <select value={form.method} onChange={(e) => setForm((f) => ({ ...f, method: e.target.value }))}>
          {['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <input placeholder="suite" value={form.suite}
          onChange={(e) => setForm((f) => ({ ...f, suite: e.target.value }))} />
        <input type="number" placeholder="expected status" value={form.expectStatus}
          onChange={(e) => setForm((f) => ({ ...f, expectStatus: e.target.value }))} />
        <input placeholder="body must NOT contain" value={form.bodyMustNotContain}
          onChange={(e) => setForm((f) => ({ ...f, bodyMustNotContain: e.target.value }))} />
        <button onClick={createTest}>create check</button>
      </div>
    </div>
  )
}
