import React, { useEffect, useState } from 'react'
import { api } from './api'

const CAPS = ['passive_discovery', 'active_verification', 'vulnerability_analysis', 'intrusive_testing']

export default function Orchestration() {
  const [scanners, setScanners] = useState([])
  const [workers, setWorkers] = useState([])
  const [jobs, setJobs] = useState([])
  const [error, setError] = useState('')
  const [claimInfo, setClaimInfo] = useState('')
  const [scanner, setScanner] = useState({ name: '', capability: CAPS[2], version: '' })
  const [worker, setWorker] = useState({ name: '', capabilities: [CAPS[2]], max_concurrent: 1 })
  const [job, setJob] = useState({ scanner: '', capability: CAPS[2], principal: 'ci', target: '', environment: 'ci' })

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    Promise.all([
      api.get('/api/v1/orchestration/scanners'),
      api.get('/api/v1/orchestration/workers'),
      api.get('/api/v1/orchestration/jobs'),
    ]).then(([s, w, j]) => { setScanners(s.data); setWorkers(w.data); setJobs(j.data) })
      .catch((e) => setError(String(e.message || e)))
  }

  async function addScanner() {
    try {
      await api.post('/api/v1/orchestration/scanners', {
        ...scanner, display_name: scanner.name, actor: 'console',
      })
      setScanner({ name: '', capability: CAPS[2], version: '' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function addWorker() {
    try {
      await api.post('/api/v1/orchestration/workers', { ...worker, actor: 'console' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function queueJob() {
    try {
      await api.post('/api/v1/orchestration/jobs', {
        scanner: job.scanner, capability: job.capability, principal: job.principal,
        targets: [{ type: 'repository', value: job.target }],
        environment: job.environment, actor: 'console',
      })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function act(row, action) {
    try {
      await api.post(`/api/v1/orchestration/jobs/${row.id}/${action}`,
        { actor: 'console', reason: action === 'cancel' ? 'console cancel' : undefined })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function claim(w) {
    try {
      const r = await api.post('/api/v1/orchestration/jobs/claim',
        { worker_id: w.id, actor: 'console' })
      setClaimInfo(r.data
        ? `leased ${r.data.id.slice(0, 8)} to ${w.name}`
        : r.rejected ? `rejected ${r.rejected.job_id.slice(0, 8)}: ${r.rejected.reason}` : 'no queued jobs')
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  return (
    <div>
      <div className="bar">
        <span className="count">{scanners.length} scanners · {workers.length} workers · {jobs.length} jobs</span>
        <button onClick={load}>refresh</button>
        {claimInfo && <span className="muted">{claimInfo}</span>}
      </div>
      {error && <p className="error">{error}</p>}

      <h2 className="section">jobs</h2>
      <table>
        <thead><tr><th>job</th><th>scanner</th><th>status</th><th>attempts</th><th>worker</th><th></th></tr></thead>
        <tbody>
          {jobs.map((row) => (
            <tr key={row.id}>
              <td className="title">{row.id.slice(0, 8)}</td>
              <td>{row.scanner} <span className="muted">({row.capability})</span></td>
              <td><span className={`status st-${row.status}`}>{row.status}</span>
                {row.error && <div className="muted small">{row.error}</div>}</td>
              <td>{row.attempts}/{row.max_attempts}</td>
              <td>{(row.worker_id || '—').slice(0, 8)}</td>
              <td>
                {['queued', 'leased', 'running'].includes(row.status) &&
                  <button className="mini" onClick={() => act(row, 'cancel')}>cancel</button>}
                {['failed', 'cancelled'].includes(row.status) &&
                  <button className="mini" onClick={() => act(row, 'retry')}>retry</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!jobs.length && <p className="empty">No jobs queued.</p>}

      <h2 className="section">workers</h2>
      <table>
        <thead><tr><th>worker</th><th>capabilities</th><th>active</th><th>status</th><th></th></tr></thead>
        <tbody>
          {workers.map((w) => (
            <tr key={w.id}>
              <td className="title">{w.name}</td>
              <td className="muted">{w.capabilities.join(', ') || 'any'}</td>
              <td>{w.active_jobs}/{w.max_concurrent}</td>
              <td><span className={`status st-${w.status}`}>{w.status}</span></td>
              <td><button className="mini" onClick={() => claim(w)}>claim next</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      {!workers.length && <p className="empty">No workers registered.</p>}

      <h2 className="section">scanners</h2>
      <table>
        <thead><tr><th>scanner</th><th>capability</th><th>version</th><th>enabled</th></tr></thead>
        <tbody>
          {scanners.map((s) => (
            <tr key={s.id}>
              <td className="title">{s.name}</td>
              <td><span className="pill">{s.capability}</span></td>
              <td>{s.version || '—'}</td>
              <td>{s.enabled ? 'yes' : 'no'}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 className="section">queue a job</h2>
      <p className="muted small">
        Queueing requires an active authorization grant for the target; the decision is
        stored with the job and revalidated when a worker claims it.
      </p>
      <div className="card">
        <select value={job.scanner} onChange={(e) => setJob((j) => ({ ...j, scanner: e.target.value }))}>
          <option value="">scanner</option>
          {scanners.map((s) => <option key={s.id} value={s.name}>{s.name}</option>)}
        </select>
        <input placeholder="repository target (e.g. acme/saria)" value={job.target}
          onChange={(e) => setJob((j) => ({ ...j, target: e.target.value }))} />
        <input placeholder="principal" value={job.principal}
          onChange={(e) => setJob((j) => ({ ...j, principal: e.target.value }))} />
        <input placeholder="environment" value={job.environment}
          onChange={(e) => setJob((j) => ({ ...j, environment: e.target.value }))} />
        <button onClick={queueJob}>queue</button>
      </div>

      <h2 className="section">register</h2>
      <div className="card">
        <input placeholder="scanner name" value={scanner.name}
          onChange={(e) => setScanner((s) => ({ ...s, name: e.target.value }))} />
        <select value={scanner.capability} onChange={(e) => setScanner((s) => ({ ...s, capability: e.target.value }))}>
          {CAPS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <input placeholder="version" value={scanner.version}
          onChange={(e) => setScanner((s) => ({ ...s, version: e.target.value }))} />
        <button onClick={addScanner}>add scanner</button>
      </div>
      <div className="card">
        <input placeholder="worker name" value={worker.name}
          onChange={(e) => setWorker((w) => ({ ...w, name: e.target.value }))} />
        <input type="number" min="1" max="32" value={worker.max_concurrent}
          onChange={(e) => setWorker((w) => ({ ...w, max_concurrent: Number(e.target.value) }))} />
        <button onClick={addWorker}>add worker</button>
      </div>
    </div>
  )
}
