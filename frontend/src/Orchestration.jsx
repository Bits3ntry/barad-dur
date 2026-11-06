import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Dialog, PageHeader, Pager, usePage } from './ui'

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
  const [schedules, setSchedules] = useState([])
  const [assets, setAssets] = useState([])
  const [schedule, setSchedule] = useState({ name: '', kind: 'scan', scanner: '', asset_id: '', principal: 'ci', target: '', interval_minutes: 1440 })
  const [tickInfo, setTickInfo] = useState('')
  const [internal, setInternal] = useState([])
  const [internalNote, setInternalNote] = useState('')
  const [internalBusy, setInternalBusy] = useState('')
  const [logRow, setLogRow] = useState(null)

  // Runs and schedules accumulate for the life of the platform; scanners and
  // workers are registration lists short enough to read whole.
  const pagedJobs = usePage(jobs, 25)
  const pagedSchedules = usePage(schedules, 25)

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    Promise.all([
      api.get('/api/v1/orchestration/scanners'),
      api.get('/api/v1/orchestration/workers'),
      api.get('/api/v1/orchestration/jobs'),
      api.get('/api/v1/orchestration/schedules'),
      api.get('/api/v1/assets'),
      api.get('/api/v1/orchestration/internal'),
    ]).then(([s, w, j, sc, a, internalScans]) => {
      setScanners(s.data); setWorkers(w.data); setJobs(j.data)
      setSchedules(sc.data); setAssets(a.data); setInternal(internalScans.data)
    }).catch((e) => setError(String(e.message || e)))
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

  async function addSchedule() {
    try {
      const payload = {
        name: schedule.name, kind: schedule.kind, principal: schedule.principal,
        interval_minutes: Number(schedule.interval_minutes), actor: 'console',
      }
      if (schedule.kind === 'easm') {
        payload.asset_id = schedule.asset_id
      } else {
        payload.scanner = schedule.scanner
        payload.capability = scanners.find((s) => s.name === schedule.scanner)?.capability || CAPS[2]
        payload.targets = [{ type: 'repository', value: schedule.target }]
      }
      await api.post('/api/v1/orchestration/schedules', payload)
      setSchedule((s) => ({ ...s, name: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function toggleSchedule(row) {
    try {
      await api.patch(`/api/v1/orchestration/schedules/${row.id}`,
        { enabled: !row.enabled, actor: 'console' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function runInternal(row) {
    setInternalNote('')
    setInternalBusy(row.name)
    try {
      const r = await api.post(`/api/v1/orchestration/internal/${row.name}/run`,
        { actor: 'console' })
      // The job row and the log are the feedback; a second banner saying the
      // same thing is noise on a screen that already has a table for it.
      setInternalNote('')
      if (r.data.run) setLogRow(r.data.run)
      load()
    } catch (e) {
      setInternalNote(`${row.name}: ${String(e.message || e)}`)
    } finally {
      setInternalBusy('')
    }
  }

  async function openLog(run) {
    try {
      const r = await api.get(`/api/v1/orchestration/internal/runs/${run.id}`)
      setLogRow(r.data)
    } catch (e) {
      setInternalNote(String(e.message || e))
    }
  }

  async function tickNow() {
    try {
      const r = await api.post('/api/v1/orchestration/schedules/tick', { actor: 'console' })
      setTickInfo(`tick: ${r.data.processed} processed` +
        (r.data.results.length ? ` (${r.data.results.map((x) => x.result).join(', ')})` : ''))
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

  // Mientras corre un barrido, la página tiene que mostrarlo: el request del
  // botón sigue abierto, así que la lista se refresca sola.
  useEffect(() => {
    if (!internalBusy) return undefined
    const timer = setInterval(load, 4000)
    return () => clearInterval(timer)
  }, [internalBusy])

  const internalRuns = internal.flatMap((row) => (row.runs || []).map((run) => ({ ...run, source: row.label })))
  const jobsView = [
    ...internalRuns.map((run) => ({
      key: `internal-${run.id}`, kind: 'internal', status: run.status, when: run.started_at,
      name: run.source, trigger: run.trigger,
      what: `${run.counters?.versions_analyzed ?? 0} builds · `
        + `${run.counters?.findings_created ?? 0} new · ${run.counters?.findings_refreshed ?? 0} refreshed`,
      duration: run.duration_ms, raw: run,
    })),
    ...jobs.map((job) => ({
      key: `job-${job.id}`, kind: 'scan', status: job.status, when: job.created_at,
      name: job.scanner, trigger: job.principal || 'worker',
      what: `${job.capability}${job.worker_id ? ` · worker ${job.worker_id.slice(0, 8)}` : ''}`
        + `${job.attempts ? ` · attempt ${job.attempts}/${job.max_attempts}` : ''}`
        + `${job.error ? ` · ${job.error}` : ''}`,
      duration: null, raw: job,
    })),
  ].sort((a, b) => new Date(b.when) - new Date(a.when))
  const running = jobsView.filter((row) => ['running', 'leased'].includes(row.status)).length
  const nextInternal = internal[0]?.schedule?.next_due_at
  const scheduleCount = schedules.length + internal.length

  const logDialog = (
    <Dialog open={Boolean(logRow)} size="wide" hideFooter
      title={logRow ? `${logRow.name || 'internal-scan'} · ${new Date(logRow.started_at).toLocaleString()} · ${logRow.status}` : ''}
      onClose={() => setLogRow(null)}>
      {logRow && (
        <div className="stack">
          <p className="muted" style={{ margin: 0 }}>
            trigger {logRow.trigger}{logRow.actor ? ` · by ${logRow.actor}` : ''} ·{' '}
            {logRow.duration_ms != null ? `${(logRow.duration_ms / 1000).toFixed(1)}s` : '—'}
          </p>
          <pre className="code mono" style={{ margin: 0 }}>{logRow.log || 'no log recorded'}</pre>
        </div>
      )}
    </Dialog>
  )

  return (
    <div className="stack">
      <PageHeader title="Orchestration"
        subtitle="What is scheduled, what is running, and who runs it. Pipelines and git actions live in Pipelines." />
      <div className="toolbar">
        <span className="count">
          {scheduleCount} scheduled · {running} running · {workers.length} workers
          {nextInternal ? ` · next sweep ${new Date(nextInternal).toLocaleString()}` : ''}
        </span>
        <button onClick={load}>refresh</button>
        {claimInfo && <span className="muted">{claimInfo}</span>}
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      {internalNote && <div className="banner banner-info">{internalNote}</div>}

      <h2 className="section">schedules</h2>
      <p className="muted small" style={{ marginTop: 0 }}>
        What will run on its own. A schedule fires a job; the job appears below while it runs.
      </p>
      <table>
        <thead><tr><th>schedule</th><th>what</th><th>every</th><th>next run</th>
          <th>last</th><th></th></tr></thead>
        <tbody>
          {internal.map((row) => (
            <tr key={row.name}>
              <td className="title mono">{row.label}</td>
              <td>
                {row.title}
                <div className="muted small">
                  {Object.entries(row.sources).filter(([, on]) => on).map(([key]) => key).join(' + ') || 'all sources off'}
                  {row.autorun ? '' : ' · external clock'}
                </div>
              </td>
              <td>{row.schedule.interval_hours}h</td>
              <td>{row.schedule.next_due_at
                ? new Date(row.schedule.next_due_at).toLocaleString()
                : 'never ran'}</td>
              <td className="muted">
                {row.last_run
                  ? `${row.last_run.status} · ${row.last_run.duration_ms != null
                    ? `${(row.last_run.duration_ms / 1000).toFixed(1)}s` : '—'} · `
                    + `${row.last_run.counters.findings_created ?? 0} new`
                  : 'never'}
              </td>
              <td>
                <button className="primary-action" disabled={internalBusy === row.name}
                  onClick={() => runInternal(row)}>
                  {internalBusy === row.name ? 'running…' : 'run now'}
                </button>
                {row.last_run && (
                  <button className="mini" onClick={() => openLog(row.last_run)}>log</button>
                )}
              </td>
            </tr>
          ))}
          {pagedSchedules.rows.map((row) => (
            <tr key={row.id}>
              <td className="title">{row.name}</td>
              <td>
                {row.kind === 'easm' ? 'surface collection' : 'scan job'}
                <div className="muted small">
                  {row.kind === 'easm'
                    ? (assets.find((a) => a.id === row.asset_id)?.value || row.asset_id?.slice(0, 8))
                    : (row.targets[0]?.value || '—')}
                  {row.enabled ? '' : ' · paused'}
                </div>
              </td>
              <td>{row.interval_minutes}m</td>
              <td>{new Date(row.next_run_at).toLocaleString()}{row.due ? ' (due)' : ''}</td>
              <td className="muted">
                {row.last_error
                  ? <span className="error small">{row.last_error}</span>
                  : (row.last_run_at ? new Date(row.last_run_at).toLocaleTimeString() : 'never')}
              </td>
              <td>
                <button className="mini" onClick={() => toggleSchedule(row)}>
                  {row.enabled ? 'pause' : 'resume'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {scheduleCount === 0 && <p className="empty">Nothing scheduled.</p>}
      <div className="toolbar">
        <Pager page={pagedSchedules.page} pages={pagedSchedules.pages} onChange={pagedSchedules.setPage}
          total={pagedSchedules.total} perPage={pagedSchedules.perPage} unit="schedules" />
        <span className="row-end">
          {tickInfo && <span className="muted">{tickInfo}</span>}
          <button onClick={tickNow}>evaluate schedules now</button>
        </span>
      </div>
      <details className="card">
        <summary>add a scan schedule</summary>
        <div className="card">
          <input placeholder="schedule name" value={schedule.name}
            onChange={(e) => setSchedule((s) => ({ ...s, name: e.target.value }))} />
          <select value={schedule.kind} onChange={(e) => setSchedule((s) => ({ ...s, kind: e.target.value }))}>
            <option value="scan">scan job</option>
            <option value="easm">easm collection</option>
          </select>
          {schedule.kind === 'scan' ? (
            <>
              <select value={schedule.scanner}
                onChange={(e) => setSchedule((s) => ({ ...s, scanner: e.target.value }))}>
                <option value="">scanner</option>
                {scanners.map((s) => <option key={s.id} value={s.name}>{s.name}</option>)}
              </select>
              <input placeholder="repository target" value={schedule.target}
                onChange={(e) => setSchedule((s) => ({ ...s, target: e.target.value }))} />
            </>
          ) : (
            <select value={schedule.asset_id}
              onChange={(e) => setSchedule((s) => ({ ...s, asset_id: e.target.value }))}>
              <option value="">domain asset</option>
              {assets.filter((a) => ['domain', 'subdomain'].includes(a.type))
                .map((a) => <option key={a.id} value={a.id}>{a.value}</option>)}
            </select>
          )}
          <input type="number" min="15" value={schedule.interval_minutes}
            onChange={(e) => setSchedule((s) => ({ ...s, interval_minutes: e.target.value }))} />
          <input placeholder="principal" value={schedule.principal}
            onChange={(e) => setSchedule((s) => ({ ...s, principal: e.target.value }))} />
          <button onClick={addSchedule}>add schedule</button>
        </div>
      </details>

      <h2 className="section">jobs</h2>
      <p className="muted small" style={{ marginTop: 0 }}>
        Every run, newest first: the platform's own sweeps and the scans handed to a worker.
      </p>
      <table>
        <thead><tr><th>job</th><th>source</th><th>status</th><th>started</th>
          <th>what it did</th><th>duration</th><th></th></tr></thead>
        <tbody>
          {jobsView.map((row) => (
            <tr key={row.key}>
              <td className="title mono">{row.name}</td>
              <td className="muted">{row.kind === 'internal' ? row.trigger : 'worker'}</td>
              <td><span className={`status st-${row.status}`}>{row.status}</span></td>
              <td className="muted">{new Date(row.when).toLocaleString()}</td>
              <td className="muted">{row.what}</td>
              <td className="muted">{row.duration != null ? `${(row.duration / 1000).toFixed(1)}s` : '—'}</td>
              <td>
                {row.kind === 'internal' && (
                  <button className="mini" onClick={() => openLog(row.raw)}>log</button>
                )}
                {row.kind === 'scan' && ['queued', 'leased', 'running'].includes(row.status) && (
                  <button className="mini" onClick={() => act(row.raw, 'cancel')}>cancel</button>
                )}
                {row.kind === 'scan' && ['failed', 'cancelled'].includes(row.status) && (
                  <button className="mini" onClick={() => act(row.raw, 'retry')}>retry</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!jobsView.length && (
        <p className="empty">
          Nothing has run yet. The sweep starts when its schedule fires, or when you press run now.
        </p>
      )}
      <Pager page={pagedJobs.page} pages={pagedJobs.pages} onChange={pagedJobs.setPage}
        total={pagedJobs.total} perPage={pagedJobs.perPage} unit="scan jobs" className="row-end" />

      <h2 className="section">workers</h2>
      <p className="muted small" style={{ marginTop: 0 }}>
        A worker is a container or tool that registers itself and claims jobs. Nothing here means
        nobody is claiming work — the platform's own sweeps do not need one.
      </p>
      {workers.length ? (
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
      ) : <p className="empty">No worker registered.</p>}

      <details className="card">
        <summary>setup: scanners, workers and manual jobs</summary>
        <p className="muted small">
          Queueing a scan requires an active authorization grant for the target; the decision is
          stored with the job and revalidated when a worker claims it.
        </p>
        <h3 className="section">scanners</h3>
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
        {!scanners.length && <p className="empty">No scanner registered.</p>}
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
      </details>
      {logDialog}
    </div>
  )
}
