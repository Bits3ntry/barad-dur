import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { Dialog, EmptyState, PageHeader, Pager, usePage } from './ui'

/* ──────────────────────────────── orchestration ────────────────────────────────

   One page answers three questions, in this order:

     what will run on its own   the schedules, including the platform's own
                                sweeps (advisory feeds, CPE matching, KEV/EPSS)
     who will run it            the workers, with their heartbeat, and a door to
                                Settings → Runtime for the limits
     what has run               every run, newest first, paginated, with where it
                                came from: an internal sweep, a worker, or a CLI

   The origin matters and used to be invisible: "internal", "cli" and "worker" are
   three different blast radii and three different people to call at 3am. */

const CAPS = ['passive_discovery', 'active_verification', 'vulnerability_analysis',
  'intrusive_testing']

/* The catalogue holds the labels: a map of English prose cannot be translated,
   and a profile the catalogue does not know falls back to what the API sent. */
const PROFILE_LABEL = {
  'recon.simple': 'orchestration.profile.recon.simple',
  'web.redteam': 'orchestration.profile.web.redteam',
  'recon.advanced': 'orchestration.profile.recon.advanced',
  'web.exposure': 'orchestration.profile.web.exposure',
  'code.sast': 'orchestration.profile.code.sast',
  'code.secrets': 'orchestration.profile.code.secrets',
  'code.supply-chain': 'orchestration.profile.code.supply-chain',
  'image.supply-chain': 'orchestration.profile.image.supply-chain',
}

function originOf(job) {
  if (job.origin === 'cli' || job.executor === 'cli') return 'cli'
  return 'worker'
}

function typeOf(job, t) {
  if (job.scanner !== 'shauron-surface') {
    return job.scanner || t('orchestration.type.scan')
  }
  const name = job.profile?.name
  if (name && PROFILE_LABEL[name]) return t(PROFILE_LABEL[name])
  return job.profile?.label || name || t('orchestration.type.surface')
}

/* Relative time is a sentence in every language that is not English, so the unit
   is a key: "hace 2 h" is not "2h ago" with a word swapped in. */
function ago(value, t) {
  if (!value) return '—'
  const seconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000)
  if (seconds < 90) return t('orchestration.time.secondsAgo', { n: Math.round(seconds) })
  if (seconds < 5400) return t('orchestration.time.minutesAgo', { n: Math.round(seconds / 60) })
  if (seconds < 172800) return t('orchestration.time.hoursAgo', { n: Math.round(seconds / 3600) })
  return t('orchestration.time.daysAgo', { n: Math.round(seconds / 86400) })
}

function untilSweep(value, t) {
  if (!value) return '—'
  const ms = new Date(value).getTime() - Date.now()
  if (ms <= 0) return t('orchestration.time.dueNow')
  const minutes = Math.round(ms / 60000)
  if (minutes < 90) return t('orchestration.time.inMinutes', { n: minutes })
  return t('orchestration.time.inHours', { n: Math.round(minutes / 60) })
}

function duration(row, t) {
  if (row.kind === 'internal') {
    return row.raw.duration_ms != null
      ? t('orchestration.time.seconds', { n: (row.raw.duration_ms / 1000).toFixed(1) })
      : '—'
  }
  const start = row.raw.started_at || row.raw.created_at
  const end = row.raw.finished_at
  if (!start || !end) return '—'
  const seconds = (new Date(end) - new Date(start)) / 1000
  return Number.isFinite(seconds) && seconds >= 0
    ? t('orchestration.time.seconds', { n: seconds.toFixed(1) }) : '—'
}

export default function Orchestration() {
  const { t, tOr } = useI18n()
  const [scanners, setScanners] = useState([])
  const [workers, setWorkers] = useState([])
  const [jobs, setJobs] = useState([])
  const [schedules, setSchedules] = useState([])
  const [assets, setAssets] = useState([])
  const [internal, setInternal] = useState([])
  const [error, setError] = useState('')
  const [claimInfo, setClaimInfo] = useState('')
  const [tickInfo, setTickInfo] = useState('')
  const [internalNote, setInternalNote] = useState('')
  const [internalBusy, setInternalBusy] = useState('')
  const [logRow, setLogRow] = useState(null)
  const [filter, setFilter] = useState('all')
  const [newSchedule, setNewSchedule] = useState(false)

  const [scanner, setScanner] = useState({ name: '', capability: CAPS[2], version: '' })
  const [worker, setWorker] = useState({ name: '', capabilities: [CAPS[2]], max_concurrent: 1 })
  const [job, setJob] = useState({ scanner: '', capability: CAPS[2], principal: 'ci',
    target: '', environment: 'ci' })
  const [schedule, setSchedule] = useState({ name: '', kind: 'scan', scanner: '',
    asset_id: '', principal: 'ci', target: '', interval_minutes: 1440 })

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

  useEffect(() => {
    if (!internalBusy) return undefined
    const timer = setInterval(load, 4000)
    return () => clearInterval(timer)
  }, [internalBusy])

  async function addScanner() {
    try {
      await api.post('/api/v1/orchestration/scanners', {
        ...scanner, display_name: scanner.name, actor: 'console' })
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
        ...job, targets: job.target ? [{ type: 'repository', value: job.target }] : [],
        actor: 'console' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function act(row, action) {
    try {
      await api.post(`/api/v1/orchestration/jobs/${row.id}/${action}`, { actor: 'console' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function addSchedule() {
    try {
      const payload = { ...schedule, actor: 'console',
        interval_minutes: Number(schedule.interval_minutes) || 1440,
        targets: schedule.target ? [{ type: 'repository', value: schedule.target }] : [] }
      await api.post('/api/v1/orchestration/schedules', payload)
      setNewSchedule(false)
      setSchedule({ name: '', kind: 'scan', scanner: '', asset_id: '', principal: 'ci',
        target: '', interval_minutes: 1440 })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function toggleSchedule(row) {
    try {
      await api.post(`/api/v1/orchestration/schedules/${row.id}/toggle`, { actor: 'console' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function runInternal(row) {
    setInternalBusy(row.name)
    setInternalNote('')
    try {
      const r = await api.post(`/api/v1/orchestration/internal/${row.name}/run`,
        { actor: 'console' })
      const counters = r.data?.counters || {}
      setInternalNote(t('orchestration.internal.note', {
        label: row.label,
        created: counters.findings_created ?? 0,
        refreshed: counters.findings_refreshed ?? 0,
      }))
      load()
    } catch (e) { setError(String(e.message || e)) } finally { setInternalBusy('') }
  }

  async function openLog(run) {
    try {
      const r = await api.get(`/api/v1/orchestration/internal/runs/${run.id}`)
      setLogRow(r.data || run)
    } catch (e) { setError(String(e.message || e)) }
  }

  async function tickNow() {
    try {
      const r = await api.post('/api/v1/orchestration/schedules/tick', { actor: 'console' })
      setTickInfo(t('orchestration.schedules.tickInfo', { ran: r.ran ?? 0, due: r.due ?? 0 }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function claim(w) {
    try {
      const r = await api.post('/api/v1/orchestration/jobs/claim',
        { worker_id: w.id, actor: 'console' })
      setClaimInfo(r.data
        ? t('orchestration.workers.claimLeased',
          { id: r.data.id.slice(0, 8), name: w.name })
        : r.rejected
          ? t('orchestration.workers.claimRejected',
            { id: r.rejected.job_id.slice(0, 8), reason: r.rejected.reason })
          : t('orchestration.workers.claimNone'))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  const runs = useMemo(() => {
    const internalRuns = internal.flatMap((row) => (row.runs || []).map((run) => ({
      ...run, source: row.label, sourceTitle: row.title })))
    const rows = [
      ...internalRuns.map((run) => ({
        key: `internal-${run.id}`, kind: 'internal', origin: 'internal',
        status: run.status, when: run.started_at,
        type: run.source, detail: run.sourceTitle,
        what: t('orchestration.runs.whatInternal', {
          builds: run.counters?.versions_analyzed ?? 0,
          n: run.counters?.findings_created ?? 0,
        }),
        raw: run,
      })),
      ...jobs.map((row) => ({
        key: `job-${row.id}`, kind: 'scan', origin: originOf(row),
        status: row.status, when: row.created_at,
        type: typeOf(row, t),
        detail: (row.targets || []).map((target) => target.value).join(', ') || '—',
        what: row.error || (row.worker_id
          ? t('orchestration.runs.workerTag', { id: row.worker_id.slice(0, 8) }) : ''),
        raw: row,
      })),
    ]
    return rows.sort((a, b) => new Date(b.when) - new Date(a.when))
  }, [internal, jobs, t])

  const visible = filter === 'all' ? runs : runs.filter((row) => row.origin === filter)
  const paged = usePage(visible, 20)
  const liveWorkers = workers.filter((w) => w.status === 'online')
  const staleWorkers = workers.length - liveWorkers.length
  const alive = liveWorkers.length
  const running = runs.filter((row) => ['running', 'leased'].includes(row.status)).length
  const nextSweep = internal
    .map((row) => row.schedule?.next_due_at).filter(Boolean).sort()[0]
  const scheduleCount = schedules.length + internal.length

  const counts = {
    internal: runs.filter((row) => row.origin === 'internal').length,
    worker: runs.filter((row) => row.origin === 'worker').length,
    cli: runs.filter((row) => row.origin === 'cli').length,
  }

  return (
    <div className="stack orch">
      <PageHeader title={t('orchestration.title')}
        subtitle={t('orchestration.subtitle')}
        actions={<>
          <button className="ghost" onClick={load}>{t('common.refresh')}</button>
          <button onClick={() => setNewSchedule(true)}>{t('orchestration.newSchedule')}</button>
        </>} />

      {error && <div className="banner banner-error">{error}</div>}
      {internalNote && <div className="banner banner-info">{internalNote}</div>}

      <div className="orch-strip">
        <div><span>{t('orchestration.kpi.sweeps')}</span><b className="mono">{internal.length}</b></div>
        <div><span>{t('orchestration.kpi.schedules')}</span><b className="mono">{schedules.length}</b></div>
        <div><span>{t('orchestration.kpi.nextSweep')}</span><b className="mono">{untilSweep(nextSweep, t)}</b></div>
        <div><span>{t('orchestration.kpi.running')}</span><b className="mono">{running}</b></div>
        <div><span>{t('orchestration.kpi.workersAlive')}</span><b className="mono">{alive}</b></div>
      </div>

      <div className="orch-top">
        <section className="card orch-card">
          <header>
            <b>{t('orchestration.internal.title')}</b>
            <span>{t('orchestration.internal.subtitle')}</span>
          </header>
          <table className="orch-table">
            <tbody>
              {internal.map((row) => (
                <tr key={row.name}>
                  <td>
                    <b>{row.label}</b>
                    <small className="muted">
                      {Object.entries(row.sources || {}).filter(([, on]) => on)
                        .map(([key]) => key).join(' + ') || t('orchestration.internal.allSourcesOff')}
                      {row.autorun ? '' : ` · ${t('orchestration.internal.externalClock')}`}
                    </small>
                  </td>
                  <td className="mono muted">
                    {t('orchestration.internal.every', { h: row.schedule?.interval_hours ?? '—' })}
                    <small>{t('orchestration.internal.next', {
                      when: row.schedule?.next_due_at
                        ? new Date(row.schedule.next_due_at).toLocaleString()
                        : t('common.never'),
                    })}</small>
                  </td>
                  <td>
                    {row.last_run
                      ? <span className={`status st-${row.last_run.status}`}>
                          {tOr(`status.${row.last_run.status}`, row.last_run.status)}</span>
                      : <span className="muted">{t('common.never')}</span>}
                    {row.last_run && (
                      <small className="muted">
                        {row.last_run.duration_ms != null
                          ? `${t('orchestration.time.seconds', { n: (row.last_run.duration_ms / 1000).toFixed(1) })} · `
                          : ''}
                        {t('orchestration.internal.newFindings',
                          { n: row.last_run.counters?.findings_created ?? 0 })}
                      </small>
                    )}
                  </td>
                  <td className="orch-actions">
                    <button className="mini" disabled={internalBusy === row.name}
                            onClick={() => runInternal(row)}>
                      {internalBusy === row.name
                        ? t('orchestration.internal.running')
                        : t('orchestration.internal.runNow')}
                    </button>
                    {row.last_run && (
                      <button className="mini" onClick={() => openLog(row.last_run)}>
                        {t('orchestration.action.log')}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <header className="orch-sub">
            <b>{t('orchestration.schedules.title')}</b>
            <span><button className="mini" onClick={tickNow}>
                {t('orchestration.schedules.evaluateNow')}
              </button>
              {tickInfo && <span className="muted"> {tickInfo}</span>}</span>
          </header>
          {pagedSchedules.rows.length ? (
            <table className="orch-table">
              <tbody>
                {pagedSchedules.rows.map((row) => (
                  <tr key={row.id}>
                    <td>
                      <b>{row.name}</b>
                      <small className="muted">
                        {row.kind === 'easm'
                          ? t('orchestration.kind.easm') : t('orchestration.kind.scan')} ·{' '}
                        {row.kind === 'easm'
                          ? (assets.find((a) => a.id === row.asset_id)?.value
                             || row.asset_id?.slice(0, 8))
                          : (row.targets?.[0]?.value || '—')}
                        {row.enabled ? '' : ` · ${t('orchestration.schedules.paused')}`}
                      </small>
                    </td>
                    <td className="mono muted">
                      {t('orchestration.schedules.every', { m: row.interval_minutes })}
                    </td>
                    <td className="mono muted">{row.due ? t('orchestration.time.dueNow')
                      : new Date(row.next_run_at).toLocaleString()}</td>
                    <td className="orch-actions">
                      <button className="mini" onClick={() => toggleSchedule(row)}>
                        {row.enabled
                          ? t('orchestration.schedules.pause')
                          : t('orchestration.schedules.resume')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="hint orch-empty">{t('orchestration.schedules.empty')}</p>}
        </section>

        <section className="card orch-card">
          <header>
            <b>{t('orchestration.workers.title')}</b>
            <span>{t('orchestration.workers.alive', { n: alive })}
              {staleWorkers
                ? ` · ${t('orchestration.workers.stale', { n: staleWorkers })}` : ''}</span>
          </header>
          {liveWorkers.length ? (
            <table className="orch-table">
              <thead>
                <tr><th>{t('orchestration.workers.col.worker')}</th>
                  <th>{t('orchestration.workers.col.slots')}</th>
                  <th>{t('common.status')}</th><th></th></tr>
              </thead>
              <tbody>
                {liveWorkers.map((row) => (
                  <tr key={row.id}>
                    <td>
                      <b>{row.name}</b>
                      <small className="muted">
                        {row.capabilities.join(', ') || t('orchestration.workers.any')}
                      </small>
                    </td>
                    <td className="mono muted" title={t('orchestration.workers.slotsTitle')}>
                      {row.active_jobs ?? 0}/{row.max_concurrent ?? 1}</td>
                    <td><span className={`status st-${row.status}`}>
                      {tOr(`status.${row.status}`, row.status)}</span></td>
                    <td className="orch-actions">
                      <button className="mini" onClick={() => claim(row)}>
                        {t('orchestration.workers.claim')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="hint orch-empty">{t('orchestration.workers.empty')}</p>}
          {staleWorkers > 0 && (
            <p className="hint orch-empty">
              {t('orchestration.workers.staleNote', { n: staleWorkers })}
            </p>
          )}

          <div className="orch-door">
            <div>
              <b>{t('orchestration.workers.doorTitle')}</b>
              <small>{t('orchestration.workers.doorHint')}</small>
            </div>
            <button className="mini"
                    onClick={() => { window.location.hash = 'settings::runtime' }}>
              {t('orchestration.workers.doorAction')}
            </button>
          </div>
          {claimInfo && <p className="hint">{claimInfo}</p>}
        </section>
      </div>

      <section className="card orch-card">
        <header>
          <b>{t('orchestration.runs.title')}</b>
          <div className="orch-filters">
            {[['all', 'common.all'], ['internal', 'orchestration.origin.internal'],
              ['worker', 'orchestration.origin.worker'], ['cli', 'orchestration.origin.cli']]
              .map(([key, label]) => (
              <button key={key} className={filter === key ? 'on' : ''}
                      onClick={() => setFilter(key)}>
                {t(label)}
                {key !== 'all' && <span className="mono">{counts[key]}</span>}
              </button>
            ))}
          </div>
        </header>
        {paged.rows.length ? (
          <table className="orch-table orch-runs">
            <thead>
              <tr><th>{t('orchestration.runs.col.when')}</th>
                <th>{t('orchestration.runs.col.type')}</th>
                <th>{t('orchestration.runs.col.target')}</th>
                <th>{t('orchestration.runs.col.origin')}</th>
                <th>{t('common.status')}</th>
                <th>{t('orchestration.runs.col.took')}</th><th></th></tr>
            </thead>
            <tbody>
              {paged.rows.map((row) => (
                <tr key={row.key}>
                  <td className="mono muted">{new Date(row.when).toLocaleString()}</td>
                  <td><b>{row.type}</b>
                    {row.what && <small className="muted" title={row.what}>{row.what}</small>}</td>
                  <td className="mono" title={row.detail}>{row.detail}</td>
                  <td><span className={`orch-origin o-${row.origin}`}>
                    {tOr(`orchestration.origin.${row.origin}`, row.origin)}</span></td>
                  <td><span className={`status st-${row.status}`}>
                    {tOr(`status.${row.status}`, row.status)}</span></td>
                  <td className="mono muted">{duration(row, t)}</td>
                  <td className="orch-actions">
                    {row.kind === 'internal' && (
                      <button className="mini" onClick={() => openLog(row.raw)}>
                        {t('orchestration.action.log')}
                      </button>
                    )}
                    {row.kind === 'scan' && row.raw.scanner === 'shauron-surface' && (
                      <button className="mini"
                              onClick={() => { window.location.hash = `surface::${row.raw.id}` }}>
                        {t('orchestration.runs.flow')}
                      </button>
                    )}
                    {row.kind === 'scan'
                      && ['queued', 'leased', 'running'].includes(row.status) && (
                      <button className="mini" onClick={() => act(row.raw, 'cancel')}>
                        {t('orchestration.runs.cancel')}
                      </button>
                    )}
                    {row.kind === 'scan'
                      && ['failed', 'cancelled'].includes(row.status) && (
                      <button className="mini" onClick={() => act(row.raw, 'retry')}>
                        {t('common.retry')}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState title={t('orchestration.runs.emptyTitle')}
                      hint={t('orchestration.runs.emptyHint')} />
        )}
        <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
               total={paged.total} perPage={paged.perPage} unit={t('unit.runs')} />
      </section>

      <details className="card orch-setup">
        <summary>{t('orchestration.setup.title')}</summary>
        <p className="muted small">{t('orchestration.setup.intro')}</p>
        <table className="orch-table">
          <tbody>
            {scanners.map((row) => (
              <tr key={row.id}>
                <td><b>{row.name}</b></td>
                <td><span className="pill">{row.capability}</span></td>
                <td className="mono muted">{row.version || '—'}</td>
                <td>{row.enabled
                  ? t('orchestration.setup.enabled') : t('orchestration.setup.disabled')}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!scanners.length && <p className="hint orch-empty">{t('orchestration.setup.noScanner')}</p>}

        <div className="orch-setup-row">
          <select value={job.scanner} onChange={(e) => setJob((j) => ({ ...j, scanner: e.target.value }))}>
            <option value="">{t('orchestration.setup.scannerPlaceholder')}</option>
            {scanners.map((row) => <option key={row.id} value={row.name}>{row.name}</option>)}
          </select>
          <input placeholder={t('orchestration.setup.repositoryTarget')} value={job.target}
                 onChange={(e) => setJob((j) => ({ ...j, target: e.target.value }))} />
          <input placeholder={t('orchestration.setup.principal')} value={job.principal}
                 onChange={(e) => setJob((j) => ({ ...j, principal: e.target.value }))} />
          <input placeholder={t('orchestration.setup.environment')} value={job.environment}
                 onChange={(e) => setJob((j) => ({ ...j, environment: e.target.value }))} />
          <button onClick={queueJob}>{t('orchestration.setup.queue')}</button>
        </div>

        <div className="orch-setup-row">
          <input placeholder={t('orchestration.setup.scannerName')} value={scanner.name}
                 onChange={(e) => setScanner((s) => ({ ...s, name: e.target.value }))} />
          <select value={scanner.capability}
                  onChange={(e) => setScanner((s) => ({ ...s, capability: e.target.value }))}>
            {CAPS.map((cap) => <option key={cap} value={cap}>{cap}</option>)}
          </select>
          <input placeholder={t('orchestration.setup.version')} value={scanner.version}
                 onChange={(e) => setScanner((s) => ({ ...s, version: e.target.value }))} />
          <button onClick={addScanner}>{t('orchestration.setup.addScanner')}</button>
        </div>

        <div className="orch-setup-row">
          <input placeholder={t('orchestration.setup.workerName')} value={worker.name}
                 onChange={(e) => setWorker((w) => ({ ...w, name: e.target.value }))} />
          <input type="number" min="1" max="32" value={worker.max_concurrent}
                 onChange={(e) => setWorker((w) => ({ ...w, max_concurrent: Number(e.target.value) }))} />
          <button onClick={addWorker}>{t('orchestration.setup.addWorker')}</button>
        </div>
      </details>

      <Dialog open={newSchedule} title={t('orchestration.dialog.newSchedule')}
              confirmLabel={t('orchestration.dialog.create')}
              onClose={() => setNewSchedule(false)} onConfirm={addSchedule}>
        <div className="orch-form">
          <label>{t('orchestration.field.name')}<input value={schedule.name}
            onChange={(e) => setSchedule((s) => ({ ...s, name: e.target.value }))} /></label>
          <label>{t('orchestration.field.kind')}
            <select value={schedule.kind}
                    onChange={(e) => setSchedule((s) => ({ ...s, kind: e.target.value }))}>
              <option value="scan">{t('orchestration.kind.scan')}</option>
              <option value="easm">{t('orchestration.kind.easm')}</option>
            </select>
          </label>
          {schedule.kind === 'scan' ? (
            <>
              <label>{t('orchestration.field.scanner')}
                <select value={schedule.scanner}
                        onChange={(e) => setSchedule((s) => ({ ...s, scanner: e.target.value }))}>
                  <option value="">—</option>
                  {scanners.map((row) => <option key={row.id} value={row.name}>{row.name}</option>)}
                </select>
              </label>
              <label>{t('orchestration.field.repositoryTarget')}<input value={schedule.target}
                onChange={(e) => setSchedule((s) => ({ ...s, target: e.target.value }))} /></label>
            </>
          ) : (
            <label>{t('orchestration.field.domainAsset')}
              <select value={schedule.asset_id}
                      onChange={(e) => setSchedule((s) => ({ ...s, asset_id: e.target.value }))}>
                <option value="">—</option>
                {assets.filter((a) => ['domain', 'subdomain'].includes(a.type))
                  .map((a) => <option key={a.id} value={a.id}>{a.value}</option>)}
              </select>
            </label>
          )}
          <label>{t('orchestration.field.everyMinutes')}
            <input type="number" min="15" value={schedule.interval_minutes}
              onChange={(e) => setSchedule((s) => ({ ...s, interval_minutes: e.target.value }))} /></label>
          <label>{t('orchestration.field.principal')}<input value={schedule.principal}
            onChange={(e) => setSchedule((s) => ({ ...s, principal: e.target.value }))} /></label>
        </div>
      </Dialog>

      <Dialog open={Boolean(logRow)} size="wide" hideFooter
              title={logRow ? `${logRow.name || t('orchestration.log.defaultName')} · `
                + `${new Date(logRow.started_at).toLocaleString()} · `
                + `${tOr(`status.${logRow.status}`, logRow.status)}` : ''}
              onClose={() => setLogRow(null)}>
        {logRow && (
          <div className="stack">
            <p className="muted" style={{ margin: 0 }}>
              {t('orchestration.log.trigger', { trigger: logRow.trigger })}
              {logRow.actor ? ` · ${t('orchestration.log.by', { actor: logRow.actor })}` : ''} ·{' '}
              {logRow.duration_ms != null
                ? t('orchestration.time.seconds', { n: (logRow.duration_ms / 1000).toFixed(1) })
                : '—'}
            </p>
            <pre className="code mono" style={{ margin: 0 }}>
              {logRow.log || t('orchestration.log.empty')}
            </pre>
          </div>
        )}
      </Dialog>
    </div>
  )
}
