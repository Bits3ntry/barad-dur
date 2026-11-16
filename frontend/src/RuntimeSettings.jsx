import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Banner, Card } from './ui'
import { useI18n } from './i18n'

/* How many scans may run at once, and against whom.

   The screen shows the limits *and* the state they are acting on, because a cap
   without a queue is a number nobody can judge: "2 per zone" only means something
   next to "200 queued, 2 in flight on councilbox.com". Replicas are read-only on
   purpose — Barad-dûr runs in Docker and the replica count belongs to the
   orchestrator, not to a web form. */

const LIMITS = [
  { key: 'per_zone', labelKey: 'runtimeSettings.limit.perZone.label',
    hintKey: 'runtimeSettings.limit.perZone.hint', step: 1 },
  { key: 'per_org', labelKey: 'runtimeSettings.limit.perOrg.label',
    hintKey: 'runtimeSettings.limit.perOrg.hint', step: 1 },
  { key: 'per_worker', labelKey: 'runtimeSettings.limit.perWorker.label',
    hintKey: 'runtimeSettings.limit.perWorker.hint', step: 1 },
  { key: 'queue_ceiling', labelKey: 'runtimeSettings.limit.queueCeiling.label',
    hintKey: 'runtimeSettings.limit.queueCeiling.hint', step: 50 },
]

const POOL = [
  { key: 'min_workers', labelKey: 'runtimeSettings.pool.minWorkers.label',
    hintKey: 'runtimeSettings.pool.minWorkers.hint', step: 1 },
  { key: 'max_workers', labelKey: 'runtimeSettings.pool.maxWorkers.label',
    hintKey: 'runtimeSettings.pool.maxWorkers.hint', step: 1 },
  { key: 'scale_down_after_s', labelKey: 'runtimeSettings.pool.scaleDownAfter.label',
    hintKey: 'runtimeSettings.pool.scaleDownAfter.hint', step: 60 },
]

function Stepper({ value, low, high, step, onChange, disabled }) {
  const { t } = useI18n()
  const move = (delta) => {
    const next = Math.min(high, Math.max(low, value + delta))
    if (next !== value) onChange(next)
  }
  return (
    <div className="rt-stepper">
      <button type="button" onClick={() => move(-step)} disabled={disabled || value <= low}
              aria-label={t('runtimeSettings.decrease')}>−</button>
      <span className="mono">{value}</span>
      <button type="button" onClick={() => move(step)} disabled={disabled || value >= high}
              aria-label={t('runtimeSettings.increase')}>+</button>
    </div>
  )
}

function when(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

export default function RuntimeSettings() {
  const { t } = useI18n()
  const [data, setData] = useState(null)
  const [draft, setDraft] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState('')

  useEffect(() => { load() }, [])

  async function load() {
    setError('')
    try {
      const body = await api.get('/api/v1/surface/runtime')
      setData(body)
      setDraft(body.policy)
    } catch (err) {
      setError(err.message || String(err))
    }
  }

  const bounds = data?.bounds || {}
  const state = data?.state || {}
  const dirty = useMemo(() => Boolean(draft && data
    && JSON.stringify(draft) !== JSON.stringify(data.policy)), [draft, data])

  async function save() {
    setBusy(true); setError(''); setSaved('')
    try {
      const body = await api.put('/api/v1/surface/runtime',
        { ...draft, actor: 'console' })
      setData(body)
      setDraft(body.policy)
      setSaved(t('runtimeSettings.saved'))
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setBusy(false)
    }
  }

  if (!draft) {
    return <div className="settings-body rt-page">
      {error ? <Banner kind="error">{error}</Banner> : <p className="hint">{t('runtimeSettings.loading')}</p>}
    </div>
  }

  const workers = state.workers_online ?? 0
  const queue = state.queue ?? 0
  const perWorker = draft.per_worker || 1
  // What actually runs in parallel, for one busy zone: the smallest of the three.
  const parallel = Math.max(1, Math.min(draft.per_zone, draft.per_org, workers * perWorker || 1))

  return <div className="settings-body rt-page">
    <header className="rt-head">
      <div>
        <div className="rt-eyebrow">{t('runtimeSettings.eyebrow')}</div>
        <h2>{t('runtimeSettings.title')}</h2>
        <p className="hint">{t('runtimeSettings.intro.before')} <b>{t('runtimeSettings.intro.bold')}</b>{t('runtimeSettings.intro.after')}</p>
      </div>
      <div className="rt-actions">
        {dirty && <span className="rt-dirty">{t('runtimeSettings.unsaved')}</span>}
        <button className="btn-primary" onClick={save} disabled={busy || !dirty}>
          {busy ? t('runtimeSettings.saving') : t('runtimeSettings.save')}
        </button>
      </div>
    </header>

    {error && <Banner kind="error">{error}</Banner>}
    {saved && <p className="rt-saved">{saved}</p>}

    <div className="rt-strip">
      <div><span>{t('runtimeSettings.strip.workers')}</span><b className="mono">{workers}</b></div>
      <div><span>{t('runtimeSettings.strip.queue')}</span><b className="mono">{queue}</b></div>
      <div><span>{t('runtimeSettings.strip.inFlight')}</span><b className="mono">{state.in_flight ?? 0}</b></div>
      <div><span>{t('runtimeSettings.strip.poolTarget')}</span><b className="mono">
        {state.pool?.target ?? '—'}
        <small> / {state.pool?.max ?? '—'} · {state.pool?.binding || ''}</small>
      </b></div>
    </div>

    <div className="rt-grid">
      <Card title={t('runtimeSettings.limits.title')}>
        <div className="rt-fields">
          {LIMITS.map((row) => {
            const [low, high] = bounds[row.key] || [1, 99]
            return <div className="rt-field" key={row.key}>
              <div className="rt-label">
                <b>{t(row.labelKey)}</b>
                <small>{t(row.hintKey)}</small>
              </div>
              <Stepper value={draft[row.key]} low={low} high={high} step={row.step}
                       disabled={busy}
                       onChange={(next) => setDraft({ ...draft, [row.key]: next })} />
            </div>
          })}

          {POOL.map((row) => {
            const [low, high] = bounds[row.key] || [1, 99]
            return <div className="rt-field" key={row.key}>
              <div className="rt-label">
                <b>{t(row.labelKey)}</b>
                <small>{t(row.hintKey)}</small>
              </div>
              <Stepper value={draft[row.key]} low={low} high={high} step={row.step}
                       disabled={busy}
                       onChange={(next) => setDraft({ ...draft, [row.key]: next })} />
            </div>
          })}

          <div className="rt-field rt-locked">
            <div className="rt-label">
              <b>{t('runtimeSettings.replicas.title')}</b>
              <small>{t('runtimeSettings.replicas.hint')} <code>docker service scale</code></small>
            </div>
            <span className="rt-pill">
              {t('runtimeSettings.replicas.pill', { target: state.pool?.target ?? '—', alive: workers,
                registered: state.workers_registered ?? workers })}
            </span>
          </div>
        </div>

        <div className="rt-preview">
          <div>
            {queue > 0
              ? <>{t('runtimeSettings.preview.queued', { queue, parallel })}
                {state.in_flight ? t('runtimeSettings.preview.inFlight', { n: state.in_flight }) : ''}</>
              : <>{t(parallel === 1 ? 'runtimeSettings.preview.idleOne' : 'runtimeSettings.preview.idle', { parallel })}</>}
          </div>
          <div className="rt-bar"><i style={{ width: `${Math.min(100, (parallel / 8) * 100)}%` }} /></div>
          <small className="hint">
            {t('runtimeSettings.preview.note', { zone: draft.per_zone, min: draft.min_workers })}
          </small>
        </div>
      </Card>

      <Card title={t('runtimeSettings.waiting.title')}>
        {!(state.waiting || []).length ? (
          <p className="hint">{t('runtimeSettings.waiting.empty')}</p>
        ) : (
          <table className="rt-table">
            <tbody>
              {(state.waiting || []).map((row) => (
                <tr key={row.job_id}>
                  <td className="mono">{row.targets
                    ? (JSON.parse(row.targets)[0] || {}).value || row.job_id.slice(0, 8)
                    : row.job_id.slice(0, 8)}</td>
                  <td className={row.reason.startsWith('waiting for a worker') ? 'rt-ok' : 'rt-warn'}>
                    {t('runtimeSettings.waiting.queued')}
                  </td>
                  <td className="rt-why">{row.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="hint rt-foot">
          {t('runtimeSettings.foot.before')} <code>platform_settings</code>{t('runtimeSettings.foot.after')}
          {data.updated_at ? t('runtimeSettings.foot.lastChange', { when: when(data.updated_at) }) : ''}
        </p>
      </Card>
    </div>

    <p className="hint">
      {t('runtimeSettings.footnote')}
    </p>
  </div>
}
