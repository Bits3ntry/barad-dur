import React, { useCallback, useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Card, EmptyState, Loading, PageHeader } from './ui'
import { useI18n } from './i18n'

/* Missions (F4): the operator's authorization, read before anything runs.
   The screen is deliberately blunt about the two things that matter — what the
   envelope allows, and what the field agent actually did. A refusal from the API
   (a target outside scope) is shown verbatim: it is the product, not an error. */

const CAPABILITIES = [
  { value: 'validate', labelKey: 'missions.capability.validate', profile: 'angmar' },
  { value: 'discover', labelKey: 'missions.capability.discover', profile: 'morgoth' },
  { value: 'exploit', labelKey: 'missions.capability.exploit', profile: 'morgoth' },
]

const STATUS_CLASS = {
  approved: 'run-live', running: 'run-live', done: 'run-ok',
  failed: 'run-warn', revoked: 'run-warn', draft: 'run-warn',
}

const STATUS_KEY = {
  approved: 'missions.status.approved',
  running: 'status.running',
  done: 'missions.status.done',
  failed: 'status.failed',
  revoked: 'missions.status.revoked',
  draft: 'missions.status.draft',
}

function statusLabel(status, tOr) {
  return tOr(STATUS_KEY[status] || `missions.status.${status}`, status)
}

function stamp(value) {
  return value ? new Date(value).toLocaleString() : '—'
}

export default function Missions() {
  const { t, tOr, tCount } = useI18n()
  const [missions, setMissions] = useState([])
  const [active, setActive] = useState('')
  const [detail, setDetail] = useState(null)
  const [events, setEvents] = useState({})
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [pending, setPending] = useState([])

  const load = useCallback(async () => {
    try {
      // What waits on a human, in the one queue that answers it: missions to
      // approve, runs paused for a decision and candidates to judge. It moved
      // here from the catalogue, which had no business owning a work queue.
      const [body, inbox] = await Promise.all([
        api.get('/api/v1/agent/missions?limit=50'),
        api.get('/api/v1/agents/inbox').catch(() => ({ data: [] })),
      ])
      setPending(inbox.data || [])
      setMissions(body.data || [])
      setError('')
      if (!active && (body.data || []).length) setActive(body.data[0].id)
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setLoading(false)
    }
  }, [active])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!active) { setDetail(null); return }
    let live = true
    api.get(`/api/v1/agent/missions/${active}`)
      .then((body) => { if (live) setDetail(body.data) })
      .catch((caught) => { if (live) setError(String(caught.message || caught)) })
    return () => { live = false }
  }, [active])

  async function openTask(taskId) {
    try {
      const body = await api.get(`/api/v1/agent/tasks/${taskId}/events`)
      setEvents((current) => ({ ...current, [taskId]: body.data || [] }))
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }

  async function revoke(mission) {
    try {
      const body = await api.post(`/api/v1/agent/missions/${mission.id}/revoke?actor=console`, {})
      setNotice(tCount('missions.notice.revoked', body.stopped))
      await load()
      const fresh = await api.get(`/api/v1/agent/missions/${mission.id}`)
      setDetail(fresh.data)
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }

  if (loading) return <Loading label={t('missions.loading')} />

  return (
    <div className="runs-page">
      <PageHeader
        title={t('missions.title')}
        subtitle={t('missions.subtitle')}
        actions={(
          <div className="row" style={{ gap: 8 }}>
            <button className="btn-ghost" onClick={load}>{t('common.refresh')}</button>
            <button className="btn-primary" onClick={() => setCreating((v) => !v)}>
              {creating ? t('common.close') : t('missions.new')}
            </button>
          </div>
        )}
      />
      {error && <Banner kind="error">{error}</Banner>}
      {notice && <Banner kind="ok">{notice}</Banner>}

      {pending.length > 0 && (
        <Card title={tCount('missions.pending.title', pending.length)}>
          <p className="settings-note">{t('missions.pending.hint')}</p>
          <div className="stack" style={{ gap: 6 }}>
            {pending.map((row) => (
              <div key={`${row.kind}:${row.id}`} className="row" style={{ gap: 8, alignItems: 'baseline' }}>
                <span className="pill">{tOr(`missions.pending.kind.${row.kind}`, row.kind)}</span>
                <strong>{row.title}</strong>
                <span className="muted">{row.detail}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {creating && (
        <CreateMission onCreated={async (mission) => {
          setCreating(false)
          setNotice(t('missions.notice.authorized'))
          await load()
          setActive(mission.id)
        }} onError={setError} />
      )}

      {missions.length === 0 && !creating && (
        <EmptyState title={t('missions.empty.title')}
          hint={t('missions.empty.hint')} />
      )}

      {missions.length > 0 && (
        <div className="runs-layout">
          <aside className="runs-rail" aria-label={t('missions.railAria')}>
            {missions.map((mission) => (
              <button key={mission.id}
                className={`runs-rail-item${active === mission.id ? ' active' : ''}`}
                onClick={() => setActive(mission.id)}>
                <span className="runs-rail-title">{mission.goal}</span>
                <span className="runs-rail-meta">
                  <span className={STATUS_CLASS[mission.status] || ''}>
                    {statusLabel(mission.status, tOr)}
                  </span>
                  <span>{mission.capability}</span>
                  <span>{tCount('missions.tasks', mission.tasks)}</span>
                </span>
              </button>
            ))}
          </aside>
          <section className="runs-main">
            {!detail && <Loading label={t('missions.loadingDetail')} />}
            {detail && (
              <MissionDetail mission={detail} events={events}
                onOpenTask={openTask} onRevoke={revoke} />
            )}
          </section>
        </div>
      )}
    </div>
  )
}

function CreateMission({ onCreated, onError }) {
  const { t } = useI18n()
  const [form, setForm] = useState({
    goal: '', capability: 'validate', target: '', tools: 'curl, python',
    tokens: 20000, steps: 10, usd: 0.5, minutes: 30, actor: 'console',
  })
  const [busy, setBusy] = useState(false)

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    onError('')
    try {
      const body = await api.post('/api/v1/agent/missions', {
        goal: form.goal,
        capability: form.capability,
        targets: [{ kind: 'url', value: form.target, methods: ['GET', 'POST'] }],
        tools: form.tools.split(',').map((tool) => tool.trim()).filter(Boolean),
        budget: { steps: Number(form.steps), tokens: Number(form.tokens),
                  wall_s: 900, usd: Number(form.usd) },
        deadline_minutes: Number(form.minutes),
        actor: form.actor,
      })
      onCreated(body.data)
    } catch (caught) {
      onError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title={t('missions.form.title')}>
      <form className="stack" onSubmit={submit}>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <input placeholder={t('missions.form.goalPlaceholder')}
            value={form.goal} style={{ flex: 2, minWidth: 280 }}
            onChange={(e) => setForm({ ...form, goal: e.target.value })} />
          <select value={form.capability}
            onChange={(e) => setForm({ ...form, capability: e.target.value })}>
            {CAPABILITIES.map((cap) => (
              <option key={cap.value} value={cap.value}>{t(cap.labelKey)}</option>
            ))}
          </select>
        </div>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <input placeholder={t('missions.form.targetPlaceholder')}
            value={form.target} style={{ flex: 2, minWidth: 260 }}
            onChange={(e) => setForm({ ...form, target: e.target.value })} />
          <input placeholder={t('missions.form.toolsPlaceholder')} value={form.tools}
            onChange={(e) => setForm({ ...form, tools: e.target.value })} />
        </div>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <input placeholder={t('missions.form.tokens')} value={form.tokens}
            onChange={(e) => setForm({ ...form, tokens: e.target.value })} />
          <input placeholder={t('missions.form.steps')} value={form.steps}
            onChange={(e) => setForm({ ...form, steps: e.target.value })} />
          <input placeholder={t('missions.form.usd')} value={form.usd}
            onChange={(e) => setForm({ ...form, usd: e.target.value })} />
          <input placeholder={t('missions.form.minutes')} value={form.minutes}
            onChange={(e) => setForm({ ...form, minutes: e.target.value })} />
          <button className="btn-primary" disabled={busy || !form.goal || !form.target}>
            {t('missions.form.authorize')}
          </button>
        </div>
        <p className="muted" style={{ fontSize: 11.5 }}>
          {t('missions.form.note')}
        </p>
      </form>
    </Card>
  )
}

function MissionDetail({ mission, events, onOpenTask, onRevoke }) {
  const { t, tOr, tCount } = useI18n()
  const budget = mission.budget || {}
  return (
    <div className="stack">
      <Card title={t('missions.envelope.title')}>
        <p className="run-question">{mission.goal}</p>
        <div className="run-meta">
          <span className={`pill ${STATUS_CLASS[mission.status] || ''}`}>{statusLabel(mission.status, tOr)}</span>
          <span className="pill">{mission.profile || '—'}</span>
          <span className="pill">{mission.capability}</span>
          <span className="pill">{t('missions.tokens', { n: budget.tokens ?? '—' })}</span>
          <span className="pill">{tCount('missions.steps', budget.steps ?? '—')}</span>
          <span className="pill">${budget.usd ?? 0}</span>
          <span className="pill">{t('missions.envelope.deadline', { when: stamp(mission.deadline_at) })}</span>
        </div>
        <ul className="run-calls" style={{ marginTop: 10 }}>
          {(mission.targets || []).map((target) => (
            <li key={target.value}>
              <code>{target.kind}</code> {target.value}
              <span className="run-refs">
                {(target.methods || []).map((method) => (
                  <span className="run-ref" key={method}>{method}</span>
                ))}
              </span>
            </li>
          ))}
        </ul>
        <ul className="run-calls">
          {(mission.tools || []).map((tool) => (
            <li key={tool}><code>{tool}</code> <span className="muted">{t('missions.envelope.allowed')}</span></li>
          ))}
        </ul>
        {mission.signature && (
          <p className="muted" style={{ fontSize: 11 }}>
            {t('missions.envelope.signed', { sig: mission.signature.slice(0, 22) })}
          </p>
        )}
        {mission.status !== 'revoked' && mission.status !== 'done' && (
          <button className="mini btn-danger" onClick={() => onRevoke(mission)}>
            {t('missions.envelope.revoke')}
          </button>
        )}
        {mission.revoked_at && (
          <p className="run-stop">
            {t('missions.envelope.revokedBy', { actor: mission.revoked_by, when: stamp(mission.revoked_at) })}
          </p>
        )}
      </Card>

      <Card title={t('missions.tasksTitle', { n: (mission.task_rows || []).length })}>
        {(mission.task_rows || []).length === 0 && (
          <p className="muted">{t('missions.noTasks')}</p>
        )}
        <ol className="run-steps">
          {(mission.task_rows || []).map((task) => (
            <li key={task.id} className="run-step">
              <div className="run-step-head">
                <span className="run-step-role">{task.kind}</span>
                <span className={`pill ${task.status === 'done' ? 'run-ok' : ''}`}>{task.status}</span>
                <span className="run-step-seq">{t('missions.task.attempt', { n: task.attempts })}</span>
                {task.worker && <span className="run-step-prompt">{task.worker}</span>}
                <button className="mini" style={{ marginLeft: 'auto' }}
                  onClick={() => onOpenTask(task.id)}>{t('missions.task.events')}</button>
              </div>
              <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                {t('missions.task.mustReturn', {
                  target: (task.target || {}).value,
                  list: (task.must_return || []).join(', '),
                })}
              </p>
              {(events[task.id] || []).length > 0 && (
                <ul className="run-calls">
                  {events[task.id].map((event) => (
                    <li key={event.seq}>
                      <code>{event.kind}</code>
                      {event.tool && <span className="muted">{event.tool}</span>}
                      <span className="run-refs">
                        <span className="run-ref">
                          {JSON.stringify(event.payload).slice(0, 90)}
                        </span>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {task.result && (
                <p className="muted" style={{ fontSize: 12 }}>
                  {t('missions.task.result', { result: JSON.stringify(task.result).slice(0, 160) })}
                </p>
              )}
            </li>
          ))}
        </ol>
      </Card>
    </div>
  )
}
