import React, { useCallback, useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Card, EmptyState, Loading, PageHeader } from './ui'
import { useI18n } from './i18n'

/* The run ledger (F2): what the orchestrator actually did, step by step.
   A run is the receipt of an answer — the question, the plan, the tool calls with
   the ids they read, and the claims that survived validation. If a claim was
   downgraded, it says INVALID here instead of quietly disappearing. */

const STATUS_KEY = {
  running: 'status.running',
  answered: 'aiRuns.status.answered',
  failed: 'status.failed',
  stopped_no_provider: 'aiRuns.status.noProvider',
  stopped_budget: 'aiRuns.status.budget',
  stopped_max_steps: 'aiRuns.status.maxSteps',
  stopped_no_progress: 'aiRuns.status.noProgress',
}

function statusClass(status) {
  if (status === 'answered') return 'run-ok'
  if (status === 'running') return 'run-live'
  return 'run-warn'
}

function shortId(value) {
  return value ? `${value.slice(0, 8)}…` : '—'
}

function duration(run) {
  if (!run.started_at || !run.finished_at) return '—'
  const ms = new Date(run.finished_at) - new Date(run.started_at)
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`
}

export default function AiRuns({ focus = {} }) {
  const { t, tOr, tCount } = useI18n()
  const [runs, setRuns] = useState([])
  const [active, setActive] = useState('')
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const body = await api.get('/api/v1/ai/runs?limit=50')
      setRuns(body.data || [])
      setError('')
      if (!active && (body.data || []).length) setActive(body.data[0].id)
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setLoading(false)
    }
  }, [active])

  useEffect(() => { load() }, [load])

  // A receipt linked from a chat answer: `#ai-runs::<id>` opens that run instead of
  // the newest one, so "which run cost that?" is a link somebody can send.
  useEffect(() => {
    if (focus.runId) setActive(focus.runId)
  }, [focus.runId])

  useEffect(() => {
    if (!active) { setDetail(null); return }
    let live = true
    api.get(`/api/v1/ai/runs/${active}`)
      .then((body) => { if (live) setDetail(body.data) })
      .catch((caught) => { if (live) setError(String(caught.message || caught)) })
    return () => { live = false }
  }, [active])

  if (loading) return <Loading label={t('aiRuns.loading')} />

  return (
    <div className="runs-page">
      <PageHeader
        title={t('aiRuns.title')}
        subtitle={t('aiRuns.subtitle')}
        actions={<button className="btn-ghost" onClick={load}>{t('common.refresh')}</button>}
      />
      {error && <Banner kind="error">{error}</Banner>}
      {runs.length === 0 && (
        <EmptyState title={t('aiRuns.empty.title')}
          hint={t('aiRuns.empty.hint')} />
      )}
      {runs.length > 0 && (
        <div className="runs-layout">
          <aside className="runs-rail" aria-label={t('aiRuns.runsAria')}>
            {runs.map((run) => (
              <button key={run.id}
                className={`runs-rail-item${active === run.id ? ' active' : ''}`}
                onClick={() => setActive(run.id)}>
                <span className="runs-rail-title">{run.question}</span>
                <span className="runs-rail-meta">
                  <span className={statusClass(run.status)}>
                    {tOr(STATUS_KEY[run.status] || `aiRuns.status.${run.status}`, run.status)}
                  </span>
                  <span>{tCount('aiRuns.steps', run.steps)}</span>
                  <span>{duration(run)}</span>
                </span>
              </button>
            ))}
          </aside>
          <section className="runs-main">
            {!detail && <Loading label={t('aiRuns.loadingDetail')} />}
            {detail && <RunDetail run={detail} />}
          </section>
        </div>
      )}
    </div>
  )
}

function RunDetail({ run }) {
  const { t, tOr, tCount } = useI18n()
  const steps = run.step_rows || []
  const cited = new Set()
  for (const step of steps) {
    for (const call of step.tool_calls || []) {
      for (const ref of call.refs || []) cited.add(ref)
    }
  }
  return (
    <div className="stack">
      <Card title={t('aiRuns.card.question')}>
        <p className="run-question">{run.question}</p>
        <div className="run-meta">
          <span className={`pill ${statusClass(run.status)}`}>
            {tOr(STATUS_KEY[run.status] || `aiRuns.status.${run.status}`, run.status)}
          </span>
          <span className="pill">{run.mode}</span>
          <span className="pill">{tCount('aiRuns.steps', run.steps)}</span>
          <span className="pill">{tCount('aiRuns.toolCalls', run.tool_calls)}</span>
          <span className="pill">
            {t('aiRuns.tokensSplit', { input: run.tokens_in, output: run.tokens_out })}
          </span>
          {run.cached_tokens > 0 && (
            <span className="pill pill-active">
              {t('aiRuns.cached', { n: run.cached_tokens })}
            </span>
          )}
          <span className="pill">
            {run.price_known ? `$${(run.cost_usd || 0).toFixed(4)}` : t('aiRuns.priceUnknown')}
          </span>
          <span className="pill">{duration(run)}</span>
          <span className="pill">{t('aiRuns.asRole', { role: run.role })}</span>
        </div>
        {run.stop_reason && <p className="run-stop">{t('aiRuns.stopped', { reason: run.stop_reason })}</p>}
        {run.error && <Banner kind="error">{run.error}</Banner>}
      </Card>

      {run.answer && (
        <Card title={t('aiRuns.card.answer')}>
          <div className="run-answer">{run.answer}</div>
        </Card>
      )}

      <Card title={tCount('aiRuns.plan', steps.length)}>
        {steps.length === 0 && (
          <p className="muted">
            {t('aiRuns.noSteps', { reason: run.stop_reason || t('aiRuns.noStepsReason') })}
          </p>
        )}
        <ol className="run-steps">
          {steps.map((step) => (
            <li key={step.seq} className="run-step">
              <div className="run-step-head">
                <span className="run-step-role">{step.role}</span>
                <span className="run-step-seq">#{step.seq}</span>
                {step.prompt_version && <span className="run-step-prompt">{step.prompt_version}</span>}
                <span className="run-step-cost">
                  {step.cost_usd == null ? t('aiRuns.priceUnknown') : `$${step.cost_usd.toFixed(5)}`}
                </span>
                {/* Whatever the endpoint reported beyond the counters, verbatim: a
                    flat plan meters an allowance here, and the drawer says so
                    without pretending to interpret it. */}
                {step.usage && Object.keys(step.usage).length > 0 && (
                  <span className="run-step-usage" title={JSON.stringify(step.usage)}>
                    {Object.keys(step.usage).join(' · ')}
                  </span>
                )}
              </div>
              {(step.tool_calls || []).length > 0 && (
                <ul className="run-calls">
                  {step.tool_calls.map((call, index) => (
                    <li key={index}>
                      <code>{call.tool}</code>
                      {call.status !== 200 && <span className="run-call-bad">{t('aiRuns.callFailed')}</span>}
                      {(call.refs || []).length > 0 && (
                        <span className="run-refs">
                          {(call.refs || []).slice(0, 8).map((ref) => (
                            <span className="run-ref" key={ref}>{ref}</span>
                          ))}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
              {step.handoff && (step.handoff.claims || []).length > 0 && (
                <ul className="run-claims">
                  {step.handoff.claims.map((claim, index) => (
                    <li key={index} className={claim.invalid ? 'claim-invalid' : ''}>
                      <span className={`claim-level claim-${claim.level}`}>{claim.level}</span>
                      <span>{claim.text}</span>
                      {claim.invalid && <span className="claim-badge">{t('aiRuns.invalidRefs')}</span>}
                    </li>
                  ))}
                </ul>
              )}
              {step.handoff && (step.handoff.open_questions || []).length > 0 && (
                <ul className="run-questions">
                  {step.handoff.open_questions.map((question, index) => (
                    <li key={index}>{question}</li>
                  ))}
                </ul>
              )}
              {/* A specialist the ceiling refused to run: the answer is partial and
                  the receipt says which question was never asked. */}
              {step.handoff && (step.handoff.skipped || []).length > 0 && (
                <ul className="run-skipped">
                  {step.handoff.skipped.map((note, index) => (
                    <li key={index}>{t('aiRuns.skipped')}: {note}</li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ol>
      </Card>

      {cited.size > 0 && (
        <Card title={t('aiRuns.idsCited', { n: cited.size })}>
          <div className="run-refs run-refs-wide">
            {Array.from(cited).sort().map((ref) => (
              <span className="run-ref" key={ref}>{ref}</span>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
