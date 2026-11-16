import React, { useEffect, useMemo, useState } from 'react'
import Icon from './icons'
import { api } from './api'
import { useI18n } from './i18n'
import { Card } from './ui'

/* The autonomous trace, drawn the way the data actually moved.

   A scanner finding's provenance is one run id. An agent's is a mission the
   operator approved, a task a worker claimed, and an ordered exchange: the tool it
   called, what came back, what it refused, and the verdict. That is the story this
   panel tells — one line per event, in order, with the request legible.

   "Usable" is not "we found something": it is the gates' verdict plus a replay that
   answered. The badge says which of the two you are looking at. */

const EVENT_ICON = {
  tool: 'pipelines',
  observation: 'search',
  refusal: 'gates',
  note: 'analysis',
  final: 'findings',
}

function when(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString()
}

function argvLine(payload) {
  const argv = payload?.argv || []
  if (!argv.length) return payload?.head ? String(payload.head).split('\n')[0] : ''
  return argv.map((part) => (/\s/.test(part) ? JSON.stringify(part) : part)).join(' ')
}

/* One tool call and the answer it got are one step: the diagram reads
   "asked for this → got that" instead of two unrelated boxes. */
function buildSteps(events) {
  const steps = []
  for (const event of events) {
    const last = steps[steps.length - 1]
    if (event.kind === 'observation' && last && last.kind === 'tool' && !last.observation) {
      last.observation = event
      continue
    }
    steps.push({ kind: event.kind, tool: event, observation: null })
  }
  return steps
}

function statusOf(step) {
  const head = step.observation?.payload?.head || ''
  const first = head.split('\n')[0].trim()
  if (first) return first
  if (step.kind === 'refusal') return step.tool?.payload?.why || ''
  if (step.kind === 'final') {
    // A verdict has no observation, so reading only `head` made the last card say
    // "no output recorded" about the one thing that says everything.
    const answer = (step.tool?.payload?.answer || '').split('\n')
      .map((line) => line.replace(/[#*`]/g, '').trim())
      .find((line) => line.length > 3)
    return answer || step.tool?.payload?.error || ''
  }
  return ''
}

export default function AgentTrace({ findingId }) {
  const { t } = useI18n()
  const [trace, setTrace] = useState(null)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(0)

  useEffect(() => {
    let alive = true
    api.get(`/api/v1/findings/${encodeURIComponent(findingId)}/trace`)
      .then((data) => { if (alive) setTrace(data.data) })
      .catch((caught) => { if (alive) setError(String(caught.message || caught)) })
    return () => { alive = false }
  }, [findingId])

  const events = useMemo(() => (trace?.events || []), [trace])
  const steps = useMemo(() => buildSteps(events), [events])
  const active = steps[Math.min(selected, Math.max(0, steps.length - 1))]

  if (error) return <div className="banner banner-error">{error}</div>
  if (!trace) return <div className="empty">{t('trace.loading')}</div>

  const autonomous = Boolean(trace.mission)
  if (!autonomous) {
    return (
      <div className="empty">
        <strong>{t('trace.none.title')}</strong>
        <span>{t('trace.none.body')}</span>
      </div>
    )
  }

  const failedGate = (trace.gates || []).find((gate) => gate.verdict === 'refuted')

  return (
    <div className="stack">
      <div className={`trace-verdict ${trace.usable ? 'usable' : 'unusable'}`}>
        <Icon name={trace.usable ? 'gates' : 'analysis'} size={16} />
        <div>
          <strong>
            {trace.usable ? t('trace.verdict.usable') : t('trace.verdict.notUsable')}
          </strong>
          <span>
            {t('trace.verdict.detail', {
              evidence: trace.finding?.evidence_level || '—',
              exploit: trace.finding?.exploit_state || '—',
            })}
          </span>
        </div>
      </div>

      <Card title={t('trace.mission.title')} band>
        <dl className="trace-grid">
          <dt>{t('trace.mission.goal')}</dt><dd>{trace.mission.goal}</dd>
          <dt>{t('trace.mission.lane')}</dt>
          <dd>{trace.mission.capability} · {trace.mission.profile}</dd>
          <dt>{t('trace.mission.approved')}</dt>
          <dd>{trace.mission.approved_by || '—'} · {trace.mission.status}</dd>
          <dt>{t('trace.mission.budget')}</dt>
          <dd>
            {t('trace.mission.budgetValue', {
              steps: trace.mission.budget?.steps ?? '—',
              tokens: trace.mission.budget?.tokens ?? '—',
            })}
          </dd>
          {trace.task && (
            <>
              <dt>{t('trace.mission.task')}</dt>
              <dd>
                {trace.task.kind} · {trace.task.worker || '—'} · {trace.task.status}
                {' · '}
                {t('trace.mission.attempts', { n: trace.task.attempts })}
              </dd>
            </>
          )}
        </dl>
      </Card>

      <Card title={t('trace.flow.title', { n: steps.length })} band
        actions={<span className="muted">
          {t('trace.flow.counts', {
            calls: steps.filter((step) => step.kind === 'tool').length,
            refused: steps.filter((step) => step.kind === 'refusal').length,
          })}
        </span>}>
        <div className="trace-flow">
          <ol className="trace-nodes">
            {steps.map((step, index) => (
              <li key={index} className={`trace-node-item ${step.kind}`}>
                {/* The flow is the order; the arrow between cards is the only thing
                    that says "and then". */}
                <button type="button"
                  className={`trace-node ${index === selected ? 'is-on' : ''}`}
                  onClick={() => setSelected(index)}
                  aria-current={index === selected ? 'step' : undefined}>
                  <span className="trace-node-index">{index + 1}</span>
                  <span className="trace-node-icon">
                    <Icon name={EVENT_ICON[step.kind] || 'search'} size={14} />
                  </span>
                  <span className="trace-node-body">
                    <span className="trace-node-title">
                      {step.kind === 'tool'
                        ? (argvLine(step.tool?.payload) || t('trace.kind.tool'))
                        : t(`trace.kind.${step.kind}`)}
                    </span>
                    <span className="trace-node-status">
                      {statusOf(step) || t('trace.flow.noStatus')}
                    </span>
                  </span>
                  <span className="trace-node-meta">
                    {step.observation?.payload?.bytes
                      ? t('trace.flow.bytes', { n: step.observation.payload.bytes })
                      : ''}
                  </span>
                </button>
              </li>
            ))}
          </ol>

          {/* The side panel: the step you clicked, spelled out. A diagram you cannot
              open is decoration, not evidence. */}
          <aside className="trace-detail">
            {active ? (
              <>
                <header>
                  <span className="trace-kind">{t(`trace.kind.${active.kind}`)}</span>
                  <span className="trace-at">{when(active.tool?.at)}</span>
                </header>
                {active.tool?.payload?.argv?.length > 0 && (
                  <>
                    <h5>{t('trace.detail.request')}</h5>
                    <pre className="trace-code">{argvLine(active.tool.payload)}</pre>
                  </>
                )}
                {active.kind === 'refusal' && (
                  <>
                    <h5>{t('trace.detail.refused')}</h5>
                    <p className="muted">{active.tool?.payload?.why}</p>
                    {active.tool?.payload?.target && (
                      <pre className="trace-code">{active.tool.payload.target}</pre>
                    )}
                  </>
                )}
                {active.observation && (
                  <>
                    <h5>{t('trace.detail.response')}</h5>
                    <p className="muted">
                      {t('trace.detail.exit', { rc: active.observation.payload?.rc ?? '—' })}
                      {' · '}
                      {t('trace.flow.bytes', { n: active.observation.payload?.bytes ?? 0 })}
                    </p>
                    <pre className="trace-code tall">
                      {active.observation.payload?.head || ''}
                    </pre>
                    {(active.observation.payload?.head || '').length
                      < (active.observation.payload?.bytes ?? 0) && (
                      /* The body in the record is the head of the response, not all of
                         it: saying so beats a page that ends mid-tag. */
                      <p className="muted">
                        {t('trace.detail.truncated', {
                          shown: (active.observation.payload?.head || '').length,
                          total: active.observation.payload?.bytes ?? 0,
                        })}
                      </p>
                    )}
                  </>
                )}
                {active.kind === 'final' && (
                  <>
                    <h5>{t('trace.detail.verdict')}</h5>
                    <pre className="trace-code tall">
                      {active.tool?.payload?.answer || active.tool?.payload?.error || ''}
                    </pre>
                  </>
                )}
                {active.kind === 'note' && (
                  <p className="muted">{active.tool?.payload?.text || ''}</p>
                )}
              </>
            ) : (
              <p className="muted">{t('trace.detail.pick')}</p>
            )}
          </aside>
        </div>
      </Card>

      <Card title={t('trace.gates.title')} band>
        {failedGate && (
          <div className="banner banner-error">
            {t('trace.gates.failed', { stage: failedGate.stage })}
          </div>
        )}
        <table>
          <thead>
            <tr>
              <th>{t('trace.gates.stage')}</th>
              <th>{t('trace.gates.verdict')}</th>
              <th>{t('trace.gates.reason')}</th>
            </tr>
          </thead>
          <tbody>
            {(trace.gates || []).map((gate) => (
              <tr key={gate.stage}>
                <td className="mono">{gate.stage}</td>
                <td>
                  <span className={`chip ${gate.verdict === 'confirmed' ? 'ok' : 'warn'}`}>
                    {gate.verdict}
                  </span>
                </td>
                <td className="muted">{gate.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card title={t('trace.repeats.title')} band>
        {(trace.repeats || []).length === 0 ? (
          <p className="muted">{t('trace.repeats.none')}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t('trace.repeats.at')}</th>
                <th>{t('trace.repeats.result')}</th>
                <th>{t('trace.repeats.steps')}</th>
              </tr>
            </thead>
            <tbody>
              {(trace.repeats || []).map((run) => (
                <tr key={run.id}>
                  <td className="muted">{when(run.at)}</td>
                  <td>{run.result}{run.error ? ` · ${run.error}` : ''}</td>
                  <td>{run.steps}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
