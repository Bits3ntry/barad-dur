import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Banner, EmptyState, Loading } from './ui'
import { useI18n } from './i18n'

/* The channel as relations (A6). Everything here is a projection of three tables —
   `chat_turns`, `ai_steps`, `agent_task_events` — merged by time on the server. This
   screen exists so the operator can see *who asked whom for what*: the orchestrator
   delegating, a specialist handing back claims, a field agent running a tool, and every
   refusal as a card. It never writes. */

const ICON = {
  said: '💬',
  delegated: '↳',
  field_step: '▶',
  tool: '⚙',
  observation: '👁',
  refusal: '⛔',
  final: '✔',
}

function oneLine(value, limit = 160) {
  const text = typeof value === 'string' ? value : JSON.stringify(value || {})
  const flat = (text || '').replace(/\s+/g, ' ').trim()
  return flat.length > limit ? `${flat.slice(0, limit)}…` : flat
}

function EventBody({ event, t, tCount }) {
  if (event.kind === 'said') {
    return <p className="thread-text">{oneLine(event.content, 320)}</p>
  }
  if (event.kind === 'delegated') {
    return (
      <div className="thread-detail">
        <span>{tCount('thread.calls', (event.tools || []).length)}</span>
        <span>{t('thread.tokens', { n: event.tokens || 0 })}</span>
        {event.prompt_version && <code>{event.prompt_version}</code>}
        {(event.tools || []).length > 0 && (
          <span className="thread-tools">{event.tools.map((tool) => (
            <code key={tool}>{tool}</code>
          ))}</span>
        )}
        {(event.claims || []).length > 0 && (
          <ul className="thread-claims">
            {event.claims.slice(0, 4).map((claim, index) => (
              <li key={index} className={claim.invalid ? 'claim-invalid' : ''}>
                <span className={`claim-level claim-${claim.level || 'hypothesis'}`}>
                  {claim.level || 'hypothesis'}
                </span>
                {' '}{oneLine(claim.text, 140)}
                {claim.invalid && <span className="claim-badge">{t('thread.invalid')}</span>}
              </li>
            ))}
          </ul>
        )}
        {(event.skipped || []).length > 0 && (
          <p className="thread-skipped">{t('thread.skipped')}: {event.skipped.join(' · ')}</p>
        )}
      </div>
    )
  }
  if (event.kind === 'field_step') {
    return (
      <div className="thread-detail">
        <span>{t('thread.tokens', { n: event.tokens || 0 })}</span>
        {event.prompt_version && <code>{event.prompt_version}</code>}
        {(event.tools || []).length > 0 && (
          <span className="thread-tools">{event.tools.map((tool, index) => (
            <code key={index}>{tool}</code>
          ))}</span>
        )}
      </div>
    )
  }
  const payload = event.payload || {}
  return (
    <p className="thread-text">
      {payload.tool ? <code>{payload.tool}</code> : null}{' '}
      {payload.why || payload.state || payload.head || payload.argv
        ? oneLine(payload.why || payload.state || payload.head || payload.argv)
        : null}
    </p>
  )
}

export default function Thread({ sessionId }) {
  const { t, tOr, tCount } = useI18n()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!sessionId) { setData(null); return }
    let live = true
    api.get(`/api/v1/ai/sessions/${sessionId}/thread`)
      .then((body) => { if (live) { setData(body.data); setError('') } })
      .catch((caught) => { if (live) setError(String(caught.message || caught)) })
    return () => { live = false }
  }, [sessionId])

  if (!sessionId) return <EmptyState title={t('thread.empty.title')}
                                     hint={t('thread.empty.hint')} />
  if (error) return <Banner kind="error">{error}</Banner>
  if (!data) return <Loading label={t('thread.loading')} />
  if (!(data.events || []).length) {
    return <EmptyState title={t('thread.empty.title')} hint={t('thread.empty.hint')} />
  }

  return (
    <div className="thread">
      <p className="thread-totals muted">
        {tCount('thread.events', data.totals.events)} ·{' '}
        {tCount('thread.runs', data.totals.runs)} ·{' '}
        {t('thread.tokens', { n: data.totals.tokens })}
      </p>
      <ol className="thread-events">
        {(data.events || []).map((event, index) => (
          <li key={`${event.kind}-${index}`} className={`thread-event kind-${event.kind}`}>
            <span className="thread-icon" aria-hidden>{ICON[event.kind] || '·'}</span>
            <div className="thread-main">
              <div className="thread-head">
                <span className="thread-author">{event.author || '—'}</span>
                <span className="thread-kind">
                  {tOr(`thread.kind.${event.kind}`, event.kind)}
                </span>
                <span className="thread-at">{(event.at || '').replace('T', ' ').slice(0, 19)}</span>
              </div>
              <EventBody event={event} t={t} tCount={tCount} />
            </div>
          </li>
        ))}
      </ol>
    </div>
  )
}
