import React, { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './api'
import Icon from './icons'
import { Banner, EmptyState, Loading, PageHeader } from './ui'
import { useI18n } from './i18n'
import Thread from './Thread'

/* One conversation, two surfaces (§4c): this screen and the floating panel. The
   conversation body is exported so the panel cannot grow a second implementation
   of "render a turn" — a lookalike would drift within a week. */

const PROFILE_LABEL = { palantir: 'Palantír', angmar: 'Angmar', morgoth: 'Morgoth' }

function roleLabel(turn, t) {
  if (turn.role === 'user') return t('chat.role.you')
  if (turn.role === 'specialist') return `@${turn.profile || 'specialist'}`
  return PROFILE_LABEL[turn.profile] || 'Shauron'
}

/* A purl or a uuid does not fit in a chip, and the half that identifies it is the
   tail. The full value stays in the title and in the run behind the chip. */
function shortRef(ref) {
  const text = String(ref || '')
  if (text.length <= 26) return text
  if (text.startsWith('pkg:')) {
    const at = text.lastIndexOf('@')
    const name = at > 0 ? text.slice(text.lastIndexOf('/', at) + 1, at) : text
    return name.length <= 24 ? name : `${name.slice(0, 22)}…`
  }
  return `${text.slice(0, 12)}…${text.slice(-8)}`
}

export function useSessions() {
  const [sessions, setSessions] = useState([])
  const [error, setError] = useState('')
  const reload = useCallback(async () => {
    try {
      const body = await api.get('/api/v1/ai/sessions')
      setSessions(body.data || [])
      setError('')
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }, [])
  useEffect(() => { reload() }, [reload])
  return { sessions, setSessions, reload, error }
}

export function Conversation({ sessionId, compact = false, onTurn, onNavigate }) {
  const { t, tOr, tCount } = useI18n()
  const [session, setSession] = useState(null)
  const [question, setQuestion] = useState('')
  // `@name` is how the operator hands a question to one agent instead of the
  // orchestrator. The suggestion list reads the same catalogue the Agents screen
  // shows, so a mention can never name an agent the console does not have.
  const [mention, setMention] = useState(null)
  const areaRef = useRef(null)
  const [busy, setBusy] = useState(false)
  // The turn is synchronous: the server cannot stream steps yet, so the UI
  // shows elapsed time. A fake step counter would be worse than none.
  const [startedAt, setStartedAt] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [error, setError] = useState('')
  const endRef = useRef(null)

  useEffect(() => {
    if (!busy) { setElapsed(0); return undefined }
    const timer = setInterval(
      () => setElapsed(Math.round((Date.now() - startedAt) / 1000)), 1000)
    return () => clearInterval(timer)
  }, [busy, startedAt])

  const load = useCallback(async () => {
    if (!sessionId) { setSession(null); return }
    try {
      const body = await api.get(`/api/v1/ai/sessions/${sessionId}`)
      setSession(body.data)
      setError('')
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }, [sessionId])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end', behavior: 'smooth' })
  }, [session?.turn_rows?.length, busy])

  /* The loop runs off the request (A4): the turn comes back `pending` with its run id
     and we poll the run until it closes, then read the turn it wrote. The elapsed
     counter above measures this wait, so it is honest instead of decorative. */
  async function waitForRun(runId) {
    const started = Date.now()
    while (Date.now() - started < 6 * 60 * 1000) {
      await new Promise((resolve) => setTimeout(resolve, 1500))
      try {
        const body = await api.get(`/api/v1/ai/runs/${runId}`)
        const status = body?.data?.status
        if (status && status !== 'running') return body.data
      } catch {
        // A lost poll is not a lost run: it closes itself and the ledger has it.
        return null
      }
    }
    return null
  }

  // One path for both: typing a question and pressing a button under an answer are the
  // same act. Two implementations of this is how a receipt ends up on one of them.
  const submit = async (text) => {
    if (!text || !sessionId || busy) return
    setBusy(true)
    setStartedAt(Date.now())
    setError('')
    setQuestion('')
    try {
      const body = await api.post(`/api/v1/ai/sessions/${sessionId}/turns`,
                                  { question: text, background: true })
      const runId = body?.data?.run?.id
      const finished = body?.data?.pending && runId ? await waitForRun(runId) : null
      await load()
      // The run that ended without an answer says why: a swept run (the process died)
      // used to leave the operator staring at their own question.
      if (finished && finished.status && finished.status !== 'answered') {
        setError(finished.error || finished.stop_reason || `the run ended as ${finished.status}`)
      }
      onTurn?.(body.data)
    } catch (caught) {
      setError(String(caught.message || caught))
      setQuestion(text)
    } finally {
      setBusy(false)
    }
  }

  const send = async (event) => {
    event.preventDefault()
    const text = question.trim()
    setQuestion('')
    await submit(text)
  }

  // A suggestion is either a place to go or a sentence to send — never a new endpoint.
  // The platform already validated both before the button reached the screen.
  const takeSuggestion = async (suggestion) => {
    if (suggestion.href) {
      const [screen, arg] = suggestion.href.replace(/^#/, "").split("::")
      if (screen === "ai-runs" && arg) onNavigate?.("ai-runs", { runId: arg })
      else onNavigate?.(screen, arg ? { q: arg } : {})
      return
    }
    if (suggestion.prompt) await submit(suggestion.prompt)
  }

  function onQuestion(value) {
    setQuestion(value)
    const match = value.match(/(^|\s)@([a-z0-9._-]*)$/i)
    if (!match) { setMention(null); return }
    api.get(`/api/v1/agents?q=${encodeURIComponent(match[2])}`)
      .then((body) => {
        const items = (body.data || []).slice(0, 6)
        setMention(items.length ? { items, index: 0 } : null)
      })
      .catch(() => setMention(null))
  }

  function pickMention(agent) {
    setQuestion((current) => current.replace(/@([a-z0-9._-]*)$/i, `@${agent.slug} `))
    setMention(null)
    areaRef.current?.focus()
  }

  function onKeyDown(event) {
    if (mention) {
      if (event.key === 'ArrowDown') {
        event.preventDefault()
        setMention((current) => ({
          ...current, index: (current.index + 1) % current.items.length }))
        return
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault()
        setMention((current) => ({
          ...current,
          index: (current.index - 1 + current.items.length) % current.items.length }))
        return
      }
      if (event.key === 'Enter' || event.key === 'Tab') {
        event.preventDefault()
        pickMention(mention.items[mention.index])
        return
      }
      if (event.key === 'Escape') { setMention(null); return }
    }
    if (event.key === 'Enter' && !event.shiftKey) send(event)
  }

  // Pinning is the cheapest context control in the design: a pinned turn is what the
  // prompt keeps when compaction folds everything else into the brief.
  async function togglePin(turn, pins) {
    try {
      if (pins) {
        await api.del(`/api/v1/ai/sessions/${sessionId}/pins/${pins.id}`)
      } else {
        await api.post(`/api/v1/ai/sessions/${sessionId}/pins`, { turn_id: turn.id })
      }
      await load()
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }

  if (!sessionId) {
    return (
      <EmptyState
        title={t('chat.empty.title')}
        hint={t('chat.empty.hint')}
      />
    )
  }
  if (!session) return <Loading label={t('chat.loading')} />

  const turns = session.turn_rows || []
  const pinByTurn = {}
  for (const pin of session.pins || []) {
    if (pin.turn_id && !pinByTurn[pin.turn_id]) pinByTurn[pin.turn_id] = pin
  }
  return (
    <div className={`chat${compact ? ' chat-compact' : ''}`}>
      {error && <Banner kind="error">{error}</Banner>}
      <div className="chat-log">
        {turns.length === 0 && (
          <p className="chat-hint muted">
            {t('chat.hint')}{' '}
            <strong>{t('chat.hintUnknown')}</strong>{' '}
            {t('chat.hintAfter')}
          </p>
        )}
        {turns.map((turn) => (turn.role === 'compaction' ? (
          <div key={turn.id} className="chat-divider" title={t('chat.compaction.title')}>
            <span>{turn.content}</span>
          </div>
        ) : (
          <div key={turn.id} className={`chat-turn chat-${turn.role}`}>
            <div className="chat-meta">
              <span className="chat-author">{roleLabel(turn, t)}</span>
              {turn.role !== 'user' && (
                <span className="chat-role">{tOr(`chat.role.${turn.role}`, turn.role)}</span>
              )}
              {turn.tokens > 0 && <span className="chat-tokens">{t('chat.tokens', { n: turn.tokens })}</span>}
              <button type="button"
                className={`chat-pin${pinByTurn[turn.id] ? ' pinned' : ''}`}
                title={pinByTurn[turn.id] ? t('chat.pin.remove') : t('chat.pin.add')}
                aria-pressed={!!pinByTurn[turn.id]}
                onClick={() => togglePin(turn, pinByTurn[turn.id])}>
                {pinByTurn[turn.id] ? '📌' : '📍'}
              </button>
            </div>
            <div className="chat-body">{turn.content}</div>
            {(turn.suggestions || []).length > 0 && turn.role !== "user" && (
              <div className="chat-suggest">
                {turn.suggestions.map((suggestion, index) => (
                  <button key={`${turn.id}-s${index}`} type="button"
                          className="chat-suggest__btn" disabled={busy}
                          onClick={() => takeSuggestion(suggestion)}>
                    {suggestion.label}
                  </button>
                ))}
              </div>
            )}
            {(turn.citations || []).length > 0 && (
              <div className="chat-cites">
                <span className="chat-cites-label">
                  {t('chat.cite.title', { n: turn.citations.length })}
                </span>
                {turn.citations.slice(0, 10).map((ref) => (
                  <button key={ref} type="button" className="chat-cite" title={ref}
                    onClick={() => onNavigate?.('search', { q: ref })}>
                    {shortRef(ref)}
                  </button>
                ))}
                {turn.citations.length > 10 && (
                  <span className="chat-cite-more">+{turn.citations.length - 10}</span>
                )}
              </div>
            )}
            {turn.run_id && (
              <button type="button" className="chat-run"
                onClick={() => onNavigate?.('ai-runs', { runId: turn.run_id })}>
                {t('chat.run.open')}{turn.tokens > 0 ? ` · ${t('chat.tokens', { n: turn.tokens })}` : ''}
              </button>
            )}
          </div>
        )))}
        {busy && (
          <div className="chat-turn chat-orchestrator">
            <div className="chat-meta"><span className="chat-author">Shauron</span></div>
            <div className="chat-body muted">
              {elapsed > 0 ? t('chat.working', { n: elapsed }) : t('chat.thinking')}
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>
      <form className="chat-composer" onSubmit={send}>
        <div className="chat-input">
          {mention && (
            <div className="agent-mention-list chat-mention-list" role="listbox">
              {mention.items.map((agent, index) => (
                <button key={agent.slug} type="button" role="option"
                  aria-selected={index === mention.index}
                  className={`agent-mention${index === mention.index ? ' active' : ''}`}
                  onMouseDown={(event) => { event.preventDefault(); pickMention(agent) }}>
                  <span className="agent-avatar"
                    style={agent.color
                      ? { background: `${agent.color}22`, borderColor: `${agent.color}55` }
                      : undefined}>
                    {agent.avatar || '🐴'}
                  </span>
                  <span>
                    <strong>{agent.name}</strong>
                    <span className="muted"> @{agent.slug}</span>
                  </span>
                </button>
              ))}
            </div>
          )}
          <textarea
            ref={areaRef}
            value={question}
            onChange={(event) => onQuestion(event.target.value)}
            rows={compact ? 2 : 3}
            placeholder={t('chat.placeholder')}
            aria-label={t('chat.askAria')}
            onKeyDown={onKeyDown}
          />
        </div>
        <button className="btn-primary" disabled={busy || !question.trim()}>{t('chat.send')}</button>
      </form>
      {session.brief_version > 0 && (
        <p className="chat-footnote muted">
          {tCount('chat.compactionCount', session.brief_version)}
        </p>
      )}
    </div>
  )
}

export default function Chat({ onBack, onNavigate }) {
  const { t, tOr, tCount } = useI18n()
  const { sessions, reload, error } = useSessions()
  const [active, setActive] = useState('')
  // Two readings of one conversation: what was said (the chat) and who asked whom for
  // what (the thread). Same records, so switching cannot disagree with itself.
  const [view, setView] = useState('chat')

  useEffect(() => {
    if (!active && sessions.length) setActive(sessions[0].id)
  }, [sessions, active])

  const create = async () => {
    const body = await api.post('/api/v1/ai/sessions', {})
    await reload()
    setActive(body.data.id)
  }

  return (
    <div className="chat-page">
      <PageHeader
        title={t('chat.title')}
        subtitle={t('chat.subtitle')}
        actions={(
          <div className="chat-actions">
            <div className="seg" role="tablist" aria-label={t('chat.viewAria')}>
              <button role="tab" aria-selected={view === 'chat'}
                className={`seg-item${view === 'chat' ? ' active' : ''}`}
                onClick={() => setView('chat')}>{t('chat.view.chat')}</button>
              <button role="tab" aria-selected={view === 'thread'}
                className={`seg-item${view === 'thread' ? ' active' : ''}`}
                onClick={() => setView('thread')}>{t('chat.view.thread')}</button>
            </div>
            {/* The traces of these answers used to have their own sidebar row;
                they are this conversation's evidence, read from here. */}
            {onNavigate && (
              <button className="btn-ghost" onClick={() => onNavigate('ai-runs')}>
                {t('nav.ai-runs')} →
              </button>
            )}
            <button className="btn-primary" onClick={create}>{t('chat.newSession')}</button>
            {onBack && <button className="btn-ghost" onClick={onBack}>{t('chat.backToConsole')}</button>}
          </div>
        )}
      />
      {error && <Banner kind="error">{error}</Banner>}
      <div className="chat-layout">
        <aside className="chat-rail" aria-label={t('chat.sessionsAria')}>
          {sessions.length === 0 && <p className="muted chat-rail-empty">{t('chat.noSessions')}</p>}
          {sessions.map((session) => (
            <button
              key={session.id}
              className={`chat-rail-item${active === session.id ? ' active' : ''}`}
              onClick={() => setActive(session.id)}
            >
              <span className="chat-rail-title">{session.title || t('chat.untitled')}</span>
              <span className="chat-rail-meta">
                <span>{tCount('chat.turns', session.turns ?? 0)}</span>
                <span className={`chat-rail-state state-${session.status}`}>
                  {tOr(`chat.status.${session.status}`, session.status)}
                </span>
              </span>
            </button>
          ))}
        </aside>
        <section className="chat-main">
          {view === 'thread'
            ? <Thread sessionId={active} />
            : <Conversation sessionId={active} onTurn={reload} onNavigate={onNavigate} />}
        </section>
      </div>
    </div>
  )
}
