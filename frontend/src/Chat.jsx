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
  // The confirmation of an in-place action (mission approved, cycle created).
  const [notice, setNotice] = useState('')
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
  /* While a mission is alive the conversation is the harness: one poll of the same
     payload the thread renders, so the operator sees the task, its attempts and every
     command as they land — instead of a blank screen that does not say if it is
     working. */
  const missions = session?.missions || []
  const live = missions.some(missionAlive)
  useEffect(() => {
    if (!live) return undefined
    const timer = setInterval(() => { load() }, 3000)
    return () => clearInterval(timer)
  }, [live, load])
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
    // Approving happens here: the button is the "sí", so it posts and reloads the thread
    // instead of taking the operator to another screen to repeat it.
    if (suggestion.action === "approve_mission" && suggestion.mission_id) {
      try {
        await api.post(`/api/v1/agent/missions/${suggestion.mission_id}/approve`, {})
        await load()
        setNotice("Misión aprobada — el worker la toma en segundos.")
      } catch (caught) {
        setError(String(caught.message || caught))
      }
      return
    }
    if (suggestion.action === "create_cycle" && suggestion.name) {
      try {
        await api.post("/api/v1/cycles",
                       { name: suggestion.name, kind: suggestion.kind || "pentest_external",
                         actor: "chat" })
        setNotice(`Ciclo «${suggestion.name}» creado.`)
        onNavigate?.("cycles")
      } catch (caught) {
        setError(String(caught.message || caught))
      }
      return
    }
    // A validation button sends the sentence the platform wrote for it — never its own
    // label. Sending the label turned "validá el impacto de <id>" into "Validar el SQLi de
    // Juice Shop", a description with no id, and the turn fell back to a read-only essay.
    if (suggestion.action === "validate_finding" && suggestion.finding_id) {
      await submit(suggestion.prompt ||
                   `@angmar validá el impacto de ${suggestion.finding_id}`)
      return
    }
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
  // A mission belongs to the turn that armed it (its citation) or reported it. One
  // mapping, so the panel under a turn shows that turn's run and nothing else.
  const missionByTurn = {}
  for (const mission of missions) {
    for (const turn of turns) {
      const refs = [mission.id, mission.run_id,
                    ...(turn.citations || []),
                    ...((turn.suggestions || []).map((item) => item.mission_id))]
      if (refs.filter(Boolean).includes(mission.id)) missionByTurn[turn.id] = mission
    }
  }
  const pinByTurn = {}
  for (const pin of session.pins || []) {
    if (pin.turn_id && !pinByTurn[pin.turn_id]) pinByTurn[pin.turn_id] = pin
  }
  return (
    <div className={`chat${compact ? ' chat-compact' : ''}`}>
      {sessionId && <ThreadTrace sessionId={sessionId} />}
      {notice && <Banner kind="info">{notice}</Banner>}
      {error && <Banner kind="error">{error}</Banner>}
      <div className="chat-log">
        {live && <LiveStrip missions={missions} />}
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
            <div className="chat-body chat-md"
                 dangerouslySetInnerHTML={{ __html: markdownToHtml(turn.content) }} />
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
            {(turn.run_id || missionByTurn[turn.id]) && (
              <Harness runId={turn.run_id} mission={missionByTurn[turn.id]} />
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


/* ── the harness, in the thread ───────────────────────────────────────────────
   Leaving the conversation to find out what the assistant is doing is the friction
   this exists to remove. A mission this thread armed renders its task, its attempts
   and every command under the turn that armed it, and the strip at the top says it is
   alive while it is. Same records the Missions screen reads. */

const PROVISIONAL = ['queued', 'claimed', 'running']

function missionAlive(mission) {
  if (!mission) return false
  if (['approved', 'running'].includes(mission.status)) return true
  return (mission.tasks || []).some((task) => PROVISIONAL.includes(task.status))
}

/* One line per event: what was run, what came back. The status of a response lives in
   the first line of its head, because that is what curl wrote. */
function eventLine(event) {
  const payload = event.payload || {}
  if (event.kind === 'tool') {
    const argv = (payload.argv || []).join(' ')
    return { text: `${event.tool || payload.tool || 'tool'} ${argv}`.trim(),
             meta: payload.rc === 0 ? 'rc 0' : `rc ${payload.rc}` }
  }
  if (event.kind === 'observation') {
    const first = String(payload.head || '').split('\n')[0]
    const status = first.match(/\s(\d{3})\b/)
    return { text: status ? first.replace(/^HTTP\/[\d.]+\s*/, '') : '—',
             meta: payload.bytes ? `${payload.bytes} B` : '' }
  }
  if (event.kind === 'refusal') {
    return { text: payload.reason || payload.detail || 'refused', meta: '' }
  }
  if (event.kind === 'final') {
    const verdict = /VERDICT:\s*([A-Z ]+)/i.exec(String(payload.answer || ''))
    if (verdict) return { text: verdict[1].trim(), meta: payload.error || '' }
    return { text: payload.error ? 'error' : 'final', meta: payload.error || '' }
  }
  return { text: event.kind, meta: '' }
}

function LiveStrip({ missions }) {
  const { t } = useI18n()
  const running = missions.filter(missionAlive)
  const task = running.flatMap((mission) => mission.tasks || [])
    .find((row) => PROVISIONAL.includes(row.status))
  const events = running.flatMap((mission) =>
    (mission.tasks || []).flatMap((row) => row.events || []))
  const last = events[events.length - 1]
  const line = last ? eventLine(last) : null
  return (
    <div className="chat-live" role="status">
      <span className="chat-live__dot" aria-hidden="true" />
      <span className="chat-live__title">{t('chat.harness.running')}</span>
      {task && (
        <span className="chat-live__task">
          <code>{task.kind}</code> · {task.status}
          {task.attempts > 1 ? ` · intento ${task.attempts}` : ''}
        </span>
      )}
      {line && <span className="chat-live__last">{line.text}</span>}
      <span className="chat-live__n">
        {t('chat.harness.calls', { n: events.filter((event) => event.kind === 'tool').length })}
      </span>
    </div>
  )
}

function Harness({ runId, mission }) {
  const { t, tOr } = useI18n()
  const [steps, setSteps] = useState(null)
  const [busy, setBusy] = useState(false)
  const live = missionAlive(mission)
  const tasks = mission?.tasks || []
  const events = tasks.flatMap((task) => task.events || [])
  const tools = events.filter((event) => event.kind === 'tool').length

  const open = async (element) => {
    if (!element.open || steps || busy || !runId) return
    setBusy(true)
    try {
      const body = await api.get(`/api/v1/ai/runs/${runId}`)
      setSteps(body?.data?.step_rows || [])
    } catch {
      setSteps([])
    } finally {
      setBusy(false)
    }
  }

  return (
    <details className={`chat-harness${live ? ' live' : ''}`} open={live || undefined}
             onToggle={(event) => open(event.currentTarget)}>
      <summary>
        {live && <span className="chat-harness__pulse" aria-hidden="true" />}
        <span className="chat-harness__title">
          {mission ? `${mission.capability} · ${mission.profile}` : t('chat.run.open')}
        </span>
        {mission && (
          <span className="chat-harness__state">
            {tOr(`chat.harness.state.${mission.status}`, mission.status)}
          </span>
        )}
        {tools > 0 && (
          <span className="chat-harness__count">{t('chat.harness.calls', { n: tools })}</span>
        )}
        {mission?.tokens ? (
          <span className="chat-harness__budget">{t('chat.harness.budget', { n: mission.tokens })}</span>
        ) : null}
      </summary>
      {tasks.map((task) => (
        <div className="chat-harness__task" key={task.id}>
          <div className="chat-harness__task-head">
            <code>{task.kind}</code>
            <span className={`chat-harness__task-state state-${task.status}`}>
              {tOr(`chat.harness.state.${task.status}`, task.status)}
            </span>
            {task.attempts > 1 && (
              <span className="muted">· {t('chat.harness.attempt', { n: task.attempts })}</span>
            )}
            {task.error && <span className="chat-harness__error">{task.error}</span>}
          </div>
          {(task.events || []).length === 0 && (
            <div className="chat-harness__row muted">{t('chat.harness.noEvents')}</div>
          )}
          {(task.events || []).map((event) => {
            const line = eventLine(event)
            return (
              <div className={`chat-harness__row kind-${event.kind}`} key={`${task.id}-${event.seq}`}>
                <span className="chat-harness__seq">{event.seq}</span>
                <span className="chat-harness__kind">{event.kind}</span>
                <span className="chat-harness__what">{line.text}</span>
                {line.meta && <span className="chat-harness__meta">{line.meta}</span>}
              </div>
            )
          })}
        </div>
      ))}
      {steps && steps.length > 0 && (
        <div className="chat-harness__steps">
          <div className="chat-harness__row muted">{t('chat.harness.modelCalls')}</div>
          {steps.map((step) => {
            let toolCalls = []
            try { toolCalls = JSON.parse(step.tool_calls || '[]') } catch { toolCalls = [] }
            return (
              <div className="chat-harness__row" key={`step-${step.seq}`}>
                <span className="chat-harness__seq">{step.seq}</span>
                <span className="chat-harness__kind">
                  {step.role}{step.phase ? ` · ${step.phase}` : ''}
                </span>
                <span className="chat-harness__what">
                  {toolCalls
                    .map((call) => `${call.tool || '?'}${call.status && call.status !== 200 ? ' ⚠' : ''}`)
                    .join(' · ') || '—'}
                </span>
                <span className="chat-harness__meta">
                  {(step.tokens_in || 0) + (step.tokens_out || 0)} tok
                </span>
              </div>
            )
          })}
        </div>
      )}
      {busy && <div className="chat-harness__row muted">{t('chat.loading')}</div>}
    </details>
  )
}



// Minimal markdown, on purpose: bold, inline code, fenced code and line breaks are what a
// field report actually uses. A full parser is a dependency and a surface; this is neither.
function escapeHtml(text) {
  return String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
}

function markdownToHtml(source) {
  let html = escapeHtml(source)
  const fences = []
  html = html.replace(/```[a-zA-Z]*\n?([\s\S]*?)```/g, (_match, code) => {
    fences.push(`<pre class="chat-code">${code.replace(/^\n/, "")}</pre>`)
    return `\u0000${fences.length - 1}\u0000`
  })
  html = html
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
  html = html
    .split(/\n{2,}/)
    .map((block) => {
      const trimmed = block.trim()
      if (!trimmed) return ""
      if (/^\u0000\d+\u0000$/.test(trimmed)) return trimmed
      return `<p>${trimmed.replace(/\n/g, "<br/>")}</p>`
    })
    .join("")
  html = html.replace(/\u0000(\d+)\u0000/g, (_m, index) => fences[Number(index)])
  return html
}

// The relation view, inside the conversation: who spoke, delegating to whom, what each
// run cost. Hermes shows the room while it works; a separate tab you have to remember to
// open is the friction this replaces.
function ThreadTrace({ sessionId }) {
  const [events, setEvents] = useState(null)
  const [busy, setBusy] = useState(false)

  const open = async (element) => {
    if (!element.open || events || busy) return
    setBusy(true)
    try {
      const body = await api.get(`/api/v1/ai/sessions/${sessionId}/thread`)
      setEvents((body?.data?.events) || [])
    } catch {
      setEvents([])
    } finally {
      setBusy(false)
    }
  }

  return (
    <details className="chat-thread" onToggle={(event) => open(event.currentTarget)}>
      <summary>relaciones de esta sesión</summary>
      {busy && !events && <div className="chat-thread__row">cargando…</div>}
      {events && events.length === 0 && (
        <div className="chat-thread__row">sin actividad registrada</div>
      )}
      {(events || []).map((event) => (
        <div className="chat-thread__row" key={`${event.order}-${event.kind}`}>
          <span className="chat-thread__n">{event.order}</span>
          <span className={`chat-thread__kind chat-thread__kind--${event.kind}`}>
            {event.kind}
          </span>
          <span className="chat-thread__who">
            {event.author}{event.role && event.role !== "user" ? ` · ${event.role}` : ""}
          </span>
          <span className="chat-thread__what">{(event.content || "").slice(0, 90)}</span>
          {event.tokens > 0 && (
            <span className="chat-thread__tok">{event.tokens} tok</span>
          )}
        </div>
      ))}
    </details>
  )
}

export default function Chat({ onBack, onNavigate, focus }) {
  const { t, tOr, tCount } = useI18n()
  const { sessions, reload, error } = useSessions()
  // The address owns which conversation is open: `#chat::<id>` survives an F5, a
  // bookmark and a paste, and the rail is a shortcut to the same address.
  const [active, setActive] = useState(focus?.sessionId || '')
  // Two readings of one conversation: what was said (the chat) and who asked whom for
  // what (the thread). Same records, so switching cannot disagree with itself.
  const [view, setView] = useState('chat')

  const select = (id) => {
    setActive(id)
    if (id) window.history.pushState({}, '', `/#chat::${id}`)
  }

  // A focus that changes under us (a link, the back button) reopens that conversation.
  useEffect(() => {
    if (focus?.sessionId && focus.sessionId !== active) setActive(focus.sessionId)
  }, [focus?.sessionId])  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!active && sessions.length) select(sessions[0].id)
  }, [sessions, active])

  const create = async () => {
    const body = await api.post('/api/v1/ai/sessions', {})
    await reload()
    select(body.data.id)
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
              onClick={() => select(session.id)}
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
