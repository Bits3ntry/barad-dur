import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import { Banner, ConfirmButton, Dialog, EmptyState, Loading, PageHeader } from './ui'
import { useI18n } from './i18n'

/* Agents: who is on the team, and what each one may do.

   This screen is the catalogue and nothing else. The conversation lives in the
   Assistant — a thread here was a second assistant with its own composer, and it
   sat empty because the real one is one click away. The two other lists that
   shared this page belong to their owners: what waits on a human is the inbox
   (Missions), and what a domain allows is Grants.

   A spec declares tools; it never invents them. `tools_missing` is shown, not
   hidden: naming a tool that does not exist is exactly what `draft` means. */

const CLASSES = ['orchestrator', 'analyst', 'query', 'field']
const STATUSES = ['draft', 'active', 'archived']

function Avatar({ agent }) {
  const style = agent && agent.color
    ? { background: `${agent.color}22`, borderColor: `${agent.color}55` }
    : undefined
  return (
    <span className="agent-avatar" style={style}>
      {(agent && agent.avatar) || '🐴'}
    </span>
  )
}

function slugOf(name) {
  return String(name || '').toLowerCase().normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64)
}

function AgentCard({ agent, active, onSelect }) {
  const { t, tCount } = useI18n()
  return (
    <button type="button" className={`agent-card${active ? ' active' : ''}`}
      onClick={() => onSelect(agent)}>
      <Avatar agent={agent} />
      <span className="agent-card-body">
        <span className="agent-card-name">
          {agent.name}
          <span className={`pill pill-${agent.status}`}>{t(`agents.status.${agent.status}`)}</span>
        </span>
        {agent.description
          ? <span className="muted agent-card-desc">{agent.description}</span>
          : null}
        <span className="muted agent-card-meta">
          {t(`agents.class.${agent.class}`)} · {tCount('agents.toolsCount', agent.tools.length)}
          {agent.tools_missing.length
            ? ` · ${tCount('agents.toolsMissing', agent.tools_missing.length)}`
            : ''}
          {agent.active_runs ? ` · ${tCount('agents.activeRuns', agent.active_runs)}` : ''}
          {agent.cost_today_usd ? ` · $${Number(agent.cost_today_usd).toFixed(2)}` : ''}
        </span>
      </span>
    </button>
  )
}

function Editor({ agent, tools, busy, onPatch, onClone, onNavigate }) {
  const { t, tCount, tOr } = useI18n()
  const [name, setName] = useState(agent.name)
  const [description, setDescription] = useState(agent.description || '')
  const [mustReturn, setMustReturn] = useState((agent.must_return || []).join('\n'))
  const [query, setQuery] = useState('')
  const timer = useRef(null)

  // Text is saved shortly after typing stops. A save-on-blur-only field loses the
  // edit when the panel is closed by anything that does not fire a blur, and the
  // operator has no way to tell that it never landed.
  const soon = useCallback((changes) => {
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => onPatch(changes), 700)
  }, [onPatch])

  // The editor follows the selection: another agent is another record, and a draft
  // left over from the previous one would write one agent's words into another row.
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current)
    setName(agent.name)
    setDescription(agent.description || '')
    setMustReturn((agent.must_return || []).join('\n'))
    setQuery('')
  }, [agent.id])

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])

  const declared = new Set(agent.tools)
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return tools
    return tools.filter((tool) => [tool.name, tool.summary]
      .join(' ').toLowerCase().includes(needle))
  }, [tools, query])

  function toggleTool(tool) {
    const next = new Set(declared)
    if (next.has(tool.name)) next.delete(tool.name); else next.add(tool.name)
    // Saving on the click is what makes the counter move: a picker behind a save
    // button hides whether the click worked.
    onPatch({ tools: [...next] })
  }

  return (
    <div className="agent-main">
      <div className="agent-thread-head">
        <span className="row" style={{ gap: 9 }}>
          <Avatar agent={agent} />
          <span className="stack" style={{ gap: 2 }}>
            <strong>{agent.name}</strong>
            <span className="muted mono">{agent.slug}</span>
          </span>
        </span>
        <span className="row" style={{ gap: 6 }}>
          <span className="muted" style={{ fontSize: 11 }}>{t('agents.edit.autosave')}</span>
          <button className="mini" disabled={busy} onClick={onClone}>{t('agents.clone')}</button>
          {agent.status !== 'archived' && (
            <ConfirmButton confirmLabel={t('agents.archiveConfirm')}
              onConfirm={() => onPatch({ status: 'archived' })}>
              {t('agents.archive')}
            </ConfirmButton>
          )}
        </span>
      </div>

      <section className="form-section">
        <h3>{t('agents.edit.identity')}</h3>
        <p className="settings-note">{t('agents.edit.identityHint')}</p>

        <div className="field">
          <label className="field-label">{t('agents.field.name')}</label>
          <input value={name} onChange={(event) => {
            setName(event.target.value)
            if (event.target.value.trim()) soon({ name: event.target.value.trim() })
          }} />
        </div>

        <div className="field">
          <label className="field-label">{t('agents.field.class')}</label>
          <select value={agent.class}
            onChange={(event) => onPatch({ agent_class: event.target.value })}>
            {CLASSES.map((value) => (
              <option key={value} value={value}>{t(`agents.class.${value}`)}</option>
            ))}
          </select>
          <span className="muted">{t(`agents.edit.class.${agent.class}`)}</span>
        </div>

        <div className="field">
          <label className="field-label">{t('agents.field.status')}</label>
          <select value={agent.status}
            onChange={(event) => onPatch({ status: event.target.value })}>
            {STATUSES.map((value) => (
              <option key={value} value={value}>{t(`agents.status.${value}`)}</option>
            ))}
          </select>
          <span className="muted">{t(`agents.edit.status.${agent.status}`)}</span>
        </div>

        <div className="field">
          <label className="field-label">{t('agents.field.description')}</label>
          <textarea rows={3} value={description}
            onChange={(event) => {
              setDescription(event.target.value)
              soon({ description: event.target.value })
            }} />
          <span className="muted">{t('agents.edit.descriptionHint')}</span>
        </div>
      </section>

      <section className="form-section">
        <h3>{t('agents.field.tools')}</h3>
        <p className="settings-note">{t('agents.edit.toolsHint')}</p>
        {agent.tools_missing.length > 0 && (
          <Banner kind="warn">
            {tCount('agents.edit.toolsMissing', agent.tools_missing.length)}:{' '}
            <span className="mono">{agent.tools_missing.join(', ')}</span>
          </Banner>
        )}
        <input value={query} placeholder={t('agents.filterTools')}
          onChange={(event) => setQuery(event.target.value)} />
        <div className="toggle-group">
          {visible.map((tool) => {
            const others = (tool.used_by || []).filter((slug) => slug !== agent.slug)
            return (
              <label className="toggle-row" key={tool.name}>
                <input type="checkbox" checked={declared.has(tool.name)} disabled={busy}
                  onChange={() => toggleTool(tool)} />
                <span>
                  <strong className="mono">{tool.name}</strong>
                  <span className="muted"> · {tOr(`agents.risk.${tool.risk}`, tool.risk)}</span>
                  <span className="muted"> · {tool.summary}</span>
                  {others.length ? (
                    <span className="muted"> · {t('agents.usedBy', { names: others.join(', ') })}</span>
                  ) : null}
                </span>
              </label>
            )
          })}
          {!visible.length && <p className="muted">{t('agents.filterToolsEmpty')}</p>}
        </div>
      </section>

      <section className="form-section">
        <h3>{t('agents.field.mustReturn')}</h3>
        <p className="settings-note">{t('agents.edit.mustReturnHint')}</p>
        <div className="field">
          <textarea rows={4} value={mustReturn}
            placeholder={t('agents.field.mustReturnPlaceholder')}
            onChange={(event) => {
              setMustReturn(event.target.value)
              soon({
                must_return: event.target.value.split('\n')
                  .map((line) => line.trim()).filter(Boolean),
              })
            }} />
        </div>
      </section>

      {onNavigate && (
        <div className="row" style={{ gap: 8 }}>
          {/* The conversation is not here: one door to the Assistant, one to what
              this team is allowed to run in the field. */}
          <button className="btn-ghost" onClick={() => onNavigate('chat')}>
            {t('agents.openAssistant')} →
          </button>
          <button className="btn-ghost" onClick={() => onNavigate('missions')}>
            {t('nav.missions')} →
          </button>
        </div>
      )}
    </div>
  )
}

export default function Agents({ onNavigate }) {
  const { t, tCount } = useI18n()
  const [agents, setAgents] = useState([])
  const [tools, setTools] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [query, setQuery] = useState('')
  const [creating, setCreating] = useState(false)
  const [draft, setDraft] = useState({ name: '', agent_class: 'analyst', description: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = useCallback(async () => {
    try {
      const [list, catalogue] = await Promise.all([
        api.get('/api/v1/agents'),
        api.get('/api/v1/agents/tools'),
      ])
      setAgents(list.data || [])
      setTools(catalogue.data || [])
      setError('')
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }, [])

  useEffect(() => { load() }, [load])

  // A confirmation that stays on screen stops meaning "just now". It retires on its
  // own so a stale "Saved." cannot answer for the next edit.
  useEffect(() => {
    if (!notice) return undefined
    const timer = setTimeout(() => setNotice(''), 3500)
    return () => clearTimeout(timer)
  }, [notice])

  const selected = agents.find((agent) => agent.id === selectedId) || agents[0] || null

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return agents
    return agents.filter((agent) => [
      agent.name, agent.slug, agent.class, agent.description, ...agent.tools,
    ].join(' ').toLowerCase().includes(needle))
  }, [agents, query])

  async function patch(agent, changes) {
    setBusy(true); setNotice('')
    try {
      await api.patch(`/api/v1/agents/${agent.id}`, changes)
      await load()
      setNotice(t('agents.saved'))
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setBusy(false) }
  }

  async function clone(agent) {
    setBusy(true); setNotice('')
    try {
      const created = await api.post(`/api/v1/agents/${agent.id}/clone`)
      await load()
      if (created.data?.id) setSelectedId(created.data.id)
      setNotice(t('agents.cloned', { name: created.data?.name || agent.name }))
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setBusy(false) }
  }

  async function create() {
    const name = draft.name.trim()
    if (!name) { setError(t('agents.newAgentName')); return }
    setBusy(true); setError('')
    try {
      const created = await api.post('/api/v1/agents', {
        name, slug: slugOf(name), agent_class: draft.agent_class,
        description: draft.description.trim() || null, status: 'draft',
        tools: [], must_return: [], tech_affinity: [],
      })
      await load()
      if (created.data?.id) setSelectedId(created.data.id)
      setCreating(false)
      setDraft({ name: '', agent_class: 'analyst', description: '' })
      setNotice(t('agents.created'))
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setBusy(false) }
  }

  return (
    <div className="stack">
      <PageHeader title={t('agents.title')} subtitle={t('agents.subtitle')}
        actions={(
          <div className="row" style={{ gap: 8 }}>
            {onNavigate && (
              <button className="btn-ghost" onClick={() => onNavigate('missions')}>
                {t('nav.missions')} →
              </button>
            )}
            <button className="btn-primary" onClick={() => setCreating(true)}>
              {t('agents.newAgent')}
            </button>
          </div>
        )} />

      {error && <Banner kind="error">{error}</Banner>}
      {notice && <Banner kind="ok">{notice}</Banner>}

      {!agents.length && !error && <Loading label={t('agents.loading')} />}

      {agents.length > 0 && (
        <div className="agent-shell">
          <div className="agent-side">
            <div className="agent-side-head">
              <span className="muted">{t('agents.catalogue')}</span>
              <span className="muted">{tCount('agents.total', agents.length)}</span>
            </div>
            <input value={query} placeholder={t('agents.filterPlaceholder')}
              onChange={(event) => setQuery(event.target.value)} />
            <div className="agent-list">
              {visible.map((agent) => (
                <AgentCard key={agent.id} agent={agent} active={selected?.id === agent.id}
                  onSelect={(row) => setSelectedId(row.id)} />
              ))}
              {!visible.length && <p className="muted">{t('agents.filterEmpty')}</p>}
            </div>
          </div>

          {selected ? (
            <Editor agent={selected} tools={tools} busy={busy}
              onPatch={(changes) => patch(selected, changes)}
              onClone={() => clone(selected)} onNavigate={onNavigate} />
          ) : (
            <div className="agent-main">
              <EmptyState title={t('agents.select.title')} hint={t('agents.select.hint')} />
            </div>
          )}
        </div>
      )}

      <Dialog open={creating} title={t('agents.newAgentDialog')}
        confirmLabel={t('agents.newAgentCreate')} onClose={() => setCreating(false)}
        onConfirm={create}>
        <div className="stack">
          <div className="field">
            <label className="field-label">{t('agents.field.name')}</label>
            <input value={draft.name} placeholder={t('agents.field.namePlaceholder')}
              onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} />
            <span className="muted mono">{slugOf(draft.name) || '—'}</span>
          </div>
          <div className="field">
            <label className="field-label">{t('agents.field.class')}</label>
            <select value={draft.agent_class}
              onChange={(event) => setDraft((current) => ({ ...current, agent_class: event.target.value }))}>
              {CLASSES.map((value) => (
                <option key={value} value={value}>{t(`agents.class.${value}`)}</option>
              ))}
            </select>
            <span className="muted">{t(`agents.edit.class.${draft.agent_class}`)}</span>
          </div>
          <div className="field">
            <label className="field-label">{t('agents.field.description')}</label>
            <textarea rows={3} value={draft.description}
              placeholder={t('agents.edit.descriptionHint')}
              onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))} />
          </div>
          <p className="settings-note">{t('agents.newAgentNote')}</p>
        </div>
      </Dialog>
    </div>
  )
}
