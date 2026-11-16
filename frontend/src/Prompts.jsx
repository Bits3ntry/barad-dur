import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Banner, Card, EmptyState, Loading, PageHeader } from './ui'
import { useI18n } from './i18n'

/* Prompts as versions (A8). This screen is the answer to "what was it told?" and to
   "I want to change it": the active text, the drafts, and — the part that makes an
   edit a measurement instead of a guess — what each version actually did.

   Three rules the screen inherits from the API, and the copy says them out loud:
   a draft never reaches a run, an active version cannot be edited in place, and
   activating is a human act that archives the previous one. */

function Receipts({ data, t, tCount }) {
  if (!data) return null
  const { steps = 0, runs = 0, tokens = 0, invalid_refs: invalid = 0 } = data
  return (
    <span className="prompt-receipts">
      <span>{tCount('prompts.runs', runs)}</span>
      <span>{tCount('prompts.steps', steps)}</span>
      <span>{t('prompts.tokens', { n: tokens })}</span>
      {invalid > 0 && <span className="prompt-invalid">{t('prompts.invalid', { n: invalid })}</span>}
    </span>
  )
}

export default function Prompts() {
  const { t, tOr, tCount } = useI18n()
  const [entries, setEntries] = useState([])
  const [activeKey, setActiveKey] = useState('')
  const [body, setBody] = useState('')
  const [notes, setNotes] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const payload = await api.get('/api/v1/ai/prompts')
      const rows = payload.data || []
      setEntries(rows)
      setError('')
      if (!activeKey && rows.length) setActiveKey(rows[0].key)
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setLoading(false)
    }
  }, [activeKey])

  useEffect(() => { load() }, [load])

  const entry = useMemo(
    () => entries.find((row) => row.key === activeKey) || null, [entries, activeKey])

  // The editor opens on the active text (or the code floor when there is none), so
  // "nueva versión" is a change to something real, never a blank page.
  useEffect(() => {
    if (!entry) { setBody(''); setNotes(''); return }
    setBody(entry.active ? entry.active.body : entry.code_default || '')
    setNotes('')
  }, [entry])

  if (loading) return <Loading label={t('prompts.loading')} />

  const say = (message) => {
    setNotice(message)
    window.setTimeout(() => setNotice(''), 3500)
  }

  const saveDraft = async () => {
    if (!entry) return
    setBusy(true)
    try {
      const created = await api.post('/api/v1/ai/prompts',
        { key: entry.key, body, notes: notes || null })
      await load()
      say(t('prompts.notice.drafted', { label: created.data.label }))
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  const activate = async (row) => {
    setBusy(true)
    try {
      await api.post(`/api/v1/ai/prompts/${row.id}/activate`, {})
      await load()
      say(t('prompts.notice.activated', { label: row.label }))
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  const versions = entry ? entry.versions.filter((row) => row.id !== (entry.active || {}).id) : []

  return (
    <div className="prompts-page">
      <PageHeader title={t('prompts.title')} subtitle={t('prompts.subtitle')} />
      {error && <Banner kind="error">{error}</Banner>}
      {notice && <Banner kind="ok">{notice}</Banner>}
      {entries.length === 0 && (
        <EmptyState title={t('prompts.empty.title')} hint={t('prompts.empty.hint')} />
      )}
      {entries.length > 0 && (
        <div className="prompts-layout">
          <aside className="prompts-rail" aria-label={t('prompts.railAria')}>
            {entries.map((row) => (
              <button key={row.key}
                className={`prompts-rail-item${row.key === activeKey ? ' active' : ''}`}
                onClick={() => setActiveKey(row.key)}>
                <span className="prompts-rail-key">{row.key}</span>
                <span className="prompts-rail-meta">
                  {row.active
                    ? <span className="pill pill-active">{t('prompts.version', { n: row.active.version })}</span>
                    : <span className="muted">{t('prompts.codeFloor')}</span>}
                </span>
              </button>
            ))}
          </aside>

          <section className="prompts-main stack">
            {entry && (
              <>
                <Card title={t('prompts.card.editor', { key: entry.key })}>
                  <p className="muted prompts-note">{t('prompts.editor.note')}</p>
                  <div className="field">
                    <label htmlFor="prompt-body">{t('prompts.form.body')}</label>
                    <textarea id="prompt-body" rows={14} value={body}
                      onChange={(event) => setBody(event.target.value)}
                      className="prompt-body" spellCheck={false} />
                  </div>
                  <div className="field">
                    <label htmlFor="prompt-notes">{t('prompts.form.notes')}</label>
                    <input id="prompt-notes" value={notes}
                      placeholder={t('prompts.form.notesPlaceholder')}
                      onChange={(event) => setNotes(event.target.value)} />
                  </div>
                  <div className="prompts-actions">
                    <button className="btn-primary" disabled={busy || body.trim().length < 20}
                      onClick={saveDraft}>{t('prompts.form.draft')}</button>
                    <button className="btn-ghost" disabled={busy}
                      onClick={() => setBody(entry.active ? entry.active.body
                                                          : entry.code_default || '')}>
                      {t('prompts.form.reset')}
                    </button>
                  </div>
                </Card>

                <Card title={t('prompts.card.active')}>
                  {!entry.active && (
                    <p className="muted">
                      {t('prompts.noActive')}{' '}
                      <code>{entry.key}@code</code>
                    </p>
                  )}
                  {entry.active && (
                    <div className="prompt-version">
                      <div className="prompt-version-head">
                        <span className="prompt-label">{entry.active.label}</span>
                        <Receipts data={entry.active.receipts} t={t} tCount={tCount} />
                      </div>
                      {entry.active.notes && <p className="muted">{entry.active.notes}</p>}
                      <p className="muted">
                        {t('prompts.activatedBy', {
                          who: entry.active.activated_by || '—',
                          when: entry.active.activated_at || '—',
                        })}
                      </p>
                    </div>
                  )}
                </Card>

                <Card title={tCount('prompts.card.versions', versions.length)}>
                  {versions.length === 0 && (
                    <p className="muted">{t('prompts.noVersions')}</p>
                  )}
                  <ul className="prompt-versions">
                    {versions.map((row) => (
                      <li key={row.id} className="prompt-version">
                        <div className="prompt-version-head">
                          <span className="prompt-label">{row.label}</span>
                          <span className={`pill${row.status === 'draft' ? ' pill-active' : ''}`}>
                            {tOr(`prompts.status.${row.status}`, row.status)}
                          </span>
                          <Receipts data={row.receipts} t={t} tCount={tCount} />
                        </div>
                        {row.notes && <p className="muted">{row.notes}</p>}
                        {row.status === 'draft' && (
                          <div className="prompts-actions">
                            <button className="btn-primary mini" disabled={busy}
                              onClick={() => activate(row)}>
                              {t('prompts.form.activate')}
                            </button>
                            <button className="btn-ghost mini" disabled={busy}
                              onClick={() => { setBody(row.body); window.scrollTo({ top: 0 }) }}>
                              {t('prompts.form.load')}
                            </button>
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </Card>
              </>
            )}
          </section>
        </div>
      )}
    </div>
  )
}
