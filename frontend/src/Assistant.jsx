import React, { useEffect, useState } from 'react'
import { api } from './api'
import Icon from './icons'
import { Banner } from './ui'
import { useI18n } from './i18n'
import { Conversation, useSessions } from './Chat'

/* The floating launcher (§4c): present on every screen except the chat screen
   itself, and it resumes the last conversation instead of starting an orphan
   thread. The panel renders the same `Conversation` the page does. */

export default function Assistant({ hidden = false, onOpen, onNavigate }) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState('')
  const [error, setError] = useState('')
  const { sessions, reload } = useSessions()

  useEffect(() => {
    if (!open) return
    if (!active && sessions.length) setActive(sessions[0].id)
  }, [open, sessions, active])

  useEffect(() => {
    if (!open) return undefined
    const onKey = (event) => { if (event.key === 'Escape') setOpen(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  const start = async () => {
    try {
      const body = await api.post('/api/v1/ai/sessions', {})
      await reload()
      setActive(body.data.id)
      setError('')
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }

  if (hidden) return null

  return (
    <>
      <button
        className="assistant-launcher"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-label={t('assistant.launcherAria')}
        title={t('assistant.launcherTitle')}
      >
        <Icon name="chat" size={18} />
        <span>Shauron</span>
      </button>

      {open && (
        <section className="assistant-panel" aria-label={t('assistant.panelAria')}>
          <header className="assistant-head">
            <div>
              <strong>Shauron</strong>
              <small>{t('assistant.tagline')}</small>
            </div>
            <div className="assistant-head-actions">
              <button className="btn-ghost mini" onClick={start}>{t('assistant.new')}</button>
              {onOpen && (
                <button className="btn-ghost mini" onClick={() => { setOpen(false); onOpen() }}>
                  {t('assistant.fullScreen')}
                </button>
              )}
              <button className="btn-ghost mini" onClick={() => setOpen(false)} aria-label={t('assistant.closeAria')}>
                ✕
              </button>
            </div>
          </header>
          {error && <Banner kind="error">{error}</Banner>}
          <div className="assistant-body">
            {sessions.length === 0 && !active
              ? (
                <div className="assistant-empty">
                  <p>{t('assistant.empty.title')}</p>
                  <button className="btn-primary" onClick={start}>{t('assistant.empty.start')}</button>
                </div>
              )
              : <Conversation sessionId={active} compact onTurn={reload}
                              onNavigate={onNavigate} />}
          </div>
        </section>
      )}
    </>
  )
}
