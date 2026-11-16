import React, { useEffect, useRef, useState } from 'react'
import { api } from './api'
import { ErrorBanner, Loading, Pill } from './ui'
import { useI18n } from './i18n'

/* The organisation block in the sidebar, opened up.

   It answers three questions in one place: where am I (name, slug, my role, how
   much is in here), where else can I go (the seats I hold), and how do I open
   another (create + land in it). Switching writes the choice and reloads: every
   screen holds data resolved for the previous organisation, and a console that
   keeps a cached project list from the old one is worse than a second of white.

   An API key sees one organisation and no "create": a key belongs to one org,
   and creating another with it would seat nobody. */

export default function OrgMenu({ org, onOpenSettings }) {
  const { t, tCount, tOr } = useI18n()
  const [open, setOpen] = useState(false)
  const [rows, setRows] = useState(null)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const box = useRef(null)

  useEffect(() => {
    if (!open) return
    setError(''); setRows(null)
    api.get('/api/v1/orgs')
      .then((body) => setRows(body.data || []))
      .catch((caught) => setError(String(caught.message || caught)))
  }, [open])

  useEffect(() => {
    if (!open) return
    const away = (event) => {
      if (box.current && !box.current.contains(event.target)) setOpen(false)
    }
    const escape = (event) => { if (event.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', away)
    document.addEventListener('keydown', escape)
    return () => {
      document.removeEventListener('mousedown', away)
      document.removeEventListener('keydown', escape)
    }
  }, [open])

  function switchTo(row) {
    if (row.active) return
    api.setOrg(row.id)
    window.location.reload()
  }

  async function create() {
    if (name.trim().length < 2) return
    setBusy(true); setError('')
    try {
      const body = await api.post('/api/v1/orgs',
                                  { name: name.trim(), actor: 'console' })
      // Straight into the new organisation: a menu that creates one and leaves
      // you in the old one makes you repeat the same click in the same menu.
      api.setOrg(body.data?.id || '')
      window.location.reload()
    } catch (caught) {
      setError(String(caught.message || caught))
      setBusy(false)
    }
  }

  const active = (rows || []).find((row) => row.active)
  // A key is one organisation, by design. Saying so is better than a button that
  // answers 403: the door out is signing in, and the menu names it.
  const person = Boolean(api.settings().token)

  return (
    <div className="org-menu-wrap" ref={box}>
      <button className={`org-switcher${open ? ' is-open' : ''}`}
              onClick={() => setOpen((value) => !value)}
              aria-expanded={open} aria-haspopup="dialog">
        {org?.logo
          ? <img className="org-avatar" src={org.logo} alt="" />
          : <span className="org-avatar org-avatar-fallback">{(org?.name || 'O').slice(0, 1)}</span>}
        <span className="org-switcher-copy">
          <small>{t('shell.organization')}</small>
          <strong>{org?.name || t('shell.yourOrganization')}</strong>
        </span>
        <span className="org-switcher-action">{open ? '▴' : '▾'}</span>
      </button>

      {open && (
        <div className="org-menu" role="dialog" aria-label={t('org.menu.title')}>
          <div className="org-menu-head">
            <strong>{org?.name || t('shell.yourOrganization')}</strong>
            <span className="muted mono">{org?.slug || '—'}</span>
            {active && (
              <div className="row" style={{ gap: 6, marginTop: 6 }}>
                <Pill>{tOr(`role.${active.role}`, active.role)}</Pill>
                <span className="muted">
                  {[
                    tCount('org.menu.member', active.members),
                    tCount('org.menu.project', active.projects),
                    tCount('org.menu.finding', active.findings),
                  ].join(' · ')}
                </span>
              </div>
            )}
          </div>

          {error && <ErrorBanner error={error} />}
          {rows === null && <Loading rows={1} />}

          {rows !== null && rows.length > 1 && (
            <div className="org-menu-list">
              <span className="muted">{t('org.menu.others')}</span>
              {rows.filter((row) => !row.active).map((row) => (
                <button key={row.id} className="org-menu-row" onClick={() => switchTo(row)}>
                  <span className="org-menu-avatar">{(row.name || '?').slice(0, 1)}</span>
                  <span className="org-menu-name">
                    <strong>{row.name}</strong>
                    <span className="muted">
                      {tOr(`role.${row.role}`, row.role)} · {t('org.menu.findings', { n: row.findings })}
                    </span>
                  </span>
                  <span className="org-menu-go">→</span>
                </button>
              ))}
            </div>
          )}

          {!person && (
            <p className="muted org-menu-note">{t('org.menu.key')}</p>
          )}

          {person && (creating ? (
            <div className="org-menu-create">
              <input autoFocus value={name} placeholder={t('org.menu.name.ph')}
                     aria-label={t('org.menu.name.ph')}
                     onChange={(event) => setName(event.target.value)}
                     onKeyDown={(event) => event.key === 'Enter' && create()} />
              <div className="row" style={{ gap: 6 }}>
                <button className="btn-primary" disabled={busy || name.trim().length < 2}
                        onClick={create}>
                  {busy ? t('org.menu.creating') : t('org.menu.create')}
                </button>
                <button className="btn-ghost" onClick={() => { setCreating(false); setName('') }}>
                  {t('common.cancel')}
                </button>
              </div>
            </div>
          ) : (
            <div className="org-menu-actions">
              <button className="org-menu-row" onClick={() => setCreating(true)}>
                <span className="org-menu-avatar">+</span>
                <span className="org-menu-name">
                  <strong>{t('org.menu.new')}</strong>
                  <span className="muted">{t('org.menu.new.hint')}</span>
                </span>
              </button>
            </div>
          ))}

          {/* The settings door is not a privilege of being a person: it is where
              the key's own organisation is renamed, and where a key is issued. */}
          {onOpenSettings && (
            <div className="org-menu-actions">
              <button className="org-menu-row" onClick={() => { setOpen(false); onOpenSettings() }}>
                <span className="org-menu-avatar">⚙</span>
                <span className="org-menu-name">
                  <strong>{t('org.menu.settings')}</strong>
                  <span className="muted">{t('org.menu.settings.hint')}</span>
                </span>
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
