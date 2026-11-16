import React, { useEffect, useState } from 'react'
import { api } from './api'
import { BrandMark } from './Login'
import { useI18n } from './i18n'

/* The public end of an invitation. Nothing here knows the workspace's data:
   the token resolves to one seat (organization name, role, email) and that is
   all this screen ever shows. */

function readToken() {
  const hash = new URLSearchParams((window.location.hash || '').replace(/^#/, ''))
  const query = new URLSearchParams(window.location.search)
  return hash.get('token') || query.get('token') || ''
}

export default function Invite() {
  const { t } = useI18n()
  const [token] = useState(readToken)
  const [invite, setInvite] = useState(null)
  const [error, setError] = useState('')
  const [form, setForm] = useState({ display_name: '', password: '', confirm: '' })
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!token) { setError(t('invite.error.missingToken')); return }
    api.get(`/api/v1/auth/invitations/${encodeURIComponent(token)}`)
      .then((r) => setInvite(r.data))
      .catch(() => setError(t('invite.error.unknown')))
  }, [token])

  async function accept(event) {
    event.preventDefault()
    setError('')
    if (form.password.length < 8) {
      setError(t('invite.error.password'))
      return
    }
    if (form.password !== form.confirm) {
      setError(t('invite.error.mismatch'))
      return
    }
    setBusy(true)
    try {
      const result = await api.post('/api/v1/auth/invitations/accept', {
        token,
        password: form.password,
        display_name: form.display_name.trim() || undefined,
      })
      api.save({
        key: '',
        token: result.session.access_token,
        refresh_token: result.session.refresh_token,
        expires_at: result.session.expires_at,
      })
      window.location.replace('/#dashboard')
    } catch (e) {
      setError(String(e.message || e))
      setBusy(false)
    }
  }

  return (
    <div className="gate startup-gate">
      <section className="gate-panel">
        <div className="auth-card">
          <div className="onb-brand">
            <BrandMark size={30} />
            <span>Barad-dûr</span>
          </div>

          {error && !invite && (
            <>
              <h1 className="auth-h1">{t('invite.error.title')}</h1>
              <p className="auth-sub">{error} {t('invite.error.askAdmin')}</p>
            </>
          )}

          {!invite && !error && <p className="auth-sub">{t('invite.checking')}</p>}

          {invite && (
            <>
              <span className="onb-kicker">{t('invite.kicker')}</span>
              <h1 className="auth-h1">{t('invite.title', { org: invite.org_name })}</h1>
              <p className="auth-sub">
                {t('invite.sub.rolePrefix')}<strong>{invite.role_label}</strong>{t('invite.sub.emailJoin')}<strong>{invite.email}</strong>.
                {invite.expires_at && ` ${t('invite.sub.expires', { date: new Date(invite.expires_at).toLocaleString() })}`}
              </p>

              {!invite.valid && (
                <p className="banner banner-error">
                  {t('invite.invalidPre')}{invite.status}{t('invite.invalidPost')}
                </p>
              )}

              {invite.valid && (
                <form onSubmit={accept} className="onb-form">
                  <label>
                    {t('invite.field.name')}
                    <input value={form.display_name}
                      onChange={(e) => setForm({ ...form, display_name: e.target.value })}
                      placeholder={t('invite.placeholder.name')} autoComplete="name" />
                  </label>
                  <label>
                    {t('invite.field.password')}
                    <input type="password" value={form.password}
                      onChange={(e) => setForm({ ...form, password: e.target.value })}
                      placeholder={t('invite.placeholder.password')} autoComplete="new-password" />
                  </label>
                  <label>
                    {t('invite.field.confirm')}
                    <input type="password" value={form.confirm}
                      onChange={(e) => setForm({ ...form, confirm: e.target.value })}
                      autoComplete="new-password" />
                  </label>
                  {error && <p className="banner banner-error">{error}</p>}
                  <button className="btn-primary" type="submit" disabled={busy}>
                    {busy ? t('invite.busy') : t('invite.action')}
                  </button>
                </form>
              )}
            </>
          )}
        </div>
      </section>
    </div>
  )
}
