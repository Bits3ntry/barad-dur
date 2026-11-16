import React, { useEffect, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'

/* The deployment's outgoing mail. One relay serves invitations and every email
   notification channel, so this is a deployment setting, not an organization
   one. It is used twice: inside Settings, and inline on the onboarding step
   that has to send an invitation.

   Two honest states matter here: which source is in effect
   (database / environment / none), and whether a password is stored — the
   password itself is write-only and never comes back. */

const DEFAULT_FORM = {
  host: '',
  port: 587,
  sender: 'barad-dur@localhost',
  user: '',
  password: '',
  starttls: true,
}

export default function MailSettings({ onConfigured, defaultRecipient = '' }) {
  const { t } = useI18n()
  const [status, setStatus] = useState(null)
  const [form, setForm] = useState(DEFAULT_FORM)
  const [testTo, setTestTo] = useState(defaultRecipient)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  function load() {
    return api.get('/api/v1/deployment/mail')
      .then((r) => {
        setStatus(r.data)
        setForm({
          host: r.data.host || '',
          port: r.data.port || 587,
          sender: r.data.sender || 'barad-dur@localhost',
          user: r.data.user || '',
          password: '',
          starttls: Boolean(r.data.starttls),
        })
      })
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(() => { load() }, [])

  // The identity may arrive after this panel mounts, so the default recipient
  // is applied when it shows up rather than only at first render.
  useEffect(() => {
    if (defaultRecipient) setTestTo((current) => current || defaultRecipient)
  }, [defaultRecipient])

  async function save(event) {
    event.preventDefault()
    setError('')
    setNotice('')
    if (!form.host.trim()) { setError(t('mail.error.hostRequired')); return }
    setBusy('save')
    try {
      const r = await api.put('/api/v1/deployment/mail', {
        host: form.host.trim(),
        port: Number(form.port) || 25,
        sender: form.sender.trim(),
        user: form.user.trim(),
        password: form.password,
        starttls: form.starttls,
        actor: 'console',
      })
      setStatus(r.data)
      setForm((f) => ({ ...f, password: '' }))
      setNotice(t('mail.savedNotice', { host: r.data.host, port: r.data.port }))
      if (onConfigured) onConfigured(r.data)
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  async function sendTest() {
    setError('')
    setNotice('')
    if (!testTo.trim()) { setError(t('mail.error.testRecipient')); return }
    setBusy('test')
    try {
      const r = await api.post('/api/v1/deployment/mail/test',
        { to: testTo.trim(), actor: 'console' })
      setNotice(t('mail.testDelivered', { to: r.data.to, via: sourceLabel }))
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  async function useEnvironment() {
    setError('')
    setNotice('')
    setBusy('reset')
    try {
      const r = await api.del('/api/v1/deployment/mail?actor=console')
      setStatus(r.data)
      setForm({ ...DEFAULT_FORM, host: r.data.host || '', port: r.data.port || 587,
        sender: r.data.sender || DEFAULT_FORM.sender })
      setNotice(r.data.source === 'environment'
        ? t('mail.resetEnvironment')
        : t('mail.resetOff'))
      if (onConfigured) onConfigured(r.data)
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  const sourceText = status?.source === 'database'
    ? t('mail.source.database')
    : status?.source === 'environment'
      ? t('mail.source.environment')
      : t('mail.source.none')
  const sourceLabel = status?.source === 'database'
    ? t('mail.sourceLabel.database')
    : status?.source === 'environment'
      ? t('mail.sourceLabel.environment')
      : t('mail.sourceLabel.none')

  return (
    <div className="stack" style={{ gap: 10 }}>
      {status && (
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          {t('mail.status.delivery')} <strong>{status.configured ? `${status.host}:${status.port}` : t('mail.status.off')}</strong>
          {' · '}{sourceText}
          {status.password_set ? t('mail.status.passwordStored') : ''}
          {status.updated_by ? t('mail.status.lastChangedBy', { user: status.updated_by }) : ''}
        </p>
      )}

      <form onSubmit={save} className="onb-form onb-grid" style={{ maxWidth: 'none' }}>
        <label>
          {t('mail.host')}
          <input value={form.host} placeholder="smtp.example.com"
            onChange={(e) => setForm({ ...form, host: e.target.value })} />
        </label>
        <label>
          {t('mail.port')}
          <input type="number" min="1" max="65535" value={form.port}
            onChange={(e) => setForm({ ...form, port: e.target.value })} />
          <span className="onb-help">{t('mail.portHint')}</span>
        </label>
        <label>
          {t('mail.sender')}
          <input value={form.sender} placeholder="barad-dur@example.com"
            onChange={(e) => setForm({ ...form, sender: e.target.value })} />
        </label>
        <label>
          {t('mail.user')}
          <input value={form.user} autoComplete="off" placeholder={t('mail.userPlaceholder')}
            onChange={(e) => setForm({ ...form, user: e.target.value })} />
        </label>
        <label>
          {t('mail.password')}
          <input type="password" value={form.password} autoComplete="new-password"
            placeholder={status?.password_set ? t('mail.passwordStoredPlaceholder') : t('mail.passwordNotSet')}
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <span className="onb-help">{t('mail.passwordHint')}</span>
        </label>
        <label className="onb-check">
          <input type="checkbox" checked={form.starttls}
            onChange={(e) => setForm({ ...form, starttls: e.target.checked })} />
          <span>{t('mail.starttls')}</span>
          <span className="onb-help">{t('mail.starttlsHint')}</span>
        </label>
        <div className="onb-form-actions row" style={{ gap: 10 }}>
          <button className="btn-primary" type="submit" disabled={busy === 'save'}>
            {busy === 'save' ? t('mail.saving') : t('mail.save')}
          </button>
          {status?.source === 'database' && (
            <button type="button" className="mini quiet" onClick={useEnvironment}
              disabled={busy === 'reset'}>{t('mail.useEnvironment')}</button>
          )}
        </div>
      </form>

      <div className="onb-inline-form" style={{ maxWidth: 'none' }}>
        <input value={testTo} placeholder={t('mail.testPlaceholder')} type="email"
          onChange={(e) => setTestTo(e.target.value)} />
        <span className="onb-help" style={{ alignSelf: 'center' }}>
          {t('mail.testHint')}
        </span>
        <button type="button" className="mini" onClick={sendTest} disabled={busy === 'test'}>
          {busy === 'test' ? t('mail.testSending') : t('mail.testSend')}
        </button>
      </div>

      {notice && <p className="banner banner-info" role="status">{notice}</p>}
      {error && <p className="banner banner-error" role="alert">{error}</p>}
    </div>
  )
}
