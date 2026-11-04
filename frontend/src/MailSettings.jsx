import React, { useEffect, useState } from 'react'
import { api } from './api'

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
    if (!form.host.trim()) { setError('A mail server name is required.'); return }
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
      setNotice(`Saved. Mail will leave through ${r.data.host}:${r.data.port}.`)
      if (onConfigured) onConfigured(r.data)
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  async function sendTest() {
    setError('')
    setNotice('')
    if (!testTo.trim()) { setError('Enter an address to receive the test.'); return }
    setBusy('test')
    try {
      const r = await api.post('/api/v1/deployment/mail/test',
        { to: testTo.trim(), actor: 'console' })
      setNotice(`Test delivered to ${r.data.to} via ${sourceLabel}.`)
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
        ? 'Configuration removed. The deployment environment takes over.'
        : 'Configuration removed. Email delivery is off until one of the two is set.')
      if (onConfigured) onConfigured(r.data)
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  const sourceText = status?.source === 'database'
    ? 'saved here (wins over the environment)'
    : status?.source === 'environment'
      ? 'from the deployment environment'
      : 'not configured'
  const sourceLabel = status?.source === 'database'
    ? 'the saved configuration'
    : status?.source === 'environment'
      ? 'the deployment environment'
      : 'nothing'

  return (
    <div className="stack" style={{ gap: 10 }}>
      {status && (
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          Delivery: <strong>{status.configured ? `${status.host}:${status.port}` : 'off'}</strong>
          {' · '}{sourceText}
          {status.password_set ? ' · password stored' : ''}
          {status.updated_by ? ` · last changed by ${status.updated_by}` : ''}
        </p>
      )}

      <form onSubmit={save} className="onb-form onb-grid" style={{ maxWidth: 'none' }}>
        <label>
          Mail server
          <input value={form.host} placeholder="smtp.example.com"
            onChange={(e) => setForm({ ...form, host: e.target.value })} />
        </label>
        <label>
          Port
          <input type="number" min="1" max="65535" value={form.port}
            onChange={(e) => setForm({ ...form, port: e.target.value })} />
          <span className="onb-help">587 with STARTTLS, 465 implicit TLS, 25 plain relay.</span>
        </label>
        <label>
          From address
          <input value={form.sender} placeholder="barad-dur@example.com"
            onChange={(e) => setForm({ ...form, sender: e.target.value })} />
        </label>
        <label>
          Username
          <input value={form.user} autoComplete="off" placeholder="empty = anonymous relay"
            onChange={(e) => setForm({ ...form, user: e.target.value })} />
        </label>
        <label>
          Password
          <input type="password" value={form.password} autoComplete="new-password"
            placeholder={status?.password_set ? 'stored — leave blank to keep it' : 'not set'}
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <span className="onb-help">Encrypted before it is stored; never shown again.</span>
        </label>
        <label className="onb-check">
          <input type="checkbox" checked={form.starttls}
            onChange={(e) => setForm({ ...form, starttls: e.target.checked })} />
          <span>STARTTLS</span>
          <span className="onb-help">Most relays on port 587 require it; turn it off for a plain local relay.</span>
        </label>
        <div className="onb-form-actions row" style={{ gap: 10 }}>
          <button className="btn-primary" type="submit" disabled={busy === 'save'}>
            {busy === 'save' ? 'Saving…' : 'Save mail server'}
          </button>
          {status?.source === 'database' && (
            <button type="button" className="mini quiet" onClick={useEnvironment}
              disabled={busy === 'reset'}>use environment instead</button>
          )}
        </div>
      </form>

      <div className="onb-inline-form" style={{ maxWidth: 'none' }}>
        <input value={testTo} placeholder="send a test to…" type="email"
          onChange={(e) => setTestTo(e.target.value)} />
        <span className="onb-help" style={{ alignSelf: 'center' }}>
          A configuration only counts once a server accepts a message.
        </span>
        <button type="button" className="mini" onClick={sendTest} disabled={busy === 'test'}>
          {busy === 'test' ? 'sending…' : 'send test'}
        </button>
      </div>

      {notice && <p className="banner banner-info" role="status">{notice}</p>}
      {error && <p className="banner banner-error" role="alert">{error}</p>}
    </div>
  )
}
