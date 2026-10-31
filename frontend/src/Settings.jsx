import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function Settings({ onClose }) {
  const [form, setForm] = useState(api.settings())
  const [login, setLogin] = useState({ email: '', password: '', org_slug: '' })
  const [identity, setIdentity] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.get('/api/v1/auth/me')
      .then((r) => setIdentity(r.data))
      .catch(() => setIdentity(null))
  }, [])

  function save(event) {
    event.preventDefault()
    api.save({
      url: form.url.trim(),
      key: (form.key || '').trim(),
      token: (form.token || '').trim(),
    })
    onClose(true)
  }

  async function signIn(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      const payload = { email: login.email.trim(), password: login.password }
      if (login.org_slug.trim()) payload.org_slug = login.org_slug.trim()
      const response = await api.post('/api/v1/auth/login', payload)
      const next = { url: form.url.trim(), key: '', token: response.session.token }
      api.save(next)
      setForm(next)
      setIdentity({ kind: 'user', role: response.session.role,
                    user: { email: response.session.email,
                            display_name: response.session.display_name } })
      setLogin({ email: '', password: '', org_slug: '' })
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function signOut() {
    try { await api.post('/api/v1/auth/logout', {}) } catch { /* session may be gone */ }
    const next = { url: form.url.trim(), key: '', token: '' }
    api.save(next)
    setForm(next)
    setIdentity(null)
  }

  return (
    <div className="card">
      <div className="bar">
        <h3>Connection</h3>
        <button className="mini" onClick={() => onClose(false)}>close</button>
      </div>
      {identity && (
        <p className="muted">
          {identity.kind === 'api_key'
            ? `service identity · ${identity.org}`
            : `${identity.user?.email} · ${identity.role} · ${identity.org}`}{' '}
          {identity.kind === 'user' && <button className="mini" onClick={signOut}>sign out</button>}
        </p>
      )}
      <form onSubmit={save}>
        <label>
          Platform URL
          <input
            value={form.url}
            onChange={(e) => setForm({ ...form, url: e.target.value })}
            placeholder="http://127.0.0.1:8090"
            autoComplete="off"
          />
        </label>
        <label>
          API key (service identity)
          <input
            value={form.key || ''}
            onChange={(e) => setForm({ ...form, key: e.target.value, token: '' })}
            placeholder="raw key (stored in this browser's localStorage)"
            autoComplete="off"
          />
        </label>
        <button type="submit">save</button>
      </form>
      <p className="hint">
        The key stays local to this browser and rides the X-API-Key header.
        Signing in with a user account replaces it with a session token that
        carries the account's role.
      </p>

      <h3 className="section">sign in</h3>
      {error && <p className="error">{error}</p>}
      <form onSubmit={signIn}>
        <label>
          Email
          <input value={login.email} autoComplete="username"
            onChange={(e) => setLogin({ ...login, email: e.target.value })} />
        </label>
        <label>
          Password
          <input type="password" value={login.password} autoComplete="current-password"
            onChange={(e) => setLogin({ ...login, password: e.target.value })} />
        </label>
        <label>
          Org slug (only needed when the email exists in several orgs)
          <input value={login.org_slug} autoComplete="off"
            onChange={(e) => setLogin({ ...login, org_slug: e.target.value })} />
        </label>
        <button type="submit" disabled={busy}>{busy ? 'signing in…' : 'sign in'}</button>
      </form>
      <p className="hint">
        The first account is created with <code>POST /api/v1/auth/bootstrap</code>{' '}
        plus the deployment's <code>BOOTSTRAP_TOKEN</code>; later accounts are
        managed from the members tab.
      </p>
    </div>
  )
}
