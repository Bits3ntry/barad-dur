import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function Settings({ onClose }) {
  const [form, setForm] = useState(api.settings())
  const [login, setLogin] = useState({ email: '', password: '', org_slug: '' })
  const [identity, setIdentity] = useState(null)
  const [keys, setKeys] = useState({ rows: [], total: 0, error: '', fresh: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  function loadKeys() {
    api.get('/api/v1/org/keys')
      .then((r) => setKeys((k) => ({ ...k, rows: r.data, total: r.total, error: '' })))
      .catch((e) => setKeys((k) => ({ ...k, error: String(e.message || e) })))
  }

  async function createKey() {
    try {
      const r = await api.post('/api/v1/org/keys', { label: 'console', actor: 'console' })
      setKeys((k) => ({ ...k, fresh: r.data.key, error: '' }))
      loadKeys()
    } catch (e) { setKeys((k) => ({ ...k, error: String(e.message || e) })) }
  }

  async function revokeKey(row) {
    if (!window.confirm(`Revoke key "${row.label}"? Clients using it will get 401.`)) return
    try {
      await api.post(`/api/v1/org/keys/${row.id}/revoke`,
        { actor: 'console', reason: 'revoked from console' })
      loadKeys()
    } catch (e) { setKeys((k) => ({ ...k, error: String(e.message || e) })) }
  }

  useEffect(() => {
    api.get('/api/v1/auth/me')
      .then((r) => setIdentity(r.data))
      .catch(() => setIdentity(null))
    loadKeys()
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
    <div className="stack">
      <div className="row">
        <span className="muted">API key, user session or sign-in</span>
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
      <h3 className="section">service identities (API keys)</h3>
      {keys.error && <p className="error">{keys.error}</p>}
      {keys.fresh && (
        <p className="receipt">
          new key (shown once): <code>{keys.fresh}</code>
        </p>
      )}
      <table>
        <thead><tr><th>label</th><th>created</th><th>status</th><th></th></tr></thead>
        <tbody>
          {keys.rows.map((row) => (
            <tr key={row.id}>
              <td>{row.label || '—'}</td>
              <td>{row.created_at ? new Date(row.created_at).toLocaleString() : '—'}</td>
              <td><span className={`status st-${row.revoked_at ? 'disabled' : 'active'}`}>
                {row.revoked_at ? 'revoked' : 'active'}
              </span></td>
              <td>{!row.revoked_at && (
                <button className="mini" onClick={() => revokeKey(row)}>revoke</button>
              )}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="card">
        <button onClick={createKey}>create service key</button>
        <span className="hint">admin only; the last active key cannot be revoked</span>
      </div>

      <p className="hint">
        The first account is created with <code>POST /api/v1/auth/bootstrap</code>{' '}
        plus the deployment's <code>BOOTSTRAP_TOKEN</code>; later accounts are
        managed from the members tab.
      </p>
    </div>
  )
}
