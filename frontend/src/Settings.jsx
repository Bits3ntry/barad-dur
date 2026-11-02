import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Dialog, Input, Select, CheckBox, Loading, Banner, EmptyState, useToasts, Table } from './ui'

export default function Settings({ onClose }) {
  const { toasts, push, dismiss } = useToasts()
  const [form, setForm] = useState(api.settings())
  const [login, setLogin] = useState({ email: '', password: '', org_slug: '' })
  const [identity, setIdentity] = useState(null)
  const [keys, setKeys] = useState({ rows: [], total: 0, error: '', fresh: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [revokeOpen, setRevokeOpen] = useState(false)
  const [revokeRow, setRevokeRow] = useState(null)
  const [signOptions, setSignOptions] = useState({ sso: null, mfa: null })

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
      push('Service key created.', 'success')
    } catch (e) {
      setKeys((k) => ({ ...k, error: String(e.message || e) }))
      push(String(e.message || e), 'error')
    }
  }

  async function revokeKey(row) {
    setRevokeRow(row)
    setRevokeOpen(true)
  }

  async function confirmRevoke() {
    if (!revokeRow) return
    try {
      await api.post(`/api/v1/org/keys/${revokeRow.id}/revoke`,
        { actor: 'console', reason: 'revoked from console' })
      loadKeys()
      push(`Key "${revokeRow.label}" revoked.`, 'success')
    } catch (e) {
      push(String(e.message || e), 'error')
    }
    setRevokeOpen(false)
    setRevokeRow(null)
  }

  useEffect(() => {
    api.get('/api/v1/auth/oidc/status')
      .then((r) => setSignOptions((s) => ({ ...s, sso: r.data })))
      .catch(() => setSignOptions((s) => ({ ...s, sso: null })))
    api.get('/api/v1/auth/mfa')
      .then((r) => setSignOptions((s) => ({ ...s, mfa: r.data })))
      .catch(() => setSignOptions((s) => ({ ...s, mfa: null })))
    api.get('/api/v1/auth/me')
      .then((r) => setIdentity(r.data))
      .catch(() => setIdentity(null))
    loadKeys()
  }, [])

  function save(event) {
    event.preventDefault()
    const next = api.settings()
    const cleared = !form.token.trim()
    api.save({
      url: form.url.trim(),
      key: (form.key || '').trim(),
      token: cleared ? '' : (next.token || ''),
      refresh_token: cleared ? '' : (next.refresh_token || ''),
      expires_at: cleared ? '' : (next.expires_at || ''),
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
      push('Signed in.', 'success')
    } catch (e) {
      setError(String(e.message || e))
      push(String(e.message || e), 'error')
    } finally {
      setBusy(false)
    }
  }

  async function signOut() {
    try { await api.post('/api/v1/auth/logout', {}) } catch { /* session may be gone */ }
    const next = { url: form.url.trim(), key: '', token: '',
      refresh_token: '', expires_at: '' }
    api.save(next)
    setForm(next)
    setIdentity(null)
    push('Signed out.', 'info')
  }

  async function changePassword(event) {
    event.preventDefault()
    setError('')
    if (login.password.length < 8) { setError('Password must be at least 8 characters.'); return }
    if (login.new_password !== login.confirm_password) { setError('New passwords do not match.'); return }
    try {
      await api.post(`/api/v1/auth/users/${identity.user_id}/password`,
        { password: login.new_password, actor: 'console' })
      push('Password changed.', 'success')
      setLogin({ email: '', password: '', org_slug: '', new_password: '', confirm_password: '' })
    } catch (e) {
      setError(String(e.message || e))
      push(String(e.message || e), 'error')
    }
  }

  return (
    <div className="stack">
      <div className="row">
        <span className="muted">API key, user session or sign-in</span>
        <span className="muted" style={{ marginLeft: 'auto', fontSize: 11 }}>
          theme: <select value={form.theme || ''} onChange={(e) => setForm({ ...form, theme: e.target.value })} style={{ minWidth: 100 }}>
            <option value="dark">dark</option>
            <option value="light">light</option>
            <option value="system">system</option>
          </select>{' '}
          density: <select value={form.density || ''} onChange={(e) => setForm({ ...form, density: e.target.value })} style={{ minWidth: 90 }}>
            <option value="comfortable">comfortable</option>
            <option value="compact">compact</option>
          </select>
        </span>
      </div>

      {identity && (
        <p className="muted">
          {identity.kind === 'api_key'
            ? `service identity · ${identity.org}`
            : `${identity.user?.email} · ${identity.role} · ${identity.org}`}{' '}
          {identity.kind === 'user' && <button className="mini" onClick={signOut}>sign out</button>}
        </p>
      )}

      <div className="signin-block">
        <h3 className="section">sign-in and security</h3>
        <p className="muted" style={{ margin: '0 0 6px' }}>
          Second factor:{' '}
          {signOptions.mfa === null
            ? 'needs a signed-in user'
            : signOptions.mfa.enabled
              ? `enabled · ${signOptions.mfa.recovery_codes_left} recovery code(s) left`
              : 'off'}
          {identity?.kind === 'user' && ' — manage it in Administration → My security'}
        </p>
        <p className="muted" style={{ margin: 0 }}>
          Single sign-on:{' '}
          {signOptions.sso?.configured
            ? `${signOptions.sso.provider} · ${signOptions.sso.issuer}`
            : 'not configured'}
          {' · '}
          {signOptions.sso?.configured
            ? (signOptions.sso.auto_provision
              ? 'new identities are provisioned as viewers'
              : 'only accounts that already exist here can sign in')
            : 'set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI'}
        </p>
      </div>

      {identity && identity.kind === 'user' && (
        <>
          <h3 className="section">change password</h3>
          <form onSubmit={changePassword}>
            <Input label="New password" type="password" value={login.new_password}
              onChange={(v) => setLogin({ ...login, new_password: v })} placeholder="at least 8 chars" />
            <Input label="Confirm" type="password" value={login.confirm_password}
              onChange={(v) => setLogin({ ...login, confirm_password: v })} />
            <button type="submit" disabled={busy}>{busy ? 'changing…' : 'Change password'}</button>
          </form>
        </>
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

      <Dialog open={revokeOpen} title={`Revoke key "${revokeRow?.label || ''}"?`}
        onClose={() => setRevokeOpen(false)} confirmLabel="Revoke" destructive onConfirm={confirmRevoke}>
        <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
          Clients using this key will stop working immediately with 401 responses.
          The last active key cannot be revoked.
        </p>
      </Dialog>

      <h3 className="section">sign in</h3>
      {error && <Banner kind="error">{error}</Banner>}
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
      {keys.error && <Banner kind="error">{keys.error}</Banner>}
      {keys.fresh && (
        <p className="receipt">
          new key (shown once): <code>{keys.fresh}</code>
        </p>
      )}
      <Table head={['label', 'created', 'status', '']}>
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
      </Table>
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
