import React, { useEffect, useState } from 'react'
import { api } from './api'
import { BrandMark } from './Login'

/* The public end of an invitation. Nothing here knows the workspace's data:
   the token resolves to one seat (organization name, role, email) and that is
   all this screen ever shows. */

function readToken() {
  const hash = new URLSearchParams((window.location.hash || '').replace(/^#/, ''))
  const query = new URLSearchParams(window.location.search)
  return hash.get('token') || query.get('token') || ''
}

export default function Invite() {
  const [token] = useState(readToken)
  const [invite, setInvite] = useState(null)
  const [error, setError] = useState('')
  const [form, setForm] = useState({ display_name: '', password: '', confirm: '' })
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!token) { setError('This link is missing its invitation token.'); return }
    api.get(`/api/v1/auth/invitations/${encodeURIComponent(token)}`)
      .then((r) => setInvite(r.data))
      .catch(() => setError('This invitation is unknown or has been removed.'))
  }, [token])

  async function accept(event) {
    event.preventDefault()
    setError('')
    if (form.password.length < 8) {
      setError('Choose a password with at least 8 characters.')
      return
    }
    if (form.password !== form.confirm) {
      setError('The two passwords do not match.')
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
              <h1 className="auth-h1">This link cannot be used</h1>
              <p className="auth-sub">{error} Ask an administrator for a new invitation.</p>
            </>
          )}

          {!invite && !error && <p className="auth-sub">Checking your invitation…</p>}

          {invite && (
            <>
              <span className="onb-kicker">Invitation</span>
              <h1 className="auth-h1">Join {invite.org_name}</h1>
              <p className="auth-sub">
                You were invited as <strong>{invite.role_label}</strong> with{' '}
                <strong>{invite.email}</strong>.
                {invite.expires_at && ` The link expires on ${new Date(invite.expires_at).toLocaleString()}.`}
              </p>

              {!invite.valid && (
                <p className="banner banner-error">
                  This invitation is {invite.status} and can no longer be accepted.
                  Ask an administrator for a new one.
                </p>
              )}

              {invite.valid && (
                <form onSubmit={accept} className="onb-form">
                  <label>
                    Your name
                    <input value={form.display_name}
                      onChange={(e) => setForm({ ...form, display_name: e.target.value })}
                      placeholder="How teammates will see you" autoComplete="name" />
                  </label>
                  <label>
                    Password
                    <input type="password" value={form.password}
                      onChange={(e) => setForm({ ...form, password: e.target.value })}
                      placeholder="At least 8 characters" autoComplete="new-password" />
                  </label>
                  <label>
                    Confirm password
                    <input type="password" value={form.confirm}
                      onChange={(e) => setForm({ ...form, confirm: e.target.value })}
                      autoComplete="new-password" />
                  </label>
                  {error && <p className="banner banner-error">{error}</p>}
                  <button className="btn-primary" type="submit" disabled={busy}>
                    {busy ? 'Joining…' : 'Accept and sign in'}
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
