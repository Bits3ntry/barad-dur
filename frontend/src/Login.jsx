import React, { useState } from 'react'
import { api } from './api'
import { Dialog, Input, Loading, Banner } from './ui'

/* The entrance. Nothing else renders without credentials: an app that shows a
   broken dashboard to a visitor is worse than an honest sign-in screen. */

export function BrandMark({ size = 30 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" role="img" aria-label="Barad-dûr">
      <defs>
        <linearGradient id="bd-eye" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#f7d08a" />
          <stop offset="100%" stopColor="#ff7a45" />
        </linearGradient>
      </defs>
      <path d="M16 1.6 20.6 7h-1.7v3.1h1.9v2.4h1.6v14.9H9.6V12.5h1.6v-2.4h1.9V7h-1.7L16 1.6Z"
        fill="#20242e" stroke="#3a4152" strokeWidth="0.7" />
      <path d="M12.1 7.2 16 3.1l3.9 4.1" fill="none" stroke="url(#bd-eye)"
        strokeWidth="1.1" strokeLinecap="round" />
      <ellipse cx="16" cy="15.1" rx="3.5" ry="2.2" fill="#0b0d12" stroke="#f5c26b"
        strokeWidth="0.9" />
      <circle cx="16" cy="15.1" r="1.15" fill="url(#bd-eye)" />
    </svg>
  )
}

export default function Login({ onAuthenticated }) {
  const [mode, setMode] = useState('signin')
  const [form, setForm] = useState({ email: '', password: '', org_slug: '', url: '', key: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [resetOpen, setResetOpen] = useState(false)
  const [resetEmail, setResetEmail] = useState('')

  const set = (field) => (event) => setForm((f) => ({ ...f, [field]: event.target.value }))

  async function submit(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    const url = form.url.trim()
    const previous = api.settings()
    try {
      if (mode === 'key') {
        if (form.key.trim().length < 8) throw new Error('That API key looks too short.')
        api.save({ url, key: form.key.trim(), token: '' })
        try {
          await api.get('/api/v1/auth/me')
        } catch (probeError) {
          api.save(previous)
          throw probeError
        }
        onAuthenticated()
        return
      }
      if (!form.email.trim() || !form.password) {
        throw new Error('Email and password are required.')
      }
      const payload = { email: form.email.trim(), password: form.password }
      if (form.org_slug.trim()) payload.org_slug = form.org_slug.trim()
      api.save({ url, key: '', token: '' })
      const response = await api.post('/api/v1/auth/login', payload)
      api.save({ url, key: '', token: response.session.token })
      onAuthenticated()
    } catch (e) {
      const message = String(e.message || e)
      setError(message.includes('401') ? 'Those credentials were rejected.' : message)
    } finally {
      setBusy(false)
    }
  }

  async function requestReset(event) {
    // called by the dialog's confirm button (no event) and by the form submit
    if (event && event.preventDefault) event.preventDefault()
    setError('')
    if (!resetEmail.trim()) { setError('Enter the email address on your account.'); return }
    try {
      const response = await api.post('/api/v1/auth/password/reset/request', { email: resetEmail.trim() })
      setError(response.data?.ok
        ? 'Reset link sent. If the address is on file, check your mail (or your admin for the manual link code).'
        : response.data?.message || 'No account found for that address — nothing to do.')
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const oidcConfigured = typeof window !== 'undefined'
    && (localStorage.getItem('barad.oidc') === 'true'
        || (typeof process !== 'undefined' && process.env?.OIDC_ISSUER))

  return (
    <div className="gate">
      <section className="gate-brand">
        <div className="row" style={{ gap: 12 }}>
          <BrandMark size={38} />
          <span className="gate-eyebrow">management plane</span>
        </div>
        <h1 className="gate-title">BARAD<span>-</span>DÛR</h1>
        <p className="gate-copy">
          One place to see what is exposed, what is exploitable and what it costs
          to fix — across supply chain, code, attack surface and pentest work.
        </p>
        <ul className="gate-list">
          <li>Findings with occurrences, priority, SLA and verified remediation.</li>
          <li>SBOM, licenses, VEX and advisory correlation per project version.</li>
          <li>Pull request review with gate verdicts and inline evidence.</li>
          <li>Authorized scanning only: every active job passes the same grant.</li>
        </ul>
        <p className="gate-foot">Self-hosted. Nothing leaves this deployment.</p>
      </section>

      <section className="gate-panel">
        <div className="auth-card">
          <div>
            <h2 className="auth-h1">{mode === 'signin' ? 'Sign in' : 'Connect with an API key'}</h2>
            <p className="auth-sub">
              {mode === 'signin'
                ? 'Your session carries your role.'
                : 'A service identity for automation and scripts.'}
            </p>
          </div>

          <div className="auth-tabs" role="tablist">
            <button role="tab" aria-selected={mode === 'signin'}
              className={mode === 'signin' ? 'active' : ''}
              onClick={() => { setMode('signin'); setError('') }}>Sign in</button>
            <button role="tab" aria-selected={mode === 'key'}
              className={mode === 'key' ? 'active' : ''}
              onClick={() => { setMode('key'); setError('') }}>API key</button>
          </div>

          {error && <div className="banner banner-error" role="alert">{error}</div>}

          <form onSubmit={submit}>
            {mode === 'signin' ? (
              <>
                <label>
                  <span>Email</span>
                  <input type="email" autoComplete="username" autoFocus
                    value={form.email} onChange={set('email')} placeholder="you@company.com" />
                </label>
                <label>
                  <span>Password</span>
                  <input type="password" autoComplete="current-password"
                    value={form.password} onChange={set('password')} placeholder="••••••••" />
                </label>
                <label>
                  <span>Organization <span className="muted">(only if your email belongs to several)</span></span>
                  <input value={form.org_slug} onChange={set('org_slug')} placeholder="slug" />
                </label>
              </>
            ) : (
              <label>
                <span>API key</span>
                <input type="password" autoFocus value={form.key} onChange={set('key')}
                  placeholder="bdr_…" />
              </label>
            )}

            <label>
              <span>Platform URL <span className="muted">(blank = this host)</span></span>
              <input value={form.url} onChange={set('url')} placeholder="https://barad.example.com" />
            </label>

            <button className="btn-primary" type="submit" disabled={busy}>
              {busy ? 'checking…' : mode === 'signin' ? 'Enter' : 'Connect'}
            </button>
          </form>

          <p className="auth-hint">
            First time? The very first account is created with the deployment's
            <span className="mono"> BOOTSTRAP_TOKEN </span> through
            <span className="mono"> POST /api/v1/auth/bootstrap</span>.
          </p>

          <div style={{ marginTop: 14, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="mini" onClick={() => setResetOpen(true)}>Forgot password?</button>
            {oidcConfigured && (
              <button className="mini" onClick={() => { setMode('oidc'); setError('') }}>
                Sign in with OIDC
              </button>
            )}
          </div>
        </div>
      </section>

      <Dialog open={resetOpen} title="Reset your password"
        onConfirm={requestReset}
        onClose={() => setResetOpen(false)}
        confirmLabel="Request reset">
        <form onSubmit={requestReset}>
          <Input label="Email address on file" value={resetEmail}
            onChange={setResetEmail} placeholder="you@company.com" />
          <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
            The reset request goes through the platform's SMTP channel when it is
            configured. If SMTP is not provisioned, the administrator can issue
            a manual reset token and you will be contacted out-of-band.
          </p>
          <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
            {oidcConfigured
              ? 'Password reset is available when OIDC is configured.'
              : 'Password reset requires SMTP. Use the admin recovery process.'}
          </p>
        </form>
      </Dialog>
    </div>
  )
}
