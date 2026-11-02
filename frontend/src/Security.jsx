import React, { useEffect, useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, PageHeader, Input } from './ui'

/* My security: the second factor, by the person it protects.

   Enrolment is a handshake, and the screen says so: the secret is shown, a code
   confirms the authenticator actually has it, and only then does login start
   asking for it. Recovery codes appear exactly once. */

export default function Security() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [password, setPassword] = useState('')
  const [enrolment, setEnrolment] = useState(null)
  const [code, setCode] = useState('')
  const [recovery, setRecovery] = useState(null)
  const [disableCode, setDisableCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [identity, setIdentity] = useState(null)

  function load() {
    setError('')
    setLoading(true)
    Promise.all([
      api.get('/api/v1/auth/mfa').then((r) => r.data),
      api.get('/api/v1/auth/me').then((r) => r.data).catch(() => null),
    ])
      .then(([mfa, me]) => { setStatus(mfa); setIdentity(me) })
      .catch((e) => setError(String(e.message || e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  async function startEnrol() {
    setError('')
    setBusy(true)
    try {
      const { data } = await api.post('/api/v1/auth/mfa/enroll', { password })
      setEnrolment(data)
      setPassword('')
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function confirmEnrol() {
    setError('')
    setBusy(true)
    try {
      const { data } = await api.post('/api/v1/auth/mfa/activate', { code: code.trim() })
      setRecovery(data.recovery_codes)
      setEnrolment(null)
      setCode('')
      load()
    } catch (e) {
      setError('That code did not match. Check the authenticator clock and try the next one.')
    } finally {
      setBusy(false)
    }
  }

  async function disable() {
    setError('')
    setBusy(true)
    try {
      await api.post('/api/v1/auth/mfa/disable', { code: disableCode.trim() })
      setDisableCode('')
      load()
    } catch (e) {
      setError('To turn the factor off you need a current code or a recovery code.')
    } finally {
      setBusy(false)
    }
  }

  async function rotateCodes() {
    setError('')
    setBusy(true)
    try {
      const { data } = await api.post('/api/v1/auth/mfa/recovery-codes', { password })
      setRecovery(data.recovery_codes)
      setPassword('')
      load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const isUser = identity?.kind === 'user'

  return (
    <div className="stack">
      <PageHeader
        title="My security"
        subtitle="Optional second factor for your own account — it is never enabled on your behalf"
        actions={<button onClick={load}>refresh</button>}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      {!isUser && identity && (
        <Card title="Second factor needs a signed-in user">
          <EmptyState title="You are using an API key"
            hint="Multi-factor belongs to a person. Sign in with email and password (or SSO) to manage it." />
        </Card>
      )}

      {isUser && status && (
        <Card title="Multi-factor authentication (TOTP)"
          actions={<span className={`status st-${status.enabled ? 'active' : 'disabled'}`}>
            {status.enabled ? 'enabled' : 'off'}
          </span>}>
          {!status.enabled && !enrolment && (
            <>
              <p className="muted" style={{ marginTop: 0 }}>
                Works with any authenticator app (Google Authenticator, 1Password, Aegis…).
                Enrolment is two steps: scan the secret, then prove a code from it.
              </p>
              <Input label="Confirm your password to start" type="password" value={password}
                onChange={setPassword} placeholder="current password" />
              <button className="primary-action" disabled={busy || !password} onClick={startEnrol}>
                start enrolment
              </button>
            </>
          )}

          {enrolment && (
            <div className="stack">
              <p className="muted" style={{ marginTop: 0 }}>
                Scan with the authenticator, or type the secret. Nothing changes at
                login until you confirm a code.
              </p>
              <div className="mfa-enrol">
                <div className="mfa-qr">
                  <QRCodeSVG value={enrolment.otpauth} size={148} includeMargin />
                </div>
                <div className="stack" style={{ gap: 6 }}>
                  <span className="muted">secret (manual entry)</span>
                  <code className="mono" style={{ fontSize: 13, wordBreak: 'break-all' }}>
                    {enrolment.secret}
                  </code>
                  <span className="muted" style={{ fontSize: 12 }}>
                    {enrolment.digits} digits · {enrolment.period}s period · SHA1
                  </span>
                  <a className="link" href={enrolment.otpauth}>open in authenticator</a>
                </div>
              </div>
              <Input label="Code from the app" value={code} onChange={setCode}
                placeholder="123456" />
              <div className="row">
                <button className="primary-action" disabled={busy || code.trim().length < 6}
                  onClick={confirmEnrol}>confirm and enable</button>
                <button onClick={() => { setEnrolment(null); setCode('') }}>cancel</button>
              </div>
            </div>
          )}

          {recovery && (
            <div className="stack">
              <p className="muted" style={{ marginTop: 0 }}>
                Save these now — they are shown once and each works a single time.
              </p>
              <div className="mfa-codes">
                {recovery.map((item) => <code key={item}>{item}</code>)}
              </div>
              <button onClick={() => setRecovery(null)}>I saved them</button>
            </div>
          )}

          {status.enabled && (
            <div className="stack">
              <p className="muted" style={{ marginTop: 0 }}>
                {status.recovery_codes_left} recovery code(s) left
                {status.enrolled_at
                  ? ` · enabled ${new Date(status.enrolled_at).toLocaleDateString()}` : ''}.
              </p>
              <div className="row">
                <Input label="Confirm password to rotate codes" type="password" value={password}
                  onChange={setPassword} placeholder="current password" />
                <button disabled={busy || !password} onClick={rotateCodes}>
                  new recovery codes
                </button>
              </div>
              <div className="row">
                <Input label="Code or recovery code to turn it off" value={disableCode}
                  onChange={setDisableCode} placeholder="123456 or XXXXX-XXXXX" />
                <button className="btn-danger" disabled={busy || !disableCode.trim()}
                  onClick={disable}>disable multi-factor</button>
              </div>
            </div>
          )}
        </Card>
      )}

      {loading && !status && <Card><span className="muted">loading…</span></Card>}
    </div>
  )
}
