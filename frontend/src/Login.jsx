import React, { useEffect, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { Dialog, Input, Loading, Banner } from './ui'

const STARTUP_STEPS = [
  { id: 'owner', labelKey: 'login.progress.owner' },
  { id: 'details', labelKey: 'login.progress.details' },
  { id: 'team', labelKey: 'login.progress.team' },
  { id: 'code', labelKey: 'login.progress.code' },
  { id: 'tickets', labelKey: 'login.progress.tickets' },
  { id: 'enter', labelKey: 'login.progress.enter' },
]

function slugify(value) {
  return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
}

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
  const { t } = useI18n()
  const [mode, setMode] = useState('signin')
  const [form, setForm] = useState({ email: '', password: '', org_slug: '', url: '', key: '' })
  const [setup, setSetup] = useState({
    org_name: '', org_slug: '', email: '', display_name: '', password: '', setup_code: '',
  })
  const [bootstrap, setBootstrap] = useState(undefined)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [resetOpen, setResetOpen] = useState(false)
  const [resetEmail, setResetEmail] = useState('')
  const [sso, setSso] = useState(null)
  const [challenge, setChallenge] = useState(null)
  const [mfaCode, setMfaCode] = useState('')
  const [mfaBusy, setMfaBusy] = useState(false)
  const [useRecovery, setUseRecovery] = useState(false)

  // SSO is offered only when the deployment configured it; a button that leads
  // to a 503 is worse than no button.
  useEffect(() => {
    api.get('/api/v1/auth/oidc/status')
      .then((r) => setSso(r.data))
      .catch(() => setSso(null))
    api.get('/api/v1/auth/bootstrap/status')
      .then((r) => {
        setBootstrap(r.data)
        if (r.data?.available && r.data?.setup_enabled) {
          setMode('setup')
          if (!r.data.organization_exists && window.location.pathname !== '/startup') {
            window.history.replaceState({}, '', '/startup')
          }
        }
      })
      .catch(() => setBootstrap(null))
  }, [])

  const set = (field) => (event) => setForm((f) => ({ ...f, [field]: event.target.value }))
  const setSetupField = (field) => (event) => {
    const value = field === 'org_slug' ? slugify(event.target.value) : event.target.value
    setSetup((current) => ({ ...current, [field]: value }))
  }

  function openSetup() {
    setMode('setup')
    setError('')
  }

  function openSignIn() {
    setMode('signin')
    setError('')
  }

  function openApiKey() {
    setMode('key')
    setError('')
  }

  async function submit(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    const url = form.url.trim()
    const previous = api.settings()
    try {
      if (mode === 'setup') {
        if (!setup.org_name.trim() || !setup.org_slug.trim() || !setup.email.trim()
          || !setup.password || !setup.setup_code.trim()) {
          throw new Error(t('login.error.setupRequired'))
        }
        const response = await api.post('/api/v1/auth/bootstrap', {
          org_name: setup.org_name.trim(),
          org_slug: setup.org_slug.trim(),
          email: setup.email.trim(),
          display_name: setup.display_name.trim() || undefined,
          password: setup.password,
        }, { headers: { 'X-Bootstrap-Token': setup.setup_code.trim() } })
        api.save({
          url,
          key: '',
          token: response.session.access_token,
          refresh_token: response.session.refresh_token,
          expires_at: response.session.expires_at,
        })
        window.history.replaceState({}, '', '/startup#step=2')
        onAuthenticated({ firstSetup: true })
        return
      }
      if (mode === 'key') {
        if (form.key.trim().length < 8) throw new Error(t('login.error.keyTooShort'))
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
        throw new Error(t('login.error.credentialsRequired'))
      }
      const payload = { email: form.email.trim(), password: form.password }
      if (form.org_slug.trim()) payload.org_slug = form.org_slug.trim()
      api.save({ url, key: '', token: '' })
      const response = await api.post('/api/v1/auth/login', payload)
      if (response.data?.mfa_required) {
        setChallenge(response.data)
        setForm((f) => ({ ...f, password: '' }))
        setMode('signin')
        return
      }
      api.save({
        url,
        key: '',
        token: response.session.access_token,
        refresh_token: response.session.refresh_token,
        expires_at: response.session.expires_at,
      })
      onAuthenticated()
    } catch (e) {
      const message = String(e.message || e)
      setError(message.includes('401')
        ? (mode === 'setup' ? t('login.error.setupCodeRejected') : t('login.error.credentialsRejected'))
        : message)
    } finally {
      setBusy(false)
    }
  }

  async function requestReset(event) {
    // called by the dialog's confirm button (no event) and by the form submit
    if (event && event.preventDefault) event.preventDefault()
    setError('')
    if (!resetEmail.trim()) { setError(t('login.error.resetEmailRequired')); return }
    try {
      const response = await api.post('/api/v1/auth/password/reset/request', { email: resetEmail.trim() })
      setError(response.data?.ok
        ? t('login.reset.sent')
        : response.data?.message || t('login.reset.noAccount'))
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  /* Pre-session exchange: the code proves the second factor before any
     credential exists, so it cannot go through api.post (which refuses to run
     without a key or token). */
  async function postPublic(path, payload) {
    const base = (api.settings().url || '').replace(/\/$/, '')
    const response = await fetch(`${base}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const body = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`)
    return body
  }

  async function verifyMfa(event) {
    event.preventDefault()
    setError('')
    setMfaBusy(true)
    try {
      const response = await postPublic('/api/v1/auth/mfa/verify', {
        challenge: challenge.challenge,
        code: mfaCode.trim(),
      })
      api.save({
        url: form.url.trim(),
        key: '',
        token: response.session.access_token,
        refresh_token: response.session.refresh_token,
        expires_at: response.session.expires_at,
      })
      onAuthenticated()
    } catch (e) {
      setError(t('login.mfa.rejected'))
    } finally {
      setMfaBusy(false)
    }
  }

  async function startSso() {
    setError('')
    const slug = form.org_slug.trim()
    if (!slug) {
      setError(t('login.error.ssoSlugRequired'))
      return
    }
    try {
      const response = await api.get(
        `/api/v1/auth/oidc/start?org_slug=${encodeURIComponent(slug)}`)
      const target = response.data?.authorization_url || response.authorization_url
      if (!target) throw new Error(t('login.error.ssoNoRedirect'))
      window.location.assign(target)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const isStartup = mode === 'setup' && bootstrap?.organization_exists === false

  return (
    <div className={isStartup ? 'gate startup-gate' : 'gate'}>
      {!isStartup && <section className="gate-brand">
        <div className="row" style={{ gap: 12 }}>
          <BrandMark size={38} />
          <span className="gate-eyebrow">{t('login.brand.eyebrow')}</span>
        </div>
        <h1 className="gate-title">BARAD<span>-</span>DÛR</h1>
        <p className="gate-copy">{t('login.brand.copy')}</p>
        <ul className="gate-list">
          <li>{t('login.brand.point.findings')}</li>
          <li>{t('login.brand.point.sbom')}</li>
          <li>{t('login.brand.point.review')}</li>
          <li>{t('login.brand.point.scan')}</li>
        </ul>
        <p className="gate-foot">{t('login.brand.foot')}</p>
      </section>}

      <section className="gate-panel">
        <div className="auth-card">
          <div>
            <h2 className="auth-h1">{bootstrap === undefined
              ? t('login.title.preparing')
              : mode === 'setup' ? t('login.title.setup')
              : mode === 'signin' ? t('login.title.signin') : t('login.title.key')}</h2>
            <p className="auth-sub">
              {bootstrap === undefined
                ? t('login.sub.preparing')
                : mode === 'setup' ? t('login.sub.setup')
                : mode === 'signin'
                ? t('login.sub.signin')
                : t('login.sub.key')}
            </p>
          </div>

          {bootstrap !== undefined && !(bootstrap?.available && bootstrap?.setup_enabled) && (
          <div className="auth-tabs" role="tablist">
            <button role="tab" aria-selected={mode === 'signin'}
              className={mode === 'signin' ? 'active' : ''}
              onClick={openSignIn}>{t('login.tab.signin')}</button>
            {bootstrap?.available && bootstrap?.setup_enabled && (
              <button role="tab" aria-selected={mode === 'setup'}
                className={mode === 'setup' ? 'active' : ''}
                onClick={openSetup}>{t('login.tab.setup')}</button>
            )}
            <button role="tab" aria-selected={mode === 'key'}
              className={mode === 'key' ? 'active' : ''}
              onClick={openApiKey}>{t('login.tab.key')}</button>
          </div>
          )}

          {error && <div className="banner banner-error" role="alert">{error}</div>}

          {mode === 'setup' && !bootstrap?.organization_exists && (
            <div className="startup-progress" aria-label={t('login.progress.aria')}>
              <div className="startup-progress-label">
                {t('login.progress.step', { current: 1, total: STARTUP_STEPS.length })}
              </div>
              <ol>
                {STARTUP_STEPS.map((step, index) => (
                  <li key={step.id} className={index === 0 ? 'current' : ''}>
                    <span>{index + 1}</span>{t(step.labelKey)}
                  </li>
                ))}
              </ol>
              <p>{t('login.progress.foot')}</p>
            </div>
          )}

          {bootstrap === undefined ? (
            <Loading rows={2} label={t('login.loading.checking')} />
          ) : challenge ? (
            <form onSubmit={verifyMfa}>
              <p className="auth-sub">
                {useRecovery
                  ? t('login.mfa.subRecovery')
                  : t('login.mfa.sub')}
              </p>
              <label>
                <span>{useRecovery ? t('login.mfa.recoveryLabel') : t('login.mfa.codeLabel')}</span>
                <input
                  autoFocus
                  value={mfaCode}
                  onChange={(event) => setMfaCode(event.target.value)}
                  inputMode={useRecovery ? 'text' : 'numeric'}
                  autoComplete="one-time-code"
                  placeholder={useRecovery ? 'XXXXX-XXXXX' : '123456'}
                />
              </label>
              <button className="btn-primary" type="submit" disabled={mfaBusy || !mfaCode.trim()}>
                {mfaBusy ? t('login.mfa.checking') : t('login.mfa.verify')}
              </button>
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <button type="button" className="link"
                  onClick={() => { setUseRecovery((v) => !v); setMfaCode('') }}>
                  {useRecovery ? t('login.mfa.useAuthenticator') : t('login.mfa.useRecovery')}
                </button>
                <button type="button" className="link"
                  onClick={() => { setChallenge(null); setMfaCode(''); setUseRecovery(false) }}>
                  {t('login.mfa.backToSignIn')}
                </button>
              </div>
            </form>
          ) : (
          <form onSubmit={submit}>
            {mode === 'setup' ? (
              <>
                <label>
                  <span>{t('login.field.workspaceName')}</span>
                  <input autoFocus value={setup.org_name} onChange={setSetupField('org_name')}
                    placeholder={t('login.placeholder.workspaceName')} />
                </label>
                <label>
                  <span>{t('login.field.workspaceSlug')}</span>
                  <input value={setup.org_slug} onChange={setSetupField('org_slug')}
                    placeholder={t('login.placeholder.workspaceSlug')} />
                </label>
                <label>
                  <span>{t('login.field.yourName')}</span>
                  <input value={setup.display_name} onChange={setSetupField('display_name')}
                    placeholder={t('login.placeholder.yourName')} />
                </label>
                <label>
                  <span>{t('login.field.ownerEmail')}</span>
                  <input type="email" autoComplete="username" value={setup.email}
                    onChange={setSetupField('email')} placeholder={t('login.placeholder.email')} />
                </label>
                <label>
                  <span>{t('login.field.password')}</span>
                  <input type="password" autoComplete="new-password" value={setup.password}
                    onChange={setSetupField('password')} placeholder={t('login.placeholder.password')} />
                </label>
                <label>
                  <span>{t('login.field.setupCode')}</span>
                  <input type="password" autoComplete="off" value={setup.setup_code}
                    onChange={setSetupField('setup_code')} placeholder={t('login.placeholder.setupCode')} />
                </label>
              </>
            ) : mode === 'signin' ? (
              <>
                <label>
                  <span>{t('login.field.email')}</span>
                  <input type="email" autoComplete="username" autoFocus
                    value={form.email} onChange={set('email')} placeholder={t('login.placeholder.email')} />
                </label>
                <label>
                  <span>{t('login.field.password')}</span>
                  <input type="password" autoComplete="current-password"
                    value={form.password} onChange={set('password')} placeholder="••••••••" />
                </label>
                <label>
                  <span>{t('login.field.organization')} <span className="muted">{t('login.field.organizationHint')}</span></span>
                  <input value={form.org_slug} onChange={set('org_slug')} placeholder={t('login.placeholder.slug')} />
                </label>
              </>
            ) : (
              <label>
                <span>{t('login.field.apiKey')}</span>
                <input type="password" autoFocus value={form.key} onChange={set('key')}
                  placeholder="bdr_…" />
              </label>
            )}

            <label>
              <span>{t('login.field.platformUrl')} <span className="muted">{t('login.field.platformUrlHint')}</span></span>
              <input value={form.url} onChange={set('url')} placeholder="https://barad.example.com" />
            </label>

            <button className="btn-primary" type="submit" disabled={busy}>
              {busy ? t('login.busy.checking') : mode === 'setup' ? t('login.submit.create')
                : mode === 'signin' ? t('login.submit.enter') : t('login.submit.connect')}
            </button>
          </form>
          )}

          {!challenge && bootstrap !== undefined && sso?.configured && mode === 'signin' && (
            <>
              <button type="button" className="sso-button" onClick={startSso}>
                {t('login.sso.continue', { provider: sso.provider })}
              </button>
              {sso.auto_provision === false && (
                <p className="auth-hint" style={{ borderTop: 'none', paddingTop: 0 }}>
                  {t('login.sso.hint')}
                </p>
              )}
            </>
          )}

          {bootstrap?.available && bootstrap?.setup_enabled && mode !== 'setup' && (
            <p className="auth-hint">
              {t('login.hint.firstInstallPre')}<strong>{t('login.tab.setup')}</strong>{t('login.hint.firstInstallPost')}
            </p>
          )}

          {bootstrap !== undefined && !(bootstrap?.available && bootstrap?.setup_enabled) && (
          <div style={{ marginTop: 14, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="mini" onClick={() => setResetOpen(true)}>{t('login.forgot')}</button>
          </div>
          )}
        </div>
      </section>

      <Dialog open={resetOpen} title={t('login.reset.title')}
        onConfirm={requestReset}
        onClose={() => setResetOpen(false)}
        confirmLabel={t('login.reset.confirm')}>
        <form onSubmit={requestReset}>
          <Input label={t('login.reset.emailLabel')} value={resetEmail}
            onChange={setResetEmail} placeholder={t('login.placeholder.email')} />
          <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
            {t('login.reset.note')}
          </p>
          <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
            {sso?.configured
              ? t('login.reset.ssoConfigured')
              : t('login.reset.ssoMissing')}
          </p>
        </form>
      </Dialog>
    </div>
  )
}
