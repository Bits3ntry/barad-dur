import React, { useEffect, useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, PageHeader, Input } from './ui'
import { useI18n } from './i18n'

/* My security: the second factor, by the person it protects.

   Enrolment is a handshake, and the screen says so: the secret is shown, a code
   confirms the authenticator actually has it, and only then does login start
   asking for it. Recovery codes appear exactly once. */

export default function Security() {
  const { t } = useI18n()
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
      setError(t('security.mfa.errorCodeMismatch'))
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
      setError(t('security.disable.errorCode'))
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
        title={t('security.title')}
        subtitle={t('security.subtitle')}
        actions={<button onClick={load}>{t('common.refresh')}</button>}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      {!isUser && identity && (
        <Card title={t('security.apiKey.title')}>
          <EmptyState title={t('security.apiKey.emptyTitle')}
            hint={t('security.apiKey.emptyHint')} />
        </Card>
      )}

      {isUser && status && (
        <Card title={t('security.mfa.title')}
          actions={<span className={`status st-${status.enabled ? 'active' : 'disabled'}`}>
            {status.enabled ? t('security.mfa.enabled') : t('security.mfa.off')}
          </span>}>
          {!status.enabled && !enrolment && (
            <>
              <p className="muted" style={{ marginTop: 0 }}>
                {t('security.mfa.intro')}
              </p>
              <Input label={t('security.mfa.passwordLabel')} type="password" value={password}
                onChange={setPassword} placeholder={t('security.mfa.passwordPlaceholder')} />
              <button className="primary-action" disabled={busy || !password} onClick={startEnrol}>
                {t('security.mfa.start')}
              </button>
            </>
          )}

          {enrolment && (
            <div className="stack">
              <p className="muted" style={{ marginTop: 0 }}>
                {t('security.enrol.intro')}
              </p>
              <div className="mfa-enrol">
                <div className="mfa-qr">
                  <QRCodeSVG value={enrolment.otpauth} size={148} includeMargin />
                </div>
                <div className="stack" style={{ gap: 6 }}>
                  <span className="muted">{t('security.enrol.secretLabel')}</span>
                  <code className="mono" style={{ fontSize: 13, wordBreak: 'break-all' }}>
                    {enrolment.secret}
                  </code>
                  <span className="muted" style={{ fontSize: 12 }}>
                    {t('security.enrol.params', { digits: enrolment.digits, period: enrolment.period })}
                  </span>
                  <a className="link" href={enrolment.otpauth}>{t('security.enrol.open')}</a>
                </div>
              </div>
              <Input label={t('security.enrol.codeLabel')} value={code} onChange={setCode}
                placeholder="123456" />
              <div className="row">
                <button className="primary-action" disabled={busy || code.trim().length < 6}
                  onClick={confirmEnrol}>{t('security.enrol.confirm')}</button>
                <button onClick={() => { setEnrolment(null); setCode('') }}>{t('security.enrol.cancel')}</button>
              </div>
            </div>
          )}

          {recovery && (
            <div className="stack">
              <p className="muted" style={{ marginTop: 0 }}>
                {t('security.recovery.intro')}
              </p>
              <div className="mfa-codes">
                {recovery.map((item) => <code key={item}>{item}</code>)}
              </div>
              <button onClick={() => setRecovery(null)}>{t('security.recovery.saved')}</button>
            </div>
          )}

          {status.enabled && (
            <div className="stack">
              <p className="muted" style={{ marginTop: 0 }}>
                {t('security.recovery.left', { n: status.recovery_codes_left })}
                {status.enrolled_at
                  ? t('security.recovery.enabledAt', { date: new Date(status.enrolled_at).toLocaleDateString() }) : ''}.
              </p>
              <div className="row">
                <Input label={t('security.recovery.rotateLabel')} type="password" value={password}
                  onChange={setPassword} placeholder={t('security.mfa.passwordPlaceholder')} />
                <button disabled={busy || !password} onClick={rotateCodes}>
                  {t('security.recovery.rotate')}
                </button>
              </div>
              <div className="row">
                <Input label={t('security.disable.codeLabel')} value={disableCode}
                  onChange={setDisableCode} placeholder="123456 or XXXXX-XXXXX" />
                <button className="btn-danger" disabled={busy || !disableCode.trim()}
                  onClick={disable}>{t('security.disable.button')}</button>
              </div>
            </div>
          )}
        </Card>
      )}

      {loading && !status && <Card><span className="muted">{t('security.loading')}</span></Card>}
    </div>
  )
}
