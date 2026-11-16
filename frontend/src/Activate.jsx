import React, { useEffect, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { Banner, Card, EmptyState, ErrorBanner, PageHeader } from './ui'

/* Approving a terminal is a person's decision, so this screen is deliberately
   bare: what is asking, from where, and two buttons. The code arrives in the
   fragment (`#activate::ABCD-EFGH`) so a link from the CLI lands with it filled. */

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

function normalise(raw) {
  const cleaned = (raw || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8)
  return cleaned.length > 4 ? `${cleaned.slice(0, 4)}-${cleaned.slice(4)}` : cleaned
}

export default function Activate({ code: incoming }) {
  const { t } = useI18n()
  const [code, setCode] = useState(normalise(incoming))
  const [pending, setPending] = useState([])
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState('')

  useEffect(() => { load() }, [])

  async function load() {
    setError('')
    try {
      const body = await api.get('/api/v1/auth/device/pending')
      setPending(body.pending || [])
    } catch (err) {
      setError(err.message || String(err))
    }
  }

  const waiting = pending.find(
    (row) => row.user_code.replace('-', '') === code.replace('-', ''))

  async function decide(decision) {
    setBusy(decision)
    setError('')
    try {
      const body = await api.post('/api/v1/auth/device/approve', { user_code: code, decision })
      setResult(body)
      setPending(pending.filter((row) => row.user_code !== body.user_code))
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setBusy('')
    }
  }

  return (
    <>
      <PageHeader
        title={t('activate.title')}
        subtitle={t('activate.subtitle')}
      />
      {error && <ErrorBanner error={error} onRetry={load} />}
      {result ? (
        <Banner kind={result.status === 'approved' ? 'ok' : 'info'}>
          {result.status === 'approved'
            ? (result.hostname
              ? t('activate.result.approvedHost', { host: result.hostname })
              : t('activate.result.approved'))
            : t('activate.result.denied')}
        </Banner>
      ) : (
        <Card title={t('activate.code.title')}>
          <div className="activate">
            <label>
              <span className="activate-label">{t('activate.code.label')}</span>
              <input
                className="activate-input"
                value={code}
                spellCheck={false}
                autoComplete="off"
                placeholder="XXXX-XXXX"
                onChange={(event) => setCode(normalise(event.target.value))}
              />
            </label>
            {code.length === 9 && (
              <div className="activate-target">
                {waiting ? (
                  <>
                    <p>
                      <strong>{waiting.hostname || t('activate.unnamedMachine')}</strong>
                      {waiting.platform ? ` · ${waiting.platform}` : ''}
                      {waiting.agent ? ` · ${t('activate.target.agent', { agent: waiting.agent })}` : ''}
                    </p>
                    <p className="hint">
                      {t('activate.target.requested', {
                        time: waiting.requested_at ? new Date(waiting.requested_at).toLocaleTimeString() : '',
                      })}
                      {' · '}{t('activate.target.expires', {
                        time: waiting.expires_at ? new Date(waiting.expires_at).toLocaleTimeString() : '',
                      })}
                    </p>
                  </>
                ) : (
                  <p className="hint">
                    {t('activate.target.none')}
                  </p>
                )}
                <div className="activate-actions">
                  <button onClick={() => decide('approve')} disabled={!waiting || !!busy}>
                    {busy === 'approve' ? t('activate.busy') : t('activate.action.approve')}
                  </button>
                  <button className="ghost" onClick={() => decide('deny')}
                          disabled={!waiting || !!busy}>
                    {t('activate.action.deny')}
                  </button>
                </div>
              </div>
            )}
          </div>
        </Card>
      )}
      <Card title={t('activate.pending.title')}>
        {!pending.length ? (
          <EmptyState title={t('activate.pending.emptyTitle')}
                      hint={t('activate.pending.emptyHint')} />
        ) : (
          <ul className="activate-list">
            {pending.map((row) => (
              <li key={row.user_code}>
                <button className="ghost" onClick={() => setCode(row.user_code)}>
                  <span className="mono">{row.user_code}</span>
                  <span>{row.hostname || t('activate.unnamed')}</span>
                  <span className="hint">{row.platform || ''}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  )
}
