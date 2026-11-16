import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Card, EmptyState, ErrorBanner, Loading, Pill, Table } from './ui'
import { useI18n } from './i18n'

/* What the platform is wired to, and where each answer comes from.

   Every block names its source — `saved` (the console) or `environment` (this
   install) — because "configured" without that is a fact the operator cannot act
   on. Nothing here is editable: the connection form lives in Connections
   (onboarding) and the mail form in Delivery, and a second editor for the same
   row is how two screens start disagreeing. */

const STATE_TONE = { verified: 'ok', error: 'warn', unverified: 'default' }

function Row({ label, children }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  )
}

function Source({ source, t }) {
  const label = source === 'saved' ? t('integrations.source.saved')
    : source === 'environment' ? t('integrations.source.environment')
      : t('integrations.source.none')
  return <Pill tone={source === 'none' ? 'default' : 'ok'}>{label}</Pill>
}

export default function IntegrationsSettings({ onOpenSection, onNavigate }) {
  const { t } = useI18n()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/api/v1/integrations')
      .then((body) => setData(body.data))
      .catch((caught) => setError(String(caught.message || caught)))
  }, [])

  if (error) return <ErrorBanner error={error} />
  if (!data) return <Loading label={t('integrations.loading')} />

  const connections = data.connections || []
  const scm = data.scm || {}
  const jira = data.jira || {}
  const mail = data.mail || {}

  return (
    <div className="settings-body stack">
      <Card title={t('integrations.title')}>
        <p className="settings-intro">{t('integrations.intro')}</p>
      </Card>

      <Card title={t('integrations.connections.title')}
            actions={onOpenSection && (
              <button className="btn-ghost" onClick={() => onOpenSection('setup')}>
                {t('integrations.connections.manage')} →
              </button>
            )}>
        {connections.length === 0 ? (
          <EmptyState title={t('integrations.connections.empty')}
                      hint={t('integrations.connections.empty.hint')} />
        ) : (
          <Table head={[t('integrations.col.provider'), t('integrations.col.url'),
                        t('integrations.col.account'), t('integrations.col.access'),
                        t('integrations.col.state'), t('integrations.col.verified')]}>
            {connections.map((row) => (
              <tr key={row.id}>
                <td>
                  <strong>{row.provider_label || row.provider}</strong>
                  <span className="muted"> · {row.kind}</span>
                </td>
                <td className="mono">{row.base_url || '—'}</td>
                <td className="muted">{row.account || '—'}</td>
                <td><Pill>{row.access || 'read'}</Pill></td>
                <td>
                  <Pill tone={STATE_TONE[row.state] || 'default'}>{row.state}</Pill>
                  {row.last_error && <div className="muted">{row.last_error}</div>}
                </td>
                <td className="muted">{row.verified_at ? row.verified_at.slice(0, 10) : '—'}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title={t('integrations.scm.title')}
            actions={onOpenSection && (
              <button className="btn-ghost" onClick={() => onOpenSection('setup')}>
                {t('integrations.configure')} →
              </button>
            )}>
        <dl>
          <Row label={t('integrations.field.state')}>
            <Source source={scm.configured ? (scm.connections ? 'saved' : 'environment') : 'none'} t={t} />
          </Row>
          <Row label={t('integrations.field.providers')}>
            {(scm.providers || []).join(', ') || '—'}
          </Row>
          <Row label={t('integrations.field.repositories')}>
            {scm.repositories ?? 0}
            {scm.by_provider && Object.keys(scm.by_provider).length > 0 && (
              <span className="muted">
                {' · '}
                {Object.entries(scm.by_provider).map(([name, total]) => `${name}: ${total}`).join(' · ')}
              </span>
            )}
          </Row>
          <Row label={t('integrations.field.environment')}>
            <span className="muted">
              {Object.entries(scm.environment || {}).map(([name, state]) => (
                <span key={name} style={{ marginRight: 10 }}>
                  <span className="mono">{name}</span>{' '}
                  {state.token_present ? t('integrations.env.present') : t('integrations.env.absent')}
                </span>
              ))}
            </span>
          </Row>
        </dl>
        {(data.repositories || []).length > 0 && (
          <details style={{ marginTop: 10 }}>
            <summary>{t('integrations.repositories.all', { n: data.repositories.length })}</summary>
            <ul className="repo-cards">
              {data.repositories.map((row) => (
                <li key={`${row.provider}:${row.remote_url}`}>
                  <span className="repo-head">
                    <span className="repo-name">{row.name}</span>
                    <Pill>{row.provider}</Pill>
                    {row.last_commit_sha && (
                      <span className="mono muted">{row.last_commit_sha.slice(0, 8)}</span>
                    )}
                  </span>
                  <span className="repo-remote">{row.remote_url}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
      </Card>

      <Card title={t('integrations.jira.title')}
            actions={onNavigate && (
              <button className="btn-ghost" onClick={() => onNavigate('jira')}>
                {t('integrations.jira.open')} →
              </button>
            )}>
        <dl>
          <Row label={t('integrations.field.state')}><Source source={jira.source} t={t} /></Row>
          <Row label={t('integrations.field.base_url')}>{jira.base_url || '—'}</Row>
          <Row label={t('integrations.field.account')}>{jira.account || '—'}</Row>
          <Row label={t('integrations.field.projects')}>
            {(jira.project_keys || []).join(', ') || '—'}
          </Row>
          <Row label={t('integrations.field.links')}>
            {t('integrations.jira.links', { linked: jira.linked ?? 0, total: jira.links ?? 0 })}
            {(jira.failed_links || 0) > 0 && (
              <span className="muted"> · {t('integrations.jira.failed', { n: jira.failed_links })}</span>
            )}
          </Row>
          <Row label={t('integrations.field.outbox')}>
            {t('integrations.jira.outbox', { pending: jira.outbox_pending ?? 0, failed: jira.outbox_failed ?? 0 })}
          </Row>
          <Row label={t('integrations.field.webhook')}>
            {jira.webhook_secret ? t('integrations.env.present') : t('integrations.env.absent')}
          </Row>
        </dl>
      </Card>

      <Card title={t('integrations.mail.title')}
            actions={onOpenSection && (
              <button className="btn-ghost" onClick={() => onOpenSection('delivery')}>
                {t('integrations.configure')} →
              </button>
            )}>
        <dl>
          <Row label={t('integrations.field.state')}><Source source={mail.source} t={t} /></Row>
          <Row label={t('integrations.field.host')}>
            {mail.host ? `${mail.host}:${mail.port}` : '—'}
          </Row>
          <Row label={t('integrations.field.sender')}>{mail.sender || '—'}</Row>
          <Row label={t('integrations.field.user')}>{mail.user || '—'}</Row>
          <Row label={t('integrations.field.password')}>
            {mail.has_password ? t('integrations.env.present') : t('integrations.env.absent')}
          </Row>
          <Row label={t('integrations.field.starttls')}>
            {mail.starttls ? t('integrations.env.present') : t('integrations.env.absent')}
          </Row>
        </dl>
        {mail.configured && !mail.has_password && (
          <Banner kind="warn">{t('integrations.mail.nopassword')}</Banner>
        )}
      </Card>
    </div>
  )
}
