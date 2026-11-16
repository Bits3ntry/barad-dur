import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading } from './ui'
import ScanDialog from './ScanDialog'
import AssetMap from './AssetMap'
import AssetRelations from './AssetRelations'
import SubdomainCard, { SubdomainDrawer } from './AssetSubdomains'
import { useI18n } from './i18n'

/* One asset, one page. The table answers "what do I have"; this answers "what is
   this thing": where it sits, what it points at, what it serves, who owns it,
   what we are allowed to do with it, and how it connects to the rest of the
   estate. Nothing here is invented — a panel without data says so, and the map
   blurs rather than guessing a coordinate. */

function when(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function days(value) {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  return Math.round((date - Date.now()) / 86400000)
}

/* The API answers `parent` as the derived ancestor — `{id, value, depth}` — because
   the list needs the depth to draw the tree. This page wants the name: rendering
   the object itself is React error #31, and the whole asset screen dies with it. */
function labelOf(value) {
  if (value == null) return null
  if (typeof value === 'string' || typeof value === 'number') return String(value)
  return value.value || value.name || value.label || value.slug || null
}

function Stat({ label, value, tone }) {
  return (
    <div className="asset-stat">
      <span className="metric-label">{label}</span>
      <span className={`asset-stat-value${tone ? ` tone-${tone}` : ''}`}>{value}</span>
    </div>
  )
}

export default function AssetDetail({ assetId }) {
  const { t, tCount } = useI18n()
  const [asset, setAsset] = useState(null)
  const [geo, setGeo] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [requesting, setRequesting] = useState(false)
  const [notice, setNotice] = useState('')

  useEffect(() => { load() }, [assetId])

  async function load() {
    setLoading(true)
    setError('')
    try {
      const body = await api.get(`/api/v1/assets/${assetId}`)
      setAsset(body.data || body)
      // The map is a second question with its own failure mode: an asset can be
      // perfectly known and still have no location.
      api.get(`/api/v1/assets/${assetId}/geo`)
        .then(setGeo)
        .catch((err) => setGeo({ available: false, reason: err.message || String(err),
                                 points: [] }))
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setLoading(false)
    }
  }

  // Asking for permission from the page where the absence was noticed: the
  // operator should not have to remember which screen the request lives on.
  async function requestAuthorization() {
    setRequesting(true)
    setNotice('')
    try {
      const zoneCover = asset?.authorization?.zone_cover
      await api.post(`/api/v1/assets/${assetId}/request`,
                     { level: zoneCover ? 'advanced' : 'simple', actor: 'console' })
      setNotice(t('assetDetail.notice.requested'))
      await load()
    } catch (err) {
      setNotice(err.message || String(err))
    } finally {
      setRequesting(false)
    }
  }

  const latest = asset?.latest || {}
  const certificate = latest.certificate || null
  const addresses = useMemo(
    () => [...(latest.ipv4 || []), ...(latest.ipv6 || [])], [latest])
  const technologies = asset?.technologies || []
  const ports = asset?.ports || []
  const services = asset?.services || []
  const subdomains = asset?.subdomains || []
  const subdomainCount = asset?.subdomain_count ?? subdomains.length
  const [subOpen, setSubOpen] = useState(false)
  const web = asset?.web || []
  const openPorts = ports.filter((row) => row.state === 'open').length
  const authorization = asset?.authorization || {}
  const covered = Boolean(authorization.covered)
  const pending = Boolean(authorization.pending_request_id)
  const zoneCover = authorization.zone_cover || null
  const authLabel = covered
    ? t('assetDetail.auth.authorized',
        { level: authorization.level || t('assetDetail.auth.scan') })
    : pending ? t('assetDetail.auth.pending') : t('assetDetail.auth.none')
  const authTone = covered ? 'ok' : pending ? 'warn' : 'bad'
  const grants = asset?.grants || []
  const isUrl = asset?.type === 'url' || String(asset?.value || '').startsWith('http')

  if (loading) return <Loading rows={4} label={t('assetDetail.loading')} />
  if (error) return <ErrorBanner error={error} onRetry={load} />
  if (!asset) return <EmptyState title={t('assetDetail.notFound.title')}
    hint={t('assetDetail.notFound.hint')} />

  const certDays = certificate ? days(certificate.not_after) : null
  const grantLabel = grants.length
    ? `${grants[0].level || 'simple'}${grants[0].status ? ` (${grants[0].status})` : ''}`
    : covered ? `${authorization.level} (active)` : null

  return (
    <>
      <header className="run-hero">
        <div className="run-hero-main">
          <div className="run-eyebrow">
            <span className="run-status">{asset.type}</span>
            <span className="run-dot">·</span>
            <span>{asset.classification_status || 'unclassified'}</span>
            <span className={`run-health ${authTone}`}>{authLabel}</span>
          </div>
          <h1 className="run-title mono asset-value">{asset.value}</h1>
          <div className="run-meta">
            <span>{asset.source || 'manual'}</span>
            <span>{asset.project
              ? t('assetDetail.project', { name: labelOf(asset.project_name) || labelOf(asset.project) })
              : t('assetDetail.standalone')}</span>
            <span>{t('assetDetail.lastObserved', { when: when(asset.last_seen_at || latest.observed_at) })}</span>
            <span>{tCount('assetDetail.observations', asset.observations || 0)}</span>
          </div>
        </div>
        <div className="run-hero-actions">
          {!covered && !pending && (
            <button className="ghost" disabled={requesting} onClick={requestAuthorization}>
              {requesting ? t('assetDetail.requesting') : t('assetDetail.request')}
            </button>
          )}
          <button onClick={() => setScanning(true)} disabled={!covered}
                  title={covered ? '' : t('assetDetail.noGrantTitle')}>
            {t('assetDetail.runScan')}
          </button>
          <button className="ghost" onClick={() => { window.location.hash = 'assets' }}>
            {t('assetDetail.allAssets')}
          </button>
        </div>
      </header>

      <p className={`run-verdict ${authTone}`}>
        {covered
          ? t('assetDetail.verdict.covered', { level: authorization.level })
          : pending
            ? t('assetDetail.verdict.pending')
            : zoneCover
              ? t('assetDetail.verdict.zoneCover', { target: zoneCover.target })
              : t('assetDetail.verdict.none')}
      </p>

      {notice && <p className="hint asset-notice">{notice}</p>}

      <div className="asset-top">
        <Card title={t('assetDetail.card.where')}>
          <AssetMap points={geo?.points || []} reason={geo?.reason || ''}
                    address={asset.value} />
        </Card>

        <Card title={t('assetDetail.card.addressCert')}>
          <div className="asset-stats">
            <Stat label={t('assetDetail.stat.state')}
                  value={addresses.length ? t('assetDetail.value.answering')
                    : t('assetDetail.value.notObserved')} />
            <Stat label={t('assetDetail.stat.addresses')} value={addresses.length || '—'} />
            <Stat label={t('assetDetail.stat.certificate')}
                  value={certificate ? (certDays != null
                    ? t('assetDetail.value.daysLeft', { n: certDays })
                    : t('assetDetail.value.noExpiry'))
                    : t('assetDetail.value.notProbed')}
                  tone={certDays != null && certDays < 20 ? 'bad' : undefined} />
            <Stat label={t('assetDetail.stat.openPorts')} value={openPorts || '—'} />
            <Stat label={t('assetDetail.stat.products')} value={technologies.length || '—'} />
            <Stat label={t('assetDetail.stat.subdomains')} value={subdomainCount || '—'} />
          </div>
          <dl className="asset-facts">
            <dt>{t('assetDetail.fact.ip')}</dt>
            <dd className="mono">{addresses.length ? addresses.join(', ')
              : t('assetDetail.value.noneObserved')}</dd>
            <dt>{t('assetDetail.fact.issuer')}</dt>
            <dd>{typeof certificate?.issuer === 'string'
              ? certificate.issuer
              : certificate?.issuer?.organizationName || certificate?.issuer?.commonName
                || (certificate ? t('assetDetail.value.unknownIssuer') : '—')}</dd>
            <dt>{t('assetDetail.fact.subject')}</dt>
            <dd className="mono">{certificate?.subject?.commonName || asset.value}</dd>
            <dt>{t('assetDetail.fact.validTo')}</dt>
            <dd>{when(certificate?.not_after)}
              {certDays != null && <span className="muted"> {t('assetDetail.value.days', { n: certDays })}</span>}</dd>
            <dt>{t('assetDetail.fact.tls')}</dt>
            <dd className="mono">{certificate?.tls_version || '—'}</dd>
            {certificate?.error && (
              <>
                <dt>{t('assetDetail.fact.trust')}</dt>
                <dd className="asset-bad">{certificate.error}</dd>
              </>
            )}
            <dt>{t('common.owner')}</dt>
            <dd>{asset.owner || '—'}</dd>
            <dt>{t('assetDetail.fact.groups')}</dt>
            <dd>{(asset.groups || []).length
              ? asset.groups.map((group) => labelOf(group) || '—').join(', ')
              : '—'}</dd>
          </dl>
        </Card>
      </div>

      <Card title={t('assetDetail.card.services')
        + (services.length ? ` · ${services.length}` : '')}>
        {!services.length ? (
          <p className="hint">{t('assetDetail.services.empty')}</p>
        ) : (
          <div className="service-list">
            {services.map((row) => (
              <details className="service" key={`${row.port}/${row.protocol}`}
                       open={row.web.length > 0}>
                <summary>
                  <span className="service-port mono">
                    {row.port}<span className="muted">/{row.protocol}</span>
                  </span>
                  <span className="service-what">
                    <span className="service-name">{row.service || t('common.unknown')}</span>
                    <span className="muted small">{row.purpose || t('assetDetail.services.notAnnounced')}</span>
                  </span>
                  <span className="service-product mono">
                    {row.product
                      ? <>{row.product}{row.version && <span className="muted"> {row.version}</span>}</>
                      : <span className="muted">—</span>}
                  </span>
                  <span className="muted small service-sources">
                    {row.sources.map((name) => name.replace('shauron:', '')).join(', ')}
                  </span>
                </summary>
                <div className="service-body">
                  {row.tls && (
                    <p className="service-line muted small">
                      {t('assetDetail.services.certificate',
                        { issuer: row.tls.issuer || t('assetDetail.value.unknownIssuer') })}
                      {row.tls.days_left != null && ` · ${t('assetDetail.value.daysLeft', { n: row.tls.days_left })}`}
                      {row.tls.cipher && ` · ${row.tls.cipher}`}
                      {row.tls.error && <span className="asset-bad"> · {row.tls.error}</span>}
                    </p>
                  )}
                  {row.web.map((page) => (
                    <div className="service-line" key={page.url}>
                      <a className="mono" href={page.url} target="_blank" rel="noreferrer">
                        {page.url}
                      </a>
                      <span className="mono muted">{page.status ?? '—'}</span>
                      <span className="mono">{page.server || '—'}</span>
                      <span className="tech-chips">
                        {page.tech.length ? page.tech.map((entry) => (
                          <span key={entry.name} className="pill">
                            {entry.name}
                            {entry.version && <span className="mono"> {entry.version}</span>}
                          </span>
                        )) : <span className="muted">{t('assetDetail.services.noTech')}</span>}
                      </span>
                    </div>
                  ))}
                  {!row.web.length && !row.tls && (
                    <p className="service-line muted small">
                      {row.product
                        ? t('assetDetail.services.banner',
                          { product: `${row.product}${row.version ? ` ${row.version}` : ''}` })
                        : t('assetDetail.services.unnamed')}
                    </p>
                  )}
                </div>
              </details>
            ))}
          </div>
        )}
      </Card>

      <details className="card">
        <summary>
          {t('assetDetail.tech.summary')}
          {technologies.length ? ` ${tCount('assetDetail.tech.products', technologies.length)}` : ''}
        </summary>
        {!technologies.length ? (
          <p className="hint">{t('assetDetail.tech.empty')}</p>
        ) : (
          <table className="asset-tech">
            <thead>
              <tr><th>{t('assetDetail.tech.col.product')}</th><th>{t('assetDetail.tech.col.version')}</th>
                <th>{t('assetDetail.tech.col.readBy')}</th><th>{t('assetDetail.tech.col.source')}</th>
                <th>{t('assetDetail.tech.col.confidence')}</th><th>{t('assetDetail.tech.col.seen')}</th></tr>
            </thead>
            <tbody>
              {technologies.map((tech) => (
                <tr key={`${tech.name}:${tech.version || ''}`}>
                  <td className="mono">{tech.name}</td>
                  <td className="mono">{tech.version || <span className="muted">—</span>}</td>
                  <td className="muted">{(tech.source || '').replace('shauron:', '') || '—'}</td>
                  <td className="muted">{tech.evidence || '—'}</td>
                  <td>
                    <span className={`asset-conf conf-${tech.confidence || 'range'}`}>
                      {tech.confidence || 'range'}
                    </span>
                  </td>
                  <td className="muted">{when(tech.observed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </details>

      <Card title={t('assetDetail.card.subdomains')
        + (subdomainCount ? ` · ${subdomainCount}` : '')}>
        <SubdomainCard rows={subdomains} total={subdomainCount}
                       onOpenAll={() => setSubOpen(true)}
                       onOpenOne={(id) => { window.location.hash = `asset::${id}` }} />
      </Card>

      <SubdomainDrawer open={subOpen} onClose={() => setSubOpen(false)}
                       rows={subdomains} total={subdomainCount} assetValue={asset.value} />

      <Card title={t('assetDetail.card.relationships')}>
        <AssetRelations asset={asset} parent={asset.parent}
                        children={subdomains} addresses={addresses}
                        onOpenChildren={() => setSubOpen(true)}
                        project={asset.project}
                        projectName={labelOf(asset.project_name) || labelOf(asset.project)}
                        grant={grantLabel} covered={covered} />
      </Card>

      <ScanDialog open={scanning} onClose={() => setScanning(false)}
                  initialTarget={asset.value} targetKind={isUrl ? 'url' : 'domain'}
                  onStarted={(id) => { window.location.hash = `surface::${id}` }} />
    </>
  )
}
