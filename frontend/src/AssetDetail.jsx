import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading } from './ui'
import ScanDialog from './ScanDialog'
import AssetMap from './AssetMap'
import AssetRelations from './AssetRelations'

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
      setNotice('authorization requested — approve it in Settings → Grants')
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
  const web = asset?.web || []
  const openPorts = ports.filter((row) => row.state === 'open').length
  const authorization = asset?.authorization || {}
  const covered = Boolean(authorization.covered)
  const pending = Boolean(authorization.pending_request_id)
  const zoneCover = authorization.zone_cover || null
  const authLabel = covered ? `${authorization.level || 'scan'} authorized`
    : pending ? 'authorization requested' : 'no authorization'
  const authTone = covered ? 'ok' : pending ? 'warn' : 'bad'
  const grants = asset?.grants || []
  const isUrl = asset?.type === 'url' || String(asset?.value || '').startsWith('http')

  if (loading) return <Loading rows={4} label="reading the asset" />
  if (error) return <ErrorBanner error={error} onRetry={load} />
  if (!asset) return <EmptyState title="asset not found" hint="it may belong to another workspace" />

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
              ? `project ${labelOf(asset.project_name) || labelOf(asset.project)}`
              : 'standalone'}</span>
            <span>last observed {when(asset.last_seen_at || latest.observed_at)}</span>
            <span>{asset.observations || 0} observation(s)</span>
          </div>
        </div>
        <div className="run-hero-actions">
          {!covered && !pending && (
            <button className="ghost" disabled={requesting} onClick={requestAuthorization}>
              {requesting ? 'requesting…' : 'request authorization'}
            </button>
          )}
          <button onClick={() => setScanning(true)} disabled={!covered}
                  title={covered ? '' : 'nothing can be scanned without a grant'}>
            run a scan
          </button>
          <button className="ghost" onClick={() => { window.location.hash = 'assets' }}>
            all assets
          </button>
        </div>
      </header>

      <p className={`run-verdict ${authTone}`}>
        {covered
          ? `scans up to ${authorization.level} are authorized on this asset. `
            + 'Launching one from here still goes through the platform, which re-checks the grant.'
          : pending
            ? 'a permission request is waiting in Settings → Grants; nothing can be scanned until it is approved.'
            : zoneCover
              ? `no grant covers this name. ${zoneCover.target} is active and covers its
                 subdomains, but a wildcard never covers the apex — request the apex
                 explicitly if this host should be in scope.`
              : 'no grant covers this asset: declaring it never authorized a scan. '
                + 'Ask for one in Settings → Grants.'}
      </p>

      {notice && <p className="hint asset-notice">{notice}</p>}

      <div className="asset-top">
        <Card title="where it is">
          <AssetMap points={geo?.points || []} reason={geo?.reason || ''}
                    address={asset.value} />
        </Card>

        <Card title="address & certificate">
          <div className="asset-stats">
            <Stat label="state" value={addresses.length ? 'answering' : 'not observed'} />
            <Stat label="addresses" value={addresses.length || '—'} />
            <Stat label="certificate"
                  value={certificate ? (certDays != null ? `${certDays}d left` : 'no expiry')
                    : 'not probed'}
                  tone={certDays != null && certDays < 20 ? 'bad' : undefined} />
            <Stat label="open ports" value={openPorts || '—'} />
            <Stat label="products" value={technologies.length || '—'} />
          </div>
          <dl className="asset-facts">
            <dt>ip</dt>
            <dd className="mono">{addresses.length ? addresses.join(', ') : 'none observed'}</dd>
            <dt>issuer</dt>
            <dd>{typeof certificate?.issuer === 'string'
              ? certificate.issuer
              : certificate?.issuer?.organizationName || certificate?.issuer?.commonName
                || (certificate ? 'unknown issuer' : '—')}</dd>
            <dt>subject</dt>
            <dd className="mono">{certificate?.subject?.commonName || asset.value}</dd>
            <dt>valid to</dt>
            <dd>{when(certificate?.not_after)}
              {certDays != null && <span className="muted"> · {certDays} days</span>}</dd>
            <dt>tls</dt>
            <dd className="mono">{certificate?.tls_version || '—'}</dd>
            {certificate?.error && (
              <>
                <dt>trust</dt>
                <dd className="asset-bad">{certificate.error}</dd>
              </>
            )}
            <dt>owner</dt>
            <dd>{asset.owner || '—'}</dd>
            <dt>groups</dt>
            <dd>{(asset.groups || []).length
              ? asset.groups.map((group) => labelOf(group) || '—').join(', ')
              : '—'}</dd>
          </dl>
        </Card>
      </div>

      <Card title={`open ports${ports.length ? ` · ${ports.length}` : ''}`}>
        {!ports.length ? (
          <p className="hint">
            nothing listening was read — a simple scan resolves the name; the ports
            table needs the advanced one.
          </p>
        ) : (
          <table className="asset-tech">
            <thead>
              <tr><th>port</th><th>service</th><th>what it is for</th><th>product</th>
                <th>version</th><th>answered the banner</th><th>last seen</th></tr>
            </thead>
            <tbody>
              {ports.map((row) => (
                <tr key={`${row.port}/${row.protocol}`}>
                  <td className="mono">
                    {row.port}<span className="muted">/{row.protocol}</span>
                  </td>
                  <td className="mono">{row.service || <span className="muted">—</span>}</td>
                  <td>{row.purpose || <span className="muted">not announced</span>}</td>
                  <td className="mono">{row.product || <span className="muted">—</span>}</td>
                  <td className="mono">
                    {row.version || <span className="muted">—</span>}
                  </td>
                  <td className="muted small">
                    {row.sources.map((name) => name.replace('shauron:', '')).join(', ')}
                  </td>
                  <td className="muted">{when(row.observed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title={`web${web.length ? ` · ${web.length}` : ''}`}>
        {!web.length ? (
          <p className="hint">
            no web answer was read. The stack behind a site (server, language, CMS
            and its version) comes from reading the page, not from the port.
          </p>
        ) : (
          <table className="asset-tech">
            <thead>
              <tr><th>url</th><th>status</th><th>server</th><th>stack</th><th>seen</th></tr>
            </thead>
            <tbody>
              {web.map((row) => (
                <tr key={row.url}>
                  <td className="mono">{row.url}</td>
                  <td className="mono">{row.status ?? <span className="muted">—</span>}</td>
                  <td className="mono">{row.server || <span className="muted">—</span>}</td>
                  <td>
                    <span className="tech-chips">
                      {row.tech.length ? row.tech.map((entry) => (
                        <span key={entry.name} className="pill">
                          {entry.name}
                          {entry.version && <span className="mono"> {entry.version}</span>}
                        </span>
                      )) : <span className="muted">nothing fingerprinted</span>}
                    </span>
                  </td>
                  <td className="muted">{when(row.observed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <details className="card">
        <summary>
          fingerprint evidence
          {technologies.length ? ` · ${technologies.length} product(s)` : ''}
        </summary>
        {!technologies.length ? (
          <p className="hint">nothing fingerprinted yet — run an advanced scan</p>
        ) : (
          <table className="asset-tech">
            <thead>
              <tr><th>product</th><th>version</th><th>read by</th><th>what said it</th>
                <th>confidence</th><th>seen</th></tr>
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

      <Card title="relationships">
        <AssetRelations asset={asset} parent={asset.parent}
                        children={asset.children || []} addresses={addresses}
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
