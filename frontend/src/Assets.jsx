import React, { useEffect, useState } from 'react'
import { api } from './api'
import { EmptyState, ErrorBanner, PageHeader, Table } from './ui'

/* Assets answers "what is exposed, where does it live, and when does its
   certificate expire" — addresses and certificate come from the latest
   observation, not from a JSON blob the reader has to parse. */

function certificateTone(days) {
  if (days === null || days === undefined) return ''
  if (days < 0) return 'sev sev-critical'
  if (days <= 14) return 'sev sev-high'
  if (days <= 30) return 'sev sev-medium'
  return 'pill'
}

function CertCell({ latest }) {
  const cert = latest?.certificate
  if (!cert) return <span className="muted">not probed</span>
  return (
    <div className="stack" style={{ gap: 2 }}>
      <span className="muted">{cert.issuer || 'unknown issuer'}</span>
      <span className={certificateTone(cert.days_left)}>
        {cert.days_left === null || cert.days_left === undefined
          ? 'no expiry'
          : `${cert.days_left}d left`}
      </span>
      {cert.not_after && (
        <span className="muted" style={{ fontSize: 11.5 }}>
          {new Date(cert.not_after).toLocaleDateString()} · {cert.tls_version || '—'}
        </span>
      )}
    </div>
  )
}

function AddressCell({ latest }) {
  if (!latest) return <span className="muted">never observed</span>
  const v4 = latest.ipv4 || []
  const v6 = latest.ipv6 || []
  if (!v4.length && !v6.length) return <span className="muted">no addresses</span>
  return (
    <div className="stack" style={{ gap: 2 }}>
      {v4.map((ip) => <span key={ip} className="mono">{ip}</span>)}
      {v6.slice(0, 2).map((ip) => <span key={ip} className="mono muted">{ip}</span>)}
      {v6.length > 2 && <span className="muted">+{v6.length - 2} ipv6</span>}
    </div>
  )
}

export default function Assets() {
  const [assets, setAssets] = useState([])
  const [domain, setDomain] = useState('')
  const [manual, setManual] = useState({ type: 'domain', value: '' })
  const [principal, setPrincipal] = useState(
    () => localStorage.getItem('barad.principal') || 'console')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [history, setHistory] = useState(null)

  useEffect(() => { load() }, [])

  function rememberPrincipal(value) {
    setPrincipal(value)
    localStorage.setItem('barad.principal', value)
  }

  function load() {
    api.get('/api/v1/assets')
      .then((r) => setAssets(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  async function openHistory(asset) {
    if (history?.assetId === asset.id) { setHistory(null); return }
    try {
      const { data } = await api.get(`/api/v1/assets/${asset.id}/changes`)
      setHistory({ assetId: asset.id, asset: asset.value, ...data })
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function collect(asset, withTls = true) {
    setBusy(asset.id)
    setError('')
    setNotice('')
    try {
      const result = await api.post(`/api/v1/assets/${asset.id}/collect`,
        { actor: principal, tls: withTls })
      const dns = result.data.observation.dns || {}
      const tls = result.data.observation.tls
      setNotice(`collected ${asset.value}: ${(dns.ipv4 || []).length} ipv4, `
        + `${(dns.ipv6 || []).length} ipv6${tls ? ', certificate read' : ', DNS only'}`)
      load()
    } catch (e) {
      const message = String(e.message || e)
      setError(message.includes('403')
        ? `Not authorized for ${principal}: issue a grant for that principal `
          + `(passive_discovery, and active_verification for the TLS probe). ${message}`
        : message)
    }
    setBusy('')
  }

  async function sweep() {
    if (!domain.trim()) return
    setBusy('sweep')
    try {
      const result = await api.post('/api/v1/assets/discover',
        { domain: domain.trim(), actor: principal })
      setNotice(`crt.sh sweep: ${result.data.created} new / ${result.data.refreshed} refreshed`)
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
    setBusy('')
  }

  async function addManual() {
    if (!manual.value.trim()) return
    await api.post('/api/v1/assets',
      { ...manual, value: manual.value.trim(), actor: principal })
    setManual((m) => ({ ...m, value: '' }))
    load()
  }

  return (
    <div className="stack">
      <PageHeader
        title="Attack surface"
        subtitle={`${assets.length} assets · addresses and certificate come from the latest observation`}
      />

      <div className="toolbar">
        <input placeholder="seed domain, e.g. bitsentry.xyz" value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && sweep()} />
        <button onClick={sweep} disabled={busy === 'sweep'}>
          {busy === 'sweep' ? 'sweeping…' : 'sweep crt.sh'}
        </button>
        <span className="spacer" />
        <label className="field-label" htmlFor="principal">principal</label>
        <input id="principal" value={principal} style={{ minWidth: 150 }}
          onChange={(e) => rememberPrincipal(e.target.value)}
          title="The identity grants are issued to; collection is authorized per principal" />
      </div>

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {assets.length ? (
        <Table head={['type', 'value', 'addresses', 'certificate', 'last observed', '']}>
          {assets.map((asset) => (
            <React.Fragment key={asset.id}>
              <tr className={history?.assetId === asset.id ? 'selected' : ''}>
                <td><span className="pill">{asset.type}</span></td>
                <td className="title">{asset.value}</td>
                <td><AddressCell latest={asset.latest} /></td>
                <td><CertCell latest={asset.latest} /></td>
                <td className="muted">
                  {asset.latest
                    ? new Date(asset.latest.observed_at).toLocaleString()
                    : new Date(asset.last_seen_at).toLocaleDateString()}
                </td>
                <td>
                  <div className="row">
                    <button className="mini" disabled={busy === asset.id}
                      onClick={() => collect(asset, true)}>
                      {busy === asset.id ? 'collecting…' : 'collect'}
                    </button>
                    <button className="mini" onClick={() => openHistory(asset)}>
                      {history?.assetId === asset.id ? 'hide' : 'history'}
                    </button>
                  </div>
                </td>
              </tr>
              {history?.assetId === asset.id && (
                <tr className="detail-row"><td colSpan={6}>
                  <div className="detail">
                    <dl>
                      <dt>observations</dt><dd>{history.snapshots}</dd>
                      <dt>changes</dt>
                      <dd>
                        {(!history.latest_changes || !history.latest_changes.length)
                          && <span className="muted">none between the last two observations</span>}
                        {(history.latest_changes || []).map((change, index) => (
                          <div key={index} className="occ-row">
                            <strong>{change.field}</strong>: {String(change.before ?? '—')}
                            {' → '}{String(change.after ?? '—')}
                          </div>
                        ))}
                      </dd>
                    </dl>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </Table>
      ) : (
        !error && <EmptyState title="No assets yet"
          hint="Sweep a seed domain to discover hosts, then collect addresses and certificates." />
      )}

      <div className="toolbar">
        <select value={manual.type}
          onChange={(e) => setManual((m) => ({ ...m, type: e.target.value }))}>
          <option value="domain">domain</option>
          <option value="ip">ip</option>
          <option value="url">url</option>
          <option value="cidr">cidr</option>
        </select>
        <input placeholder="add an asset manually" value={manual.value}
          onChange={(e) => setManual((m) => ({ ...m, value: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && addManual()} />
        <button onClick={addManual}>add asset</button>
      </div>
    </div>
  )
}
