import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function Assets() {
  const [assets, setAssets] = useState([])
  const [domain, setDomain] = useState('')
  const [manual, setManual] = useState({ type: 'domain', value: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState(null)
  const [snapshotDraft, setSnapshotDraft] = useState('{"ip": "", "tech": []}')

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/assets').then((r) => setAssets(r.data)).catch((e) => setError(String(e.message || e)))
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

  async function collect(asset) {
    try {
      const result = await api.post(`/api/v1/assets/${asset.id}/collect`,
        { actor: 'console', tls: false })
      setError('')
      window.alert(`observed ${result.data.observation.dns.ipv4.length} ipv4 / `
        + `${result.data.observation.dns.ipv6.length} ipv6`)
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function addSnapshot(asset) {
    try {
      const parsed = JSON.parse(snapshotDraft)
      await api.post(`/api/v1/assets/${asset.id}/snapshots`, {
        data: parsed, source: 'console', actor: 'console',
      })
      setHistory(null)
      setTimeout(() => openHistory(asset), 150)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function sweep() {
    if (!domain.trim()) return
    setBusy(true)
    try {
      const result = await api.post('/api/v1/assets/discover', { domain: domain.trim(), actor: 'console' })
      setError(`crt.sh sweep: ${result.data.created} new / ${result.data.refreshed} refreshed`)
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
    setBusy(false)
  }

  async function addManual() {
    if (!manual.value.trim()) return
    await api.post('/api/v1/assets', { ...manual, value: manual.value.trim(), actor: 'console' })
    setManual((m) => ({ ...m, value: '' }))
    load()
  }

  return (
    <div>
      <div className="bar">
        <input placeholder="seed domain, e.g. councilbox.com" value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && sweep()} />
        <button onClick={sweep} disabled={busy}>{busy ? 'sweeping…' : 'sweep crt.sh'}</button>
        <span className="count">{assets.length} assets</span>
      </div>
      <div className="bar">
        <select value={manual.type} onChange={(e) => setManual((m) => ({ ...m, type: e.target.value }))}>
          <option value="domain">domain</option>
          <option value="ip">ip</option>
          <option value="url">url</option>
          <option value="cidr">cidr</option>
        </select>
        <input placeholder="manual asset value" value={manual.value}
          onChange={(e) => setManual((m) => ({ ...m, value: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && addManual()} />
        <button onClick={addManual}>add asset</button>
      </div>
      {error && <p className="error">{error}</p>}
      <table>
        <thead><tr><th>type</th><th>value</th><th>source</th><th>first seen</th><th>last seen</th><th></th></tr></thead>
        <tbody>
          {assets.map((a) => (
            <React.Fragment key={a.id}>
              <tr className={history?.assetId === a.id ? 'selected' : ''}>
                <td><span className="pill">{a.type}</span></td>
                <td className="title">{a.value}</td>
                <td>{a.source}</td>
                <td>{new Date(a.discovered_at).toLocaleDateString()}</td>
                <td>{new Date(a.last_seen_at).toLocaleDateString()}</td>
                <td><button onClick={() => openHistory(a)}>history</button></td>
              </tr>
              {history?.assetId === a.id && (
                <tr className="detail-row"><td colSpan={6}>
                  <div className="detail">
                    <dl>
                      <dt>snapshots</dt><dd>{history.snapshots}</dd>
                      <dt>latest changes</dt>
                      <dd>
                        {(!history.latest_changes || history.latest_changes.length === 0) &&
                          <span className="muted">no changes between observations</span>}
                        {(history.latest_changes || []).map((c, index) => (
                          <div key={index} className="occ-row">
                            <strong>{c.field}</strong>: {String(c.before ?? '—')} → {String(c.after ?? '—')}
                          </div>
                        ))}
                      </dd>
                    </dl>
                    <div className="bar">
                      <input value={snapshotDraft} style={{ minWidth: 380 }}
                        onChange={(e) => setSnapshotDraft(e.target.value)}
                        placeholder='observation JSON, e.g. {"ip": "1.2.3.4"}' />
                      <button onClick={() => addSnapshot(a)}>record snapshot</button>
                    </div>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      {!assets.length && !error && <p className="empty">No assets yet — sweep a seed domain.</p>}
    </div>
  )
}
