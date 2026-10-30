import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function Assets() {
  const [assets, setAssets] = useState([])
  const [domain, setDomain] = useState('')
  const [manual, setManual] = useState({ type: 'domain', value: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/assets').then((r) => setAssets(r.data)).catch((e) => setError(String(e.message || e)))
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
        <thead><tr><th>type</th><th>value</th><th>source</th><th>first seen</th><th>last seen</th></tr></thead>
        <tbody>
          {assets.map((a) => (
            <tr key={a.id}>
              <td><span className="pill">{a.type}</span></td>
              <td className="title">{a.value}</td>
              <td>{a.source}</td>
              <td>{new Date(a.discovered_at).toLocaleDateString()}</td>
              <td>{new Date(a.last_seen_at).toLocaleDateString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!assets.length && !error && <p className="empty">No assets yet — sweep a seed domain.</p>}
    </div>
  )
}
