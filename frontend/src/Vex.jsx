import React, { useEffect, useState } from 'react'
import { api } from './api'

const VEX_STATUSES = ['not_affected', 'affected', 'fixed', 'under_investigation']

export function VexSection({ findingId, onChange }) {
  const [statements, setStatements] = useState([])
  const [status, setStatus] = useState('not_affected')
  const [statement, setStatement] = useState('')

  useEffect(() => { load() }, [findingId])

  function load() {
    api.get('/api/v1/vex').then((r) =>
      setStatements(r.data.filter((row) => row.finding_id === findingId))).catch(() => {})
  }

  async function add() {
    if (!statement.trim()) return
    await api.post('/api/v1/vex', { finding_id: findingId, status, statement: statement.trim(), author: 'console' })
    setStatement('')
    load()
    onChange?.()
  }

  return (
    <>
      <dl>
        <dt>VEX</dt>
        <dd>
          {statements.map((v) => (
            <div key={v.id} className="vex-row">
              <span className={`vex-${v.status}`}>{v.status}</span> — {v.statement}
              <span className="muted"> ({v.author || 'anonym'})</span>
            </div>
          ))}
          {!statements.length && <span className="muted">—</span>}
        </dd>
      </dl>
      <div className="bar">
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          {VEX_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input placeholder="statement" value={statement}
          onChange={(e) => setStatement(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && add()} />
        <button onClick={add}>add statement</button>
      </div>
    </>
  )
}
