import React, { useEffect, useState } from 'react'
import { api } from './api'

const ROLES = ['owner', 'admin', 'analyst', 'viewer']

export default function Members() {
  const [members, setMembers] = useState([])
  const [audit, setAudit] = useState({ data: [], chain_ok: null })
  const [form, setForm] = useState({ identity: '', role: 'viewer', added_by: 'console' })
  const [error, setError] = useState('')

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/members').then((r) => setMembers(r.data)).catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/audit').then(setAudit).catch((e) => setError(String(e.message || e)))
  }

  async function add() {
    if (!form.identity.trim()) return
    await api.post('/api/v1/members', form)
    setForm((f) => ({ ...f, identity: '' }))
    load()
  }

  async function setRole(member, role) {
    await api.patch(`/api/v1/members/${member.id}`, { role, changed_by: 'console' })
    load()
  }

  async function remove(member) {
    await api.del(`/api/v1/members/${member.id}?changed_by=console`)
    load()
  }

  return (
    <div>
      <div className="bar">
        <input placeholder="identity (email)" value={form.identity}
          onChange={(e) => setForm((f) => ({ ...f, identity: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && add()} />
        <select value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}>
          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <button onClick={add}>add member</button>
        <span className="count">{members.length} members</span>
      </div>
      {error && <p className="error">{error}</p>}
      <table>
        <thead><tr><th>identity</th><th>role</th><th>added by</th><th>status</th><th></th></tr></thead>
        <tbody>
          {members.map((m) => (
            <tr key={m.id} className={m.role === 'viewer' ? 'muted-row' : ''}>
              <td>{m.identity}</td>
              <td>
                <select value={m.role} onChange={(e) => setRole(m, e.target.value)}>
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </td>
              <td>{m.added_by || '—'}</td>
              <td><span className={`status st-${m.status}`}>{m.status}</span></td>
              <td>{m.status === 'active' && <button onClick={() => remove(m)}>remove</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2 className="section">audit ledger {audit.chain_ok === false ? <span className="sev sev-critical">chain broken</span> : <span className="ok">verified</span>}</h2>
      <table>
        <thead><tr><th>#</th><th>at</th><th>actor</th><th>action</th><th>detail</th><th>hash</th></tr></thead>
        <tbody>
          {audit.data.map((row) => (
            <tr key={row.position}>
              <td>{row.position}</td>
              <td>{new Date(row.at).toLocaleString()}</td>
              <td>{row.actor}</td>
              <td>{row.action}</td>
              <td>{row.detail || '—'}</td>
              <td className="muted">{row.hash.slice(0, 10)}…</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
