import React, { useEffect, useState } from 'react'
import { api } from './api'

const ROLES = ['owner', 'admin', 'analyst', 'viewer']
const CREATABLE = ['admin', 'analyst', 'viewer']

export default function Members() {
  const [members, setMembers] = useState([])
  const [users, setUsers] = useState([])
  const [userError, setUserError] = useState('')
  const [audit, setAudit] = useState({ data: [], chain_ok: null })
  const [form, setForm] = useState({ identity: '', role: 'viewer', added_by: 'console' })
  const [user, setUser] = useState({ email: '', password: '', role: 'analyst' })
  const [error, setError] = useState('')

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/members').then((r) => setMembers(r.data)).catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/audit').then(setAudit).catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/auth/users')
      .then((r) => { setUsers(r.data); setUserError('') })
      .catch((e) => setUserError(String(e.message || e)))
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

  async function createUser() {
    setUserError('')
    try {
      await api.post('/api/v1/auth/users', { ...user, actor: 'console' })
      setUser({ email: '', password: '', role: 'analyst' })
      load()
    } catch (e) { setUserError(String(e.message || e)) }
  }

  async function patchUser(row, patch) {
    setUserError('')
    try {
      await api.patch(`/api/v1/auth/users/${row.id}`, { ...patch, actor: 'console' })
      load()
    } catch (e) { setUserError(String(e.message || e)) }
  }

  return (
    <div>
      <h2 className="section">accounts (login users)</h2>
      {userError && <p className="error">{userError}</p>}
      <table>
        <thead><tr><th>email</th><th>role</th><th>status</th><th>last login</th><th></th></tr></thead>
        <tbody>
          {users.map((row) => (
            <tr key={row.id}>
              <td className="title">{row.email}</td>
              <td>
                <select value={row.role} disabled={row.role === 'owner'}
                  onChange={(e) => patchUser(row, { role: e.target.value })}>
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </td>
              <td><span className={`status st-${row.status}`}>{row.status}</span></td>
              <td>{row.last_login_at ? new Date(row.last_login_at).toLocaleString() : 'never'}</td>
              <td>
                {row.role !== 'owner' && (
                  <button className="mini"
                    onClick={() => patchUser(row, { status: row.status === 'active' ? 'disabled' : 'active' })}>
                    {row.status === 'active' ? 'disable' : 'enable'}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!users.length && !userError && <p className="empty">No accounts yet — bootstrap the first owner from Settings.</p>}
      <div className="card">
        <input placeholder="email" value={user.email}
          onChange={(e) => setUser((u) => ({ ...u, email: e.target.value }))} />
        <input type="password" placeholder="password (8+ chars)" value={user.password}
          onChange={(e) => setUser((u) => ({ ...u, password: e.target.value }))} />
        <select value={user.role} onChange={(e) => setUser((u) => ({ ...u, role: e.target.value }))}>
          {CREATABLE.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <button onClick={createUser}>create account</button>
      </div>

      <h2 className="section">named members (audit attribution)</h2>
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
