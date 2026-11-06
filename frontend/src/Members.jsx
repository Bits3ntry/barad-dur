import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Pager, PageHeader, usePage } from './ui'
import { ROLE_ORDER, roleLabel } from './roles'

const ROLES = ROLE_ORDER
const CREATABLE = ['admin', 'analyst', 'viewer']
const PER_PAGE = 25

export default function Members() {
  const [members, setMembers] = useState([])
  const [users, setUsers] = useState([])
  const [userError, setUserError] = useState('')
  const [audit, setAudit] = useState({ data: [], chain_ok: null })
  const [form, setForm] = useState({ identity: '', role: 'viewer', added_by: 'console' })
  const [user, setUser] = useState({ email: '', password: '', role: 'analyst' })
  const [invites, setInvites] = useState([])
  const [inviteForm, setInviteForm] = useState({ email: '', role: 'viewer' })
  const [inviteLink, setInviteLink] = useState('')
  const [error, setError] = useState('')

  // Four lists live on this screen and each is bounded by its own endpoint, so
  // each gets its own page: a long ledger must not bury the invitation form.
  const accounts = usePage(users, PER_PAGE)
  const invitations = usePage(invites, PER_PAGE)
  const named = usePage(members, PER_PAGE)
  const ledger = usePage(audit.data, PER_PAGE)

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/members').then((r) => setMembers(r.data)).catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/audit').then(setAudit).catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/auth/users')
      .then((r) => { setUsers(r.data); setUserError('') })
      .catch((e) => setUserError(String(e.message || e)))
    api.get('/api/v1/onboarding/invitations')
      .then((r) => setInvites(r.data || []))
      .catch(() => setInvites([]))
  }

  async function invite(event) {
    event?.preventDefault()
    setUserError('')
    if (!inviteForm.email.trim()) return
    try {
      const result = await api.post('/api/v1/onboarding/invitations', {
        email: inviteForm.email.trim(), role: inviteForm.role, actor: 'console',
      })
      setInviteForm({ email: '', role: inviteForm.role })
      setInviteLink(result.delivery?.sent ? '' : (result.data.invite_url || ''))
      load()
    } catch (e) { setUserError(String(e.message || e)) }
  }

  async function reissue(row) {
    setUserError('')
    try {
      const result = await api.post(`/api/v1/onboarding/invitations/${row.id}/resend`,
        { actor: 'console' })
      setInviteLink(result.delivery?.sent ? '' : (result.data.invite_url || ''))
      load()
    } catch (e) { setUserError(String(e.message || e)) }
  }

  async function revokeInvite(row) {
    setUserError('')
    try {
      await api.post(`/api/v1/onboarding/invitations/${row.id}/revoke`, { actor: 'console' })
      setInviteLink('')
      load()
    } catch (e) { setUserError(String(e.message || e)) }
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
    <div className="stack">
      <PageHeader title="Members and access" />
      <h2 className="section">accounts (login users)</h2>
      {userError && <div className="banner banner-error">{userError}</div>}
      <Pager page={accounts.page} pages={accounts.pages} onChange={accounts.setPage}
        total={accounts.total} perPage={accounts.perPage} unit="accounts" className="row-end" />
      <table>
        <thead><tr><th>email</th><th>role</th><th>status</th><th>last login</th><th></th></tr></thead>
        <tbody>
          {accounts.rows.map((row) => (
            <tr key={row.id}>
              <td className="title">{row.email}</td>
              <td>
                <select value={row.role} disabled={row.role === 'owner'}
                  onChange={(e) => patchUser(row, { role: e.target.value })}>
                  {ROLES.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}
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
      <Pager page={accounts.page} pages={accounts.pages} onChange={accounts.setPage}
        total={accounts.total} perPage={accounts.perPage} unit="accounts" className="row-end" />
      {!users.length && !userError && <p className="empty">No accounts yet — bootstrap the first owner from Settings.</p>}
      <div className="card">
        <input placeholder="email" value={user.email}
          onChange={(e) => setUser((u) => ({ ...u, email: e.target.value }))} />
        <input type="password" placeholder="password (8+ chars)" value={user.password}
          onChange={(e) => setUser((u) => ({ ...u, password: e.target.value }))} />
        <select value={user.role} onChange={(e) => setUser((u) => ({ ...u, role: e.target.value }))}>
          {CREATABLE.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}
        </select>
        <button onClick={createUser}>create account</button>
      </div>

      {/* An invitation is a seat that exists before the person does. It stays
          here until accepted or revoked, and the single-use link is the only
          way to hand it over when the deployment has no SMTP. */}
      <h2 className="section">invitations</h2>
      <Pager page={invitations.page} pages={invitations.pages} onChange={invitations.setPage}
        total={invitations.total} perPage={invitations.perPage} unit="invitations" className="row-end" />
      {invites.length === 0
        ? <p className="empty">No invitations. Create one to add a teammate without setting a password for them.</p>
        : (
          <table>
            <thead><tr><th>email</th><th>role</th><th>team</th><th>status</th><th>sent</th><th></th></tr></thead>
            <tbody>
              {invitations.rows.map((row) => (
                <tr key={row.id}>
                  <td className="title">{row.email}</td>
                  <td>{row.role_label || roleLabel(row.role)}</td>
                  <td>{row.team || '—'}</td>
                  <td><span className={`status st-${row.status}`}>{row.status}</span></td>
                  <td className="muted">
                    {row.last_sent_at
                      ? `${row.last_delivery === 'email' ? 'email' : 'manual link'} · `
                        + new Date(row.last_sent_at).toLocaleDateString()
                      : 'not sent'}
                  </td>
                  <td>
                    {row.status !== 'accepted' && (
                      <>
                        <button className="mini" onClick={() => reissue(row)}>new link</button>
                        {row.status === 'pending' && (
                          <button className="mini" onClick={() => revokeInvite(row)}>revoke</button>
                        )}
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      <Pager page={invitations.page} pages={invitations.pages} onChange={invitations.setPage}
        total={invitations.total} perPage={invitations.perPage} unit="invitations" className="row-end" />
      <form className="card" onSubmit={invite}>
        <input type="email" placeholder="teammate@example.com" value={inviteForm.email}
          onChange={(e) => setInviteForm((f) => ({ ...f, email: e.target.value }))} />
        <select value={inviteForm.role}
          onChange={(e) => setInviteForm((f) => ({ ...f, role: e.target.value }))}>
          {CREATABLE.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}
        </select>
        <button type="submit">create invitation</button>
      </form>
      {inviteLink && (
        <div className="onb-link">
          <span className="onb-help">Single-use link — the previous one stops working.</span>
          <div className="onb-link-row">
            <input readOnly value={inviteLink} onFocus={(e) => e.target.select()} />
            <button type="button" className="mini"
              onClick={() => navigator.clipboard?.writeText(inviteLink)}>copy</button>
          </div>
        </div>
      )}

      <h2 className="section">named members (audit attribution)</h2>
      <div className="toolbar">
        <input placeholder="identity (email)" value={form.identity}
          onChange={(e) => setForm((f) => ({ ...f, identity: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && add()} />
        <select value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}>
          {ROLES.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}
        </select>
        <button onClick={add}>add member</button>
        <span className="count">{members.length} members</span>
        <Pager page={named.page} pages={named.pages} onChange={named.setPage}
          total={named.total} perPage={named.perPage} unit="members" className="row-end" />
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      <table>
        <thead><tr><th>identity</th><th>role</th><th>added by</th><th>status</th><th></th></tr></thead>
        <tbody>
          {named.rows.map((m) => (
            <tr key={m.id} className={m.role === 'viewer' ? 'muted-row' : ''}>
              <td>{m.identity}</td>
              <td>
                <select value={m.role} onChange={(e) => setRole(m, e.target.value)}>
                  {ROLES.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}
                </select>
              </td>
              <td>{m.added_by || '—'}</td>
              <td><span className={`status st-${m.status}`}>{m.status}</span></td>
              <td>{m.status === 'active' && <button onClick={() => remove(m)}>remove</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager page={named.page} pages={named.pages} onChange={named.setPage}
        total={named.total} perPage={named.perPage} unit="members" className="row-end" />
      <h2 className="section">audit ledger {audit.chain_ok === false ? <span className="sev sev-critical">chain broken</span> : <span className="ok">verified</span>}</h2>
      <Pager page={ledger.page} pages={ledger.pages} onChange={ledger.setPage}
        total={ledger.total} perPage={ledger.perPage} unit="entries" className="row-end" />
      <table>
        <thead><tr><th>#</th><th>at</th><th>actor</th><th>action</th><th>detail</th><th>hash</th></tr></thead>
        <tbody>
          {ledger.rows.map((row) => (
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
      <Pager page={ledger.page} pages={ledger.pages} onChange={ledger.setPage}
        total={ledger.total} perPage={ledger.perPage} unit="entries" className="row-end" />
    </div>
  )
}
