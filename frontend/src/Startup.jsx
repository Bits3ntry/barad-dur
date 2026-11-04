import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import { BrandMark } from './Login'
import MailSettings from './MailSettings'

/* The first-run walk-through, six ordered steps from an empty workspace to a
   usable one. Everything is saved as it is entered, so the rail is free to move
   in both directions and a reload resumes where the owner left off.

   Two rules shape this screen:
   - the copy states what the platform actually does (roles, read-only code
     access, the fact that an invitation is a seat and email is one channel);
   - an optional step can be skipped without pretending it was configured. */

const STEPS = [
  { key: 'workspace', label: 'Workspace', title: 'Workspace and owner',
    hint: 'The first owner was created with the setup code.' },
  { key: 'organization', label: 'Organization', title: 'Organization details',
    hint: 'Name, logo, a line about what the organization does and its site.' },
  { key: 'team', label: 'Team', title: 'Invite your team',
    hint: 'Add the people who will work in Barad-dûr. Invitations are single-use links.' },
  { key: 'code', label: 'Code', title: 'Connect code',
    hint: 'GitHub, GitLab or Gitea — read-only access to list and clone repositories.' },
  { key: 'tickets', label: 'Tickets', title: 'Connect tickets',
    hint: 'Link Jira so findings can be imported and exported as tickets.' },
  { key: 'enter', label: 'Enter', title: 'Enter Barad-dûr',
    hint: 'Scope comes first, then applications and authorization.' },
]

function initialStep() {
  const value = Number(new URLSearchParams(window.location.hash.slice(1)).get('step'))
  return Number.isInteger(value) && value >= 2 && value <= STEPS.length ? value : 2
}

function downsample(file, size = 128) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('The file could not be read.'))
    reader.onload = () => {
      const image = new Image()
      image.onerror = () => reject(new Error('That file is not an image.'))
      image.onload = () => {
        const scale = Math.min(1, size / Math.max(image.width, image.height))
        const canvas = document.createElement('canvas')
        canvas.width = Math.round(image.width * scale)
        canvas.height = Math.round(image.height * scale)
        canvas.getContext('2d').drawImage(image, 0, 0, canvas.width, canvas.height)
        resolve(canvas.toDataURL('image/png'))
      }
      image.src = String(reader.result)
    }
    reader.readAsDataURL(file)
  })
}

function StatusPill({ status }) {
  return <span className={`onb-pill ${status}`}>{status}</span>
}

function RoleTable({ roles, value, onChange }) {
  return (
    <div className="onb-role-table" role="radiogroup" aria-label="Role">
      {roles.map((role) => (
        <button type="button" key={role.value} role="radio"
          aria-checked={value === role.value}
          className={`onb-role${value === role.value ? ' selected' : ''}`}
          onClick={() => onChange(role.value)}>
          <span className="onb-role-head">
            <span className="onb-radio" aria-hidden="true" />
            <span className="onb-role-name">{role.label}</span>
            <span className={`onb-risk ${role.value}`}>{role.risk}</span>
          </span>
          <span className="onb-role-summary">{role.summary}</span>
          <span className="onb-role-access">{role.access}</span>
        </button>
      ))}
    </div>
  )
}

export default function Startup({ onFinish }) {
  const [step, setStep] = useState(initialStep)
  const [state, setState] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [inviteLink, setInviteLink] = useState('')
  const [logoBusy, setLogoBusy] = useState(false)
  const [mailOpen, setMailOpen] = useState(false)

  const [org, setOrg] = useState({ name: '', description: '', website: '', logo: '' })
  const [invite, setInvite] = useState({ email: '', role: 'viewer', team_id: '' })
  const [team, setTeam] = useState({ name: '', description: '' })
  const [scm, setScm] = useState({ provider: 'github', base_url: '', token: '', label: '' })
  const [tickets, setTickets] = useState({ base_url: '', account: '', token: '', project_key: '' })
  const logoInput = useRef(null)
  const linkRef = useRef(null)

  function showLink(url) {
    setInviteLink(url)
    // The link is the only way to hand a seat over when SMTP is absent, so it
    // must not land below the fold unnoticed.
    window.requestAnimationFrame(() => linkRef.current?.scrollIntoView({ block: 'nearest' }))
  }

  const owner = useMemo(() => (state?.members || []).find((row) => row.role === 'owner'), [state])
  const actor = owner?.email || 'onboarding'

  function applyState(next) {
    setState(next)
    setOrg({
      name: next.org.name || '',
      description: next.org.description || '',
      website: next.org.website || '',
      logo: next.org.logo || '',
    })
  }

  function load() {
    return api.get('/api/v1/onboarding')
      .then((r) => { applyState(r.data); return r.data })
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(() => { load() }, [])

  function go(next) {
    setStep(next)
    setError('')
    setNotice('')
    setInviteLink('')
    window.history.replaceState({}, '', `/startup#step=${next}`)
  }

  async function run(key, work, success) {
    setBusy(key)
    setError('')
    setNotice('')
    try {
      const result = await work()
      if (success) setNotice(success(result))
      await load()
      return result
    } catch (e) {
      setError(String(e.message || e))
      return null
    } finally {
      setBusy('')
    }
  }

  async function saveOrganization(event) {
    event?.preventDefault()
    if (!org.name.trim() || org.name.trim().length < 2) {
      setError('The organization needs a name of at least 2 characters.')
      return
    }
    const result = await run('org', () => api.patch('/api/v1/org', {
      name: org.name.trim(),
      description: org.description,
      website: org.website.trim(),
      logo: org.logo,
      actor,
    }), () => 'Organization details saved.')
    if (result) go(3)
  }

  async function handleLogo(file) {
    if (!file) return
    if (file.size > 2 * 1024 * 1024) {
      setError('Choose an image under 2 MB.')
      return
    }
    setLogoBusy(true)
    setError('')
    try {
      const dataUrl = await downsample(file)
      setOrg((current) => ({ ...current, logo: dataUrl }))
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLogoBusy(false)
    }
  }

  async function sendInvite(event) {
    event?.preventDefault()
    if (!invite.email.trim()) {
      setError('Enter the email address of the person you want to invite.')
      return
    }
    const result = await run('invite', () => api.post('/api/v1/onboarding/invitations', {
      email: invite.email.trim(),
      role: invite.role,
      team_id: invite.team_id || undefined,
      actor,
    }))
    if (!result) return
    // The link is a fallback, not a receipt: when a server took the message the
    // invitation lives in the person's inbox, and printing a live token here
    // only spreads it.
    showLink(result.delivery?.sent ? '' : (result.data.invite_url || ''))
    setInvite({ email: '', role: invite.role, team_id: invite.team_id })
    setNotice(result.delivery?.sent
      ? `Invitation email sent to ${result.data.email}. It expires on `
        + new Date(result.data.expires_at).toLocaleDateString() + '.'
      : `Seat created for ${result.data.email}. Email delivery is not configured on `
        + 'this deployment, so copy the single-use link below and send it yourself.')
  }

  async function resend(row) {
    const result = await run(`resend:${row.id}`,
      () => api.post(`/api/v1/onboarding/invitations/${row.id}/resend`, { actor }))
    if (!result) return
    showLink(result.delivery?.sent ? '' : (result.data.invite_url || ''))
    setNotice(result.delivery?.sent
      ? `Invitation re-sent to ${row.email}; the previous link no longer works.`
      : `New link for ${row.email}. Copy it below; the previous link no longer works.`)
  }

  async function revoke(row) {
    await run(`revoke:${row.id}`,
      () => api.post(`/api/v1/onboarding/invitations/${row.id}/revoke`, { actor }),
      () => `Invitation for ${row.email} revoked.`)
  }

  async function createTeam(event) {
    event?.preventDefault()
    if (team.name.trim().length < 2) {
      setError('Give the team a name.')
      return
    }
    const result = await run('team',
      () => api.post('/api/v1/onboarding/teams',
        { name: team.name.trim(), description: team.description, actor }),
      () => `Team “${team.name.trim()}” created.`)
    if (result) setTeam({ name: '', description: '' })
  }

  async function connectScm(event) {
    event?.preventDefault()
    if (scm.token.trim().length < 4) {
      setError('Paste the access token for the code host.')
      return
    }
    const result = await run('scm', () => api.post('/api/v1/onboarding/connections', {
      kind: 'scm',
      provider: scm.provider,
      base_url: scm.base_url.trim(),
      token: scm.token.trim(),
      label: scm.label.trim() || undefined,
      actor,
    }), () => `${scm.label.trim() || scm.provider} connected read-only.`)
    if (result) setScm({ ...scm, token: '', label: '' })
  }

  async function connectTickets(event) {
    event?.preventDefault()
    if (!tickets.base_url.trim() || !tickets.account.trim() || !tickets.token.trim()) {
      setError('Jira needs its base URL, the token owner’s email and the API token.')
      return
    }
    const result = await run('tickets', () => api.post('/api/v1/onboarding/connections', {
      kind: 'tickets',
      provider: 'jira',
      base_url: tickets.base_url.trim(),
      account: tickets.account.trim(),
      token: tickets.token.trim(),
      project_key: tickets.project_key.trim() || undefined,
      actor,
    }), () => 'Jira connected. Findings can be exported as tickets.')
    if (result) setTickets({ ...tickets, token: '' })
  }

  async function verifyConnection(row) {
    const result = await run(`verify:${row.id}`,
      () => api.post(`/api/v1/onboarding/connections/${row.id}/verify`, { actor }))
    if (!result) return
    setNotice(result.verified
      ? `${row.provider_label} still answers; the connection is live.`
      : `${row.provider_label} did not answer: ${result.data.last_error}`)
  }

  async function removeConnection(row) {
    await run(`remove:${row.id}`,
      () => api.post(`/api/v1/onboarding/connections/${row.id}/remove`, { actor }),
      () => `${row.provider_label} connection removed.`)
  }

  async function finish() {
    const result = await run('finish', () => api.post('/api/v1/onboarding/complete?actor='
      + encodeURIComponent(actor), {}))
    if (result) {
      window.history.replaceState({}, '', '/#dashboard')
      onFinish()
    }
  }

  if (!state) {
    return (
      <main className="onb-shell">
        <div className="onb-body">
          <p className="onb-kicker">Barad-dûr setup</p>
          <h1 className="onb-h1">Preparing your workspace</h1>
          {error
            ? <p className="banner banner-error">{error}</p>
            : <p className="onb-sub">Reading the current state of the organization…</p>}
        </div>
      </main>
    )
  }

  const current = STEPS[step - 1]
  const scmConnections = state.connections?.scm || []
  const ticketConnections = state.connections?.tickets || []
  const pending = (state.invitations || []).filter((row) => row.status === 'pending')
  const people = (state.members || []).length + pending.length
  const mailReady = state.mail?.configured

  const stepBody = () => {
    if (step === 2) {
      return (
        <form className="onb-form" onSubmit={saveOrganization}>
          <div className="onb-logo-row">
            <div className="onb-logo" aria-hidden="true">
              {org.logo
                ? <img src={org.logo} alt="" />
                : <span>{(org.name || 'B').slice(0, 1).toUpperCase()}</span>}
            </div>
            <div className="onb-logo-actions">
              <button type="button" className="mini" onClick={() => logoInput.current?.click()}>
                {logoBusy ? 'reading…' : org.logo ? 'replace logo' : 'upload logo'}
              </button>
              {org.logo && (
                <button type="button" className="mini quiet"
                  onClick={() => setOrg({ ...org, logo: '' })}>remove</button>
              )}
              <span className="onb-help">PNG, JPG or SVG. Resized to 128 px and stored with the organization.</span>
              <input ref={logoInput} type="file" accept="image/*" hidden
                onChange={(e) => handleLogo(e.target.files?.[0])} />
            </div>
          </div>

          <label>
            Organization name
            <input value={org.name} onChange={(e) => setOrg({ ...org, name: e.target.value })}
              placeholder="Barad-dûr Labs" />
            <span className="onb-help">Shown in the sidebar and on every screen. The slug
              <code className="onb-code">{state.org.slug}</code> stays fixed.</span>
          </label>
          <label>
            What the organization does
            <textarea rows={3} value={org.description}
              onChange={(e) => setOrg({ ...org, description: e.target.value })}
              placeholder="One line a new teammate would understand." />
          </label>
          <label>
            Corporate website
            <input value={org.website} onChange={(e) => setOrg({ ...org, website: e.target.value })}
              placeholder="https://example.com" inputMode="url" />
          </label>
          <div className="onb-actions">
            <button className="btn-primary" type="submit" disabled={busy === 'org'}>
              {busy === 'org' ? 'Saving…' : 'Save and continue'}
            </button>
          </div>
        </form>
      )
    }

    if (step === 3) {
      return (
        <>
          <div className="onb-section-head">
            <h2>Pick the role that fits the person</h2>
            <p>Add more roles later from Members. Roles are the ceiling; teams decide
              what someone can see inside it.</p>
          </div>

          <RoleTable roles={state.roles} value={invite.role}
            onChange={(role) => setInvite({ ...invite, role })} />

          <form className="onb-invite-form" onSubmit={sendInvite}>
            <label>
              Email
              <input type="email" value={invite.email} autoComplete="off"
                onChange={(e) => setInvite({ ...invite, email: e.target.value })}
                placeholder="teammate@example.com" />
            </label>
            <label>
              Team
              <select value={invite.team_id}
                onChange={(e) => setInvite({ ...invite, team_id: e.target.value })}>
                <option value="">No team</option>
                {state.teams.map((row) => (
                  <option key={row.id} value={row.id}>{row.name}</option>
                ))}
              </select>
            </label>
            <label>
              Role
              <select value={invite.role}
                onChange={(e) => setInvite({ ...invite, role: e.target.value })}>
                {state.roles.map((role) => (
                  <option key={role.value} value={role.value}>{role.label}</option>
                ))}
              </select>
            </label>
            <button className="btn-primary" type="submit" disabled={busy === 'invite'}>
              {mailReady
                ? (busy === 'invite' ? 'Sending…' : 'Send invitation')
                : (busy === 'invite' ? 'Creating…' : 'Create invitation')}
            </button>
          </form>

          {inviteLink && (
            <div className="onb-link" ref={linkRef}>
              <span className="onb-help">Single-use link — expires in a few days, works once.</span>
              <div className="onb-link-row">
                <input readOnly value={inviteLink} onFocus={(e) => e.target.select()} />
                <button type="button" className="mini"
                  onClick={() => navigator.clipboard?.writeText(inviteLink)}>copy</button>
              </div>
            </div>
          )}

          {!mailReady && (
            <>
              <p className="onb-note">
                Email delivery is not configured on this deployment. Invitations are
                created and listed here either way; the single-use link is shown after
                each invitation so you can send it through your own channel. Configure
                a mail server and every later invitation is emailed automatically.
              </p>
              <div>
                <button type="button" className="mini" onClick={() => setMailOpen((open) => !open)}>
                  {mailOpen ? 'hide mail settings' : 'configure email delivery'}
                </button>
              </div>
              {mailOpen && (
                <MailSettings
                  defaultRecipient={owner?.email || ''}
                  onConfigured={() => {
                    load()
                    setMailOpen(false)
                    setNotice('Email delivery configured. New invitations are emailed.')
                  }} />
              )}
            </>
          )}
          {mailReady && (
            <p className="onb-help">
              Email delivery: {state.mail.host}:{state.mail.port} · from {state.mail.sender}
              {state.mail.source === 'environment' ? ' (deployment environment)' : ''}
            </p>
          )}

          <div className="onb-section-head">
            <h2>Pending invitations</h2>
            <p>{pending.length
              ? `${pending.length} seat${pending.length === 1 ? '' : 's'} waiting to be accepted.`
              : 'Nobody is pending. Invitations appear here until they are accepted or revoked.'}</p>
          </div>
          {(state.invitations || []).length === 0
            ? <p className="onb-empty">No invitations yet.</p>
            : (
              <table className="onb-table">
                <thead>
                  <tr><th>Email</th><th>Role</th><th>Team</th><th>Status</th><th>Sent</th><th /></tr>
                </thead>
                <tbody>
                  {state.invitations.map((row) => (
                    <tr key={row.id}>
                      <td>{row.email}</td>
                      <td>{row.role_label}</td>
                      <td>{row.team || <span className="onb-muted">no team</span>}</td>
                      <td><StatusPill status={row.status} /></td>
                      <td className="onb-muted">
                        {row.last_sent_at
                          ? `${row.last_delivery === 'email' ? 'email' : 'manual'} · `
                            + new Date(row.last_sent_at).toLocaleDateString()
                          : 'not sent'}
                      </td>
                      <td className="onb-row-actions">
                        {row.status !== 'accepted' && (
                          <>
                            <button className="mini quiet" onClick={() => resend(row)}
                              disabled={busy === `resend:${row.id}`}>new link</button>
                            {row.status === 'pending' && (
                              <button className="mini quiet" onClick={() => revoke(row)}
                                disabled={busy === `revoke:${row.id}`}>revoke</button>
                            )}
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

          <div className="onb-section-head">
            <h2>Teams</h2>
            <p>Optional. Teams give access to their assets and findings. Without a team,
              a member who does not see all data sees nothing.</p>
          </div>
          {state.teams.length === 0
            ? <p className="onb-empty">This organization has no teams yet.</p>
            : (
              <table className="onb-table">
                <thead><tr><th>Team</th><th>What it covers</th><th>Members</th></tr></thead>
                <tbody>
                  {state.teams.map((row) => (
                    <tr key={row.id}>
                      <td>{row.name}</td>
                      <td className="onb-muted">{row.description || '—'}</td>
                      <td>{row.members}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          <form className="onb-inline-form" onSubmit={createTeam}>
            <input value={team.name} placeholder="Team name"
              onChange={(e) => setTeam({ ...team, name: e.target.value })} />
            <input value={team.description} placeholder="What it covers (optional)"
              onChange={(e) => setTeam({ ...team, description: e.target.value })} />
            <button className="mini" type="submit" disabled={busy === 'team'}>create team</button>
          </form>

          <div className="onb-actions">
            <button className="btn-primary" onClick={() => go(4)}>Continue</button>
            <button className="mini quiet" onClick={() => go(4)}>Invite people later</button>
          </div>
        </>
      )
    }

    if (step === 4) {
      return (
        <>
          <div className="onb-section-head">
            <h2>Code hosts, read-only</h2>
            <p>Barad-dûr uses this credential to list and clone repositories for analysis.
              It never pushes, edits or deletes anything — not now, not later. Use a
              token that can read repositories, not an account password.</p>
          </div>
          <form className="onb-form onb-grid" onSubmit={connectScm}>
            <label>
              Provider
              <select value={scm.provider}
                onChange={(e) => setScm({ ...scm, provider: e.target.value })}>
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
                <option value="gitea">Gitea</option>
              </select>
            </label>
            <label>
              Base URL
              <input value={scm.base_url} onChange={(e) => setScm({ ...scm, base_url: e.target.value })}
                placeholder={scm.provider === 'gitea' ? 'https://git.example.com' : 'default public host'} />
              <span className="onb-help">Leave empty for the public service; self-hosted needs its URL.</span>
            </label>
            <label className="onb-span">
              Access token
              <input type="password" value={scm.token} autoComplete="off"
                onChange={(e) => setScm({ ...scm, token: e.target.value })}
                placeholder="read-only personal access token" />
            </label>
            <label>
              Label
              <input value={scm.label} onChange={(e) => setScm({ ...scm, label: e.target.value })}
                placeholder="e.g. bitsentry" />
            </label>
            <div className="onb-form-actions">
              <button className="btn-primary" type="submit" disabled={busy === 'scm'}>
                {busy === 'scm' ? 'Checking…' : 'Connect read-only'}
              </button>
            </div>
          </form>

          <div className="onb-section-head">
            <h2>Connected code hosts</h2>
            <p>{scmConnections.length
              ? 'Verified by reading the token owner’s identity.'
              : 'Nothing connected yet. Repositories are added later, one by one.'}</p>
          </div>
          {scmConnections.length === 0
            ? <p className="onb-empty">No code host connected.</p>
            : (
              <table className="onb-table">
                <thead><tr><th>Provider</th><th>Account</th><th>Base URL</th><th>Access</th><th>Verified</th><th /></tr></thead>
                <tbody>
                  {scmConnections.map((row) => (
                    <tr key={row.id}>
                      <td>{row.label || row.provider_label}</td>
                      <td>{row.account || <span className="onb-muted">unknown</span>}</td>
                      <td className="onb-muted">{row.base_url}</td>
                      <td><span className="onb-pill read">read-only</span></td>
                      <td className="onb-muted">{row.verified_at
                        ? new Date(row.verified_at).toLocaleDateString() : row.last_error || '—'}</td>
                      <td className="onb-row-actions">
                        <button className="mini quiet" onClick={() => verifyConnection(row)}
                          disabled={busy === `verify:${row.id}`}>check</button>
                        <button className="mini quiet" onClick={() => removeConnection(row)}
                          disabled={busy === `remove:${row.id}`}>remove</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

          <div className="onb-actions">
            <button className="btn-primary" onClick={() => go(5)}>Continue</button>
            <button className="mini quiet" onClick={() => go(5)}>Connect code later</button>
          </div>
        </>
      )
    }

    if (step === 5) {
      return (
        <>
          <div className="onb-section-head">
            <h2>Jira</h2>
            <p>Optional. A Jira connection lets findings be exported as issues and their
              status read back. Use an API token scoped to the project you care about.</p>
          </div>
          <form className="onb-form onb-grid" onSubmit={connectTickets}>
            <label>
              Jira base URL
              <input value={tickets.base_url}
                onChange={(e) => setTickets({ ...tickets, base_url: e.target.value })}
                placeholder="https://your-team.atlassian.net" inputMode="url" />
            </label>
            <label>
              Token owner email
              <input value={tickets.account}
                onChange={(e) => setTickets({ ...tickets, account: e.target.value })}
                placeholder="you@example.com" />
            </label>
            <label>
              API token
              <input type="password" value={tickets.token} autoComplete="off"
                onChange={(e) => setTickets({ ...tickets, token: e.target.value })}
                placeholder="Atlassian API token" />
            </label>
            <label>
              Project key
              <input value={tickets.project_key}
                onChange={(e) => setTickets({ ...tickets, project_key: e.target.value })}
                placeholder="SEC (optional)" />
            </label>
            <div className="onb-form-actions">
              <button className="btn-primary" type="submit" disabled={busy === 'tickets'}>
                {busy === 'tickets' ? 'Checking…' : 'Connect Jira'}
              </button>
            </div>
          </form>

          <div className="onb-section-head">
            <h2>Connected trackers</h2>
            <p>{ticketConnections.length
              ? 'Verified by reading the token owner’s profile.'
              : 'Nothing connected yet. The Jira screen keeps working without a connection; nothing is exported until one exists.'}</p>
          </div>
          {ticketConnections.length === 0
            ? <p className="onb-empty">No ticket tracker connected.</p>
            : (
              <table className="onb-table">
                <thead><tr><th>Tracker</th><th>Account</th><th>Base URL</th><th>Project</th><th /></tr></thead>
                <tbody>
                  {ticketConnections.map((row) => (
                    <tr key={row.id}>
                      <td>{row.provider_label}</td>
                      <td>{row.account || '—'}</td>
                      <td className="onb-muted">{row.base_url}</td>
                      <td>{row.config?.project_key || <span className="onb-muted">any</span>}</td>
                      <td className="onb-row-actions">
                        <button className="mini quiet" onClick={() => verifyConnection(row)}
                          disabled={busy === `verify:${row.id}`}>check</button>
                        <button className="mini quiet" onClick={() => removeConnection(row)}
                          disabled={busy === `remove:${row.id}`}>remove</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

          <div className="onb-actions">
            <button className="btn-primary" onClick={() => go(6)}>Continue</button>
            <button className="mini quiet" onClick={() => go(6)}>Connect tickets later</button>
          </div>
        </>
      )
    }

    const summary = [
      { key: 2, label: 'Organization profile',
        value: state.org.name + (state.org.website ? ` · ${state.org.website}` : ''),
        done: Boolean(state.org.name) },
      { key: 3, label: 'People',
        value: `${state.members.length} member${state.members.length === 1 ? '' : 's'}`
          + (pending.length ? ` · ${pending.length} pending` : ''),
        done: people > 1 },
      { key: 4, label: 'Code hosts',
        value: scmConnections.length
          ? scmConnections.map((row) => row.label || row.provider_label).join(', ')
          : 'not connected',
        done: scmConnections.length > 0 },
      { key: 5, label: 'Ticket tracker',
        value: ticketConnections.length
          ? ticketConnections.map((row) => row.provider_label).join(', ')
          : 'not connected',
        done: ticketConnections.length > 0 },
    ]
    return (
      <>
        <div className="onb-section-head">
          <h2>Everything is in place</h2>
          <p>Anything left unattended can be finished later from Members, Settings and
            the Jira screen. Opening the workspace never starts a scan by itself.</p>
        </div>
        <ul className="onb-summary">
          {summary.map((row) => (
            <li key={row.key}>
              <span className={`onb-tick${row.done ? ' done' : ''}`}>{row.done ? '✓' : '–'}</span>
              <span className="onb-summary-label">{row.label}</span>
              <span className="onb-summary-value">{row.value}</span>
              <button className="mini quiet" onClick={() => go(row.key)}>edit</button>
            </li>
          ))}
        </ul>
        <div className="onb-actions">
          <button className="btn-primary" onClick={finish} disabled={busy === 'finish'}>
            {busy === 'finish' ? 'Opening…' : 'Enter Barad-dûr'}
          </button>
          <span className="onb-help">Start with Scope, then add applications and authorize analysis.</span>
        </div>
      </>
    )
  }

  return (
    <main className="onb-shell">
      <div className="onb-body">
        <header className="onb-head">
          <div className="onb-brand">
            <BrandMark size={26} />
            <span>Barad-dûr</span>
          </div>
          <span className="onb-kicker">Setup · step {step} of {STEPS.length}</span>
          <h1 className="onb-h1">{current.title}</h1>
          <p className="onb-sub">{current.hint}</p>
        </header>

        <nav className="onb-rail" aria-label="Onboarding steps">
          {STEPS.map((entry, index) => {
            const number = index + 1
            const status = number < 2 ? 'done'
              : number === step ? 'current' : number < step ? 'done' : ''
            return (
              <button key={entry.key} type="button" className={`onb-rail-step ${status}`}
                onClick={() => go(number)} aria-current={number === step ? 'step' : undefined}>
                <span className="onb-rail-num">{number < step ? '✓' : number}</span>
                <span className="onb-rail-label">{entry.label}</span>
              </button>
            )
          })}
        </nav>

        <div className="onb-stage">
          {error && <p className="banner banner-error" role="alert">{error}</p>}
          {notice && <p className="banner banner-info" role="status">{notice}</p>}
          {stepBody()}
        </div>
      </div>
    </main>
  )
}
