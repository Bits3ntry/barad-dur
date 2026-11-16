import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import { BrandMark } from './Login'
import { useI18n } from './i18n'
import MailSettings from './MailSettings'

/* The first-run walk-through, six ordered steps from an empty workspace to a
   usable one. Everything is saved as it is entered, so the rail is free to move
   in both directions and a reload resumes where the owner left off.

   Two rules shape this screen:
   - the copy states what the platform actually does (roles, read-only code
     access, the fact that an invitation is a seat and email is one channel);
   - an optional step can be skipped without pretending it was configured. */

const STEPS = [
  { key: 'workspace', labelKey: 'startup.step.workspace.label', titleKey: 'startup.step.workspace.title',
    hintKey: 'startup.step.workspace.hint' },
  { key: 'organization', labelKey: 'startup.step.organization.label', titleKey: 'startup.step.organization.title',
    hintKey: 'startup.step.organization.hint' },
  { key: 'team', labelKey: 'startup.step.team.label', titleKey: 'startup.step.team.title',
    hintKey: 'startup.step.team.hint' },
  { key: 'code', labelKey: 'startup.step.code.label', titleKey: 'startup.step.code.title',
    hintKey: 'startup.step.code.hint' },
  { key: 'tickets', labelKey: 'startup.step.tickets.label', titleKey: 'startup.step.tickets.title',
    hintKey: 'startup.step.tickets.hint' },
  { key: 'enter', labelKey: 'startup.step.enter.label', titleKey: 'startup.step.enter.title',
    hintKey: 'startup.step.enter.hint' },
]

function initialStep() {
  const value = Number(new URLSearchParams(window.location.hash.slice(1)).get('step'))
  return Number.isInteger(value) && value >= 2 && value <= STEPS.length ? value : 2
}

function downsample(file, size = 128) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('unreadable'))
    reader.onload = () => {
      const image = new Image()
      image.onerror = () => reject(new Error('not-an-image'))
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
  const { tOr } = useI18n()
  return <span className={`onb-pill ${status}`}>{tOr(`startup.status.${status}`, status)}</span>
}

function RoleTable({ roles, value, onChange }) {
  const { t } = useI18n()
  return (
    <div className="onb-role-table" role="radiogroup" aria-label={t('startup.role.aria')}>
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
  const { t, tCount } = useI18n()
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
      setError(t('startup.error.orgName'))
      return
    }
    const result = await run('org', () => api.patch('/api/v1/org', {
      name: org.name.trim(),
      description: org.description,
      website: org.website.trim(),
      logo: org.logo,
      actor,
    }), () => t('startup.notice.orgSaved'))
    if (result) go(3)
  }

  async function handleLogo(file) {
    if (!file) return
    if (file.size > 2 * 1024 * 1024) {
      setError(t('startup.error.logoTooLarge'))
      return
    }
    setLogoBusy(true)
    setError('')
    try {
      const dataUrl = await downsample(file)
      setOrg((current) => ({ ...current, logo: dataUrl }))
    } catch (e) {
      const message = String(e.message || e)
      setError(message === 'unreadable' ? t('startup.error.fileUnreadable')
        : message === 'not-an-image' ? t('startup.error.fileNotImage')
        : message)
    } finally {
      setLogoBusy(false)
    }
  }

  async function sendInvite(event) {
    event?.preventDefault()
    if (!invite.email.trim()) {
      setError(t('startup.error.inviteEmail'))
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
      ? t('startup.notice.inviteSent', {
        email: result.data.email,
        date: new Date(result.data.expires_at).toLocaleDateString(),
      })
      : t('startup.notice.seatCreated', { email: result.data.email }))
  }

  async function resend(row) {
    const result = await run(`resend:${row.id}`,
      () => api.post(`/api/v1/onboarding/invitations/${row.id}/resend`, { actor }))
    if (!result) return
    showLink(result.delivery?.sent ? '' : (result.data.invite_url || ''))
    setNotice(result.delivery?.sent
      ? t('startup.notice.resent', { email: row.email })
      : t('startup.notice.newLink', { email: row.email }))
  }

  async function revoke(row) {
    await run(`revoke:${row.id}`,
      () => api.post(`/api/v1/onboarding/invitations/${row.id}/revoke`, { actor }),
      () => t('startup.notice.revoked', { email: row.email }))
  }

  async function createTeam(event) {
    event?.preventDefault()
    if (team.name.trim().length < 2) {
      setError(t('startup.error.teamName'))
      return
    }
    const result = await run('team',
      () => api.post('/api/v1/onboarding/teams',
        { name: team.name.trim(), description: team.description, actor }),
      () => t('startup.notice.teamCreated', { name: team.name.trim() }))
    if (result) setTeam({ name: '', description: '' })
  }

  async function connectScm(event) {
    event?.preventDefault()
    if (scm.token.trim().length < 4) {
      setError(t('startup.error.scmToken'))
      return
    }
    const result = await run('scm', () => api.post('/api/v1/onboarding/connections', {
      kind: 'scm',
      provider: scm.provider,
      base_url: scm.base_url.trim(),
      token: scm.token.trim(),
      label: scm.label.trim() || undefined,
      actor,
    }), () => t('startup.notice.scmConnected', { provider: scm.label.trim() || scm.provider }))
    if (result) setScm({ ...scm, token: '', label: '' })
  }

  async function connectTickets(event) {
    event?.preventDefault()
    if (!tickets.base_url.trim() || !tickets.account.trim() || !tickets.token.trim()) {
      setError(t('startup.error.jiraFields'))
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
    }), () => t('startup.notice.jiraConnected'))
    if (result) setTickets({ ...tickets, token: '' })
  }

  async function verifyConnection(row) {
    const result = await run(`verify:${row.id}`,
      () => api.post(`/api/v1/onboarding/connections/${row.id}/verify`, { actor }))
    if (!result) return
    setNotice(result.verified
      ? t('startup.notice.verifyOk', { provider: row.provider_label })
      : t('startup.notice.verifyFail', { provider: row.provider_label, error: result.data.last_error }))
  }

  async function removeConnection(row) {
    await run(`remove:${row.id}`,
      () => api.post(`/api/v1/onboarding/connections/${row.id}/remove`, { actor }),
      () => t('startup.notice.connectionRemoved', { provider: row.provider_label }))
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
          <p className="onb-kicker">{t('startup.loading.kicker')}</p>
          <h1 className="onb-h1">{t('startup.loading.title')}</h1>
          {error
            ? <p className="banner banner-error">{error}</p>
            : <p className="onb-sub">{t('startup.loading.sub')}</p>}
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
                {logoBusy ? t('startup.logo.reading') : org.logo ? t('startup.logo.replace') : t('startup.logo.upload')}
              </button>
              {org.logo && (
                <button type="button" className="mini quiet"
                  onClick={() => setOrg({ ...org, logo: '' })}>{t('startup.logo.remove')}</button>
              )}
              <span className="onb-help">{t('startup.logo.help')}</span>
              <input ref={logoInput} type="file" accept="image/*" hidden
                onChange={(e) => handleLogo(e.target.files?.[0])} />
            </div>
          </div>

          <label>
            {t('startup.field.orgName')}
            <input value={org.name} onChange={(e) => setOrg({ ...org, name: e.target.value })}
              placeholder="Barad-dûr Labs" />
            <span className="onb-help">
              {t('startup.field.orgNameHelpPre')}
              <code className="onb-code">{state.org.slug}</code>
              {t('startup.field.orgNameHelpPost')}
            </span>
          </label>
          <label>
            {t('startup.field.description')}
            <textarea rows={3} value={org.description}
              onChange={(e) => setOrg({ ...org, description: e.target.value })}
              placeholder={t('startup.placeholder.description')} />
          </label>
          <label>
            {t('startup.field.website')}
            <input value={org.website} onChange={(e) => setOrg({ ...org, website: e.target.value })}
              placeholder="https://example.com" inputMode="url" />
          </label>
          <div className="onb-actions">
            <button className="btn-primary" type="submit" disabled={busy === 'org'}>
              {busy === 'org' ? t('startup.busy.saving') : t('startup.action.saveContinue')}
            </button>
          </div>
        </form>
      )
    }

    if (step === 3) {
      return (
        <>
          <div className="onb-section-head">
            <h2>{t('startup.roles.title')}</h2>
            <p>{t('startup.roles.hint')}</p>
          </div>

          <RoleTable roles={state.roles} value={invite.role}
            onChange={(role) => setInvite({ ...invite, role })} />

          <form className="onb-invite-form" onSubmit={sendInvite}>
            <label>
              {t('startup.field.email')}
              <input type="email" value={invite.email} autoComplete="off"
                onChange={(e) => setInvite({ ...invite, email: e.target.value })}
                placeholder="teammate@example.com" />
            </label>
            <label>
              {t('startup.field.team')}
              <select value={invite.team_id}
                onChange={(e) => setInvite({ ...invite, team_id: e.target.value })}>
                <option value="">{t('startup.option.noTeam')}</option>
                {state.teams.map((row) => (
                  <option key={row.id} value={row.id}>{row.name}</option>
                ))}
              </select>
            </label>
            <label>
              {t('startup.field.role')}
              <select value={invite.role}
                onChange={(e) => setInvite({ ...invite, role: e.target.value })}>
                {state.roles.map((role) => (
                  <option key={role.value} value={role.value}>{role.label}</option>
                ))}
              </select>
            </label>
            <button className="btn-primary" type="submit" disabled={busy === 'invite'}>
              {mailReady
                ? (busy === 'invite' ? t('startup.busy.sending') : t('startup.action.sendInvite'))
                : (busy === 'invite' ? t('startup.busy.creating') : t('startup.action.createInvite'))}
            </button>
          </form>

          {inviteLink && (
            <div className="onb-link" ref={linkRef}>
              <span className="onb-help">{t('startup.link.help')}</span>
              <div className="onb-link-row">
                <input readOnly value={inviteLink} onFocus={(e) => e.target.select()} />
                <button type="button" className="mini"
                  onClick={() => navigator.clipboard?.writeText(inviteLink)}>{t('common.copy')}</button>
              </div>
            </div>
          )}

          {!mailReady && (
            <>
              <p className="onb-note">
                {t('startup.mail.note')}
              </p>
              <div>
                <button type="button" className="mini" onClick={() => setMailOpen((open) => !open)}>
                  {mailOpen ? t('startup.mail.hide') : t('startup.mail.configure')}
                </button>
              </div>
              {mailOpen && (
                <MailSettings
                  defaultRecipient={owner?.email || ''}
                  onConfigured={() => {
                    load()
                    setMailOpen(false)
                    setNotice(t('startup.mail.configured'))
                  }} />
              )}
            </>
          )}
          {mailReady && (
            <p className="onb-help">
              {t('startup.mail.ready', {
                host: state.mail.host, port: state.mail.port, sender: state.mail.sender,
              })}
              {state.mail.source === 'environment' ? t('startup.mail.env') : ''}
            </p>
          )}

          <div className="onb-section-head">
            <h2>{t('startup.invites.title')}</h2>
            <p>{pending.length
              ? tCount('startup.invites.pending', pending.length)
              : t('startup.invites.noneWaiting')}</p>
          </div>
          {(state.invitations || []).length === 0
            ? <p className="onb-empty">{t('startup.invites.empty')}</p>
            : (
              <table className="onb-table">
                <thead>
                  <tr><th>{t('startup.th.email')}</th><th>{t('startup.th.role')}</th><th>{t('startup.th.team')}</th><th>{t('startup.th.status')}</th><th>{t('startup.th.sent')}</th><th /></tr>
                </thead>
                <tbody>
                  {state.invitations.map((row) => (
                    <tr key={row.id}>
                      <td>{row.email}</td>
                      <td>{row.role_label}</td>
                      <td>{row.team || <span className="onb-muted">{t('startup.cell.noTeam')}</span>}</td>
                      <td><StatusPill status={row.status} /></td>
                      <td className="onb-muted">
                        {row.last_sent_at
                          ? `${row.last_delivery === 'email' ? t('startup.delivery.email') : t('startup.delivery.manual')} · `
                            + new Date(row.last_sent_at).toLocaleDateString()
                          : t('startup.cell.notSent')}
                      </td>
                      <td className="onb-row-actions">
                        {row.status !== 'accepted' && (
                          <>
                            <button className="mini quiet" onClick={() => resend(row)}
                              disabled={busy === `resend:${row.id}`}>{t('startup.action.newLink')}</button>
                            {row.status === 'pending' && (
                              <button className="mini quiet" onClick={() => revoke(row)}
                                disabled={busy === `revoke:${row.id}`}>{t('startup.action.revoke')}</button>
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
            <h2>{t('startup.teams.title')}</h2>
            <p>{t('startup.teams.hint')}</p>
          </div>
          {state.teams.length === 0
            ? <p className="onb-empty">{t('startup.teams.empty')}</p>
            : (
              <table className="onb-table">
                <thead><tr><th>{t('startup.th.team')}</th><th>{t('startup.th.covers')}</th><th>{t('startup.th.members')}</th></tr></thead>
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
            <input value={team.name} placeholder={t('startup.placeholder.teamName')}
              onChange={(e) => setTeam({ ...team, name: e.target.value })} />
            <input value={team.description} placeholder={t('startup.placeholder.teamCovers')}
              onChange={(e) => setTeam({ ...team, description: e.target.value })} />
            <button className="mini" type="submit" disabled={busy === 'team'}>{t('startup.action.createTeam')}</button>
          </form>

          <div className="onb-actions">
            <button className="btn-primary" onClick={() => go(4)}>{t('startup.action.continue')}</button>
            <button className="mini quiet" onClick={() => go(4)}>{t('startup.action.later.invite')}</button>
          </div>
        </>
      )
    }

    if (step === 4) {
      return (
        <>
          <div className="onb-section-head">
            <h2>{t('startup.code.title')}</h2>
            <p>{t('startup.code.hint')}</p>
          </div>
          <form className="onb-form onb-grid" onSubmit={connectScm}>
            <label>
              {t('startup.field.provider')}
              <select value={scm.provider}
                onChange={(e) => setScm({ ...scm, provider: e.target.value })}>
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
                <option value="gitea">Gitea</option>
              </select>
            </label>
            <label>
              {t('startup.field.baseUrl')}
              <input value={scm.base_url} onChange={(e) => setScm({ ...scm, base_url: e.target.value })}
                placeholder={scm.provider === 'gitea' ? 'https://git.example.com' : t('startup.placeholder.defaultHost')} />
              <span className="onb-help">{t('startup.code.baseUrlHelp')}</span>
            </label>
            <label className="onb-span">
              {t('startup.field.accessToken')}
              <input type="password" value={scm.token} autoComplete="off"
                onChange={(e) => setScm({ ...scm, token: e.target.value })}
                placeholder={t('startup.placeholder.scmToken')} />
            </label>
            <label>
              {t('startup.field.label')}
              <input value={scm.label} onChange={(e) => setScm({ ...scm, label: e.target.value })}
                placeholder={t('startup.placeholder.scmLabel')} />
            </label>
            <div className="onb-form-actions">
              <button className="btn-primary" type="submit" disabled={busy === 'scm'}>
                {busy === 'scm' ? t('startup.busy.checking') : t('startup.action.connectReadOnly')}
              </button>
            </div>
          </form>

          <div className="onb-section-head">
            <h2>{t('startup.connected.code.title')}</h2>
            <p>{scmConnections.length
              ? t('startup.connected.code.hint')
              : t('startup.connected.code.hintEmpty')}</p>
          </div>
          {scmConnections.length === 0
            ? <p className="onb-empty">{t('startup.connected.code.empty')}</p>
            : (
              <table className="onb-table">
                <thead><tr><th>{t('startup.th.provider')}</th><th>{t('startup.th.account')}</th><th>{t('startup.th.baseUrl')}</th><th>{t('startup.th.access')}</th><th>{t('startup.th.verified')}</th><th /></tr></thead>
                <tbody>
                  {scmConnections.map((row) => (
                    <tr key={row.id}>
                      <td>{row.label || row.provider_label}</td>
                      <td>{row.account || <span className="onb-muted">{t('common.unknown')}</span>}</td>
                      <td className="onb-muted">{row.base_url}</td>
                      <td><span className="onb-pill read">{t('startup.pill.readOnly')}</span></td>
                      <td className="onb-muted">{row.verified_at
                        ? new Date(row.verified_at).toLocaleDateString() : row.last_error || '—'}</td>
                      <td className="onb-row-actions">
                        <button className="mini quiet" onClick={() => verifyConnection(row)}
                          disabled={busy === `verify:${row.id}`}>{t('startup.action.check')}</button>
                        <button className="mini quiet" onClick={() => removeConnection(row)}
                          disabled={busy === `remove:${row.id}`}>{t('startup.action.remove')}</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

          <div className="onb-actions">
            <button className="btn-primary" onClick={() => go(5)}>{t('startup.action.continue')}</button>
            <button className="mini quiet" onClick={() => go(5)}>{t('startup.action.later.code')}</button>
          </div>
        </>
      )
    }

    if (step === 5) {
      return (
        <>
          <div className="onb-section-head">
            <h2>Jira</h2>
            <p>{t('startup.jira.hint')}</p>
          </div>
          <form className="onb-form onb-grid" onSubmit={connectTickets}>
            <label>
              {t('startup.field.jiraBaseUrl')}
              <input value={tickets.base_url}
                onChange={(e) => setTickets({ ...tickets, base_url: e.target.value })}
                placeholder="https://your-team.atlassian.net" inputMode="url" />
            </label>
            <label>
              {t('startup.field.jiraAccount')}
              <input value={tickets.account}
                onChange={(e) => setTickets({ ...tickets, account: e.target.value })}
                placeholder="you@example.com" />
            </label>
            <label>
              {t('startup.field.jiraToken')}
              <input type="password" value={tickets.token} autoComplete="off"
                onChange={(e) => setTickets({ ...tickets, token: e.target.value })}
                placeholder={t('startup.placeholder.jiraToken')} />
            </label>
            <label>
              {t('startup.field.projectKey')}
              <input value={tickets.project_key}
                onChange={(e) => setTickets({ ...tickets, project_key: e.target.value })}
                placeholder={t('startup.placeholder.projectKey')} />
            </label>
            <div className="onb-form-actions">
              <button className="btn-primary" type="submit" disabled={busy === 'tickets'}>
                {busy === 'tickets' ? t('startup.busy.checking') : t('startup.action.connectJira')}
              </button>
            </div>
          </form>

          <div className="onb-section-head">
            <h2>{t('startup.connected.tickets.title')}</h2>
            <p>{ticketConnections.length
              ? t('startup.connected.tickets.hint')
              : t('startup.connected.tickets.hintEmpty')}</p>
          </div>
          {ticketConnections.length === 0
            ? <p className="onb-empty">{t('startup.connected.tickets.empty')}</p>
            : (
              <table className="onb-table">
                <thead><tr><th>{t('startup.th.tracker')}</th><th>{t('startup.th.account')}</th><th>{t('startup.th.baseUrl')}</th><th>{t('startup.th.project')}</th><th /></tr></thead>
                <tbody>
                  {ticketConnections.map((row) => (
                    <tr key={row.id}>
                      <td>{row.provider_label}</td>
                      <td>{row.account || '—'}</td>
                      <td className="onb-muted">{row.base_url}</td>
                      <td>{row.config?.project_key || <span className="onb-muted">{t('startup.cell.any')}</span>}</td>
                      <td className="onb-row-actions">
                        <button className="mini quiet" onClick={() => verifyConnection(row)}
                          disabled={busy === `verify:${row.id}`}>{t('startup.action.check')}</button>
                        <button className="mini quiet" onClick={() => removeConnection(row)}
                          disabled={busy === `remove:${row.id}`}>{t('startup.action.remove')}</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

          <div className="onb-actions">
            <button className="btn-primary" onClick={() => go(6)}>{t('startup.action.continue')}</button>
            <button className="mini quiet" onClick={() => go(6)}>{t('startup.action.later.tickets')}</button>
          </div>
        </>
      )
    }

    const summary = [
      { key: 2, label: t('startup.summary.org'),
        value: state.org.name + (state.org.website ? ` · ${state.org.website}` : ''),
        done: Boolean(state.org.name) },
      { key: 3, label: t('startup.summary.people'),
        value: tCount('startup.summary.members', state.members.length)
          + (pending.length ? ` · ${t('startup.summary.pending', { n: pending.length })}` : ''),
        done: people > 1 },
      { key: 4, label: t('startup.summary.code'),
        value: scmConnections.length
          ? scmConnections.map((row) => row.label || row.provider_label).join(', ')
          : t('startup.summary.notConnected'),
        done: scmConnections.length > 0 },
      { key: 5, label: t('startup.summary.tickets'),
        value: ticketConnections.length
          ? ticketConnections.map((row) => row.provider_label).join(', ')
          : t('startup.summary.notConnected'),
        done: ticketConnections.length > 0 },
    ]
    return (
      <>
        <div className="onb-section-head">
          <h2>{t('startup.finish.title')}</h2>
          <p>{t('startup.finish.hint')}</p>
        </div>
        <ul className="onb-summary">
          {summary.map((row) => (
            <li key={row.key}>
              <span className={`onb-tick${row.done ? ' done' : ''}`}>{row.done ? '✓' : '–'}</span>
              <span className="onb-summary-label">{row.label}</span>
              <span className="onb-summary-value">{row.value}</span>
              <button className="mini quiet" onClick={() => go(row.key)}>{t('startup.action.edit')}</button>
            </li>
          ))}
        </ul>
        <div className="onb-actions">
          <button className="btn-primary" onClick={finish} disabled={busy === 'finish'}>
            {busy === 'finish' ? t('startup.busy.opening') : t('startup.finish.enter')}
          </button>
          <span className="onb-help">{t('startup.finish.help')}</span>
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
          <span className="onb-kicker">{t('startup.header.step', { step, total: STEPS.length })}</span>
          <h1 className="onb-h1">{t(current.titleKey)}</h1>
          <p className="onb-sub">{t(current.hintKey)}</p>
        </header>

        <nav className="onb-rail" aria-label={t('startup.rail.aria')}>
          {STEPS.map((entry, index) => {
            const number = index + 1
            const status = number < 2 ? 'done'
              : number === step ? 'current' : number < step ? 'done' : ''
            return (
              <button key={entry.key} type="button" className={`onb-rail-step ${status}`}
                onClick={() => go(number)} aria-current={number === step ? 'step' : undefined}>
                <span className="onb-rail-num">{number < step ? '✓' : number}</span>
                <span className="onb-rail-label">{t(entry.labelKey)}</span>
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
