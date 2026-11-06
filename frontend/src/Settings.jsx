import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Card, Dialog, EmptyState, PageHeader, Pager, Table, ToastContainer, usePage, useToasts,
  getDensity, getTheme, setDensity, setTheme } from './ui'
import MailSettings from './MailSettings'
import AdvisoriesSettings from './AdvisoriesSettings'
import Icon from './icons'
import Security from './Security'
import Notifications from './Notifications'
import Grants from './Grants'
import Members from './Members'
import Audit from './Audit'
import Setup from './Setup'

const SECTION_GROUPS = [
  { label: 'Workspace settings', items: [
    { key: 'organization', label: 'Organization', icon: 'organization', hint: 'Identity and workspace details' },
    { key: 'account', label: 'Account', icon: 'members', hint: 'Sign-in and local connection' },
    { key: 'appearance', label: 'Appearance', icon: 'appearance', hint: 'Theme and density' },
    { key: 'delivery', label: 'Delivery', icon: 'notifications', hint: 'Email and notification routes' },
    { key: 'intelligence', label: 'Intelligence', icon: 'vulnerabilities', hint: 'Advisory feeds and the daily re-check' },
    { key: 'keys', label: 'Service identities', icon: 'key', hint: 'API keys for automation' },
  ] },
  { label: 'Administration', items: [
    { key: 'security', label: 'My security', icon: 'grants', hint: 'Multi-factor authentication' },
    { key: 'notifications', label: 'Notifications', icon: 'notifications', hint: 'Alerts and delivery channels' },
    { key: 'grants', label: 'Grants', icon: 'grants', hint: 'Scanner authorization' },
    { key: 'members', label: 'Members', icon: 'members', hint: 'People, roles and invitations' },
    { key: 'audit', label: 'Audit trail', icon: 'audit', hint: 'Recorded security actions' },
    { key: 'setup', label: 'Setup guide', icon: 'setup', hint: 'Finish workspace configuration' },
  ] },
]
const SECTIONS = SECTION_GROUPS.flatMap((group) => group.items)
const ADMIN_SECTIONS = new Set(SECTION_GROUPS[1].items.map((item) => item.key))

export default function Settings({ section = 'organization', org, onOrgChanged, onNavigate, onBack,
  onSessionChanged }) {
  const active = SECTIONS.some((item) => item.key === section) ? section : 'organization'
  const { toasts, push, dismiss } = useToasts()
  const [orgForm, setOrgForm] = useState(() => ({
    name: org?.name || '', description: org?.description || '', website: org?.website || '', logo: org?.logo || '',
  }))
  const [connection, setConnection] = useState(() => api.settings())
  const [login, setLogin] = useState({ email: '', password: '', org_slug: '', new_password: '', confirm_password: '' })
  const [identity, setIdentity] = useState(null)
  const [keys, setKeys] = useState({ rows: [], total: 0, error: '', fresh: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [revokeRow, setRevokeRow] = useState(null)
  const [signOptions, setSignOptions] = useState({ sso: null, mfa: null })
  const [appearance, setAppearance] = useState({ theme: getTheme(), density: getDensity() })
  const keyPage = usePage(keys.rows, 10)

  useEffect(() => {
    setOrgForm({
      name: org?.name || '', description: org?.description || '', website: org?.website || '', logo: org?.logo || '',
    })
  }, [org])

  function loadKeys() {
    api.get('/api/v1/org/keys')
      .then((r) => setKeys((current) => ({ ...current, rows: r.data, total: r.total, error: '' })))
      .catch((e) => setKeys((current) => ({ ...current, error: String(e.message || e) })))
  }

  function loadIdentity() {
    api.get('/api/v1/auth/oidc/status')
      .then((r) => setSignOptions((current) => ({ ...current, sso: r.data })))
      .catch(() => setSignOptions((current) => ({ ...current, sso: null })))
    api.get('/api/v1/auth/mfa')
      .then((r) => setSignOptions((current) => ({ ...current, mfa: r.data })))
      .catch(() => setSignOptions((current) => ({ ...current, mfa: null })))
    api.get('/api/v1/auth/me').then((r) => setIdentity(r.data)).catch(() => setIdentity(null))
  }

  useEffect(() => {
    loadIdentity()
    loadKeys()
  }, [])

  async function saveOrganization(event) {
    event.preventDefault()
    if (orgForm.name.trim().length < 2) {
      push('Organization name must be at least 2 characters.', 'error')
      return
    }
    setBusy(true)
    try {
      const { data } = await api.patch('/api/v1/org', {
        name: orgForm.name.trim(), description: orgForm.description, website: orgForm.website.trim(),
        logo: orgForm.logo.trim(), actor: 'console',
      })
      onOrgChanged?.(data)
      push('Organization details saved.', 'success')
    } catch (e) {
      push(String(e.message || e), 'error')
    } finally {
      setBusy(false)
    }
  }

  function saveConnection(event) {
    event.preventDefault()
    const current = api.settings()
    const cleared = !(connection.key || '').trim()
    api.save({
      url: connection.url.trim(), key: (connection.key || '').trim(),
      token: cleared ? '' : (current.token || ''), refresh_token: cleared ? '' : (current.refresh_token || ''),
      expires_at: cleared ? '' : (current.expires_at || ''),
    })
    setConnection(api.settings())
    onSessionChanged?.()
    push('Connection saved in this browser.', 'success')
  }

  async function signIn(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      const payload = { email: login.email.trim(), password: login.password }
      if (login.org_slug.trim()) payload.org_slug = login.org_slug.trim()
      const response = await api.post('/api/v1/auth/login', payload)
      const next = { url: connection.url.trim(), key: '', token: response.session.token }
      api.save(next)
      setConnection(next)
      setIdentity({ kind: 'user', role: response.session.role,
        user: { email: response.session.email, display_name: response.session.display_name } })
      setLogin({ email: '', password: '', org_slug: '', new_password: '', confirm_password: '' })
      onSessionChanged?.()
      push('Signed in.', 'success')
    } catch (e) {
      setError(String(e.message || e))
      push(String(e.message || e), 'error')
    } finally {
      setBusy(false)
    }
  }

  async function signOut() {
    try { await api.post('/api/v1/auth/logout', {}) } catch { /* session may already be gone */ }
    const next = { url: connection.url.trim(), key: '', token: '', refresh_token: '', expires_at: '' }
    api.save(next)
    setConnection(next)
    setIdentity(null)
    onSessionChanged?.()
    push('Signed out.', 'info')
  }

  async function changePassword(event) {
    event.preventDefault()
    setError('')
    if (login.new_password.length < 8) { setError('Password must be at least 8 characters.'); return }
    if (login.new_password !== login.confirm_password) { setError('New passwords do not match.'); return }
    try {
      await api.post(`/api/v1/auth/users/${identity.user_id}/password`,
        { password: login.new_password, actor: 'console' })
      setLogin((current) => ({ ...current, new_password: '', confirm_password: '' }))
      push('Password changed.', 'success')
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function createKey() {
    try {
      const r = await api.post('/api/v1/org/keys', { label: 'console', actor: 'console' })
      setKeys((current) => ({ ...current, fresh: r.data.key, error: '' }))
      loadKeys()
      push('Service key created.', 'success')
    } catch (e) {
      setKeys((current) => ({ ...current, error: String(e.message || e) }))
      push(String(e.message || e), 'error')
    }
  }

  async function confirmRevoke() {
    if (!revokeRow) return
    try {
      await api.post(`/api/v1/org/keys/${revokeRow.id}/revoke`,
        { actor: 'console', reason: 'revoked from settings' })
      loadKeys()
      push(`Key “${revokeRow.label}” revoked.`, 'success')
    } catch (e) {
      push(String(e.message || e), 'error')
    }
    setRevokeRow(null)
  }

  function applyAppearance(next) {
    setAppearance(next)
    setTheme(next.theme)
    setDensity(next.density)
    push('Appearance updated.', 'success')
  }

  const nav = (key) => onNavigate?.('settings', { settingsSection: key })
  const identityLabel = identity?.kind === 'api_key'
    ? `Service identity · ${identity.org || 'organization'}`
    : identity?.user?.email || 'No user session'

  const body = () => {
    if (active === 'security') return <div className="settings-body"><Security /></div>
    if (active === 'notifications') return <div className="settings-body"><Notifications /></div>
    if (active === 'grants') return <div className="settings-body"><Grants /></div>
    if (active === 'members') return <div className="settings-body"><Members /></div>
    if (active === 'audit') return <div className="settings-body"><Audit /></div>
    if (active === 'setup') return <div className="settings-body"><Setup onNavigate={onNavigate} /></div>
    if (active === 'intelligence') return <AdvisoriesSettings />
    if (active === 'organization') return (
      <div className="settings-body stack">
        <div className="settings-overview">
          <div className="settings-org-mark">
            {orgForm.logo ? <img src={orgForm.logo} alt="" /> : <span>{(orgForm.name || 'O').slice(0, 1)}</span>}
          </div>
          <div>
            <p className="settings-kicker">Current workspace</p>
            <h2>{org?.name || 'Organization'}</h2>
            <p>{org?.slug ? `Slug: ${org.slug}` : 'Workspace identity and ownership.'}</p>
          </div>
        </div>
        <Card title="Organization profile">
          <form className="settings-form" onSubmit={saveOrganization}>
            <label>Name<input value={orgForm.name} onChange={(e) => setOrgForm({ ...orgForm, name: e.target.value })} /></label>
            <label>Website<input value={orgForm.website} onChange={(e) => setOrgForm({ ...orgForm, website: e.target.value })} placeholder="https://example.com" /></label>
            <label className="settings-span">Description<textarea value={orgForm.description} onChange={(e) => setOrgForm({ ...orgForm, description: e.target.value })} placeholder="What does this workspace protect?" /></label>
            <label className="settings-span">Logo URL or image data<input value={orgForm.logo} onChange={(e) => setOrgForm({ ...orgForm, logo: e.target.value })} placeholder="https://… or saved image data" /></label>
            <div className="settings-actions settings-span"><button className="btn-primary" disabled={busy}>Save organization</button></div>
          </form>
        </Card>
        <Card title="Workspace administration">
          <div className="settings-link-list">
            <button onClick={() => onNavigate?.('members')}><span><strong>Members and access</strong><small>Invite people, assign roles and manage seats.</small></span><span>→</span></button>
            <button onClick={() => onNavigate?.('grants')}><span><strong>Authorization grants</strong><small>Review what scanner work is allowed to do.</small></span><span>→</span></button>
            <button onClick={() => onNavigate?.('audit')}><span><strong>Audit trail</strong><small>Review recorded configuration and security actions.</small></span><span>→</span></button>
          </div>
        </Card>
      </div>
    )
    if (active === 'appearance') return (
      <div className="settings-body stack">
        <Card title="Appearance">
          <p className="settings-intro">Choose a contrast mode that stays calm through long investigations. System follows your device automatically.</p>
          <div className="appearance-grid">
            {['light', 'dark', 'system'].map((value) => (
              <button key={value} className={`appearance-choice${appearance.theme === value ? ' active' : ''}`}
                onClick={() => applyAppearance({ ...appearance, theme: value })}>
                <Icon name={value === 'light' ? 'sun' : value === 'dark' ? 'moon' : 'appearance'} />
                <strong>{value}</strong><small>{value === 'system' ? 'Follow device preference' : value === 'dark' ? 'Low-glare dark surface' : 'High-legibility light surface'}</small>
              </button>
            ))}
          </div>
        </Card>
        <Card title="Information density">
          <div className="appearance-grid density-grid">
            {['comfortable', 'compact'].map((value) => (
              <button key={value} className={`appearance-choice${appearance.density === value ? ' active' : ''}`}
                onClick={() => applyAppearance({ ...appearance, density: value })}>
                <Icon name="appearance" /><strong>{value}</strong><small>{value === 'comfortable' ? 'More breathing room for analysis' : 'More rows for operations'}</small>
              </button>
            ))}
          </div>
        </Card>
      </div>
    )
    if (active === 'delivery') return (
      <div className="settings-body stack">
        <Card title="Notifications">
          <p className="settings-intro">Notification preferences and delivery channels have their own operating screen, so alert history remains visible while you configure it.</p>
          <button className="btn-primary" onClick={() => onNavigate?.('notifications')}>Open notifications</button>
        </Card>
        {(identity?.kind === 'api_key' || ['owner', 'admin'].includes(identity?.role)) && <Card title="Deployment email (SMTP)">
          <p className="settings-intro">Invitations and email notification channels leave through this relay. Saving here overrides deployment variables.</p>
          <MailSettings defaultRecipient={identity?.user?.email || ''} />
        </Card>}
      </div>
    )
    if (active === 'keys') return (
      <div className="settings-body stack">
        <Card title="Service identities" actions={<Pager page={keyPage.page} pages={keyPage.pages} onChange={keyPage.setPage} total={keyPage.total} perPage={keyPage.perPage} unit="keys" />}>
          <p className="settings-intro">Use service keys for automation. They are shown only once and revoked rather than deleted.</p>
          {keys.error && <Banner kind="error">{keys.error}</Banner>}
          {keys.fresh && <p className="receipt">New key (shown once): <code>{keys.fresh}</code></p>}
          <Table head={['Label', 'Created', 'Status', '']} empty={<EmptyState title="No service identities" hint="Create one only for a concrete automation need." />}>
            {keyPage.rows.map((row) => <tr key={row.id}><td>{row.label || '—'}</td><td>{row.created_at ? new Date(row.created_at).toLocaleString() : '—'}</td><td><span className={`status st-${row.revoked_at ? 'disabled' : 'active'}`}>{row.revoked_at ? 'revoked' : 'active'}</span></td><td>{!row.revoked_at && <button className="mini" onClick={() => setRevokeRow(row)}>revoke</button>}</td></tr>)}
          </Table>
          <div className="settings-actions"><button className="btn-primary" onClick={createKey}>Create service key</button></div>
        </Card>
      </div>
    )
    return (
      <div className="settings-body stack">
        <Card title="Account and sign-in">
          <div className="account-summary"><span className="identity-dot" /><div><strong>{identityLabel}</strong><small>{identity?.kind === 'user' ? `${identity.role} · ${identity.org}` : 'This browser controls the local console connection.'}</small></div>{identity?.kind === 'user' && <button className="mini" onClick={signOut}>Sign out</button>}</div>
          <div className="settings-link-list">
            <button onClick={() => onNavigate?.('security')}><span><strong>Multi-factor authentication</strong><small>{signOptions.mfa?.enabled ? 'Enabled for this account.' : 'Manage a second factor for your own account.'}</small></span><span>→</span></button>
          </div>
        </Card>
        <Card title="Console connection">
          <form className="settings-form" onSubmit={saveConnection}>
            <label className="settings-span">Platform URL<input value={connection.url || ''} onChange={(e) => setConnection({ ...connection, url: e.target.value })} placeholder="http://127.0.0.1:8090" /></label>
            <label className="settings-span">API key<input value={connection.key || ''} onChange={(e) => setConnection({ ...connection, key: e.target.value })} placeholder="Stored only in this browser" /></label>
            <div className="settings-actions settings-span"><button className="btn-primary">Save connection</button></div>
          </form>
        </Card>
        <Card title="Sign in with an account">
          {error && <Banner kind="error">{error}</Banner>}
          <form className="settings-form" onSubmit={signIn}>
            <label>Email<input value={login.email} autoComplete="username" onChange={(e) => setLogin({ ...login, email: e.target.value })} /></label>
            <label>Password<input type="password" value={login.password} autoComplete="current-password" onChange={(e) => setLogin({ ...login, password: e.target.value })} /></label>
            <label className="settings-span">Organization slug <small>Only when your email is in more than one organization.</small><input value={login.org_slug} onChange={(e) => setLogin({ ...login, org_slug: e.target.value })} /></label>
            <div className="settings-actions settings-span"><button disabled={busy}>Sign in</button></div>
          </form>
          <p className="settings-note">Single sign-on: {signOptions.sso?.configured ? `${signOptions.sso.provider} is configured.` : 'not configured on this deployment.'}</p>
        </Card>
        {identity?.kind === 'user' && <Card title="Change password"><form className="settings-form" onSubmit={changePassword}><label>New password<input type="password" value={login.new_password} onChange={(e) => setLogin({ ...login, new_password: e.target.value })} /></label><label>Confirm password<input type="password" value={login.confirm_password} onChange={(e) => setLogin({ ...login, confirm_password: e.target.value })} /></label><div className="settings-actions settings-span"><button disabled={busy}>Change password</button></div></form></Card>}
      </div>
    )
  }

  return <div className="settings-page">
    {!ADMIN_SECTIONS.has(active) && <PageHeader title="Settings" subtitle="Organization, access and console preferences in one workspace." actions={<button className="btn-ghost" onClick={onBack}>← Back to console</button>} />}
    <div className="settings-layout">
      <nav className="settings-nav" aria-label="Settings sections">
        <button className="settings-back" onClick={onBack}>← Back to console</button>
        {SECTION_GROUPS.map((group) => <div className="settings-nav-group" key={group.label}>
          <div className="settings-nav-label">{group.label}</div>
          {group.items.map((item) => <button key={item.key} className={active === item.key ? 'active' : ''} onClick={() => nav(item.key)}><Icon name={item.icon} /><span><strong>{item.label}</strong><small>{item.hint}</small></span></button>)}
        </div>)}
      </nav>
      {body()}
    </div>
    <ToastContainer toasts={toasts} dismiss={dismiss} />
    <Dialog open={Boolean(revokeRow)} title={`Revoke key “${revokeRow?.label || ''}”?`} destructive confirmLabel="Revoke" onClose={() => setRevokeRow(null)} onConfirm={confirmRevoke}><p className="muted">Clients using this key will stop working immediately. The last active key cannot be revoked.</p></Dialog>
  </div>
}