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
import RuntimeSettings from './RuntimeSettings'
import AiSettings from './AiSettings'
import McpSettings from './McpSettings'
import IntegrationsSettings from './IntegrationsSettings'
import { useI18n, useLanguages } from './i18n'

const SECTION_GROUPS = [
  { label: 'settings.group.workspace', items: [
    { key: 'organization', label: 'settings.section.organization', icon: 'organization', hint: 'settings.section.organization.hint' },
    { key: 'account', label: 'settings.section.account', icon: 'members', hint: 'settings.section.account.hint' },
    { key: 'appearance', label: 'settings.section.appearance', icon: 'appearance', hint: 'settings.section.appearance.hint' },
    // What the platform talks to, in one place: two connections and a
    // mailserver, each naming whether it came from the console or the install.
    { key: 'integrations', label: 'settings.section.integrations', icon: 'components', hint: 'settings.section.integrations.hint' },
    { key: 'delivery', label: 'settings.section.delivery', icon: 'notifications', hint: 'settings.section.delivery.hint' },
    { key: 'intelligence', label: 'settings.section.intelligence', icon: 'vulnerabilities', hint: 'settings.section.intelligence.hint' },
    { key: 'ai', label: 'settings.section.ai', icon: 'analysis', hint: 'settings.section.ai.hint' },
    { key: 'keys', label: 'settings.section.keys', icon: 'key', hint: 'settings.section.keys.hint' },
    // The MCP sheet sits next to the keys it hands out: an external agent needs
    // both, and a section that only prints JSON would send it hunting for the key.
    { key: 'mcp', label: 'settings.section.mcp', icon: 'analysis', hint: 'settings.section.mcp.hint' },
  ] },
  { label: 'settings.group.admin', items: [
    { key: 'security', label: 'settings.section.security', icon: 'grants', hint: 'settings.section.security.hint' },
    { key: 'notifications', label: 'settings.section.notifications', icon: 'notifications', hint: 'settings.section.notifications.hint' },
    { key: 'grants', label: 'settings.section.grants', icon: 'grants', hint: 'settings.section.grants.hint' },
    { key: 'runtime', label: 'settings.section.runtime', icon: 'orchestration', hint: 'settings.section.runtime.hint' },
    { key: 'members', label: 'settings.section.members', icon: 'members', hint: 'settings.section.members.hint' },
    { key: 'audit', label: 'settings.section.audit', icon: 'audit', hint: 'settings.section.audit.hint' },
    { key: 'setup', label: 'settings.section.setup', icon: 'setup', hint: 'settings.section.setup.hint' },
  ] },
]
const SECTIONS = SECTION_GROUPS.flatMap((group) => group.items)
const ADMIN_SECTIONS = new Set(SECTION_GROUPS[1].items.map((item) => item.key))

export default function Settings({ section = 'organization', org, onOrgChanged, onNavigate, onBack,
  onSessionChanged }) {
  const { t, lang, setLang } = useI18n()
  const languages = useLanguages()
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
      push(t('settings.org.errorNameShort'), 'error')
      return
    }
    setBusy(true)
    try {
      const { data } = await api.patch('/api/v1/org', {
        name: orgForm.name.trim(), description: orgForm.description, website: orgForm.website.trim(),
        logo: orgForm.logo.trim(), actor: 'console',
      })
      onOrgChanged?.(data)
      push(t('settings.org.saved'), 'success')
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
    push(t('settings.account.connectionSaved'), 'success')
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
      push(t('settings.account.signedIn'), 'success')
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
    push(t('settings.account.signedOut'), 'info')
  }

  async function changePassword(event) {
    event.preventDefault()
    setError('')
    if (login.new_password.length < 8) { setError(t('settings.account.errorPasswordShort')); return }
    if (login.new_password !== login.confirm_password) { setError(t('settings.account.errorPasswordMismatch')); return }
    try {
      await api.post(`/api/v1/auth/users/${identity.user_id}/password`,
        { password: login.new_password, actor: 'console' })
      setLogin((current) => ({ ...current, new_password: '', confirm_password: '' }))
      push(t('settings.account.passwordChanged'), 'success')
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function createKey() {
    try {
      const r = await api.post('/api/v1/org/keys', { label: 'console', actor: 'console' })
      setKeys((current) => ({ ...current, fresh: r.data.key, error: '' }))
      loadKeys()
      push(t('settings.keys.created'), 'success')
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
      push(t('settings.keys.revoked', { label: revokeRow.label }), 'success')
    } catch (e) {
      push(String(e.message || e), 'error')
    }
    setRevokeRow(null)
  }

  function applyAppearance(next) {
    setAppearance(next)
    setTheme(next.theme)
    setDensity(next.density)
    push(t('settings.appearanceSaved'), 'success')
  }

  const nav = (key) => onNavigate?.('settings', { settingsSection: key })
  const identityLabel = identity?.kind === 'api_key'
    ? t('settings.account.serviceIdentity', { org: identity.org || t('settings.account.organizationFallback') })
    : identity?.user?.email || t('settings.account.noSession')

  const body = () => {
    if (active === 'security') return <div className="settings-body"><Security /></div>
    if (active === 'notifications') return <div className="settings-body"><Notifications /></div>
    if (active === 'grants') return <div className="settings-body"><Grants /></div>
    if (active === 'runtime') return <RuntimeSettings />
    if (active === 'members') return <div className="settings-body"><Members /></div>
    if (active === 'audit') return <div className="settings-body"><Audit /></div>
    if (active === 'setup') return <div className="settings-body"><Setup onNavigate={onNavigate} /></div>
    if (active === 'intelligence') return <AdvisoriesSettings />
    if (active === 'ai') return <AiSettings />
    if (active === 'organization') return (
      <div className="settings-body stack">
        <div className="settings-overview">
          <div className="settings-org-mark">
            {orgForm.logo ? <img src={orgForm.logo} alt="" /> : <span>{(orgForm.name || 'O').slice(0, 1)}</span>}
          </div>
          <div>
            <p className="settings-kicker">{t('settings.org.kicker')}</p>
            <h2>{org?.name || t('settings.org.fallbackName')}</h2>
            <p>{org?.slug ? t('settings.org.slug', { slug: org.slug }) : t('settings.org.noSlug')}</p>
          </div>
        </div>
        <Card title={t('settings.org.profileTitle')}>
          <form className="settings-form" onSubmit={saveOrganization}>
            <label>{t('settings.org.name')}<input value={orgForm.name} onChange={(e) => setOrgForm({ ...orgForm, name: e.target.value })} /></label>
            <label>{t('settings.org.website')}<input value={orgForm.website} onChange={(e) => setOrgForm({ ...orgForm, website: e.target.value })} placeholder="https://example.com" /></label>
            <label className="settings-span">{t('settings.org.description')}<textarea value={orgForm.description} onChange={(e) => setOrgForm({ ...orgForm, description: e.target.value })} placeholder={t('settings.org.descriptionPlaceholder')} /></label>
            <label className="settings-span">{t('settings.org.logo')}<input value={orgForm.logo} onChange={(e) => setOrgForm({ ...orgForm, logo: e.target.value })} placeholder={t('settings.org.logoPlaceholder')} /></label>
            <div className="settings-actions settings-span"><button className="btn-primary" disabled={busy}>{t('settings.org.save')}</button></div>
          </form>
        </Card>
        <Card title={t('settings.org.adminTitle')}>
          <div className="settings-link-list">
            <button onClick={() => onNavigate?.('members')}><span><strong>{t('settings.org.membersTitle')}</strong><small>{t('settings.org.membersHint')}</small></span><span>→</span></button>
            <button onClick={() => onNavigate?.('grants')}><span><strong>{t('settings.org.grantsTitle')}</strong><small>{t('settings.org.grantsHint')}</small></span><span>→</span></button>
            <button onClick={() => onNavigate?.('audit')}><span><strong>{t('settings.org.auditTitle')}</strong><small>{t('settings.org.auditHint')}</small></span><span>→</span></button>
          </div>
        </Card>
      </div>
    )
    if (active === 'appearance') return (
      <div className="settings-body stack">
        <Card title={t('appearance.title')}>
          <p className="settings-intro">{t('appearance.intro')}</p>
          <div className="appearance-grid">
            {['light', 'dark', 'system'].map((value) => (
              <button key={value} className={`appearance-choice${appearance.theme === value ? ' active' : ''}`}
                onClick={() => applyAppearance({ ...appearance, theme: value })}>
                <Icon name={value === 'light' ? 'sun' : value === 'dark' ? 'moon' : 'appearance'} />
                <strong>{t(`appearance.${value}`)}</strong>
                <small>{t(`appearance.${value}Hint`)}</small>
              </button>
            ))}
          </div>
        </Card>
        <Card title={t('appearance.densityTitle')}>
          <div className="appearance-grid density-grid">
            {['comfortable', 'compact'].map((value) => (
              <button key={value} className={`appearance-choice${appearance.density === value ? ' active' : ''}`}
                onClick={() => applyAppearance({ ...appearance, density: value })}>
                <Icon name="appearance" /><strong>{t(`appearance.${value}`)}</strong>
                <small>{t(`appearance.${value}Hint`)}</small>
              </button>
            ))}
          </div>
        </Card>
        <Card title={t('language.title')}>
          <p className="settings-intro">{t('language.intro')}</p>
          <div className="lang-grid" role="radiogroup" aria-label={t('language.title')}>
            {languages.map((entry) => (
              <button key={entry.code} type="button" role="radio"
                aria-checked={lang === entry.code}
                className={`lang-choice${lang === entry.code ? ' active' : ''}`}
                onClick={() => setLang(entry.code)}>
                <span>
                  <strong>{entry.name}</strong>
                  <small>{entry.code.toUpperCase()}</small>
                </span>
                {lang === entry.code && <em>{t('language.current')}</em>}
              </button>
            ))}
          </div>
          <p className="settings-note">{t('language.addHint')}</p>
        </Card>
      </div>
    )
    if (active === 'integrations') return (
      <div className="settings-body">
        <IntegrationsSettings onOpenSection={nav} onNavigate={onNavigate} />
      </div>
    )
    if (active === 'delivery') return (
      <div className="settings-body stack">
        <Card title={t('settings.delivery.notificationsTitle')}>
          <p className="settings-intro">{t('settings.delivery.notificationsIntro')}</p>
          <button className="btn-primary" onClick={() => onNavigate?.('notifications')}>{t('settings.delivery.openNotifications')}</button>
        </Card>
        {(identity?.kind === 'api_key' || ['owner', 'admin'].includes(identity?.role)) && <Card title={t('settings.delivery.mailTitle')}>
          <p className="settings-intro">{t('settings.delivery.mailIntro')}</p>
          <MailSettings defaultRecipient={identity?.user?.email || ''} />
        </Card>}
      </div>
    )
    if (active === 'mcp') return (
      <div className="settings-body">
        <McpSettings onOpenSection={nav} />
      </div>
    )
    if (active === 'keys') return (
      <div className="settings-body stack">
        <Card title={t('settings.keys.title')} actions={<Pager page={keyPage.page} pages={keyPage.pages} onChange={keyPage.setPage} total={keyPage.total} perPage={keyPage.perPage} unit="keys" />}>
          <p className="settings-intro">{t('settings.keys.intro')}</p>
          {keys.error && <Banner kind="error">{keys.error}</Banner>}
          {keys.fresh && <p className="receipt">{t('settings.keys.fresh')} <code>{keys.fresh}</code></p>}
          <Table head={[t('settings.keys.colLabel'), t('settings.keys.colCreated'), t('settings.keys.colStatus'), '']} empty={<EmptyState title={t('settings.keys.emptyTitle')} hint={t('settings.keys.emptyHint')} />}>
            {keyPage.rows.map((row) => <tr key={row.id}><td>{row.label || '—'}</td><td>{row.created_at ? new Date(row.created_at).toLocaleString() : '—'}</td><td><span className={`status st-${row.revoked_at ? 'disabled' : 'active'}`}>{row.revoked_at ? t('settings.keys.stateRevoked') : t('settings.keys.stateActive')}</span></td><td>{!row.revoked_at && <button className="mini" onClick={() => setRevokeRow(row)}>{t('settings.keys.revoke')}</button>}</td></tr>)}
          </Table>
          <div className="settings-actions"><button className="btn-primary" onClick={createKey}>{t('settings.keys.create')}</button></div>
        </Card>
      </div>
    )
    return (
      <div className="settings-body stack">
        <Card title={t('settings.account.title')}>
          {/* The identity is described here and ended here. It used to carry the
              button only for a user session: a console running on an API key had no
              way to disconnect from anywhere in the product. */}
          <div className="account-summary">
            <span className="identity-dot" />
            <div>
              <strong>{identityLabel}</strong>
              <small>{identity?.kind === 'user'
                ? `${identity.role} · ${identity.org}`
                : t('settings.account.localConnection')}</small>
            </div>
            {identity && (
              <button className="mini" onClick={signOut}>
                {identity.kind === 'user'
                  ? t('settings.account.signOut')
                  : t('settings.account.disconnect')}
              </button>
            )}
          </div>
          <div className="settings-link-list">
            <button onClick={() => onNavigate?.('security')}><span><strong>{t('settings.account.mfaTitle')}</strong><small>{signOptions.mfa?.enabled ? t('settings.account.mfaEnabled') : t('settings.account.mfaHint')}</small></span><span>→</span></button>
          </div>
        </Card>
        <Card title={t('settings.account.connectionTitle')}>
          <form className="settings-form" onSubmit={saveConnection}>
            <label className="settings-span">{t('settings.account.url')}<input value={connection.url || ''} onChange={(e) => setConnection({ ...connection, url: e.target.value })} placeholder="http://127.0.0.1:8090" /></label>
            <label className="settings-span">{t('settings.account.apiKey')}<input value={connection.key || ''} onChange={(e) => setConnection({ ...connection, key: e.target.value })} placeholder={t('settings.account.apiKeyPlaceholder')} /></label>
            <div className="settings-actions settings-span"><button className="btn-primary">{t('settings.account.saveConnection')}</button></div>
          </form>
        </Card>
        <Card title={t('settings.account.signInTitle')}>
          {error && <Banner kind="error">{error}</Banner>}
          <form className="settings-form" onSubmit={signIn}>
            <label>{t('settings.account.email')}<input value={login.email} autoComplete="username" onChange={(e) => setLogin({ ...login, email: e.target.value })} /></label>
            <label>{t('settings.account.password')}<input type="password" value={login.password} autoComplete="current-password" onChange={(e) => setLogin({ ...login, password: e.target.value })} /></label>
            <label className="settings-span">{t('settings.account.orgSlug')} <small>{t('settings.account.orgSlugHint')}</small><input value={login.org_slug} onChange={(e) => setLogin({ ...login, org_slug: e.target.value })} /></label>
            <div className="settings-actions settings-span"><button disabled={busy}>{t('settings.account.signIn')}</button></div>
          </form>
          <p className="settings-note">{t('settings.account.sso', { state: signOptions.sso?.configured
            ? t('settings.account.ssoConfigured', { provider: signOptions.sso.provider })
            : t('settings.account.ssoNotConfigured') })}</p>
        </Card>
        {identity?.kind === 'user' && <Card title={t('settings.account.changePasswordTitle')}><form className="settings-form" onSubmit={changePassword}><label>{t('settings.account.newPassword')}<input type="password" value={login.new_password} onChange={(e) => setLogin({ ...login, new_password: e.target.value })} /></label><label>{t('settings.account.confirmPassword')}<input type="password" value={login.confirm_password} onChange={(e) => setLogin({ ...login, confirm_password: e.target.value })} /></label><div className="settings-actions settings-span"><button disabled={busy}>{t('settings.account.changePassword')}</button></div></form></Card>}
      </div>
    )
  }

  return <div className="settings-page">
    {!ADMIN_SECTIONS.has(active) && <PageHeader title={t('settings.title')} subtitle={t('settings.subtitle')} actions={<button className="btn-ghost" onClick={onBack}>{t('settings.backToConsole')}</button>} />}
    <div className="settings-layout">
      <nav className="settings-nav" aria-label={t('settings.navAria')}>
        <button className="settings-back" onClick={onBack}>{t('settings.backToConsole')}</button>
        {SECTION_GROUPS.map((group) => <div className="settings-nav-group" key={group.label}>
          <div className="settings-nav-label">{t(group.label)}</div>
          {group.items.map((item) => <button key={item.key} className={active === item.key ? 'active' : ''} onClick={() => nav(item.key)}><Icon name={item.icon} /><span><strong>{t(item.label)}</strong><small>{t(item.hint)}</small></span></button>)}
        </div>)}
      </nav>
      {body()}
    </div>
    <ToastContainer toasts={toasts} dismiss={dismiss} />
    <Dialog open={Boolean(revokeRow)} title={t('settings.keys.revokeTitle', { label: revokeRow?.label || '' })} destructive confirmLabel={t('settings.keys.revokeConfirm')} onClose={() => setRevokeRow(null)} onConfirm={confirmRevoke}><p className="muted">{t('settings.keys.revokeBody')}</p></Dialog>
  </div>
}
