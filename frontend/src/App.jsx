import React, { useEffect, useMemo, useState } from 'react'
import Audit from './Audit'
import Dashboard from './Dashboard'
import Gates from './Gates'
import Grants from './Grants'
import Licenses from './Licenses'
import Lifecycle from './Lifecycle'
import Members from './Members'
import Assets from './Assets'
import Components from './Components'
import Findings from './Findings'
import Notifications from './Notifications.jsx'
import CodeReview from './CodeReview'
import Jira from './Jira'
import Orchestration from './Orchestration'
import Pentest from './Pentest'
import Regression from './Regression'
import Pipelines from './Pipelines'
import Settings from './Settings'
import Setup from './Setup'
import Projects from './Projects'
import { api } from './api'
import Login, { BrandMark } from './Login'
import { Modal } from './ui'

/* Navigation is grouped by what a person is trying to do, not by module name:
   16 flat tabs were unreadable and overflowed on a laptop screen. */
const NAV = [
  { group: 'Overview', items: [
    { key: 'setup', label: 'Setup guide' },
    { key: 'dashboard', label: 'Dashboard' },
    { key: 'projects', label: 'Projects' },
    { key: 'findings', label: 'Findings' },
    { key: 'assets', label: 'Attack surface' },
    { key: 'notifications', label: 'Notifications' },
  ] },
  { group: 'Supply chain', items: [
    { key: 'components', label: 'Components' },
    { key: 'licenses', label: 'Licenses' },
  ] },
  { group: 'Code', items: [
    { key: 'code', label: 'Pull requests' },
    { key: 'pipelines', label: 'Pipelines' },
    { key: 'gates', label: 'Quality gates' },
  ] },
  { group: 'Testing', items: [
    { key: 'pentest', label: 'Pentests' },
    { key: 'regression', label: 'Regression' },
  ] },
  { group: 'Operations', items: [
    { key: 'orchestration', label: 'Orchestration' },
    { key: 'jira', label: 'Jira' },
    { key: 'remediation', label: 'Remediation' },
  ] },
  { group: 'Administration', items: [
    { key: 'grants', label: 'Grants' },
    { key: 'audit', label: 'Audit trail' },
    { key: 'members', label: 'Members' },
  ] },
]

const ALL_KEYS = NAV.flatMap((entry) => entry.items.map((item) => item.key))

function tabFromHash() {
  const requested = (window.location.hash || '').replace('#', '')
  return ALL_KEYS.includes(requested) ? requested : 'dashboard'
}

export default function App() {
  const [tab, setTab] = useState(tabFromHash)
  const [projects, setProjects] = useState([])
  const [projectsError, setProjectsError] = useState('')
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [session, setSession] = useState(() => api.settings())

  const needsKey = !session.key && !session.token
  const [providerUrl, setProviderUrl] = useState(session.url || '')

  useEffect(() => {
    if (needsKey) return
    setProviderUrl(api.settings().url || '')
  }, [needsKey])

  useEffect(() => {
    const onHash = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    if (needsKey) return
    setProjectsError('')
    api.get('/api/v1/projects')
      .then((data) => setProjects(data.data || []))
      .catch((error) => setProjectsError(String(error.message || error)))
  }, [needsKey, settingsOpen])

  const go = (key) => {
    setTab(key)
    window.location.hash = key
  }

  const title = useMemo(() => {
    for (const entry of NAV) {
      const found = entry.items.find((item) => item.key === tab)
      if (found) return found.label
    }
    return 'Dashboard'
  }, [tab])

  if (needsKey) {
    return <Login onAuthenticated={() => {
      setSession(api.settings())
      setSettingsOpen(false)
    }} />
  }

  const screen = () => {
    switch (tab) {
      case 'setup': return <Setup onNavigate={go} />
      case 'projects': return <Projects onNavigate={go} />
      case 'findings': return <Findings projects={projects} />
      case 'code': return <CodeReview projects={projects} />
      case 'gates': return <Gates projects={projects} />
      case 'licenses': return <Licenses projects={projects} />
      case 'pentest': return <Pentest projects={projects} />
      case 'jira': return <Jira />
      case 'regression': return <Regression />
      case 'orchestration': return <Orchestration />
      case 'grants': return <Grants />
      case 'audit': return <Audit />
      case 'remediation': return <Lifecycle />
      case 'members': return <Members />
      case 'assets': return <Assets />
      case 'components': return <Components projects={projects} />
      case 'pipelines': return <Pipelines />
      case 'notifications': return <Notifications />
      default: return <Dashboard projects={projects} onNavigate={go} />
    }
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark size={26} />
          <span className="brand-text">
            <span className="brand-name">BARAD-DÛR</span>
            <span className="brand-sub">security management</span>
          </span>
        </div>
        {NAV.map((entry) => (
          <div className="nav-group" key={entry.group}>
            <div className="nav-group-title">{entry.group}</div>
            {entry.items.map((item) => (
              <button
                key={item.key}
                className={`nav-item ${tab === item.key ? 'active' : ''}`}
                aria-current={tab === item.key ? 'page' : undefined}
                onClick={() => go(item.key)}
              >
                <span>{item.label}</span>
              </button>
            ))}
          </div>
        ))}
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <div className="crumbs">barad-dûr / {title.toLowerCase()}</div>
          </div>
          <div className="topbar-actions">
            <span className="pill">
              {session.token ? 'signed in' : 'api key'}
              {providerUrl ? ` · ${providerUrl.replace(/^https?:\/\//, '')}` : ''}
            </span>
            <button className="btn-ghost mini" onClick={() => setSettingsOpen(true)}>
              settings
            </button>
            <button className="btn-ghost mini" onClick={async () => {
              if (session.token) { try { await api.post('/api/v1/auth/logout', {}) } catch { /* session may be gone */ } }
              api.save({ url: api.settings().url || '', key: '', token: '' })
              setSession(api.settings())
            }}>sign out</button>
          </div>
        </header>

        <main className="content">
          {projectsError && (
            <div className="banner banner-error" role="alert">
              <span>{projectsError}</span>
              <span className="row-end">
                <button className="mini" onClick={() => setSettingsOpen(true)}>settings</button>
              </span>
            </div>
          )}
          {screen()}
        </main>
      </div>

      {settingsOpen && (
        <Modal title="Connection and identity" onClose={() => {
          setSettingsOpen(false)
          setSession(api.settings())
        }}>
          <Settings onClose={() => {
            setSettingsOpen(false)
            setSession(api.settings())
          }} />
        </Modal>
      )}
    </div>
  )
}
