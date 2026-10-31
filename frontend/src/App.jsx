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
import CodeReview from './CodeReview'
import Jira from './Jira'
import Orchestration from './Orchestration'
import Pentest from './Pentest'
import Regression from './Regression'
import Pipelines from './Pipelines'
import Settings from './Settings'
import { api } from './api'
import { Modal } from './ui'

/* Navigation is grouped by what a person is trying to do, not by module name:
   16 flat tabs were unreadable and overflowed on a laptop screen. */
const NAV = [
  { group: 'Overview', items: [
    { key: 'dashboard', label: 'Dashboard' },
    { key: 'findings', label: 'Findings' },
    { key: 'assets', label: 'Assets' },
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

  useEffect(() => {
    if (needsKey) setSettingsOpen(true)
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

  const screen = () => {
    switch (tab) {
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
      default: return <Dashboard projects={projects} onNavigate={go} />
    }
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-name">BARAD-DÛR</span>
          <span className="brand-sub">security management</span>
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
              {session.role || (session.key ? 'api key' : session.token ? 'session' : 'no auth')}
            </span>
            <button className="btn-ghost mini" onClick={() => setSettingsOpen(true)}>
              settings
            </button>
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
