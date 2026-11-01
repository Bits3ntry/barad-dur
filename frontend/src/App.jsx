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
import CtemCycle from './CtemCycle'
import { api } from './api'
import Login, { BrandMark } from './Login'
import { Modal } from './ui'

/* Navigation follows the CTEM loop: the five phases are the spine, and the
   screens that feed them sit underneath. Groups collapse, because 20 flat rows
   pushed everything below the fold — the sidebar is a map, not a list. */
const NAV = [
  { group: '', collapsible: false, items: [
    { key: 'dashboard', label: 'Dashboard' },
  ] },
  { group: 'CTEM cycle', collapsible: true, defaultOpen: true, items: [
    { key: 'ctem', label: 'Cycle overview' },
    { key: 'scoping', label: 'Scoping' },
    { key: 'discovery', label: 'Discovery' },
    { key: 'prioritization', label: 'Prioritization' },
    { key: 'validation', label: 'Validation' },
    { key: 'mobilization', label: 'Mobilization', badge: 'sla' },
  ] },
  { group: 'Work', collapsible: true, defaultOpen: true, items: [
    { key: 'findings', label: 'Findings', badge: 'critical' },
    { key: 'projects', label: 'Projects' },
    { key: 'assets', label: 'Attack surface' },
    { key: 'components', label: 'Components' },
  ] },
  { group: 'Delivery', collapsible: true, items: [
    { key: 'pipelines', label: 'Pipelines' },
    { key: 'gates', label: 'Quality gates' },
    { key: 'code', label: 'Pull requests' },
    { key: 'pentest', label: 'Pentests' },
    { key: 'regression', label: 'Regression' },
  ] },
  { group: 'Supply chain', collapsible: true, items: [
    { key: 'licenses', label: 'Licenses' },
    { key: 'orchestration', label: 'Orchestration' },
    { key: 'jira', label: 'Jira' },
    { key: 'remediation', label: 'Remediation' },
  ] },
  { group: 'Administration', collapsible: true, items: [
    { key: 'notifications', label: 'Notifications' },
    { key: 'grants', label: 'Grants' },
    { key: 'members', label: 'Members' },
    { key: 'audit', label: 'Audit trail' },
    { key: 'setup', label: 'Setup guide' },
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
  const [org, setOrg] = useState(null)
  const [badges, setBadges] = useState({})

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

  function loadProjects() {
    setProjectsError('')
    return api.get('/api/v1/projects')
      .then((data) => setProjects(data.data || []))
      .catch((error) => setProjectsError(String(error.message || error)))
  }

  useEffect(() => {
    if (needsKey) return
    loadProjects()
    api.get('/api/v1/org').then((r) => setOrg(r.data)).catch(() => setOrg(null))
    // Badges are the one number worth carrying into the sidebar: what is
    // critical and what is past its SLA.
    api.get('/api/v1/dashboard/summary')
      .then((r) => {
        const finding = r.data.findings || {}
        setBadges({
          critical: (finding.by_severity_open || {}).CRITICAL || 0,
          sla: finding.sla_breached || 0,
        })
      })
      .catch(() => setBadges({}))
  }, [needsKey, settingsOpen])

  // Collapsed nav groups, remembered across reloads.
  const [closedGroups, setClosedGroups] = useState(() => {
    try {
      const stored = localStorage.getItem('barad.nav.closed')
      if (stored) return new Set(JSON.parse(stored))
    } catch { /* first run */ }
    return new Set(NAV.filter((entry) => entry.collapsible && !entry.defaultOpen)
      .map((entry) => entry.group))
  })

  function toggleGroup(group) {
    const next = new Set(closedGroups)
    if (next.has(group)) next.delete(group); else next.add(group)
    setClosedGroups(next)
    localStorage.setItem('barad.nav.closed', JSON.stringify([...next]))
  }

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
      case 'ctem': return <CtemCycle onNavigate={go} />
      case 'scoping':
      case 'discovery':
      case 'prioritization':
      case 'validation':
      case 'mobilization':
        return <CtemCycle focus={tab} onNavigate={go} />
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
      case 'components': return <Components projects={projects} onChanged={loadProjects} />
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
            <span className="brand-name">{org ? org.name : 'BARAD-DÛR'}</span>
            <span className="brand-sub">continuous exposure</span>
          </span>
        </div>
        {NAV.map((entry) => {
          const closed = entry.collapsible && closedGroups.has(entry.group)
          return (
            <div className="nav-group" key={entry.group || 'primary'}>
              {entry.group && (entry.collapsible ? (
                <button className="nav-group-title collapsible"
                  aria-expanded={!closed}
                  onClick={() => toggleGroup(entry.group)}>
                  <span>{entry.group}</span>
                  <span className={`nav-chevron${closed ? '' : ' open'}`}
                    aria-hidden="true" />
                </button>
              ) : (
                <div className="nav-group-title">{entry.group}</div>
              ))}
              {!closed && entry.items.map((item) => {
                const count = item.badge ? badges[item.badge] : 0
                return (
                  <button
                    key={item.key}
                    className={`nav-item${entry.group === 'CTEM cycle' && item.key !== 'ctem' ? ' nested' : ''}`
                      + `${tab === item.key ? ' active' : ''}`}
                    aria-current={tab === item.key ? 'page' : undefined}
                    onClick={() => go(item.key)}
                  >
                    <span>{item.label}</span>
                    {count > 0 && (
                      <span className={`badge-count${item.badge === 'critical' ? ' bad' : ''}`}>
                        {count}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          )
        })}
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
