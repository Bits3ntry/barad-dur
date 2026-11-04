import React, { useEffect, useMemo, useRef, useState } from 'react'
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
import Startup from './Startup'
import Invite from './Invite'
import Projects from './Projects'
import Sbom from './Sbom'
import CtemCycle from './CtemCycle'
import Scope from './Scope'
import Vulnerabilities from './Vulnerabilities'
import Analysis from './Analysis'
import Exposures from './Exposures'
import AttackSurface from './AttackSurface'
import Cycles from './Cycles'
import BusinessImpact from './BusinessImpact'
import Security from './Security'
import Icon from './icons'
import MyWork from './MyWork'
import { api } from './api'
import Login, { BrandMark } from './Login'
import { Modal } from './ui'

/* Navigation follows the CTEM loop: the five phases are the spine, and the
   screens that feed them sit underneath. Groups collapse, because 20 flat rows
   pushed everything below the fold — the sidebar is a map, not a list. */
const NAV = [
  // The four things an operator reads every day, with no group label: a label
  // over a first row is furniture, not information.
  { group: '', collapsible: false, items: [
    { key: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
    { key: 'my-work', label: 'My work', icon: 'my-work' },
    { key: 'findings', label: 'Findings', icon: 'findings', badge: 'critical' },
    { key: 'vulnerabilities', label: 'Vulnerabilities', icon: 'vulnerabilities' },
  ] },
  // The cycle is one frame with three working areas inside it. Each area owns
  // the screens that feed it; nothing is duplicated across groups.
  { group: 'CTEM cycle', collapsible: true, defaultOpen: true, items: [
    { key: 'ctem', label: 'Cycle overview', icon: 'cycle' },
  ], sections: [
    { label: 'Scoping', items: [
      { key: 'cycles', label: 'Cycles', icon: 'cycles' },
      { key: 'scope', label: 'Scope', icon: 'scope' },
    ] },
    { label: 'Inventory', items: [
      { key: 'projects', label: 'Projects', icon: 'applications' },
      { key: 'assets', label: 'Assets', icon: 'assets' },
      { key: 'attack-surface', label: 'Attack surface', icon: 'attack-surface' },
      { key: 'components', label: 'Components', icon: 'components' },
      { key: 'exposures', label: 'Exposures', icon: 'exposures' },
    ] },
    { label: 'Prioritization', items: [
      { key: 'priority-rules', label: 'Prioritization rules', icon: 'prioritization' },
      { key: 'business-impact', label: 'Business impact', icon: 'business-impact' },
    ] },
  ] },
  { group: 'Code security', collapsible: true, defaultOpen: true, items: [
    { key: 'analysis', label: 'Code analysis', icon: 'analysis' },
    { key: 'code', label: 'Pull requests', icon: 'code' },
  ] },
  { group: 'Delivery', collapsible: true, items: [
    { key: 'pipelines', label: 'Pipelines', icon: 'pipelines' },
    { key: 'gates', label: 'Quality gates', icon: 'gates' },
    { key: 'pentest', label: 'Pentests', icon: 'pentest' },
    { key: 'regression', label: 'Regression', icon: 'regression' },
  ] },
  { group: 'Supply chain', collapsible: true, items: [
    { key: 'sbom', label: 'SBOMs', icon: 'components' },
    { key: 'licenses', label: 'Licenses', icon: 'licenses' },
    { key: 'orchestration', label: 'Orchestration', icon: 'orchestration' },
    { key: 'jira', label: 'Jira', icon: 'jira' },
    { key: 'remediation', label: 'Remediation', icon: 'remediation' },
  ] },
  { group: 'Administration', collapsible: true, items: [
    { key: 'security', label: 'My security', icon: 'grants' },
    { key: 'notifications', label: 'Notifications', icon: 'notifications' },
    { key: 'grants', label: 'Grants', icon: 'grants' },
    { key: 'members', label: 'Members', icon: 'members' },
    { key: 'audit', label: 'Audit trail', icon: 'audit' },
    { key: 'setup', label: 'Setup guide', icon: 'setup' },
  ] },
]

/* Keys that used to live in the sidebar. They keep resolving so an old link or
   a bookmark lands on the screen that replaced it instead of the dashboard. */
const LEGACY_KEYS = {
  scoping: 'ctem',
  discovery: 'ctem',
  prioritization: 'ctem',
  validation: 'ctem',
  mobilization: 'ctem',
}

const NAV_ITEMS = NAV.flatMap((entry) => [
  ...entry.items,
  ...((entry.sections || []).flatMap((section) => section.items)),
])
const ALL_KEYS = [...NAV_ITEMS.map((item) => item.key), ...Object.keys(LEGACY_KEYS)]

/* The hash carries an optional focus so one screen can hand a record to
   another: #findings::<finding id> and #analysis::run=<run>&path=…&line=… */
function parseHash() {
  const raw = (window.location.hash || '').replace('#', '')
  const [key, ...rest] = raw.split('::')
  const tail = rest.join('::')
  const tab = LEGACY_KEYS[key] || (ALL_KEYS.includes(key) ? key : 'dashboard')
  const focus = {}
  if (tab === 'sbom' && tail) {
    const [projectSlug, ...rest] = tail.split('/')
    focus.projectSlug = projectSlug
    focus.version = decodeURIComponent(rest.join('/'))
  }
  if (tab === 'findings' && tail) focus.findingId = tail
  if (tab === 'analysis' && tail) {
    const params = new URLSearchParams(tail)
    focus.runId = params.get('run') || undefined
    focus.path = params.get('path') || undefined
    focus.line = params.get('line') ? Number(params.get('line')) : undefined
  }
  return { tab, focus }
}

/* Projects has real URLs — /projects and /projects/{slug}[/{tab}] — so a
   reload, a pasted link and the back button all land on the same record.
   Every other screen still rides the hash; the two coexist because only one
   of them is in the address bar at a time. */
const PROJECT_PATH = /^\/projects(?:\/([^/]+))?(?:\/([a-z-]+))?\/?$/

function parseProjectPath() {
  // A hash names another screen; a stale /projects path behind it must not win.
  if (window.location.hash) return null
  const match = window.location.pathname.match(PROJECT_PATH)
  if (!match) return null
  return {
    slug: match[1] ? decodeURIComponent(match[1]) : '',
    tab: match[2] || 'summary',
  }
}

export default function App() {
  const [projectRoute, setProjectRoute] = useState(() => parseProjectPath())
  const [tab, setTab] = useState(() => (parseProjectPath() ? 'projects' : parseHash().tab))
  const [focus, setFocus] = useState(() => parseHash().focus)
  const [projects, setProjects] = useState([])
  const [projectsError, setProjectsError] = useState('')
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [session, setSession] = useState(() => api.settings())
  const [org, setOrg] = useState(null)
  const [badges, setBadges] = useState({})
  const [query, setQuery] = useState('')
  const searchRef = useRef(null)

  // ⌘K / Ctrl+K jumps to the search box; the box is the keyboard path to every
  // screen, which is cheaper than memorising the tree.
  useEffect(() => {
    const onKey = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        searchRef.current?.focus()
        searchRef.current?.select()
      }
      if (event.key === 'Escape') {
        setQuery('')
        searchRef.current?.blur()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const needsKey = !session.key && !session.token
  const [providerUrl, setProviderUrl] = useState(session.url || '')

  useEffect(() => {
    if (needsKey) return
    setProviderUrl(api.settings().url || '')
  }, [needsKey])

  useEffect(() => {
    const onHash = () => {
      // The hash names a screen only when the path does not name a project.
      const project = window.location.hash ? null : parseProjectPath()
      if (project) { setProjectRoute(project); setTab('projects'); setFocus({}); return }
      const next = parseHash()
      setProjectRoute(null)
      setTab(next.tab)
      setFocus(next.focus)
    }
    const onPop = () => onHash()
    window.addEventListener('hashchange', onHash)
    window.addEventListener('popstate', onPop)
    return () => {
      window.removeEventListener('hashchange', onHash)
      window.removeEventListener('popstate', onPop)
    }
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
    setFocus({})
    if (key === 'projects') {
      window.history.pushState({}, '', '/projects')
      setProjectRoute({ slug: '', tab: 'summary' })
      if (window.location.hash) window.history.replaceState({}, '', '/projects')
      return
    }
    setProjectRoute(null)
    // pushState, not location.hash: assigning the hash keeps the current path,
    // which is how /projects/aurea/components#grants ended up as a dead link.
    window.history.pushState({}, '', `/#${key}`)
  }

  function openBom(slug, version) {
    setTab('sbom')
    setFocus({ projectSlug: slug, version })
    window.history.pushState({}, '', `/#sbom::${slug}/${encodeURIComponent(version)}`)
  }

  function openProject(slug, nextTab = 'summary') {
    if (!slug) return
    const suffix = nextTab && nextTab !== 'summary' ? `/${nextTab}` : ''
    window.history.pushState({}, '', `/projects/${encodeURIComponent(slug)}${suffix}`)
    setProjectRoute({ slug, tab: nextTab || 'summary' })
    setTab('projects')
  }

  function switchProjectTab(nextTab) {
    if (!projectRoute?.slug) return
    const suffix = nextTab && nextTab !== 'summary' ? `/${nextTab}` : ''
    window.history.pushState({}, '',
      `/projects/${encodeURIComponent(projectRoute.slug)}${suffix}`)
    setProjectRoute({ slug: projectRoute.slug, tab: nextTab || 'summary' })
  }

  function closeProject() {
    window.history.pushState({}, '', '/projects')
    setProjectRoute({ slug: '', tab: 'summary' })
  }

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return []
    return NAV_ITEMS.filter((item) => item.label.toLowerCase().includes(needle)).slice(0, 8)
  }, [query])

  const title = useMemo(() => {
    const found = NAV_ITEMS.find((item) => item.key === tab)
    return found ? found.label : 'Dashboard'
  }, [tab])

  // An invitation is opened by someone with no credential yet: it must render
  // before the sign-in gate, never behind it.
  if (window.location.pathname === '/invite') {
    return <Invite />
  }

  if (needsKey) {
    return <Login onAuthenticated={(context = {}) => {
      setSession(api.settings())
      setSettingsOpen(false)
      // The first bootstrap lands on /startup, which owns the rest of the
      // walk-through. Sending it to the Setup guide here would overwrite the
      // step hash and drop the owner into the wrong screen.
      if (context.firstSetup && window.location.pathname !== '/startup') go('setup')
    }} />
  }

  if (window.location.pathname === '/startup') {
    return <Startup onFinish={() => go('dashboard')} />
  }

  const screen = () => {
    switch (tab) {
      case 'setup': return <Setup onNavigate={go} />
      case 'ctem': return <CtemCycle onNavigate={go} />
      case 'priority-rules': return <Lifecycle initialTab="rules" />
      case 'business-impact': return <BusinessImpact onNavigate={go} />
      case 'projects': return (
        <Projects
          slug={projectRoute?.slug || ''}
          tab={projectRoute?.tab || 'summary'}
          onNavigate={go}
          onOpenProject={openProject}
          onProjectTab={switchProjectTab}
          onCloseProject={closeProject} />
      )
      case 'findings': return (
        <Findings projects={projects} focusId={focus.findingId}
          onOpenAnalysis={(target) => {
            const params = new URLSearchParams({ run: target.runId })
            if (target.path) params.set('path', target.path)
            if (target.line) params.set('line', String(target.line))
            window.location.hash = `analysis::${params.toString()}`
          }} />
      )
      case 'code': return <CodeReview projects={projects} />
      case 'gates': return <Gates projects={projects} />
      case 'sbom': return (
        <Sbom focus={focus} onOpen={openBom} onBack={() => go('sbom')} />
      )
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
      case 'scope': return <Scope />
      case 'vulnerabilities': return <Vulnerabilities onNavigate={go} />
      case 'analysis': return (
        <Analysis projects={projects} focusRun={focus}
          onOpenFinding={(findingId) => { window.location.hash = `findings::${findingId}` }} />
      )
      case 'exposures': return <Exposures />
      case 'attack-surface': return <AttackSurface />
      case 'cycles': return <Cycles />
      case 'my-work': return <MyWork />
      case 'components': return <Components projects={projects} onChanged={loadProjects} />
      case 'pipelines': return <Pipelines />
      case 'security': return <Security />
      case 'notifications': return <Notifications />
      default: return <Dashboard projects={projects} onNavigate={go} />
    }
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          {org && org.logo
            ? <img className="brand-logo" src={org.logo} alt="" />
            : <BrandMark size={26} />}
          <span className="brand-text">
            <span className="brand-name">{org ? org.name : 'BARAD-DÛR'}</span>
            <span className="brand-sub">continuous exposure</span>
          </span>
        </div>
        {(() => {
          const renderNavItem = (item) => {
            const count = item.badge ? badges[item.badge] : 0
            return (
              <button
                key={item.key}
                className={`nav-item${tab === item.key ? ' active' : ''}`}
                aria-current={tab === item.key ? 'page' : undefined}
                onClick={() => go(item.key)}
              >
                <span className="nav-item-label">
                  <Icon name={item.icon} />
                  <span>{item.label}</span>
                </span>
                {count > 0 && (
                  <span className={`badge-count${item.badge === 'critical' ? ' bad' : ''}`}>
                    {count}
                  </span>
                )}
              </button>
            )
          }
          return NAV.map((entry) => {
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
              {!closed && entry.items.map(renderNavItem)}
              {!closed && (entry.sections || []).map((section) => (
                <div className="nav-section" key={section.label}>
                  <div className="nav-section-title">{section.label}</div>
                  {section.items.map(renderNavItem)}
                </div>
              ))}
            </div>
            )
          })
        })()}
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <div className="crumbs">barad-dûr / {title.toLowerCase()}</div>
          </div>
          <div className="topbar-search">
            <Icon name="search" size={14} />
            <input
              ref={searchRef}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search or go to"
              aria-label="Search or go to"
            />
            {!query && <kbd className="kbd">⌘K</kbd>}
            {query && (
              <div className="search-results" role="listbox">
                {matches.length === 0 && (
                  <div className="search-empty">no screen matches “{query.trim()}”</div>
                )}
                {matches.map((item) => (
                  <button
                    key={item.key}
                    role="option"
                    aria-selected={tab === item.key}
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={() => {
                      go(item.key)
                      setQuery('')
                      searchRef.current?.blur()
                    }}
                  >
                    <Icon name={item.icon} size={14} />
                    <span>{item.label}</span>
                  </button>
                ))}
              </div>
            )}
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
              api.save({ url: api.settings().url || '', key: '', token: '',
                refresh_token: '', expires_at: '' })
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
