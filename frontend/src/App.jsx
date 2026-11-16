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
import Sbom from './Sbom'
import PipelineBuilder from './PipelineBuilder'
import Findings from './Findings'
import Notifications from './Notifications.jsx'
import CodeReview from './CodeReview'
import Jira from './Jira'
import Orchestration from './Orchestration'
import SurfaceRun from './SurfaceRun'
import Scans from './Scans'
import FindingPage from './FindingPage'
import FindingIntake from './FindingIntake'
import OrgMenu from './OrgMenu'
import ErrorBoundary from './ErrorBoundary'
import Activate from './Activate'
import AssetDetail from './AssetDetail'
import Pentest from './Pentest'
import Regression from './Regression'
import Pipelines from './Pipelines'
import Settings from './Settings'
import Setup from './Setup'
import Guide from './Guide'
import Startup from './Startup'
import Invite from './Invite'
import Projects from './Projects'
import CtemCycle from './CtemCycle'
import Scope from './Scope'
import Vulnerabilities from './Vulnerabilities'
import Analysis from './Analysis'
import CveDetail from './CveDetail'
import ComponentDetail from './ComponentDetail'
import Exposures from './Exposures'
import AttackSurface from './AttackSurface'
import Cycles from './Cycles'
import CycleDetail from './CycleDetail'
import BusinessContext from './BusinessContext'
import ThreatModel from './ThreatModel'
import BusinessImpact from './BusinessImpact'
import Security from './Security'
import Chat from './Chat'
import Agents from './Agents'
import Assistant from './Assistant'
import AiRuns from './AiRuns'
import Missions from './Missions'
import Prompts from './Prompts'
import Icon from './icons'
import GlobalSearch from './GlobalSearch'
import SearchResults from './SearchResults'
import Candidates from './Candidates'
import MyWork from './MyWork'
import { api } from './api'
import Login, { BrandMark } from './Login'
import { getTheme, setTheme } from './ui'
import { useI18n, AVAILABLE_LANGUAGES, languageName } from './i18n'

/* Navigation follows the CTEM loop: the five phases are the spine, and the
   screens that feed them sit underneath. Groups collapse, because 20 flat rows
   pushed everything below the fold — the sidebar is a map, not a list. */
const NAV = [
  // One door per object. The daily queue plus the two AI working surfaces; a
  // view that answers a narrower question about one of these is a tab inside
  // it, never a second row in the rail (that is how four assistant entries were
  // born from one conversation).
  //
  // `label` and `group` hold translation keys, never English: the sidebar is
  // rendered through `t()` and the key is also the stable id a collapsed group
  // is remembered by, so a language switch cannot open or close a group.
  { group: '', collapsible: false, items: [
    { key: 'dashboard', label: 'nav.dashboard', icon: 'dashboard' },
    { key: 'my-work', label: 'nav.my-work', icon: 'my-work' },
    { key: 'findings', label: 'nav.findings', icon: 'findings', badge: 'critical' },
    { key: 'vulnerabilities', label: 'nav.vulnerabilities', icon: 'vulnerabilities' },
    // The conversation and the traces of what it read are one object. `ai-runs`
    // stays a reachable view from inside the assistant, not a door of its own.
    { key: 'chat', label: 'nav.assistant', icon: 'chat' },
    { key: 'agents', label: 'nav.agents', icon: 'my-work' },
    // What each participant is told. Authorship belongs beside the catalogue: the
    // prompt is the difference between two agents with the same tools.
    { key: 'prompts', label: 'nav.prompts', icon: 'chat' },
  ] },
  // The cycle is one frame with three working areas inside it. Each area owns
  // the screens that feed it; nothing is duplicated across groups.
  { group: 'nav.group.ctem', collapsible: true, defaultOpen: true, items: [
    { key: 'ctem', label: 'nav.ctem', icon: 'cycle' },
  ], sections: [
    { label: 'nav.section.scoping', items: [
      { key: 'cycles', label: 'nav.cycles', icon: 'cycles' },
      { key: 'scope', label: 'nav.scope', icon: 'scope' },
      // The judgement everything downstream hangs on: which *projects* carry the
      // business. A threat model and a cycle's selection start here, not from 274
      // domains of equal weight.
      { key: 'business-context', label: 'nav.business-context', icon: 'business-impact' },
      // What an attacker would do to the jewel, in ATT&CK's vocabulary, and who
      // would do it. A threat model outlives one cycle.
      { key: 'threat-model', label: 'nav.threat-model', icon: 'attack-surface' },
    ] },
    { label: 'nav.section.inventory', items: [
      // Discovery is where the cycle touches the estate, and a scan is a
      // definition that recurs — not a one-off job buried in Orchestration.
      { key: 'scans', label: 'nav.scans', icon: 'attack-surface' },
      { key: 'projects', label: 'nav.projects', icon: 'applications' },
      { key: 'assets', label: 'nav.assets', icon: 'assets' },
      // Every build with a bill of materials. The application-grouped view of
      // the same builds (and the web surface) are reached from here.
      { key: 'sbom', label: 'nav.sbom', icon: 'components' },
      { key: 'exposures', label: 'nav.exposures', icon: 'exposures' },
    ] },
  ] },
  { group: 'nav.group.delivery', collapsible: true, items: [
    { key: 'pipeline', label: 'nav.pipeline', icon: 'pipelines' },
    { key: 'gates', label: 'nav.gates', icon: 'gates' },
    { key: 'pentest', label: 'nav.pentest', icon: 'pentest' },
    { key: 'regression', label: 'nav.regression', icon: 'regression' },
  ] },
  { group: 'nav.group.supply', collapsible: true, items: [
    { key: 'licenses', label: 'nav.licenses', icon: 'licenses' },
    { key: 'orchestration', label: 'nav.orchestration', icon: 'orchestration' },
    { key: 'jira', label: 'nav.jira', icon: 'jira' },
    // Tasks and the priority rules that produce them are one screen with two
    // tabs; two sidebar rows switched a `<select>` inside the same component.
    { key: 'remediation', label: 'nav.remediation', icon: 'remediation' },
  ] },
  // The product's own documentation, next to the work it describes. It is a
  // screen like any other, so it is searchable from ⌘K and linkable by address.
  { group: 'nav.group.help', collapsible: false, items: [
    { key: 'guide', label: 'nav.guide', icon: 'help' },
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
  pipelines: 'pipeline',
}

/* Screens that are no longer doors in the sidebar because they are reached from
   the object that needs them: the analysis viewer from a finding, the execution
   traces from the assistant, the application-grouped builds from Builds, the
   impact table from the crown jewels. They keep their keys and their names so a
   bookmark, a pasted link, a CTEM phase link and the crumb still resolve. */
const HIDDEN_SCREENS = {
  activate: 'title.activate',
  asset: 'title.asset',
  // Two entity pages reached from the rows that name them: an advisory and the
  // package that carries it. Both own a real path, and the hash form keeps an
  // old bookmark resolving.
  cve: 'cve.title',
  component: 'componentSheet.title',
  analysis: 'title.analysis',
  code: 'title.code',
  'pipeline-new': 'title.pipeline-new',
  // The search page owns a hash route so a result set can be pasted: the
  // dropdown is a shortcut, this is the screen that lists everything.
  search: 'search.page.title',
  // The queue of what the agents proposed: reached from a cycle's scan result and
  // from a finding's trace, and linkable because a candidate review is shared work.
  candidates: 'candidates.title',
  // The runs list moved into Orchestration; the run detail is still reached from
  // there, so the key has to keep resolving or `#surface::<id>` falls to dashboard.
  surface: 'title.surface',
  settings: 'title.settings',
  security: 'title.security',
  notifications: 'title.notifications',
  grants: 'title.grants',
  members: 'title.members',
  audit: 'title.audit',
  setup: 'title.setup',
  // Demoted by the navigation audit: each answers a narrower question about an
  // object that already owns a sidebar door, so it is reached from there.
  'attack-surface': 'nav.attack-surface',
  components: 'nav.components',
  missions: 'nav.missions',
  'ai-runs': 'nav.ai-runs',
  'business-impact': 'nav.business-impact',
  'priority-rules': 'nav.priority-rules',
}
const SETTINGS_KEYS = new Set(['security', 'notifications', 'grants', 'runtime',
                               'members', 'audit', 'setup'])

const NAV_ITEMS = NAV.flatMap((entry) => [
  ...entry.items,
  ...((entry.sections || []).flatMap((section) => section.items)),
])
const ALL_KEYS = [
  ...NAV_ITEMS.map((item) => item.key),
  ...Object.keys(LEGACY_KEYS),
  ...Object.keys(HIDDEN_SCREENS),
]

/* The hash carries an optional focus so one screen can hand a record to
   another: #findings::<finding id> and #analysis::run=<run>&path=…&line=… */
function parseHash() {
  const raw = (window.location.hash || '').replace('#', '')
  const [key, ...rest] = raw.split('::')
  const tail = rest.join('::')
  const tab = LEGACY_KEYS[key] || (ALL_KEYS.includes(key) ? key : 'dashboard')
  const focus = {}
  if (SETTINGS_KEYS.has(tab)) return { tab: 'settings', focus: { settingsSection: tab } }
  if ((key === 'sbom' || tab === 'components') && tail) {
    // A label can belong to several components at once (a monorepo ships
    // backend and web as `main`), so the exact build travels in the link.
    const [path, versionId] = tail.split('::')
    const [projectSlug, ...rest] = path.split('/')
    focus.projectSlug = projectSlug
    // project/component/version: two builds can share a label, so the component
    // belongs in the address. A two-segment tail is the old project/version form.
    if (rest.length >= 2) {
      focus.component = decodeURIComponent(rest[0])
      focus.version = decodeURIComponent(rest.slice(1).join('/'))
    } else {
      focus.version = decodeURIComponent(rest.join('/'))
    }
    if (versionId) focus.versionId = versionId
  }
  // The tail of `#findings` is one of three things: the record form (`new`, so the
  // form is a link somebody can paste to a colleague and reuse), a facet query the
  // queue answers, or a record id. Every old link keeps working.
  if (tab === 'findings' && tail) {
    if (tail === 'new' || tail.startsWith('new&')) {
      focus.newFinding = true
      const params = new URLSearchParams(tail.slice(3))
      focus.queue = Object.fromEntries(
        [...params.entries()].filter(([, value]) => value))
    } else if (tail.includes('=')) {
      const params = new URLSearchParams(tail)
      focus.queue = Object.fromEntries(
        [...params.entries()].filter(([, value]) => value))
    } else {
      focus.findingId = tail
    }
  }
  // A dashboard KPI opens the list already filtered: #vulnerabilities::kev=1
  // is the "known exploited" door, and the screen reads the filter from here
  // instead of landing on the full catalogue and asking again.
  if (tab === 'vulnerabilities' && tail) {
    const params = new URLSearchParams(tail)
    if (params.get('kev')) focus.kev = true
    if (params.get('severity')) focus.severity = params.get('severity')
    // A search hit lands on the advisory itself: `q` filters the estate list to
    // that signature and `cve` opens the row instead of asking for a second click.
    if (params.get('q')) focus.q = params.get('q')
    if (params.get('project')) focus.project = params.get('project')
    if (params.get('cve')) focus.cve = params.get('cve')
  }
  if (tab === 'analysis' && tail) {
    const params = new URLSearchParams(tail)
    focus.runId = params.get('run') || undefined
    focus.path = params.get('path') || undefined
    focus.line = params.get('line') ? Number(params.get('line')) : undefined
  }
  if (tab === 'surface' && tail) focus.runId = tail   // run detail, not a list
  if (tab === 'search' && tail) focus.q = decodeURIComponent(tail)
  // A run is addressable so a chat answer can hand its receipt to a colleague:
  // `#ai-runs::<run id>` opens that run, the plain key lists them.
  if (tab === 'ai-runs' && tail) focus.runId = tail
  if (tab === 'activate' && tail) focus.code = decodeURIComponent(tail)
  if (tab === 'asset' && tail) focus.assetId = tail
  // The advisory and the component sheet carry their entity in the address, so a
  // link to "CVE-2021-23337" or to one package opens that record, not a list.
  if (tab === 'cve' && tail) focus.cveId = decodeURIComponent(tail)
  if (tab === 'component' && tail) focus.componentId = decodeURIComponent(tail)
  // A cycle is a screen of its own: #cycles::<uuid> opens it, the plain key lists them.
  if (tab === 'cycles' && tail) focus.cycleId = tail
  // The review queue opened from a campaign: only that cycle's claims.
  if (tab === 'candidates' && tail) focus.cycleId = tail
  // The guide carries the chapter in the address, so a link can point at one.
  if (tab === 'guide' && tail) focus.chapter = decodeURIComponent(tail)
  if (tab === 'settings' && tail) focus.settingsSection = tail
  // `#surface` on its own used to be a second list of runs. The list lives in
  // Orchestration now, so an old bookmark lands there instead of on a screen that
  // is only there for the history books.
  if (tab === 'surface' && !focus.runId) return { tab: 'orchestration', focus: {} }
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

/* The pipeline and the scanner fleet are things people paste to each other, so
   they own a real path too. A fragment is invisible to a bookmark, to the
   server and to anyone reading a link out loud. */
const SCREEN_PATHS = {
  pipeline: '/pipeline',
  'pipeline-new': '/pipeline/new',
  orchestration: '/orchestration',
}
const PATH_SCREENS = Object.fromEntries(
  Object.entries(SCREEN_PATHS).map(([key, path]) => [path, key]))

/* An entity page owns a readable path too — `/cve/CVE-2021-23337` is the whole
   point of asking for a route instead of a panel: it can be pasted, bookmarked
   and reloaded. The id travels in the path, so these are patterns, not entries
   in the table above. */
const CVE_PATH = /^\/cve\/([^/]+)\/?$/
const COMPONENT_PATH = /^\/component\/([^/]+)\/?$/

function parseEntityPath(pathname) {
  const cve = pathname.match(CVE_PATH)
  if (cve) return { tab: 'cve', focus: { cveId: decodeURIComponent(cve[1]) } }
  const component = pathname.match(COMPONENT_PATH)
  if (component) {
    return { tab: 'component', focus: { componentId: decodeURIComponent(component[1]) } }
  }
  return null
}

/* One resolver for both address shapes: a hash wins, then a real path. A legacy
   fragment that owns a path is rewritten in place, so the address bar never
   keeps two spellings of the same screen. */
function parseRoute() {
  if (window.location.hash) {
    const next = parseHash()
    const path = SCREEN_PATHS[next.tab]
    if (path) window.history.replaceState({}, '', path)
    return { tab: next.tab, focus: next.focus, project: null }
  }
  const project = parseProjectPath()
  if (project) return { tab: 'projects', focus: {}, project }
  const entity = parseEntityPath(window.location.pathname)
  if (entity) return { tab: entity.tab, focus: entity.focus, project: null }
  const key = PATH_SCREENS[window.location.pathname.replace(/\/+$/, '') || '/']
  return { tab: key || 'dashboard', focus: {}, project: null }
}

export default function App() {
  const { t, lang, setLang } = useI18n()
  // Resolved once; the listeners below re-resolve on every real navigation.
  const [entry] = useState(parseRoute)
  const [projectRoute, setProjectRoute] = useState(entry.project)
  const [tab, setTab] = useState(entry.tab)
  const [focus, setFocus] = useState(entry.focus)
  const [projects, setProjects] = useState([])
  const [projectsError, setProjectsError] = useState('')
  const [session, setSession] = useState(() => api.settings())
  const [theme, setThemePreference] = useState(() => getTheme())
  const [org, setOrg] = useState(null)
  const [badges, setBadges] = useState({})

  const needsKey = !session.key && !session.token

  useEffect(() => {
    const onRoute = () => {
      const next = parseRoute()
      setProjectRoute(next.project)
      setTab(next.tab)
      setFocus(next.focus)
    }
    window.addEventListener('hashchange', onRoute)
    window.addEventListener('popstate', onRoute)
    return () => {
      window.removeEventListener('hashchange', onRoute)
      window.removeEventListener('popstate', onRoute)
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
  }, [needsKey])

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

  const go = (key, nextFocus = {}) => {
    const settingsChild = SETTINGS_KEYS.has(key)
    const destination = settingsChild ? 'settings' : key
    const destinationFocus = settingsChild ? { ...nextFocus, settingsSection: key } : nextFocus
    setTab(destination)
    setFocus(destinationFocus)
    const path = SCREEN_PATHS[destination]
    if (path) {
      window.history.pushState({}, '', path)
      setProjectRoute(null)
      return
    }
    if (destination === 'projects') {
      window.history.pushState({}, '', '/projects')
      setProjectRoute({ slug: '', tab: 'summary' })
      if (window.location.hash) window.history.replaceState({}, '', '/projects')
      return
    }
    setProjectRoute(null)
    // pushState, not location.hash: assigning the hash keeps the current path,
    // which is how /projects/aurea/components#grants ended up as a dead link.
    // A focus that the destination can re-read belongs in the address, or the link
    // is only half pasteable.
    let tail = ''
    if (destination === 'settings' && destinationFocus.settingsSection) {
      tail = `::${destinationFocus.settingsSection}`
    } else if (destination === 'ai-runs' && destinationFocus.runId) {
      tail = `::${destinationFocus.runId}`
    } else if (destination === 'search' && destinationFocus.q) {
      tail = `::${encodeURIComponent(destinationFocus.q)}`
    }
    window.history.pushState({}, '', `/#${destination}${tail}`)
  }

  /* The screen's address is written here, not inside the screen: every other
     navigation goes through `go`, and a second writer is how the hash and the
     state drift apart. */
  function goSearch(term) {
    const query = String(term || '').trim()
    setTab('search')
    setFocus({ q: query })
    setProjectRoute(null)
    window.history.pushState({}, '', `/#search::${encodeURIComponent(query)}`)
  }

  function openSettings(section = 'organization') {
    go('settings', { settingsSection: section })
  }

  function toggleTheme() {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    setThemePreference(next)
  }

  function openComponentVersion(slug, component, version, versionId) {
    setTab('components')
    setFocus({ projectSlug: slug, component, version, versionId })
    const parts = [slug]
    if (component) parts.push(encodeURIComponent(component))
    parts.push(encodeURIComponent(version))
    const hash = `/#components::${parts.join('/')}${versionId ? `::${versionId}` : ''}`
    window.history.pushState({}, '', hash)
  }

  function openProject(slug, nextTab = 'summary') {
    if (!slug) return
    const suffix = nextTab && nextTab !== 'summary' ? `/${nextTab}` : ''
    window.history.pushState({}, '', `/projects/${encodeURIComponent(slug)}${suffix}`)
    setProjectRoute({ slug, tab: nextTab || 'summary' })
    setTab('projects')
  }

  /* Two entity pages, both addressable on their own: the advisory by its id
     (`/cve/CVE-2021-23337`) and the component sheet by the component's id, which
     is the only identifier a package@version always has — a purl is longer than
     a URL should carry and a name plus version can repeat across an org. */
  function openCve(cveId) {
    if (!cveId) return
    window.history.pushState({}, '', `/cve/${encodeURIComponent(cveId)}`)
    setProjectRoute(null)
    setTab('cve')
    setFocus({ cveId })
    window.scrollTo({ top: 0 })
  }

  function openComponentSheet(componentId) {
    if (!componentId) return
    window.history.pushState({}, '', `/component/${encodeURIComponent(componentId)}`)
    setProjectRoute(null)
    setTab('component')
    setFocus({ componentId })
    window.scrollTo({ top: 0 })
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

  // Every search hit owns a deep link: the project's real URL, the exact
  // project/component/version build, the asset screen, the advisory row and
  // the finding drawer the rest of the console already opens.
  function openSearchResult(result) {
    if (result.kind === 'project') {
      openProject(result.slug)
      return
    }
    if (result.kind === 'component') {
      openComponentVersion(result.project_slug, result.component,
        result.version_label, result.version_id)
      return
    }
    if (result.kind === 'version') {
      openComponentVersion(result.project_slug, result.component,
        result.version || result.title, result.version_id)
      return
    }
    if (result.kind === 'asset') {
      window.location.hash = `asset::${result.id}`
      return
    }
    if (result.kind === 'vulnerability') {
      // A search hit names one advisory: open its page, not the list filtered to
      // it and one more click.
      openCve(result.id)
      return
    }
    if (result.kind === 'finding') {
      window.location.hash = `findings::${result.id}`
    }
  }

  const title = useMemo(() => {
    const found = NAV_ITEMS.find((item) => item.key === tab)
    return found ? t(found.label) : t(HIDDEN_SCREENS[tab] || 'nav.dashboard')
  }, [tab, t])

  // An invitation is opened by someone with no credential yet: it must render
  // before the sign-in gate, never behind it.
  if (window.location.pathname === '/invite') {
    return <Invite />
  }

  if (needsKey) {
    return <Login onAuthenticated={(context = {}) => {
      setSession(api.settings())
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
          onOpenVersion={openComponentVersion}
          onProjectTab={switchProjectTab}
          onCloseProject={closeProject} />
      )
      case 'findings': return focus.newFinding ? (
        <FindingIntake seed={focus.queue || {}}
                       onDone={() => go('findings')}
                       onCancel={() => go('findings')} />
      ) : focus.findingId ? (
        <FindingPage id={focus.findingId}
                     onBack={() => go('findings')}
                     onOpenAnalysis={(target) => {
                       const params = new URLSearchParams({ run: target.runId })
                       if (target.path) params.set('path', target.path)
                       if (target.line) params.set('line', String(target.line))
                       window.location.hash = `analysis::${params.toString()}`
                     }} />
      ) : (
        <Findings projects={projects} focus={focus} />
      )
      case 'code': return <CodeReview projects={projects} />
      case 'gates': return <Gates projects={projects} />

      case 'licenses': return <Licenses projects={projects} />
      case 'pentest': return <Pentest projects={projects} onNavigate={go} />
      case 'jira': return <Jira onOpenFinding={(findingId) => { window.location.hash = `findings::${findingId}` }} />
      case 'regression': return <Regression />
      case 'orchestration': return <Orchestration />
      case 'surface': return <SurfaceRun runId={focus.runId} />
      case 'scans': return <Scans initialTab={focus.scansTab || 'scans'} onNavigate={go} />
      case 'activate': return <Activate code={focus.code} />
      case 'asset': return <AssetDetail assetId={focus.assetId} />
      case 'chat': return <Chat onBack={() => go('dashboard')} onNavigate={go} />
      case 'agents': return <Agents onNavigate={go} />
      case 'ai-runs': return <AiRuns focus={focus} />
      case 'missions': return <Missions />
      case 'prompts': return <Prompts />
      case 'grants': return <Grants />
      case 'audit': return <Audit />
      case 'remediation': return <Lifecycle />
      case 'guide': return <Guide chapter={focus.chapter} onNavigate={go} />
      case 'members': return <Members />
      case 'search': return (
        <SearchResults query={focus.q || ''} onQuery={goSearch}
          onOpenResult={openSearchResult} />
      )
      case 'candidates': return <Candidates cycleId={focus.cycleId || ''} />
      case 'assets': return <Assets onNavigate={go} />
      case 'scope': return <Scope />
      case 'business-context': return <BusinessContext onNavigate={go} />
      case 'threat-model': return <ThreatModel />
      case 'vulnerabilities': return <Vulnerabilities onNavigate={go} onOpenCve={openCve}
        focus={focus} />
      case 'cve': return (
        <CveDetail cveId={focus.cveId}
          onBack={() => go('vulnerabilities')}
          onOpenComponent={openComponentSheet}
          onOpenAsset={(assetId) => { window.location.hash = `asset::${assetId}` }} />
      )
      case 'component': return (
        <ComponentDetail componentId={focus.componentId}
          /* Back returns where the reader came from — a build, usually — instead
             of resetting to the list of builds. A deep link in a fresh tab has
             nothing to return to, so it falls back to the index. */
          onBack={() => (window.history.length > 1 ? window.history.back() : go('components'))}
          onOpenCve={openCve}
          onOpenVersion={openComponentVersion} />
      )
      case 'analysis': return (
        <Analysis projects={projects} focusRun={focus}
          onOpenFinding={(findingId) => { window.location.hash = `findings::${findingId}` }} />
      )
      case 'exposures': return <Exposures />
      case 'attack-surface': return <AttackSurface onNavigate={go} />
      case 'cycles': return focus.cycleId
        ? <CycleDetail cycleId={focus.cycleId} onBack={() => go('cycles')} />
        : <Cycles />
      case 'my-work': return <MyWork />
      case 'sbom': return <Sbom focus={focus} onOpen={openComponentVersion}
        onBack={() => go('sbom')} onOpenComponents={() => go('components')}
        onOpenComponent={openComponentSheet}
        onOpenFinding={(findingId) => { window.location.hash = `findings::${findingId}` }} />
      case 'components': return <Components projects={projects} focus={focus} onChanged={loadProjects}
        onOpenProject={openProject} onOpenVersion={openComponentVersion}
        onOpenComponent={openComponentSheet}
        onOpenFinding={(findingId) => { window.location.hash = `findings::${findingId}` }}
        onBack={() => go('components')} />
      case 'pipeline': return <Pipelines
        onNewPipeline={() => go('pipeline-new')}
        onOpenFinding={(findingId) => { window.location.hash = `findings::${findingId}` }} />
      case 'pipeline-new': return <PipelineBuilder
        onBack={() => go('pipeline')} onDone={() => go('pipeline')} />
      case 'security': return <Security />
      case 'notifications': return <Notifications />
      case 'settings': return <Settings
        section={focus.settingsSection || 'organization'}
        org={org}
        onOrgChanged={setOrg}
        onNavigate={go}
        onBack={() => go('dashboard')}
        onSessionChanged={() => setSession(api.settings())}
      />
      default: return <Dashboard projects={projects} onNavigate={go} />
    }
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <button className="product-brand" onClick={() => go('dashboard')} aria-label={t('nav.dashboard')}>
          <BrandMark size={28} />
          <span className="product-brand-copy">
            <span>barad-dûr</span>
            <small>exposure control</small>
          </span>
        </button>
        <OrgMenu org={org} onOpenSettings={() => openSettings('organization')} />
        {(() => {
          const renderNavItem = (item) => {
            const count = item.badge ? badges[item.badge] : 0
            return (
              <button
                key={item.key}
                className={`nav-item${tab === item.key ? ' active' : ''}${item.disabled ? ' nav-item-disabled' : ''}`}
                aria-current={tab === item.key ? 'page' : undefined}
                aria-disabled={item.disabled || undefined}
                onClick={() => !item.disabled && go(item.key)}
                title={item.disabled ? t('shell.notAvailable') : undefined}
              >
                <span className="nav-item-label">
                  <Icon name={item.icon} />
                  <span>{t(item.label)}</span>
                </span>
                {item.disabled && <span className="nav-item-state">{t('nav.notReady')}</span>}
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
                  <span>{t(entry.group)}</span>
                  <span className={`nav-chevron${closed ? '' : ' open'}`}
                    aria-hidden="true" />
                </button>
              ) : (
                <div className="nav-group-title">{t(entry.group)}</div>
              ))}
              {!closed && entry.items.map(renderNavItem)}
              {!closed && (entry.sections || []).map((section) => (
                <div className="nav-section" key={section.label}>
                  <div className="nav-section-title">{t(section.label)}</div>
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
            <div className="crumbs">barad-dûr / {title}</div>
          </div>
          <GlobalSearch screens={NAV_ITEMS} onScreen={go}
            onResult={openSearchResult} onSeeAll={goSearch} />
          <div className="topbar-actions">
            <button className="icon-btn" onClick={() => go('guide')}
              title={t('shell.openGuide')} aria-label={t('shell.openGuide')}>
              <Icon name="help" size={16} />
            </button>
            {(() => {
              const next = AVAILABLE_LANGUAGES[(AVAILABLE_LANGUAGES.indexOf(lang) + 1)
                % AVAILABLE_LANGUAGES.length]
              return (
                <button className="lang-chip" onClick={() => setLang(next)}
                  title={`${t('shell.language.switch')} → ${languageName(next)}`}
                  aria-label={`${t('shell.language.switch')} → ${languageName(next)}`}>
                  {lang.toUpperCase()}
                </button>
              )
            })()}
            {(() => {
              const isDark = document.documentElement.dataset.theme === 'dark'
              const label = theme === 'system' ? t('shell.theme.system')
                : (isDark ? t('shell.theme.light') : t('shell.theme.dark'))
              return (
            <button className="theme-toggle" onClick={toggleTheme}
              title={isDark ? t('shell.theme.toLight') : t('shell.theme.toDark')}>
              <Icon name={isDark ? 'sun' : 'moon'} size={15} />
              <span>{label}</span>
            </button>
              )
            })()}
            {/* One door, not two: the shell used to print *how* you are signed in
                ("session started" / "API key") next to a sign-out button, which is
                both noise and a destructive action one click from every screen.
                What the reader actually needs from the topbar is the way back to
                the settings that describe this connection — signing out lives
                there, beside the identity it ends. */}
            <button className="identity-control" onClick={() => openSettings('account')}>
              <span className="identity-dot" aria-hidden="true" />
              <span>{t('shell.settings')}</span>
            </button>
          </div>
        </header>

        <main className="content">
          {projectsError && (
            <div className="banner banner-error" role="alert">
              <span>{projectsError}</span>
              <span className="row-end">
                <button className="mini" onClick={() => openSettings('connection')}>settings</button>
              </span>
            </div>
          )}
          {/* A screen that throws takes the tree with it; the boundary keeps the
              shell and turns the failure into something readable. Keyed by the
              screen so navigating away clears it. */}
          <ErrorBoundary key={`${tab}:${focus.findingId || ''}`}>{screen()}</ErrorBoundary>
        </main>
      </div>

      <Assistant hidden={tab === 'chat'} onOpen={() => go('chat')} onNavigate={go} />

    </div>
  )
}
