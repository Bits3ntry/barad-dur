import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, Dialog, ErrorBanner, Loading, PageHeader, Stat,
  SeverityBadge, Tabs } from './ui'
import ProjectsPortfolio from './ProjectsPortfolio'
import ProjectRuntimeGraph from './ProjectRuntimeGraph'
import ProjectVerification from './ProjectVerification'
import ReleaseDialog from './ReleaseDialog'

/* Inventory first, findings later.
   This screen answers "what do we have?" — projects, the components that make
   them up, their code, the environments each version runs in, and the assets we
   know about. It never asks for a scan: a version can be typed by hand, or read
   from an optional /health endpoint.

   The SBOM portfolio (versions, advisories, OSV scans) keeps its own tab so the
   supply-chain view did not disappear when inventory became the entry point. */

const TABS = [
  { id: 'projects', label: 'Projects' },
  { id: 'pending', label: 'Catalogue' },
  { id: 'portfolio', label: 'SBOM portfolio' },
]

const COMPONENT_KINDS = ['backend', 'frontend', 'web', 'ios', 'android', 'worker',
  'service', 'library', 'infrastructure', 'other']
const EXPOSURES = ['unknown', 'internal', 'public']
const ASSET_KINDS = ['domain', 'subdomain', 'url', 'ip', 'api', 'mobile_app']

const PROJECT_TABS = [
  { id: 'summary', label: 'Summary' },
  { id: 'components', label: 'Components' },
  { id: 'environments', label: 'Environments' },
  { id: 'assets', label: 'Assets' },
]

function unit(count, singular, pluralForm) {
  return count === 1 ? singular : (pluralForm || `${singular}s`)
}

function plural(count, singular, pluralForm) {
  return `${count} ${count === 1 ? singular : (pluralForm || `${singular}s`)}`
}

function VersionVulnerabilities({ rows }) {
  if (!rows.length) return null
  return (
    <tr className="version-vulnerabilities"><td colSpan="3">
      <div className="version-vulnerability-list">
        <strong>{plural(rows.length, 'vulnerability')}</strong>
        {rows.map((row) => (
          <div className="row" key={row.id}>
            <span className="mono">{row.cve_id || row.signature}</span>
            <SeverityBadge severity={row.severity} />
            <span className="muted">{row.title || 'untitled finding'}</span>
            <span className="count">{plural(row.open_findings, 'open finding')}</span>
          </div>
        ))}
      </div>
    </td></tr>
  )
}

/* Eleven builds of one component are read as a column: a 40-character sha in a
   table cell is noise, so the row shows its first eight and keeps the whole
   label in the tooltip. A tag or a branch name passes through untouched. */
const SHA_LABEL = /^[0-9a-f]{7,40}$/i

function shortLabel(value) {
  return SHA_LABEL.test(value || '') ? String(value).slice(0, 8) : value
}

/* The mix, not just the total: a build with three criticals and a build with
   forty lows are not the same Tuesday, and a number alone cannot say which one
   you are looking at. */
const BAR_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function SeverityBar({ counts = {}, width = 96 }) {
  const shown = BAR_ORDER.filter((severity) => counts[severity] > 0)
  const total = shown.reduce((sum, severity) => sum + counts[severity], 0)
  if (!total) return <span className="sev-bar is-empty" style={{ width }} title="no open finding" />
  return (
    <span className="sev-bar" style={{ width }}
      title={shown.map((severity) => `${counts[severity]} ${severity.toLowerCase()}`).join(' · ')}>
      {shown.map((severity) => (
        <i key={severity} className={`sev-bar-${severity.toLowerCase()}`}
          style={{ flexGrow: counts[severity] }} />
      ))}
    </span>
  )
}

function NeedsAttribution({ intakes, components, versions, busy, onAssign }) {
  if (!intakes.length) return null
  return (
    <Card title="Needs attribution"
      actions={<span className="count">{plural(intakes.length, 'CI scan')}</span>}>
      <p className="muted attribution-intro">
        These scans reached this project through a repository, but could not be tied to one
        component. Choose the component before the scan can proceed; a version is optional.
      </p>
      <div className="attribution-list">
        {intakes.map((intake) => (
          <AttributionIntake key={intake.id} intake={intake} components={components}
            versions={versions} busy={busy === `attribution:${intake.id}`}
            onAssign={onAssign} />
        ))}
      </div>
    </Card>
  )
}

function AttributionIntake({ intake, components, versions, busy, onAssign }) {
  const suggested = components.find((component) => intake.candidates?.includes(component.id))
  const [componentId, setComponentId] = useState(suggested?.id || '')
  const [versionId, setVersionId] = useState('')
  const [note, setNote] = useState('')
  const [localError, setLocalError] = useState('')
  const subject = intake.subject || {}
  const componentVersions = versions.filter((version) => version.component_id === componentId)

  async function submit(event) {
    event.preventDefault()
    if (!componentId) {
      setLocalError('Choose the component that owns this scan.')
      return
    }
    setLocalError('')
    const selectedVersion = componentVersions.find((version) => version.id === versionId)
    const assigned = await onAssign(intake, {
      component: componentId,
      version: selectedVersion?.version,
      note: note.trim() || undefined,
    })
    if (assigned) {
      setNote('')
      setVersionId('')
    }
  }

  return (
    <section className="attribution-intake">
      <div className="attribution-subject">
        <strong className="mono">{subject.repository || 'repository not recorded'}</strong>
        <span className="muted">
          {[subject.branch, subject.commit && String(subject.commit).slice(0, 12),
            subject.pull_request && `PR ${subject.pull_request}`].filter(Boolean).join(' · ') ||
            'CI scan awaiting an owner'}
        </span>
        {subject.version && <span className="pill mono">reported {subject.version}</span>}
      </div>
      <form className="attribution-form" onSubmit={submit}>
        <label>
          Component
          <select value={componentId} disabled={busy} onChange={(event) => {
            setComponentId(event.target.value)
            setVersionId('')
          }}>
            <option value="">choose component…</option>
            {components.map((component) => (
              <option key={component.id} value={component.id}>
                {component.name}{intake.candidates?.includes(component.id) ? ' · suggested' : ''}
              </option>
            ))}
          </select>
        </label>
        <label>
          Version <span className="onb-optional">optional</span>
          <select value={versionId} disabled={busy || !componentId}
            onChange={(event) => setVersionId(event.target.value)}>
            <option value="">no version</option>
            {componentVersions.map((version) => (
              <option key={version.id} value={version.id}>{version.version}</option>
            ))}
          </select>
        </label>
        <label className="attribution-note">
          Note <span className="onb-optional">optional</span>
          <input value={note} disabled={busy} placeholder="Why this component owns the scan"
            onChange={(event) => setNote(event.target.value)} />
        </label>
        <button className="btn-primary" type="submit" disabled={busy || !components.length}>
          {busy ? 'assigning…' : 'assign'}
        </button>
      </form>
      {!components.length && <p className="attribution-error">Add a component before assigning this scan.</p>}
      {localError && <p className="attribution-error" role="alert">{localError}</p>}
    </section>
  )
}

function slugify(value) {
  return (value || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120)
}

// An interval stored in minutes, said the way a person says it.
function cadence(minutes) {
  if (!minutes) return 'manual only'
  if (minutes % 1440 === 0) return minutes / 1440 === 1 ? 'daily' : `every ${minutes / 1440}d`
  if (minutes % 60 === 0) return minutes / 60 === 1 ? 'hourly' : `every ${minutes / 60}h`
  return `every ${minutes}m`
}

function dueLabel(iso) {
  const ms = new Date(iso).getTime() - Date.now()
  if (!Number.isFinite(ms)) return ''
  if (ms <= 0) return 'due now'
  const minutes = Math.round(ms / 60000)
  if (minutes < 60) return `next in ${Math.max(minutes, 1)}m`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `next in ${hours}h`
  return `next in ${Math.round(hours / 24)}d`
}

function fail(setError) {
  return (e) => setError(String(e.message || e))
}

export default function Projects({ onNavigate, slug = '', tab = 'summary',
                                   onOpenProject, onOpenVersion, onProjectTab, onCloseProject }) {
  const [view, setView] = useState('projects')
  const [list, setList] = useState(null)
  const [pending, setPending] = useState(null)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [busy, setBusy] = useState('')
  const [filter, setFilter] = useState('')

  function loadProjects() {
    setError('')
    return api.get('/api/v1/projects')
      .then((r) => setList(r.data || []))
      .catch(fail(setError))
  }

  function loadPending() {
    return api.get('/api/v1/inventory/unassigned')
      .then((r) => setPending(r))
      .catch(fail(setError))
  }

  useEffect(() => { loadProjects(); loadPending() }, [])

  async function createProject(draft) {
    const result = await api.post('/api/v1/projects', {
      name: draft.name.trim(),
      slug: draft.slug || undefined,
      group: draft.group.trim() || undefined,
      description: draft.description.trim() || undefined,
      owner: draft.owner.trim() || undefined,
      actor: 'console',
    })
    // The first component is part of the same intent: a product is made of
    // parts, and asking for one here saves a second empty screen.
    if (draft.componentName && draft.componentName.trim()) {
      await api.post(`/api/v1/projects/${result.data.slug}/components`, {
        name: draft.componentName.trim(),
        kind: draft.componentKind || 'backend',
        actor: 'console',
      })
    }
    setCreating(false)
    await loadProjects()
    if (onOpenProject) onOpenProject(result.data.slug)
  }

  async function fileAsset(asset, projectSlug) {
    if (!projectSlug) return
    setBusy(`file:${asset.id}`)
    setError('')
    try {
      await api.post(`/api/v1/assets/${asset.id}/catalog`,
        { project: projectSlug, actor: 'console' })
      await Promise.all([loadPending(), loadProjects()])
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  // The open project is the URL, not component state: /projects/{slug}.
  if (slug) {
    return <ProjectInventory refSlug={slug} initialTab={tab}
      onNavigate={onNavigate}
      onOpenVersion={onOpenVersion}
      onTab={onProjectTab}
      onBack={() => {
        if (onCloseProject) onCloseProject()
        loadProjects()
        loadPending()
      }} />
  }

  const projects = list || []
  const pendingRows = pending?.data || []
  const groups = [...new Set(projects.map((p) => p.group).filter(Boolean))].sort()
  const needle = filter.trim().toLowerCase()
  const visible = needle
    ? projects.filter((p) => `${p.name} ${p.slug} ${p.group || ''} ${p.owner || ''}`
      .toLowerCase().includes(needle))
    : projects

  return (
    <div className="stack">
      <PageHeader
        title="Projects"
        subtitle="Products you own, their parts, the code behind them and the version running in each environment. Inventory only — nothing here starts a scan."
        actions={(
          <>
            {(list || []).length > 0 && (
              <button className="btn-primary mini" onClick={() => setCreating(true)}>new project</button>
            )}
            <button className="mini" onClick={() => { loadProjects(); loadPending() }}>refresh</button>
          </>
        )}
      />

      <Tabs tabs={TABS} active={view} onChange={setView} />

      {error && <ErrorBanner error={error} onRetry={() => { loadProjects(); loadPending() }} />}

      {view === 'portfolio' && <ProjectsPortfolio onNavigate={onNavigate} />}

      {view === 'projects' && (
        !list ? <Card><Loading rows={4} /></Card> : (
          <>
            <p className="inventory-summary">
              <strong>{projects.length}</strong> {unit(projects.length, 'project')} ·
              <strong>{sum(projects, 'components')}</strong> {unit(sum(projects, 'components'), 'component')} ·
              <strong>{new Set(projects.flatMap((p) => p.counts?.environments || [])).size}</strong> {unit(new Set(projects.flatMap((p) => p.counts?.environments || [])).size, 'environment')} ·
              <strong>{sum(projects, 'repositories')}</strong> {unit(sum(projects, 'repositories'), 'repository', 'repositories')} ·
              <strong>{sum(projects, 'assets')}</strong> {unit(sum(projects, 'assets'), 'asset')}
            </p>

            {!projects.length ? (
              <Card>
                <div className="onb-empty-state">
                  <h2>No projects yet</h2>
                  <p>
                    A project groups everything you own for one product: its components
                    (backend, web, iOS…), the repositories behind them and the version
                    running in each environment. Recording it needs no scan.
                  </p>
                  <ol className="onb-empty-steps">
                    <li><strong>1.</strong> Name the product and who owns it</li>
                    <li><strong>2.</strong> Add its parts and the code behind them</li>
                    <li><strong>3.</strong> Record what runs in DEV, PRE and PRO</li>
                  </ol>
                  <button className="btn-primary" onClick={() => setCreating(true)}>
                    create the first project
                  </button>
                </div>
              </Card>
            ) : (
              <Card title="Inventory"
                actions={(
                  <div className="row">
                    <input placeholder="filter name, group or owner" value={filter}
                      onChange={(e) => setFilter(e.target.value)} style={{ minWidth: 220 }} />
                    <span className="count">{visible.length} of {projects.length}</span>
                  </div>
                )}>
                <table>
                  <thead>
                    <tr><th>project</th><th>group</th><th>owner</th><th>components</th>
                      <th>environments</th><th>deployments</th><th>repositories</th><th>assets</th>
                      <th>actions</th></tr>
                  </thead>
                  <tbody>
                    {visible.map((project) => (
                      <tr key={project.id} className="clickable"
                        onClick={() => onOpenProject && onOpenProject(project.slug)}>
                        <td className="title">
                          {project.name}
                          <span className="muted" style={{ marginLeft: 8, fontSize: 11 }}>{project.slug}</span>
                          {project.description && (
                            <div className="muted" style={{ fontSize: 11.5, maxWidth: 380,
                              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {project.description}
                            </div>
                          )}
                        </td>
                        <td className="muted">{project.group || '—'}</td>
                        <td className="muted">{project.owner || '—'}</td>
                        <td className="num">{project.counts?.components ?? 0}</td>
                        <td>
                          {(project.counts?.environments || []).map((env) => (
                            <span className="pill" key={env} style={{ marginRight: 4 }}>{env}</span>
                          ))}
                          {!(project.counts?.environments || []).length && <span className="muted">—</span>}
                        </td>
                        <td className="num">{project.counts?.deployments ?? 0}</td>
                        <td className="num">{project.counts?.repositories ?? 0}</td>
                        <td className="num">{project.counts?.assets ?? 0}</td>
                        <td>
                          <button className="mini" onClick={(e) => {
                            e.stopPropagation(); if (onOpenProject) onOpenProject(project.slug)
                          }}>open</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!visible.length && <p className="muted">Nothing matches “{filter.trim()}”.</p>}
              </Card>
            )}
          </>
        )
      )}

      {view === 'pending' && (
        <>
          <Card title="Discovered but not filed"
            actions={<span className="count">{pendingRows.length} assets</span>}>
            <p className="muted" style={{ marginTop: 0 }}>
              Discovery adds candidates here. Filing one says “this is ours and it belongs to
              this project”; it does not put it in scope and grants nothing.
            </p>
            {!pendingRows.length
              ? <p className="muted">Nothing to catalogue. Assets appear here after discovery finds them.</p>
              : (
                <table>
                  <thead><tr><th>asset</th><th>type</th><th>source</th><th>discovered</th>
                    <th>file under</th></tr></thead>
                  <tbody>
                    {pendingRows.map((asset) => (
                      <tr key={asset.id}>
                        <td className="mono">{asset.value}</td>
                        <td className="muted">{asset.type}</td>
                        <td className="muted">{asset.source}</td>
                        <td className="muted">{asset.discovered_at
                          ? new Date(asset.discovered_at).toLocaleDateString() : '—'}</td>
                        <td>
                          <div className="row">
                            <select defaultValue="" id={`file-${asset.id}`}>
                              <option value="">choose project…</option>
                              {(pending?.projects || []).map((project) => (
                                <option key={project.id} value={project.slug}>{project.name}</option>
                              ))}
                            </select>
                            <button className="mini" disabled={busy === `file:${asset.id}`}
                              onClick={() => fileAsset(asset,
                                document.getElementById(`file-${asset.id}`).value)}>
                              {busy === `file:${asset.id}` ? 'filing…' : 'file'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
          </Card>
        </>
      )}

      {creating && (
        <ProjectForm mode="create" groups={groups}
          onClose={() => setCreating(false)}
          onSubmit={createProject} />
      )}
    </div>
  )
}

function sum(projects, key) {
  return projects.reduce((total, project) => total + (project.counts?.[key] || 0), 0)
}

/* One form for "create" and "edit": the fields are the project's own context —
   name, who owns it, what it does — plus, on creation, the first component, so
   a new project is never an empty shell. */
function ProjectForm({ mode, initial, groups = [], onClose, onSubmit }) {
  const [form, setForm] = useState({
    name: initial?.name || '',
    slug: '',
    group: initial?.group || '',
    owner: initial?.owner || '',
    description: initial?.description || '',
    componentName: '',
    componentKind: 'backend',
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const preview = mode === 'create' ? (form.slug || slugify(form.name)) : initial?.slug

  async function submit(event) {
    event.preventDefault()
    setError('')
    if (form.name.trim().length < 2) {
      setError('A project needs a name of at least 2 characters.')
      return
    }
    if (mode === 'create' && preview.length < 2) {
      setError('That name produces no usable identifier; use letters or digits.')
      return
    }
    setBusy(true)
    try {
      await onSubmit({ ...form, slug: mode === 'create' ? preview : undefined })
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy(false) }
  }

  return (
    <Dialog open hideFooter title={mode === 'create' ? 'New project' : `Edit ${initial.name}`}
      onClose={onClose} body={(
        <form className="onb-form" onSubmit={submit}>
          <p className="onb-help" style={{ margin: 0 }}>
            A project is one product you own. Its components, code and environments live
            inside it — you can add them right after this.
          </p>

          <div className="onb-grid">
            <label>
              Project name
              <input autoFocus value={form.name} placeholder="AUREA"
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </label>
            <label>
              Group <span className="onb-optional">optional</span>
              <input value={form.group} placeholder="Bitsentry" list="project-groups"
                onChange={(e) => setForm({ ...form, group: e.target.value })} />
              <datalist id="project-groups">
                {groups.map((group) => <option key={group} value={group} />)}
              </datalist>
              <span className="onb-help">The product line or account it belongs to.</span>
            </label>
            <label>
              Owner <span className="onb-optional">optional</span>
              <input value={form.owner} placeholder="ana@bitsentry.xyz"
                onChange={(e) => setForm({ ...form, owner: e.target.value })} />
              <span className="onb-help">Who answers for this product.</span>
            </label>
            <label>
              Identifier
              <input value={mode === 'create' ? form.slug : preview} readOnly={mode === 'edit'}
                placeholder={slugify(form.name) || 'aurea'}
                onChange={(e) => setForm({ ...form, slug: slugify(e.target.value) })} />
              <span className="onb-help">
                {mode === 'create'
                  ? `Used in URLs and filters: /projects/${preview || '…'} — it cannot be changed after creation`
                  : 'The identifier never changes; only the display name does.'}
              </span>
            </label>
          </div>

          <label>
            What it does <span className="onb-optional">optional</span>
            <textarea rows={2} value={form.description}
              placeholder="Customer app and its APIs, used by the retail team."
              onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </label>

          {mode === 'create' && (
            <div className="onb-inline-section">
              <span className="onb-section-label">First component · optional</span>
              <div className="onb-grid">
                <label>
                  Name
                  <input value={form.componentName} placeholder="Backend"
                    onChange={(e) => setForm({ ...form, componentName: e.target.value })} />
                </label>
                <label>
                  Component type
                  <select value={form.componentKind}
                    onChange={(e) => setForm({ ...form, componentKind: e.target.value })}>
                    {COMPONENT_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
                  </select>
                </label>
              </div>
              <span className="onb-help">
                A part of the product: backend, web, iOS, Android… You can add the rest later.
              </span>
            </div>
          )}

          {error && <p className="banner banner-error" role="alert">{error}</p>}

          <div className="row-end">
            <button className="mini" type="button" onClick={onClose}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy}>
              {busy ? 'saving…' : (mode === 'create' ? 'create project' : 'save changes')}
            </button>
          </div>
        </form>
      )} />
  )
}

/* ───────────────────────── one project ───────────────────────── */

function ProjectInventory({ refSlug, initialTab = 'summary', onTab, onBack, onNavigate, onOpenVersion }) {
  const [data, setData] = useState(null)
  const [attributionIntakes, setAttributionIntakes] = useState([])
  const [tab, setTab] = useState(initialTab)

  // Back/forward rewrites the URL; the tab follows it.
  useEffect(() => { setTab(initialTab) }, [initialTab])
  useEffect(() => {
    if (initialTab === 'vulnerabilities') onTab?.('components')
  }, [initialTab, onTab])

  function chooseTab(next) {
    setTab(next)
    if (onTab) onTab(next)
  }
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [dialog, setDialog] = useState(null)  // {kind, row?}
  const [releaseOpen, setReleaseOpen] = useState(false)
  // Components are accordions: a project with forty parts must not paint forty
  // version tables. The open set is a reading preference, so it survives reload.
  const [openComponents, setOpenComponents] = useState(() => {
    try {
      const stored = localStorage.getItem('barad.projects.open')
      if (stored) return new Set(JSON.parse(stored))
    } catch { /* first run */ }
    return new Set()
  })
  // Versions are paged per component: the last five are what a reader wants,
  // the rest is one click away.
  const [shownVersions, setShownVersions] = useState({})

  function toggleComponent(id) {
    setOpenComponents((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id); else next.add(id)
      localStorage.setItem('barad.projects.open', JSON.stringify([...next]))
      return next
    })
  }

  function expandAll(ids) {
    const next = new Set(ids)
    localStorage.setItem('barad.projects.open', JSON.stringify([...next]))
    setOpenComponents(next)
  }

  function collapseAll() {
    localStorage.setItem('barad.projects.open', '[]')
    setOpenComponents(new Set())
  }
  const [editing, setEditing] = useState(false)

  // Notices are confirmations, not content: they leave on their own.
  useEffect(() => {
    if (!notice) return undefined
    const timer = setTimeout(() => setNotice(''), 8000)
    return () => clearTimeout(timer)
  }, [notice])

  function load() {
    setError('')
    // Each version arrives with the counts of its own findings, so this screen
    // no longer pulls the whole vulnerability list to count them again.
    return Promise.all([
      api.get(`/api/v1/projects/${encodeURIComponent(refSlug)}/inventory`),
      api.get('/api/v1/scans/attribution-intakes'),
    ]).then(([inventory, intakes]) => {
      setData(inventory.data)
      setAttributionIntakes(intakes.data || [])
    })
      .catch(fail(setError))
  }

  useEffect(() => { load() }, [refSlug])

  async function act(key, work, message) {
    setBusy(key)
    setError('')
    setNotice('')
    try {
      await work()
      if (message) setNotice(message)
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  async function assignAttribution(intake, assignment) {
    setBusy(`attribution:${intake.id}`)
    setError('')
    setNotice('')
    try {
      await api.post(`/api/v1/scans/attribution-intakes/${encodeURIComponent(intake.id)}/assign`, assignment)
      setNotice('CI scan assigned to its component.')
      await load()
      return true
    } catch (e) {
      setError(String(e.message || e))
      return false
    } finally { setBusy('') }
  }

  if (!data) {
    return (
      <div className="stack">
        <PageHeader title="Project" actions={<button className="mini" onClick={onBack}>← all projects</button>} />
        <Card>{error ? <ErrorBanner error={error} onRetry={load} /> : <Loading rows={5} />}</Card>
      </div>
    )
  }

  const { project, components, repositories, deployments, environments, assets,
    versions = [] } = data
  const pendingAttributions = attributionIntakes.filter((intake) =>
    intake.status === 'needs_attribution' && intake.subject?.project === project.slug)
  const setupComplete = [components, versions, deployments, assets].every((rows) => rows.length > 0)

  return (
    <div className="stack">
      <nav className="project-crumb" aria-label="Breadcrumb">
        <button type="button" onClick={onBack}>Projects</button>
        <span className="sep" aria-hidden="true">/</span>
        <span aria-current="page">{project.slug}</span>
      </nav>

      <PageHeader
        title={project.name}
        subtitle={project.description}
        actions={(
          <>
            <button className="mini" onClick={onBack}>← all projects</button>
            <button className="mini" onClick={() => setEditing(true)}>edit project</button>
            <button className="mini" onClick={load}>refresh</button>
          </>
        )}
      />

      <dl className="project-meta">
        <div className="meta-item"><dt>identifier</dt><dd>{project.slug}</dd></div>
        {project.group && <div className="meta-item"><dt>group</dt><dd>{project.group}</dd></div>}
        {project.owner && <div className="meta-item"><dt>owner</dt><dd>{project.owner}</dd></div>}
        <div className="meta-item"><dt>components</dt><dd>{components.length}</dd></div>
        <div className="meta-item"><dt>environments</dt><dd>{environments.length}</dd></div>
        <div className="meta-item"><dt>assets</dt><dd>{assets.length}</dd></div>
      </dl>

      {editing && (
        <ProjectForm mode="edit" initial={project} groups={[]}
          onClose={() => setEditing(false)}
          onSubmit={async (draft) => {
            await api.patch(`/api/v1/projects/${project.slug}`, {
              name: draft.name.trim(),
              group: draft.group.trim(),
              description: draft.description,
              owner: draft.owner,
              actor: 'console',
            })
            setEditing(false)
            setNotice('Project updated.')
            await load()
          }} />
      )}

      {error && <ErrorBanner error={error} onRetry={load} />}
      {notice && (
        <div className="inv-notice" role="status">
          <span>{notice}</span>
          <button className="mini ghost" onClick={() => setNotice('')}
            aria-label="dismiss message">✕</button>
        </div>
      )}

      <Tabs tabs={PROJECT_TABS} active={tab} onChange={chooseTab} />

      {tab === 'summary' && (
        <>
          <Card tight>
            <div className="metrics">
              <Stat label={unit(components.length, 'component')} value={components.length} />
              <Stat label={unit(versions.length, 'version')} value={versions.length} />
              <Stat label={unit(environments.length, 'environment')} value={environments.length} />
              <Stat label={unit(assets.length, 'asset')} value={assets.length} />
            </div>
          </Card>

          {/* Once all four are recorded the checklist has nothing left to say:
              the metrics and the graph below are the summary. It comes back the
              moment one of them empties. */}
          {!setupComplete && <Card title="Setup path"
            actions={<span className="count">
              {[components.length, versions.length, deployments.length, assets.length]
                .filter(Boolean).length} of 4 recorded
            </span>}>
            {(() => {
              const steps = [
                { key: 'components', label: 'Components', count: components.length,
                  action: 'add', hint: 'Optional. The parts of the product — backend, web, iOS. A WordPress site skips this and lives as a domain.',
                  open: { kind: 'component' } },
                { key: 'versions', label: 'Versions', count: versions.length,
                  action: 'name', hint: 'The builds a component ships. An SBOM attaches to the version, not to the environment.',
                  open: { kind: 'version' } },
                { key: 'deployments', label: 'Environments', count: deployments.length,
                  action: 'deploy', hint: 'Which version runs in DEV, PRE and PRO, and whether it faces the internet.',
                  open: { kind: 'deployment' } },
                { key: 'assets', label: 'Assets', count: assets.length,
                  action: 'add', hint: 'The domains, URLs and IPs you know of. No scan needed to record them.',
                  open: { kind: 'asset' } },
              ]
              const nextKey = steps.find((step) => !step.count)?.key
              return (
                <ul className="setup-path">
                  {steps.map((step, index) => (
                    <li key={step.key}
                      className={`${step.count ? 'done' : ''} ${nextKey === step.key ? 'next' : ''}`}>
                      <span className="setup-mark">{index + 1}</span>
                      <div>
                        <strong>
                          {step.label}
                          {step.count ? <span className="setup-check"> ✓ recorded</span> : null}
                        </strong>
                        <p>{step.hint}</p>
                      </div>
                      <span className="count">{step.count}</span>
                      <button className={`mini ${nextKey === step.key ? 'primary' : ''}`}
                        onClick={() => setDialog(step.open)}>{step.action}</button>
                    </li>
                  ))}
                </ul>
              )
            })()}
          </Card>}

          <Card title="Running now"
            actions={<div className="row">
              <button className="mini" onClick={() => setReleaseOpen(true)}>
                new environment
              </button>
            </div>}>
            {!deployments.length
              ? <p className="muted">
                Nothing deployed yet. Pick a version and an environment — a deployment is
                only "where this build runs".
              </p>
              : (
                <table>
                  <thead><tr><th>environment</th><th>component</th><th>version</th>
                    <th>domains</th><th>exposure</th></tr></thead>
                  <tbody>
                    {deployments.map((row) => (
                      <tr key={row.id}>
                        <td className="title">{row.environment}</td>
                        <td>{row.component || '—'}</td>
                        <td className="mono">{row.version_label || <span className="muted">unknown</span>}</td>
                        <td>
                          {(row.domains || []).map((domain) => (
                            <span className="pill mono" key={domain}
                              style={{ marginRight: 4 }}>{domain}</span>
                          ))}
                          {!(row.domains || []).length && <span className="muted">—</span>}
                        </td>
                        <td><span className={`pill ${row.exposure === 'public' ? 'warn' : ''}`}>{row.exposure}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            <ProjectRuntimeGraph data={data} />
          </Card>
        </>
      )}

      {tab === 'components' && (
        <>
          <NeedsAttribution intakes={pendingAttributions} components={components} versions={versions}
            busy={busy} onAssign={assignAttribution} />
          <Card title="Components"
            actions={(
              <div className="row">
                <button className="mini" onClick={() => expandAll(components.map((row) => row.id))}>
                  expand all
                </button>
                <button className="mini" onClick={collapseAll}>collapse all</button>
                <button className="mini" onClick={() => setDialog({ kind: 'component' })}>
                  add component
                </button>
              </div>
            )}>
            {!components.length ? (
              <div className="onb-empty-state" style={{ padding: '20px 16px 24px' }}>
                <h2>No components yet</h2>
                <p>
                  A component is one deployable unit — backend, web, iOS. It is optional:
                  a site with no code of yours lives as a domain only, under Assets.
                </p>
                <button className="btn-primary" onClick={() => setDialog({ kind: 'component' })}>
                  add the first component
                </button>
              </div>
            ) : (
              <>
              <p className="version-legend muted">
                <span className="version-legend-bar" aria-hidden="true">
                  <i className="sev-bar-critical" /><i className="sev-bar-high" />
                  <i className="sev-bar-medium" /><i className="sev-bar-low" />
                </span>
                bar = that build's open dependency findings, worst first
                (critical, high, medium, low) · the code and secrets columns are
                source findings, from SAST and the secret scanner · newest build first
              </p>
              <div className="component-tree">
                {components.map((component) => {
                  const componentVersions = versions.filter(
                    (row) => row.component_id === component.id)
                  const latest = componentVersions[0]
                  const isOpen = openComponents.has(component.id)
                  const shown = shownVersions[component.id] || 5
                  const visible = componentVersions.slice(0, shown)
                  const hidden = Math.max(0, componentVersions.length - visible.length)
                  return (
                    <section className={`component-block${isOpen ? ' open' : ''}`} key={component.id}>
                      <header className="component-head">
                        <button type="button" className="component-toggle"
                          aria-expanded={isOpen}
                          onClick={() => toggleComponent(component.id)}>
                          <span className="caret" aria-hidden="true">{isOpen ? '▾' : '▸'}</span>
                          <span className="component-ident">
                            <h3>{component.name}</h3>
                            <span className="muted component-sub">
                              {plural(componentVersions.length, 'version')}
                              {component.kind && component.kind.toLowerCase()
                                !== component.name.toLowerCase()
                                ? ` · ${component.kind}` : ''}
                              {component.repositories.length
                                ? ` · ${plural(component.repositories.length, 'repository', 'repositories')}`
                                : ' · no code'}
                            </span>
                          </span>
                        </button>
                        <div className="row component-actions">
                          {latest && (
                            <span className="component-summary"
                              title={`newest build: ${latest.version}`}>
                              {latest.sbom_imports ? (
                                <>
                                  <SeverityBar counts={latest.findings?.by_severity} width={72} />
                                  <span className="muted">
                                    {shortLabel(latest.version)} · {latest.findings?.vulns || 0} vulns
                                    {latest.findings?.code ? ` · ${latest.findings.code} code` : ''}
                                    {latest.findings?.secrets ? ` · ${latest.findings.secrets} secrets` : ''}
                                  </span>
                                </>
                              ) : (
                                <span className="muted">
                                  {shortLabel(latest.version)} · not analysed
                                </span>
                              )}
                            </span>
                          )}
                          <button className="mini"
                            onClick={() => setDialog({ kind: 'version', presetComponent: component.id })}>
                            new version
                          </button>
                        </div>
                      </header>

                      {isOpen && (
                        <>
                          {component.repositories.length > 0 ? (
                            <ul className="component-repos">
                              {component.repositories.map((repo) => (
                                <li key={repo.id}>
                                  <span className="repo-name">{repo.name}</span>
                                  <span className="muted">{repo.provider}</span>
                                  {repo.remote_url && (
                                    <a className="repo-remote mono" href={repo.remote_url}
                                      target="_blank" rel="noreferrer">{repo.remote_url}</a>
                                  )}
                                  {repo.last_commit_sha && (
                                    <span className="muted mono">
                                      {String(repo.last_commit_sha).slice(0, 7)}
                                    </span>
                                  )}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <button className="mini component-attach"
                              onClick={() => setDialog({ kind: 'repository', presetComponent: component.id })}>
                              attach code
                            </button>
                          )}

                          {componentVersions.length ? (
                            <>
                              <table className="version-tree">
                                <thead>
                                  <tr>
                                    <th>version</th>
                                    <th>deployed</th>
                                    <th>inventory</th>
                                    <th title="open dependency findings on this build">vulns</th>
                                    <th className="num"
                                      title="code weaknesses reported by a SAST run on this build">code</th>
                                    <th className="num"
                                      title="leaked credentials reported by a secret scanner on this build">secrets</th>
                                    <th className="num"
                                      title="record which environment this build runs in">deploy</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {visible.map((version) => {
                                    const counts = version.findings || {}
                                    return (
                                      <tr key={version.id}>
                                        <td className="mono version-label">
                                          <button className="version-open" title={version.version}
                                            onClick={() => onOpenVersion?.(
                                              project.slug, component.slug || component.name,
                                              version.version)}>
                                            {shortLabel(version.version)}
                                          </button>
                                          {version.baseline && <span className="pill version-baseline">baseline</span>}
                                        </td>
                                        <td className="version-envs">
                                          {version.deployments.length
                                            ? version.deployments.map((dep) => (
                                              <span className="pill env-pill" key={dep.deployment_id}>
                                                {dep.environment}
                                              </span>
                                            ))
                                            : <span className="muted">—</span>}
                                        </td>
                                        <td>
                                          <div className="version-inventory">
                                            {version.sbom_imports ? (
                                              <>
                                                <span>{version.components} components</span>
                                                <span className="muted">
                                                  {plural(version.sbom_imports, 'SBOM import')}
                                                </span>
                                              </>
                                            ) : (
                                              <span className="muted"
                                                title="no BOM was imported for this label: the build exists, its contents do not">
                                                no BOM
                                              </span>
                                            )}
                                          </div>
                                        </td>
                                        <td>
                                          {/* A build with no BOM was never analysed:
                                              a 0 here would read as "clean". */}
                                          {version.sbom_imports ? (
                                            <div className="version-findings">
                                              <SeverityBar counts={counts.by_severity} />
                                              <span className={counts.vulns ? 'version-count' : 'muted'}>
                                                {counts.vulns || 0}
                                              </span>
                                            </div>
                                          ) : (
                                            <span className="muted"
                                              title="nothing imported for this label, so nothing has been analysed">
                                              not analysed
                                            </span>
                                          )}
                                          {counts.dismissed > 0 && (
                                            <div className="muted version-settled"
                                              title="settled findings are listed on the build, and do not count as open">
                                              {counts.dismissed} settled · not counted
                                            </div>
                                          )}
                                        </td>
                                        <td className="num">
                                          {counts.code
                                            ? <span className="version-count">{counts.code}</span>
                                            : <span className="muted">—</span>}
                                        </td>
                                        <td className="num">
                                          {counts.secrets
                                            ? <span className="version-count">{counts.secrets}</span>
                                            : <span className="muted">—</span>}
                                        </td>
                                        <td className="row version-actions">
                                          <button className="mini"
                                            onClick={() => setDialog({
                                              kind: 'deployment', presetComponent: component.id,
                                              presetVersion: version.version,
                                            })}>
                                            deploy
                                          </button>
                                        </td>
                                      </tr>
                                    )
                                  })}
                                </tbody>
                              </table>
                              {(hidden > 0 || shown > 5) && (
                                <div className="version-pager">
                                  {hidden > 0 && (
                                    <button className="mini"
                                      onClick={() => setShownVersions((current) => ({
                                        ...current, [component.id]: shown + 5,
                                      }))}>
                                      show {hidden} more
                                    </button>
                                  )}
                                  {shown > 5 && hidden > 0 && (
                                    <button className="mini"
                                      onClick={() => setShownVersions((current) => ({
                                        ...current, [component.id]: componentVersions.length,
                                      }))}>
                                      show all {componentVersions.length}
                                    </button>
                                  )}
                                  {shown > 5 && hidden === 0 && (
                                    <button className="mini"
                                      onClick={() => setShownVersions((current) => ({
                                        ...current, [component.id]: 5,
                                      }))}>
                                      show newest 5
                                    </button>
                                  )}
                                </div>
                              )}
                            </>
                          ) : (
                            <p className="muted component-empty">
                              No version named yet — a version is a build, it does not need
                              an environment to exist.
                            </p>
                          )}
                        </>
                      )}
                    </section>
                  )
                })}

                {versions.some((row) => !row.component_id) && (
                  <section className={`component-block product-wide${openComponents.has('__wide') ? ' open' : ''}`}>
                    <header className="component-head">
                      <button type="button" className="component-toggle"
                        aria-expanded={openComponents.has('__wide')}
                        onClick={() => toggleComponent('__wide')}>
                        <span className="caret" aria-hidden="true">
                          {openComponents.has('__wide') ? '▾' : '▸'}
                        </span>
                        <span className="component-ident">
                          <h3>Product-wide releases</h3>
                          <span className="muted component-sub">versions named without a component</span>
                        </span>
                      </button>
                    </header>
                    {openComponents.has('__wide') && (
                      <table className="version-tree">
                        <thead><tr><th>version</th><th>runs in</th><th></th></tr></thead>
                        <tbody>
                          {versions.filter((row) => !row.component_id).map((version) => (
                            <React.Fragment key={version.id}>
                            <tr>
                              <td className="mono version-label">
                                {version.version}
                                {version.sbom_imports ? (
                                  <span className="version-note">
                                    {plural(version.sbom_imports, 'SBOM import')}
                                  </span>
                                ) : null}
                              </td>
                              <td>
                                {version.deployments.length
                                  ? version.deployments.map((dep) => (
                                    <span className="pill env-pill" key={dep.deployment_id}>
                                      {dep.environment}
                                    </span>
                                  ))
                                  : <span className="muted">not deployed</span>}
                              </td>
                              <td />
                            </tr>

                            </React.Fragment>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </section>
                )}
              </div>
              </>
            )}
          </Card>

        </>
      )}

      {tab === 'environments' && (
        <>
          <Card title="Environments"
            actions={<button className="mini"
              onClick={() => setReleaseOpen(true)}>new environment</button>}>
            {!deployments.length
              ? <p className="muted">
                No environment yet. A deployment is a version of a component running
                somewhere — DEV, PRE, PRO — with its domain.
              </p>
              : (
                <table>
                  <thead><tr><th>environment</th><th>component</th><th>version</th><th>domains</th>
                    <th>exposure</th><th>auth</th><th>version check</th><th>actions</th></tr></thead>
                  <tbody>
                    {deployments.map((row) => (
                      <tr key={row.id}>
                        <td className="title">{row.environment}</td>
                        <td>{row.component || '—'}</td>
                        <td className="mono">
                          {row.version_label || <span className="muted">unknown</span>}
                          <span className="muted" style={{ marginLeft: 6, fontSize: 10 }}>
                            · {row.source}{row.source === 'health' ? ' check' : ''}
                          </span>
                        </td>
                        <td>
                          {(row.domains || []).map((domain) => (
                            <span className="pill mono" key={domain}
                              style={{ marginRight: 4 }}>{domain}</span>
                          ))}
                          {!(row.domains || []).length && (
                            <button className="mini"
                              onClick={() => setDialog({ kind: 'asset', presetDeployment: row.id })}>
                              add domain
                            </button>
                          )}
                        </td>
                        <td><span className={`pill ${row.exposure === 'public' ? 'warn' : ''}`}>{row.exposure}</span></td>
                        <td className="muted">{row.requires_auth ? 'required' : 'no'}</td>
                        <td className="muted">
                          {row.probe
                            ? (row.probe.enabled
                              ? (row.last_checked_at
                                ? `${row.last_check_status === 'ok' ? 'ok' : 'failed'} · ${new Date(row.last_checked_at).toLocaleString()}`
                                : 'configured, not run')
                              : 'disabled')
                            : 'not configured'}
                          {row.probe && row.probe.enabled && (
                            <div style={{ fontSize: 11 }}>
                              {cadence(row.probe.interval_minutes)}
                              {row.probe.next_due_at ? ` · ${dueLabel(row.probe.next_due_at)}` : ''}
                            </div>
                          )}
                          {row.last_check_error && (
                            <div style={{ color: 'var(--critical)', fontSize: 11 }}>{row.last_check_error}</div>
                          )}
                        </td>
                        <td>
                          <div className="row">
                            <button className="mini" onClick={() => setDialog({ kind: 'edit', row })}>edit</button>
                            <button className="mini" onClick={() => setDialog({ kind: 'probe', row })}>
                              probe
                            </button>
                            {row.probe && (
                              <button className="mini" disabled={busy === `check:${row.id}`}
                                onClick={() => act(`check:${row.id}`,
                                  () => api.post(`/api/v1/deployments/${row.id}/health/check`),
                                  `Version read from ${row.probe.url}.`)}>
                                {busy === `check:${row.id}` ? 'checking…' : 'check now'}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
          </Card>
          <p className="muted" style={{ fontSize: 12 }}>
            <strong>probe</strong> configures the read-only GET against the deployment's own
            endpoint (for example <code>https://api.example/health</code>); <strong>check now</strong>
            {' '}runs it immediately and records the version. It needs no scan authorization, and
            the token, when there is one, is stored encrypted and never shown again.
          </p>
        </>
      )}

      {tab === 'assets' && (
        <ProjectVerification slug={project.slug}
          onAdd={() => setDialog({ kind: 'asset' })}
          onOpenGrants={() => onNavigate && onNavigate('grants')} />
      )}

      <ReleaseDialog open={releaseOpen} onClose={() => setReleaseOpen(false)}
        slug={project.slug} components={components} versions={versions} assets={assets}
        onDone={(message) => { setNotice(`Created ${message}.`); load() }} />

      <ProjectDialogs dialog={dialog} setDialog={setDialog} project={project}
        components={components} deployments={deployments} assets={assets}
        versions={versions}
        onChanged={load} notify={(message) => setNotice(message)}
        onDone={(message) => { setDialog(null); setNotice(message || ''); load() }} />
    </div>
  )
}

/* ───────────────────────── dialogs ───────────────────────── */

function ProjectDialogs({ dialog, setDialog, project, components, deployments = [],
                         assets = [], versions = [], onDone, onChanged, notify }) {
  const [form, setForm] = useState({})
  const [error, setError] = useState('')
  const [localError, setLocalError] = useState('')
  const [busy, setBusy] = useState('')
  const [remoteRepos, setRemoteRepos] = useState(null)

  useEffect(() => {
    if (!dialog) return
    setLocalError('')
    if (dialog.presetComponent || dialog.presetVersion) {
      // "deploy" on a version row carries both: the component and which version.
      const known = dialog.presetVersion
        ? versions.find((row) => row.version === dialog.presetVersion
          && (!dialog.presetComponent || row.component_id === dialog.presetComponent))
        : null
      setForm({
        component_id: dialog.presetComponent || known?.component_id || '',
        version_id: known?.id || '',
      })
      setError('')
      setRemoteRepos(null)
      return
    }
    if (dialog.presetDeployment) {
      const deployment = deployments.find((row) => row.id === dialog.presetDeployment)
      setForm({ deployment_id: dialog.presetDeployment,
        component_id: deployment?.component_id || '' })
      setError('')
      setRemoteRepos(null)
      return
    }
    if (!dialog.row) { setForm({}); setError(''); setRemoteRepos(null); return }
    const row = dialog.row
    if (dialog.kind === 'edit') {
      setForm({ environment: row.environment, version_id: row.version_id || '',
        exposure: row.exposure, requires_auth: row.requires_auth })
    }
    if (dialog.kind === 'version-rename') {
      setForm({ version: row.version })
    }
    if (dialog.kind === 'probe') {
      setForm({ url: row.probe?.url || '', token: '',
        version_path: row.probe?.version_path || 'auto',
        status_path: row.probe?.status_path || 'status',
        enabled: row.probe?.enabled ?? true,
        interval_minutes: row.probe?.interval_minutes || 0 })
    }
  }, [dialog])

  if (!dialog) return null
  const close = () => setDialog(null)

  async function submit(work, message) {
    setBusy('save')
    setError('')
    try {
      await work()
      onDone(message)
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  // Small mutations stay inside the dialog: refresh the parent, say what happened.
  async function actOn(asset, work) {
    setBusy(asset.id)
    setLocalError('')
    try {
      await work()
      await onChanged?.()
      notify?.(`${asset.value} updated in ${dialog.row?.environment || 'this environment'}.`)
    } catch (e) {
      setLocalError(String(e.message || e))
    } finally { setBusy('') }
  }

  async function loadRemoteRepositories() {
    setError('')
    try {
      const connections = await api.get('/api/v1/onboarding/connections')
      const scm = (connections.data?.scm || [])[0]
      if (!scm) { setError('No code host connected. Connect one in Settings first.'); return }
      const listed = await api.get(`/api/v1/onboarding/connections/${scm.id}/repositories`)
      setRemoteRepos(listed.data || [])
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  if (dialog.kind === 'version') {
    return (
      <Dialog open hideFooter title="New version" onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          const label = (form.version || '').trim()
          if (components.length && !form.component_id) {
            setError('Choose the component this version belongs to.')
            return
          }
          if (!label) {
            setError('Name the version: 1.8, 2026.02, release-42…')
            return
          }
          submit(() => api.post(`/api/v1/projects/${project.slug}/versions`, {
            version: label, component_id: form.component_id || undefined,
            actor: 'console' }), `Version ${label} created.`) }}>
          <p className="onb-help" style={{ margin: 0 }}>
            A version belongs to one component. It exists before any environment runs it,
            and an SBOM uploaded for it attaches here.
          </p>
          {components.length ? (
            <label>
              Component
              <select autoFocus value={form.component_id || ''}
                onChange={(e) => setForm({ ...form, component_id: e.target.value })}>
                <option value="">choose…</option>
                {components.map((component) => (
                  <option key={component.id} value={component.id}>{component.name}</option>
                ))}
              </select>
              <span className="onb-help">The code unit that ships this build.</span>
            </label>
          ) : null}
          <label>
            Version
            <input autoFocus={!components.length} value={form.version || ''} placeholder="1.8"
              onChange={(e) => setForm({ ...form, version: e.target.value })} />
            <span className="onb-help">
              Used by the SBOM upload and by every deployment of this build.
            </span>
          </label>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? 'creating…' : 'create version'}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'version-rename') {
    const row = dialog.row
    return (
      <Dialog open hideFooter title={`Rename ${row.version}`} onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          const label = (form.version || '').trim()
          if (!label) { setError('Give the version a name.'); return }
          submit(() => api.patch(
            `/api/v1/projects/${project.slug}/versions/${encodeURIComponent(row.version)}`
            + (row.component_id ? `?component_id=${row.component_id}` : ''),
            { version: label }), `Version renamed to ${label}.`) }}>
          <p className="onb-help" style={{ margin: 0 }}>
            Renaming keeps its SBOM and every deployment that runs it — they follow the
            new label.
          </p>
          <label>
            Version
            <input autoFocus value={form.version ?? row.version}
              onChange={(e) => setForm({ ...form, version: e.target.value })} />
            <span className="onb-help">
              {row.component || 'product-wide'}
              {row.deployments?.length
                ? ` · runs in ${row.deployments.map((use) => use.environment).join(', ')}`
                : ' · not deployed'}
            </span>
          </label>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? 'saving…' : 'rename'}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'asset') {
    return (
      <Dialog open hideFooter title="Add asset" onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          if (!(form.value || '').trim()) {
            setError('Give the asset a value: a domain, a URL or an IP.')
            return
          }
          submit(() => api.post(`/api/v1/projects/${project.slug}/assets`, {
            type: form.type || 'domain', value: form.value.trim(),
            component_id: form.component_id || undefined,
            deployment_id: form.deployment_id || undefined,
            notes: form.notes || undefined, actor: 'console' }),
            `${form.value.trim()} recorded under ${project.name}.`) }}>
          <p className="onb-help" style={{ margin: 0 }}>
            Record a domain, URL or IP you know of. Nothing is contacted: recording an
            asset never authorizes a scan.
          </p>
          <div className="onb-grid">
            <label>
              Type
              <select value={form.type || 'domain'}
                onChange={(e) => setForm({ ...form, type: e.target.value })}>
                {ASSET_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
              </select>
            </label>
            <label>
              Value
              <input autoFocus value={form.value || ''} placeholder="app.example.com"
                onChange={(e) => setForm({ ...form, value: e.target.value })} />
            </label>
          </div>
          <div className="onb-grid">
            <label>
              Environment <span className="onb-optional">optional</span>
              <select value={form.deployment_id || ''}
                onChange={(e) => {
                  const deployment = deployments.find((row) => row.id === e.target.value)
                  setForm({ ...form, deployment_id: e.target.value,
                    component_id: deployment?.component_id || form.component_id || '' })
                }}>
                <option value="">no environment</option>
                {deployments
                  .filter((row) => !form.component_id || row.component_id === form.component_id)
                  .map((row) => (
                    <option key={row.id} value={row.id}>
                      {(row.component || 'unassigned') + ' · ' + row.environment}
                    </option>
                  ))}
              </select>
              <span className="onb-help">DEV, PRE, PRO… where it answers.</span>
            </label>
            <label>
              Component <span className="onb-optional">optional</span>
              <select value={form.component_id || ''}
                onChange={(e) => setForm({ ...form, component_id: e.target.value,
                  deployment_id: '' })}>
                <option value="">project only — no code component</option>
                {components.map((component) => (
                  <option key={component.id} value={component.id}>{component.name}</option>
                ))}
              </select>
              <span className="onb-help">A WordPress site can skip it.</span>
            </label>
          </div>
          <label>
            Notes <span className="onb-optional">optional</span>
            <input value={form.notes || ''} placeholder="Staging storefront, vendor hosted"
              onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          </label>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? 'saving…' : 'add asset'}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'component') {
    return (
      <Dialog open hideFooter title="Add component" onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          if (!(form.name || '').trim()) {
            setError('Give the component a name: Backend, Web, iOS…')
            return
          }
          submit(() => api.post(`/api/v1/projects/${project.slug}/components`, {
            name: form.name.trim(), kind: form.kind || 'backend', actor: 'console' }),
            `Component ${form.name.trim()} added.`) }}>
          <div className="onb-grid">
            <label>
              Name
              <input autoFocus value={form.name || ''} placeholder="Backend"
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </label>
            <label>
              Kind
              <select value={form.kind || 'backend'}
                onChange={(e) => setForm({ ...form, kind: e.target.value })}>
                {COMPONENT_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
              </select>
            </label>
          </div>
          <span className="onb-help">
            A part of the product: backend, web, iOS… A site with no code of yours can live
            as a domain instead.
          </span>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? 'saving…' : 'add component'}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'repository') {
    return (
      <Dialog open hideFooter title="Attach repository" onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          if (!(form.remote_url || '').trim()) {
            setError('Paste the repository URL, or pick one from the code host.')
            return
          }
          submit(() => api.post(`/api/v1/projects/${project.slug}/repositories`, {
            remote_url: form.remote_url.trim(),
            component_id: form.component_id || undefined,
            actor: 'console' }), 'Repository attached to the project.') }}>
          <label>
            Remote URL
            <input autoFocus value={form.remote_url || ''}
              placeholder="https://gitea.example/bitsentry/aurea-api.git"
              onChange={(e) => setForm({ ...form, remote_url: e.target.value })} />
          </label>
          <label>
            Component <span className="onb-optional">optional</span>
            <select value={form.component_id || ''}
              onChange={(e) => setForm({ ...form, component_id: e.target.value })}>
              <option value="">project only</option>
              {components.map((component) => (
                <option key={component.id} value={component.id}>{component.name}</option>
              ))}
            </select>
            <span className="onb-help">Which unit builds from this code.</span>
          </label>
          <button type="button" className="mini" onClick={loadRemoteRepositories}>
            list from the connected code host
          </button>
          {remoteRepos && (
            <div className="onb-repo-list">
              {!remoteRepos.length && <p className="muted">The token sees no repository.</p>}
              {remoteRepos.map((repo) => (
                <button type="button" key={repo.url} className="onb-repo-row"
                  onClick={() => setForm({ ...form, remote_url: repo.url })}>
                  <span>{repo.name}</span>
                  <span className="muted">{repo.private ? 'private' : 'public'}</span>
                </button>
              ))}
            </div>
          )}
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? 'attaching…' : 'attach'}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'deployment') {
    const suggested = [...new Set(['DEV', 'PRE', 'PRO', 'STAGING',
      ...deployments.map((row) => row.environment)])]
    const componentVersions = versions.filter(
      (row) => row.component_id === form.component_id)
    const creatingVersion = form.version_choice === '__new'
      || Boolean(form.component_id && !componentVersions.length)
    return (
      <Dialog open hideFooter title="Deploy a version" onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          const environment = (form.environment || '').trim()
          const domain = (form.domain || '').trim()
          if (!form.component_id) {
            setError('Choose the component being deployed.')
            return
          }
          if (environment.length < 2) {
            setError('Name the environment: DEV, PRE, PRO…')
            return
          }
          if (creatingVersion && !(form.version_label || '').trim()) {
            setError('Name the version being deployed, or pick an existing one.')
            return
          }
          submit(async () => {
            const created = await api.post(`/api/v1/projects/${project.slug}/deployments`, {
              component_id: form.component_id,
              environment,
              version_id: creatingVersion ? undefined : (form.version_id || undefined),
              version_label: creatingVersion ? form.version_label.trim() : undefined,
              exposure: form.exposure || 'unknown',
              requires_auth: Boolean(form.requires_auth), actor: 'console' })
            if (domain) {
              await api.post(`/api/v1/projects/${project.slug}/assets`, {
                type: 'domain', value: domain, deployment_id: created.data.id,
                actor: 'console' })
            }
          }, domain ? `${environment} deployed with ${domain}.`
            : `${environment} deployed.`)
        }}>
          <div className="onb-grid">
            <label>
              Component
              <select autoFocus value={form.component_id || ''}
                onChange={(e) => setForm({ ...form, component_id: e.target.value,
                  version_id: '', version_choice: '', version_label: '' })}>
                <option value="">choose…</option>
                {components.map((component) => (
                  <option key={component.id} value={component.id}>{component.name}</option>
                ))}
              </select>
            </label>
            <label>
              Environment
              <input value={form.environment || ''} placeholder="PRO" list="env-options"
                onChange={(e) => setForm({ ...form, environment: e.target.value })} />
              <datalist id="env-options">
                {suggested.map((name) => <option key={name} value={name} />)}
              </datalist>
              <span className="onb-help">DEV, PRE, PRO, STAGING… the name the team uses.</span>
            </label>
          </div>

          <label>
            Version
            {!creatingVersion ? (
              <select value={form.version_id || ''}
                onChange={(e) => {
                  if (e.target.value === '__new') {
                    setForm({ ...form, version_choice: '__new', version_id: '' })
                  } else {
                    setForm({ ...form, version_id: e.target.value, version_choice: '' })
                  }
                }}>
                <option value="">choose a version…</option>
                {componentVersions.map((row) => (
                  <option key={row.id} value={row.id}>
                    {row.version}{row.sbom_imports ? ' · SBOM' : ''}
                    {row.deployments.length ? ' · already running' : ''}
                  </option>
                ))}
                <option value="__new">＋ a version that does not exist yet…</option>
              </select>
            ) : (
              <input value={form.version_label || ''} placeholder="1.8"
                onChange={(e) => setForm({ ...form, version_label: e.target.value })} />
            )}
            <span className="onb-help">
              {creatingVersion
                ? 'A new version of this component, created with the deployment.'
                : 'The version being deployed. Its SBOM lives on the Versions tab.'}
            </span>
          </label>

          <label>
            Domain <span className="onb-optional">optional</span>
            <input value={form.domain || ''} placeholder="api.aurea.example"
              onChange={(e) => setForm({ ...form, domain: e.target.value })} />
            <span className="onb-help">
              The hostname that answers in this environment. Recorded with the deployment;
              nothing is contacted.
            </span>
          </label>

          <label className="onb-check">
            <input type="checkbox" checked={Boolean(form.requires_auth)}
              onChange={(e) => setForm({ ...form, requires_auth: e.target.checked })} />
            requires authentication
          </label>

          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? 'deploying…' : 'deploy'}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'edit') {
    const row = deployments.find((item) => item.id === dialog.row?.id) || dialog.row
    const domains = assets.filter((asset) => asset.deployment_id === row.id)
    const unattached = assets.filter((asset) => !asset.deployment_id)
    const componentVersions = versions.filter(
      (version) => version.component_id === row.component_id)
    return (
      <Dialog open hideFooter
        title={`Environment · ${row.component || 'unassigned'} · ${row.environment}`}
        onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          if ((form.environment ?? row.environment ?? '').trim().length < 2) {
            setError('Name the environment: DEV, PRE, PRO…')
            return
          }
          submit(() => api.patch(`/api/v1/deployments/${row.id}`, {
            environment: (form.environment ?? row.environment).trim(),
            version_id: form.version_id || undefined,
            exposure: form.exposure || 'unknown',
            requires_auth: Boolean(form.requires_auth), actor: 'console' }),
            `${form.environment || row.environment} updated.`) }}>
          <div className="onb-grid">
            <label>
              Environment
              <input autoFocus value={form.environment ?? row.environment} placeholder="PRO"
                onChange={(e) => setForm({ ...form, environment: e.target.value })} />
              <span className="onb-help">Renaming keeps the version and its domains.</span>
            </label>
            <label>
              Version
              <select value={form.version_id || ''}
                onChange={(e) => setForm({ ...form, version_id: e.target.value })}>
                <option value="">keep {row.version_label || 'none'}</option>
                {componentVersions.map((version) => (
                  <option key={version.id} value={version.id}>{version.version}</option>
                ))}
              </select>
              <span className="onb-help">What this environment runs.</span>
            </label>
            <label>
              Exposure
              <select value={form.exposure || 'unknown'}
                onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
                {EXPOSURES.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
              <span className="onb-help">Does the internet reach it?</span>
            </label>
            <label className="onb-check">
              <input type="checkbox" checked={Boolean(form.requires_auth)}
                onChange={(e) => setForm({ ...form, requires_auth: e.target.checked })} />
              requires authentication
            </label>
          </div>

          <div className="onb-inline-section">
            <span className="onb-section-label">Domains in this environment</span>
            {!domains.length && (
              <p className="onb-help" style={{ margin: 0 }}>
                No domain yet. A domain is what a scan can reach; a version alone is not.
              </p>
            )}
            {domains.map((asset) => (
              <div className="row-between" key={asset.id}>
                <span className="mono">{asset.value}</span>
                <button className="mini" type="button" disabled={busy === asset.id}
                  onClick={() => actOn(asset, () => api.del(
                    `/api/v1/assets/${asset.id}/links/${asset.deployment.link_id}`))}>
                  {busy === asset.id ? 'removing…' : 'unlink'}
                </button>
              </div>
            ))}
            {unattached.length > 0 && (
              <label>
                Attach an existing asset
                <select value="" onChange={(e) => {
                  const asset = unattached.find((item) => item.id === e.target.value)
                  if (!asset) return
                  actOn(asset, () => api.post(`/api/v1/projects/${project.slug}/assets`, {
                    type: asset.type, value: asset.value, deployment_id: row.id,
                    actor: 'console' }))
                }}>
                  <option value="">choose an asset…</option>
                  {unattached.map((asset) => (
                    <option key={asset.id} value={asset.id}>
                      {asset.value} · {asset.type}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <button className="mini" type="button"
              onClick={() => setDialog({ kind: 'asset', presetDeployment: row.id })}>
              add a new domain
            </button>
          </div>

          {localError && <p className="banner banner-error">{localError}</p>}
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? 'saving…' : 'save changes'}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'probe') {
    const row = dialog.row
    return (
      <Dialog open hideFooter
        title={`Version probe · ${row.component || ''} ${row.environment}`}
        onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          submit(() => api.put(`/api/v1/deployments/${row.id}/health-probe`, {
            url: form.url, token: form.token || undefined,
            version_path: form.version_path || 'auto',
            status_path: form.status_path || 'status',
            enabled: form.enabled !== false,
            interval_minutes: Number(form.interval_minutes) || 0,
            actor: 'console' }), 'Probe saved. Run “check now” to read the version.') }}>
          <p className="onb-help" style={{ margin: 0 }}>
            A GET against the deployment's own endpoint. Nothing is written to it.
          </p>
          <label>
            Health URL
            <input autoFocus value={form.url || ''} placeholder="https://api.aurea.example/health"
              onChange={(e) => setForm({ ...form, url: e.target.value })} />
          </label>
          <label>
            Bearer token <span className="onb-optional">optional</span>
            <input type="password" value={form.token || ''}
              placeholder={row.probe?.token_set ? 'stored — leave blank to keep it' : 'not set'}
              onChange={(e) => setForm({ ...form, token: e.target.value })} />
          </label>
          <div className="onb-grid">
            <label>
              Version field
              <input value={form.version_path || 'auto'} placeholder="auto"
                onChange={(e) => setForm({ ...form, version_path: e.target.value })} />
            </label>
            <label>
              Status field
              <input value={form.status_path || 'status'}
                onChange={(e) => setForm({ ...form, status_path: e.target.value })} />
            </label>
          </div>
          <label>
            Check every
            <select value={String(form.interval_minutes ?? 0)}
              onChange={(e) => setForm({ ...form, interval_minutes: e.target.value })}>
              <option value="0">manually only — I press “check now”</option>
              <option value="15">every 15 minutes</option>
              <option value="60">hourly</option>
              <option value="360">every 6 hours</option>
              <option value="1440">daily</option>
            </select>
            <span className="onb-optional">
              automatic runs come from the scheduler tick — see Operations
            </span>
          </label>
          <label className="onb-check">
            <input type="checkbox" checked={form.enabled !== false}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
            enabled
          </label>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>cancel</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? 'saving…' : 'save probe'}
            </button>
          </div>
        </form>
      )} />
    )
  }

  return null
}