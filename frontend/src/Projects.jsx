import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { Card, Dialog, ErrorBanner, Loading, PageHeader, Stat,
  SeverityBadge, Tabs, queueHash } from './ui'
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
  { id: 'projects', labelKey: 'projects.tab.projects' },
  { id: 'pending', labelKey: 'projects.tab.catalogue' },
  { id: 'portfolio', labelKey: 'projects.tab.portfolio' },
]

const COMPONENT_KINDS = ['backend', 'frontend', 'web', 'ios', 'android', 'worker',
  'service', 'library', 'infrastructure', 'other']
const EXPOSURES = ['unknown', 'internal', 'public']
const ASSET_KINDS = ['domain', 'subdomain', 'url', 'ip', 'api', 'mobile_app']

const PROJECT_TABS = [
  { id: 'summary', labelKey: 'projects.tab.summary' },
  { id: 'components', labelKey: 'projects.tab.components' },
  { id: 'environments', labelKey: 'projects.tab.environments' },
  { id: 'assets', labelKey: 'projects.tab.assets' },
]

/* Counts live in the catalogue, not in a suffix: "1 versión" and "3 versiones"
   share a noun but not its plural, and English is not the only language here. */
function unit(tCount, key, count) {
  return tCount(`projects.unit.${key}`, count)
}

function plural(tCount, key, count) {
  return tCount(`projects.count.${key}`, count)
}

function VersionVulnerabilities({ rows }) {
  const { t, tCount } = useI18n()
  if (!rows.length) return null
  return (
    <tr className="version-vulnerabilities"><td colSpan="3">
      <div className="version-vulnerability-list">
        <strong>{plural(tCount, 'vulnerability', rows.length)}</strong>
        {rows.map((row) => (
          <div className="row" key={row.id}>
            <span className="mono">{row.cve_id || row.signature}</span>
            <SeverityBadge severity={row.severity} />
            <span className="muted">{row.title || t('projects.finding.untitled')}</span>
            <span className="count">{plural(tCount, 'openFinding', row.open_findings)}</span>
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
  const { t, tCount } = useI18n()
  const shown = BAR_ORDER.filter((severity) => counts[severity] > 0)
  const total = shown.reduce((sum, severity) => sum + counts[severity], 0)
  if (!total) return <span className="sev-bar is-empty" style={{ width }} title={t('projects.severity.barEmpty')} />
  return (
    <span className="sev-bar" style={{ width }}
      title={shown.map((severity) => tCount(
        `projects.severity.tip.${severity.toLowerCase()}`, counts[severity])).join(' · ')}>
      {shown.map((severity) => (
        <i key={severity} className={`sev-bar-${severity.toLowerCase()}`}
          style={{ flexGrow: counts[severity] }} />
      ))}
    </span>
  )
}

function NeedsAttribution({ intakes, components, versions, busy, onAssign }) {
  const { t, tCount } = useI18n()
  if (!intakes.length) return null
  return (
    <Card title={t('projects.attribution.title')}
      actions={<span className="count">{plural(tCount, 'ciScan', intakes.length)}</span>}>
      <p className="muted attribution-intro">{t('projects.attribution.intro')}</p>
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
  const { t } = useI18n()
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
      setLocalError(t('projects.attribution.chooseComponent'))
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
        <strong className="mono">{subject.repository || t('projects.attribution.repositoryMissing')}</strong>
        <span className="muted">
          {[subject.branch, subject.commit && String(subject.commit).slice(0, 12),
            subject.pull_request && t('projects.attribution.pr', { n: subject.pull_request })]
            .filter(Boolean).join(' · ') || t('projects.attribution.awaitingOwner')}
        </span>
        {subject.version && (
          <span className="pill mono">{t('projects.attribution.reported', { version: subject.version })}</span>
        )}
      </div>
      <form className="attribution-form" onSubmit={submit}>
        <label>
          {t('projects.field.component')}
          <select value={componentId} disabled={busy} onChange={(event) => {
            setComponentId(event.target.value)
            setVersionId('')
          }}>
            <option value="">{t('projects.choose.component')}</option>
            {components.map((component) => (
              <option key={component.id} value={component.id}>
                {component.name}{intake.candidates?.includes(component.id)
                  ? ` · ${t('projects.attribution.suggested')}` : ''}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t('projects.field.version')} <span className="onb-optional">{t('projects.optional')}</span>
          <select value={versionId} disabled={busy || !componentId}
            onChange={(event) => setVersionId(event.target.value)}>
            <option value="">{t('projects.option.noVersion')}</option>
            {componentVersions.map((version) => (
              <option key={version.id} value={version.id}>{version.version}</option>
            ))}
          </select>
        </label>
        <label className="attribution-note">
          {t('projects.field.note')} <span className="onb-optional">{t('projects.optional')}</span>
          <input value={note} disabled={busy} placeholder={t('projects.attribution.notePlaceholder')}
            onChange={(event) => setNote(event.target.value)} />
        </label>
        <button className="btn-primary" type="submit" disabled={busy || !components.length}>
          {busy ? t('projects.action.assigning') : t('projects.action.assign')}
        </button>
      </form>
      {!components.length && (
        <p className="attribution-error">{t('projects.attribution.addComponentFirst')}</p>
      )}
      {localError && <p className="attribution-error" role="alert">{localError}</p>}
    </section>
  )
}

function slugify(value) {
  return (value || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120)
}

// An interval stored in minutes, said the way a person says it.
function cadence(t, minutes) {
  if (!minutes) return t('projects.cadence.manual')
  if (minutes % 1440 === 0) {
    return minutes / 1440 === 1
      ? t('projects.cadence.daily')
      : t('projects.cadence.everyDays', { n: minutes / 1440 })
  }
  if (minutes % 60 === 0) {
    return minutes / 60 === 1
      ? t('projects.cadence.hourly')
      : t('projects.cadence.everyHours', { n: minutes / 60 })
  }
  return t('projects.cadence.everyMinutes', { n: minutes })
}

function dueLabel(t, iso) {
  const ms = new Date(iso).getTime() - Date.now()
  if (!Number.isFinite(ms)) return ''
  if (ms <= 0) return t('projects.due.now')
  const minutes = Math.round(ms / 60000)
  if (minutes < 60) return t('projects.due.minutes', { n: Math.max(minutes, 1) })
  const hours = Math.round(minutes / 60)
  if (hours < 48) return t('projects.due.hours', { n: hours })
  return t('projects.due.days', { n: Math.round(hours / 24) })
}

function fail(setError) {
  return (e) => setError(String(e.message || e))
}

export default function Projects({ onNavigate, slug = '', tab = 'summary',
                                   onOpenProject, onOpenVersion, onProjectTab, onCloseProject }) {
  const { t, tCount } = useI18n()
  const [view, setView] = useState('projects')
  const [list, setList] = useState(null)
  const [pending, setPending] = useState(null)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [busy, setBusy] = useState('')
  // Which rows asked to take their subdomains with them. React state, not a DOM
  // read: an uncontrolled checkbox inside a row that re-renders loses its tick.
  const [withKids, setWithKids] = useState({})
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

  async function fileAsset(asset, projectSlug, includeChildren = false) {
    if (!projectSlug) return
    setBusy(`file:${asset.id}`)
    setError('')
    try {
      await api.post(`/api/v1/assets/${asset.id}/catalog`,
        { project: projectSlug, actor: 'console',
          include_children: Boolean(includeChildren) })
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
        title={t('projects.title')}
        subtitle={t('projects.subtitle')}
        actions={(
          <>
            {(list || []).length > 0 && (
              <button className="btn-primary mini" onClick={() => setCreating(true)}>
                {t('projects.action.newProject')}
              </button>
            )}
            <button className="mini" onClick={() => { loadProjects(); loadPending() }}>
              {t('common.refresh')}
            </button>
          </>
        )}
      />

      <Tabs tabs={TABS.map((entry) => ({ ...entry, label: t(entry.labelKey) }))}
        active={view} onChange={setView} />

      {error && <ErrorBanner error={error} onRetry={() => { loadProjects(); loadPending() }} />}

      {view === 'portfolio' && <ProjectsPortfolio onNavigate={onNavigate} />}

      {view === 'projects' && (
        !list ? <Card><Loading rows={4} /></Card> : (
          <>
            <p className="inventory-summary">
              <strong>{projects.length}</strong> {unit(tCount, 'project', projects.length)} ·
              <strong>{sum(projects, 'components')}</strong> {unit(tCount, 'component', sum(projects, 'components'))} ·
              <strong>{new Set(projects.flatMap((p) => p.counts?.environments || [])).size}</strong> {unit(tCount, 'environment', new Set(projects.flatMap((p) => p.counts?.environments || [])).size)} ·
              <strong>{sum(projects, 'repositories')}</strong> {unit(tCount, 'repository', sum(projects, 'repositories'))} ·
              <strong>{sum(projects, 'assets')}</strong> {unit(tCount, 'asset', sum(projects, 'assets'))}
            </p>

            {!projects.length ? (
              <Card>
                <div className="onb-empty-state">
                  <h2>{t('projects.empty.title')}</h2>
                  <p>{t('projects.empty.body')}</p>
                  <ol className="onb-empty-steps">
                    <li><strong>1.</strong> {t('projects.empty.step1')}</li>
                    <li><strong>2.</strong> {t('projects.empty.step2')}</li>
                    <li><strong>3.</strong> {t('projects.empty.step3')}</li>
                  </ol>
                  <button className="btn-primary" onClick={() => setCreating(true)}>
                    {t('projects.empty.action')}
                  </button>
                </div>
              </Card>
            ) : (
              <Card title={t('projects.inventory.title')}
                actions={(
                  <div className="row">
                    <input placeholder={t('projects.inventory.filter')} value={filter}
                      onChange={(e) => setFilter(e.target.value)} style={{ minWidth: 220 }} />
                    <span className="count">{t('projects.inventory.count', {
                      visible: visible.length, total: projects.length })}</span>
                  </div>
                )}>
                <table>
                  <thead>
                    <tr><th>{t('projects.col.project')}</th><th>{t('projects.col.group')}</th>
                      <th>{t('common.owner')}</th><th>{t('projects.col.components')}</th>
                      <th>{t('projects.col.environments')}</th><th>{t('projects.col.deployments')}</th>
                      <th>{t('projects.col.repositories')}</th><th>{t('projects.col.assets')}</th>
                      <th>{t('common.actions')}</th></tr>
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
                          }}>{t('common.open')}</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!visible.length && (
                  <p className="muted">{t('projects.inventory.noMatch', { filter: filter.trim() })}</p>
                )}
              </Card>
            )}
          </>
        )
      )}

      {view === 'pending' && (
        <>
          <Card title={t('projects.pending.title')}
            actions={<span className="count">
              {pending?.total && pending.total > pendingRows.length
                ? t('projects.pending.showing', { shown: pendingRows.length, total: pending.total })
                : unit(tCount, 'asset', pendingRows.length)}
            </span>}>
            <p className="muted" style={{ marginTop: 0 }}>{t('projects.pending.intro')}</p>
            {!pendingRows.length
              ? <p className="muted">{t('projects.pending.empty')}</p>
              : (
                <table>
                  <thead><tr><th>{t('projects.col.asset')}</th><th>{t('projects.col.type')}</th>
                    <th>{t('common.source')}</th><th>{t('projects.col.discovered')}</th>
                    <th>{t('projects.pending.fileUnder')}</th></tr></thead>
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
                              <option value="">{t('projects.choose.project')}</option>
                              {(pending?.projects || []).map((project) => (
                                <option key={project.id} value={project.slug}>{project.name}</option>
                              ))}
                            </select>
                            {asset.type === 'domain' && (
                              <label className="file-children"
                                     title={t('projects.pending.withKidsHint')}>
                                <input type="checkbox"
                                       checked={Boolean(withKids[asset.id])}
                                       onChange={(event) => setWithKids((state) => ({
                                         ...state, [asset.id]: event.target.checked }))} />
                                {t('projects.pending.withKids')}
                              </label>
                            )}
                            <button className="mini" disabled={busy === `file:${asset.id}`}
                              onClick={() => fileAsset(asset,
                                document.getElementById(`file-${asset.id}`).value,
                                withKids[asset.id])}>
                              {busy === `file:${asset.id}` ? t('projects.action.filing') : t('projects.action.file')}
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
  const { t } = useI18n()
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
      setError(t('projects.error.nameTooShort'))
      return
    }
    if (mode === 'create' && preview.length < 2) {
      setError(t('projects.error.noIdentifier'))
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
    <Dialog open hideFooter
      title={mode === 'create'
        ? t('projects.dialog.newProject')
        : t('projects.dialog.editProject', { name: initial.name })}
      onClose={onClose} body={(
        <form className="onb-form" onSubmit={submit}>
          <p className="onb-help" style={{ margin: 0 }}>{t('projects.form.intro')}</p>

          <div className="onb-grid">
            <label>
              {t('projects.field.projectName')}
              <input autoFocus value={form.name} placeholder="AUREA"
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </label>
            <label>
              {t('projects.field.group')} <span className="onb-optional">{t('projects.optional')}</span>
              <input value={form.group} placeholder="Bitsentry" list="project-groups"
                onChange={(e) => setForm({ ...form, group: e.target.value })} />
              <datalist id="project-groups">
                {groups.map((group) => <option key={group} value={group} />)}
              </datalist>
              <span className="onb-help">{t('projects.field.groupHint')}</span>
            </label>
            <label>
              {t('projects.field.owner')} <span className="onb-optional">{t('projects.optional')}</span>
              <input value={form.owner} placeholder="ana@bitsentry.xyz"
                onChange={(e) => setForm({ ...form, owner: e.target.value })} />
              <span className="onb-help">{t('projects.field.ownerHint')}</span>
            </label>
            <label>
              {t('projects.field.identifier')}
              <input value={mode === 'create' ? form.slug : preview} readOnly={mode === 'edit'}
                placeholder={slugify(form.name) || 'aurea'}
                onChange={(e) => setForm({ ...form, slug: slugify(e.target.value) })} />
              <span className="onb-help">
                {mode === 'create'
                  ? t('projects.field.identifierHintNew', { slug: preview || '…' })
                  : t('projects.field.identifierHintEdit')}
              </span>
            </label>
          </div>

          <label>
            {t('projects.field.description')} <span className="onb-optional">{t('projects.optional')}</span>
            <textarea rows={2} value={form.description}
              placeholder={t('projects.field.descriptionPlaceholder')}
              onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </label>

          {mode === 'create' && (
            <div className="onb-inline-section">
              <span className="onb-section-label">{t('projects.form.firstComponent')}</span>
              <div className="onb-grid">
                <label>
                  {t('projects.field.name')}
                  <input value={form.componentName} placeholder="Backend"
                    onChange={(e) => setForm({ ...form, componentName: e.target.value })} />
                </label>
                <label>
                  {t('projects.field.componentKind')}
                  <select value={form.componentKind}
                    onChange={(e) => setForm({ ...form, componentKind: e.target.value })}>
                    {COMPONENT_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
                  </select>
                </label>
              </div>
              <span className="onb-help">{t('projects.form.kindHint')}</span>
            </div>
          )}

          {error && <p className="banner banner-error" role="alert">{error}</p>}

          <div className="row-end">
            <button className="mini" type="button" onClick={onClose}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy}>
              {busy ? t('projects.action.saving')
                : (mode === 'create' ? t('projects.action.createProject') : t('projects.action.saveChanges'))}
            </button>
          </div>
        </form>
      )} />
  )
}

/* ───────────────────────── one project ───────────────────────── */

function ProjectInventory({ refSlug, initialTab = 'summary', onTab, onBack, onNavigate, onOpenVersion }) {
  const { t, tCount } = useI18n()
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
  // Which rows asked to take their subdomains with them. React state, not a DOM
  // read: an uncontrolled checkbox inside a row that re-renders loses its tick.
  const [withKids, setWithKids] = useState({})
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
      setNotice(t('projects.notice.ciScanAssigned'))
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
        <PageHeader title={t('projects.detail.title')}
          actions={<button className="mini" onClick={onBack}>{t('projects.action.allProjects')}</button>} />
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
      <nav className="project-crumb" aria-label={t('projects.crumb.aria')}>
        <button type="button" onClick={onBack}>{t('projects.title')}</button>
        <span className="sep" aria-hidden="true">/</span>
        <span aria-current="page">{project.slug}</span>
      </nav>

      <PageHeader
        title={project.name}
        subtitle={project.description}
        actions={(
          <>
            <button className="mini" onClick={onBack}>{t('projects.action.allProjects')}</button>
            <button className="mini" onClick={() => setEditing(true)}>
              {t('projects.action.editProject')}
            </button>
            <button className="mini" onClick={load}>{t('common.refresh')}</button>
          </>
        )}
      />

      <dl className="project-meta">
        <div className="meta-item"><dt>{t('projects.meta.identifier')}</dt><dd>{project.slug}</dd></div>
        {project.group && (
          <div className="meta-item"><dt>{t('projects.col.group')}</dt><dd>{project.group}</dd></div>
        )}
        {project.owner && (
          <div className="meta-item"><dt>{t('common.owner')}</dt><dd>{project.owner}</dd></div>
        )}
        <div className="meta-item"><dt>{t('projects.col.components')}</dt><dd>{components.length}</dd></div>
        <div className="meta-item"><dt>{t('projects.col.environments')}</dt><dd>{environments.length}</dd></div>
        <div className="meta-item"><dt>{t('projects.col.assets')}</dt><dd>{assets.length}</dd></div>
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
            setNotice(t('projects.notice.updated'))
            await load()
          }} />
      )}

      {error && <ErrorBanner error={error} onRetry={load} />}
      {notice && (
        <div className="inv-notice" role="status">
          <span>{notice}</span>
          <button className="mini ghost" onClick={() => setNotice('')}
            aria-label={t('projects.notice.dismiss')}>✕</button>
        </div>
      )}

      <Tabs tabs={PROJECT_TABS.map((entry) => ({ ...entry, label: t(entry.labelKey) }))}
        active={tab} onChange={chooseTab} />

      {tab === 'summary' && (
        <>
          <Card tight>
            <div className="metrics">
              <Stat label={unit(tCount, 'component', components.length)} value={components.length} />
              <Stat label={unit(tCount, 'version', versions.length)} value={versions.length} />
              <Stat label={unit(tCount, 'environment', environments.length)} value={environments.length} />
              <Stat label={unit(tCount, 'asset', assets.length)} value={assets.length} />
            </div>
          </Card>

          {/* Once all four are recorded the checklist has nothing left to say:
              the metrics and the graph below are the summary. It comes back the
              moment one of them empties. */}
          {!setupComplete && <Card title={t('projects.setup.title')}
            actions={<span className="count">
              {t('projects.setup.recorded', {
                n: [components.length, versions.length, deployments.length, assets.length]
                  .filter(Boolean).length,
              })}
            </span>}>
            {(() => {
              const steps = [
                { key: 'components', labelKey: 'projects.setup.step.components',
                  count: components.length, actionKey: 'projects.action.add',
                  hintKey: 'projects.setup.hint.components', open: { kind: 'component' } },
                { key: 'versions', labelKey: 'projects.setup.step.versions',
                  count: versions.length, actionKey: 'projects.action.name',
                  hintKey: 'projects.setup.hint.versions', open: { kind: 'version' } },
                { key: 'deployments', labelKey: 'projects.setup.step.environments',
                  count: deployments.length, actionKey: 'projects.action.deploy',
                  hintKey: 'projects.setup.hint.environments', open: { kind: 'deployment' } },
                { key: 'assets', labelKey: 'projects.setup.step.assets',
                  count: assets.length, actionKey: 'projects.action.add',
                  hintKey: 'projects.setup.hint.assets', open: { kind: 'asset' } },
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
                          {t(step.labelKey)}
                          {step.count
                            ? <span className="setup-check"> {t('projects.setup.recordedMark')}</span>
                            : null}
                        </strong>
                        <p>{t(step.hintKey)}</p>
                      </div>
                      <span className="count">{step.count}</span>
                      <button className={`mini ${nextKey === step.key ? 'primary' : ''}`}
                        onClick={() => setDialog(step.open)}>{t(step.actionKey)}</button>
                    </li>
                  ))}
                </ul>
              )
            })()}
          </Card>}

          <Card title={t('projects.running.title')}
            actions={<div className="row">
              <button className="mini" onClick={() => setReleaseOpen(true)}>
                {t('projects.action.newEnvironment')}
              </button>
            </div>}>
            {!deployments.length
              ? <p className="muted">{t('projects.running.empty')}</p>
              : (
                <table>
                  <thead><tr><th>{t('projects.col.environment')}</th>
                    <th>{t('projects.col.component')}</th><th>{t('projects.col.version')}</th>
                    <th>{t('projects.col.domains')}</th><th>{t('projects.col.exposure')}</th></tr></thead>
                  <tbody>
                    {deployments.map((row) => (
                      <tr key={row.id}>
                        <td className="title">{row.environment}</td>
                        <td>{row.component || '—'}</td>
                        <td className="mono">
                          {row.version_label || <span className="muted">{t('common.unknown')}</span>}
                        </td>
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
          <Card band
            title={t('projects.tab.components')}
            actions={(
              <div className="row">
                <div className="btn-group" role="group" aria-label={t('projects.hint.expandAll')}>
                  <button className="mini" onClick={() => expandAll(components.map((row) => row.id))}>
                    {t('projects.action.expandAll')}
                  </button>
                  <button className="mini" onClick={collapseAll}>{t('projects.action.collapseAll')}</button>
                </div>
                <button className="mini primary" onClick={() => setDialog({ kind: 'component' })}>
                  {t('projects.action.addComponent')}
                </button>
              </div>
            )}>
            {!components.length ? (
              <div className="onb-empty-state" style={{ padding: '20px 16px 24px' }}>
                <h2>{t('projects.component.empty.title')}</h2>
                <p>{t('projects.component.empty.body')}</p>
                <button className="btn-primary" onClick={() => setDialog({ kind: 'component' })}>
                  {t('projects.action.addFirstComponent')}
                </button>
              </div>
            ) : (
              <>
              <p className="version-legend muted">
                <span className="version-legend-bar" aria-hidden="true">
                  <i className="sev-bar-critical" /><i className="sev-bar-high" />
                  <i className="sev-bar-medium" /><i className="sev-bar-low" />
                </span>
                {t('projects.legend')}
              </p>
              <div className="component-tree">
                {components.map((component) => {
                  const componentVersions = versions.filter(
                    (row) => row.component_id === component.id)
                  const latest = componentVersions[0]
                  const isOpen = openComponents.has(component.id)
                  // Coverage at a glance: a build with no SBOM was never
                  // analysed, and that is a different fact from "clean".
                  const analysed = componentVersions.filter((row) => row.sbom_imports).length
                  const shown = shownVersions[component.id] || 5
                  const visible = componentVersions.slice(0, shown)
                  const hidden = Math.max(0, componentVersions.length - visible.length)
                  return (
                    <section className={`component-block${isOpen ? ' open' : ''}`} key={component.id}>
                      <header className="component-head">
                        <button type="button" className="component-toggle"
                          aria-expanded={isOpen}
                          onClick={() => toggleComponent(component.id)}>
                          <span className={`caret${isOpen ? ' open' : ''}`} aria-hidden="true">
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none"
                              stroke="currentColor" strokeWidth="3" strokeLinecap="round"
                              strokeLinejoin="round"><path d="M9 5l7 7-7 7" /></svg>
                          </span>
                          <span className="component-ident">
                            <h3>{component.name}</h3>
                            <span className="muted component-sub">
                              {plural(tCount, 'version', componentVersions.length)}
                              {component.kind && component.kind.toLowerCase()
                                !== component.name.toLowerCase()
                                ? ` · ${component.kind}` : ''}
                              {component.repositories.length
                                ? ` · ${plural(tCount, 'repository', component.repositories.length)}`
                                : ` · ${t('projects.component.noCode')}`}
                            </span>
                          </span>
                        </button>
                        <div className="row component-actions">
                          {componentVersions.length > 0 && (
                            <span
                              className={`pill ${analysed === 0 ? 'bad' : analysed < componentVersions.length ? 'warn' : ''}`}
                              title={analysed === componentVersions.length
                                ? t('projects.component.sbom.all')
                                : analysed === 0
                                  ? t('projects.component.sbom.none')
                                  : t('projects.component.sbom.some')}
                            >
                              {analysed === 0
                                ? t('projects.component.neverAnalysed')
                                : t('projects.component.analysed', {
                                  analysed, total: componentVersions.length })}
                            </span>
                          )}
                          {latest && (
                            <span className="component-summary"
                              title={t('projects.component.newestBuild', { version: latest.version })}>
                              {latest.sbom_imports ? (
                                <>
                                  <SeverityBar counts={latest.findings?.by_severity} width={72} />
                                  <span className="muted">
                                    {shortLabel(latest.version)} · {t('projects.component.vulns', {
                                      n: latest.findings?.vulns || 0 })}
                                    {latest.findings?.code
                                      ? ` · ${t('projects.component.code', { n: latest.findings.code })}`
                                      : ''}
                                    {latest.findings?.secrets
                                      ? ` · ${t('projects.component.secrets', { n: latest.findings.secrets })}`
                                      : ''}
                                  </span>
                                </>
                              ) : (
                                <span className="muted">
                                  {shortLabel(latest.version)} · {t('projects.component.notAnalysed')}
                                </span>
                              )}
                            </span>
                          )}
                          <button className="mini"
                            onClick={() => setDialog({ kind: 'version', presetComponent: component.id })}>
                            {t('projects.action.newVersion')}
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
                              {t('projects.action.attachCode')}
                            </button>
                          )}

                          {componentVersions.length ? (
                            <>
                              <table className="version-tree">
                                <thead>
                                  <tr>
                                    <th>{t('projects.col.version')}</th>
                                    <th>{t('projects.col.deployed')}</th>
                                    <th>{t('projects.col.inventory')}</th>
                                    <th title={t('projects.hint.vulns')}>{t('projects.col.vulns')}</th>
                                    <th className="num" title={t('projects.hint.code')}>
                                      {t('projects.col.code')}
                                    </th>
                                    <th className="num" title={t('projects.hint.secrets')}>
                                      {t('projects.col.secrets')}
                                    </th>
                                    <th className="num" title={t('projects.hint.deploy')}>
                                      {t('projects.col.deploy')}
                                    </th>
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
                                          {version.baseline && (
                                            <span className="pill version-baseline">
                                              {t('projects.version.baseline')}
                                            </span>
                                          )}
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
                                                <span>{plural(tCount, 'component', version.components)}</span>
                                                <span className="muted">
                                                  {plural(tCount, 'sbomImport', version.sbom_imports)}
                                                </span>
                                              </>
                                            ) : (
                                              <span className="muted"
                                                title={t('projects.version.noBomHint')}>
                                                {t('projects.version.noBom')}
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
                                              {/* The number is the door: this build's
                                                  queue, opened already narrowed. A dead
                                                  count makes the reader redo the filter
                                                  the screen already knows. */}
                                              <button
                                                className={`linkish ${counts.vulns ? 'version-count' : 'muted'}`}
                                                title={t('findings.door')}
                                                onClick={() => {
                                                  window.location.hash = queueHash({
                                                    project: project.slug,
                                                    build: version.id,
                                                    build_label: version.version,
                                                    // The cell counts open dependency
                                                    // findings, so the door carries
                                                    // that scope.
                                                    kind: 'vulnerability',
                                                    open: '1',
                                                  })
                                                }}>
                                                {counts.vulns || 0}
                                              </button>
                                            </div>
                                          ) : (
                                            <span className="muted"
                                              title={t('projects.version.notAnalysedHint')}>
                                              {t('projects.version.notAnalysed')}
                                            </span>
                                          )}
                                          {counts.dismissed > 0 && (
                                            <div className="muted version-settled"
                                              title={t('projects.version.settledHint')}>
                                              {t('projects.version.settled', { n: counts.dismissed })}
                                            </div>
                                          )}
                                        </td>
                                        <td className="num">
                                          {counts.code
                                            ? <span className="version-count">{counts.code}</span>
                                            : <span className="muted"
                                              title={t('projects.version.noSastHint')}>—</span>}
                                        </td>
                                        <td className="num">
                                          {counts.secrets
                                            ? <span className="version-count">{counts.secrets}</span>
                                            : <span className="muted"
                                              title={t('projects.version.noSecretHint')}>—</span>}
                                        </td>
                                        <td className="row version-actions">
                                          <button className="mini"
                                            onClick={() => setDialog({
                                              kind: 'deployment', presetComponent: component.id,
                                              presetVersion: version.version,
                                            })}>
                                            {t('projects.action.deploy')}
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
                                      {t('projects.pager.showMore', { n: hidden })}
                                    </button>
                                  )}
                                  {shown > 5 && hidden > 0 && (
                                    <button className="mini"
                                      onClick={() => setShownVersions((current) => ({
                                        ...current, [component.id]: componentVersions.length,
                                      }))}>
                                      {t('projects.pager.showAll', { n: componentVersions.length })}
                                    </button>
                                  )}
                                  {shown > 5 && hidden === 0 && (
                                    <button className="mini"
                                      onClick={() => setShownVersions((current) => ({
                                        ...current, [component.id]: 5,
                                      }))}>
                                      {t('projects.pager.showNewest')}
                                    </button>
                                  )}
                                </div>
                              )}
                            </>
                          ) : (
                            <p className="muted component-empty">
                              {t('projects.component.noVersions')}
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
                        <span className={`caret${openComponents.has('__wide') ? ' open' : ''}`} aria-hidden="true">
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none"
                              stroke="currentColor" strokeWidth="3" strokeLinecap="round"
                              strokeLinejoin="round"><path d="M9 5l7 7-7 7" /></svg>
                          </span>
                        <span className="component-ident">
                          <h3>{t('projects.wide.title')}</h3>
                          <span className="muted component-sub">{t('projects.wide.sub')}</span>
                        </span>
                      </button>
                    </header>
                    {openComponents.has('__wide') && (
                      <table className="version-tree">
                        <thead><tr><th>{t('projects.col.version')}</th>
                          <th>{t('projects.wide.runsIn')}</th><th></th></tr></thead>
                        <tbody>
                          {versions.filter((row) => !row.component_id).map((version) => (
                            <React.Fragment key={version.id}>
                            <tr>
                              <td className="mono version-label">
                                {version.version}
                                {version.sbom_imports ? (
                                  <span className="version-note">
                                    {plural(tCount, 'sbomImport', version.sbom_imports)}
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
                                  : <span className="muted">{t('projects.version.notDeployed')}</span>}
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
          <Card title={t('projects.tab.environments')}
            actions={<button className="mini" onClick={() => setReleaseOpen(true)}>
              {t('projects.action.newEnvironment')}
            </button>}>
            {!deployments.length
              ? <p className="muted">{t('projects.env.empty')}</p>
              : (
                <table>
                  <thead><tr><th>{t('projects.col.environment')}</th>
                    <th>{t('projects.col.component')}</th><th>{t('projects.col.version')}</th>
                    <th>{t('projects.col.domains')}</th><th>{t('projects.col.exposure')}</th>
                    <th>{t('projects.col.auth')}</th><th>{t('projects.col.versionCheck')}</th>
                    <th>{t('common.actions')}</th></tr></thead>
                  <tbody>
                    {deployments.map((row) => (
                      <tr key={row.id}>
                        <td className="title">{row.environment}</td>
                        <td>{row.component || '—'}</td>
                        <td className="mono">
                          {row.version_label || <span className="muted">{t('common.unknown')}</span>}
                          <span className="muted" style={{ marginLeft: 6, fontSize: 10 }}>
                            · {row.source}{row.source === 'health' ? ` ${t('projects.env.check')}` : ''}
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
                              {t('projects.action.addDomain')}
                            </button>
                          )}
                        </td>
                        <td><span className={`pill ${row.exposure === 'public' ? 'warn' : ''}`}>{row.exposure}</span></td>
                        <td className="muted">
                          {row.requires_auth ? t('projects.env.authRequired') : t('common.no')}
                        </td>
                        <td className="muted">
                          {row.probe
                            ? (row.probe.enabled
                              ? (row.last_checked_at
                                ? `${row.last_check_status === 'ok'
                                  ? t('projects.probe.ok') : t('projects.probe.failed')} · ${new Date(row.last_checked_at).toLocaleString()}`
                                : t('projects.probe.configured'))
                              : t('projects.probe.disabled'))
                            : t('projects.probe.notConfigured')}
                          {row.probe && row.probe.enabled && (
                            <div style={{ fontSize: 11 }}>
                              {cadence(t, row.probe.interval_minutes)}
                              {row.probe.next_due_at ? ` · ${dueLabel(t, row.probe.next_due_at)}` : ''}
                            </div>
                          )}
                          {row.last_check_error && (
                            <div style={{ color: 'var(--critical)', fontSize: 11 }}>{row.last_check_error}</div>
                          )}
                        </td>
                        <td>
                          <div className="row">
                            <button className="mini" onClick={() => setDialog({ kind: 'edit', row })}>
                              {t('projects.action.edit')}
                            </button>
                            <button className="mini" onClick={() => setDialog({ kind: 'probe', row })}>
                              {t('projects.action.probe')}
                            </button>
                            {row.probe && (
                              <button className="mini" disabled={busy === `check:${row.id}`}
                                onClick={() => act(`check:${row.id}`,
                                  () => api.post(`/api/v1/deployments/${row.id}/health/check`),
                                  t('projects.notice.versionRead', { url: row.probe.url }))}>
                                {busy === `check:${row.id}`
                                  ? t('projects.action.checking') : t('projects.action.checkNow')}
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
            <strong>{t('projects.action.probe')}</strong> {t('projects.probe.footnoteA')}{' '}
            <code>https://api.example/health</code>{t('projects.probe.footnoteB')}{' '}
            <strong>{t('projects.action.checkNow')}</strong> {t('projects.probe.footnoteC')}
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
        onDone={(message) => {
          setNotice(t('projects.notice.created', { message })); load()
        }} />

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
  const { t } = useI18n()
  const [form, setForm] = useState({})
  const [error, setError] = useState('')
  const [localError, setLocalError] = useState('')
  const [busy, setBusy] = useState('')
  // Which rows asked to take their subdomains with them. React state, not a DOM
  // read: an uncontrolled checkbox inside a row that re-renders loses its tick.
  const [withKids, setWithKids] = useState({})
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
      const result = await work()
      onDone(typeof message === 'function' ? message(result) : message)
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
      notify?.(t('projects.notice.assetUpdated', {
        value: asset.value,
        environment: dialog.row?.environment || t('projects.notice.thisEnvironment'),
      }))
    } catch (e) {
      setLocalError(String(e.message || e))
    } finally { setBusy('') }
  }

  async function loadRemoteRepositories() {
    setError('')
    try {
      const connections = await api.get('/api/v1/onboarding/connections')
      const scm = (connections.data?.scm || [])[0]
      if (!scm) { setError(t('projects.error.noCodeHost')); return }
      const listed = await api.get(`/api/v1/onboarding/connections/${scm.id}/repositories`)
      setRemoteRepos(listed.data || [])
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  if (dialog.kind === 'version') {
    return (
      <Dialog open hideFooter title={t('projects.dialog.newVersion')} onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          const label = (form.version || '').trim()
          if (components.length && !form.component_id) {
            setError(t('projects.error.chooseComponent'))
            return
          }
          if (!label) {
            setError(t('projects.error.nameVersion'))
            return
          }
          submit(() => api.post(`/api/v1/projects/${project.slug}/versions`, {
            version: label, component_id: form.component_id || undefined,
            actor: 'console' }), t('projects.notice.versionCreated', { version: label })) }}>
          <p className="onb-help" style={{ margin: 0 }}>{t('projects.dialog.versionIntro')}</p>
          {components.length ? (
            <label>
              {t('projects.field.component')}
              <select autoFocus value={form.component_id || ''}
                onChange={(e) => setForm({ ...form, component_id: e.target.value })}>
                <option value="">{t('projects.option.choose')}</option>
                {components.map((component) => (
                  <option key={component.id} value={component.id}>{component.name}</option>
                ))}
              </select>
              <span className="onb-help">{t('projects.field.componentHint')}</span>
            </label>
          ) : null}
          <label>
            {t('projects.field.version')}
            <input autoFocus={!components.length} value={form.version || ''} placeholder="1.8"
              onChange={(e) => setForm({ ...form, version: e.target.value })} />
            <span className="onb-help">{t('projects.field.versionHint')}</span>
          </label>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? t('projects.action.creating') : t('projects.action.createVersion')}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'version-rename') {
    const row = dialog.row
    return (
      <Dialog open hideFooter
        title={t('projects.dialog.renameVersion', { version: row.version })} onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          const label = (form.version || '').trim()
          if (!label) { setError(t('projects.error.versionName')); return }
          submit(() => api.patch(
            `/api/v1/projects/${project.slug}/versions/${encodeURIComponent(row.version)}`
            + (row.component_id ? `?component_id=${row.component_id}` : ''),
            { version: label }), t('projects.notice.versionRenamed', { version: label })) }}>
          <p className="onb-help" style={{ margin: 0 }}>{t('projects.dialog.renameIntro')}</p>
          <label>
            {t('projects.field.version')}
            <input autoFocus value={form.version ?? row.version}
              onChange={(e) => setForm({ ...form, version: e.target.value })} />
            <span className="onb-help">
              {row.component || t('projects.version.productWide')}
              {row.deployments?.length
                ? ` · ${t('projects.version.runsIn', {
                  envs: row.deployments.map((use) => use.environment).join(', ') })}`
                : ` · ${t('projects.version.notDeployed')}`}
            </span>
          </label>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? t('projects.action.saving') : t('projects.action.rename')}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'asset') {
    return (
      <Dialog open hideFooter title={t('projects.dialog.addAsset')} onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          if (!(form.value || '').trim()) {
            setError(t('projects.error.assetValue'))
            return
          }
          submit(() => api.post(`/api/v1/projects/${project.slug}/assets`, {
            type: form.type || 'domain', value: form.value.trim(),
            component_id: form.component_id || undefined,
            deployment_id: form.deployment_id || undefined,
            notes: form.notes || undefined, actor: 'console' }),
            (result) => {
              const decision = result?.authorization || {}
              const where = decision.request
                ? t('projects.notice.assetAuthRequested')
                : decision.excluded
                  ? t('projects.notice.assetExcluded')
                  : decision.covered
                    ? t('projects.notice.assetCovered')
                    : ''
              return `${t('projects.notice.assetRecorded', {
                value: form.value.trim(), project: project.name })}${where ? ` ${where}` : ''}`
            }) }}>
          <p className="onb-help" style={{ margin: 0 }}>{t('projects.dialog.assetIntro')}</p>
          <div className="onb-grid">
            <label>
              {t('projects.field.type')}
              <select value={form.type || 'domain'}
                onChange={(e) => setForm({ ...form, type: e.target.value })}>
                {ASSET_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
              </select>
            </label>
            <label>
              {t('projects.field.value')}
              <input autoFocus value={form.value || ''} placeholder="app.example.com"
                onChange={(e) => setForm({ ...form, value: e.target.value })} />
            </label>
          </div>
          <div className="onb-grid">
            <label>
              {t('projects.field.environment')} <span className="onb-optional">{t('projects.optional')}</span>
              <select value={form.deployment_id || ''}
                onChange={(e) => {
                  const deployment = deployments.find((row) => row.id === e.target.value)
                  setForm({ ...form, deployment_id: e.target.value,
                    component_id: deployment?.component_id || form.component_id || '' })
                }}>
                <option value="">{t('projects.option.noEnvironment')}</option>
                {deployments
                  .filter((row) => !form.component_id || row.component_id === form.component_id)
                  .map((row) => (
                    <option key={row.id} value={row.id}>
                      {(row.component || t('projects.component.unassigned')) + ' · ' + row.environment}
                    </option>
                  ))}
              </select>
              <span className="onb-help">{t('projects.field.environmentHint')}</span>
            </label>
            <label>
              {t('projects.field.component')} <span className="onb-optional">{t('projects.optional')}</span>
              <select value={form.component_id || ''}
                onChange={(e) => setForm({ ...form, component_id: e.target.value,
                  deployment_id: '' })}>
                <option value="">{t('projects.option.projectOnlyLong')}</option>
                {components.map((component) => (
                  <option key={component.id} value={component.id}>{component.name}</option>
                ))}
              </select>
              <span className="onb-help">{t('projects.field.componentOptionalHint')}</span>
            </label>
          </div>
          <label>
            {t('projects.field.notes')} <span className="onb-optional">{t('projects.optional')}</span>
            <input value={form.notes || ''} placeholder={t('projects.field.notesPlaceholder')}
              onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          </label>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? t('projects.action.saving') : t('projects.action.addAsset')}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'component') {
    return (
      <Dialog open hideFooter title={t('projects.dialog.addComponent')} onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          if (!(form.name || '').trim()) {
            setError(t('projects.error.componentName'))
            return
          }
          submit(() => api.post(`/api/v1/projects/${project.slug}/components`, {
            name: form.name.trim(), kind: form.kind || 'backend', actor: 'console' }),
            t('projects.notice.componentAdded', { name: form.name.trim() })) }}>
          <div className="onb-grid">
            <label>
              {t('projects.field.name')}
              <input autoFocus value={form.name || ''} placeholder="Backend"
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </label>
            <label>
              {t('projects.field.kind')}
              <select value={form.kind || 'backend'}
                onChange={(e) => setForm({ ...form, kind: e.target.value })}>
                {COMPONENT_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
              </select>
            </label>
          </div>
          <span className="onb-help">{t('projects.dialog.componentIntro')}</span>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? t('projects.action.saving') : t('projects.action.addComponent')}
            </button>
          </div>
        </form>
      )} />
    )
  }

  if (dialog.kind === 'repository') {
    return (
      <Dialog open hideFooter title={t('projects.dialog.attachRepo')} onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          if (!(form.remote_url || '').trim()) {
            setError(t('projects.error.repositoryUrl'))
            return
          }
          submit(() => api.post(`/api/v1/projects/${project.slug}/repositories`, {
            remote_url: form.remote_url.trim(),
            component_id: form.component_id || undefined,
            actor: 'console' }), t('projects.notice.repoAttached')) }}>
          <label>
            {t('projects.field.remoteUrl')}
            <input autoFocus value={form.remote_url || ''}
              placeholder="https://gitea.example/bitsentry/aurea-api.git"
              onChange={(e) => setForm({ ...form, remote_url: e.target.value })} />
          </label>
          <label>
            {t('projects.field.component')} <span className="onb-optional">{t('projects.optional')}</span>
            <select value={form.component_id || ''}
              onChange={(e) => setForm({ ...form, component_id: e.target.value })}>
              <option value="">{t('projects.option.projectOnly')}</option>
              {components.map((component) => (
                <option key={component.id} value={component.id}>{component.name}</option>
              ))}
            </select>
            <span className="onb-help">{t('projects.field.repositoryComponentHint')}</span>
          </label>
          <button type="button" className="mini" onClick={loadRemoteRepositories}>
            {t('projects.action.listRemote')}
          </button>
          {remoteRepos && (
            <div className="onb-repo-list">
              {!remoteRepos.length && (
                <p className="muted">{t('projects.error.noRemoteRepos')}</p>
              )}
              {remoteRepos.map((repo) => (
                <button type="button" key={repo.url} className="onb-repo-row"
                  onClick={() => setForm({ ...form, remote_url: repo.url })}>
                  <span>{repo.name}</span>
                  <span className="muted">
                    {repo.private ? t('projects.repo.private') : t('projects.repo.public')}
                  </span>
                </button>
              ))}
            </div>
          )}
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? t('projects.action.attaching') : t('projects.action.attach')}
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
      <Dialog open hideFooter title={t('projects.dialog.deploy')} onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          const environment = (form.environment || '').trim()
          const domain = (form.domain || '').trim()
          if (!form.component_id) {
            setError(t('projects.error.chooseDeployedComponent'))
            return
          }
          if (environment.length < 2) {
            setError(t('projects.error.nameEnvironment'))
            return
          }
          if (creatingVersion && !(form.version_label || '').trim()) {
            setError(t('projects.error.nameDeployedVersion'))
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
          }, domain
            ? t('projects.notice.deployedWith', { environment, domain })
            : t('projects.notice.deployed', { environment }))
        }}>
          <div className="onb-grid">
            <label>
              {t('projects.field.component')}
              <select autoFocus value={form.component_id || ''}
                onChange={(e) => setForm({ ...form, component_id: e.target.value,
                  version_id: '', version_choice: '', version_label: '' })}>
                <option value="">{t('projects.option.choose')}</option>
                {components.map((component) => (
                  <option key={component.id} value={component.id}>{component.name}</option>
                ))}
              </select>
            </label>
            <label>
              {t('projects.field.environment')}
              <input value={form.environment || ''} placeholder="PRO" list="env-options"
                onChange={(e) => setForm({ ...form, environment: e.target.value })} />
              <datalist id="env-options">
                {suggested.map((name) => <option key={name} value={name} />)}
              </datalist>
              <span className="onb-help">{t('projects.field.environmentNameHint')}</span>
            </label>
          </div>

          <label>
            {t('projects.field.version')}
            {!creatingVersion ? (
              <select value={form.version_id || ''}
                onChange={(e) => {
                  if (e.target.value === '__new') {
                    setForm({ ...form, version_choice: '__new', version_id: '' })
                  } else {
                    setForm({ ...form, version_id: e.target.value, version_choice: '' })
                  }
                }}>
                <option value="">{t('projects.option.chooseVersion')}</option>
                {componentVersions.map((row) => (
                  <option key={row.id} value={row.id}>
                    {row.version}{row.sbom_imports ? ' · SBOM' : ''}
                    {row.deployments.length ? ` · ${t('projects.version.alreadyRunning')}` : ''}
                  </option>
                ))}
                <option value="__new">{t('projects.option.newVersion')}</option>
              </select>
            ) : (
              <input value={form.version_label || ''} placeholder="1.8"
                onChange={(e) => setForm({ ...form, version_label: e.target.value })} />
            )}
            <span className="onb-help">
              {creatingVersion
                ? t('projects.field.deployVersionHintNew')
                : t('projects.field.deployVersionHint')}
            </span>
          </label>

          <label>
            {t('projects.field.domain')} <span className="onb-optional">{t('projects.optional')}</span>
            <input value={form.domain || ''} placeholder="api.aurea.example"
              onChange={(e) => setForm({ ...form, domain: e.target.value })} />
            <span className="onb-help">{t('projects.field.domainHint')}</span>
          </label>

          <label className="onb-check">
            <input type="checkbox" checked={Boolean(form.requires_auth)}
              onChange={(e) => setForm({ ...form, requires_auth: e.target.checked })} />
            {t('projects.field.requiresAuth')}
          </label>

          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? t('projects.action.deploying') : t('projects.action.deploy')}
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
        title={t('projects.dialog.environment', {
          component: row.component || t('projects.component.unassigned'),
          environment: row.environment,
        })}
        onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          if ((form.environment ?? row.environment ?? '').trim().length < 2) {
            setError(t('projects.error.nameEnvironment'))
            return
          }
          submit(() => api.patch(`/api/v1/deployments/${row.id}`, {
            environment: (form.environment ?? row.environment).trim(),
            version_id: form.version_id || undefined,
            exposure: form.exposure || 'unknown',
            requires_auth: Boolean(form.requires_auth), actor: 'console' }),
            t('projects.notice.environmentUpdated', {
              environment: form.environment || row.environment })) }}>
          <div className="onb-grid">
            <label>
              {t('projects.field.environment')}
              <input autoFocus value={form.environment ?? row.environment} placeholder="PRO"
                onChange={(e) => setForm({ ...form, environment: e.target.value })} />
              <span className="onb-help">{t('projects.field.environmentRenameHint')}</span>
            </label>
            <label>
              {t('projects.field.version')}
              <select value={form.version_id || ''}
                onChange={(e) => setForm({ ...form, version_id: e.target.value })}>
                <option value="">{t('projects.option.keepVersion', {
                  version: row.version_label || t('common.none') })}</option>
                {componentVersions.map((version) => (
                  <option key={version.id} value={version.id}>{version.version}</option>
                ))}
              </select>
              <span className="onb-help">{t('projects.field.versionRunsHint')}</span>
            </label>
            <label>
              {t('projects.field.exposure')}
              <select value={form.exposure || 'unknown'}
                onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
                {EXPOSURES.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
              <span className="onb-help">{t('projects.field.exposureHint')}</span>
            </label>
            <label className="onb-check">
              <input type="checkbox" checked={Boolean(form.requires_auth)}
                onChange={(e) => setForm({ ...form, requires_auth: e.target.checked })} />
              {t('projects.field.requiresAuth')}
            </label>
          </div>

          <div className="onb-inline-section">
            <span className="onb-section-label">{t('projects.section.domains')}</span>
            {!domains.length && (
              <p className="onb-help" style={{ margin: 0 }}>{t('projects.section.noDomain')}</p>
            )}
            {domains.map((asset) => (
              <div className="row-between" key={asset.id}>
                <span className="mono">{asset.value}</span>
                <button className="mini" type="button" disabled={busy === asset.id}
                  onClick={() => actOn(asset, () => api.del(
                    `/api/v1/assets/${asset.id}/links/${asset.deployment.link_id}`))}>
                  {busy === asset.id ? t('projects.action.removing') : t('projects.action.unlink')}
                </button>
              </div>
            ))}
            {unattached.length > 0 && (
              <label>
                {t('projects.field.attachAsset')}
                <select value="" onChange={(e) => {
                  const asset = unattached.find((item) => item.id === e.target.value)
                  if (!asset) return
                  actOn(asset, () => api.post(`/api/v1/projects/${project.slug}/assets`, {
                    type: asset.type, value: asset.value, deployment_id: row.id,
                    actor: 'console' }))
                }}>
                  <option value="">{t('projects.option.chooseAsset')}</option>
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
              {t('projects.action.addNewDomain')}
            </button>
          </div>

          {localError && <p className="banner banner-error">{localError}</p>}
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? t('projects.action.saving') : t('projects.action.saveChanges')}
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
        title={t('projects.dialog.probe', {
          component: row.component || '', environment: row.environment })}
        onClose={close} body={(
        <form className="onb-form" onSubmit={(e) => { e.preventDefault()
          submit(() => api.put(`/api/v1/deployments/${row.id}/health-probe`, {
            url: form.url, token: form.token || undefined,
            version_path: form.version_path || 'auto',
            status_path: form.status_path || 'status',
            enabled: form.enabled !== false,
            interval_minutes: Number(form.interval_minutes) || 0,
            actor: 'console' }), t('projects.notice.probeSaved')) }}>
          <p className="onb-help" style={{ margin: 0 }}>{t('projects.dialog.probeIntro')}</p>
          <label>
            {t('projects.field.healthUrl')}
            <input autoFocus value={form.url || ''} placeholder="https://api.aurea.example/health"
              onChange={(e) => setForm({ ...form, url: e.target.value })} />
          </label>
          <label>
            {t('projects.field.bearerToken')} <span className="onb-optional">{t('projects.optional')}</span>
            <input type="password" value={form.token || ''}
              placeholder={row.probe?.token_set
                ? t('projects.field.tokenStored') : t('projects.field.tokenNotSet')}
              onChange={(e) => setForm({ ...form, token: e.target.value })} />
          </label>
          <div className="onb-grid">
            <label>
              {t('projects.field.versionPath')}
              <input value={form.version_path || 'auto'} placeholder="auto"
                onChange={(e) => setForm({ ...form, version_path: e.target.value })} />
            </label>
            <label>
              {t('projects.field.statusPath')}
              <input value={form.status_path || 'status'}
                onChange={(e) => setForm({ ...form, status_path: e.target.value })} />
            </label>
          </div>
          <label>
            {t('projects.field.checkEvery')}
            <select value={String(form.interval_minutes ?? 0)}
              onChange={(e) => setForm({ ...form, interval_minutes: e.target.value })}>
              <option value="0">{t('projects.option.manualOnly')}</option>
              <option value="15">{t('projects.option.every15')}</option>
              <option value="60">{t('projects.option.hourly')}</option>
              <option value="360">{t('projects.option.every6h')}</option>
              <option value="1440">{t('projects.option.daily')}</option>
            </select>
            <span className="onb-optional">{t('projects.field.schedulerHint')}</span>
          </label>
          <label className="onb-check">
            <input type="checkbox" checked={form.enabled !== false}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
            {t('projects.field.enabled')}
          </label>
          {error && <p className="banner banner-error">{error}</p>}
          <div className="row-end">
            <button className="mini" type="button" onClick={close}>{t('common.cancel')}</button>
            <button className="btn-primary" type="submit" disabled={busy === 'save'}>
              {busy === 'save' ? t('projects.action.saving') : t('projects.action.saveProbe')}
            </button>
          </div>
        </form>
      )} />
    )
  }

  return null
}