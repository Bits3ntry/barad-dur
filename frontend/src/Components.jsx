import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import { Card, Dialog, EmptyState, ErrorBanner, Loading, PageHeader, Pager, Stat, usePage } from './ui'
import Sbom from './Sbom'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

function SeverityStrip({ counts = {} }) {
  const shown = SEVERITIES.filter((severity) => counts[severity] > 0)
  if (!shown.length) return <span className="muted">none</span>
  return <span className="discovery-severity">
    {shown.map((severity) => (
      <span key={severity} className={`sev sev-${severity.toLowerCase()}`}>
        {severity[0]}{counts[severity]}
      </span>
    ))}
  </span>
}

function deployedTree(inventories, profiles) {
  return inventories.map((inventory) => {
    const versions = new Map((inventory.versions || []).map((row) => [row.id, row]))
    const components = (inventory.components || []).map((component) => {
      const deployed = new Map()
      for (const deployment of component.deployments || []) {
        if (!deployment.version_id || !deployment.version_label) continue
        const version = versions.get(deployment.version_id)
        if (!version) continue
        const record = deployed.get(version.id) || {
          ...version,
          environments: [],
          deployments: [],
          profile: profiles.get(`${inventory.project.slug}:${version.id}`),
        }
        record.environments.push(deployment.environment)
        record.deployments.push(deployment)
        deployed.set(version.id, record)
      }
      return { ...component, versions: [...deployed.values()] }
    }).filter((component) => component.versions.length)
    return { project: inventory.project, components }
  }).filter((project) => project.components.length)
}

/* One deployed component's versions. The project and component headers above
   it are the summary; this table is the list that actually grows, a row per
   release, so it gets its own pager — a single long history must not bury the
   component that follows it in the tree. */
function VersionTable({ project, component, onOpenVersion }) {
  const paged = usePage(component.versions, 10)
  return (
    <>
      <table className="discovery-version-table"><thead><tr><th>version</th><th>environments</th><th>security</th><th>critical</th><th>KEV</th><th></th></tr></thead><tbody>
        {paged.rows.map((version) => {
          const profile = version.profile
          const findings = profile?.findings
          return <tr key={version.id}>
            <td className="mono title"><button className="version-open" onClick={() => onOpenVersion?.(project.slug, component.slug || component.name, version.version)}>{version.version}</button></td>
            <td>{version.environments.map((environment) => <span className="pill env-pill" key={environment}>{environment}</span>)}</td>
            <td>{profile ? <><span className={findings.total ? 'sev sev-high' : 'pill'}>{findings.total} finding{findings.total === 1 ? '' : 's'}</span><SeverityStrip counts={findings.by_severity} /></> : <span className="muted">unavailable</span>}</td>
            <td>{profile ? findings.by_severity.CRITICAL : '—'}</td>
            <td>{profile ? findings.kev : '—'}</td>
            <td className="row-action"><button className="mini" onClick={() => onOpenVersion?.(project.slug, component.slug || component.name, version.version)}>details</button></td>
          </tr>
        })}
      </tbody></table>
      <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
        total={paged.total} perPage={paged.perPage} unit="versions"
        className="row-end" />
    </>
  )
}

export default function Components({ projects, focus = {}, onChanged, onOpenProject, onOpenVersion, onBack }) {
  const [tree, setTree] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [onlyRisk, setOnlyRisk] = useState(false)
  const [openProjects, setOpenProjects] = useState(() => new Set())
  const [openComponents, setOpenComponents] = useState(() => new Set())
  const [importOpen, setImportOpen] = useState(false)
  const [importProject, setImportProject] = useState('')
  const [importVersion, setImportVersion] = useState('')
  const [importFile, setImportFile] = useState(null)
  const [importBusy, setImportBusy] = useState(false)
  const [importNote, setImportNote] = useState('')
  const [receipt, setReceipt] = useState(null)
  const fileInput = useRef(null)

  async function load() {
    if (!projects.length) { setTree([]); return }
    setLoading(true); setError('')
    try {
      const inventories = await Promise.all(projects.map(async (project) => {
        const response = await api.get(`/api/v1/projects/${encodeURIComponent(project.slug)}/inventory`)
        return response.data
      }))
      const deployedVersions = inventories.flatMap((inventory) => (inventory.versions || [])
        .filter((version) => (version.deployments || []).length && version.component_id))
      const profiles = new Map()
      const results = await Promise.allSettled(deployedVersions.map(async (version) => {
        const project = inventories.find((inventory) => inventory.versions
          ?.some((entry) => entry.id === version.id))?.project
        if (!project) return null
        const params = new URLSearchParams({ project: project.slug, version: version.version,
          component_id: version.component_id })
        const response = await api.get(`/api/v1/inventory/profile?${params}`)
        return { key: `${project.slug}:${version.id}`, data: response.data }
      }))
      const failed = results.filter((result) => result.status === 'rejected')
      for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
          profiles.set(result.value.key, result.value.data)
        }
      }
      const nextTree = deployedTree(inventories, profiles)
      setTree(nextTree)
      setOpenProjects(new Set(nextTree.map((entry) => entry.project.slug)))
      if (failed.length) {
        setError(`${failed.length} deployed version security profile${failed.length === 1 ? '' : 's'} could not be loaded.`)
      }
    } catch (problem) {
      setError(String(problem.message || problem))
      setTree([])
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [projects])

  const visibleTree = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return tree.map((project) => {
      const components = project.components.map((component) => {
        const versions = component.versions.filter((version) => {
          const risky = (version.profile?.findings?.total || 0) > 0
          if (onlyRisk && !risky) return false
          if (!needle) return true
          return [project.project.name, project.project.slug, component.name, component.kind,
            version.version, ...version.environments].join(' ').toLowerCase().includes(needle)
        })
        return { ...component, versions }
      }).filter((component) => component.versions.length)
      return { ...project, components }
    }).filter((project) => project.components.length)
  }, [tree, query, onlyRisk])

  const totals = useMemo(() => {
    const versions = visibleTree.flatMap((project) => project.components.flatMap((component) => component.versions))
    return {
      projects: visibleTree.length,
      components: visibleTree.reduce((count, project) => count + project.components.length, 0),
      versions: versions.length,
      findings: versions.reduce((count, version) => count + (version.profile?.findings?.total || 0), 0),
      critical: versions.reduce((count, version) => count + (version.profile?.findings?.by_severity?.CRITICAL || 0), 0),
    }
  }, [visibleTree])

  function toggle(setter, key) {
    setter((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key); else next.add(key)
      return next
    })
  }

  function openImport() {
    setImportProject(projects[0]?.slug || '')
    setImportVersion('')
    setImportFile(null)
    setImportNote('')
    setImportOpen(true)
  }

  async function pickFile(file) {
    if (!file) return
    setImportFile(file); setImportNote('')
    try {
      const document = JSON.parse(await file.text())
      const component = document?.metadata?.component || {}
      if (component.version) setImportVersion(String(component.version))
      if (!importProject && component.name && !String(component.name).startsWith('/')) {
        setImportProject(String(component.name))
      }
    } catch { setImportNote('That file is not JSON; the upload will be rejected.') }
  }

  async function submitImport() {
    if (!importFile) { setImportNote('Pick a CycloneDX JSON file.'); return }
    if (!importProject.trim() || !importVersion.trim()) {
      setImportNote('Project and version are both required.'); return
    }
    setImportBusy(true); setImportNote('')
    try {
      const params = new URLSearchParams({ source: 'web', project: importProject.trim(),
        version: importVersion.trim(), filename: importFile.name })
      const response = await api.postRaw(`/api/v1/sbom?${params}`, await importFile.arrayBuffer())
      setReceipt(response)
      setImportOpen(false)
      if (onChanged) await onChanged()
      await load()
    } catch (problem) { setImportNote(String(problem.message || problem)) }
    finally { setImportBusy(false) }
  }

  if (focus.projectSlug && focus.version) {
    // The version view lives here when the route carries a version, so it needs
    // the same "open that other build" callback the standalone screen gets.
    return <Sbom focus={focus} embedded onOpen={onOpenVersion} onBack={onBack} />
  }

  return (
    <div className="stack">
      <PageHeader title="Components"
        subtitle="Deployed application versions only. Projects remains the full ownership catalog."
        actions={<><button className="mini" onClick={openImport}>import SBOM…</button><button className="mini" onClick={load}>refresh</button></>} />

      <Card tight>
        <div className="metrics">
          <Stat label="projects deployed" value={totals.projects} />
          <Stat label="components deployed" value={totals.components} />
          <Stat label="versions running" value={totals.versions} />
          <Stat label="open findings" value={totals.findings} tone={totals.findings ? 'warn' : ''} />
          <Stat label="critical" value={totals.critical} tone={totals.critical ? 'bad' : ''} />
        </div>
      </Card>

      <div className="toolbar discovery-toolbar">
        <input value={query} placeholder="filter project, component, version or environment"
          onChange={(event) => setQuery(event.target.value)} />
        <label className="row" style={{ gap: 6 }}>
          <input type="checkbox" checked={onlyRisk} onChange={(event) => setOnlyRisk(event.target.checked)} />
          only versions with findings
        </label>
        <span className="spacer" />
        <span className="count">{loading ? 'loading…' : `${totals.versions} deployed version${totals.versions === 1 ? '' : 's'}`}</span>
      </div>

      {error && <ErrorBanner error={error} onRetry={load} />}
      {receipt && <div className="banner banner-ok">import {receipt.status} — {receipt.receipt.counts.components_created} created, {receipt.receipt.counts.components_updated} updated</div>}
      {loading && !tree.length && <Loading rows={6} label="Loading deployed components" />}
      {!loading && !visibleTree.length && !error && <EmptyState title="No deployed component versions"
        hint={tree.length ? 'Clear the filters to see deployed versions.' : 'Record a component version and link it to an environment in Projects. Un-deployed catalog entries stay in Projects.'} />}

      <div className="discovery-tree">
        {visibleTree.map(({ project, components }) => {
          const projectKey = project.slug
          const projectOpen = openProjects.has(projectKey)
          return <section key={projectKey} className={`discovery-project${projectOpen ? ' open' : ''}`}>
            <header className="discovery-project-head">
              <button className="discovery-toggle" type="button" onClick={() => toggle(setOpenProjects, projectKey)} aria-expanded={projectOpen}>
                <span className="caret" aria-hidden="true">{projectOpen ? '▾' : '▸'}</span>
                <span><strong>{project.name}</strong><span className="muted">{project.slug} · {components.length} deployed component{components.length === 1 ? '' : 's'}</span></span>
              </button>
              <button className="mini" onClick={() => onOpenProject?.(project.slug, 'components')}>view project</button>
            </header>
            {projectOpen && <div className="discovery-component-list">
              {components.map((component) => {
                const componentKey = `${project.slug}:${component.id}`
                const componentOpen = openComponents.has(componentKey)
                return <section key={component.id} className="discovery-component">
                  <button className="discovery-toggle discovery-component-head" type="button" onClick={() => toggle(setOpenComponents, componentKey)} aria-expanded={componentOpen}>
                    <span className="caret" aria-hidden="true">{componentOpen ? '▾' : '▸'}</span>
                    <span><strong>{component.name}</strong><span className="muted">{component.kind} · {component.versions.length} running version{component.versions.length === 1 ? '' : 's'}</span></span>
                  </button>
                  {componentOpen && <VersionTable project={project} component={component}
                    onOpenVersion={onOpenVersion} />}
                </section>
              })}
            </div>}
          </section>
        })}
      </div>

      <Dialog open={importOpen} title="Import an SBOM" confirmLabel="import" onClose={() => setImportOpen(false)} onConfirm={submitImport}>
        <div className="stack">
          <label className="field-label" htmlFor="sbom-file">CycloneDX JSON</label>
          <input id="sbom-file" ref={fileInput} type="file" accept=".json,application/json" onChange={(event) => pickFile(event.target.files[0])} />
          <label className="field-label" htmlFor="sbom-project">project</label>
          <input id="sbom-project" value={importProject} list="sbom-projects" onChange={(event) => setImportProject(event.target.value)} />
          <datalist id="sbom-projects">{projects.map((project) => <option key={project.slug} value={project.slug} />)}</datalist>
          <label className="field-label" htmlFor="sbom-version">version</label>
          <input id="sbom-version" value={importVersion} onChange={(event) => setImportVersion(event.target.value)} />
          <p className="muted" style={{ fontSize: 12 }}>{importBusy ? 'importing…' : 'The SBOM is attached to the named project version.'}</p>
          {importNote && <div className="banner banner-error">{importNote}</div>}
        </div>
      </Dialog>
    </div>
  )
}
