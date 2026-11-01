import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import { Card, Dialog, EmptyState, ErrorBanner, Loading, PageHeader, Stat } from './ui'

/* Inventory per project version, joined with the findings of that version.

   The screen used to be pinned to whatever project came first in the nav data,
   with no selector and no search: 1.125 rows of purl nobody could narrow down.
   Dependency-Track's useful trick is the join — a component is interesting
   because of what it carries — so the findings of the selected version are
   fetched once and folded in by purl. */

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

function worstOf(counts) {
  return SEVERITY_ORDER.find((severity) => counts[severity])
}

export default function Components({ projects, onChanged }) {
  const [projectSlug, setProjectSlug] = useState('')
  const [version, setVersion] = useState('')
  const [search, setSearch] = useState('')
  const [onlyVulnerable, setOnlyVulnerable] = useState(false)
  const [rows, setRows] = useState([])
  const [profile, setProfile] = useState(null)
  const [carried, setCarried] = useState({})
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [receipt, setReceipt] = useState(null)
  const [impact, setImpact] = useState({ id: null, data: null, error: '' })
  const [importOpen, setImportOpen] = useState(false)
  const [importProject, setImportProject] = useState('')
  const [importVersion, setImportVersion] = useState('')
  const [importFile, setImportFile] = useState(null)
  const [importBusy, setImportBusy] = useState(false)
  const [importNote, setImportNote] = useState('')
  const fileInput = useRef(null)

  const project = projects.find((p) => p.slug === projectSlug)
  const versions = project?.versions || []

  // First render: land on the project with the largest inventory, which is the
  // one worth looking at, instead of whichever the API listed first.
  useEffect(() => {
    if (projectSlug || !projects.length) return
    setProjectSlug(projects[0].slug)
    setVersion(projects[0].versions?.[0] || '')
  }, [projects, projectSlug])

  useEffect(() => {
    if (!projectSlug || !version) return
    let cancelled = false
    setLoading(true); setError('')
    const query = `project=${encodeURIComponent(projectSlug)}&version=${encodeURIComponent(version)}`
    Promise.all([
      api.get(`/api/v1/components?${query}`),
      api.get(`/api/v1/inventory/profile?${query}`).catch(() => null),
      api.get(`/api/v1/findings?${query}`).catch(() => ({ data: [] })),
    ])
      .then(([components, versionProfile, findings]) => {
        if (cancelled) return
        setRows(components.data || [])
        setProfile(versionProfile?.data || null)
        const byPurl = {}
        for (const finding of findings.data || []) {
          if (!finding.component_purl) continue
          const bucket = byPurl[finding.component_purl]
            || (byPurl[finding.component_purl] = { total: 0 })
          bucket.total += 1
          const severity = finding.severity || 'UNKNOWN'
          bucket[severity] = (bucket[severity] || 0) + 1
        }
        setCarried(byPurl)
      })
      .catch((problem) => { if (!cancelled) setError(String(problem.message || problem)) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [projectSlug, version])

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return rows
      .map((row) => {
        const findings = carried[row.purl] || null
        return { ...row, findings, worst: findings ? worstOf(findings) : null }
      })
      .filter((row) => {
        if (onlyVulnerable && !row.findings) return false
        if (!needle) return true
        return `${row.name} ${row.version || ''} ${row.purl || ''} ${row.license || ''}`
          .toLowerCase().includes(needle)
      })
      .sort((left, right) => {
        if (onlyVulnerable || (left.findings || right.findings)) {
          const delta = (right.findings?.total || 0) - (left.findings?.total || 0)
          if (delta) return delta
        }
        return left.name.localeCompare(right.name)
      })
  }, [rows, carried, search, onlyVulnerable])

  async function showImpact(row) {
    if (impact.id === row.id) { setImpact({ id: null, data: null, error: '' }); return }
    try {
      const response = await api.get(`/api/v1/components/impact?component_id=${row.id}`)
      setImpact({ id: row.id, data: response.data, error: '' })
    } catch (problem) {
      setImpact({ id: row.id, data: null, error: String(problem.message || problem) })
    }
  }

  async function pickFile(file) {
    if (!file) return
    setImportFile(file)
    setImportNote('')
    try {
      const document = JSON.parse(await file.text())
      const component = document?.metadata?.component || {}
      // The version the SBOM itself declares wins: that is the project's own
      // version (pyproject/package.json version captured at scan time).
      if (component.version) setImportVersion(String(component.version))
      const name = component.name
      if (!importProject && typeof name === 'string' && !name.startsWith('/')) {
        setImportProject(name)
      }
    } catch {
      setImportNote('That file is not JSON; the upload will be rejected.')
    }
  }

  function openImport() {
    setImportProject(projectSlug)
    setImportVersion('')
    setImportFile(null)
    setImportNote('')
    setImportOpen(true)
  }

  async function submitImport() {
    if (!importFile) { setImportNote('Pick a CycloneDX JSON file.'); return }
    if (!importProject.trim() || !importVersion.trim()) {
      setImportNote('Project and version are both required.'); return
    }
    setImportBusy(true); setImportNote('')
    try {
      const params = new URLSearchParams({
        source: 'web', project: importProject.trim(),
        version: importVersion.trim(), filename: importFile.name })
      const response = await api.postRaw(`/api/v1/sbom?${params.toString()}`,
        await importFile.arrayBuffer())
      const counts = response.receipt?.counts || {}
      setReceipt(response)
      setImportOpen(false)
      setProjectSlug(importProject.trim())
      setVersion(importVersion.trim())
      setSearch(''); setOnlyVulnerable(false)
      // The sidebar's project list is owned by App; ask it to re-read so the
      // freshly created version shows up in the selector.
      if (onChanged) await onChanged()
    } catch (problem) {
      setImportNote(String(problem.message || problem))
    }
    setImportBusy(false)
  }

  return (
    <div className="stack">
      <PageHeader
        title="Components"
        subtitle={project ? `${project.name}${version ? ` · ${version}` : ''}` : 'Pick a project version'}
        actions={(
          <>
            <select value={projectSlug} aria-label="project"
              onChange={(event) => {
                const next = projects.find((p) => p.slug === event.target.value)
                setProjectSlug(event.target.value)
                setVersion(next?.versions?.[0] || '')
                setImpact({ id: null, data: null, error: '' })
              }}>
              {projects.map((entry) => (
                <option key={entry.slug} value={entry.slug}>{entry.name}</option>
              ))}
            </select>
            <select value={version} aria-label="version" disabled={!versions.length}
              onChange={(event) => setVersion(event.target.value)}>
              {versions.map((entry) => <option key={entry} value={entry}>{entry}</option>)}
            </select>
            <button onClick={openImport}>import SBOM…</button>
          </>
        )}
      />

      {profile && (
        <Card>
          <div className="metrics">
            <Stat label="components" value={profile.components.total} />
            <Stat label="vulnerable" value={profile.findings.vulnerable_components}
              tone={profile.findings.vulnerable_components ? 'warn' : ''} />
            <Stat label="findings" value={profile.findings.total} />
            <Stat label="critical" value={profile.findings.by_severity.CRITICAL}
              tone={profile.findings.by_severity.CRITICAL ? 'bad' : ''} />
            <Stat label="licenses" value={profile.licenses.distinct} />
          </div>
        </Card>
      )}

      <div className="toolbar">
        <input placeholder="search name, purl or license" value={search}
          onChange={(event) => setSearch(event.target.value)} style={{ minWidth: 260 }} />
        <label className="row" style={{ gap: 6 }}>
          <input type="checkbox" checked={onlyVulnerable}
            onChange={(event) => setOnlyVulnerable(event.target.checked)} />
          only with findings
        </label>
        <span className="spacer" />
        <span className="count">
          {loading ? 'loading…' : `${visible.length} / ${rows.length} shown`}
        </span>
      </div>

      {error && <ErrorBanner error={error} />}
      {receipt && (
        <div className="banner banner-ok">
          import {receipt.status} — {receipt.receipt.counts.components_created} created,
          {' '}{receipt.receipt.counts.components_updated} updated,
          {' '}{receipt.receipt.counts.links_created} links
        </div>
      )}

      {loading && !rows.length ? <Loading rows={6} /> : null}

      {!loading && !visible.length && !error && (
        <EmptyState title="No components match"
          hint={rows.length
            ? 'Clear the search or the "only with findings" filter.'
            : 'Upload an SBOM for this version to create its inventory.'} />
      )}

      {!!visible.length && (
        <table>
          <thead>
            <tr>
              <th>name</th><th>version</th><th>license</th><th>findings</th>
              <th>manifest</th><th></th>
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => (
              <React.Fragment key={row.id}>
                <tr>
                  <td className="title">
                    {row.name}
                    {row.purl && <div className="muted mono" style={{ fontSize: 11 }}>{row.purl}</div>}
                  </td>
                  <td>{row.version || '—'}</td>
                  <td className="muted">{row.license || '—'}</td>
                  <td>
                    {row.findings
                      ? <span className={`sev sev-${(row.worst || 'unknown').toLowerCase()}`}>
                        {row.findings.total}
                      </span>
                      : <span className="muted">—</span>}
                  </td>
                  <td className="muted mono" style={{ fontSize: 11.5 }}>
                    {row.manifest_path || '—'}
                  </td>
                  <td>
                    <button className="mini" onClick={() => showImpact(row)}>
                      {impact.id === row.id ? 'hide' : 'impact'}
                    </button>
                  </td>
                </tr>
                {impact.id === row.id && (
                  <tr className="detail-row"><td colSpan={6}>
                    <div className="detail">
                      {impact.error && <ErrorBanner error={impact.error} />}
                      {impact.data && (
                        <>
                          <p className="muted">
                            used by {impact.data.projects_using} project versions ·
                            {' '}{impact.data.total_findings} findings
                            {' '}({impact.data.open_findings} open)
                          </p>
                          {impact.data.usages.map((usage) => (
                            <div key={`${usage.project}@${usage.version}`} className="occ-row">
                              <strong>{usage.project}@{usage.version}</strong>
                              {' '}— {usage.open_findings} open / {usage.findings} total
                              {' '}{Object.entries(usage.by_severity)
                                .filter(([, count]) => count)
                                .map(([sev, count]) => `${sev}:${count}`).join(' ')}
                            </div>
                          ))}
                        </>
                      )}
                    </div>
                  </td></tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      )}

      <Dialog open={importOpen} title="Import an SBOM" confirmLabel="import"
        onClose={() => setImportOpen(false)} onConfirm={submitImport}>
        <div className="stack">
          <label className="field-label" htmlFor="sbom-file">CycloneDX JSON</label>
          <input id="sbom-file" ref={fileInput} type="file" accept=".json,application/json"
            onChange={(event) => pickFile(event.target.files[0])} />
          <label className="field-label" htmlFor="sbom-project">project</label>
          <input id="sbom-project" value={importProject} list="sbom-projects"
            placeholder="existing project, or type a new name"
            onChange={(event) => setImportProject(event.target.value)} />
          <datalist id="sbom-projects">
            {projects.map((entry) => <option key={entry.slug} value={entry.slug} />)}
          </datalist>
          <label className="field-label" htmlFor="sbom-version">version</label>
          <input id="sbom-version" value={importVersion}
            placeholder="taken from the SBOM when it declares one"
            onChange={(event) => setImportVersion(event.target.value)} />
          <p className="muted" style={{ fontSize: 12 }}>
            A new version is created for the project if it does not exist yet;
            re-importing the same file into the same version is a no-op.
            {importBusy ? ' importing…' : ''}
          </p>
          {importNote && <div className="banner banner-error">{importNote}</div>}
        </div>
      </Dialog>
    </div>
  )
}
