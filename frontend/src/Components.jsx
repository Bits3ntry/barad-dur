import React, { useEffect, useRef, useState } from 'react'
import { api } from './api'

export default function Components({ projects }) {
  const [state, setState] = useState({ total: 0, rows: [], error: '', loading: false, receipt: null })
  const project = projects[0]
  const version = project?.versions?.[0] || ''
  const fileInput = useRef(null)
  const [impact, setImpact] = useState({ id: null, data: null, error: '' })

  async function showImpact(row) {
    if (impact.id === row.id) { setImpact({ id: null, data: null, error: '' }); return }
    try {
      const response = await api.get(`/api/v1/components/impact?component_id=${row.id}`)
      setImpact({ id: row.id, data: response.data, error: '' })
    } catch (e) {
      setImpact({ id: row.id, data: null, error: String(e.message || e) })
    }
  }

  useEffect(() => {
    if (!project || !version) return
    setState((s) => ({ ...s, loading: true, error: '' }))
    api.get(`/api/v1/components?project=${encodeURIComponent(project.slug)}&version=${encodeURIComponent(version)}`)
      .then((data) => setState((s) => ({ ...s, rows: data.data, total: data.total, loading: false })))
      .catch((error) => setState((s) => ({ ...s, loading: false, error: String(error.message || error) })))
  }, [project?.id, version])

  async function upload(file) {
    if (!file) return
    setState((s) => ({ ...s, error: '', receipt: null }))
    try {
      const raw = await file.arrayBuffer()
      const params = new URLSearchParams({
        source: 'web', project: project.slug, version,
        filename: file.name,
      })
      const receipt = await api.postRaw(`/api/v1/sbom?${params.toString()}`, raw)
      setState((s) => ({ ...s, receipt }))
      const refreshed = await api.get(`/api/v1/components?project=${encodeURIComponent(project.slug)}&version=${encodeURIComponent(version)}`)
      setState((s) => ({ ...s, rows: refreshed.data, total: refreshed.total }))
    } catch (error) {
      setState((s) => ({ ...s, error: String(error.message || error) }))
    }
    if (fileInput.current) fileInput.current.value = ''
  }

  return (
    <div>
      <div className="bar">
        <span className="count">{state.loading ? 'loading…' : `${state.total} components @ ${project?.name || '—'} ${version}`}</span>
        <label className="button">
          <input ref={fileInput} type="file" accept=".json,application/json" hidden onChange={(e) => upload(e.target.files[0])} />
          upload SBOM (cyclonedx json)
        </label>
        <span className="hint">ingests via the platform API (source=web)</span>
      </div>
      {state.error && <p className="error">{state.error}</p>}
      {state.receipt && (
        <p className="receipt">
          import {state.receipt.status} — {state.receipt.receipt.counts.components_created} created,
          {' '}{state.receipt.receipt.counts.components_updated} updated,
          {' '}{state.receipt.receipt.counts.links_created} links (receipt {state.receipt.import_id})
        </p>
      )}
      <table>
        <thead><tr><th>purl</th><th>name</th><th>version</th><th>license</th><th>manifest</th><th>direct</th><th></th></tr></thead>
        <tbody>
          {state.rows.map((row) => (
            <React.Fragment key={row.id}>
              <tr>
                <td className="mono">{row.purl || '—'}</td>
                <td>{row.name}</td>
                <td>{row.version || '—'}</td>
                <td>{row.license || '—'}</td>
                <td>{row.manifest_path || '—'}</td>
                <td>{row.is_direct ? 'direct' : ''}</td>
                <td><button className="mini" onClick={() => showImpact(row)}>
                  {impact.id === row.id ? 'hide impact' : 'impact'}
                </button></td>
              </tr>
              {impact.id === row.id && (
                <tr className="detail-row"><td colSpan={7}>
                  <div className="detail">
                    {impact.error && <p className="error">{impact.error}</p>}
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
                            {' '}— {usage.open_findings} open /
                            {' '}{usage.findings} total
                            {' '}{Object.entries(usage.by_severity)
                              .map(([sev, count]) => `${sev}:${count}`).join(' ')}
                            {usage.is_direct ? ' · direct' : ''}
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
      {!state.rows.length && !state.loading && !state.error && <p className="empty">No components for this version.</p>}
    </div>
  )
}
