import React, { useEffect, useState } from 'react'
import { api } from './api'
import Highlight from './highlight'
import {
  EmptyState, ErrorBanner, PageHeader, Pager, Select, SeverityBadge, Table, Tabs,
  serverPager,
} from './ui'

/* The analysis viewer shows what an imported report plus the supplied code
   snapshot can actually prove: the file tree of what was analysed, the code we
   were given, the diff the importer attached, and each result's classification
   against a comparable baseline. When the report references a file nobody
   supplied, the screen says so instead of drawing an empty file. */

const PER_PAGE = 25
const CLASS_STYLES = {
  new: 'sev sev-high',
  persistent: 'pill',
  resolved: 'sev sev-low',
  no_reference: 'muted',
}

function Classification({ value }) {
  return (
    <span className={CLASS_STYLES[value] || 'muted'}>
      {value === 'no_reference' ? 'no reference' : value}
    </span>
  )
}

export default function Analysis({ projects, onOpenFinding, focusRun }) {
  const [project, setProject] = useState('')
  const [runs, setRuns] = useState([])
  const [run, setRun] = useState(null)
  const [tab, setTab] = useState('code')
  const [files, setFiles] = useState([])
  const [contentAvailable, setContentAvailable] = useState(false)
  const [path, setPath] = useState('')
  const [file, setFile] = useState(null)
  const [diff, setDiff] = useState(null)
  const [findings, setFindings] = useState([])
  const [error, setError] = useState('')
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const pager = serverPager(total, PER_PAGE, offset, setOffset)

  useEffect(() => {
    if (!project && projects.length) setProject(projects[0].slug)
  }, [projects])

  // Another project is another question: it starts at its first page, while a
  // page change keeps it. The reset keys off the project, not the offset.
  const lastProject = React.useRef(project)
  useEffect(() => {
    if (lastProject.current !== project) {
      lastProject.current = project
      if (offset !== 0) { setOffset(0); return }
    }
    if (project) loadRuns()
  }, [project, offset])

  // Deep link from a finding: open that run, that file, and scroll to the line.
  useEffect(() => {
    if (!focusRun?.runId) return
    let cancelled = false
    ;(async () => {
      try {
        const [{ data }, listing] = await Promise.all([
          api.get(`/api/v1/analysis/runs/${focusRun.runId}`),
          api.get(`/api/v1/analysis/runs/${focusRun.runId}/files`),
        ])
        if (cancelled) return
        setRun(data)
        setFiles(listing.data || [])
        setContentAvailable(listing.content_available)
        setTab('code')
        const wanted = focusRun.path
          || (listing.data || []).find((item) => item.available)?.path
        if (wanted) {
          await openFile(focusRun.runId, wanted)
          if (focusRun.line) {
            setTimeout(() => {
              const el = document.getElementById(`L${focusRun.line}`)
              if (el) el.scrollIntoView({ block: 'center' })
            }, 80)
          }
        }
      } catch (e) {
        if (!cancelled) setError(String(e.message || e))
      }
    })()
    return () => { cancelled = true }
  }, [focusRun?.runId])

  function loadRuns() {
    api.get(`/api/v1/analysis/runs?project=${encodeURIComponent(project)}`
      + `&limit=${PER_PAGE}&offset=${offset}`)
      .then((r) => { setRuns(r.data || []); setTotal(r.total || 0) })
      .catch((e) => setError(String(e.message || e)))
  }

  async function openRun(row) {
    if (run?.id === row.id) { setRun(null); return }
    setError('')
    setFile(null); setDiff(null); setFindings([]); setPath('')
    try {
      const [{ data }, listing] = await Promise.all([
        api.get(`/api/v1/analysis/runs/${row.id}`),
        api.get(`/api/v1/analysis/runs/${row.id}/files`),
      ])
      setRun(data)
      setFiles(listing.data || [])
      setContentAvailable(listing.content_available)
      setTab('code')
      const first = (listing.data || []).find((item) => item.available)
      if (first) openFile(row.id, first.path)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function openFile(runId, wanted) {
    setPath(wanted)
    setFile(null)
    try {
      const { data } = await api.get(
        `/api/v1/analysis/runs/${runId}/file?path=${encodeURIComponent(wanted)}`)
      setFile(data)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function loadTab(next) {
    setTab(next)
    if (!run) return
    setError('')
    try {
      if (next === 'diff' && !diff) {
        setDiff((await api.get(`/api/v1/analysis/runs/${run.id}/diff`)).data)
      }
      if (next === 'findings' && !findings.length) {
        setFindings((await api.get(`/api/v1/analysis/runs/${run.id}/findings`)).data || [])
      }
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const flagged = new Map()
  for (const item of (file?.findings || [])) {
    flagged.set(item.line, item)
  }
  const lines = (file?.content || '').split('\n')

  return (
    <div className="stack">
      <PageHeader
        title="Code analysis"
        subtitle="Imported SARIF and OpenGrep reports, with the code snapshot and diff the importer supplied"
      />

      <div className="toolbar">
        <select value={project} onChange={(e) => setProject(e.target.value)}>
          <option value="">pick a project</option>
          {projects.map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}
        </select>
        <button className="mini" onClick={loadRuns}>refresh</button>
        <span className="muted">
          Runs are recorded by the import endpoint; nothing here executes code.
        </span>
        <span className="row-end">
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit="runs" />
        </span>
      </div>

      {error && <ErrorBanner error={error} />}

      {runs.length ? (
        <Table head={['when', 'tool', 'coverage', 'revision · branch', 'origin', 'findings', 'baseline', '']}>
          {runs.map((row) => (
            <tr key={row.id} className={run?.id === row.id ? 'selected' : ''}>
              <td className="muted">{new Date(row.created_at).toLocaleString()}</td>
              <td className="title">
                {row.tool}
                <div className="muted" style={{ fontSize: 11.5 }}>
                  {row.tool_version || 'version unknown'}
                  {row.report_format ? ` · ${row.report_format}` : ''}
                </div>
              </td>
              <td>
                <span className={row.coverage === 'full' ? 'pill' : 'sev sev-medium'}>
                  {row.coverage}
                </span>
              </td>
              <td className="mono muted">
                {row.revision ? row.revision.slice(0, 10) : '—'}
                <div style={{ fontSize: 11.5 }}>
                  {row.branch || 'branch unknown'}
                  {row.pull_request ? ` · PR ${row.pull_request}` : ''}
                </div>
              </td>
              <td className="muted" style={{ fontSize: 12 }}>
                {row.repository
                  ? <span title={row.repository.remote_url || ''}>{row.repository.name}</span>
                  : 'no repository'}
              </td>
              <td>{row.findings_seen}</td>
              <td className="muted">
                {row.base_run_id ? 'comparable base' : 'no reference'}
              </td>
              <td>
                <button className="mini" onClick={() => openRun(row)}>
                  {run?.id === row.id ? 'hide' : 'open'}
                </button>
              </td>
            </tr>
          ))}
        </Table>
      ) : (
        !error && <EmptyState title="No analysis imported yet"
          hint="POST a SARIF or OpenGrep JSON report to /api/v1/analysis/import with optional code snapshots and a diff. Without a baseline nothing is labelled new or resolved." />
      )}
      {pager.pages > 1 && (
        <div className="row row-end" style={{ marginTop: 10 }}>
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit="runs" />
        </div>
      )}

      {run && (
        <>
          <Tabs
            tabs={[
              { id: 'code', label: `files (${files.length})` },
              { id: 'diff', label: 'diff' },
              { id: 'findings', label: 'results' },
            ]}
            active={tab}
            onChange={loadTab}
          />

          {tab === 'code' && (
            <div className="detail">
              <dl>
                <dt>files</dt>
                <dd>
                  {files.length ? files.map((item) => (
                    <div key={item.path} className="occ-row">
                      <button className="mini" onClick={() => openFile(run.id, item.path)}>
                        {item.path}
                      </button>
                      {' '}
                      <span className="muted">
                        {item.kind === 'reported-only'
                          ? 'referenced, no snapshot'
                          : `${item.line_count} lines`}
                        {' · '}{item.findings} result(s)
                      </span>
                      {path === item.path && <span className="pill">open</span>}
                    </div>
                  )) : <span className="muted">the report carried no file references</span>}
                </dd>
                <dt>source</dt>
                <dd>
                  {!contentAvailable && (
                    <span className="muted">
                      no code snapshot was supplied for this run: only locations can be shown
                    </span>
                  )}
                  {file && file.available ? (
                    <div className="code">
                      {lines.map((text, index) => {
                        const lineNumber = index + 1
                        const hit = flagged.get(lineNumber)
                        return (
                          <div key={lineNumber} id={`L${lineNumber}`}
                            className={`code-line${hit ? ' code-hit' : ''}`}>
                            <span className="code-num">{lineNumber}</span>
                            <span className="code-text">
                              <Highlight code={text} path={path} />
                            </span>
                            {hit && (
                              <span className="muted" style={{ fontSize: 11.5 }}>
                                {hit.rule_id} · {hit.cwe || 'no CWE'} · {hit.message}
                              </span>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <span className="muted">
                      {file ? file.reason : 'pick a file with an available snapshot'}
                    </span>
                  )}
                </dd>
              </dl>
            </div>
          )}

          {tab === 'diff' && (
            diff && diff.available ? (
              <div className="detail">
                <dl>
                  <dt>touched lines</dt>
                  <dd className="muted">
                    {diff.touched_lines.added} added · {diff.touched_lines.removed} removed
                    {' · '}{diff.note}
                  </dd>
                  {diff.files.map((entry) => (
                    <React.Fragment key={entry.path}>
                      <dt className="mono">{entry.path}</dt>
                      <dd>
                        {entry.hunks.map((hunk, index) => (
                          <div key={index} className="code">
                            <div className="muted mono">{hunk.header}</div>
                            {hunk.lines.map((line, position) => (
                              <div key={position}
                                className={`code-line code-${line.kind}`}>
                                <span className="code-num">
                                  {line.new_line || ''}
                                </span>
                                <span className="code-text">
                                  {line.kind === 'added' ? '+ ' :
                                    line.kind === 'removed' ? '- ' : '  '}
                                  {line.text || ' '}
                                </span>
                              </div>
                            ))}
                          </div>
                        ))}
                        {entry.findings.length > 0 && (
                          <div className="occ-row">
                            <span className="muted">findings in this file: </span>
                            {entry.findings.map((finding) => (
                              <button key={finding.id} className="pill"
                                onClick={() => finding.finding_id && onOpenFinding?.(finding.finding_id)}>
                                {finding.line}: {finding.rule_id}
                                {finding.on_modified_line ? ' (on a changed line)' : ''}
                              </button>
                            ))}
                          </div>
                        )}
                      </dd>
                    </React.Fragment>
                  ))}
                </dl>
              </div>
            ) : (
              <EmptyState title="No diff for this run"
                hint={diff?.reason || 'the importer did not attach a unified diff'} />
            )
          )}

          {tab === 'findings' && (
            findings.length ? (
              <Table head={['file', 'line', 'rule', 'severity', 'cwe', 'class', 'modified line', '']}>
                {findings.map((item) => (
                  <tr key={item.id}>
                    <td className="mono">{item.path}</td>
                    <td>{item.line || '—'}</td>
                    <td className="mono">{item.rule_id}</td>
                    <td><SeverityBadge severity={item.severity} /></td>
                    <td>{item.cwe || <span className="muted">unknown</span>}</td>
                    <td><Classification value={item.classification} /></td>
                    <td className="muted">
                      {item.on_modified_line ? 'yes' : 'no'}
                      {item.introduced_by_pr && ' · introduced by this change'}
                    </td>
                    <td>
                      {item.finding_id && onOpenFinding && (
                        <button className="mini" onClick={() => onOpenFinding(item.finding_id)}>
                          open finding
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              <EmptyState title="No results in this run" />
            )
          )}
        </>
      )}
    </div>
  )
}
