import React, { useEffect, useState } from 'react'
import { api } from './api'
import Highlight from './highlight'
import {
  EmptyState, ErrorBanner, PageHeader, Pager, Select, SeverityBadge, Table, Tabs,
  serverPager,
} from './ui'
import { useI18n } from './i18n'

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
  const { t, tOr } = useI18n()
  return (
    <span className={CLASS_STYLES[value] || 'muted'}>
      {value === 'no_reference' ? t('analysis.class.noReference') : tOr('analysis.class.' + value, value)}
    </span>
  )
}

export default function Analysis({ projects, onOpenFinding, focusRun }) {
  const { t, tCount, tOr } = useI18n()
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
        title={t('analysis.title')}
        subtitle={t('analysis.subtitle')}
      />

      <div className="toolbar">
        <select value={project} onChange={(e) => setProject(e.target.value)}>
          <option value="">{t('analysis.pickProject')}</option>
          {projects.map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}
        </select>
        <button className="mini" onClick={loadRuns}>{t('common.refresh')}</button>
        <span className="muted">
          {t('analysis.runsNote')}
        </span>
        <span className="row-end">
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit={t('unit.runs')} />
        </span>
      </div>

      {error && <ErrorBanner error={error} />}

      {runs.length ? (
        <Table head={[t('analysis.col.when'), t('analysis.col.tool'), t('analysis.col.coverage'),
          t('analysis.col.revision'), t('analysis.col.origin'), t('analysis.col.findings'),
          t('analysis.col.baseline'), '']}>
          {runs.map((row) => (
            <tr key={row.id} className={run?.id === row.id ? 'selected' : ''}>
              <td className="muted">{new Date(row.created_at).toLocaleString()}</td>
              <td className="title">
                {row.tool}
                <div className="muted" style={{ fontSize: 11.5 }}>
                  {row.tool_version || t('analysis.versionUnknown')}
                  {row.report_format ? ` · ${row.report_format}` : ''}
                </div>
              </td>
              <td>
                <span className={row.coverage === 'full' ? 'pill' : 'sev sev-medium'}>
                  {tOr('coverage.' + row.coverage, row.coverage)}
                </span>
              </td>
              <td className="mono muted">
                {row.revision ? row.revision.slice(0, 10) : '—'}
                <div style={{ fontSize: 11.5 }}>
                  {row.branch || t('analysis.branchUnknown')}
                  {row.pull_request ? ` · PR ${row.pull_request}` : ''}
                </div>
              </td>
              <td className="muted" style={{ fontSize: 12 }}>
                {row.repository
                  ? <span title={row.repository.remote_url || ''}>{row.repository.name}</span>
                  : t('analysis.noRepository')}
              </td>
              <td>{row.findings_seen}</td>
              <td className="muted">
                {row.base_run_id ? t('analysis.comparableBase') : t('analysis.noReference')}
              </td>
              <td>
                <button className="mini" onClick={() => openRun(row)}>
                  {run?.id === row.id ? t('analysis.action.hide') : t('analysis.action.open')}
                </button>
              </td>
            </tr>
          ))}
        </Table>
      ) : (
        !error && <EmptyState title={t('analysis.empty.runs.title')}
          hint={t('analysis.empty.runs.hint')} />
      )}
      {pager.pages > 1 && (
        <div className="row row-end" style={{ marginTop: 10 }}>
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit={t('unit.runs')} />
        </div>
      )}

      {run && (
        <>
          <Tabs
            tabs={[
              { id: 'code', label: t('analysis.tab.files', { n: files.length }) },
              { id: 'diff', label: t('analysis.tab.diff') },
              { id: 'findings', label: t('analysis.tab.results') },
            ]}
            active={tab}
            onChange={loadTab}
          />

          {tab === 'code' && (
            <div className="detail">
              <dl>
                <dt>{t('analysis.field.files')}</dt>
                <dd>
                  {files.length ? files.map((item) => (
                    <div key={item.path} className="occ-row">
                      <button className="mini" onClick={() => openFile(run.id, item.path)}>
                        {item.path}
                      </button>
                      {' '}
                      <span className="muted">
                        {item.kind === 'reported-only'
                          ? t('analysis.file.referenced')
                          : tCount('analysis.file.lines', item.line_count)}
                        {' · '}{tCount('analysis.file.results', item.findings)}
                      </span>
                      {path === item.path && <span className="pill">{t('common.open')}</span>}
                    </div>
                  )) : <span className="muted">{t('analysis.file.noReferences')}</span>}
                </dd>
                <dt>{t('common.source')}</dt>
                <dd>
                  {!contentAvailable && (
                    <span className="muted">
                      {t('analysis.source.noSnapshot')}
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
                                {hit.rule_id} · {hit.cwe || t('analysis.noCwe')} · {hit.message}
                              </span>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <span className="muted">
                      {file ? file.reason : t('analysis.file.pick')}
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
                  <dt>{t('analysis.diff.touched')}</dt>
                  <dd className="muted">
                    {t('analysis.diff.counts', {
                      added: diff.touched_lines.added,
                      removed: diff.touched_lines.removed,
                    })}
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
                            <span className="muted">{t('analysis.diff.findingsInFile')}</span>
                            {entry.findings.map((finding) => (
                              <button key={finding.id} className="pill"
                                onClick={() => finding.finding_id && onOpenFinding?.(finding.finding_id)}>
                                {finding.line}: {finding.rule_id}
                                {finding.on_modified_line ? t('analysis.diff.onChangedLine') : ''}
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
              <EmptyState title={t('analysis.empty.diff.title')}
                hint={diff?.reason || t('analysis.empty.diff.hint')} />
            )
          )}

          {tab === 'findings' && (
            findings.length ? (
              <Table head={[t('analysis.col.file'), t('analysis.col.line'),
                t('analysis.col.rule'), t('common.severity'), t('analysis.col.cwe'),
                t('analysis.col.class'), t('analysis.col.modifiedLine'), '']}>
                {findings.map((item) => (
                  <tr key={item.id}>
                    <td className="mono">{item.path}</td>
                    <td>{item.line || '—'}</td>
                    <td className="mono">{item.rule_id}</td>
                    <td><SeverityBadge severity={item.severity} /></td>
                    <td>{item.cwe || <span className="muted">{t('common.unknown')}</span>}</td>
                    <td><Classification value={item.classification} /></td>
                    <td className="muted">
                      {item.on_modified_line ? t('common.yes') : t('common.no')}
                      {item.introduced_by_pr && t('analysis.introduced')}
                    </td>
                    <td>
                      {item.finding_id && onOpenFinding && (
                        <button className="mini" onClick={() => onOpenFinding(item.finding_id)}>
                          {t('analysis.openFinding')}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              <EmptyState title={t('analysis.empty.results')} />
            )
          )}
        </>
      )}
    </div>
  )
}
