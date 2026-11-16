import React, { useEffect, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import {
  Card, Drawer, EmptyState, ErrorBanner, Loading, Pager, PageHeader, SeverityBadge,
  Table, serverPager,
} from './ui'

/* An ACTION is one workflow execution: a pipeline asked for a closed-catalog
   action (code, supply-chain, web-surface) and the platform watched it run. A
   SCANNER is the same machinery started by hand — from the CLI or the console —
   and it belongs to Orchestration, where an operator can cancel and re-run it.
   Listing both here made one table answer two different questions.

   The row is a COMMIT, not an execution. A workflow that is retried, cancelled
   and re-run leaves five rows on one sha, and the question a person arrives
   with is about the commit ("is this build green?"). The row speaks with its
   newest run — the one that owns the findings today — and opens in place to
   show the attempts behind it, so a green retry cannot bury a red attempt. */

const PER_PAGE = 25
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

function when(value) {
  return value ? new Date(value).toLocaleString() : '—'
}

function clock(value) {
  return value ? new Date(value).toLocaleTimeString() : '—'
}

function shortSha(sha) {
  return sha ? `${sha.slice(0, 8)}…` : '—'
}

/* Who launched the run. On a pull request that is the person who opened it, not
   the machine that pushed a merge commit — the human is the one you go ask. */
function actorOf(action) {
  if (action.pull_request && action.pull_request_author) return action.pull_request_author
  return action.actor || '—'
}

function versionLabel(action) {
  return [action.project, action.component, action.version].filter(Boolean).join(' · ')
}

function severityBreakdown(findings, t) {
  const bySeverity = findings?.by_severity || {}
  const open = Object.entries(bySeverity)
    .map(([severity, count]) => `${count} ${severity}`)
    .join(' · ') || t('common.none')
  return findings?.closed
    ? t('pipelines.findings.openClosed', { open, closed: findings.closed })
    : t('pipelines.findings.openOnly', { open })
}

/* One line out of a timeline event's free-form detail: enough to read the story
   without dumping raw JSON into a drawer. */
function detailText(detail, t) {
  const parts = []
  if (detail.action) parts.push(t('pipelines.detail.action', { action: detail.action }))
  if (detail.task) parts.push(t('pipelines.detail.task', { task: detail.task }))
  if (detail.tool) parts.push(detail.tool)
  if (detail.counts) {
    const counts = Object.entries(detail.counts).map(([key, value]) => `${value} ${key}`).join(', ')
    if (counts) parts.push(counts)
  }
  if (detail.ingested) {
    const counters = detail.ingested.counters
    if (counters) {
      parts.push(t('pipelines.detail.ingested', {
        created: counters.created ?? 0, existing: counters.existing ?? 0,
      }))
    }
    const components = detail.ingested.components
    const advisories = detail.ingested.vulnerabilities_received
    if (components != null || advisories != null) {
      parts.push(t('pipelines.detail.advisories', {
        components: components ?? 0, advisories: advisories ?? 0,
      }))
    }
  }
  if (detail.host) parts.push(t('pipelines.detail.host', { host: detail.host }))
  if (detail.contract_version) {
    parts.push(t('pipelines.detail.contract', { version: detail.contract_version }))
  }
  if (detail.duration_s != null) parts.push(`${detail.duration_s}s`)
  if (detail.gap_s != null) parts.push(t('pipelines.detail.gap', { seconds: detail.gap_s }))
  if (detail.reason) parts.push(detail.reason)
  if (detail.error) parts.push(detail.error)
  return parts.join(' · ')
}

/* The group's verdict is its newest run's; when the attempts behind it disagree
   the row says so instead of pretending one number answered for all of them. */
function disagreement(group, tCount) {
  if (group.earlier_failed) {
    return tCount('pipelines.disagreement.failed', group.earlier_failed)
  }
  if (group.earlier_running) {
    return tCount('pipelines.disagreement.running', group.earlier_running)
  }
  return ''
}

function Field({ label, children }) {
  return (
    <div className="row" style={{ gap: 10, alignItems: 'baseline' }}>
      <span className="muted" style={{ flex: '0 0 92px' }}>{label}</span>
      <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>{children}</span>
    </div>
  )
}

export default function Pipelines({ onOpenFinding, onNewPipeline }) {
  const { t, tCount, tOr } = useI18n()
  const [state, setState] = useState({ commits: [], total: 0, counters: {}, error: '', loading: true })
  const [offset, setOffset] = useState(0)
  const pager = serverPager(state.total, PER_PAGE, offset, setOffset)
  const [expanded, setExpanded] = useState({})
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState({ scan: null, findings: [], timeline: [], error: '', loading: false })

  function load(from = offset) {
    setState((s) => ({ ...s, loading: true, error: '' }))
    api.get(`/api/v1/pipeline/commits?limit=${PER_PAGE}&offset=${from}`)
      .then((response) => setState({
        commits: response.data || [], total: response.total || 0,
        counters: response.counters || {}, error: '', loading: false,
      }))
      .catch((error) => setState((s) => ({
        ...s, loading: false, error: String(error.message || error),
      })))
  }

  useEffect(() => { load(offset) }, [offset])

  function toggle(key) {
    setExpanded((open) => ({ ...open, [key]: !open[key] }))
  }

  async function open(action) {
    setSelected(action)
    setDetail({ scan: null, findings: [], timeline: [], error: '', loading: true })
    try {
      const [scan, findings, timeline] = await Promise.all([
        api.get(`/api/v1/scans/${action.id}`),
        api.get(`/api/v1/scans/${action.id}/findings`),
        api.get(`/api/v1/scans/${action.id}/timeline`),
      ])
      setDetail({
        scan: scan.data, findings: findings.data || [],
        timeline: timeline.data || [], error: '', loading: false,
      })
    } catch (error) {
      setDetail({
        scan: null, findings: [], timeline: [],
        error: String(error.message || error), loading: false,
      })
    }
  }

  const { commits, counters } = state
  const pagerNode = (
    <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
      total={pager.total} perPage={PER_PAGE} unit={t('pipelines.pagerUnit')} />
  )

  return (
    <div className="stack">
      <PageHeader
        title={t('pipelines.title')}
        subtitle={t('pipelines.subtitle')}
        actions={(
          <button className="primary-action" onClick={() => onNewPipeline?.()}>
            {t('pipelines.newPipeline')}
          </button>
        )} />
      <div className="toolbar">
        <span className="count">
          {t('pipelines.counters.summary', {
            commits: counters.commits || 0, runs: counters.runs || 0,
          })}
        </span>
        {counters.fail > 0 && (
          <span className="status verdict-fail">
            {t('pipelines.counters.failing', { n: counters.fail })}
          </span>
        )}
        {counters.running > 0 && (
          <span className="count">{t('pipelines.counters.running', { n: counters.running })}</span>
        )}
        {counters.superseded > 0 && (
          <span className="count" title={t('pipelines.counters.supersededHint')}>
            {t('pipelines.counters.superseded', { n: counters.superseded })}
          </span>
        )}
        <span className="row-end">
          {pagerNode}
          <button className="mini" onClick={() => load()}>{t('common.refresh')}</button>
        </span>
      </div>
      {state.error && <ErrorBanner error={state.error} onRetry={() => load()} />}

      {state.loading && !commits.length ? (
        <Loading rows={4} label={t('pipelines.loadingRuns')} />
      ) : (
        <Table
          head={[
            t('pipelines.column.started'), t('pipelines.column.commit'), t('pipelines.column.ref'),
            t('pipelines.column.event'), t('pipelines.column.actor'), t('pipelines.column.runs'),
            t('pipelines.column.verdict'), t('pipelines.column.findings'),
          ]}
          empty={!state.error && (
            <EmptyState
              title={t('pipelines.empty.title')}
              hint={t('pipelines.empty.hint')} />
          )}
        >
          {commits.map((group) => {
            const isOpen = !!expanded[group.key]
            const note = disagreement(group, tCount)
            return (
              <React.Fragment key={group.key}>
                <tr className={`clickable${isOpen ? ' selected' : ''}`}
                  onClick={() => toggle(group.key)}>
                  <td className="muted">{when(group.started_at)}</td>
                  <td className="mono">
                    {group.commit_url ? (
                      <a href={group.commit_url} target="_blank" rel="noreferrer noopener"
                        onClick={(event) => event.stopPropagation()}
                        title={group.commit}>
                        {shortSha(group.commit)}
                      </a>
                    ) : shortSha(group.commit)}
                    {group.pull_request && (
                      <div className="muted" style={{ fontSize: 11.5 }}>
                        {t('pipelines.pr', { n: group.pull_request })}
                      </div>
                    )}
                  </td>
                  <td className="mono">{group.ref || '—'}</td>
                  <td>{group.event || '—'}</td>
                  <td>{actorOf(group)}</td>
                  <td className="num">
                    {group.counts.total > 1 ? (
                      <span title={t('pipelines.runs.breakdown', {
                        failed: group.counts.fail, passed: group.counts.pass,
                        running: group.counts.running, superseded: group.counts.superseded,
                      })}>
                        {isOpen ? '▾' : '▸'} {tCount('pipelines.runs.total', group.counts.total)}
                      </span>
                    ) : <span className="muted">{t('pipelines.runs.one')}</span>}
                  </td>
                  <td>
                    {group.superseded ? (
                      <span className="status" title={t('pipelines.superseded.hint')}>
                        {t('pipelines.reEvaluated')}
                      </span>
                    ) : (
                      <span className={`status verdict-${group.verdict}`}
                        title={group.verdict_reason}>
                        {group.verdict}
                      </span>
                    )}
                    {note && (
                      <div className="muted" style={{ fontSize: 11.5, marginTop: 2 }}>{note}</div>
                    )}
                  </td>
                  <td className="num"
                    title={group.superseded
                      ? t('pipelines.findings.reportedHint', { n: group.findings?.reported || 0 })
                      : t('pipelines.findings.openHint', {
                        breakdown: severityBreakdown(group.findings, t),
                      })}>
                    {group.superseded
                      ? <span className="muted">{group.findings?.reported || 0}</span>
                      : group.findings?.total || 0}
                  </td>
                </tr>
                {/* The attempts are rows of the same table, one column each, so
                    the eye reads them under the commit they belong to instead of
                    re-learning a second set of column widths. */}
                {isOpen && group.runs.map((run) => (
                  <tr key={run.id} className="pipeline-attempt clickable" onClick={() => open(run)}>
                    <td className="muted">{when(run.started_at)}</td>
                    <td className="mono muted" title={run.id}>↳ {run.id.slice(0, 8)}</td>
                    <td className="mono muted">{run.ref || '—'}</td>
                    <td className="muted">{run.event || '—'}</td>
                    <td className="muted">{actorOf(run)}</td>
                    <td className="muted">
                      {t('pipelines.runRow.meta', {
                        status: tOr(`status.${run.status}`, run.status),
                        evidence: run.evidence,
                      })}
                    </td>
                    <td>
                      <span className={run.superseded ? 'status' : `status verdict-${run.verdict}`}>
                        {run.superseded ? t('pipelines.reEvaluated') : run.verdict}
                      </span>
                    </td>
                    <td className="num">
                      {run.superseded
                        ? <span className="muted">{run.findings?.reported || 0}</span>
                        : run.findings?.total || 0}
                    </td>
                  </tr>
                ))}
              </React.Fragment>
            )
          })}
        </Table>
      )}
      {pager.pages > 1 && (
        <div className="row row-end">{pagerNode}</div>
      )}

      <Drawer open={!!selected} onClose={() => setSelected(null)}
        title={selected
          ? t('pipelines.drawer.title', {
            action: selected.action || t('pipelines.drawer.runFallback'),
            sha: shortSha(selected.commit),
          })
          : t('pipelines.drawer.titleFallback')}>
        {selected && (
          <div className="stack">
            <Card title={t('pipelines.card.result')}>
              <div className="row" style={{ gap: 10, alignItems: 'center' }}>
                <span className={selected.superseded ? 'status' : `status verdict-${selected.verdict}`}>
                  {selected.superseded ? t('pipelines.reEvaluated') : selected.verdict}
                </span>
                <span className="muted" style={{ flex: 1 }}>
                  {selected.superseded
                    ? t('pipelines.superseded.body', { n: selected.findings?.reported || 0 })
                    : selected.verdict_reason}
                </span>
              </div>
              {!selected.superseded && (
                <p className="muted" style={{ marginTop: 8, marginBottom: 0 }}>
                  {t('pipelines.verdict.note')}
                </p>
              )}
              <div className="row" style={{ gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
                <span className="muted">{t('pipelines.meta.run')} <strong>{tOr(`status.${selected.status}`, selected.status)}</strong></span>
                <span className="muted">{t('common.evidence')} <strong>{selected.evidence}</strong></span>
                <span className="muted">{t('common.coverage')} <strong>{selected.coverage || '—'}</strong></span>
                <span className="muted">{t('pipelines.meta.findings')}{' '}
                  <strong>{selected.superseded
                    ? (selected.findings?.reported || 0)
                    : (selected.findings?.total || 0)}</strong>
                </span>
              </div>
            </Card>

            <Card title={t('pipelines.card.where')}>
              <div className="stack" style={{ gap: 8 }}>
                <Field label={t('pipelines.field.repository')}>
                  {selected.repository_url ? (
                    <a href={selected.repository_url} target="_blank" rel="noreferrer noopener">
                      {selected.repository || selected.repository_url}
                    </a>
                  ) : (selected.repository || '—')}
                </Field>
                <Field label={t('pipelines.field.component')}>{versionLabel(selected) || t('pipelines.field.unattributed')}</Field>
                <Field label={t('pipelines.field.ref')}>
                  {selected.ref || '—'}
                  {selected.pull_request && ` · ${t('pipelines.prNumber', { n: selected.pull_request })}`}
                </Field>
                <Field label={t('pipelines.field.commit')}>
                  {selected.commit_url ? (
                    <a href={selected.commit_url} target="_blank" rel="noreferrer noopener"
                      className="mono">
                      {selected.commit}
                    </a>
                  ) : <span className="mono">{selected.commit || '—'}</span>}
                </Field>
                <Field label={t('pipelines.field.actor')}>{actorOf(selected)}</Field>
                <Field label={t('pipelines.field.event')}>{selected.event || '—'}</Field>
                <Field label={t('pipelines.field.started')}>{when(selected.started_at)}</Field>
                <Field label={t('pipelines.field.finished')}>{when(selected.finished_at)}</Field>
              </div>
            </Card>

            {detail.error && <ErrorBanner error={detail.error} />}
            {detail.loading && <Loading rows={3} label={t('pipelines.loadingRun')} />}

            {detail.scan && (
              <>
                <Card title={t('pipelines.card.asked')}>
                  <ul style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6 }}>
                    {(detail.scan.tasks || []).map((task) => (
                      <li key={task.task}>
                        <span className="mono">{task.task}</span>{' '}
                        <span className="muted">· {task.contract} · {task.capability}
                          {task.required ? '' : t('pipelines.task.optional')}</span>
                      </li>
                    ))}
                  </ul>
                  <p className="muted" style={{ marginBottom: 0 }}>
                    {[
                      detail.scan.principal
                        ? t('pipelines.scan.principal', { principal: detail.scan.principal })
                        : '',
                      t('pipelines.scan.deadline', { deadline: when(detail.scan.deadline_at) }),
                    ].filter(Boolean).join(' · ')}
                  </p>
                </Card>

                <Card title={t('pipelines.card.evidence')}>
                  {(detail.scan.evidence_received || []).length ? (
                    <div className="stack" style={{ gap: 6 }}>
                      {(detail.scan.evidence_received || []).map((artifact, index) => (
                        <div key={`${artifact.kind}-${index}`} className="row"
                          style={{ gap: 10, flexWrap: 'wrap' }}>
                          <span className="mono">{artifact.kind}</span>
                          <span className="muted">{Math.round((artifact.bytes || 0) / 1024)} KB</span>
                          <span className="muted">{clock(artifact.at)}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted" style={{ margin: 0 }}>{t('pipelines.evidence.empty')}</p>
                  )}
                </Card>
              </>
            )}

            <Card title={selected.superseded
              ? t('pipelines.findings.cardReported', { n: selected.findings?.reported || 0 })
              : t('pipelines.findings.cardInRun', { n: selected.findings?.total || 0 })
                + (selected.findings?.closed
                  ? t('pipelines.findings.ofTotal', { n: detail.findings.length })
                  : '')}>
              {selected.findings?.closed > 0 && (
                <p className="muted" style={{ marginTop: 0 }}>
                  {t('pipelines.findings.closedNote', { n: selected.findings.closed })}
                </p>
              )}
              {detail.findings.length ? (
                <div className="stack" style={{ gap: 10 }}>
                  {[...detail.findings]
                    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity || 'UNKNOWN')
                      - SEVERITY_ORDER.indexOf(b.severity || 'UNKNOWN'))
                    .map((finding) => (
                      <div key={finding.id} className="stack" style={{ gap: 2 }}>
                        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                          <SeverityBadge severity={finding.severity} />
                          <span className="mono">{finding.kind}</span>
                          {finding.rule_id && <span className="muted">{finding.rule_id}</span>}
                        </div>
                        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                          <span className="mono muted">
                            {finding.path || '—'}{finding.line ? `:${finding.line}` : ''}
                          </span>
                          <span className="muted">· {tOr(`status.${finding.status}`, finding.status)}</span>
                          <button className="mini"
                            onClick={() => onOpenFinding?.(finding.id)}>{t('pipelines.finding.view')}</button>
                        </div>
                      </div>
                    ))}
                </div>
              ) : (
                <p className="muted" style={{ margin: 0 }}>
                  {selected.superseded
                    ? t('pipelines.findings.reEvaluatedEmpty')
                    : t('pipelines.findings.noneEmpty')}
                </p>
              )}
            </Card>

            <Card title={t('pipelines.card.timeline')}>
              {detail.timeline.length ? (
                <div className="stack" style={{ gap: 6 }}>
                  {detail.timeline.map((event) => (
                    <div key={event.seq} className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
                      <span className="mono muted">{clock(event.at_server)}</span>
                      <span>{event.kind}</span>
                      <span className="muted" style={{ flex: 1 }}>
                        {detailText(event.detail || {}, t)}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <p className="muted" style={{ margin: 0 }}>{t('pipelines.timeline.empty')}</p>}
            </Card>
          </div>
        )}
      </Drawer>
    </div>
  )
}
