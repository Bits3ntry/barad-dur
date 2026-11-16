import React, { useEffect, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { Banner, Card, EmptyState, ErrorBanner, Loading, PageHeader, Table } from './ui'
import ScanDialog from './ScanDialog'

/* The run screen answers four questions in reading order: what happened
   (verdict), how it flowed (graph), what each step did (table), and what the
   platform and the executor said (trace). The graph is derived from the plan —
   never hand-drawn — so a new profile appears here without touching this file. */

const TONE = {
  ok: 'ok', failed: 'bad', dropped: 'warn', running: 'info', pending: '',
}
const MARK = { ok: '●', failed: '×', dropped: '○', running: '◌', pending: '·' }

function when(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function clock(value) {
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString()
}

function shortId(id) {
  return (id || '').slice(0, 8)
}

/* Step statuses are backend values first: `common.json` already names the ones
   every screen shares, and this screen names the extra one it shows. */
function statusText(value, t, tOr) {
  if (!value) return '—'
  return tOr(`surfaceRun.status.${value}`, tOr(`status.${value}`, value))
}

/* Columns are stages, rows are steps. An edge carries how many items left the
   previous stage, because "23 hosts in, 0 out" is the sentence a graph is for. */
function FlowGraph({ plan, steps, selected, setSelected }) {
  const { t, tOr } = useI18n()
  const stages = plan?.stages || []
  if (!stages.length) return null
  const settled = {}
  steps.forEach((step) => { settled[step.step] = step })
  const columnWidth = 208
  const nodeHeight = 44
  const gapY = 20
  const padding = 18
  let tallest = 1
  const nodes = []
  stages.forEach((stage, column) => {
    tallest = Math.max(tallest, stage.steps?.length || 0)
    ;(stage.steps || []).forEach((step, row) => {
      const seen = settled[step.step] || {}
      nodes.push({
        id: step.step, stage: stage.id, column, row,
        status: seen.status || 'pending',
        items: seen.items_out,
        state: step.state,
        x: padding + column * columnWidth,
        y: padding + row * (nodeHeight + gapY),
      })
    })
  })
  const width = padding * 2 + stages.length * columnWidth - (columnWidth - 168)
  const height = padding * 2 + tallest * (nodeHeight + gapY)
  const byId = {}
  nodes.forEach((node) => { byId[node.id] = node })

  const edges = []
  stages.forEach((stage, column) => {
    const from = stage.from
    ;(stage.steps || []).forEach((step, row) => {
      const target = nodes.find((node) => node.id === step.step)
      if (!target) return
      if (from === 'targets' || !from) {
        edges.push({ key: `in-${step.step}`, x1: 6, y1: padding + 8,
                     x2: target.x, y2: target.y + nodeHeight / 2 })
        return
      }
      const sources = (stages.find((item) => item.id === from)?.steps || [])
      sources.forEach((source, index) => {
        const fromNode = byId[source.step]
        if (!fromNode) return
        edges.push({
          key: `${source.step}-${step.step}`,
          x1: fromNode.x + 168, y1: fromNode.y + nodeHeight / 2,
          x2: target.x, y2: target.y + nodeHeight / 2,
          items: settled[source.step]?.items_out,
        })
      })
    })
  })

  // Nodes are HTML buttons over an SVG that only draws the edges: an SVG <g> does
  // not take a click reliably across browsers, and "click the box to see what it
  // cost" is the whole point of this graph.
  return (
    <div className="flow-canvas" style={{ width, height }}>
      <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height}
           aria-hidden="true">
        {stages.map((stage, column) => (
          <text key={stage.id} x={padding + column * columnWidth} y={12}
                className="flow-stage-label">{stage.id}</text>
        ))}
        {edges.map((edge) => (
          <path key={edge.key}
                d={`M ${edge.x1} ${edge.y1} C ${(edge.x1 + edge.x2) / 2} ${edge.y1}, `
                   + `${(edge.x1 + edge.x2) / 2} ${edge.y2}, ${edge.x2} ${edge.y2}`}
                className="flow-edge" />
        ))}
      </svg>
      {nodes.map((node) => (
        <button key={node.id} type="button"
                className={`flow-card tone-${TONE[node.status] || 'muted'}`
                  + (selected === node.id ? ' is-selected' : '')}
                style={{ left: node.x, top: node.y, width: 168, height: nodeHeight }}
                onClick={() => setSelected(node.id)}>
          <span className="flow-node-title">
            {node.id.split('.').slice(1).join('.') || node.id}
          </span>
          <span className="flow-node-meta">
            {MARK[node.status] || '·'} {statusText(node.status, t, tOr)}
            {node.items !== undefined && node.items !== null
              ? ` · ${t('surfaceRun.flow.out', { n: node.items })}` : ''}
            {node.state && node.state !== 'allow' ? ` · ${node.state}` : ''}
          </span>
        </button>
      ))}
    </div>
  )
}


function Trace({ events }) {
  const { t } = useI18n()
  if (!events?.length) {
    return <EmptyState title={t('surfaceRun.trace.emptyTitle')}
                       hint={t('surfaceRun.trace.emptyHint')} />
  }
  return (
    <ol className="trace">
      {events.map((event) => {
        const detail = event.detail || {}
        const label = detail.step || detail.profile || event.kind
        const why = detail.reason || detail.error || ''
        const counters = detail.counters && Object.keys(detail.counters).length
          ? Object.entries(detail.counters).map(([key, value]) => `${key}=${value}`).join(', ')
          : ''
        return (
          <li key={event.seq} className={`trace-row kind-${event.kind}`}>
            <span className="trace-kind">{event.kind}</span>
            <span className="trace-actor">{detail.tool || event.source}</span>
            <span className="trace-time" title={when(event.at_client || event.at_server)}>
              {clock(event.at_server)}
            </span>
            <span className="trace-body">
              <strong>{label}</strong>
              {detail.plan_hash && (
                <span className="trace-meta"> · {t('surfaceRun.trace.plan',
                  { hash: String(detail.plan_hash).slice(0, 8) })}</span>
              )}
              {detail.basis && <span className="trace-meta"> · {detail.basis}</span>}
              {counters && <span className="trace-meta"> · {counters}</span>}
              {why && <span className="trace-why"> — {why}</span>}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

/* A diff value can be a list (14 paths, 3 MX records). `String([{}, …])` prints
   `[object Object]` once per item, which reads as noise and hides the count. */
function showValue(value, limit = 6) {
  if (Array.isArray(value)) {
    const items = value.map((item) => (typeof item === 'object' && item !== null
      ? JSON.stringify(item) : String(item)))
    const head = items.slice(0, limit).join(', ')
    return items.length > limit ? `${head} … (+${items.length - limit})` : head
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).map(([key, item]) => `${key}=${item}`).join(', ')
  }
  return String(value)
}

export default function SurfaceRun({ runId }) {
  const { t, tOr } = useI18n()
  const [runs, setRuns] = useState([])
  const [flow, setFlow] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState('')
  const [reason, setReason] = useState('')
  const [triageBusy, setTriageBusy] = useState('')
  const [launching, setLaunching] = useState(false)
  const [note, setNote] = useState('')

  useEffect(() => { load() }, [runId])

  // Live while it runs: a scan is a process, and watching it settle step by step is
  // the difference between a report and an instrument. Stops on its own.
  useEffect(() => {
    if (!runId || !flow) return undefined
    const status = flow.run?.status
    if (!['queued', 'leased', 'running', 'accepted'].includes(status)) return undefined
    const timer = setInterval(async () => {
      try { setFlow(await api.get(`/api/v1/surface/runs/${runId}`)) } catch { /* keep */ }
    }, 3000)
    return () => clearInterval(timer)
  }, [runId, flow])

  async function load() {
    setLoading(true)
    setError('')
    try {
      if (runId) {
        setFlow(await api.get(`/api/v1/surface/runs/${runId}`))
        setRuns([])
      } else {
        const body = await api.get('/api/v1/surface/runs')
        setRuns(body.runs || [])
        setFlow(null)
      }
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setLoading(false)
    }
  }

  function open(id) {
    window.location.hash = `surface::${id}`
  }

  async function triage(finding, decision) {
    setTriageBusy(finding.id)
    try {
      await api.post(`/api/v1/surface/runs/${runId}/findings/${finding.id}`,
                     { decision, reason, actor: 'console' })
      setReason('')
      setFlow(await api.get(`/api/v1/surface/runs/${runId}`))
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setTriageBusy('')
    }
  }

  if (loading) return <Loading rows={4} label={t('surfaceRun.loading')} />
  if (error) return <ErrorBanner error={error} onRetry={load} />

  if (!runId) {
    return (
      <>
        <PageHeader
          title={t('surfaceRun.title')}
          subtitle={t('surfaceRun.subtitle')}
          actions={(
            <button onClick={() => { setNote(''); setLaunching(true) }}>
              {t('surfaceRun.newRun')}
            </button>
          )}
        />
        {note && <Banner kind="info">{note}</Banner>}
        {!runs.length ? (
          <EmptyState
            title={t('surfaceRun.empty.title')}
            hint={t('surfaceRun.empty.hint')}
          />
        ) : (
          <Card>
            <Table head={[t('surfaceRun.col.run'), t('surfaceRun.col.profile'),
                          t('unit.targets'), t('surfaceRun.col.where'), t('common.status'),
                          t('surfaceRun.col.steps'), t('surfaceRun.col.observations'),
                          t('surfaceRun.col.started')]}>
              {runs.map((run) => {
                  const counters = run.summary?.counters || {}
                  return (
                    <tr key={run.id} className="clickable" onClick={() => open(run.id)}
                        tabIndex={0} role="button"
                        onKeyDown={(event) => { if (event.key === 'Enter') open(run.id) }}>
                      <td className="mono">#{shortId(run.id)}</td>
                      <td>{run.profile || '—'}</td>
                      <td className="mono truncate">
                        {(run.targets || []).map((target) => target.value).join(', ') || '—'}
                      </td>
                      <td>{run.origin}/{run.executor}</td>
                      <td><span className={`pill status-${run.status}`}>
                        {statusText(run.status, t, tOr)}</span></td>
                      <td>{counters.steps ? `${counters.ok || 0}/${counters.steps}` : '—'}</td>
                      <td>{run.summary?.observations ?? '—'}</td>
                      <td>{when(run.created_at)}</td>
                    </tr>
                )
              })}
            </Table>
          </Card>
        )}
        <ScanDialog open={launching} onClose={() => setLaunching(false)}
                    onStarted={(id, verdict) => {
                      setLaunching(false)
                      setNote(t('surfaceRun.opening', { verdict }))
                      open(id)
                    }} />
      </>
    )
  }

  if (!flow) {
    return <EmptyState title={t('surfaceRun.notFound.title')}
                       hint={t('surfaceRun.notFound.hint')} />
  }

  const run = flow.run || {}
  const steps = flow.steps || []
  const targets = (run.targets || []).map((target) => target.value).join(', ')
  // Completion is not health: a run that finished with skipped steps and partial
  // coverage is not a green run, and painting "finished" green says it was.
  const failed = steps.filter((step) => step.status === 'failed').length
  const skipped = steps.filter((step) => step.status === 'dropped').length
  const coverage = flow.summary?.coverage
  const health = failed ? 'bad' : (skipped || (coverage && coverage !== 'full'))
    ? 'warn' : 'ok'
  const healthLabel = health === 'ok' ? t('surfaceRun.health.clean')
    : health === 'warn' ? t('surfaceRun.health.partial') : t('surfaceRun.health.failed')

  return (
    <>
      <header className="run-hero">
        <div className="run-hero-main">
          <div className="run-eyebrow">
            <span className="run-status">{statusText(run.status, t, tOr)}</span>
            <span className="run-dot">·</span>
            <span>{tOr(`orchestration.profile.${run.profile?.name}`, run.profile?.label || run.profile?.name || 'surface')}</span>
            <span className={`run-health ${health}`}>{healthLabel}</span>
            {['queued', 'leased', 'running', 'accepted'].includes(run.status) && (
              <span className="run-live">{t('surfaceRun.live')}</span>
            )}
          </div>
          <h1 className="run-title">
            {t('surfaceRun.hero.title')} <span className="mono">#{shortId(run.id)}</span>
          </h1>
          <div className="run-chips">
            {(run.targets || []).map((target) => (
              <span className="run-chip" key={target.value}>{target.value}</span>
            ))}
          </div>
          <div className="run-meta">
            <span>{run.origin} / {run.executor}</span>
            <span>{when(run.created_at)}</span>
            <span>{t('surfaceRun.stepCount', { n: steps.length })}</span>
            <span>{t('surfaceRun.evidence', { state: run.evidence_state })}</span>
          </div>
        </div>
        <div className="run-hero-actions">
          <button className="ghost" onClick={() => { window.location.hash = 'surface' }}>
            {t('surfaceRun.allRuns')}
          </button>
        </div>
      </header>
      <p className={`run-verdict ${run.status === 'failed' ? 'bad'
        : steps.some((step) => step.status === 'failed') ? 'warn' : 'ok'}`}>
        {flow.verdict}
      </p>
      <Card title={t('surfaceRun.flow.title')} tight>
        <FlowGraph plan={flow.plan} steps={steps} selected={selected}
                   setSelected={setSelected} />
      </Card>
      {selected && (() => {
        const step = steps.find((row) => row.step === selected) || { step: selected }
        const counters = Object.entries(step.counters || {})
        const start = step.started_at ? new Date(step.started_at) : null
        const end = step.finished_at ? new Date(step.finished_at) : null
        const seconds = start && end ? ((end - start) / 1000).toFixed(1) : null
        return (
          <Card title={t('surfaceRun.step.title', { step: step.step })}
                actions={<button className="ghost" onClick={() => setSelected('')}>
                  {t('common.close')}
                </button>}>
            <div className="step-metrics">
              <div><span className="metric-label">{t('common.status')}</span>
                <span className={`pill status-${step.status}`}>
                  {statusText(step.status || 'pending', t, tOr)}</span></div>
              <div><span className="metric-label">{t('surfaceRun.step.took')}</span>
                <span className="metric-value">{seconds
                  ? t('surfaceRun.step.duration', { value: seconds }) : '—'}</span></div>
              <div><span className="metric-label">{t('surfaceRun.step.items')}</span>
                <span className="metric-value">
                  {step.items_in ?? '—'} → {step.items_out ?? '—'}</span></div>
              <div><span className="metric-label">{t('common.coverage')}</span>
                <span className="metric-value">{step.coverage
                  ? tOr(`coverage.${step.coverage}`, step.coverage) : '—'}</span></div>
              <div><span className="metric-label">{t('surfaceRun.step.tool')}</span>
                <span className="metric-value mono">{step.tool || '—'}</span></div>
              <div><span className="metric-label">{t('surfaceRun.step.artifacts')}</span>
                <span className="metric-value">{(step.artifacts || []).length}</span></div>
              {counters.length > 0 && (
                <div className="metric-wide">
                  <span className="metric-label">{t('surfaceRun.step.counters')}</span>
                  <span className="metric-chips">
                    {counters.map(([key, value]) => (
                      <span className="metric-chip" key={key}>
                        <em>{key}</em> {String(value)}
                      </span>
                    ))}
                  </span>
                </div>
              )}
              {(step.reason || step.error) && (
                <div className="metric-wide">
                  <span className="metric-label">{t('surfaceRun.step.why')}</span>
                  <span className="metric-why">{step.reason || step.error}</span>
                </div>
              )}
            </div>
          </Card>
        )
      })()}

      <Card title={t('surfaceRun.findings.title')}
            actions={flow.findings?.length ? (
              <input className="triage-reason" value={reason}
                     placeholder={t('surfaceRun.findings.reasonPlaceholder')}
                     onChange={(event) => setReason(event.target.value)} />
            ) : null}>
        {!flow.findings?.length ? (
          <p className="hint">{t('surfaceRun.findings.empty')}</p>
        ) : (
          <ul className="triage-list">
            {flow.findings.map((finding) => (
              <li key={finding.id}>
                <span className={`sev sev-${(finding.severity || 'unknown').toLowerCase()}`}>
                  {finding.severity || '—'}
                </span>
                <span className="triage-title">
                  {finding.title}
                  <em className="mono">{finding.url}</em>
                </span>
                <span className={`pill status-${finding.status}`}>
                  {statusText(finding.status, t, tOr)}</span>
                <span className="triage-actions">
                  <button className="mini" disabled={triageBusy === finding.id}
                          onClick={() => triage(finding, 'validate')}>
                    {t('surfaceRun.findings.validate')}
                  </button>
                  <button className="mini ghost" disabled={triageBusy === finding.id}
                          onClick={() => triage(finding, 'dismiss')}>
                    {t('surfaceRun.findings.falsePositive')}
                  </button>
                  <button className="mini ghost" disabled={triageBusy === finding.id}
                          onClick={() => triage(finding, 'accept_risk')}>
                    {t('surfaceRun.findings.acceptRisk')}
                  </button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title={t('surfaceRun.diff.title')}>
        {!flow.diff?.available ? (
          <p className="hint">{flow.diff?.reason
            ? tOr(flow.diff.reason_key, flow.diff.reason)
            : t('surfaceRun.diff.none')}</p>
        ) : (
          <div className="diff">
            <p className="diff-headline">
              {flow.diff.headline}
              {flow.diff.previous_run_id && (
                <button className="ghost" onClick={() => open(flow.diff.previous_run_id)}>
                  {t('surfaceRun.diff.previous')}
                </button>
              )}
            </p>
            <ul className="diff-list">
              {(flow.diff.changed || []).map((row, index) => (
                <li key={`c-${index}`}>
                  <span className="diff-kind">{t('surfaceRun.diff.changed')}</span>
                  <span className="mono">{row.kind} · {row.subject}{row.port ? `:${row.port}` : ''}</span>
                  <span>{row.field}: <del>{showValue(row.before)}</del> → <ins>{showValue(row.after)}</ins></span>
                </li>
              ))}
              {(flow.diff.new || []).map((row, index) => (
                <li key={`n-${index}`}>
                  <span className="diff-kind">{t('surfaceRun.diff.new')}</span>
                  <span className="mono">{row.kind} · {row.subject}{row.port ? `:${row.port}` : ''}</span>
                  <span className="hint">{Object.keys(row.value || {}).join(', ')}</span>
                </li>
              ))}
              {(flow.diff.gone || []).map((row, index) => (
                <li key={`g-${index}`}>
                  <span className="diff-kind">{t('surfaceRun.diff.gone')}</span>
                  <span className="mono">{row.kind} · {row.subject}{row.port ? `:${row.port}` : ''}</span>
                  <span className="hint">{t('surfaceRun.diff.goneHint')}</span>
                </li>
              ))}
              {!flow.diff.counts?.new && !flow.diff.counts?.changed && !flow.diff.counts?.gone && (
                <li><span className="hint">{t('surfaceRun.diff.identical')}</span></li>
              )}
            </ul>
          </div>
        )}
      </Card>
      <Card title={t('surfaceRun.steps.title')}>
        {!steps.length ? (
          <EmptyState title={t('surfaceRun.steps.emptyTitle')}
                      hint={t('surfaceRun.steps.emptyHint')} />
        ) : (
          <Table head={[t('surfaceRun.col.step'), t('common.status'),
                        t('surfaceRun.col.in'), t('surfaceRun.col.out'),
                        t('common.coverage'), t('surfaceRun.col.detail')]}>
            {steps.map((step) => (
                <tr key={`${step.seq}-${step.step}`} className="clickable"
                    onClick={() => setSelected(step.step)}>
                  <td className="mono">{step.step}</td>
                  <td><span className={`pill status-${step.status}`}>
                    {statusText(step.status, t, tOr)}</span></td>
                  <td>{step.items_in ?? '—'}</td>
                  <td>{step.items_out ?? '—'}</td>
                  <td>{step.coverage ? tOr(`coverage.${step.coverage}`, step.coverage) : '—'}</td>
                  <td className="wrap">
                    {step.reason || step.error
                      || Object.entries(step.counters || {}).map(([key, value]) => `${key}=${value}`).join(', ')
                      || '—'}
                  </td>
                </tr>
            ))}
          </Table>
        )}
        {flow.pending?.length ? (
          <p className="hint">{t('surfaceRun.steps.pending', { list: flow.pending.join(', ') })}</p>
        ) : null}
      </Card>
      <Card title={t('surfaceRun.trace.title')}>
        <Trace events={flow.events} />
      </Card>
    </>
  )
}
