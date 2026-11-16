import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Stat, SeverityBadge }
  from './ui'
import { DonutChart, BarChart, LineChart } from './Charts'
import ExposureFlow from './ExposureFlow'
import { useI18n } from './i18n'

/* The dashboard answers five questions, in this order, and nothing else:
   how are we, what needs action, what does it cover, is it moving, who runs it.
   Every number below is either a risk indicator or an inventory count, and the
   two are never mixed in one row — a flat grid of eight equal tiles was the
   reason the screen had no reading order. */

function num(value) {
  if (value == null) return '—'
  return Number(value).toLocaleString()
}

/* One verdict, stated once. The CTA is the only solid button on the screen. */
function PostureHero({ risk, scope, onNavigate }) {
  const { t, tCount } = useI18n()
  const exploited = risk.kev || 0
  const critical = risk.critical || 0
  const sla = risk.sla || 0
  const due = risk.due || 0

  const state = exploited > 0 ? t('dashboard.state.actionRequired')
    : critical > 0 ? t('dashboard.criticalOpen')
      : sla > 0 ? t('dashboard.state.pastDue')
        : risk.open === 0 ? t('dashboard.state.nothingOpen') : t('dashboard.state.monitoring')

  const verdict = exploited
    ? tCount('dashboard.verdict.exploited', exploited, { n: num(exploited) })
    : critical
      ? tCount('dashboard.verdict.critical', critical, { n: num(critical) })
      : sla
        ? tCount('dashboard.verdict.pastDue', sla, { n: num(sla) })
        : t('dashboard.verdict.clear')

  const reason = exploited
    ? t('dashboard.reason.exploited')
    : critical
      ? t('dashboard.reason.critical')
      : t('dashboard.reason.observed')

  const tone = exploited || critical ? 'is-urgent' : sla ? 'is-warn' : 'is-ok'

  return (
    <section className={`posture-hero ${tone}`} aria-labelledby="posture-verdict">
      <div className="posture-hero-main">
        <span className="posture-hero-state">{state}</span>
        <h2 className="posture-hero-verdict" id="posture-verdict">{verdict}</h2>
        <p className="posture-hero-reason">{reason} {t('dashboard.hero.scope', { scope })}</p>
        <ul className="posture-hero-facts">
          <li className={exploited ? 'bad' : ''}>
            <strong>{num(exploited)}</strong><span>{t('dashboard.knownExploited')}</span>
          </li>
          <li className={critical ? 'bad' : ''}>
            <strong>{num(critical)}</strong><span>{t('dashboard.criticalOpen')}</span>
          </li>
          <li><strong>{num(risk.open)}</strong><span>{t('dashboard.fact.openTotal')}</span></li>
        </ul>
      </div>
      <div className="posture-hero-actions">
        {exploited > 0 ? (
          <button className="btn-primary" onClick={() => onNavigate?.('vulnerabilities', { kev: 1 })}>
            {t('dashboard.action.reviewExploited', { n: num(exploited) })}
          </button>
        ) : (
          <button className="btn-primary" onClick={() => onNavigate?.('findings')}>
            {t('dashboard.action.openFindings')}
          </button>
        )}
        <button className="mini" onClick={() => onNavigate?.('findings')}>
          {t('dashboard.action.allFindings')}
        </button>
      </div>
    </section>
  )
}

/* Risk band: four numbers that all mean "do something", so they share a row and
   each one is a door to the list behind it. */
function RiskBand({ risk, onNavigate }) {
  const { t } = useI18n()
  const cards = [
    { label: t('dashboard.knownExploited'), value: risk.kev, tone: risk.kev ? 'bad' : '',
      hint: t('dashboard.risk.kev.hint'), go: ['vulnerabilities', { kev: 1 }] },
    { label: t('dashboard.criticalOpen'), value: risk.critical, tone: risk.critical ? 'bad' : '',
      hint: t('dashboard.risk.critical.hint'), go: ['findings'] },
    { label: t('dashboard.risk.sla.label'), value: risk.sla, tone: risk.sla ? 'bad' : '',
      hint: t('dashboard.risk.sla.hint'), go: ['findings'] },
    { label: t('dashboard.risk.due.label'), value: risk.due, tone: risk.due ? 'warn' : '',
      hint: t('dashboard.risk.due.hint'), go: ['findings'] },
  ]
  return (
    <div className="metrics">
      {cards.map((card) => (
        <Stat key={card.label} label={card.label} value={num(card.value)} hint={card.hint}
          tone={card.tone} quiet={!card.tone}
          onClick={onNavigate ? () => onNavigate(...card.go) : undefined} />
      ))}
    </div>
  )
}

/* Coverage band: inventory counts, deliberately quieter than the risk band.
   They answer "what do we know about", never "what is on fire". */
/* A band's footnote is copy the API composes. Deployments that speak the current
   catalogue send `note_key`; an older one sends only the sentence, so the known
   ones are matched here and everything else prints as it arrived. */
const NOTE_KEYS = {
  'counters count what exists; a coverage gap means nothing was observed or evaluated there, not that it is clean':
    'dashboard.note.coverage',
}

function noteFor(note, noteKey, tOr) {
  const known = NOTE_KEYS[String(note || '').trim().toLowerCase()]
  return tOr(noteKey || known || '', note)
}

function CoverageBand({ v0, summary, onNavigate }) {
  const { t, tOr } = useI18n()
  const items = [
    { label: t('dashboard.coverage.assets'), value: v0?.assets?.value ?? summary.assets?.total, go: 'assets' },
    { label: t('dashboard.coverage.projects'), value: v0?.projects?.value, go: 'projects' },
    { label: t('dashboard.coverage.cves'), value: v0?.vulnerabilities?.cves, go: 'vulnerabilities' },
    { label: t('dashboard.coverage.exposures'), value: v0?.exposures?.open, go: 'exposures' },
    { label: t('dashboard.coverage.changes'), value: v0?.recent_changes?.last_7d, go: 'attack-surface' },
  ]
  const coverage = v0?.coverage
  return (
    <>
      <div className="coverage-strip">
        {items.map((item) => (
          <button key={item.label} className="coverage-cell" onClick={() => onNavigate?.(item.go)}
            title={t('dashboard.coverage.openTitle', { label: item.label })}>
            <span className="coverage-value">{num(item.value)}</span>
            <span className="coverage-label">{item.label}</span>
          </button>
        ))}
      </div>
      {coverage && (
        <dl className="coverage-gaps">
          <div className={coverage.assets_without_owner ? 'is-gap' : ''}>
            <dt>{t('dashboard.coverage.withoutOwner')}</dt>
            <dd>{num(coverage.assets_without_owner)}</dd>
          </div>
          <div className={coverage.assets_without_project ? 'is-gap' : ''}>
            <dt>{t('dashboard.coverage.withoutProject')}</dt>
            <dd>{num(coverage.assets_without_project)}</dd>
          </div>
          <div>
            <dt>{t('dashboard.coverage.changeNotes')}</dt>
            <dd>{num(coverage.change_coverage_notes)}</dd>
          </div>
        </dl>
      )}
      {coverage?.note && <p className="dash-footnote">{noteFor(coverage.note, coverage.note_key, tOr)}</p>}
    </>
  )
}

export default function Dashboard({ projects, onNavigate }) {
  const { t } = useI18n()
  const [project, setProject] = useState('')
  const [version, setVersion] = useState('')
  const [summary, setSummary] = useState(null)
  const [portfolio, setPortfolio] = useState([])
  const [exposureFlow, setExposureFlow] = useState(null)
  const [series, setSeries] = useState({ findings: [], occurrences: [] })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [v0, setV0] = useState(null)

  useEffect(() => { load() }, [project, version])

  function load() {
    setError('')
    setLoading(true)
    const params = new URLSearchParams()
    if (project) params.set('project', project)
    if (project && version) params.set('version', version)
    api.get('/api/v1/dashboard/v0')
      .then((r) => setV0(r.data))
      .catch(() => setV0(null))
    api.get(`/api/v1/dashboard/summary${params.toString() ? '?' + params : ''}`)
      .then((r) => setSummary(r.data))
      .catch((e) => setError(String(e.message || e)))
      .finally(() => setLoading(false))
    // Portfolio rolls the same versions up by project, which is the grouping
    // the per-project posture list cannot show (it has no component inventory).
    api.get('/api/v1/inventory/portfolio')
      .then((r) => {
        const byProject = new Map()
        for (const row of r.data || []) {
          // Accounting rule: one version per project — the latest. Summing every
          // historical version would double-count components and findings.
          if (!row.is_latest) continue
          byProject.set(row.project, {
            project: row.project, versions: 1, components: row.components.total,
            findings: row.findings.total, kev: row.findings.kev, group: row.group,
            by_severity: { ...row.findings.by_severity },
          })
        }
        setPortfolio([...byProject.values()].sort((a, b) => a.project.localeCompare(b.project)))
      })
      .catch(() => setPortfolio([]))
    api.get(`/api/v1/dashboard/exposure-flow?window=30${params.toString() ? '&' + params : ''}`)
      .then((r) => setExposureFlow(r.data))
      .catch(() => setExposureFlow(null))
    api.get('/api/v1/dashboard/findings/severity/time-series?window=30')
      .then((r) => setSeries((prev) => ({ ...prev, findings: r.data || [] })))
      .catch(() => setSeries((prev) => ({ ...prev, findings: [] })))
    api.get('/api/v1/dashboard/findings/occurrences/time-series?window=30')
      .then((r) => setSeries((prev) => ({ ...prev, occurrences: r.data || [] })))
      .catch(() => setSeries((prev) => ({ ...prev, occurrences: [] })))
  }

  const selected = projects.find((p) => p.name === project)
  const scope = project ? `${project}${version ? ` · ${version}` : ''}` : t('dashboard.scope.allProjects')

  const header = (
    <PageHeader
      title={t('dashboard.title')}
      subtitle={t('dashboard.subtitle', { scope })}
      actions={(
        <div className="row">
          <select value={project} aria-label={t('dashboard.filter.project')}
            onChange={(e) => { setProject(e.target.value); setVersion('') }}>
            <option value="">{t('dashboard.scope.allProjects')}</option>
            {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
          </select>
          <select value={version} aria-label={t('dashboard.filter.version')}
            onChange={(e) => setVersion(e.target.value)}
            disabled={!project || !(selected?.versions?.length)}>
            <option value="">{t('dashboard.filter.allVersions')}</option>
            {(selected?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
          <button className="icon-btn" onClick={load} title={t('common.refresh')}
            aria-label={t('dashboard.action.refreshMetrics')}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round" aria-hidden="true">
              <path d="M21 12a9 9 0 1 1-3.2-6.9" /><path d="M21 3v6h-6" />
            </svg>
          </button>
        </div>
      )}
    />
  )

  if (loading && !summary) {
    return (
      <div className="stack">
        {header}
        <Card><Loading rows={4} /></Card>
      </div>
    )
  }

  if (error && !summary) {
    return (
      <div className="stack">
        {header}
        <ErrorBanner error={error} onRetry={load} />
      </div>
    )
  }

  const f = summary.findings
  const orchestration = summary.orchestration
  const openFindings = f.by_severity_open || {}
  const emptyOrg = f.total === 0 && (summary.assets?.total ?? 0) === 0
  const risk = {
    open: f.open,
    kev: f.kev_open,
    critical: openFindings.CRITICAL,
    sla: f.sla_breached,
    due: f.sla_due_within_2d,
  }

  return (
    <div className="stack screen-dashboard">
      {header}

      {emptyOrg && onNavigate && (
        <div className="banner banner-info">
          <span>{t('dashboard.empty.noData')}</span>
          <span className="row-end">
            <button className="mini" onClick={() => onNavigate('setup')}>{t('dashboard.action.openSetup')}</button>
          </span>
        </div>
      )}

      {summary.gate?.verdict && (
        <div className={`banner ${summary.gate.verdict === 'fail' ? 'banner-error' : 'banner-ok'}`}>
          <span>
            {t('dashboard.gate.label')} <strong>{summary.gate.verdict}</strong>
            {summary.gate.reasons?.length ? ` — ${summary.gate.reasons.join(' · ')}` : ''}
          </span>
          {onNavigate && (
            <span className="row-end">
              <button className="mini" onClick={() => onNavigate('gates')}>{t('dashboard.action.openGates')}</button>
            </span>
          )}
        </div>
      )}

      <PostureHero risk={risk} scope={scope} onNavigate={onNavigate} />

      <section className="dash-band" aria-labelledby="band-risk">
        <div className="band-head">
          <h2 id="band-risk">{t('dashboard.band.risk.title')}</h2>
          <p>{t('dashboard.band.risk.hint')}</p>
        </div>
        <RiskBand risk={risk} onNavigate={onNavigate} />
      </section>

      <Card band title={t('dashboard.exposureFlow.title')}
        actions={<span className="count">{t('dashboard.exposureFlow.hint')}</span>}>
        <ExposureFlow flow={exposureFlow} onNavigate={onNavigate} />
      </Card>

      <section className="dash-band" aria-labelledby="band-coverage">
        <div className="band-head">
          <h2 id="band-coverage">{t('dashboard.band.coverage.title')}</h2>
          <p>{t('dashboard.band.coverage.hint')}</p>
        </div>
        <Card tight>
          <CoverageBand v0={v0} summary={summary} onNavigate={onNavigate} />
        </Card>
      </section>

      {portfolio.length > 0 && (
        <Card band title={t('dashboard.portfolio.title')}
          actions={onNavigate && (
            <button className="mini" onClick={() => onNavigate('projects')}>{t('dashboard.portfolio.allProjects')}</button>
          )}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('dashboard.portfolio.col.project')}</th><th>{t('dashboard.portfolio.col.group')}</th>
                  <th className="num">{t('dashboard.portfolio.col.components')}</th>
                  <th className="num">{t('dashboard.portfolio.col.findings')}</th>
                  <th className="num">{t('dashboard.portfolio.col.critical')}</th>
                  <th className="num">{t('dashboard.portfolio.col.high')}</th>
                  <th className="num">{t('dashboard.portfolio.col.medium')}</th>
                  <th className="num">{t('dashboard.portfolio.col.kev')}</th>
                </tr>
              </thead>
              <tbody>
                {portfolio.map((row) => (
                  <tr key={row.project} className="clickable"
                    onClick={() => { setProject(row.project); setVersion('') }}
                    title={t('dashboard.portfolio.scopeRow', { project: row.project })}>
                    <td className="ident">{row.project}</td>
                    <td className="muted">{row.group}</td>
                    <td className="num">{num(row.components)}</td>
                    <td className="num">{num(row.findings)}</td>
                    <td className="num">
                      {row.by_severity.CRITICAL
                        ? <span className="sev sev-critical">{row.by_severity.CRITICAL}</span>
                        : <span className="muted">0</span>}
                    </td>
                    <td className="num">
                      {row.by_severity.HIGH
                        ? <span className="sev sev-high">{row.by_severity.HIGH}</span>
                        : <span className="muted">0</span>}
                    </td>
                    <td className="num">
                      {row.by_severity.MEDIUM
                        ? <span className="sev sev-medium">{row.by_severity.MEDIUM}</span>
                        : <span className="muted">0</span>}
                    </td>
                    <td className="num">
                      {row.kev ? <span className="sev sev-critical">{row.kev}</span>
                        : <span className="muted">0</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <section className="dash-band" aria-labelledby="band-trend">
        <div className="band-head">
          <h2 id="band-trend">{t('dashboard.band.trend.title')}</h2>
          <p>{t('dashboard.band.trend.hint')}</p>
        </div>
        <div className="grid grid-3">
          <Card title={t('dashboard.trend.bySeverity.title')}>
            <DonutChart
              height={190}
              data={[
                { label: t('dashboard.severity.critical'), value: openFindings.CRITICAL ?? 0, tone: 'critical' },
                { label: t('dashboard.severity.high'), value: openFindings.HIGH ?? 0, tone: 'high' },
                { label: t('dashboard.severity.medium'), value: openFindings.MEDIUM ?? 0, tone: 'medium' },
                { label: t('dashboard.severity.low'), value: openFindings.LOW ?? 0, tone: 'low' },
                { label: t('dashboard.severity.unknown'), value: openFindings.UNKNOWN ?? 0, tone: 'info' },
              ]} />
          </Card>
          <Card title={t('dashboard.trend.new30d.title')}>
            {series.findings.length ? (
              <LineChart height={190} tone="critical"
                data={series.findings.map((row) => ({
                  label: row.date.slice(5),
                  value: (row.CRITICAL || 0) + (row.HIGH || 0) + (row.MEDIUM || 0)
                    + (row.LOW || 0) + (row.UNKNOWN || 0),
                }))} />
            ) : <EmptyState title={t('dashboard.trend.new30d.empty.title')}
              hint={t('dashboard.trend.new30d.empty.hint')} />}
          </Card>
          <Card title={t('dashboard.trend.newVsResolved.title')}>
            <BarChart height={190} tones={['critical', 'ok']}
              data={[
                { label: t('dashboard.trend.newVsResolved.new'), value: f.new_last_7d ?? 0 },
                { label: t('dashboard.trend.newVsResolved.resolved'), value: f.resolved_last_7d ?? 0 },
              ]} />
            <p className="dash-footnote">
              {t('dashboard.trend.newVsResolved.footnote', {
                new: f.new_last_7d ?? 0, resolved: f.resolved_last_7d ?? 0,
              })}
            </p>
          </Card>
        </div>
      </section>

      <Card band title={t('dashboard.operations.title')}
        actions={onNavigate && (
          <button className="mini" onClick={() => onNavigate('orchestration')}>{t('dashboard.operations.orchestration')}</button>
        )}>
        <div className="metrics">
          {orchestration && (
            <>
              <Stat label={t('dashboard.ops.workersOnline')}
                value={`${orchestration.workers.online}/${orchestration.workers.total}`}
                hint={t('dashboard.ops.workersOnline.hint')}
                tone={orchestration.workers.stale ? 'warn' : 'good'} />
              <Stat label={t('dashboard.ops.jobsQueued')} value={orchestration.jobs.queued}
                hint={t('dashboard.ops.jobsQueued.hint')} />
              <Stat label={t('dashboard.ops.jobsOk24h')} value={orchestration.last_24h.succeeded} tone="good" />
              <Stat label={t('dashboard.ops.jobsFailed24h')} value={orchestration.last_24h.failed}
                tone={orchestration.last_24h.failed ? 'bad' : ''} />
              <Stat label={t('dashboard.ops.avgDuration')}
                value={orchestration.avg_duration_s != null ? `${orchestration.avg_duration_s}s` : '—'}
                hint={orchestration.avg_duration_s != null
                  ? t('dashboard.ops.avgDuration.hint') : t('dashboard.ops.avgDuration.noJobs')} />
            </>
          )}
          <Stat label={t('dashboard.ops.tasksOpen')}
            value={summary.remediation.open + summary.remediation.in_progress}
            hint={t('dashboard.ops.tasksOpen.hint')} />
          <Stat label={t('dashboard.ops.ciVerdicts')} value={`${summary.ci.verdicts.pass}/${summary.ci.verdicts.fail}`}
            hint={t('dashboard.ops.ciVerdicts.hint', { n: summary.ci.verdicts.pending })} />
          {summary.supply_chain && (
            <Stat label={t('dashboard.ops.deniedLicenses')} value={summary.supply_chain.denied}
              tone={summary.supply_chain.denied ? 'bad' : ''}
              hint={t('dashboard.ops.deniedLicenses.hint')} />
          )}
          {summary.pentest && (
            <Stat label={t('dashboard.ops.pentestFindings')} value={summary.pentest.findings_open}
              hint={t('dashboard.ops.pentestFindings.hint', { n: summary.pentest.engagements.active })}
              tone={summary.pentest.findings_open ? 'warn' : ''} />
          )}
        </div>
        {orchestration?.recent_failures?.length > 0 && (
          <details className="ops-failures">
            <summary className="muted">
              {t('dashboard.ops.recentFailures', { n: orchestration.recent_failures.length })}
            </summary>
            {orchestration.recent_failures.map((row, index) => (
              <p key={index} className="muted">
                <strong>{row.scanner}</strong>: {row.error}
              </p>
            ))}
          </details>
        )}
      </Card>

      {error && <ErrorBanner error={error} onRetry={load} />}
    </div>
  )
}
