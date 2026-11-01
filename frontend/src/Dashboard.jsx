import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Stat, Table,
         SeverityBadge, StatusBadge } from './ui'
import { DonutChart, BarChart, LineChart } from './Charts'
import ExposureFlow from './ExposureFlow'

export default function Dashboard({ projects, onNavigate }) {
  const [project, setProject] = useState('')
  const [version, setVersion] = useState('')
  const [summary, setSummary] = useState(null)
  const [portfolio, setPortfolio] = useState([])
  const [portfolioTotals, setPortfolioTotals] = useState(null)
  const [assets, setAssets] = useState([])
  const [series, setSeries] = useState({ findings: [], occurrences: [] })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => { load() }, [project, version])

  function load() {
    setError('')
    setLoading(true)
    const params = new URLSearchParams()
    if (project) params.set('project', project)
    if (project && version) params.set('version', version)
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
          const entry = {
            project: row.project, versions: 1, components: row.components.total,
            findings: row.findings.total, kev: row.findings.kev,
            group: row.group,
            by_severity: { ...row.findings.by_severity },
          }
          byProject.set(row.project, entry)
        }
        setPortfolio([...byProject.values()].sort((a, b) => a.project.localeCompare(b.project)))
        const totals = r.latest_totals || r.totals
        if (totals) {
          setPortfolioTotals({
            ...totals,
            groups: (r.groups || []).length,
            vulnerable_components: (r.data || [])
              .filter((row) => row.is_latest)
              .reduce((sum, row) => sum + (row.findings.vulnerable_components || 0), 0),
          })
        }
      })
      .catch(() => { setPortfolio([]); setPortfolioTotals(null) })
    api.get('/api/v1/assets')
      .then((r) => setAssets(r.data || []))
      .catch(() => setAssets([]))
    api.get('/api/v1/dashboard/findings/severity/time-series?window=30')
      .then((r) => setSeries((prev) => ({ ...prev, findings: r.data || [] })))
      .catch(() => setSeries((prev) => ({ ...prev, findings: [] })))
    api.get('/api/v1/dashboard/findings/occurrences/time-series?window=30')
      .then((r) => setSeries((prev) => ({ ...prev, occurrences: r.data || [] })))
      .catch(() => setSeries((prev) => ({ ...prev, occurrences: [] })))
  }

  const selected = projects.find((p) => p.name === project)
  const scope = project ? `${project}${version ? ` · ${version}` : ''}` : 'all projects'

  const header = (
    <PageHeader
      title="Security posture"
      subtitle={`Organization scope: ${scope}`}
      actions={(
        <>
          <select value={project}
            aria-label="project filter"
            onChange={(e) => { setProject(e.target.value); setVersion('') }}>
            <option value="">all projects</option>
            {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
          </select>
          <select value={version} aria-label="version filter"
            onChange={(e) => setVersion(e.target.value)}
            disabled={!project || !(selected?.versions?.length)}>
            <option value="">all versions</option>
            {(selected?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
          <button onClick={load}>refresh</button>
        </>
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

  return (
    <div className="stack">
      {header}
      {error && <ErrorBanner error={error} onRetry={load} />}

      {summary.findings.total === 0 && (summary.assets?.total ?? 0) === 0
        && onNavigate && (
        <div className="banner banner-info">
          <span>
            No data yet. The setup guide walks the six steps from an empty
            organization to a working pipeline.
          </span>
          <span className="row-end">
            <button className="mini" onClick={() => onNavigate('setup')}>open setup</button>
          </span>
        </div>
      )}

      {summary.gate?.verdict && (
        <div className={`banner ${summary.gate.verdict === 'fail' ? 'banner-error' : 'banner-ok'}`}>
          <span>
            Quality gate <strong>{summary.gate.verdict}</strong>
            {summary.gate.reasons?.length ? ` — ${summary.gate.reasons.join(' · ')}` : ''}
          </span>
          {onNavigate && (
            <span className="row-end">
              <button className="mini" onClick={() => onNavigate('gates')}>open gates</button>
            </span>
          )}
        </div>
      )}

      <Card title="Findings">
        <div className="metrics">
          <Stat label="open" value={f.open} />
          <Stat label="critical" value={openFindings.CRITICAL ?? 0}
            tone={openFindings.CRITICAL ? 'bad' : ''} />
          <Stat label="high" value={openFindings.HIGH ?? 0}
            tone={openFindings.HIGH ? 'warn' : ''} />
          <Stat label="medium" value={openFindings.MEDIUM ?? 0} />
          <Stat label="known exploited" value={f.kev_open} tone={f.kev_open ? 'bad' : ''} />
          <Stat label="SLA breached" value={f.sla_breached} tone={f.sla_breached ? 'bad' : ''} />
          <Stat label="SLA due ≤2d" value={f.sla_due_within_2d}
            tone={f.sla_due_within_2d ? 'warn' : ''} />
          <Stat label="new 7d" value={f.new_last_7d} />
          <Stat label="resolved 7d" value={f.resolved_last_7d}
            tone={f.resolved_last_7d ? 'good' : ''} />
        </div>
      </Card>

      <Card title="Exposure flow"
        actions={<span className="count">click a stage to open it</span>}>
        <ExposureFlow assets={assets} portfolio={portfolioTotals}
          findings={f} onNavigate={onNavigate} />
      </Card>

      {portfolio.length > 0 && (
        <Card title="Portfolio by group and project"
          actions={onNavigate && (
            <button className="mini" onClick={() => onNavigate('projects')}>open projects</button>
          )}>
          <table>
            <thead>
              <tr>
                <th>group</th><th>project</th><th>components</th><th>findings</th>
                <th>critical</th><th>high</th><th>medium</th><th>kev</th>
              </tr>
            </thead>
            <tbody>
              {portfolio.map((row) => (
                <tr key={row.project} className="clickable"
                  onClick={() => { setProject(row.project); setVersion('') }}>
                  <td className="muted">{row.group}</td>
                  <td className="title">{row.project}</td>
                  <td className="num">{row.components}</td>
                  <td className="num">{row.findings}</td>
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
        </Card>
      )}

      {/* Charts — real data from /api/v1/dashboard/summary */}
      <div className="grid grid-2">
        <Card title="Findings distribution">
          {openFindings && (
            <DonutChart
              data={[
                { label: 'critical', value: openFindings.CRITICAL ?? 0 },
                { label: 'high', value: openFindings.HIGH ?? 0 },
                { label: 'medium', value: openFindings.MEDIUM ?? 0 },
                { label: 'low', value: openFindings.LOW ?? 0 },
                { label: 'unknown', value: openFindings.UNKNOWN ?? 0 },
              ]}
              height={200} />
          )}
        </Card>
        <Card title="New vs resolved (7d)">
          <BarChart
            data={[
              { label: 'new', value: f.new_last_7d ?? 0 },
              { label: 'resolved', value: f.resolved_last_7d ?? 0 },
            ]}
            height={200} />
        </Card>
      </div>

      <div className="grid grid-2">
        <Card title="New findings (last 30 days)">
          {series.findings.length ? (
            <LineChart
              data={series.findings.map((row) => ({
                label: row.date.slice(5),
                value: (row.CRITICAL || 0) + (row.HIGH || 0) + (row.MEDIUM || 0)
                  + (row.LOW || 0) + (row.UNKNOWN || 0),
              }))}
              height={190} />
          ) : <EmptyState title="No findings in this window"
            hint="Import an SBOM or run a scan to populate the trend." />}
        </Card>
        <Card title="Scan occurrences (last 30 days)">
          {series.occurrences.length ? (
            <LineChart
              data={series.occurrences.map((row) => ({
                label: row.date.slice(5), value: row.count,
              }))}
              height={190} color="#5a9eec" />
          ) : <EmptyState title="No occurrences in this window" />}
        </Card>
      </div>

      <Card title="Scanner execution health">
        {orchestration && (
          <BarChart
            data={[
              { label: 'queued', value: orchestration.jobs.queued },
              { label: 'leased', value: orchestration.jobs.leased },
              { label: 'running', value: orchestration.jobs.running },
              { label: 'succeeded', value: orchestration.jobs.succeeded },
              { label: 'failed', value: orchestration.jobs.failed },
              { label: 'cancelled', value: orchestration.jobs.cancelled },
            ]}
            height={180}
            colors={['#8b949e', '#5a9eec', '#ff7b00', '#6bcb77', '#ff5a5a', '#7b5ea7']} />
        )}
      </Card>

      {orchestration && (
        <Card title="Quality gate verdict history">
          <p className="muted">
            Historical gate verdicts require the backend to store per-run history.
            See /api/v1/gates for the current verdict.
          </p>
        </Card>
      )}

      <div className="grid grid-2">
        <Card title="Assets and surface">
          <div className="metrics">
            <Stat label="assets" value={summary.assets.total} />
            <Stat label="discovered 7d" value={summary.assets.discovered_last_7d} />
            <Stat label="occurrences 7d" value={summary.occurrences_last_7d} />
          </div>
        </Card>

        <Card title="Remediation and CI">
          <div className="metrics">
            <Stat label="tasks open"
              value={summary.remediation.open + summary.remediation.in_progress} />
            <Stat label="tasks resolved" value={summary.remediation.resolved} tone="good" />
            <Stat label="CI pass/fail/pending"
              value={`${summary.ci.verdicts.pass}/${summary.ci.verdicts.fail}/${summary.ci.verdicts.pending}`} />
            {summary.supply_chain && (
              <Stat label="denied licenses" value={summary.supply_chain.denied}
                tone={summary.supply_chain.denied ? 'bad' : ''} />
            )}
          </div>
        </Card>
      </div>

      {(orchestration || summary.pentest) && (
        <div className="grid grid-2">
          {orchestration && (
            <Card title="Scanner execution">
              <div className="metrics">
                <Stat label="workers online"
                  value={`${orchestration.workers.online}/${orchestration.workers.total}`}
                  tone={orchestration.workers.stale ? 'warn' : 'good'} />
                <Stat label="jobs queued" value={orchestration.jobs.queued} />
                <Stat label="jobs ok 24h" value={orchestration.last_24h.succeeded} tone="good" />
                <Stat label="jobs failed 24h" value={orchestration.last_24h.failed}
                  tone={orchestration.last_24h.failed ? 'bad' : ''} />
                <Stat label="avg duration (s)" value={orchestration.avg_duration_s ?? '—'} />
              </div>
              {orchestration.recent_failures?.length > 0 && (
                <details style={{ marginTop: 12 }}>
                  <summary className="muted">
                    recent job failures ({orchestration.recent_failures.length})
                  </summary>
                  {orchestration.recent_failures.map((row, index) => (
                    <p key={index} className="muted">
                      <strong>{row.scanner}</strong>: {row.error}
                    </p>
                  ))}
                </details>
              )}
            </Card>
          )}
          {summary.pentest && (
            <Card title="Pentest">
              <div className="metrics">
                <Stat label="active engagements" value={summary.pentest.engagements.active} />
                <Stat label="findings open" value={summary.pentest.findings_open}
                  tone={summary.pentest.findings_open ? 'warn' : ''} />
              </div>
            </Card>
          )}
        </div>
      )}

    </div>
  )
}
