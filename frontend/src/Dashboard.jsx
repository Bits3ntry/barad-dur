import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Stat, Table } from './ui'

export default function Dashboard({ projects, onNavigate }) {
  const [project, setProject] = useState('')
  const [version, setVersion] = useState('')
  const [summary, setSummary] = useState(null)
  const [posture, setPosture] = useState([])
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
    api.get('/api/v1/dashboard/projects')
      .then((r) => setPosture(r.data || []))
      .catch(() => setPosture([]))
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

      <Card
        title="Project posture"
        actions={<span className="count">updated {new Date(summary.generated_at).toLocaleTimeString()}</span>}
      >
        <Table
          head={['project', 'open', 'critical', 'high', 'total']}
          empty={<EmptyState title="No projects yet"
            hint="Create a project and ingest an SBOM to see posture here." />}
        >
          {posture.map((row) => (
            <tr key={row.project} className="clickable"
              onClick={() => { setProject(row.project); setVersion('') }}>
              <td className="title">{row.project}</td>
              <td>{row.open}</td>
              <td>{row.critical ? <span className="sev sev-critical">{row.critical}</span> : 0}</td>
              <td>{row.high}</td>
              <td>{row.total}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  )
}
