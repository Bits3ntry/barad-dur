import React, { useEffect, useState } from 'react'
import { api } from './api'

function Card({ label, value, tone }) {
  return (
    <div className={`metric ${tone || ''}`}>
      <div className="metric-value">{value}</div>
      <div className="metric-label">{label}</div>
    </div>
  )
}

export default function Dashboard({ projects }) {
  const [project, setProject] = useState('')
  const [version, setVersion] = useState('')
  const [summary, setSummary] = useState(null)
  const [posture, setPosture] = useState([])
  const [error, setError] = useState('')

  useEffect(() => { load() }, [project, version])

  function load() {
    setError('')
    const params = new URLSearchParams()
    if (project) params.set('project', project)
    if (project && version) params.set('version', version)
    api.get(`/api/v1/dashboard/summary${params.toString() ? '?' + params : ''}`)
      .then((r) => setSummary(r.data))
      .catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/dashboard/projects')
      .then((r) => setPosture(r.data))
      .catch(() => {})
  }

  const selected = projects.find((p) => p.name === project)

  if (error) return <p className="error">{error}</p>
  if (!summary) return <p className="empty">loading…</p>

  const f = summary.findings
  return (
    <div>
      <div className="bar">
        <select value={project} onChange={(e) => { setProject(e.target.value); setVersion('') }}>
          <option value="">organization — all projects</option>
          {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
        <select value={version} onChange={(e) => setVersion(e.target.value)}
          disabled={!project || !(selected?.versions?.length)}>
          <option value="">latest / all versions</option>
          {(selected?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <span className="count">updated {new Date(summary.generated_at).toLocaleTimeString()}</span>
      </div>

      <div className="metrics">
        <Card label="open findings" value={f.open} />
        <Card label="critical" value={f.by_severity_open.CRITICAL} tone={f.by_severity_open.CRITICAL ? 'bad' : ''} />
        <Card label="high" value={f.by_severity_open.HIGH} />
        <Card label="medium" value={f.by_severity_open.MEDIUM} />
        <Card label="known exploited (KEV)" value={f.kev_open} tone={f.kev_open ? 'bad' : ''} />
        <Card label="SLA breached" value={f.sla_breached} tone={f.sla_breached ? 'bad' : ''} />
        <Card label="SLA due ≤ 2d" value={f.sla_due_within_2d} tone={f.sla_due_within_2d ? 'warn' : ''} />
        <Card label="new last 7d" value={f.new_last_7d} />
        <Card label="resolved last 7d" value={f.resolved_last_7d} tone="good" />
        <Card label="assets" value={summary.assets.total} />
        <Card label="assets new 7d" value={summary.assets.discovered_last_7d} />
        <Card label="occurrences 7d" value={summary.occurrences_last_7d} />
        <Card label="tasks open" value={summary.remediation.open + summary.remediation.in_progress} />
        <Card label="tasks resolved" value={summary.remediation.resolved} tone="good" />
        <Card label="CI pass/fail/pending"
          value={`${summary.ci.verdicts.pass}/${summary.ci.verdicts.fail}/${summary.ci.verdicts.pending}`} />
        {summary.gate && (
          <Card label="quality gate" value={summary.gate.verdict}
            tone={summary.gate.verdict === 'fail' ? 'bad' : 'good'} />
        )}
        {summary.supply_chain && (
          <Card label="denied licenses" value={summary.supply_chain.denied}
            tone={summary.supply_chain.denied ? 'bad' : ''} />
        )}
      </div>

      {summary.gate?.reasons?.length > 0 && (
        <p className="error">gate: {summary.gate.reasons.join(' · ')}</p>
      )}

      <h2 className="section">project posture</h2>
      <table>
        <thead><tr><th>project</th><th>open</th><th>critical</th><th>high</th><th>total</th></tr></thead>
        <tbody>
          {posture.map((row) => (
            <tr key={row.project} className="clickable"
              onClick={() => { setProject(row.project); setVersion('') }}>
              <td className="title">{row.project}</td>
              <td>{row.open}</td>
              <td className={row.critical ? 'sev sev-critical' : ''}>{row.critical}</td>
              <td>{row.high}</td>
              <td>{row.total}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!posture.length && <p className="empty">No projects yet.</p>}
    </div>
  )
}
