import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, ErrorBanner, Loading, PageHeader } from './ui'

/* The first thing an owner needs is not a dashboard: it is the ordered path
   from an empty organization to a working pipeline. Every step reads live
   state, so the guide doubles as a status page. */

const STEPS = [
  {
    key: 'grants',
    label: 'Grants',
    title: 'Authorize what may be scanned',
    hint: 'Nothing is scanned by default. A grant names the capabilities and '
      + 'targets allowed for a project; without one every scan is denied.',
    count: (d) => d.grants,
    unit: 'grants',
  },
  {
    key: 'components',
    label: 'Components',
    title: 'Create a project and ingest an SBOM',
    hint: 'Upload a CycloneDX or SPDX SBOM: the project and version are created '
      + 'from it and its components become the inventory every finding hangs on.',
    count: (d) => d.projects,
    unit: 'projects',
  },
  {
    key: 'gates',
    label: 'Quality gates',
    title: 'Decide what fails a build',
    hint: 'A gate turns findings into a verdict: severity thresholds, known '
      + 'exploited issues, license rules. It is what CI obeys.',
    count: (d) => d.gatePolicies,
    unit: 'policies',
  },
  {
    key: 'findings',
    label: 'Findings',
    title: 'Triage the first findings',
    hint: 'Review what the data says, accept risk with a second approver, and '
      + 'open remediation tasks with owners and deadlines.',
    count: (d) => d.components,
    unit: 'components tracked',
  },
  {
    key: 'pipelines',
    label: 'Pipelines',
    title: 'Connect continuous integration',
    hint: 'Runs reported by CI carry the gate verdict back to the pull request, '
      + 'so the decision happens before merge.',
    count: (d) => d.pipelines,
    unit: 'pipelines',
  },
  {
    key: 'members',
    label: 'Members',
    title: 'Bring the team in',
    hint: 'Analysts triage and write; viewers read. Only an owner is created by '
      + 'bootstrap, so everyone else starts here.',
    count: (d) => d.members,
    unit: 'accounts',
  },
]

const EMPTY = { grants: 0, projects: 0, components: 0, gatePolicies: 0,
  pipelines: 0, members: 0 }

async function safeCount(path, pick) {
  try {
    const body = await api.get(path)
    return pick(body)
  } catch {
    return 0
  }
}

export default function SetupGuide({ onNavigate }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  function load() {
    setError('')
    Promise.all([
      safeCount('/api/v1/authorization/grants', (b) => (b.data || []).length),
      safeCount('/api/v1/projects', (b) => (b.data || []).length),
      safeCount('/api/v1/components?limit=1', (b) => b.total ?? (b.data || []).length),
      safeCount('/api/v1/gate-policies', (b) => (b.data || []).length),
      safeCount('/api/v1/pipelines', (b) => (b.data || []).length),
      safeCount('/api/v1/auth/users', (b) => (b.data || []).length),
    ])
      .then(([grants, projects, components, gatePolicies, pipelines, members]) =>
        setData({ grants, projects, components, gatePolicies, pipelines, members }))
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(load, [])

  if (!data) {
    return (
      <div className="stack">
        <PageHeader title="Set up Barad-dûr"
          subtitle="The ordered path from an empty organization to a working pipeline." />
        <Card>{error ? <ErrorBanner error={error} onRetry={load} /> : <Loading rows={5} />}</Card>
      </div>
    )
  }

  const done = STEPS.filter((step) => step.count(data) > 0)
  const pct = Math.round((done.length / STEPS.length) * 100)
  const nextKey = STEPS.find((step) => step.count(data) === 0)?.key

  return (
    <div className="stack">
      <PageHeader
        title="Set up Barad-dûr"
        subtitle="Six steps, in this order. Each one unlocks the next — this page reads live data, so it also works as a status check."
        actions={<button onClick={load}>refresh</button>}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      <Card>
        <div className="setup-head">
          <div>
            <div className="setup-title">
              {done.length} of {STEPS.length} steps complete
            </div>
            <div className="setup-hint">
              {nextKey
                ? `Next: ${STEPS.find((s) => s.key === nextKey).title.toLowerCase()}.`
                : 'Everything is wired. Review the dashboard for posture and the audit trail for changes.'}
            </div>
          </div>
          <div className="setup-progress" role="progressbar" aria-valuenow={pct}
            aria-valuemin={0} aria-valuemax={100} aria-label="setup progress">
            <span style={{ width: `${pct}%` }} />
          </div>
          <div className="setup-meta">{pct}%</div>
        </div>
      </Card>

      <ol className="setup-steps">
        {STEPS.map((step, index) => {
          const count = step.count(data)
          const isDone = count > 0
          const isCurrent = !isDone && step.key === nextKey
          const className = `setup-step${isDone ? ' done' : ''}${isCurrent ? ' current' : ''}`
          return (
            <li key={step.key} className={className}>
              <span className="setup-num" aria-hidden="true">{isDone ? '✓' : index + 1}</span>
              <div>
                <div className="setup-title">{step.title}</div>
                <div className="setup-hint">{step.hint}</div>
              </div>
              <div className="row">
                <span className="setup-meta">{count} {step.unit}</span>
                <button className={isCurrent ? 'btn-primary mini' : 'mini'}
                  onClick={() => onNavigate && onNavigate(step.key)}>
                  {isDone ? 'open' : 'start'}
                </button>
              </div>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
