import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, ErrorBanner, Loading, PageHeader } from './ui'

/* The first thing an owner needs is not a dashboard: it is the ordered path
   from an empty organization to a working pipeline. Every step reads live
   state, so the guide doubles as a status page. */

const STEPS = [
  {
    key: 'scope',
    label: 'Scope',
    title: 'Define what belongs in scope',
    hint: 'Add domains, repositories, IPs and exclusions first. Connecting an '
      + 'integration never starts a scan automatically.',
    count: (d) => d.scopeTargets,
    unit: 'targets',
  },
  {
    key: 'projects',
    label: 'Projects',
    title: 'Organize applications',
    hint: 'Relate code and infrastructure to each application. Add repositories '
      + 'you explicitly choose to bring into Barad-dûr.',
    count: (d) => d.projects,
    unit: 'projects',
  },
  {
    key: 'assets',
    label: 'Assets',
    title: 'Add business context',
    hint: 'Add owners, environments and criticality to the assets that make up '
      + 'each application before interpreting risk.',
    count: (d) => d.assets,
    unit: 'assets',
  },
  {
    key: 'grants',
    label: 'Authorization',
    title: 'Authorize analysis',
    hint: 'Grants are a control before active work, not the product entry point. '
      + 'Set targets, tools, workers and permissions deliberately.',
    count: (d) => d.grants,
    unit: 'grants',
  },
  {
    key: 'findings',
    label: 'Findings',
    title: 'Run analysis and manage results',
    hint: 'Launch analysis only when you are ready, then triage findings with '
      + 'owners, priority and remediation deadlines.',
    count: (d) => d.components,
    unit: 'components tracked',
  },
  {
    key: 'cycles',
    label: 'Cycles',
    title: 'Create cycles when you need them',
    hint: 'Start a CTEM cycle or pentest campaign when its scope, ownership and '
      + 'evidence need a bounded operating rhythm.',
    count: (d) => d.cycles,
    unit: 'cycles',
  },
]

const EMPTY = { grants: 0, projects: 0, components: 0, assets: 0,
  scopeTargets: 0, cycles: 0 }

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
      safeCount('/api/v1/assets?limit=1', (b) => b.total ?? (b.data || []).length),
      safeCount('/api/v1/scope/targets', (b) => (b.data || []).length),
      safeCount('/api/v1/cycles', (b) => (b.data || []).length),
    ])
      .then(([grants, projects, components, assets, scopeTargets, cycles]) =>
        setData({ grants, projects, components, assets, scopeTargets, cycles }))
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
