import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Stat } from './ui'

/* The CTEM cycle as a working surface, not a noun: five phases, each one
   answered with counts and a status derived from them (see /api/v1/ctem/overview).
   A phase is never reported healthy because its table is empty. */

const ORDER = ['scoping', 'discovery', 'prioritization', 'validation', 'mobilization']

const STATUS_COPY = {
  done: { label: 'done', tone: 'good' },
  partial: { label: 'in progress', tone: 'warn' },
  empty: { label: 'not started', tone: '' },
}

function PhaseCard({ phase, index, focused, onNavigate }) {
  const status = STATUS_COPY[phase.status] || STATUS_COPY.empty
  return (
    <section className={`phase${focused ? ' focused' : ''}`} id={`phase-${phase.key}`}
      aria-label={`${phase.title}: ${status.label}`}>
      <header className="phase-head">
        <span className="phase-index">{index + 1}</span>
        <div className="phase-titles">
          <h3>{phase.title}</h3>
          <p>{phase.question}</p>
        </div>
        <span className={`phase-status ${status.tone}`}>{status.label}</span>
      </header>

      <div className="phase-metrics">
        {phase.metrics.map((metric) => (
          <Stat key={metric.label} label={metric.label} value={metric.value}
            hint={metric.hint} />
        ))}
      </div>

      <div className="phase-progress" role="progressbar" aria-valuenow={phase.progress}
        aria-valuemin={0} aria-valuemax={100}>
        <span className="track">
          <span style={{ width: `${phase.progress}%` }} className={status.tone} />
        </span>
        <span className="percent">{phase.progress}%</span>
      </div>

      <footer className="phase-links">
        {phase.links.map((link) => (
          <button key={link.screen} className="mini"
            onClick={() => onNavigate && onNavigate(link.screen)}>
            {link.label} →
          </button>
        ))}
      </footer>
    </section>
  )
}

export default function CtemCycle({ focus, onNavigate }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  function load() {
    setError('')
    api.get('/api/v1/ctem/overview')
      .then((response) => setData(response.data))
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(load, [])

  const phases = useMemo(() => {
    const list = data?.phases || []
    // Sidebar entries open the cycle on their phase: that one goes first so the
    // reader lands on what they clicked, without losing the rest of the loop.
    if (!focus) return list
    const sorted = [...list].sort((left, right) => ORDER.indexOf(left.key) - ORDER.indexOf(right.key))
    const target = sorted.find((phase) => phase.key === focus)
    return target ? [target, ...sorted.filter((phase) => phase.key !== focus)] : sorted
  }, [data, focus])

  if (!data) {
    return (
      <div className="stack">
        <PageHeader title="CTEM cycle" subtitle="Loading…" />
        <Card>{error ? <ErrorBanner error={error} onRetry={load} /> : <Loading rows={4} />}</Card>
      </div>
    )
  }

  const done = phases.filter((phase) => phase.status === 'done').length

  return (
    <div className="stack">
      <PageHeader
        title={focus ? `CTEM · ${focus}` : 'CTEM cycle'}
        subtitle={`${done} of ${phases.length} phases complete · ${data.organization.name}`}
        actions={<button onClick={load}>refresh</button>}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      {!phases.length && (
        <EmptyState title="Nothing in the cycle yet"
          hint="Create a project and ingest an SBOM: scoping and discovery fill first." />
      )}

      <div className="phase-list">
        {phases.map((phase, index) => (
          <PhaseCard key={phase.key} phase={phase}
            index={ORDER.indexOf(phase.key)} focused={phase.key === focus}
            onNavigate={onNavigate} />
        ))}
      </div>

      <p className="muted">
        Each phase is measured on its own table: scoping on the projects and scope
        targets declared, discovery on components and recent imports,
        prioritization on how much of the open set carries a priority, validation
        on engagements and regression coverage, mobilization on what got closed.
      </p>
    </div>
  )
}
