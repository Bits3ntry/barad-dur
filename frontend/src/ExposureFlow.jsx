import React from 'react'

/* Exposure flow: one left-to-right read of where exposure accumulates —
   what is reachable, what it is built from, what it carries, and what is
   actually being exploited. Every stage is a button into the screen that can
   answer it, because a number nobody can follow is decoration. */

function Stage({ label, value, hint, tone, onClick, current }) {
  return (
    <button className={`flow-stage${tone ? ` ${tone}` : ''}${current ? ' current' : ''}`}
      onClick={onClick} title={hint || label}>
      <span className="flow-value">{value}</span>
      <span className="flow-label">{label}</span>
      {hint && <span className="flow-hint">{hint}</span>}
    </button>
  )
}

export default function ExposureFlow({ assets, portfolio, findings, onNavigate }) {
  if (!portfolio) return null

  const expiring = (assets || []).filter((asset) => {
    const days = asset.latest?.certificate?.days_left
    return typeof days === 'number' && days <= 30
  }).length

  const severity = portfolio.by_severity || {}
  const go = (key) => () => onNavigate && onNavigate(key)

  return (
    <div className="flow" role="list" aria-label="Exposure flow">
      <Stage label="attack surface" value={(assets || []).length}
        hint={expiring ? `${expiring} cert${expiring === 1 ? '' : 's'} ≤30d` : 'addresses and certificates'}
        tone={expiring ? 'warn' : ''} onClick={go('assets')} />

      <span className="flow-arrow" aria-hidden="true">→</span>

      <Stage label="projects" value={portfolio.projects}
        hint={`${portfolio.groups || 0} groups`} onClick={go('projects')} />

      <span className="flow-arrow" aria-hidden="true">→</span>

      <Stage label="components" value={portfolio.components}
        hint={portfolio.vulnerable_components
          ? `${portfolio.vulnerable_components} carry findings`
          : 'no vulnerable components'}
        tone={portfolio.vulnerable_components ? 'warn' : ''} onClick={go('components')} />

      <span className="flow-arrow" aria-hidden="true">→</span>

      <Stage label="findings" value={portfolio.findings}
        hint={`${severity.CRITICAL || 0} critical · ${severity.HIGH || 0} high`}
        tone={severity.CRITICAL ? 'bad' : ''} onClick={go('findings')} />

      <span className="flow-arrow" aria-hidden="true">→</span>

      <Stage label="known exploited" value={portfolio.kev}
        hint={findings
          ? `${findings.sla_breached || 0} past SLA`
          : 'none in the catalog'}
        tone={portfolio.kev ? 'bad' : 'good'} onClick={go('findings')} />
    </div>
  )
}
