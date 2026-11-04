import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, Stat } from './ui'

const COLUMNS = [
  ['project'], ['application_component', 'repository'], ['version', 'analysis_run'],
  ['artifact'], ['deployment'], ['asset'], ['endpoint', 'finding'],
]

const TITLES = {
  project: 'project', application_component: 'component', repository: 'code',
  analysis_run: 'analysis', version: 'version', artifact: 'artifact',
  deployment: 'deployment', asset: 'asset', endpoint: 'endpoint', finding: 'finding',
}

function nodeDetail(node) {
  const fields = []
  if (node.environment) fields.push(node.environment)
  if (node.digest) fields.push(node.digest)
  if (node.revision) fields.push(node.revision)
  if (node.origin) fields.push(node.origin)
  if (node.severity) fields.push(node.severity)
  if (node.status_code) fields.push(`HTTP ${node.status_code}`)
  if (node.status && node.type !== 'finding') fields.push(node.status)
  return fields.join(' · ')
}

function layout(data) {
  const byType = new Map()
  for (const node of data.nodes || []) byType.set(node.type, [...(byType.get(node.type) || []), node])
  const positions = new Map()
  COLUMNS.forEach((types, column) => {
    const nodes = types.flatMap((type) => byType.get(type) || [])
    nodes.forEach((node, row) => positions.set(node.id, { x: 40 + column * 175, y: 58 + row * 90 }))
  })
  return positions
}

export default function RuntimeGraph({ project, onBack }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(null)

  function load() {
    if (!project) return
    setData(null); setError(''); setSelected(null)
    api.get(`/api/v1/projects/${encodeURIComponent(project)}/runtime-graph`)
      .then((response) => setData(response.data))
      .catch((problem) => setError(String(problem.message || problem)))
  }

  useEffect(load, [project])
  const positions = useMemo(() => data ? layout(data) : new Map(), [data])
  const focus = selected ? new Set([selected, ...((data?.edges || [])
    .filter((edge) => edge.from === selected || edge.to === selected)
    .flatMap((edge) => [edge.from, edge.to]))]) : null
  const selectedNode = data?.nodes?.find((node) => node.id === selected)

  if (!data) return <Card>{error ? <ErrorBanner error={error} onRetry={load} /> : <Loading rows={5} />}</Card>
  const { summary } = data
  if (data.nodes.length === 1) return (
    <EmptyState title={`No runtime relationships are recorded for ${data.project.name} yet`}
      hint="Start by adding a component, a deployment and the asset that exposes it." />
  )

  const height = Math.max(380, ...[...positions.values()].map((point) => point.y + 70))
  return (
    <div className="runtime-graph-stack">
      <div className="runtime-graph-head">
        <div>
          <strong>{data.project.name} · running now</strong>
          <p className="muted">Hover or select a node to isolate its branch. The graph shows stored evidence only.</p>
        </div>
        <button className="mini" onClick={onBack}>back to portfolio</button>
      </div>
      <div className="metrics runtime-graph-metrics">
        <Stat label="components" value={summary.components} />
        <Stat label="active deployments" value={summary.active_deployments} />
        <Stat label="assets" value={summary.assets} />
        <Stat label="endpoints" value={summary.registered_endpoints} />
        <Stat label="open findings" value={summary.open_findings} tone={summary.open_findings ? 'warn' : ''} />
      </div>
      {summary.coverage?.length > 0 && <p className="runtime-graph-coverage">{summary.coverage.join(' · ')}</p>}
      <div className="runtime-graph-wrap" onClick={() => setSelected(null)}>
        <svg className="runtime-graph" viewBox={`0 0 1220 ${height}`} role="img"
          aria-label={`Runtime evidence graph for ${data.project.name}`}>
          <defs><marker id="runtime-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7" /></marker></defs>
          {COLUMNS.map((types, index) => <text key={index} x={40 + index * 175} y="24" className="runtime-graph-column">{types.map((type) => TITLES[type]).join(' / ')}</text>)}
          {(data.edges || []).map((edge, index) => {
            const from = positions.get(edge.from); const to = positions.get(edge.to)
            if (!from || !to) return null
            const dim = focus && !focus.has(edge.from) && !focus.has(edge.to)
            const mid = (from.x + to.x) / 2
            return <path key={`${edge.from}-${edge.to}-${index}`} className={`runtime-graph-edge${dim ? ' dim' : ''}`}
              d={`M ${from.x + 134} ${from.y + 25} C ${mid} ${from.y + 25}, ${mid} ${to.y + 25}, ${to.x - 8} ${to.y + 25}`}
              markerEnd="url(#runtime-arrow)"><title>{edge.relation.replaceAll('_', ' ')}</title></path>
          })}
          {(data.nodes || []).map((node) => {
            const point = positions.get(node.id); if (!point) return null
            const dim = focus && !focus.has(node.id)
            return <g key={node.id} transform={`translate(${point.x},${point.y})`} tabIndex="0" role="button"
              aria-label={`${TITLES[node.type]} ${node.label}`} onClick={(event) => { event.stopPropagation(); setSelected(node.id) }}
              onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelected(node.id) } }}
              className={`runtime-graph-node ${node.type}${dim ? ' dim' : ''}${selected === node.id ? ' selected' : ''}`}>
              <rect width="134" height="52" rx="7" />
              <text x="10" y="19" className="runtime-graph-node-type">{TITLES[node.type]}</text>
              <text x="10" y="37" className="runtime-graph-node-label">{node.label.length > 19 ? `${node.label.slice(0, 18)}…` : node.label}</text>
              <title>{`${TITLES[node.type]} · ${node.label}${nodeDetail(node) ? ` · ${nodeDetail(node)}` : ''}`}</title>
            </g>
          })}
        </svg>
      </div>
      {selectedNode && <Card title={`${TITLES[selectedNode.type]} · ${selectedNode.label}`} actions={<button className="mini" onClick={() => setSelected(null)}>clear focus</button>}>
        <p className="mono">{selectedNode.id}</p>
        <p className="muted">{nodeDetail(selectedNode) || 'No additional runtime metadata is recorded for this evidence.'}</p>
      </Card>}
      <Card title="Relationship list" actions={<span className="count">mobile fallback</span>}>
        <div className="runtime-graph-list">
          {(data.edges || []).map((edge, index) => {
            const from = data.nodes.find((node) => node.id === edge.from); const to = data.nodes.find((node) => node.id === edge.to)
            return <button key={`${edge.from}-${edge.to}-${index}`} className="runtime-graph-list-row" onClick={() => setSelected(edge.to)}>
              <span>{from?.label || edge.from}</span><b>{edge.relation.replaceAll('_', ' ')}</b><span>{to?.label || edge.to}</span>
            </button>
          })}
        </div>
      </Card>
    </div>
  )
}
