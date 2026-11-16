import React, { useMemo, useState } from 'react'
import { Card, EmptyState } from './ui'
import { degrees, hash, radiusFor } from './graphForce'
import useForceGraph from './useForceGraph'
import { useI18n } from './i18n'

/* ───────────────────────── the running-now graph ─────────────────────────

   A force-directed reading of the project inventory, in the manner of a
   knowledge graph: every record is a node, its size follows how many
   relationships it carries, and the reader can move, pan, zoom and filter.
   Physics is local (about 80 lines) so the console keeps its two runtime
   dependencies; the layout is deterministic because the seed is hashed from
   the node id rather than drawn from Math.random().
   ──────────────────────────────────────────────────────────────────────── */


const TYPE_META = {
  project: { title: 'project', column: 0 },
  component: { title: 'component', column: 1 },
  repository: { title: 'code', column: 1 },
  version: { title: 'version', column: 2 },
  deployment: { title: 'deployment', column: 3 },
  asset: { title: 'asset', column: 4 },
}
const TYPE_ORDER = Object.keys(TYPE_META)

/* Relation names are written into the edges as stable identifiers; the label a
   reader sees is a catalogue entry keyed by this map, so the drawing order and
   the physics never depend on the active language. */
const RELATION_KEYS = {
  contains: 'contains', 'has code': 'hasCode', 'uses code': 'usesCode',
  ships: 'ships', 'runs as': 'runsAs', 'is exposed by': 'isExposedBy', owns: 'owns',
}

function buildGraph(data) {
  const nodes = []
  const byId = new Map()
  const edges = []
  const add = (type, id, label, extra = {}) => {
    const key = `${type}:${id}`
    if (byId.has(key)) return key
    const node = { id: key, type, label, ...extra }
    nodes.push(node)
    byId.set(key, node)
    return key
  }
  const join = (from, to, relation) => {
    if (from && to && !edges.some((edge) => edge.from === from && edge.to === to)) {
      edges.push({ from, to, relation })
    }
  }
  const project = add('project', data.project.id, data.project.name)
  const componentNodes = new Map()
  const versionNodes = new Map()
  const deploymentNodes = new Map()

  for (const component of data.components || []) {
    const id = add('component', component.id, component.name, { kind: component.kind })
    componentNodes.set(component.id, id)
    join(project, id, 'contains')
    for (const repository of component.repositories || []) {
      const repo = add('repository', repository.id, repository.name, { provider: repository.provider })
      join(id, repo, 'has code')
    }
  }
  for (const repository of data.unlinked_repositories || []) {
    const repo = add('repository', repository.id, repository.name, { provider: repository.provider })
    join(project, repo, 'uses code')
  }
  for (const version of data.versions || []) {
    const id = add('version', version.id, version.version, { component: version.component })
    versionNodes.set(version.id, id)
    join(componentNodes.get(version.component_id) || project, id, 'ships')
  }
  for (const deployment of data.deployments || []) {
    const id = add('deployment', deployment.id, `${deployment.environment} · ${deployment.name}`, {
      environment: deployment.environment,
      version: deployment.version_label,
      status: deployment.status,
      health: deployment.last_check_status,
    })
    deploymentNodes.set(deployment.id, id)
    join(versionNodes.get(deployment.version_id)
      || componentNodes.get(deployment.component_id) || project, id, 'runs as')
  }
  for (const asset of data.assets || []) {
    const id = add('asset', asset.id, asset.value, { assetType: asset.type, source: asset.source })
    join(deploymentNodes.get(asset.deployment_id) || project, id,
      asset.deployment_id ? 'is exposed by' : 'owns')
  }
  return { nodes, edges }
}

function detail(node) {
  return [node.environment, node.version, node.health, node.kind, node.provider, node.assetType]
    .filter(Boolean).join(' · ')
}

/* ─────────────────────────────── component ─────────────────────────────── */

export default function ProjectRuntimeGraph({ data }) {
  const { t, tCount, tOr } = useI18n()
  const typeLabel = (type) => tOr(`projectRuntime.type.${TYPE_META[type]?.title}`, type)
  const relationLabel = (relation) => tOr(`projectRuntime.relation.${RELATION_KEYS[relation] || relation}`,
    relation)
  const graph = useMemo(() => buildGraph(data), [data])
  const degree = useMemo(() => degrees(graph.nodes, graph.edges), [graph])

  const [hiddenTypes, setHiddenTypes] = useState(() => new Set())
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(null)

  const nodes = useMemo(() => graph.nodes.map((node) => ({
    ...node, degree: degree.get(node.id) || 0, r: radiusFor(degree.get(node.id) || 0),
  })), [graph, degree])

  const needle = query.trim().toLowerCase()
  const visibleNodes = useMemo(() => nodes.filter((node) => {
    if (hiddenTypes.has(node.type)) return false
    if (needle && !`${typeLabel(node.type)} ${node.label} ${detail(node)}`
      .toLowerCase().includes(needle)) return false
    return true
  }), [nodes, hiddenTypes, needle])
  const visibleIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes])
  const visibleEdges = useMemo(() => graph.edges.filter((edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to)),
    [graph, visibleIds])

  const neighbors = useMemo(() => {
    const map = new Map()
    for (const edge of visibleEdges) {
      if (!map.has(edge.from)) map.set(edge.from, new Set())
      if (!map.has(edge.to)) map.set(edge.to, new Set())
      map.get(edge.from).add(edge.to)
      map.get(edge.to).add(edge.from)
    }
    return map
  }, [visibleEdges])

  // One engine for both graphs: `useForceGraph` is what the dependency tab uses
  // too, so "the same as in projects" is true by construction, not by memory.
  const position = useMemo(() => {
    const columns = new Map(TYPE_ORDER.map((type) => [
      type, visibleNodes.filter((node) => node.type === type),
    ]))
    return (node) => {
      const rows = columns.get(node.type) || []
      const row = rows.indexOf(node)
      return {
        x: (TYPE_META[node.type].column - 2) * 215 + (hash(node.id) % 41) - 20,
        y: (row - (rows.length - 1) / 2) * 96 + (hash(`${node.id}y`) % 33) - 16,
      }
    }
  }, [visibleNodes])

  const engine = useForceGraph({
    nodes: visibleNodes,
    edges: visibleEdges,
    position,
    clusterDirection: 'out',
    onSelect: (id) => setSelected((current) => (
      id === null ? null : (current === id ? null : id))),
  })
  const {
    view, settled, hovered, setHovered, setAwake, zoomBy, fit, reset: resetLayout,
  } = engine

  const focusId = hovered || selected
  const focusSet = focusId ? new Set([focusId, ...(neighbors.get(focusId) || [])]) : null

  const selectedNode = nodes.find((node) => node.id === selected)
  const selectedLinks = selected ? graph.edges
    .filter((edge) => edge.from === selected || edge.to === selected)
    .map((edge) => ({
      edge,
      other: nodes.find((node) => node.id === (edge.from === selected ? edge.to : edge.from)),
      outgoing: edge.from === selected,
    })) : []
  const isolated = visibleNodes.filter((node) => !(neighbors.get(node.id)?.size)).length
  const typeCounts = useMemo(() => {
    const counts = new Map()
    for (const node of nodes) counts.set(node.type, (counts.get(node.type) || 0) + 1)
    return counts
  }, [nodes])

  if (graph.nodes.length <= 1) {
    return <EmptyState title={t('projectRuntime.empty.title')}
      hint={t('projectRuntime.empty.hint')} />
  }

  return (
    <div className="project-graph-stack">
      {/* The four counters live once, on the summary card above this graph:
          repeating them here made the same numbers appear twice on one screen. */}
      <div className="graph-toolbar">
        <div className="graph-chips" role="group" aria-label={t('projectRuntime.filterByKind')}>
          {TYPE_ORDER.filter((type) => typeCounts.get(type)).map((type) => {
            const off = hiddenTypes.has(type)
            return (
              <button key={type} type="button" aria-pressed={!off}
                className={`graph-chip type-${type}${off ? ' off' : ''}`}
                onClick={() => setHiddenTypes((current) => {
                  const next = new Set(current)
                  if (next.has(type)) next.delete(type); else next.add(type)
                  return next
                })}>
                <span className="graph-chip-dot" />
                {typeLabel(type)}
                <span className="graph-chip-count">{typeCounts.get(type)}</span>
              </button>
            )
          })}
        </div>
        <div className="graph-tools">
          <input className="graph-filter" value={query} placeholder={t('projectRuntime.filterNodes')}
            aria-label={t('projectRuntime.filterNodesAria')}
            onChange={(event) => setQuery(event.target.value)} />
          <button type="button" className="mini" onClick={() => zoomBy(1 / 1.25)}
            aria-label={t('projectRuntime.zoomOut')}>−</button>
          <button type="button" className="mini graph-zoom" onClick={() => zoomBy(1 / view.zoom)}
            aria-label={t('projectRuntime.resetZoom')}>{Math.round(view.zoom * 100)}%</button>
          <button type="button" className="mini" onClick={() => zoomBy(1.25)}
            aria-label={t('projectRuntime.zoomIn')}>+</button>
          <button type="button" className="mini" onClick={fit}>{t('projectRuntime.fit')}</button>
          <button type="button" className="mini" onClick={resetLayout}>{t('projectRuntime.reset')}</button>
        </div>
      </div>

      <div className="project-graph-wrap" ref={engine.wrapRef}>
        <svg className="project-graph" ref={engine.svgRef} viewBox={`0 0 ${engine.VIEW.w} ${engine.VIEW.h}`}
          role="img" aria-label={t('projectRuntime.ariaLabel', { project: data.project.name })}
          {...engine.svgHandlers}>
          <g transform={`translate(${engine.VIEW.w / 2 + view.x} ${engine.VIEW.h / 2 + view.y}) scale(${view.zoom})`}>
            {visibleEdges.map((edge) => {
              const from = settled.get(edge.from)
              const to = settled.get(edge.to)
              if (!from || !to) return null
              const dim = focusSet && !(focusSet.has(edge.from) && focusSet.has(edge.to))
              const hot = focusSet && focusSet.has(edge.from) && focusSet.has(edge.to)
              return (
                <line key={`${edge.from}->${edge.to}`}
                  className={`graph-edge${dim ? ' dim' : ''}${hot ? ' hot' : ''}`}
                  x1={from.x} y1={from.y} x2={to.x} y2={to.y}>
                  <title>{relationLabel(edge.relation)}</title>
                </line>
              )
            })}
            {/* Relation names appear while a node is being pointed at — one
                per edge, placed a third of the way from the source so the
                reading direction is the line's own direction. Keeping them for
                a click-selection made three "contains" labels compete. */}
            {hovered && visibleEdges.filter((edge) => focusSet.has(edge.from) && focusSet.has(edge.to))
              .map((edge) => {
                const from = settled.get(edge.from)
                const to = settled.get(edge.to)
                if (!from || !to) return null
                return (
                  <text key={`label-${edge.from}->${edge.to}`} className="graph-edge-label"
                    x={from.x + (to.x - from.x) * 0.36} y={from.y + (to.y - from.y) * 0.36 - 5}
                    textAnchor="middle">
                    {relationLabel(edge.relation)}
                  </text>
                )
              })}
            {visibleNodes.map((node) => {
              const point = settled.get(node.id)
              if (!point) return null
              const dim = focusSet && !focusSet.has(node.id)
              const isFocus = focusId === node.id
              return (
                <g key={node.id} transform={`translate(${point.x},${point.y})`}
                  className={`graph-node type-${node.type}${dim ? ' dim' : ''}${isFocus ? ' focus' : ''}${point.fixed ? ' pinned' : ''}`}
                  role="button" tabIndex="0"
                  aria-label={`${typeLabel(node.type)} ${node.label}, ${tCount('projectRuntime.connections', node.degree)}`}
                  {...engine.nodeHandlers(point, node)}
                  onPointerEnter={() => setHovered(node.id)}
                  onPointerLeave={() => setHovered((current) => (current === node.id ? null : current))}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      setSelected((current) => (current === node.id ? null : node.id))
                    }
                  }}>
                  <circle r={node.r + 9} className="graph-node-hit" />
                  <circle r={node.r} className="graph-node-dot" />
                  <text x={node.r + 7} y={4} className="graph-node-label">
                    {node.label.length > 32 ? `${node.label.slice(0, 31)}…` : node.label}
                  </text>
                  <title>{`${typeLabel(node.type)} · ${node.label}${detail(node) ? ` · ${detail(node)}` : ''} · ${tCount('projectRuntime.connections', node.degree)}`}</title>
                </g>
              )
            })}
          </g>
        </svg>
        {!visibleNodes.length && (
          <p className="graph-empty">{t('projectRuntime.allFiltered')}</p>
        )}
        <span className="graph-hint">
          {t('projectRuntime.hint')}
        </span>
      </div>

      <p className="muted" style={{ margin: 0, fontSize: 12 }}>
        {t('projectRuntime.sizeNote')}
        {isolated > 0 && ` ${tCount('projectRuntime.isolated', isolated)}`}
      </p>

      {selectedNode && (
        <Card title={`${typeLabel(selectedNode.type)} · ${selectedNode.label}`}
          actions={<button className="mini" onClick={() => setSelected(null)}>{t('projectRuntime.clearFocus')}</button>}>
          <p className="muted" style={{ marginTop: 0 }}>
            {detail(selectedNode) || t('projectRuntime.noMetadata')}
            {' · '}{tCount('projectRuntime.connections', selectedNode.degree)}
          </p>
          <div className="graph-neighbor-list">
            {selectedLinks.map(({ edge, other, outgoing }) => (
              <button key={`${edge.from}-${edge.to}`} type="button" className="graph-neighbor"
                onClick={() => setSelected(other.id)}>
                <span className="graph-neighbor-rel">{outgoing ? relationLabel(edge.relation) : '←'}</span>
                <span className={`graph-neighbor-type type-${other.type}`}>{typeLabel(other.type)}</span>
                <span className="graph-neighbor-label">{other.label}</span>
              </button>
            ))}
            {!selectedLinks.length && <p className="muted">{t('projectRuntime.noRelation')}</p>}
          </div>
        </Card>
      )}

      <Card title={t('projectRuntime.relationshipList')}
        actions={<span className="count">{t('projectRuntime.listFallback')}</span>}>
        <div className="project-graph-list">
          {visibleEdges.map((edge) => {
            const from = nodes.find((node) => node.id === edge.from)
            const to = nodes.find((node) => node.id === edge.to)
            return (
              <button key={`${edge.from}-${edge.to}`} className="project-graph-row"
                onClick={() => setSelected(edge.to)}>
                <span>{from?.label}</span><b>{relationLabel(edge.relation)}</b><span>{to?.label}</span>
              </button>
            )
          })}
        </div>
      </Card>
    </div>
  )
}