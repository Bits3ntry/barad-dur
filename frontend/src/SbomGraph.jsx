import React, { useMemo, useState } from 'react'
import { Card, EmptyState } from './ui'
import { degrees, hash, radiusFor } from './graphForce'
import useForceGraph from './useForceGraph'

/* ─────────────────────────── the dependency graph ───────────────────────────

   A build read as a constellation, the way the project summary reads its
   inventory: bigger means more dependencies, hotter means worse findings, and a
   node nobody connects to is drawn as what it is — something the graph cannot
   explain.

   The interaction is the project summary's, not a lookalike: `useForceGraph` is
   the same engine over there, so drag (with the cluster), pan, wheel zoom,
   pinning and reset behave identically in both screens.
   ──────────────────────────────────────────────────────────────────────────── */

const FILL = {
  CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)',
  LOW: 'var(--low)', UNKNOWN: 'var(--text-dim)',
}

/* Size answers two questions at once: how much hangs off this package, and how
   much is wrong with it. The first grows slowly (a package with 40 dependents is
   not 8× a package with 5), the second fast enough to spot at a glance. */
function nodeRadius(degree, findings) {
  return Math.min(30, radiusFor(degree) + Math.min(11, Math.sqrt(findings || 0) * 3.4))
}

function buildGraph(rows) {
  const byPurl = new Map()
  for (const row of rows) if (row.purl) byPurl.set(row.purl, row)
  const nodes = rows.map((row) => ({
    id: row.component_id,
    label: row.name || '—',
    version: row.version,
    findings: row.findings || 0,
    worst: row.worst || (row.findings ? 'UNKNOWN' : null),
    row,
  }))
  const ids = new Set(nodes.map((node) => node.id))
  const edges = []
  for (const row of rows) {
    const parent = row.parent_purl ? byPurl.get(row.parent_purl) : null
    if (parent && ids.has(parent.component_id) && parent.component_id !== row.component_id) {
      edges.push({ from: row.component_id, to: parent.component_id })
    }
  }
  return { nodes, edges }
}

export default function SbomGraph({ rows, onPick, selected, compact = false }) {
  const graph = useMemo(() => buildGraph(rows), [rows])
  const degree = useMemo(() => degrees(graph.nodes, graph.edges), [graph])
  const [query, setQuery] = useState('')
  const [showAll, setShowAll] = useState(false)
  const [localId, setLocalId] = useState(null)

  const nodes = useMemo(() => graph.nodes.map((node) => ({
    ...node,
    degree: degree.get(node.id) || 0,
    r: nodeRadius(degree.get(node.id) || 0, node.findings),
  })), [graph, degree])

  const needle = query.trim().toLowerCase()
  // 495 nodes fitted to one screen is a hairball, and a hairball teaches nothing.
  // The graph opens on the packages that carry findings, says how many it is
  // showing, and lets the reader ask for the rest or focus a neighbourhood.
  const ranked = useMemo(() => [...nodes].sort((a, b) => (
    (b.findings - a.findings) || (b.degree - a.degree)
  )), [nodes])

  const focused = useMemo(() => {
    if (!localId) return null
    const keep = new Set([localId])
    for (let hop = 0; hop < 2; hop += 1) {
      for (const edge of graph.edges) {
        if (keep.has(edge.from)) keep.add(edge.to)
        if (keep.has(edge.to)) keep.add(edge.from)
      }
    }
    return keep
  }, [localId, graph.edges])

  const visibleNodes = useMemo(() => {
    let pool = nodes
    if (focused) pool = nodes.filter((node) => focused.has(node.id))
    else if (!showAll && !needle) pool = ranked.slice(0, 90)
    if (!needle) return pool
    return pool.filter((node) => `${node.label} ${node.version || ''}`.toLowerCase().includes(needle))
  }, [nodes, ranked, focused, showAll, needle])
  const visibleIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes])
  const visibleEdges = useMemo(
    () => graph.edges.filter((edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to)),
    [graph, visibleIds])

  // Selection, never hover: a graph that reacts to the pointer cannot be panned,
  // zoomed or dragged without the drawing moving under you.
  const focusId = selected && selected.component_id
  const focusSet = useMemo(() => {
    if (!focusId) return null
    const set = new Set([focusId])
    for (const edge of visibleEdges) {
      if (edge.from === focusId) set.add(edge.to)
      if (edge.to === focusId) set.add(edge.from)
    }
    return set
  }, [focusId, visibleEdges])

  // Unconnected nodes would drift inward with the gravity and hide behind the
  // graph they are absent from: they get their own band on the right.
  const position = useMemo(() => {
    const attached = new Set()
    for (const edge of visibleEdges) { attached.add(edge.from); attached.add(edge.to) }
    const lonely = visibleNodes.filter((node) => !attached.has(node.id))
    const ring = Math.max(220, Math.sqrt(Math.max(1, visibleNodes.length - lonely.length)) * 62)
    return (node) => {
      if (!attached.has(node.id)) {
        const index = lonely.indexOf(node)
        return {
          x: ring + 240 + (hash(`${node.id}x`) % 60),
          y: (index - (lonely.length - 1) / 2) * 34 + (hash(`${node.id}y`) % 24) - 12,
        }
      }
      const angle = (hash(node.id) % 360) * (Math.PI / 180)
      const spread = 0.55 + ((hash(`${node.id}r`) % 100) / 100) * 0.75
      return {
        x: Math.cos(angle) * ring * spread + (hash(node.id) % 41) - 20,
        y: Math.sin(angle) * ring * spread + (hash(`${node.id}y`) % 41) - 20,
      }
    }
  }, [visibleNodes, visibleEdges])

  const engine = useForceGraph({
    nodes: visibleNodes,
    edges: visibleEdges,
    position,
    // Edges point child → parent here, so "what it brings in" is the 'in' side.
    clusterDirection: 'in',
    onSelect: (id) => {
      if (!id) { onPick(null); return }
      setLocalId(id)
      const node = nodes.find((candidate) => candidate.id === id)
      if (node) onPick(node.row)
    },
  })
  const { view, settled } = engine

  if (!rows.length) {
    return (
      <Card>
        <EmptyState title="Nothing to draw"
          hint="This build has no components yet: import a BOM and the graph starts here." />
      </Card>
    )
  }

  return (
    <Card tight>
      <div className="sbom-graph-toolbar">
        <input value={query} placeholder="highlight a package" onChange={(event) => setQuery(event.target.value)} />
        <span className="sbom-legend">
          <span className="sbom-legend-dot" style={{ background: 'var(--critical)' }} />critical
          <span className="sbom-legend-dot" style={{ background: 'var(--high)' }} />high
          <span className="sbom-legend-dot" style={{ background: 'var(--medium)' }} />medium
          <span className="sbom-legend-dot" style={{ background: 'var(--low)' }} />low
          <span className="sbom-legend-dot is-clean" />clean
        </span>
        <span className="muted sbom-legend-note">
          size = dependencies + findings · dashed = nothing depends on it
        </span>
        <span className="muted">
          {visibleNodes.length} of {nodes.length}
        </span>
        {localId ? (
          <button className="mini" onClick={() => setLocalId(null)}>focus · clear ✕</button>
        ) : (
          <button className="mini" onClick={() => setShowAll((value) => !value)}>
            {showAll ? 'only with findings' : 'show all'}
          </button>
        )}
        <span className="row-end graph-zoom">
          <button type="button" className="mini" onClick={() => engine.zoomBy(1 / 1.25)}
            aria-label="zoom out">−</button>
          <button type="button" className="mini graph-zoom"
            onClick={() => engine.zoomBy(1 / view.zoom)}
            aria-label="reset zoom">{Math.round(view.zoom * 100)}%</button>
          <button type="button" className="mini" onClick={() => engine.zoomBy(1.25)}
            aria-label="zoom in">+</button>
          <button type="button" className="mini" onClick={engine.fit}>fit</button>
          <button type="button" className="mini" onClick={engine.reset}>reset</button>
        </span>
      </div>

      <div className={`sbom-graph-canvas${compact ? ' is-compact' : ''}`} ref={engine.wrapRef}>
        <svg ref={engine.svgRef} viewBox={`0 0 ${engine.VIEW.w} ${engine.VIEW.h}`} role="img"
          aria-label="dependency graph of this build" {...engine.svgHandlers}>
          <g transform={`translate(${engine.VIEW.w / 2 + view.x} ${engine.VIEW.h / 2 + view.y}) scale(${view.zoom})`}>
            {visibleEdges.map((edge) => {
              const from = settled.get(edge.from)
              const to = settled.get(edge.to)
              if (!from || !to) return null
              const active = focusSet && (edge.from === focusId || edge.to === focusId)
              return (
                <line key={`${edge.from}-${edge.to}`}
                  x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                  className={`sbom-graph-edge${active ? ' is-active' : ''}`}
                  style={{ opacity: focusSet ? (active ? 0.75 : 0.08) : 0.24 }} />
              )
            })}
            {visibleNodes.map((node) => {
              const entry = settled.get(node.id)
              if (!entry) return null
              const color = node.worst ? FILL[node.worst] || FILL.UNKNOWN : null
              const dim = focusSet ? !focusSet.has(node.id) : false
              const lonely = !node.degree
              const isSelected = selected && selected.component_id === node.id
              return (
                <g key={node.id} transform={`translate(${entry.x},${entry.y})`}
                  className={`sbom-graph-node-group${entry.fixed ? ' is-pinned' : ''}`}
                  style={{ opacity: dim ? 0.22 : 1 }}
                  role="button" tabIndex={0}
                  aria-label={`${node.label}${node.version ? ` ${node.version}` : ''}, ${node.findings} findings`}
                  {...engine.nodeHandlers(entry, node)}>
                  <circle r={node.r + 8} className="sbom-graph-hit" fill="transparent" />
                  <circle r={node.r} fill={color || 'var(--panel-2)'}
                    stroke={isSelected ? 'var(--accent)' : (lonely ? 'var(--text-dim)' : 'var(--line)')}
                    strokeWidth={isSelected ? 2.5 : 1.2}
                    strokeDasharray={lonely ? '3 3' : undefined}
                    className="sbom-graph-dot" />
                  {node.findings > 0 && (
                    <text className="sbom-graph-count" dy="0.32em" textAnchor="middle"
                      fontSize={Math.max(8, Math.min(13, node.r * 0.75))}>
                      {node.findings}
                    </text>
                  )}
                  {(view.zoom >= 1.05 || node.r >= 13 || isSelected) && (
                    <text className="sbom-graph-label" x={node.r + 5} dy="0.32em">
                      {node.label}
                    </text>
                  )}
                </g>
              )
            })}
          </g>
        </svg>
        <span className="graph-hint">
          drag a node to move it with its dependencies · drag the canvas to pan · scroll to zoom ·
          double-click releases it
        </span>
      </div>
    </Card>
  )
}
