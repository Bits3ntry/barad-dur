import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Card, EmptyState } from './ui'

/* ───────────────────────── the running-now graph ─────────────────────────

   A force-directed reading of the project inventory, in the manner of a
   knowledge graph: every record is a node, its size follows how many
   relationships it carries, and the reader can move, pan, zoom and filter.
   Physics is local (about 80 lines) so the console keeps its two runtime
   dependencies; the layout is deterministic because the seed is hashed from
   the node id rather than drawn from Math.random().
   ──────────────────────────────────────────────────────────────────────── */

const VIEW = { w: 900, h: 520 }

const TYPE_META = {
  project: { title: 'project', column: 0 },
  component: { title: 'component', column: 1 },
  repository: { title: 'code', column: 1 },
  version: { title: 'version', column: 2 },
  deployment: { title: 'deployment', column: 3 },
  asset: { title: 'asset', column: 4 },
}
const TYPE_ORDER = Object.keys(TYPE_META)

const MIN_RADIUS = 5.5
const MAX_RADIUS = 24

function radiusFor(degree) {
  return Math.min(MAX_RADIUS, MIN_RADIUS + Math.sqrt(degree) * 4.1)
}

function hash(text) {
  let value = 2166136261
  for (let i = 0; i < text.length; i += 1) {
    value ^= text.charCodeAt(i)
    value = Math.imul(value, 16777619)
  }
  return Math.abs(value)
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

function degrees(nodes, edges) {
  const map = new Map(nodes.map((node) => [node.id, 0]))
  for (const edge of edges) {
    map.set(edge.from, (map.get(edge.from) || 0) + 1)
    map.set(edge.to, (map.get(edge.to) || 0) + 1)
  }
  return map
}

function detail(node) {
  return [node.environment, node.version, node.health, node.kind, node.provider, node.assetType]
    .filter(Boolean).join(' · ')
}

/* ── physics: seeded columns, then repulsion + springs + gravity ────────── */

const REPULSION = 9000
const GRAVITY = 0.006
const STIFFNESS = 0.05
const DAMPING = 0.58

function seed(nodes, edges) {
  const columns = new Map()
  for (const type of TYPE_ORDER) columns.set(type, nodes.filter((node) => node.type === type))
  const sim = {
    nodes: [],
    links: [],
    index: new Map(),
    settled: false,
  }
  for (const type of TYPE_ORDER) {
    const rows = columns.get(type)
    const column = TYPE_META[type].column
    rows.forEach((node, row) => {
      const degree = node.degree
      const entry = {
        id: node.id,
        x: (column - 2) * 215 + (hash(node.id) % 41) - 20,
        y: (row - (rows.length - 1) / 2) * 96 + (hash(`${node.id}y`) % 33) - 16,
        vx: 0,
        vy: 0,
        r: radiusFor(degree),
        fixed: false,
      }
      sim.index.set(node.id, entry)
      sim.nodes.push(entry)
    })
  }
  for (const edge of edges) {
    const from = sim.index.get(edge.from)
    const to = sim.index.get(edge.to)
    if (!from || !to) continue
    sim.links.push({ a: from, b: to, rest: 96 + from.r + to.r, relation: edge.relation })
  }
  return sim
}

function step(sim) {
  const count = sim.nodes.length
  for (let i = 0; i < count; i += 1) {
    const a = sim.nodes[i]
    for (let j = i + 1; j < count; j += 1) {
      const b = sim.nodes[j]
      let dx = b.x - a.x
      let dy = b.y - a.y
      let squared = dx * dx + dy * dy
      if (squared < 1) {
        dx = (hash(a.id) % 7) - 3
        dy = (hash(b.id) % 7) - 3
        squared = Math.max(1, dx * dx + dy * dy)
      }
      const distance = Math.sqrt(squared)
      const push = Math.min(REPULSION / squared, 22)
      const fx = (dx / distance) * push
      const fy = (dy / distance) * push
      a.vx -= fx; a.vy -= fy
      b.vx += fx; b.vy += fy

      const floor = a.r + b.r + 16
      if (distance < floor) {
        const overlap = (floor - distance) * 0.3
        a.vx -= (dx / distance) * overlap
        a.vy -= (dy / distance) * overlap
        b.vx += (dx / distance) * overlap
        b.vy += (dy / distance) * overlap
      }
    }
  }
  for (const link of sim.links) {
    const dx = link.b.x - link.a.x
    const dy = link.b.y - link.a.y
    const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy))
    const pull = (distance - link.rest) * STIFFNESS
    const fx = (dx / distance) * pull
    const fy = (dy / distance) * pull
    link.a.vx += fx; link.a.vy += fy
    link.b.vx -= fx; link.b.vy -= fy
  }
  for (const node of sim.nodes) {
    if (node.fixed) { node.vx = 0; node.vy = 0; continue }
    node.vx -= node.x * GRAVITY
    node.vy -= node.y * GRAVITY
    node.vx *= DAMPING
    node.vy *= DAMPING
    const speed = Math.sqrt(node.vx * node.vx + node.vy * node.vy)
    if (speed > 22) {
      node.vx = (node.vx / speed) * 22
      node.vy = (node.vy / speed) * 22
    }
    node.x += node.vx
    node.y += node.vy
  }
}

function relax(sim, iterations) {
  for (let i = 0; i < iterations; i += 1) step(sim)
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value))
}

/* ─────────────────────────────── component ─────────────────────────────── */

export default function ProjectRuntimeGraph({ data }) {
  const graph = useMemo(() => buildGraph(data), [data])
  const degree = useMemo(() => degrees(graph.nodes, graph.edges), [graph])

  const [hiddenTypes, setHiddenTypes] = useState(() => new Set())
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(null)
  const [hovered, setHovered] = useState(null)
  const [view, setView] = useState({ zoom: 1, x: 0, y: 0 })
  const [, setFrame] = useState(0)

  const wrapRef = useRef(null)
  const svgRef = useRef(null)
  const viewRef = useRef(view)
  // Once the reader pans or zooms, the automatic fit stops fighting them.
  const touchedRef = useRef(false)
  const simRef = useRef(null)
  const dragRef = useRef(null)
  const panRef = useRef(null)
  const [awake, setAwake] = useState(false)

  const nodes = useMemo(() => graph.nodes.map((node) => ({
    ...node, degree: degree.get(node.id) || 0, r: radiusFor(degree.get(node.id) || 0),
  })), [graph, degree])

  const needle = query.trim().toLowerCase()
  const visibleNodes = useMemo(() => nodes.filter((node) => {
    if (hiddenTypes.has(node.type)) return false
    if (needle && !`${TYPE_META[node.type].title} ${node.label} ${detail(node)}`
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

  const focusId = hovered || selected
  const focusSet = focusId ? new Set([focusId, ...(neighbors.get(focusId) || [])]) : null

  const key = visibleNodes.map((node) => node.id).join('|')

  // Build (and settle) the layout whenever the visible set changes. Nodes that
  // were already on screen keep their place, so filtering does not reshuffle
  // the whole drawing. Until the reader pans or zooms, the view re-fits itself
  // so no node is ever pushed outside the canvas by the physics.
  useEffect(() => {
    const previous = simRef.current ? simRef.current.index : new Map()
    const sim = seed(visibleNodes, visibleEdges)
    for (const entry of sim.nodes) {
      const old = previous.get(entry.id)
      if (old) { entry.x = old.x; entry.y = old.y; entry.fixed = old.fixed }
    }
    relax(sim, 260)
    simRef.current = sim
    if (!touchedRef.current) fitTo(sim)
    setFrame((frame) => frame + 1)
  }, [key]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!awake) return undefined
    let raf = 0
    let frames = 0
    const loop = () => {
      const sim = simRef.current
      if (!sim || frames > 220) { setAwake(false); return }
      step(sim)
      frames += 1
      setFrame((frame) => frame + 1)
      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)
    return () => cancelAnimationFrame(raf)
  }, [awake])

  function applyView(next) {
    viewRef.current = next
    setView(next)
  }

  function zoomBy(factor, anchor) {
    const current = viewRef.current
    const zoom = clamp(current.zoom * factor, 0.3, 2.6)
    touchedRef.current = true
    if (!anchor) {
      applyView({ zoom, x: current.x, y: current.y })
      return
    }
    const scaleChange = zoom / current.zoom
    applyView({
      zoom,
      x: anchor.x - VIEW.w / 2 - ((anchor.x - VIEW.w / 2 - current.x) * scaleChange),
      y: anchor.y - VIEW.h / 2 - ((anchor.y - VIEW.h / 2 - current.y) * scaleChange),
    })
  }

  function fitTo(sim) {
    if (!sim || !sim.nodes.length) return
    const xs = sim.nodes.map((node) => node.x)
    const ys = sim.nodes.map((node) => node.y)
    const minX = Math.min(...xs); const maxX = Math.max(...xs)
    const minY = Math.min(...ys); const maxY = Math.max(...ys)
    // Labels sit to the right of their dot, so the box is padded unevenly.
    const width = Math.max(140, maxX - minX + 260)
    const height = Math.max(120, maxY - minY + 130)
    const zoom = clamp(Math.min(VIEW.w / width, VIEW.h / height), 0.35, 1.1)
    const centerX = (minX + maxX) / 2
    const centerY = (minY + maxY) / 2
    applyView({ zoom, x: -centerX * zoom, y: -centerY * zoom })
  }

  function fit() {
    touchedRef.current = false
    fitTo(simRef.current)
  }

  function resetLayout() {
    const sim = seed(visibleNodes, visibleEdges)
    relax(sim, 260)
    simRef.current = sim
    touchedRef.current = false
    fitTo(sim)
    setFrame((frame) => frame + 1)
  }

  // Wheel has to be non-passive to keep the page from scrolling, so it is
  // attached natively rather than through React's synthetic events.
  useEffect(() => {
    const element = wrapRef.current
    const svg = svgRef.current
    if (!element || !svg) return undefined
    const onWheel = (event) => {
      event.preventDefault()
      const rect = svg.getBoundingClientRect()
      const scale = rect.width / VIEW.w
      zoomBy(Math.exp(-event.deltaY * 0.0016), {
        x: (event.clientX - rect.left) / scale,
        y: (event.clientY - rect.top) / scale,
      })
    }
    element.addEventListener('wheel', onWheel, { passive: false })
    return () => element.removeEventListener('wheel', onWheel)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  function svgMetrics() {
    const rect = svgRef.current.getBoundingClientRect()
    return { rect, scale: rect.width / VIEW.w }
  }

  function startNodeDrag(event, simNode) {
    event.stopPropagation()
    if (event.button !== 0) return
    try { event.currentTarget.setPointerCapture(event.pointerId) } catch { /* synthetic events */ }
    dragRef.current = { node: simNode, lastX: event.clientX, lastY: event.clientY, moved: false }
    simNode.fixed = true
  }

  function moveNode(event) {
    const drag = dragRef.current
    if (!drag) return
    const { scale } = svgMetrics()
    const zoom = viewRef.current.zoom
    drag.node.x += (event.clientX - drag.lastX) / (scale * zoom)
    drag.node.y += (event.clientY - drag.lastY) / (scale * zoom)
    drag.lastX = event.clientX
    drag.lastY = event.clientY
    drag.moved = true
    setAwake(true)
  }

  function endNode(event, node) {
    const drag = dragRef.current
    dragRef.current = null
    if (!drag) return
    if (!drag.moved) setSelected((current) => (current === node.id ? null : node.id))
    event.stopPropagation()
  }

  function startPan(event) {
    if (event.button !== 0) return
    try { event.currentTarget.setPointerCapture(event.pointerId) } catch { /* synthetic events */ }
    touchedRef.current = true
    panRef.current = {
      startX: event.clientX, startY: event.clientY,
      originX: viewRef.current.x, originY: viewRef.current.y, moved: false,
    }
  }

  function movePan(event) {
    const pan = panRef.current
    if (!pan) return
    const { scale } = svgMetrics()
    const dx = (event.clientX - pan.startX) / scale
    const dy = (event.clientY - pan.startY) / scale
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) pan.moved = true
    applyView({ ...viewRef.current, x: pan.originX + dx, y: pan.originY + dy })
  }

  function endPan() {
    const pan = panRef.current
    panRef.current = null
    if (pan && !pan.moved) setSelected(null)
  }

  const sim = simRef.current
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
    return <EmptyState title="No runtime relationships are recorded yet"
      hint="Add a component, version, deployment and asset to make the running surface visible." />
  }

  return (
    <div className="project-graph-stack">
      {/* The four counters live once, on the summary card above this graph:
          repeating them here made the same numbers appear twice on one screen. */}
      <div className="graph-toolbar">
        <div className="graph-chips" role="group" aria-label="filter by kind">
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
                {TYPE_META[type].title}
                <span className="graph-chip-count">{typeCounts.get(type)}</span>
              </button>
            )
          })}
        </div>
        <div className="graph-tools">
          <input className="graph-filter" value={query} placeholder="filter nodes"
            aria-label="filter nodes by name"
            onChange={(event) => setQuery(event.target.value)} />
          <button type="button" className="mini" onClick={() => zoomBy(1 / 1.25)}
            aria-label="zoom out">−</button>
          <button type="button" className="mini graph-zoom" onClick={() => zoomBy(1 / view.zoom)}
            aria-label="reset zoom">{Math.round(view.zoom * 100)}%</button>
          <button type="button" className="mini" onClick={() => zoomBy(1.25)}
            aria-label="zoom in">+</button>
          <button type="button" className="mini" onClick={fit}>fit</button>
          <button type="button" className="mini" onClick={resetLayout}>reset</button>
        </div>
      </div>

      <div className="project-graph-wrap" ref={wrapRef}>
        <svg className="project-graph" ref={svgRef} viewBox={`0 0 ${VIEW.w} ${VIEW.h}`}
          role="img" aria-label={`Running now graph for ${data.project.name}`}
          onPointerDown={startPan} onPointerMove={movePan}
          onPointerUp={endPan} onPointerCancel={endPan}>
          <g transform={`translate(${VIEW.w / 2 + view.x} ${VIEW.h / 2 + view.y}) scale(${view.zoom})`}>
            {visibleEdges.map((edge) => {
              const from = sim?.index.get(edge.from)
              const to = sim?.index.get(edge.to)
              if (!from || !to) return null
              const dim = focusSet && !(focusSet.has(edge.from) && focusSet.has(edge.to))
              const hot = focusSet && focusSet.has(edge.from) && focusSet.has(edge.to)
              return (
                <line key={`${edge.from}->${edge.to}`}
                  className={`graph-edge${dim ? ' dim' : ''}${hot ? ' hot' : ''}`}
                  x1={from.x} y1={from.y} x2={to.x} y2={to.y}>
                  <title>{edge.relation}</title>
                </line>
              )
            })}
            {/* Relation names appear while a node is being pointed at — one
                per edge, placed a third of the way from the source so the
                reading direction is the line's own direction. Keeping them for
                a click-selection made three "contains" labels compete. */}
            {hovered && visibleEdges.filter((edge) => focusSet.has(edge.from) && focusSet.has(edge.to))
              .map((edge) => {
                const from = sim?.index.get(edge.from)
                const to = sim?.index.get(edge.to)
                if (!from || !to) return null
                return (
                  <text key={`label-${edge.from}->${edge.to}`} className="graph-edge-label"
                    x={from.x + (to.x - from.x) * 0.36} y={from.y + (to.y - from.y) * 0.36 - 5}
                    textAnchor="middle">
                    {edge.relation}
                  </text>
                )
              })}
            {visibleNodes.map((node) => {
              const point = sim?.index.get(node.id)
              if (!point) return null
              const dim = focusSet && !focusSet.has(node.id)
              const isFocus = focusId === node.id
              return (
                <g key={node.id} transform={`translate(${point.x},${point.y})`}
                  className={`graph-node type-${node.type}${dim ? ' dim' : ''}${isFocus ? ' focus' : ''}${point.fixed ? ' pinned' : ''}`}
                  role="button" tabIndex="0"
                  aria-label={`${TYPE_META[node.type].title} ${node.label}, ${node.degree} connections`}
                  onPointerDown={(event) => startNodeDrag(event, point)}
                  onPointerMove={moveNode}
                  onPointerUp={(event) => endNode(event, node)}
                  onPointerEnter={() => setHovered(node.id)}
                  onPointerLeave={() => setHovered((current) => (current === node.id ? null : current))}
                  onDoubleClick={(event) => {
                    event.stopPropagation()
                    point.fixed = false
                    setAwake(true)
                  }}
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
                  <title>{`${TYPE_META[node.type].title} · ${node.label}${detail(node) ? ` · ${detail(node)}` : ''} · ${node.degree} connections`}</title>
                </g>
              )
            })}
          </g>
        </svg>
        {!visibleNodes.length && (
          <p className="graph-empty">Every kind is filtered out. Turn one back on above.</p>
        )}
        <span className="graph-hint">
          drag a node to move it · drag the canvas to pan · scroll to zoom · double-click releases it
        </span>
      </div>

      <p className="muted" style={{ margin: 0, fontSize: 12 }}>
        Node size is the number of recorded relationships. The graph reads inventory;
        it does not scan or infer a link that no record carries.
        {isolated > 0 && ` ${isolated} visible ${isolated === 1 ? 'item has' : 'items have'} no connection to the rest — a filter is hiding the other end.`}
      </p>

      {selectedNode && (
        <Card title={`${TYPE_META[selectedNode.type].title} · ${selectedNode.label}`}
          actions={<button className="mini" onClick={() => setSelected(null)}>clear focus</button>}>
          <p className="muted" style={{ marginTop: 0 }}>
            {detail(selectedNode) || 'No additional metadata has been recorded for this item.'}
            {' · '}{selectedNode.degree} {selectedNode.degree === 1 ? 'connection' : 'connections'}
          </p>
          <div className="graph-neighbor-list">
            {selectedLinks.map(({ edge, other, outgoing }) => (
              <button key={`${edge.from}-${edge.to}`} type="button" className="graph-neighbor"
                onClick={() => setSelected(other.id)}>
                <span className="graph-neighbor-rel">{outgoing ? edge.relation : '←'}</span>
                <span className={`graph-neighbor-type type-${other.type}`}>{TYPE_META[other.type].title}</span>
                <span className="graph-neighbor-label">{other.label}</span>
              </button>
            ))}
            {!selectedLinks.length && <p className="muted">No recorded relationship reaches this item.</p>}
          </div>
        </Card>
      )}

      <Card title="Relationship list" actions={<span className="count">screen-reader and narrow-screen fallback</span>}>
        <div className="project-graph-list">
          {visibleEdges.map((edge) => {
            const from = nodes.find((node) => node.id === edge.from)
            const to = nodes.find((node) => node.id === edge.to)
            return (
              <button key={`${edge.from}-${edge.to}`} className="project-graph-row"
                onClick={() => setSelected(edge.to)}>
                <span>{from?.label}</span><b>{edge.relation}</b><span>{to?.label}</span>
              </button>
            )
          })}
        </div>
      </Card>
    </div>
  )
}