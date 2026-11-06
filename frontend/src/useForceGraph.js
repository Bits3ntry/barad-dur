import { useEffect, useRef, useState } from 'react'
import { clamp, clusterOf, relax, seedForce, step } from './graphForce'

/* One interactive force graph, used by the project summary and by the BOM's
   dependency tab.

   The two screens are different documents, not different interaction models:
   dragging a node carries what belongs to it, dragging the canvas pans, the
   wheel zooms, double-click releases a pinned node, and the resting layout only
   re-fits while the reader has not taken over. Keeping that in one hook is the
   only way "the same as in projects" stays true a month from now. */

const VIEW = { w: 980, h: 560 }

export default function useForceGraph({
  nodes,
  edges,
  position,
  onSelect,
  clusterDirection = 'out',
  onDragStart,
}) {
  const [view, setView] = useState({ zoom: 0.8, x: 0, y: 0 })
  const [hovered, setHovered] = useState(null)
  const [, setFrame] = useState(0)
  const viewRef = useRef(view)
  const simRef = useRef(null)
  const touchedRef = useRef(false)
  const dragRef = useRef(null)
  const panRef = useRef(null)
  const svgRef = useRef(null)
  const wrapRef = useRef(null)
  const [awake, setAwake] = useState(false)

  const key = nodes.map((node) => node.id).join('|')

  function applyView(next) {
    viewRef.current = next
    setView(next)
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
    applyView({
      zoom,
      x: -((minX + maxX) / 2) * zoom,
      y: -((minY + maxY) / 2) * zoom,
    })
  }

  // Settle whenever the visible set changes. Nodes already on screen keep their
  // place, so filtering does not reshuffle the drawing; the view re-fits itself
  // until the reader pans or zooms.
  useEffect(() => {
    const previous = simRef.current ? simRef.current.index : new Map()
    const sim = seedForce(nodes, edges, position)
    for (const entry of sim.nodes) {
      const old = previous.get(entry.id)
      if (old) { entry.x = old.x; entry.y = old.y; entry.fixed = old.fixed }
    }
    relax(sim, Math.round(clamp(42000 / Math.max(1, sim.nodes.length), 70, 260)))
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

  function zoomBy(factor, anchor) {
    const current = viewRef.current
    const zoom = clamp(current.zoom * factor, 0.25, 3)
    touchedRef.current = true
    if (!anchor) { applyView({ ...current, zoom }); return }
    const change = zoom / current.zoom
    applyView({
      zoom,
      x: anchor.x - VIEW.w / 2 - ((anchor.x - VIEW.w / 2 - current.x) * change),
      y: anchor.y - VIEW.h / 2 - ((anchor.y - VIEW.h / 2 - current.y) * change),
    })
  }

  function svgMetrics() {
    const rect = svgRef.current.getBoundingClientRect()
    return { rect, scale: rect.width / VIEW.w }
  }

  function svgPoint(event) {
    const box = svgRef.current.getBoundingClientRect()
    return {
      x: ((event.clientX - box.left) / box.width) * VIEW.w,
      y: ((event.clientY - box.top) / box.height) * VIEW.h,
    }
  }

  function startNodeDrag(event, entry) {
    event.stopPropagation()
    if (event.button !== 0) return
    try { event.currentTarget.setPointerCapture(event.pointerId) } catch { /* synthetic events */ }
    const sim = simRef.current
    // Everything that hangs off this node travels with it: dragging a component
    // and leaving its versions behind tears the picture apart.
    const carried = sim
      ? clusterOf(entry.id, edges, clusterDirection, 3)
        .map((id) => sim.index.get(id))
        .filter((candidate) => candidate && candidate !== entry)
      : []
    dragRef.current = {
      node: entry, carried, lastX: event.clientX, lastY: event.clientY, moved: false,
      offsets: carried.map((child) => ({ entry: child, dx: child.x - entry.x, dy: child.y - entry.y })),
    }
    entry.fixed = true
    for (const child of carried) child.fixed = true
    if (onDragStart) onDragStart(entry)
  }

  function moveNode(event) {
    const drag = dragRef.current
    if (!drag) return
    const { scale } = svgMetrics()
    const zoom = viewRef.current.zoom
    drag.node.x += (event.clientX - drag.lastX) / (scale * zoom)
    drag.node.y += (event.clientY - drag.lastY) / (scale * zoom)
    for (const offset of drag.offsets) {
      offset.entry.x = drag.node.x + offset.dx
      offset.entry.y = drag.node.y + offset.dy
    }
    drag.lastX = event.clientX
    drag.lastY = event.clientY
    drag.moved = true
    setAwake(true)
    setFrame((frame) => frame + 1)
  }

  function endNode(event, node) {
    const drag = dragRef.current
    dragRef.current = null
    if (!drag) return
    event.stopPropagation()
    if (!drag.moved) onSelect(node.id)
  }

  function unpin(event, entry) {
    event.stopPropagation()
    entry.fixed = false
    setAwake(true)
    setFrame((frame) => frame + 1)
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
    if (Math.abs(dx) + Math.abs(dy) > 3) pan.moved = true
    applyView({ zoom: viewRef.current.zoom, x: pan.originX + dx, y: pan.originY + dy })
  }

  function endPan() {
    const pan = panRef.current
    panRef.current = null
    if (pan && !pan.moved) onSelect(null)
  }

  function fit() {
    touchedRef.current = false
    fitTo(simRef.current)
  }

  function reset() {
    const sim = seedForce(nodes, edges, position)
    relax(sim, Math.round(clamp(42000 / Math.max(1, sim.nodes.length), 70, 260)))
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
      const box = svg.getBoundingClientRect()
      const anchor = {
        x: ((event.clientX - box.left) / box.width) * VIEW.w,
        y: ((event.clientY - box.top) / box.height) * VIEW.h,
      }
      zoomBy(event.deltaY < 0 ? 1.12 : 1 / 1.12, anchor)
    }
    element.addEventListener('wheel', onWheel, { passive: false })
    return () => element.removeEventListener('wheel', onWheel)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return {
    VIEW,
    view,
    viewRef,
    svgRef,
    wrapRef,
    sim: simRef.current,
    settled: simRef.current
      ? new Map(simRef.current.nodes.map((entry) => [entry.id, entry]))
      : new Map(),
    hovered,
    setHovered,
    awake,
    setAwake,
    zoomBy,
    fit,
    reset,
    applyView,
    svgPoint,
    svgHandlers: {
      onPointerDown: startPan,
      onPointerMove: movePan,
      onPointerUp: endPan,
      onPointerCancel: endPan,
    },
    nodeHandlers: (entry, node) => ({
      onPointerDown: (event) => startNodeDrag(event, entry),
      onPointerMove: moveNode,
      onPointerUp: (event) => endNode(event, node),
      onDoubleClick: (event) => unpin(event, entry),
    }),
  }
}
