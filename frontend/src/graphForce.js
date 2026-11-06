/* The force layout the console uses for its graphs.

   Extracted so the project graph and the dependency graph are the same physics,
   not two copies of it that quietly diverge. Deterministic on purpose: the seed
   comes from a hash of the node id, so the same build draws the same picture
   twice. Positions are the caller's business — a column per record type there, a
   ring here — the rest is shared. */

export const MIN_RADIUS = 5.5
export const MAX_RADIUS = 24

export function radiusFor(degree) {
  return Math.min(MAX_RADIUS, MIN_RADIUS + Math.sqrt(degree) * 4.1)
}

export function hash(text) {
  let value = 2166136261
  for (let i = 0; i < text.length; i += 1) {
    value ^= text.charCodeAt(i)
    value = Math.imul(value, 16777619)
  }
  return Math.abs(value)
}

export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value))
}

export function degrees(nodes, edges) {
  const map = new Map(nodes.map((node) => [node.id, 0]))
  for (const edge of edges) {
    map.set(edge.from, (map.get(edge.from) || 0) + 1)
    map.set(edge.to, (map.get(edge.to) || 0) + 1)
  }
  return map
}

/* What belongs to a node: the nodes reachable from it in `direction`, up to a
   depth. Dragging a component without its versions (or a package without what it
   brings in) tears the picture apart — the picture should move as a piece. */
export function clusterOf(rootId, edges, direction = 'out', depth = 3) {
  const seen = new Set([rootId])
  const found = [rootId]
  let frontier = [rootId]
  for (let level = 0; level < depth && frontier.length; level += 1) {
    const next = []
    for (const edge of edges) {
      const [from, to] = direction === 'out' ? [edge.from, edge.to] : [edge.to, edge.from]
      if (!frontier.includes(from) || seen.has(to)) continue
      seen.add(to)
      next.push(to)
      found.push(to)
    }
    frontier = next
  }
  return found
}

export const REPULSION = 9000
export const GRAVITY = 0.006
export const STIFFNESS = 0.05
export const DAMPING = 0.58

/* `position(node, index)` decides where a node starts; everything after that is
   physics. A node with no edges is still placed: the point of the graph is to
   show what is not attached to anything. */
export function seedForce(nodes, edges, position) {
  const sim = { nodes: [], links: [], index: new Map(), settled: false }
  nodes.forEach((node, row) => {
    const start = position(node, row)
    const entry = {
      id: node.id,
      x: start.x,
      y: start.y,
      vx: 0,
      vy: 0,
      r: node.r || radiusFor(node.degree || 0),
      fixed: false,
    }
    sim.index.set(node.id, entry)
    sim.nodes.push(entry)
  })
  for (const edge of edges) {
    const from = sim.index.get(edge.from)
    const to = sim.index.get(edge.to)
    if (!from || !to) continue
    sim.links.push({ a: from, b: to, rest: 96 + from.r + to.r, relation: edge.relation })
  }
  return sim
}

export function step(sim) {
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

export function relax(sim, iterations) {
  for (let i = 0; i < iterations; i += 1) step(sim)
}
