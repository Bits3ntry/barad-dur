import React, { useMemo } from 'react'

/* ─────────────────────── the asset, in the middle of its edges ───────────────────────

   A radial diagram, not a force layout: the reader came here to see what this one
   asset touches, and a simulation that rearranges itself on every visit answers a
   different question. This one is deterministic — the same asset draws the same
   picture — and every edge is something the platform actually knows:

     parent        the derived ancestor in our own inventory
     child         our assets that hang from this name
     resolves      an address the newest observation returned
     project       where it is filed (or that it is not)
     grant         the permission, and whether it is active

   Nothing is drawn for a relationship we cannot prove. */

const W = 760
const H = 400

const TONES = {
  self: 'self',
  asset: 'asset',
  address: 'address',
  project: 'project',
  grant: 'grant',
}

function shorten(value, limit = 26) {
  const text = String(value)
  if (text.length <= limit) return text
  // Keep the two ends: the leaf and the zone. A tail cut loses the part that says
  // whose subdomain it is.
  const head = text.slice(0, limit - 12)
  const tail = text.slice(-9)
  return `${head}…${tail}`
}

/* Two rings, because they answer different questions. The inner one is what the
   asset *is* — parent, address, owner, permission — and stays close to the centre;
   the outer one is what hangs from it. One ring for both put a permission next to
   a subdomain and made a crowded disc out of four different kinds of fact. */
const INNER = ['parent', 'address', 'project', 'grant']

function layout(nodes) {
  const centre = { x: W / 2, y: H / 2 }
  const inner = nodes.filter((node) => node.kind !== 'self' && INNER.includes(node.kind))
  const outer = nodes.filter((node) => node.kind === 'child')
  const placed = nodes.map((node) => {
    if (node.kind === 'self') return { ...node, x: centre.x, y: centre.y }
    const ring = INNER.includes(node.kind) ? inner : outer
    const index = ring.indexOf(node)
    const radius = INNER.includes(node.kind) ? Math.min(H / 2 - 92, 96) : H / 2 - 46
    const offset = INNER.includes(node.kind) ? Math.PI : -Math.PI / 2
    const angle = offset + (Math.PI * 2 * index) / Math.max(1, ring.length)
    return { ...node, x: centre.x + Math.cos(angle) * radius,
             y: centre.y + Math.sin(angle) * radius }
  })
  return { placed }
}

export default function AssetRelations({ asset, parent, children = [], addresses = [],
                                         project, projectName, grant, covered,
                                         onOpenChildren }) {
  const nodes = useMemo(() => {
    const list = [{ id: 'self', kind: 'self', label: asset.value, tone: TONES.self }]
    if (parent?.value) {
      list.push({ id: `parent:${parent.value}`, kind: 'parent', label: parent.value,
                  tone: 'asset', hint: 'parent', link: parent.id })
    }
    for (const child of children.slice(0, 6)) {
      // The address under the name is what tells two subdomains apart at a
      // glance: same zone, different machine.
      const address = (child.addresses || [])[0]
      list.push({ id: `child:${child.id}`, kind: 'child', label: child.value,
                  tone: 'asset', link: child.id, hint: address || null })
    }
    for (const address of addresses.slice(0, 3)) {
      list.push({ id: `ip:${address}`, kind: 'address', label: address, tone: 'address',
                  hint: 'resolves to' })
    }
    if (project) {
      list.push({ id: `project:${project}`, kind: 'project',
                  label: projectName || project, tone: 'project', hint: 'filed in',
                  link: project })
    }
    if (grant) {
      list.push({ id: `grant:${grant}`, kind: 'grant', label: grant, tone: 'grant',
                  hint: covered ? 'authorized' : 'no coverage' })
    } else {
      list.push({ id: 'grant:none', kind: 'grant', label: 'no grant', tone: 'grant',
                  hint: 'not authorized' })
    }
    return list
  }, [asset, parent, children, addresses, project, projectName, grant, covered])

  const { placed } = layout(nodes)
  const centre = placed.find((node) => node.kind === 'self')
  const extra = children.length - Math.min(children.length, 6)

  return (
    <div className="asset-rel">
      <svg viewBox={`0 0 ${W} ${H}`} role="img"
           aria-label={`relationships of ${asset.value}`}>
        {placed.filter((node) => node.kind !== 'self').map((node) => (
          <line key={`e:${node.id}`} x1={centre.x} y1={centre.y} x2={node.x} y2={node.y}
                className={`rel-edge rel-edge-${node.tone}`} />
        ))}
        {placed.map((node) => (
          <g key={node.id} className={`rel-node rel-${node.tone}`}
             onClick={() => node.link && node.kind !== 'self'
               && node.kind !== 'project' && (window.location.hash = `asset::${node.link}`)}>
            <title>{node.label}{node.hint ? ` · ${node.hint}` : ''}</title>
            <circle cx={node.x} cy={node.y}
                    r={node.kind === 'self' ? 9 : 6} />
            <text x={node.x} y={node.y - (node.kind === 'self' ? 18 : 12)}
                  textAnchor="middle" className="rel-label">
              {shorten(node.label, node.kind === 'self' ? 34 : 26)}
            </text>
            {node.hint && (
              <text x={node.x} y={node.y + (node.kind === 'self' ? 22 : 16)}
                    textAnchor="middle" className="rel-hint">{node.hint}</text>
            )}
          </g>
        ))}
      </svg>
      <div className="asset-rel-foot">
        <span>{children.length} subdomain(s) · {addresses.length} address(es)</span>
        <span className="row-end">
          {extra > 0 && <span className="muted">+{extra} not drawn</span>}
          {children.length > 0 && onOpenChildren && (
            <button className="ghost mini" onClick={onOpenChildren}>
              open the list →
            </button>
          )}
        </span>
      </div>
    </div>
  )
}
