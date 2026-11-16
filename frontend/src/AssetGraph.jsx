import React, { useMemo, useState } from 'react'
import { Card, EmptyState } from './ui'
import useForceGraph from './useForceGraph'
import { degrees, hash, radiusFor } from './graphForce'
import { useI18n } from './i18n'

/* ─────────────────────────── the domain graph ───────────────────────────

   What the inventory is actually saying: which names hang from which, and where
   they land. Two edge kinds, both observed or declared — never invented:

     parent      `dev.api.example` hangs from `api.example` because both rows
                 exist and one name is the other's suffix. Derived on the server.
     resolves_to the address the newest observation returned for that name.

   A solid ring means an active grant covers the domain; a dashed one means
   nobody may touch it yet (a pending request is not permission). The geometry
   and interaction are the console's: `useForceGraph` is the same engine the
   project summary and the dependency graph run on. */

function nodeRadius(node, degree) {
  if (node.kind === 'address') return Math.min(16, radiusFor(degree) * 0.8)
  return Math.min(26, radiusFor(degree) + 4)
}

function buildGraph(assets) {
  const live = assets.filter((asset) => !asset.archived_at)
  const nodes = []
  const edges = []
  const byValue = new Map()
  for (const asset of live) {
    const id = `a:${asset.id}`
    const kind = ['domain', 'subdomain', 'api'].includes(asset.type) ? 'domain' : asset.type
    byValue.set(String(asset.value).toLowerCase(), id)
    nodes.push({
      id, kind, label: asset.value, asset,
      depth: asset.parent?.depth || 0,
      authorized: Boolean(asset.authorization?.covered),
      pending: Boolean(asset.authorization?.pending_request_id),
    })
  }
  for (const asset of live) {
    const id = `a:${asset.id}`
    const parentId = asset.parent?.value
      ? byValue.get(String(asset.parent.value).toLowerCase()) : null
    if (parentId && parentId !== id) {
      edges.push({ from: id, to: parentId, relation: 'parent' })
    }
    const addresses = [...(asset.latest?.ipv4 || []), ...(asset.latest?.ipv6 || [])]
    for (const address of addresses.slice(0, 4)) {
      const addressId = `ip:${address}`
      if (!byValue.has(addressId)) {
        byValue.set(addressId, addressId)
        nodes.push({ id: addressId, kind: 'address', label: address, depth: 3 })
      }
      edges.push({ from: id, to: addressId, relation: 'resolves_to' })
    }
  }
  return { nodes, edges }
}

export default function AssetGraph({ assets, selectedId, onPick }) {
  const { t } = useI18n()
  const graph = useMemo(() => buildGraph(assets), [assets])
  const degree = useMemo(() => degrees(graph.nodes, graph.edges), [graph])
  const [localId, setLocalId] = useState(null)

  const nodes = useMemo(() => graph.nodes.map((node) => ({
    ...node,
    degree: degree.get(node.id) || 0,
    r: nodeRadius(node, degree.get(node.id) || 0),
  })), [graph, degree])

  // Left-to-right by depth so the picture reads as the ramification it is; the
  // jitter comes from the id hash, which keeps the drawing identical twice.
  const position = useMemo(() => (node) => ({
    x: (node.depth || 0) * 150,
    y: (hash(node.id) % 260) - 130,
  }), [])

  const engine = useForceGraph({
    nodes,
    edges: graph.edges,
    position,
    clusterDirection: 'in',
    onSelect: (id) => {
      if (!id) { setLocalId(null); onPick?.(null); return }
      setLocalId(id)
      const node = nodes.find((candidate) => candidate.id === id)
      if (node?.asset) onPick?.(node.asset)
    },
  })
  const { view, settled } = engine
  const focusId = selectedId ? `a:${selectedId}` : localId

  if (!nodes.length) {
    return (
      <Card>
        <EmptyState title={t('assetGraph.empty.title')}
          hint={t('assetGraph.empty.hint')} />
      </Card>
    )
  }

  return (
    <Card tight>
      <div className="sbom-graph-toolbar">
        <strong className="sbom-graph-head" style={{ margin: 0 }}>{t('assetGraph.heading')}</strong>
        <span className="sbom-legend">
          <span className="sbom-legend-dot" style={{ background: 'var(--panel-2)',
            border: '1px solid var(--text-dim)' }} />{t('assetGraph.legend.domain')}
          <span className="sbom-legend-dot" style={{ background: 'var(--line-strong)' }} />{t('assetGraph.legend.address')}
        </span>
        <span className="muted sbom-legend-note">
          {t('assetGraph.legendNote', {
            domains: nodes.filter((node) => node.kind === 'domain').length,
            addresses: nodes.filter((node) => node.kind === 'address').length,
          })}
        </span>
        <span className="row-end graph-zoom">
          <button type="button" className="mini" onClick={() => engine.zoomBy(1 / 1.25)}
            aria-label={t('assetGraph.zoomOut')}>−</button>
          <button type="button" className="mini" onClick={() => engine.zoomBy(1 / view.zoom)}
            aria-label={t('assetGraph.resetZoom')}>{Math.round(view.zoom * 100)}%</button>
          <button type="button" className="mini" onClick={() => engine.zoomBy(1.25)}
            aria-label={t('assetGraph.zoomIn')}>+</button>
          <button type="button" className="mini" onClick={engine.fit}>{t('assetGraph.fit')}</button>
          <button type="button" className="mini" onClick={engine.reset}>{t('assetGraph.reset')}</button>
        </span>
      </div>

      <div className="sbom-graph-canvas" ref={engine.wrapRef}>
        <svg ref={engine.svgRef} viewBox={`0 0 ${engine.VIEW.w} ${engine.VIEW.h}`} role="img"
          aria-label={t('assetGraph.ariaLabel')}
          {...engine.svgHandlers}>
          <g transform={`translate(${engine.VIEW.w / 2 + view.x} ${engine.VIEW.h / 2 + view.y}) scale(${view.zoom})`}>
            {graph.edges.map((edge) => {
              const from = settled.get(edge.from)
              const to = settled.get(edge.to)
              if (!from || !to) return null
              const active = focusId && (edge.from === focusId || edge.to === focusId)
              return (
                <line key={`${edge.from}-${edge.to}`}
                  x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                  className={`asset-graph-edge${active ? ' is-active' : ''}`}
                  strokeDasharray={edge.relation === 'parent' ? undefined : '5 4'}
                  style={{ opacity: focusId ? (active ? 0.95 : 0.1) : 0.75 }} />
              )
            })}
            {nodes.map((node) => {
              const entry = settled.get(node.id)
              if (!entry) return null
              const isSelected = focusId === node.id
              const dim = focusId ? !isSelected && !graph.edges.some(
                (edge) => (edge.from === focusId && edge.to === node.id)
                  || (edge.to === focusId && edge.from === node.id)) : false
              const address = node.kind === 'address'
              // Structure stays neutral: severity colours mean severity here, so
              // an authorized domain is a solid ring and an unauthorized one is
              // dashed, never green versus red.
              const stroke = isSelected ? 'var(--text)'
                : node.authorized ? 'var(--text-dim)' : 'var(--line-strong)'
              return (
                <g key={node.id} transform={`translate(${entry.x},${entry.y})`}
                  className={`sbom-graph-node-group${entry.fixed ? ' is-pinned' : ''}`}
                  style={{ opacity: dim ? 0.28 : 1 }}
                  role="button" tabIndex={0}
                  aria-label={`${node.label}${node.pending ? t('assetGraph.pendingSuffix') : ''}`}
                  {...engine.nodeHandlers(entry, node)}>
                  <circle r={node.r + 8} className="sbom-graph-hit" fill="transparent" />
                  <circle r={node.r}
                    fill={address ? 'var(--line-strong)' : 'var(--panel-2)'}
                    stroke={address ? 'var(--panel)' : stroke}
                    strokeWidth={isSelected ? 2.5 : (address ? 1 : 1.6)}
                    strokeDasharray={address ? undefined : (node.authorized ? undefined : '4 3')}
                    className="sbom-graph-dot" />
                  {(!address || view.zoom >= 1.05 || isSelected) && (
                    <text className="sbom-graph-label" x={node.r + 5} dy="0.32em">
                      {node.label}{node.pending ? ' ·' : ''}
                    </text>
                  )}
                </g>
              )
            })}
          </g>
        </svg>
        <span className="graph-hint">
          {t('assetGraph.hint')}
        </span>
      </div>
    </Card>
  )
}
