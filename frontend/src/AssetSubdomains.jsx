import React, { useEffect, useMemo, useState } from 'react'

/* ─────────────────────── the children, listed instead of counted ───────────────────────

   "50 subdomains" is a number, and a graph that draws six of them answers nothing
   about the other forty-four. The panel lists every child with the two or three
   facts that decide which one is worth opening first: does it answer, what is open
   on it, is its certificate running out, was it ever observed. Every row is a door:
   clicking goes to that asset's own page.

   Nothing here is computed twice — the rows arrive from the same endpoint that
   resolved the asset, from observations already stored. */

function stamp(value) {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  const minutes = Math.round((Date.now() - date.getTime()) / 60000)
  if (minutes < 2) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  if (minutes < 60 * 24) return `${Math.round(minutes / 60)}h ago`
  return `${Math.round(minutes / 1440)}d ago`
}

function certTone(days) {
  if (days == null) return ''
  if (days < 0) return 'asset-bad'
  if (days < 20) return 'asset-warn'
  return 'muted'
}

function Row({ row, onOpen }) {
  const seen = stamp(row.observed_at)
  return (
    <li>
      <button className="sub-row" onClick={() => onOpen(row.id)}>
        <span className="sub-name mono">{row.value}</span>
        <span className="sub-meta">
          {row.addresses.length > 0
            ? <span className="mono muted">{row.addresses.join(', ')}</span>
            : <span className="muted">no address</span>}
          {row.ports > 0 && <span className="pill">{row.ports} port(s)</span>}
          {row.products > 0 && <span className="pill">{row.products} product(s)</span>}
          {row.certificate_days != null && (
            <span className={certTone(row.certificate_days)}>
              {row.certificate_days < 0
                ? 'certificate expired'
                : `cert ${row.certificate_days}d`}
            </span>
          )}
          {row.classification_status && row.classification_status !== 'unclassified' && (
            <span className="pill">{row.classification_status}</span>
          )}
          <span className="sub-seen muted small">{seen || 'never observed'}</span>
        </span>
      </button>
    </li>
  )
}

export function SubdomainDrawer({ open, onClose, rows = [], total = 0, assetValue = '' }) {
  const [query, setQuery] = useState('')

  useEffect(() => {
    if (!open) return undefined
    const onKey = (event) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return rows
    return rows.filter((row) => row.value.toLowerCase().includes(needle)
      || row.addresses.some((address) => address.includes(needle)))
  }, [rows, query])

  if (!open) return null

  return (
    <div className="sub-drawer-scrim" onClick={onClose} role="presentation">
      <aside className="sub-drawer" onClick={(event) => event.stopPropagation()}
             role="dialog" aria-modal="true" aria-label="subdomains">
        <header className="sub-drawer-head">
          <div>
            <h2 className="sub-drawer-title">subdomains</h2>
            <p className="muted small">
              {filtered.length === total
                ? `${total} under ${assetValue}`
                : `${filtered.length} of ${total} under ${assetValue}`}
            </p>
          </div>
          <button className="ghost mini" onClick={onClose} aria-label="close">✕</button>
        </header>
        <input className="sub-drawer-filter" placeholder="filter by name or address"
               value={query} onChange={(event) => setQuery(event.target.value)} />
        {!rows.length ? (
          <p className="empty">no subdomain is known for this name yet</p>
        ) : !filtered.length ? (
          <p className="empty">nothing matches “{query}”</p>
        ) : (
          <ul className="sub-list">
            {filtered.map((row) => (
              <Row key={row.id} row={row}
                   onOpen={(id) => { window.location.hash = `asset::${id}`; onClose() }} />
            ))}
          </ul>
        )}
      </aside>
    </div>
  )
}

export default function SubdomainCard({ rows = [], total = 0, onOpenAll, onOpenOne }) {
  const preview = rows.slice(0, 4)
  return (
    <div className="sub-preview">
      {!rows.length ? (
        <p className="hint">no subdomain is known for this name yet.</p>
      ) : (
        <ul className="sub-list">
          {preview.map((row) => (
            <Row key={row.id} row={row} onOpen={onOpenOne} />
          ))}
        </ul>
      )}
      {total > preview.length && (
        <button className="ghost sub-more" onClick={onOpenAll}>
          open all {total} →
        </button>
      )}
    </div>
  )
}
