import React, { useCallback, useEffect, useRef, useState } from 'react'

/* Shared UI primitives. Small on purpose: every screen composes these so
   loading, empty, error and destructive states behave the same everywhere. */

export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="page-head">
      <div>
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-sub">{subtitle}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  )
}

export function Card({ title, actions, children, tight }) {
  return (
    <section className={`card ${tight ? 'card-tight' : ''}`}>
      {(title || actions) && (
        <div className="row" style={{ marginBottom: 12 }}>
          {title && <h2 className="card-title" style={{ margin: 0 }}>{title}</h2>}
          {actions && <div className="row row-end">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  )
}

export function Banner({ kind = 'info', children, action }) {
  return (
    <div className={`banner banner-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <span style={{ minWidth: 0 }}>{children}</span>
      {action && <span className="row-end">{action}</span>}
    </div>
  )
}

export function ErrorBanner({ error, onRetry }) {
  if (!error) return null
  const message = typeof error === 'string' ? error : String(error.message || error)
  return (
    <Banner kind="error" action={onRetry && (
      <button className="mini" onClick={onRetry}>retry</button>
    )}>
      {message}
    </Banner>
  )
}

export function EmptyState({ title, hint, action }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {hint && <span>{hint}</span>}
      {action}
    </div>
  )
}

export function Loading({ rows = 3, label = 'loading' }) {
  return (
    <div className="stack" aria-busy="true" aria-label={label}>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton" style={{ width: `${100 - index * 12}%` }} />
      ))}
    </div>
  )
}

export function Table({ head, children, empty }) {
  const rows = React.Children.toArray(children)
  if (rows.length === 0 && empty) return empty
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{head.map((cell, index) => <th key={index}>{cell}</th>)}</tr></thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

export function Stat({ value, label, tone }) {
  return (
    <div className={`metric ${tone || ''}`}>
      <div className="metric-value">{value}</div>
      <div className="metric-label">{label}</div>
    </div>
  )
}

/* Two-step destructive action: the first click asks, the second confirms. */
export function ConfirmButton({ children, confirmLabel = 'confirm', onConfirm,
                                className = 'mini' }) {
  const [armed, setArmed] = useState(false)
  const timer = useRef(null)

  useEffect(() => () => clearTimeout(timer.current), [])

  const click = () => {
    if (!armed) {
      setArmed(true)
      timer.current = setTimeout(() => setArmed(false), 4000)
      return
    }
    clearTimeout(timer.current)
    setArmed(false)
    onConfirm()
  }

  return (
    <button className={`${className} ${armed ? 'btn-danger' : ''}`} onClick={click}
      aria-live="polite">
      {armed ? confirmLabel : children}
    </button>
  )
}

/* Data loading with the states a screen actually needs to render. */
export function useAsync(loader, deps = []) {
  const [state, setState] = useState({ data: null, error: '', loading: true, loadedAt: 0 })
  const alive = useRef(true)

  const run = useCallback(() => {
    setState((prior) => ({ ...prior, loading: true, error: '' }))
    Promise.resolve()
      .then(loader)
      .then((data) => {
        if (alive.current) setState({ data, error: '', loading: false, loadedAt: Date.now() })
      })
      .catch((error) => {
        if (alive.current) {
          setState({ data: null, error: String(error.message || error), loading: false,
            loadedAt: Date.now() })
        }
      })
  }, deps)

  useEffect(() => {
    alive.current = true
    run()
    return () => { alive.current = false }
  }, [run])

  return { ...state, reload: run, setData: (data) => setState((s) => ({ ...s, data })) }
}

export function Field({ label, hint, children }) {
  return (
    <label>
      <span>{label}</span>
      {children}
      {hint && <span className="muted">{hint}</span>}
    </label>
  )
}

export function Modal({ title, children, onClose }) {
  useEffect(() => {
    const escape = (event) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', escape)
    return () => window.removeEventListener('keydown', escape)
  }, [onClose])

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}
        onClick={(event) => event.stopPropagation()}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  )
}
