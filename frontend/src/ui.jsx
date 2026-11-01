import React, { useCallback, useEffect, useRef, useState } from 'react'

/* Shared UI primitives. Small on purpose: every screen composes these so
   loading, empty, error and destructive states behave the same everywhere. */

/* ── design tokens: dark / light / system, comfortable / compact ── */
const TOKENS = {
  dark: {
    bg: '#0d1117', panel: '#151b23', panel2: '#1c2430', border: '#30363d',
    text: '#e6edf3', muted: '#8b949e', accent: '#ff7b00', accentHover: '#ff9c3f',
    sev: { critical: '#ff5a5a', high: '#ff9c3f', medium: '#ffd166', low: '#6bcb77', unknown: '#8b949e' },
    st: { open: '#7b5ea7', acknowledged: '#5a9eec', in_progress: '#ff7b00',
          resolved: '#6bcb77', false_positive: '#c5cbec', accepted_risk: '#8b949e' },
    dialogBg: '#1c2430', dialogBorder: '#30363d', dialogText: '#e6edf3',
    overlay: 'rgba(13,17,23,0.66)',
  },
  light: {
    bg: '#f6f8fa', panel: '#ffffff', panel2: '#f0f3f6', border: '#d0d7de',
    text: '#1f2328', muted: '#57606a', accent: '#d24700', accentHover: '#e05800',
    sev: { critical: '#b30000', high: '#c2410c', medium: '#b7791f', low: '#2f855a', unknown: '#57606a' },
    st: { open: '#7b5ea7', acknowledged: '#2b6cb0', in_progress: '#c96800',
          resolved: '#2f855a', false_positive: '#57606a', accepted_risk: '#57606a' },
    dialogBg: '#ffffff', dialogBorder: '#d0d7de', dialogText: '#1f2328',
    overlay: 'rgba(246,248,250,0.72)',
  },
  system: {
    bg: '#0d1117', panel: '#151b23', panel2: '#1c2430', border: '#30363d',
    text: '#e6edf3', muted: '#8b949e', accent: '#ff7b00', accentHover: '#ff9c3f',
    sev: { critical: '#ff5a5a', high: '#ff9c3f', medium: '#ffd166', low: '#6bcb77', unknown: '#8b949e' },
    st: { open: '#7b5ea7', acknowledged: '#5a9eec', in_progress: '#ff7b00',
          resolved: '#6bcb77', false_positive: '#c5cbec', accepted_risk: '#8b949e' },
    dialogBg: '#1c2430', dialogBorder: '#30363d', dialogText: '#e6edf3',
    overlay: 'rgba(13,17,23,0.66)',
  },
}

const ROOT = document.documentElement

export function getTheme() {
  if (typeof window === 'undefined') return 'light'
  const stored = localStorage.getItem('barad.theme')
  if (stored === 'dark' || stored === 'light' || stored === 'system') return stored
  // Readable by default: a dark console was hard to read for long sessions.
  // Anyone who prefers dark keeps it via Settings (stored) or "system".
  return 'light'
}

export function getDensity() {
  if (typeof window === 'undefined') return 'comfortable'
  const stored = localStorage.getItem('barad.density')
  if (stored === 'comfortable' || stored === 'compact') return stored
  return 'comfortable'
}

export function setTheme(t) {
  localStorage.setItem('barad.theme', t)
  ROOT.setAttribute('data-theme', t)
  applyDensity()
}
export function setDensity(d) {
  localStorage.setItem('barad.density', d)
  ROOT.setAttribute('data-density', d)
  applyDensity()
}
function applyDensity() {
  const d = localStorage.getItem('barad.density') || 'comfortable'
  ROOT.setAttribute('data-density', d)
  // rem scale: comfortable = 16px base, compact = 14px base
  ROOT.style.setProperty('--rem', d === 'compact' ? '14px' : '16px')
  ROOT.style.setProperty('--space-sm', d === 'compact' ? '6px' : '8px')
  ROOT.style.setProperty('--space', d === 'compact' ? '10px' : '14px')
  ROOT.style.setProperty('--radius', d === 'compact' ? '4px' : '8px')
  ROOT.style.setProperty('--font-scale', d === 'compact' ? '0.92' : '1')
}

/* ── apply theme and density once, at module init ──
   This is not a component, so calling a hook here would run outside React's
   dispatcher and throw ("Cannot read properties of null (reading 'useEffect')"),
   which unmounted the whole console. Plain DOM writes are the correct tool. */
document.documentElement.setAttribute('data-theme', getTheme())
applyDensity()

/* ── PageHeader ── */
export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="page-head">
      <div>
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-sub">{subtitle}</p>}
      </div>
      {actions && <div className="row row-end">{actions}</div>}
    </div>
  )
}

/* ── Card ── */
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

/* ── Banner ── */
export function Banner({ kind = 'info', children, action }) {
  return (
    <div className={`banner banner-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <span style={{ minWidth: 0 }}>{children}</span>
      {action && <span className="row-end">{action}</span>}
    </div>
  )
}

/* ── ErrorBanner ── */
export function ErrorBanner({ error, onRetry }) {
  if (!error) return null
  const message = typeof error === 'string' ? error : String(error.message || error)
  return (
    <Banner kind="error" action={onRetry && (
      <button className="mini" onClick={onRetry}>retry</button>
    )}>{message}</Banner>
  )
}

/* ── EmptyState ── */
export function EmptyState({ title, hint, action }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {hint && <span>{hint}</span>}
      {action}
    </div>
  )
}

/* ── Loading ── */
export function Loading({ rows = 3, label = 'loading' }) {
  return (
    <div className="stack" aria-busy="true" aria-label={label}>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton" style={{ width: `${100 - index * 12}%` }} />
      ))}
    </div>
  )
}

/* ── Table ── */
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

/* ── Stat ── */
export function Stat({ value, label, tone }) {
  return (
    <div className={`metric ${tone || ''}`}>
      <div className="metric-value">{value}</div>
      <div className="metric-label">{label}</div>
    </div>
  )
}

/* ── Two-step ConfirmButton ── */
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

/* ── useAsync ── */
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

/* ── Field ── */
export function Field({ label, hint, children }) {
  return (
    <label>
      <span>{label}</span>
      {children}
      {hint && <span className="muted">{hint}</span>}
    </label>
  )
}

/* ── Modal (esc + backdrop close) ── */
export function Modal({ title, children, onClose, size = 'normal' }) {
  useEffect(() => {
    const escape = (event) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', escape)
    return () => window.removeEventListener('keydown', escape)
  }, [onClose])

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div className={`modal modal-${size}`} role="dialog" aria-modal="true" aria-label={title}
        onClick={(event) => event.stopPropagation()}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  )
}

/* ── Dialog (accessible, replaces window.alert/confirm/prompt) ── */
export function Dialog({ open, title, onClose, onConfirm, confirmLabel = 'Confirm',
                        destructive = false, size = 'normal', children, body }) {
  useEffect(() => {
    if (open) document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = '' }
  }, [open])

  if (!open) return null

  // A dialog without a confirm action is legitimate (a form owns its submit):
  // calling a missing onConfirm unmounted the app with "x is not a function".
  const onOK = () => {
    if (onConfirm) onConfirm()
    if (onClose) onClose()
  }

  return (
    <div className="modal-backdrop" role="presentation">
      <div className={`modal modal-${size}`} role="dialog" aria-modal="true"
        aria-label={title} aria-modality="alertdialog" onClick={(e) => e.stopPropagation()}>
        <div className="dialog-head">
          <h2 className="dialog-title">{title}</h2>
          <button className="mini" onClick={onClose} aria-label="close dialog">✕</button>
        </div>
        {body !== undefined ? <div className="dialog-body">{body}</div> : children}
        <div className="dialog-actions">
          <button className="mini" onClick={onClose}>Cancel</button>
          {onConfirm && (
            <button className={`${destructive ? 'btn-danger' : ''}`} onClick={onOK}
              style={{ marginLeft: 8 }}>
              {confirmLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

/* ── Input ── */
export function Input({ label, value, onChange, placeholder, type = 'text',
                        hint, disabled, textarea, rows, required }) {
  const el = textarea ? (
    <textarea rows={rows || 3}
      value={value} onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder} disabled={disabled}
      aria-label={label} required={required} />
  ) : (
    <input type={type} value={value} onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder} disabled={disabled}
      aria-label={label} required={required} />
  )
  return (
    <div className="field">
      {label && <label className="field-label">{label}</label>}
      {el}
      {hint && <span className="muted">{hint}</span>}
    </div>
  )
}

/* ── Select ── */
export function Select({ label, value, onChange, options, placeholder, disabled }) {
  const opts = [
    <option key="" value="">{placeholder || 'Select...'}</option>,
    ...options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)
  ]
  return (
    <div className="field">
      {label && <label className="field-label">{label}</label>}
      <select value={value} onChange={(e) => onChange(e.target.value)}
        disabled={disabled}>{opts}</select>
    </div>
  )
}

/* ── CheckBox ── */
export function CheckBox({ label, checked, onChange, disabled }) {
  return (
    <label className="check">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)}
        disabled={disabled} />
      <span>{label}</span>
    </label>
  )
}

/* ── Toast notifications (global manager) ── */
export function ToastItem({ toast, onDismiss }) {
  return (
    <div className={`toast toast-${toast.kind}`} role={toast.kind === 'error' ? 'alert' : 'status'}>
      <span className="toast-icon">{toast.kind === 'success' ? '✓' : toast.kind === 'error' ? '✕' : '•'}</span>
      <span className="toast-msg">{toast.message}</span>
      <button className="mini" onClick={() => onDismiss(toast.id)} aria-label="dismiss">✕</button>
    </div>
  )
}

/* ── useToasts: global toast manager ── */
export function useToasts() {
  const [toasts, setToasts] = useState([])
  const push = useCallback((message, kind = 'info', duration = 6000) => {
    const id = Date.now() + Math.random()
    setToasts((s) => [...s, { id, message, kind }])
    setTimeout(() => setToasts((s) => s.filter((t) => t.id !== id)), duration)
  }, [])
  const dismiss = useCallback((id) => {
    setToasts((s) => s.filter((t) => t.id !== id))
  }, [])
  return { toasts, push, dismiss }
}

/* ── ToastContainer: render all toasts (caller mounts once) ── */
export function ToastContainer({ toasts, dismiss }) {
  return (
    <div className="toast-stack" aria-live="polite" aria-atomic="false">
      {toasts.map((t) => <ToastItem key={t.id} toast={t} onDismiss={dismiss} />)}
    </div>
  )
}

/* ── Side panel drawer (desktop drawer + mobile full-screen fallback) ── */
export function Drawer({ open, title, onClose, children, fullScreen = false }) {
  useEffect(() => {
    if (open) document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = '' }
  }, [open])

  if (!open) return null

  return (
    <div className="modal-backdrop" role="presentation">
      <div className="drawer" style={{ width: fullScreen ? '100%' : 480 }}>
        <div className="drawer-head">
          <h2 className="drawer-title">{title}</h2>
          <button className="mini" onClick={onClose} aria-label="close drawer">✕</button>
        </div>
        <div className="drawer-body">{children}</div>
      </div>
    </div>
  )
}

/* ── Tabs ── */
export function Tabs({ tabs, active, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={active === t.id}
          className={`tab ${active === t.id ? 'active' : ''}`}
          onClick={() => onChange(t.id)}>{t.label}</button>
      ))}
    </div>
  )
}

/* ── Code block (monospace, redaction-aware) ── */
export function CodeBlock({ lines, highlightLine }) {
  return (
    <pre className="code">
      {lines.map((l) => (
        <div key={l.number} className={highlightLine === l.number ? 'code-hit' : ''}>
          <span className="code-n">{l.number}</span>{l.text}
        </div>
      ))}
    </pre>
  )
}

/* ── Severity badge ── */
export function SeverityBadge({ severity, className = '' }) {
  const s = (severity || 'unknown').toLowerCase()
  return <span className={`sev sev-${s} ${className}`}>{severity?.toUpperCase?.() || 'UNKNOWN'}</span>
}

/* ── Status badge ── */
export function StatusBadge({ status, className = '' }) {
  const s = (status || 'unknown').toLowerCase()
  return <span className={`st st-${s} ${className}`}>{status?.toLowerCase?.() || 'unknown'}</span>
}

/* ── Pill (classification) ── */
export function Pill({ children, tone = 'default', className = '' }) {
  return (
    <span className={`pill pill-${tone} ${className}`}>{children}</span>
  )
}

/* ── Toggle (theme/density pickers) ── */
export function Toggle({ label, active, onChange, options }) {
  return (
    <div className="field field-toggle">
      <span className="field-label">{label}</span>
      <div className="toggle-group" role="group" aria-label={label}>
        {options.map((o) => (
          <button key={o.value} type="button"
            className={`toggle-option ${active === o.value ? 'active' : ''}`}
            onClick={() => onChange(o.value)}>
            {o.label}
          </button>
        ))}
      </div>
    </div>
  )
}
