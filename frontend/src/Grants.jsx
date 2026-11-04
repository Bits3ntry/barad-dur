import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, Dialog, EmptyState, Loading, PageHeader } from './ui'

/* Authorization grants: the ledger of "who may run what, against which targets,
   until when". It is a record first — issuing and simulating are two deliberate
   actions behind buttons, not three forms stacked on the reading surface. */

const TARGET_TYPES = ['domain', 'wildcard_domain', 'ip', 'cidr', 'url',
  'repository', 'service', 'endpoint']
const FALLBACK_CAPABILITIES = ['passive_discovery', 'active_verification',
  'vulnerability_analysis', 'intrusive_testing']

function humanWindow(hours) {
  const value = Number(hours)
  if (!Number.isFinite(value) || value <= 0) return 'no window'
  if (value < 48) return `${value} hour${value === 1 ? '' : 's'}`
  const days = value / 24
  return `${Number.isInteger(days) ? days : days.toFixed(1)} days`
}

function expiry(iso) {
  if (!iso) return { label: '—', detail: '' }
  const date = new Date(iso)
  const days = Math.round((date.getTime() - Date.now()) / 86400000)
  const exact = date.toLocaleString()
  if (days < 0) return { label: 'expired', detail: exact, tone: 'denied' }
  if (days === 0) return { label: 'today', detail: exact, tone: 'good' }
  return { label: `${days}d left`, detail: exact, tone: 'good' }
}

function TargetList({ targets }) {
  if (!targets?.length) return <span className="muted">—</span>
  return (
    <ul className="grant-targets">
      {targets.map((target) => {
        const type = target.target_type || target.type
        const value = target.target_value || target.value
        return (
          <li key={`${type}:${value}`}>
            <span className="grant-target-type">{type}</span>
            <span className="mono">{value}</span>
          </li>
        )
      })}
    </ul>
  )
}

export default function Grants() {
  const [rows, setRows] = useState(null)
  const [total, setTotal] = useState(0)
  const [catalog, setCatalog] = useState([])
  const [error, setError] = useState('')
  const [filters, setFilters] = useState({
    status: '', principal: '', capability: '', tool: '', target: '', expired: '',
  })
  const [issueOpen, setIssueOpen] = useState(false)
  const [simulateOpen, setSimulateOpen] = useState(false)
  const [revokeGrant, setRevokeGrant] = useState(null)

  useEffect(() => { load() }, [filters])

  useEffect(() => {
    api.get('/api/v1/authorization/capabilities')
      .then((r) => setCatalog(r.data || []))
      .catch(() => setCatalog([]))
  }, [])

  function load() {
    setError('')
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value)
    api.get(`/api/v1/authorization/grants${params.toString() ? '?' + params : ''}`)
      .then((r) => { setRows(r.data || []); setTotal(r.total || 0) })
      .catch((problem) => { setError(String(problem.message || problem)); setRows([]) })
  }

  const capabilities = catalog.length
    ? catalog
    : FALLBACK_CAPABILITIES.map((id) => ({ id, description: '', invasive: false }))
  const activeFilters = Object.values(filters).filter(Boolean).length

  return (
    <div className="stack">
      <PageHeader
        title="Authorization grants"
        subtitle="Who may run a capability against which targets, and until when. Default deny: nothing runs without a grant here, and a scope exclusion always wins."
        actions={(
          <>
            <button className="mini" onClick={() => setSimulateOpen(true)}>check a decision</button>
            <button className="btn-primary mini" onClick={() => setIssueOpen(true)}>issue grant</button>
          </>
        )}
      />

      {error && <div className="banner banner-error">{error}</div>}

      <Card tight>
        <div className="grant-filters">
          <select value={filters.status}
            onChange={(event) => setFilters((f) => ({ ...f, status: event.target.value }))}>
            <option value="">any status</option>
            <option value="active">active</option>
            <option value="revoked">revoked</option>
          </select>
          <input placeholder="principal" value={filters.principal}
            onChange={(event) => setFilters((f) => ({ ...f, principal: event.target.value }))} />
          <select value={filters.capability}
            onChange={(event) => setFilters((f) => ({ ...f, capability: event.target.value }))}>
            <option value="">any capability</option>
            {capabilities.map((cap) => <option key={cap.id} value={cap.id}>{cap.id}</option>)}
          </select>
          <input placeholder="target" value={filters.target}
            onChange={(event) => setFilters((f) => ({ ...f, target: event.target.value }))} />
          <select value={filters.expired}
            onChange={(event) => setFilters((f) => ({ ...f, expired: event.target.value }))}>
            <option value="">any expiry</option>
            <option value="false">still valid</option>
            <option value="true">expired</option>
          </select>
          <input placeholder="tool" value={filters.tool}
            onChange={(event) => setFilters((f) => ({ ...f, tool: event.target.value }))} />
          {activeFilters > 0 && (
            <button className="mini" onClick={() => setFilters({
              status: '', principal: '', capability: '', tool: '', target: '', expired: '',
            })}>
              clear
            </button>
          )}
          <span className="count grant-count">
            {rows === null ? 'loading…' : `${total} grant${total === 1 ? '' : 's'}`}
          </span>
        </div>
      </Card>

      {rows === null && <Card><Loading rows={3} /></Card>}

      {rows !== null && !rows.length && (
        <Card>
          <EmptyState
            title={activeFilters ? 'No grant matches these filters' : 'No grants yet'}
            hint={activeFilters
              ? 'Clear the filters to see the whole ledger.'
              : 'A grant is permission to run one capability against specific targets, for a window. Nothing runs without it.'} />
        </Card>
      )}

      {rows !== null && rows.length > 0 && (
        <Card tight>
          <table className="grants-table">
            <thead>
              <tr>
                <th>principal</th><th>capabilities</th><th>targets</th>
                <th>restrictions</th><th>expires</th><th>status</th><th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((grant) => {
                const when = expiry(grant.valid_until)
                return (
                  <tr key={grant.id} className={grant.status === 'revoked' ? 'muted-row' : ''}>
                    <td className="title">
                      {grant.principal}
                      <div className="grant-just" title={`${grant.justification} — by ${grant.issued_by} · policy v${grant.policy_version}`}>
                        {grant.justification}
                      </div>
                      <div className="grant-restr">
                        by {grant.issued_by}
                        {grant.status === 'revoked' && grant.revoked_by
                          ? ` · revoked by ${grant.revoked_by}` : ''}
                      </div>
                    </td>
                    <td>
                      {(grant.capabilities || []).map((cap) => (
                        <span className="pill" key={cap}
                          title={capabilities.find((entry) => entry.id === cap)?.description || cap}>
                          {cap}
                        </span>
                      ))}
                    </td>
                    <td><TargetList targets={grant.targets} /></td>
                    <td className="muted">
                      {grant.environment || 'any environment'}
                      <div className="grant-restr">
                        {grant.tools?.length ? `tools: ${grant.tools.join(', ')}` : 'any tool'}
                      </div>
                    </td>
                    <td>
                      <span className={`pill ${when.tone || ''}`} title={when.detail}>{when.label}</span>
                    </td>
                    <td><span className={`pill ${grant.status === 'active' ? 'good' : 'denied'}`}>
                      {grant.status}</span></td>
                    <td className="grant-actions">
                      {grant.status === 'active' && (
                        <button className="mini" onClick={() => setRevokeGrant(grant)}>revoke</button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </Card>
      )}

      <IssueDialog open={issueOpen} onClose={() => setIssueOpen(false)}
        catalog={capabilities} onIssued={() => { setIssueOpen(false); load() }} />
      <SimulateDialog open={simulateOpen} onClose={() => setSimulateOpen(false)}
        catalog={capabilities} />
      <RevokeDialog grant={revokeGrant} onClose={() => setRevokeGrant(null)}
        onRevoked={() => { setRevokeGrant(null); load() }} />
    </div>
  )
}

/* ─────────────────────────────── dialogs ─────────────────────────────── */

const CAPABILITY_HINTS = {
  passive_discovery: 'read public data — DNS records, certificates',
  active_verification: 'connect and probe the service',
  vulnerability_analysis: 'run a scanner against the target',
  intrusive_testing: 'attempt exploitation',
}

const WINDOWS = [
  { hours: 24, label: '1 day' },
  { hours: 168, label: '7 days' },
  { hours: 720, label: '30 days' },
]

// The type of a hand-typed target, guessed the way a person writes it. The chip
// shows the guess, so a wrong guess is visible instead of silent.
function guessType(raw) {
  const value = (raw || '').trim()
  if (!value) return 'domain'
  if (value.startsWith('*.')) return 'wildcard_domain'
  if (/^https?:\/\//i.test(value)) return 'url'
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'ip'
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(value)) return 'cidr'
  if (/^[\w.-]+\/[\w.-]+$/.test(value)) return 'repository'
  return 'domain'
}

function IssueDialog({ open, onClose, catalog, onIssued }) {
  const [targets, setTargets] = useState([])
  const [query, setQuery] = useState('')
  const [assets, setAssets] = useState([])
  const [scopeTargets, setScopeTargets] = useState([])
  const [form, setForm] = useState({
    principal: 'console', issued_by: 'console-operator',
    capabilities: ['passive_discovery'], justification: '',
    hours: 168, environment: '', tools: '',
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // Load the picker's sources once, when the dialog opens: the two lists that
  // answer "what do I own?" are assets (declared by hand or discovered) and
  // scope targets (declared patterns, which are not hosts).
  useEffect(() => {
    if (!open) return
    api.get('/api/v1/assets?limit=200')
      .then((r) => setAssets(r.data || []))
      .catch(() => setAssets([]))
    api.get('/api/v1/scope/targets')
      .then((r) => setScopeTargets(r.data || []))
      .catch(() => setScopeTargets([]))
  }, [open])

  const known = useMemo(() => {
    const seen = new Map()
    for (const row of assets) {
      const type = ['domain', 'subdomain'].includes(row.type) ? 'domain' : row.type
      seen.set(`${type}:${row.value}`, { type, value: row.value, hint: row.project || '' })
    }
    for (const row of scopeTargets) {
      // Scope stores a pattern as `domain` with a leading star; a grant needs the
      // wildcard type or it would only ever match the literal string.
      const type = (row.value || '').startsWith('*.')
        ? 'wildcard_domain' : (row.target_type || 'domain')
      seen.set(`${type}:${row.value}`, { type, value: row.value, hint: 'in scope' })
    }
    return [...seen.values()]
  }, [assets, scopeTargets])

  const already = new Set(targets.map((row) => `${row.type}:${row.value}`))
  const suggestions = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return known
      .filter((row) => !already.has(`${row.type}:${row.value}`))
      .filter((row) => !needle || row.value.toLowerCase().includes(needle))
      .slice(0, 6)
  }, [known, query, targets])

  function addTarget(row) {
    if (!row.value.trim()) return
    setTargets((current) => (current.some((t) => t.type === row.type && t.value === row.value)
      ? current : [...current, { type: row.type, value: row.value.trim() }]))
    setQuery('')
    setError('')
  }

  function removeTarget(index) {
    setTargets((current) => current.filter((_, at) => at !== index))
  }

  function toggleCapability(id) {
    setForm((current) => ({
      ...current,
      capabilities: current.capabilities.includes(id)
        ? current.capabilities.filter((cap) => cap !== id)
        : [...current.capabilities, id],
    }))
    setError('')
  }

  function submit() {
    if (!targets.length) {
      setError('Pick a target above — a grant with no target permits nothing.')
      return false
    }
    if (!form.capabilities.length) {
      setError('Choose at least one capability.')
      return false
    }
    if (form.principal.trim().length < 2) {
      setError('Name who runs it (the principal the collector will act as).')
      return false
    }
    if (form.issued_by.trim().length < 2) {
      setError('Name who issues it. Invasive capabilities cannot be self-authorized.')
      return false
    }
    const hours = Number(form.hours)
    if (!Number.isFinite(hours) || hours < 1 || hours > 8760) {
      setError('The window has to be between 1 and 8760 hours.')
      return false
    }
    if (form.justification.trim().length < 4) {
      setError('Write why — the audit trail keeps this sentence.')
      return false
    }
    issue()
    return false
  }

  async function issue() {
    setBusy(true)
    setError('')
    try {
      await api.post('/api/v1/authorization/grants', {
        principal: form.principal.trim(),
        capabilities: form.capabilities,
        targets,
        issued_by: form.issued_by.trim(),
        justification: form.justification.trim(),
        hours: Number(form.hours) || 168,
        environment: form.environment.trim() || undefined,
        tools: form.tools.trim()
          ? form.tools.split(',').map((tool) => tool.trim()).filter(Boolean)
          : undefined,
      })
      setTargets([])
      setQuery('')
      setForm((current) => ({ ...current, justification: '' }))
      onIssued()
    } catch (problem) {
      setError(String(problem.message || problem))
    } finally { setBusy(false) }
  }

  const windowLabel = humanWindow(form.hours)

  return (
    <Dialog open={open} title="Issue a grant" size="wide"
      onClose={() => { if (!busy) onClose() }} onConfirm={submit}
      confirmLabel={busy ? 'issuing…' : 'issue grant'}>
      <div className="release-form">
        <fieldset className="release-group">
          <legend>Targets</legend>
          <div className="grant-picker-wrap">
          <div className="grant-picker">
            <input value={query} placeholder="search your assets, or type a value"
              aria-label="search or type a target"
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key !== 'Enter') return
                event.preventDefault()
                const first = suggestions[0]
                addTarget(first || { type: guessType(query), value: query })
              }} />
            {query.trim() && !suggestions.some(
              (row) => row.value.toLowerCase() === query.trim().toLowerCase()) && (
              <button type="button" className="mini"
                onClick={() => addTarget({ type: guessType(query), value: query })}>
                add “{query.trim()}” as {guessType(query)}
              </button>
            )}
          </div>
          {query.trim() && suggestions.length > 0 && (
            <ul className="grant-suggestions" aria-label="matching targets">
              <li className="grant-suggestions-head">matching targets</li>
              {suggestions.map((row) => (
                <li key={`${row.type}:${row.value}`}>
                  <button type="button" onClick={() => addTarget(row)}>
                    <span className="grant-target-type">{row.type}</span>
                    <span className="mono">{row.value}</span>
                    {row.hint ? <span className="grant-source">{row.hint}</span> : null}
                  </button>
                </li>
              ))}
            </ul>
          )}
          </div>
          {targets.length > 0 ? (
            <ul className="grant-chips">
              {targets.map((row, index) => (
                <li key={`${row.type}:${row.value}`} className="grant-chip">
                  <span className="grant-target-type">{row.type}</span>
                  <span className="mono">{row.value}</span>
                  <button type="button" aria-label={`remove ${row.value}`}
                    onClick={() => removeTarget(index)}>×</button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted release-hint">
              Pick from the list or type one and press Enter. Patterns work:
              <span className="mono"> *.example.com</span>, and repositories as
              <span className="mono"> owner/name</span>.
            </p>
          )}
        </fieldset>

        <fieldset className="release-group">
          <legend>Capabilities</legend>
          <div className="grant-capabilities">
            {catalog.map((cap) => (
              <label className="row release-check" key={cap.id}
                title={cap.description || CAPABILITY_HINTS[cap.id] || ''}>
                <input type="checkbox" checked={form.capabilities.includes(cap.id)}
                  onChange={() => toggleCapability(cap.id)} />
                <span>{cap.id}</span>
                {cap.invasive ? <span className="pill denied">invasive</span> : null}
                <span className="muted grant-hint">
                  {CAPABILITY_HINTS[cap.id] || cap.description}
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset className="release-group">
          <legend>Who, and for how long</legend>
          <div className="release-row">
            <label className="field">
              <span>principal (who runs it)</span>
              <input value={form.principal}
                onChange={(event) => setForm((f) => ({ ...f, principal: event.target.value }))} />
            </label>
            <label className="field">
              <span>issued by</span>
              <input value={form.issued_by}
                onChange={(event) => setForm((f) => ({ ...f, issued_by: event.target.value }))} />
            </label>
          </div>
          <div className="row grant-windows">
            {WINDOWS.map((option) => (
              <button type="button" key={option.hours}
                className={`mini ${Number(form.hours) === option.hours ? 'on' : ''}`}
                onClick={() => setForm((f) => ({ ...f, hours: option.hours }))}>
                {option.label}
              </button>
            ))}
            <span className="muted grant-or">or</span>
            <label className="grant-hours">
              <input type="number" min="1" max="8760" value={form.hours}
                aria-label="window in hours"
                onChange={(event) => setForm((f) => ({ ...f, hours: event.target.value }))} />
              <span className="muted">hours</span>
            </label>
            {!WINDOWS.some((option) => Number(form.hours) === option.hours) && (
              <span className="muted grant-hint">= {windowLabel}</span>
            )}
          </div>
          <div className="release-row">
            <label className="field">
              <span>environment (optional)</span>
              <input value={form.environment} placeholder="production"
                onChange={(event) => setForm((f) => ({ ...f, environment: event.target.value }))} />
            </label>
            <label className="field">
              <span>tools (optional, comma separated)</span>
              <input value={form.tools} placeholder="dns-collector, tls-probe"
                onChange={(event) => setForm((f) => ({ ...f, tools: event.target.value }))} />
            </label>
          </div>
          <label className="field">
            <span>justification (audited)</span>
            <input value={form.justification}
              placeholder="why this target and this window"
              onChange={(event) => {
                setForm((f) => ({ ...f, justification: event.target.value }))
                setError('')
              }} />
          </label>
        </fieldset>

        <p className="grant-summary">
          <strong>{form.principal.trim() || 'nobody'}</strong> may run{' '}
          <strong>{form.capabilities.length
            ? form.capabilities.map((cap) => cap.replace(/_/g, ' ')).join(' + ')
            : 'nothing'}</strong>{' '}
          against <strong>{targets.length || 'no'} target{targets.length === 1 ? '' : 's'}</strong>{' '}
          for <strong>{windowLabel}</strong>, issued by <strong>{form.issued_by.trim() || 'nobody'}</strong>.
          {form.capabilities.some((cap) => catalog.find((entry) => entry.id === cap)?.invasive)
            && form.principal.trim() === form.issued_by.trim()
            ? ' Invasive capabilities cannot be self-authorized: the backend will refuse this.'
            : ''}
        </p>

        {error && <p role="alert" className="release-error">{error}</p>}
      </div>
    </Dialog>
  )
}

function SimulateDialog({ open, onClose, catalog }) {
  const [form, setForm] = useState({
    principal: 'console', capability: 'passive_discovery',
    type: 'domain', value: '', tool: '', environment: '',
  })
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  async function simulate() {
    if (!form.value.trim()) { setError('Give a target value to evaluate.'); return false }
    setError('')
    try {
      const body = {
        principal: form.principal.trim() || 'console',
        capability: form.capability,
        targets: [{ type: form.type, value: form.value.trim() }],
      }
      if (form.tool.trim()) body.tool = form.tool.trim()
      if (form.environment.trim()) body.environment = form.environment.trim()
      setResult(await api.post('/api/v1/authorization/authorize', body))
    } catch (problem) {
      setError(String(problem.message || problem))
    }
    return false
  }

  return (
    <Dialog open={open} title="Check a decision" size="wide"
      onClose={onClose} onConfirm={simulate} confirmLabel="evaluate">
      <div className="release-form">
        <p className="muted release-hint">
          One question, nothing touched: may this principal run this capability against
          this target, with this tool and environment? The same engine the collectors call.
        </p>
        <div className="release-row">
          <label className="field">
            <span>principal</span>
            <input value={form.principal}
              onChange={(event) => setForm((f) => ({ ...f, principal: event.target.value }))} />
          </label>
          <label className="field">
            <span>capability</span>
            <select value={form.capability}
              onChange={(event) => setForm((f) => ({ ...f, capability: event.target.value }))}>
              {catalog.map((cap) => <option key={cap.id} value={cap.id}>{cap.id}</option>)}
            </select>
          </label>
        </div>
        <div className="release-row">
          <label className="field">
            <span>target type</span>
            <select value={form.type}
              onChange={(event) => setForm((f) => ({ ...f, type: event.target.value }))}>
              {TARGET_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
            </select>
          </label>
          <label className="field">
            <span>value</span>
            <input value={form.value} placeholder="api.example.com"
              onChange={(event) => setForm((f) => ({ ...f, value: event.target.value }))} />
          </label>
        </div>
        <div className="release-row">
          <label className="field">
            <span>tool (optional)</span>
            <input value={form.tool} placeholder="dns-collector"
              onChange={(event) => setForm((f) => ({ ...f, tool: event.target.value }))} />
          </label>
          <label className="field">
            <span>environment (optional)</span>
            <input value={form.environment} placeholder="production"
              onChange={(event) => setForm((f) => ({ ...f, environment: event.target.value }))} />
          </label>
        </div>
        {result && result.decision && (
          <div className="grant-verdict">
            <span className={`pill ${result.decision === 'allow' ? 'good' : 'denied'}`}>
              {result.decision}
            </span>
            <p className="muted">{result.reason}</p>
            <p className="muted grant-restr">
              policy v{result.policy_version} · evaluated {result.evaluated_at}
            </p>
          </div>
        )}
        {error && <p role="alert" className="release-error">{error}</p>}
      </div>
    </Dialog>
  )
}

function RevokeDialog({ grant, onClose, onRevoked }) {
  const [reason, setReason] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit() {
    if (reason.trim().length < 4) {
      setError('A reason is required: revocation is audited.')
      return false
    }
    setBusy(true)
    try {
      await api.post(`/api/v1/authorization/grants/${grant.id}/revoke`,
        { reason: reason.trim(), actor: 'console' })
      setReason('')
      onRevoked()
    } catch (problem) {
      setError(String(problem.message || problem))
    } finally { setBusy(false) }
    return false
  }

  return (
    <Dialog open={Boolean(grant)} title="Revoke grant"
      onClose={onClose} onConfirm={submit} destructive
      confirmLabel={busy ? 'revoking…' : 'revoke'}>
      <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
        {grant?.principal} loses {grant?.capabilities?.join(' + ')} immediately. The grant
        stays in the ledger as revoked, with who revoked it and why.
      </p>
      <label className="field" style={{ marginTop: 10 }}>
        <span>reason (audited)</span>
        <input value={reason}
          onChange={(event) => { setReason(event.target.value); setError('') }} />
      </label>
      {error && <p role="alert" className="release-error">{error}</p>}
    </Dialog>
  )
}
