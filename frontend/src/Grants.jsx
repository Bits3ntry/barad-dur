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

function parseTargets(text) {
  return text.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const [type, ...rest] = line.split('=')
    return { type: (type || '').trim(), value: rest.join('=').trim() }
  }).filter((target) => target.type && target.value)
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

function IssueDialog({ open, onClose, catalog, onIssued }) {
  const [form, setForm] = useState({
    principal: 'console', issued_by: 'console-operator',
    capabilities: ['passive_discovery'], targets: '', justification: '',
    hours: 168, environment: '', tools: '',
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const parsed = useMemo(() => parseTargets(form.targets), [form.targets])

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
    if (!form.capabilities.length) {
      setError('Choose at least one capability — a grant with none permits nothing.')
      return false
    }
    if (!parsed.length) {
      setError('Declare at least one target, one per line: type=value.')
      return false
    }
    if (form.principal.trim().length < 2 || form.issued_by.trim().length < 2) {
      setError('Name who runs it and who issues it.')
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
        targets: parsed.map((target) => ({ type: target.type, value: target.value })),
        issued_by: form.issued_by.trim(),
        justification: form.justification.trim(),
        hours: Number(form.hours) || 168,
        environment: form.environment.trim() || undefined,
        tools: form.tools.trim()
          ? form.tools.split(',').map((tool) => tool.trim()).filter(Boolean)
          : undefined,
      })
      setForm((current) => ({ ...current, targets: '', justification: '' }))
      onIssued()
    } catch (problem) {
      setError(String(problem.message || problem))
    } finally { setBusy(false) }
  }

  return (
    <Dialog open={open} title="Issue a grant" size="wide"
      onClose={() => { if (!busy) onClose() }} onConfirm={submit}
      confirmLabel={busy ? 'issuing…' : 'issue grant'}>
      <div className="release-form">
        <fieldset className="release-group">
          <legend>Capabilities</legend>
          <p className="muted release-hint">
            What the holder may do. Invasive capabilities cannot be self-authorized: the
            issuer must differ from the principal.
          </p>
          <div className="grant-capabilities">
            {catalog.map((cap) => (
              <label className="row release-check" key={cap.id} title={cap.description}>
                <input type="checkbox" checked={form.capabilities.includes(cap.id)}
                  onChange={() => toggleCapability(cap.id)} />
                {cap.id}
                {cap.invasive ? <span className="pill denied">invasive</span> : null}
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset className="release-group">
          <legend>Targets</legend>
          <label className="field">
            <span>one per line: type=value</span>
            <textarea rows="3" value={form.targets}
              placeholder={'domain=api.example.com\nrepository=bitsentry/aurea-server'}
              onChange={(event) => {
                setForm((f) => ({ ...f, targets: event.target.value }))
                setError('')
              }} />
          </label>
          <p className="muted release-hint">
            {parsed.length
              ? `${parsed.length} target${parsed.length === 1 ? '' : 's'}`
              : 'Types: domain, wildcard_domain, ip, cidr, url, repository, service, endpoint.'}
          </p>
        </fieldset>

        <fieldset className="release-group">
          <legend>Who and how long</legend>
          <div className="release-row">
            <label className="field">
              <span>principal (who runs)</span>
              <input value={form.principal}
                onChange={(event) => setForm((f) => ({ ...f, principal: event.target.value }))} />
            </label>
            <label className="field">
              <span>issued by</span>
              <input value={form.issued_by}
                onChange={(event) => setForm((f) => ({ ...f, issued_by: event.target.value }))} />
            </label>
            <label className="field">
              <span>valid for (hours)</span>
              <input type="number" min="1" max="8760" value={form.hours}
                onChange={(event) => setForm((f) => ({ ...f, hours: event.target.value }))} />
            </label>
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
          <p className="muted release-hint">Window: {humanWindow(form.hours)}</p>
          <label className="field">
            <span>justification (audited)</span>
            <input value={form.justification}
              placeholder="why this range and this window"
              onChange={(event) => {
                setForm((f) => ({ ...f, justification: event.target.value }))
                setError('')
              }} />
          </label>
        </fieldset>

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
