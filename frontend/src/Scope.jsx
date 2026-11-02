import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Banner, CheckBox, Dialog, EmptyState, ErrorBanner, Input, PageHeader, Select,
  Table, Tabs,
} from './ui'

/* Scope is a declaration screen, not an inventory: it lists only what somebody
   wrote down. A `*.example.com` row is a rule and never becomes a host, which is
   why patterns show as patterns and concrete rows show the asset they linked. */

const TYPES = [
  { value: 'domain', label: 'domain (exact or *.pattern)' },
  { value: 'url', label: 'url (origin + path prefix)' },
  { value: 'ip', label: 'ip' },
  { value: 'cidr', label: 'cidr' },
  { value: 'repository', label: 'repository (owner/name)' },
  { value: 'service', label: 'service' },
  { value: 'api', label: 'api' },
  { value: 'cloud_account', label: 'cloud account (declarative only)' },
]

const CAPABILITIES = [
  { value: 'passive_discovery', label: 'passive discovery' },
  { value: 'active_verification', label: 'active verification' },
  { value: 'code_analysis', label: 'code analysis' },
]

const EMPTY = {
  target_type: 'domain', value: '', reason: '', owner: '', valid_until: '',
  capabilities: ['passive_discovery'], include_apex: false, note: '',
}

export default function Scope() {
  const [tab, setTab] = useState('targets')
  const [targets, setTargets] = useState([])
  const [exclusions, setExclusions] = useState([])
  const [form, setForm] = useState({ ...EMPTY })
  const [creating, setCreating] = useState(false)
  const [exclusionForm, setExclusionForm] = useState({ target_type: 'domain', value: '', reason: '' })
  const [exclusionOpen, setExclusionOpen] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [principal, setPrincipal] = useState(
    () => localStorage.getItem('barad.principal') || 'console')
  const [checkValue, setCheckValue] = useState('')
  const [checkType, setCheckType] = useState('')
  const [checkCapability, setCheckCapability] = useState('passive_discovery')
  const [decision, setDecision] = useState(null)

  useEffect(() => { load() }, [])

  function chooseTargetType(value) {
    const capabilities = value === 'cloud_account'
      ? []
      : value === 'repository' ? ['code_analysis'] : ['passive_discovery']
    setForm((state) => ({ ...state, target_type: value, capabilities }))
  }

  function chooseExclusionType(value) {
    setExclusionForm((state) => ({ ...state, target_type: value }))
  }

  function load() {
    api.get('/api/v1/scope/targets').then((r) => setTargets(r.data || []))
      .catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/scope/exclusions').then((r) => setExclusions(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  async function createTarget() {
    setError('')
    try {
      const result = await api.post('/api/v1/scope/targets', {
        target_type: form.target_type,
        value: form.value.trim(),
        reason: form.reason || null,
        owner: form.owner || null,
        note: form.note || null,
        capabilities: form.target_type === 'cloud_account' ? [] : form.capabilities,
        include_apex: form.include_apex,
        valid_until: form.valid_until ? `${form.valid_until}T00:00:00+00:00` : null,
        actor: principal,
      })
      setCreating(false)
      setForm({ ...EMPTY })
      setNotice(result.already_known
        ? 'that target was already declared; nothing duplicated'
        : `declared ${result.data.target_type} ${result.data.value}`
          + (result.data.asset ? ` · linked asset ${result.data.asset.value}` : ' · rule only, no host created'))
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function patchTarget(row, body, label) {
    try {
      await api.patch(`/api/v1/scope/targets/${row.id}`, { ...body, actor: principal })
      setNotice(`updated ${row.value}: ${label}`)
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function createExclusion() {
    if (!exclusionForm.value.trim() || !exclusionForm.reason.trim()) return
    try {
      await api.post('/api/v1/scope/exclusions', {
        ...exclusionForm, value: exclusionForm.value.trim(), actor: principal,
      })
      setExclusionOpen(false)
      setExclusionForm({ target_type: 'domain', value: '', reason: '' })
      setNotice('exclusion added; it wins over any target that covers it')
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function runCheck() {
    setDecision(null)
    setError('')
    try {
      const result = await api.post('/api/v1/scope/check', {
        value: checkValue.trim(),
        target_type: checkType || null,
        capability: checkCapability || null,
      })
      setDecision(result.data)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const patternCount = targets.filter((row) => row.is_pattern).length
  const activeCount = targets.filter((row) => row.status === 'active').length

  return (
    <div className="stack">
      <PageHeader
        title="Scope"
        subtitle={`${targets.length} declared · ${activeCount} active · ${patternCount} pattern rule${patternCount === 1 ? '' : 's'} · exclusions always win`}
        actions={<>
          <button className="mini" onClick={() => setExclusionOpen(true)}>add exclusion</button>
          {' '}
          <button className="primary-action" onClick={() => setCreating(true)}>declare target</button>
        </>}
      />

      <Banner kind="info">
        A scope row is a declaration. It never runs a scan, and it never grants an
        authorization on its own — collectors still check a scan grant. A
        <span className="mono"> *.domain </span>
        rule covers subdomains at any depth and excludes the apex unless you tick it.
      </Banner>

      <Tabs
        tabs={[
          { id: 'targets', label: 'Targets' },
          { id: 'exclusions', label: `Exclusions (${exclusions.length})` },
          { id: 'check', label: 'Check a value' },
        ]}
        active={tab}
        onChange={setTab}
      />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {tab === 'targets' && (
        targets.length ? (
          <Table head={['type', 'value', 'capabilities', 'owner · reason', 'validity', 'asset', '']}>
            {targets.map((row) => (
              <tr key={row.id}>
                <td><span className="pill">{row.target_type}</span></td>
                <td className="title mono">
                  {row.value}
                  {row.is_pattern && <span className="pill" style={{ marginLeft: 6 }}>rule</span>}
                  {row.is_pattern && row.include_apex && (
                    <div className="muted" style={{ fontSize: 11.5 }}>includes the apex</div>
                  )}
                </td>
                <td>
                  {(row.capabilities || []).length
                    ? row.capabilities.map((c) => <span key={c} className="pill">{c}</span>)
                    : <span className="muted">none — declares nothing actionable</span>}
                </td>
                <td>
                  <div className="stack" style={{ gap: 2 }}>
                    <span className={row.owner ? '' : 'muted'}>{row.owner || 'no owner'}</span>
                    <span className="muted" style={{ fontSize: 11.5 }}>
                      {row.reason || 'no reason recorded'}
                    </span>
                  </div>
                </td>
                <td>
                  <span className={row.status === 'active' ? 'pill' : 'sev sev-medium'}>
                    {row.status}
                  </span>
                  {row.valid_until && (
                    <div className="muted" style={{ fontSize: 11.5 }}>
                      until {new Date(row.valid_until).toLocaleDateString()}
                    </div>
                  )}
                </td>
                <td>
                  {row.asset
                    ? <span className="mono">{row.asset.value}</span>
                    : <span className="muted">—</span>}
                </td>
                <td>
                  <div className="row">
                    <button className="mini" onClick={() => patchTarget(
                      row, { status: row.status === 'active' ? 'disabled' : 'active' },
                      row.status === 'active' ? 'disabled' : 're-enabled')}>
                      {row.status === 'active' ? 'disable' : 'enable'}
                    </button>
                    <button className="mini" onClick={() => patchTarget(
                      row,
                      { capabilities: row.capabilities.includes('active_verification')
                        ? row.capabilities.filter((c) => c !== 'active_verification')
                        : [...row.capabilities, 'active_verification'] },
                      'active capability toggled')}>
                      {row.capabilities.includes('active_verification')
                        ? 'drop active' : 'allow active'}
                    </button>
                    {row.is_pattern && (
                      <button className="mini" onClick={() => patchTarget(
                        row, { include_apex: !row.include_apex },
                        `apex ${row.include_apex ? 'excluded' : 'included'}`)}>
                        {row.include_apex ? 'exclude apex' : 'include apex'}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          !error && <EmptyState title="Nothing declared yet"
            hint="Declare the domains, IP ranges and repositories the organization owns. Until you do, the honest answer to “may I test this?” is no." />
        )
      )}

      {tab === 'exclusions' && (
        exclusions.length ? (
          <Table head={['type', 'value', 'reason', 'expires', 'status', '']}>
            {exclusions.map((row) => (
              <tr key={row.id}>
                <td><span className="pill">{row.target_type}</span></td>
                <td className="title mono">{row.value}</td>
                <td className="muted">{row.reason}</td>
                <td className="muted">
                  {row.expires_at ? new Date(row.expires_at).toLocaleDateString() : 'no expiry'}
                </td>
                <td>
                  <span className={row.status === 'active' ? 'pill' : 'sev sev-medium'}>
                    {row.status}
                  </span>
                </td>
                <td>
                  <button className="mini" onClick={async () => {
                    try {
                      await api.patch(`/api/v1/scope/exclusions/${row.id}`, {
                        status: row.status === 'active' ? 'disabled' : 'active',
                        actor: principal,
                      })
                      load()
                    } catch (e) { setError(String(e.message || e)) }
                  }}>
                    {row.status === 'active' ? 'disable' : 'enable'}
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          !error && <EmptyState title="No exclusions"
            hint="Exclusions cover a value or a pattern and always beat a target that would include it." />
        )
      )}

      {tab === 'check' && (
        <>
          <div className="toolbar">
            <input placeholder="value, e.g. api-aurea.bitsentry.xyz" value={checkValue}
              onChange={(e) => setCheckValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runCheck()} />
            <select value={checkType} onChange={(e) => setCheckType(e.target.value)}>
              <option value="">detect type</option>
              {TYPES.map((t) => <option key={t.value} value={t.value}>{t.value}</option>)}
            </select>
            <select value={checkCapability} onChange={(e) => setCheckCapability(e.target.value)}>
              <option value="">any capability</option>
              {CAPABILITIES.map((c) => (
                <option key={c.value} value={c.value}>{c.label}</option>
              ))}
            </select>
            <button onClick={runCheck}>check</button>
          </div>
          {decision && (
            <Banner kind={decision.allowed ? 'ok' : 'error'}>
              <strong>{decision.allowed ? 'covered' : 'denied'}</strong> — {decision.reason}.
              {' '}
              {decision.matched_rule && (
                <span className="mono">
                  rule {decision.matched_rule.type}:{decision.matched_rule.value}
                </span>
              )}
              {decision.excluded_by && (
                <span className="mono"> exclusion {decision.excluded_by.value}</span>
              )}
              {decision.capabilities.length > 0 && (
                <span className="muted"> · permits {decision.capabilities.join(', ')}</span>
              )}
            </Banner>
          )}
          <p className="muted">
            This answers a declaration question only. Running anything still needs a
            scan grant for the acting principal.
          </p>
        </>
      )}

      <Dialog open={creating} title="Declare a scope target"
        onClose={() => setCreating(false)} onConfirm={createTarget} confirmLabel="declare">
        <div className="stack">
          <Select label="type" value={form.target_type}
            options={TYPES.map((t) => ({ value: t.value, label: t.label }))}
            onChange={chooseTargetType} />
          <Input label="value" value={form.value}
            placeholder={form.target_type === 'domain' ? '*.bitsentry.xyz' : 'value'}
            hint={form.target_type === 'cloud_account'
              ? 'declarative only: it authorizes no provider address'
              : form.target_type === 'url' ? 'https://host/path — no query or fragment'
                : null}
            onChange={(value) => setForm((s) => ({ ...s, value }))} />
          <Input label="reason" value={form.reason} placeholder="why this is in bounds"
            onChange={(value) => setForm((s) => ({ ...s, reason: value }))} />
          <Input label="owner" value={form.owner} placeholder="email or principal"
            onChange={(value) => setForm((s) => ({ ...s, owner: value }))} />
          <Input label="valid until" type="date" value={form.valid_until}
            hint="leave empty for no expiry"
            onChange={(value) => setForm((s) => ({ ...s, valid_until: value }))} />
          {form.target_type === 'domain' && form.value.trim().startsWith('*.') && (
            <CheckBox label="also cover the apex domain" checked={form.include_apex}
              onChange={(checked) => setForm((s) => ({ ...s, include_apex: checked }))} />
          )}
          {form.target_type !== 'cloud_account' && (
            <div className="field">
              <label className="field-label">capabilities</label>
              {CAPABILITIES.map((c) => (
                <CheckBox key={c.value} label={c.label}
                  checked={form.capabilities.includes(c.value)}
                  onChange={(checked) => setForm((s) => ({
                    ...s,
                    capabilities: checked
                      ? [...s.capabilities, c.value]
                      : s.capabilities.filter((x) => x !== c.value),
                  }))} />
              ))}
              <span className="muted">
                Recording a capability runs nothing; a scan grant is still required.
              </span>
            </div>
          )}
        </div>
      </Dialog>

      <Dialog open={exclusionOpen} title="Add a scope exclusion"
        onClose={() => setExclusionOpen(false)} onConfirm={createExclusion} confirmLabel="exclude">
        <div className="stack">
          <Select label="type" value={exclusionForm.target_type}
            options={TYPES.map((t) => ({ value: t.value, label: t.label }))}
            onChange={chooseExclusionType} />
          <Input label="value" value={exclusionForm.value}
            onChange={(value) => setExclusionForm((s) => ({ ...s, value }))} />
          <Input label="reason (required)" value={exclusionForm.reason}
            onChange={(value) => setExclusionForm((s) => ({ ...s, reason: value }))} />
          <span className="muted">
            Excluding keeps the inventory and does not resolve findings.
          </span>
        </div>
      </Dialog>
    </div>
  )
}
