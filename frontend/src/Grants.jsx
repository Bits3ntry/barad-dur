import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, Dialog, EmptyState, Loading, Pager, PageHeader, usePage } from './ui'
import { useI18n } from './i18n'

/* Authorization grants: the ledger of "who may run what, against which targets,
   until when". It is a record first — issuing and simulating are two deliberate
   actions behind buttons, not three forms stacked on the reading surface. */

const TARGET_TYPES = ['domain', 'wildcard_domain', 'ip', 'cidr', 'url',
  'repository', 'service', 'endpoint']
const FALLBACK_CAPABILITIES = ['passive_discovery', 'active_verification',
  'vulnerability_analysis', 'intrusive_testing']
const PER_PAGE = 25

function humanWindow(hours, t, tCount) {
  const value = Number(hours)
  if (!Number.isFinite(value) || value <= 0) return t('grants.window.none')
  if (value < 48) return tCount('grants.window.hours', value)
  const days = value / 24
  return tCount('grants.window.days', Number.isInteger(days) ? days : Number(days.toFixed(1)))
}

function expiry(iso, { t, tCount, date }) {
  if (!iso) return { label: '—', detail: '' }
  const at = new Date(iso)
  const days = Math.round((at.getTime() - Date.now()) / 86400000)
  const exact = date(at)
  if (days < 0) return { label: t('grants.expiry.expired'), detail: exact, tone: 'denied' }
  if (days === 0) return { label: t('grants.expiry.today'), detail: exact, tone: 'good' }
  return { label: tCount('grants.expiry.daysLeft', days), detail: exact, tone: 'good' }
}

// A target type is read, not decoded: `wildcard_domain` in front of `*.x.com`
// is the same word twice, and `domain` on a hostname says nothing.
const TARGET_LABEL_KEY = {
  domain: 'grants.target.host', wildcard_domain: 'grants.target.pattern',
  ip: 'grants.target.ip', cidr: 'grants.target.range',
  url: 'grants.target.url', repository: 'grants.target.repo',
  service: 'grants.target.service', endpoint: 'grants.target.endpoint',
}

function targetLabel(t, type) {
  const key = TARGET_LABEL_KEY[type]
  return key ? t(key) : type
}

/* A request created by declaring a host stores its justification as English
   prose ("declared with domain x: ask for a simple scan"). It is *data* — the
   row is audited as written — but it is also the only sentence in the list, so
   the screen composes the same statement in the reader's language when the text
   is exactly that generated shape. Anything a person typed is printed verbatim. */
const DECLARATION = /^declared with (\w+) (.+?): ask for an? (\w+) scan\.?$/i

function justification(grant, t, tOr) {
  const match = DECLARATION.exec(grant.justification || '')
  if (!match) return grant.justification
  const [, type, value, level] = match
  return t('grants.row.declared', {
    type: targetLabel(t, type),
    value,
    level: tOr(`grants.level.${level}`, level),
  })
}

function TargetList({ targets }) {
  const { t } = useI18n()
  if (!targets?.length) return <span className="muted">—</span>
  return (
    <ul className="grant-targets">
      {targets.map((target) => {
        const type = target.target_type || target.type
        const value = target.target_value || target.value
        return (
          <li key={`${type}:${value}`}>
            <span className="grant-target-type">{targetLabel(t, type)}</span>
            <span className="mono">{value}</span>
          </li>
        )
      })}
    </ul>
  )
}

export default function Grants() {
  const { t, tOr, tCount, date } = useI18n()
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
  // Declaring a domain opens a request; this is the only place it is answered.
  const [requests, setRequests] = useState([])
  const [levels, setLevels] = useState([])
  const [review, setReview] = useState(null)
  const [rejecting, setRejecting] = useState(null)
  const [reviewError, setReviewError] = useState('')
  const [reviewNotice, setReviewNotice] = useState('')

  // The endpoint answers with the whole filtered ledger, so paging is a reading
  // aid: the filters above decide what the list holds, this decides how much of
  // it is on screen.
  const paged = usePage(rows || [], PER_PAGE)

  useEffect(() => {
    // A new filter is a new list: landing halfway down it would hide the newest
    // grants the filter was asked for.
    paged.setPage(0)
    load()
  }, [filters])

  useEffect(() => {
    api.get('/api/v1/authorization/capabilities')
      .then((r) => setCatalog(r.data || []))
      .catch(() => setCatalog([]))
    api.get('/api/v1/authorization/levels')
      .then((r) => setLevels(r.data || []))
      .catch(() => setLevels([]))
    loadRequests()
  }, [])

  function loadRequests() {
    api.get('/api/v1/authorization/grants?status=requested')
      .then((r) => setRequests(r.data || []))
      .catch(() => setRequests([]))
  }

  async function rejectRequest(grant, reason) {
    setReviewError('')
    try {
      await api.post(`/api/v1/authorization/grants/${grant.id}/reject`,
        { reason, actor: 'console' })
      setRejecting(null)
      setReviewNotice(t('grants.review.rejected', {
        targets: grant.targets.map((target) => target.value).join(', '),
      }))
      loadRequests(); load()
    } catch (problem) {
      setReviewError(String(problem.message || problem))
    }
  }

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
        title={t('grants.title')}
        subtitle={t('grants.subtitle')}
        actions={(
          <>
            <button className="mini" onClick={() => setSimulateOpen(true)}>
              {t('grants.action.checkDecision')}
            </button>
            <button className="btn-primary mini" onClick={() => setIssueOpen(true)}>
              {t('grants.action.issue')}
            </button>
          </>
        )}
      />

      {error && <div className="banner banner-error">{error}</div>}
      {reviewError && <div className="banner banner-error">{reviewError}</div>}
      {reviewNotice && <div className="banner banner-ok">{reviewNotice}</div>}

      {/* Requests first: the only thing on this screen that is waiting for a
          decision. The ledger below is a record, and a record never asks. */}
      {requests.length > 0 && (
        <Card tight>
          <div className="grant-caption is-request">
            <strong>{tCount('grants.requests.waiting', requests.length)}</strong>
            <span className="muted">{t('grants.requests.help')}</span>
          </div>
          <ul className="grant-list">
            {requests.map((grant) => (
              <li className="grant-row is-request" key={grant.id}>
                <div className="grant-who">
                  <div className="grant-principal">
                    <strong>{grant.requested_by || grant.issued_by}</strong>
                    <span className="pill">{grant.level || 'simple'}</span>
                  </div>
                  <div className="grant-meta">
                    {date(grant.created_at || grant.valid_from)}
                    {' · '}
                    {grant.asset?.project
                      ? t('grants.requests.project', { project: grant.asset.project })
                      : t('grants.requests.standalone')}
                  </div>
                </div>
                <div className="grant-scope">
                  <TargetList targets={grant.targets} />
                  <div className="grant-meta">{justification(grant, t, tOr)}</div>
                </div>
                <div className="grant-state">
                  <button className="mini" onClick={() => {
                    setReviewError(''); setRejecting(grant)
                  }}>{t('grants.action.reject')}</button>
                  <button className="mini btn-primary" onClick={() => setReview(grant)}>
                    {t('grants.action.reviewApprove')}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <div className="toolbar grant-filters">
        <input placeholder={t('grants.filter.principal')} value={filters.principal}
          onChange={(event) => setFilters((f) => ({ ...f, principal: event.target.value }))} />
        <input placeholder={t('grants.filter.target')} value={filters.target}
          onChange={(event) => setFilters((f) => ({ ...f, target: event.target.value }))} />
        <select value={filters.status}
          onChange={(event) => setFilters((f) => ({ ...f, status: event.target.value }))}>
          <option value="">{t('grants.filter.anyStatus')}</option>
          <option value="active">{t('grants.status.active')}</option>
          <option value="requested">{t('grants.status.requested')}</option>
          <option value="rejected">{t('grants.status.rejected')}</option>
          <option value="revoked">{t('grants.status.revoked')}</option>
        </select>
        <select value={filters.capability}
          onChange={(event) => setFilters((f) => ({ ...f, capability: event.target.value }))}>
          <option value="">{t('grants.filter.anyCapability')}</option>
          {capabilities.map((cap) => <option key={cap.id} value={cap.id}>{cap.id}</option>)}
        </select>
        <select value={filters.expired}
          onChange={(event) => setFilters((f) => ({ ...f, expired: event.target.value }))}>
          <option value="">{t('grants.filter.anyExpiry')}</option>
          <option value="false">{t('grants.filter.stillValid')}</option>
          <option value="true">{t('grants.filter.expired')}</option>
        </select>
        <input placeholder={t('grants.filter.tool')} value={filters.tool}
          onChange={(event) => setFilters((f) => ({ ...f, tool: event.target.value }))} />
        {activeFilters > 0 && (
          <button className="mini" onClick={() => setFilters({
            status: '', principal: '', capability: '', tool: '', target: '', expired: '',
          })}>
            {t('grants.filter.clear', { n: activeFilters })}
          </button>
        )}
      </div>

      {rows === null && <Card><Loading rows={3} /></Card>}

      {rows !== null && !rows.length && (
        <Card>
          <EmptyState
            title={activeFilters ? t('grants.empty.filtered.title') : t('grants.empty.none.title')}
            hint={activeFilters
              ? t('grants.empty.filtered.hint')
              : t('grants.empty.none.hint')} />
        </Card>
      )}

      {rows !== null && rows.length > 0 && (
        <Card tight>
          <div className="grant-caption">
            <strong>
              {rows === null ? t('common.loading') : tCount('grants.list.count', total)}
            </strong>
            <span className="muted">{t('grants.list.help')}</span>
            <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
              total={paged.total} perPage={paged.perPage} unit="grants" />
          </div>
          <ul className="grant-list">
            {paged.rows.map((grant) => {
              const when = expiry(grant.valid_until, { t, tCount, date })
              const caps = grant.capabilities || []
              return (
                <li key={grant.id}
                  className={`grant-row${grant.status === 'revoked' ? ' is-dim' : ''
                    }${grant.status === 'requested' ? ' is-request' : ''}`}>
                  <div className="grant-who">
                    <div className="grant-principal">
                      <strong>{grant.principal}</strong>
                      <span className={`pill ${grant.status === 'active' ? 'good'
                        : grant.status === 'requested' ? '' : 'denied'}`}>
                        {tOr(`grants.status.${grant.status}`, grant.status)}
                      </span>
                      {grant.level && <span className="pill">{tOr(`grants.level.${grant.level}`, grant.level)}</span>}
                    </div>
                    <div className="grant-just"
                      title={t('grants.row.byline', {
                        justification: grant.justification,
                        issuer: grant.issued_by,
                        version: grant.policy_version,
                      })}>
                      {justification(grant, t, tOr)}
                    </div>
                    <div className="grant-meta">
                      {t('grants.row.by', { issuer: grant.issued_by })}
                      {grant.revoked_by
                        ? t('grants.row.revokedBy', { actor: grant.revoked_by }) : ''}
                    </div>
                  </div>
                  <div className="grant-scope">
                    <TargetList targets={grant.targets} />
                    <div className="grant-meta">
                      {grant.environment || t('grants.row.anyEnvironment')}
                      {' · '}
                      {grant.tools?.length
                        ? t('grants.row.tools', { tools: grant.tools.join(', ') })
                        : t('grants.row.anyTool')}
                      {caps.length ? ` · ${caps.join(' + ')}` : ''}
                    </div>
                  </div>
                  <div className="grant-state">
                    {grant.status === 'revoked'
                      ? (
                        <span className="grant-meta" style={{ marginTop: 0, maxWidth: 240 }}
                          title={grant.revocation_reason || ''}>
                          {grant.revocation_reason || t('grants.row.revoked')}
                        </span>
                      )
                      : (
                        <span className={`pill ${when.tone || ''}`} title={when.detail}>
                          {when.label}
                        </span>
                      )}
                    {grant.status === 'active' && (
                      <button className="mini" onClick={() => setRevokeGrant(grant)}>
                        {t('grants.action.revoke')}
                      </button>
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
        </Card>
      )}

      <IssueDialog open={issueOpen} onClose={() => setIssueOpen(false)}
        catalog={capabilities} levels={levels}
        onIssued={() => { setIssueOpen(false); load() }} />
      <SimulateDialog open={simulateOpen} onClose={() => setSimulateOpen(false)}
        catalog={capabilities} />
      <RevokeDialog grant={revokeGrant} onClose={() => setRevokeGrant(null)}
        onRevoked={() => { setRevokeGrant(null); load() }} />
      <ReviewDialog grant={review} levels={levels}
        onClose={() => setReview(null)}
        onApproved={(message) => {
          setReview(null)
          setReviewNotice(message)
          loadRequests(); load()
        }}
        onError={(message) => setReviewError(message)} />
      <RejectDialog grant={rejecting} onClose={() => setRejecting(null)}
        onConfirm={(reason) => rejectRequest(rejecting, reason)} />
    </div>
  )
}

/* ─────────────────────────────── dialogs ─────────────────────────────── */

const CAPABILITY_HINT_KEY = {
  passive_discovery: 'grants.capability.passive_discovery',
  active_verification: 'grants.capability.active_verification',
  vulnerability_analysis: 'grants.capability.vulnerability_analysis',
  intrusive_testing: 'grants.capability.intrusive_testing',
}

const WINDOWS = [
  { hours: 24, labelKey: 'grants.window.option.oneDay' },
  { hours: 168, labelKey: 'grants.window.option.sevenDays' },
  { hours: 720, labelKey: 'grants.window.option.thirtyDays' },
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

function IssueDialog({ open, onClose, catalog, levels = [], onIssued }) {
  const { t, tCount } = useI18n()
  const [targets, setTargets] = useState([])
  const [query, setQuery] = useState('')
  const [assets, setAssets] = useState([])
  const [scopeTargets, setScopeTargets] = useState([])
  const [form, setForm] = useState({
    principal: 'collector', issued_by: 'console-operator',
    capabilities: ['passive_discovery'], justification: '',
    hours: 168, environment: '', tools: '', level: '',
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
      seen.set(`${type}:${row.value}`, { type, value: row.value, hint: '', inScope: true })
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
    setTargets((current) => (current.some((item) => item.type === row.type && item.value === row.value)
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
      // Hand-picked capabilities are no longer one of the three named levels,
      // and the row above must stop claiming they are.
      level: '',
      capabilities: current.capabilities.includes(id)
        ? current.capabilities.filter((cap) => cap !== id)
        : [...current.capabilities, id],
    }))
    setError('')
  }

  function submit() {
    if (!targets.length) {
      setError(t('grants.issue.targetRequired'))
      return false
    }
    if (!form.capabilities.length) {
      setError(t('grants.issue.capabilityRequired'))
      return false
    }
    if (form.principal.trim().length < 2) {
      setError(t('grants.issue.principalRequired'))
      return false
    }
    if (form.issued_by.trim().length < 2) {
      setError(t('grants.issue.issuerRequired'))
      return false
    }
    const hours = Number(form.hours)
    if (!Number.isFinite(hours) || hours < 1 || hours > 8760) {
      setError(t('grants.issue.windowInvalid'))
      return false
    }
    if (form.justification.trim().length < 4) {
      setError(t('grants.issue.justificationRequired'))
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
        level: form.level || undefined,
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

  const windowLabel = humanWindow(form.hours, t, tCount)
  const capabilitiesLabel = form.capabilities.length
    ? form.capabilities.map((cap) => cap.replace(/_/g, ' ')).join(' + ')
    : t('grants.issue.summary.nothing')
  const targetsLabel = targets.length
    ? tCount('grants.targets.count', targets.length)
    : t('grants.targets.none')

  return (
    <Dialog open={open} title={t('grants.issue.title')} size="wide"
      onClose={() => { if (!busy) onClose() }} onConfirm={submit}
      confirmLabel={busy ? t('grants.issue.busy') : t('grants.action.issue')}>
      <div className="release-form">
        <fieldset className="release-group">
          <legend>{t('grants.issue.targets')}</legend>
          <div className="grant-picker-wrap">
          <div className="grant-picker">
            <input value={query} placeholder={t('grants.issue.searchPlaceholder')}
              aria-label={t('grants.issue.searchLabel')}
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
                {t('grants.issue.addAs', {
                  value: query.trim(), type: targetLabel(t, guessType(query)),
                })}
              </button>
            )}
          </div>
          {query.trim() && suggestions.length > 0 && (
            <ul className="grant-suggestions" aria-label={t('grants.issue.matching')}>
              <li className="grant-suggestions-head">{t('grants.issue.matching')}</li>
              {suggestions.map((row) => (
                <li key={`${row.type}:${row.value}`}>
                  <button type="button" onClick={() => addTarget(row)}>
                    <span className="grant-target-type">{targetLabel(t, row.type)}</span>
                    <span className="mono">{row.value}</span>
                    {row.hint
                      ? <span className="grant-source">{row.hint}</span>
                      : row.inScope
                        ? <span className="grant-source">{t('grants.issue.inScope')}</span>
                        : null}
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
                  <span className="grant-target-type">{targetLabel(t, row.type)}</span>
                  <span className="mono">{row.value}</span>
                  <button type="button" aria-label={t('grants.issue.remove', { value: row.value })}
                    onClick={() => removeTarget(index)}>×</button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted release-hint">
              {t('grants.issue.pickHint')}
              <span className="mono"> *.example.com</span>
              {t('grants.issue.repoHint')}
              <span className="mono"> owner/name</span>.
            </p>
          )}
        </fieldset>

        <fieldset className="release-group">
          <legend>{t('grants.issue.level')}</legend>
          <div className="row grant-windows">
            {levels.map((level) => (
              <button type="button" key={level.id}
                className={`mini ${form.level === level.id ? 'on' : ''}`}
                title={level.risk || level.collects}
                onClick={() => setForm((current) => ({
                  ...current, level: level.id, capabilities: level.capabilities,
                }))}>
                {level.label || level.id}
              </button>
            ))}
            <span className="muted grant-hint">{t('grants.issue.levelHint')}</span>
          </div>
        </fieldset>

        <fieldset className="release-group">
          <legend>{t('grants.issue.capabilities')}</legend>
          <div className="grant-capabilities">
            {catalog.map((cap) => (
              <label className="row release-check" key={cap.id}
                title={cap.description || (CAPABILITY_HINT_KEY[cap.id] ? t(CAPABILITY_HINT_KEY[cap.id]) : '')}>
                <input type="checkbox" checked={form.capabilities.includes(cap.id)}
                  onChange={() => toggleCapability(cap.id)} />
                <span>{cap.id}</span>
                {cap.invasive ? <span className="pill denied">{t('grants.issue.invasive')}</span> : null}
                <span className="muted grant-hint">
                  {CAPABILITY_HINT_KEY[cap.id] ? t(CAPABILITY_HINT_KEY[cap.id]) : cap.description}
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset className="release-group">
          <legend>{t('grants.issue.who')}</legend>
          <div className="release-row">
            <label className="field">
              <span>{t('grants.issue.principal')}</span>
              <input value={form.principal}
                onChange={(event) => setForm((f) => ({ ...f, principal: event.target.value }))} />
            </label>
            <label className="field">
              <span>{t('grants.issue.issuedBy')}</span>
              <input value={form.issued_by}
                onChange={(event) => setForm((f) => ({ ...f, issued_by: event.target.value }))} />
            </label>
          </div>
          <div className="row grant-windows">
            {WINDOWS.map((option) => (
              <button type="button" key={option.hours}
                className={`mini ${Number(form.hours) === option.hours ? 'on' : ''}`}
                onClick={() => setForm((f) => ({ ...f, hours: option.hours }))}>
                {t(option.labelKey)}
              </button>
            ))}
            <span className="muted grant-or">{t('grants.issue.or')}</span>
            <label className="grant-hours">
              <input type="number" min="1" max="8760" value={form.hours}
                aria-label={t('grants.issue.windowHours')}
                onChange={(event) => setForm((f) => ({ ...f, hours: event.target.value }))} />
              <span className="muted">{t('grants.issue.hours')}</span>
            </label>
            {!WINDOWS.some((option) => Number(form.hours) === option.hours) && (
              <span className="muted grant-hint">
                {t('grants.issue.windowEquals', { window: windowLabel })}
              </span>
            )}
          </div>
          <div className="release-row">
            <label className="field">
              <span>{t('grants.issue.environment')}</span>
              <input value={form.environment} placeholder="production"
                onChange={(event) => setForm((f) => ({ ...f, environment: event.target.value }))} />
            </label>
            <label className="field">
              <span>{t('grants.issue.tools')}</span>
              <input value={form.tools} placeholder="dns-collector, tls-probe"
                onChange={(event) => setForm((f) => ({ ...f, tools: event.target.value }))} />
            </label>
          </div>
          <label className="field">
            <span>{t('grants.issue.justification')}</span>
            <input value={form.justification}
              placeholder={t('grants.issue.justificationPlaceholder')}
              onChange={(event) => {
                setForm((f) => ({ ...f, justification: event.target.value }))
                setError('')
              }} />
          </label>
        </fieldset>

        <p className="grant-summary">
          <strong>{form.principal.trim() || t('common.nobody')}</strong>{' '}
          {t('grants.issue.summary.may')}{' '}
          <strong>{capabilitiesLabel}</strong>{' '}
          {t('grants.issue.summary.against')}{' '}
          <strong>{targetsLabel}</strong>{' '}
          {t('grants.issue.summary.for')}{' '}
          <strong>{windowLabel}</strong>
          {t('grants.issue.summary.issuedBy')}{' '}
          <strong>{form.issued_by.trim() || t('common.nobody')}</strong>.
          {form.capabilities.some((cap) => catalog.find((entry) => entry.id === cap)?.invasive)
            && form.principal.trim() === form.issued_by.trim()
            ? ` ${t('grants.issue.selfAuthorized')}`
            : ''}
        </p>

        {error && <p role="alert" className="release-error">{error}</p>}
      </div>
    </Dialog>
  )
}

function SimulateDialog({ open, onClose, catalog }) {
  const { t, tOr } = useI18n()
  const [form, setForm] = useState({
    principal: 'console', capability: 'passive_discovery',
    type: 'domain', value: '', tool: '', environment: '',
  })
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  async function simulate() {
    if (!form.value.trim()) { setError(t('grants.simulate.targetRequired')); return false }
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
    <Dialog open={open} title={t('grants.simulate.title')} size="wide"
      onClose={onClose} onConfirm={simulate} confirmLabel={t('grants.simulate.evaluate')}>
      <div className="release-form">
        <p className="muted release-hint">{t('grants.simulate.hint')}</p>
        <div className="release-row">
          <label className="field">
            <span>{t('grants.simulate.principal')}</span>
            <input value={form.principal}
              onChange={(event) => setForm((f) => ({ ...f, principal: event.target.value }))} />
          </label>
          <label className="field">
            <span>{t('grants.simulate.capability')}</span>
            <select value={form.capability}
              onChange={(event) => setForm((f) => ({ ...f, capability: event.target.value }))}>
              {catalog.map((cap) => <option key={cap.id} value={cap.id}>{cap.id}</option>)}
            </select>
          </label>
        </div>
        <div className="release-row">
          <label className="field">
            <span>{t('grants.simulate.targetType')}</span>
            <select value={form.type}
              onChange={(event) => setForm((f) => ({ ...f, type: event.target.value }))}>
              {TARGET_TYPES.map((type) => (
                <option key={type} value={type}>{targetLabel(t, type)}</option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>{t('grants.simulate.value')}</span>
            <input value={form.value} placeholder="api.example.com"
              onChange={(event) => setForm((f) => ({ ...f, value: event.target.value }))} />
          </label>
        </div>
        <div className="release-row">
          <label className="field">
            <span>{t('grants.simulate.tool')}</span>
            <input value={form.tool} placeholder="dns-collector"
              onChange={(event) => setForm((f) => ({ ...f, tool: event.target.value }))} />
          </label>
          <label className="field">
            <span>{t('grants.simulate.environment')}</span>
            <input value={form.environment} placeholder="production"
              onChange={(event) => setForm((f) => ({ ...f, environment: event.target.value }))} />
          </label>
        </div>
        {result && result.decision && (
          <div className="grant-verdict">
            <span className={`pill ${result.decision === 'allow' ? 'good' : 'denied'}`}>
              {tOr(`grants.decision.${result.decision}`, result.decision)}
            </span>
            <p className="muted">{result.reason}</p>
            <p className="muted grant-restr">
              {t('grants.simulate.verdict', {
                version: result.policy_version, at: result.evaluated_at,
              })}
            </p>
          </div>
        )}
        {error && <p role="alert" className="release-error">{error}</p>}
      </div>
    </Dialog>
  )
}

/* ─────────────────────── reviewing a request ───────────────────────

   The narrow answer is the default: approving without touching anything grants
   exactly the value that was declared and nothing else. Widening is the edit —
   "everything under api.dominio.com" and "the whole zone" are different
   permissions, and the server computes what each one writes, apex included,
   because `*.base` never covers `base`. */

function ReviewDialog({ grant, levels, onClose, onApproved, onError }) {
  const { t, tCount } = useI18n()
  const [options, setOptions] = useState([])
  const [scope, setScope] = useState('exact')
  const [level, setLevel] = useState('simple')
  const [hours, setHours] = useState(720)
  const [actor, setActor] = useState('console')
  const [justification, setJustification] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!grant) return
    setScope('exact')
    setLevel(grant.level || 'simple')
    setHours(720)
    setJustification('')
    setError('')
    const values = (grant.targets || []).map((target) => target.value).join(',')
    api.get(`/api/v1/authorization/scope-options?value=${encodeURIComponent(values)}`)
      .then((r) => setOptions(r.data || []))
      .catch(() => setOptions([]))
  }, [grant])

  if (!grant) return null

  const chosen = options.find((option) => option.scope === scope)
  const targets = chosen?.targets || grant.targets
  const levelEntry = levels.find((entry) => entry.id === level)

  async function approve() {
    setError('')
    if (actor.trim().length < 2) {
      setError(t('grants.review.actorRequired'))
      return false
    }
    setBusy(true)
    try {
      const body = { actor: actor.trim(), level, hours: Number(hours) || 720,
        targets }
      if (justification.trim()) body.justification = justification.trim()
      await api.post(`/api/v1/authorization/grants/${grant.id}/approve`, body)
      onApproved(t('grants.review.approved', {
        targets: targets.map((target) => target.value).join(', '),
        level: levelEntry?.label || level,
      }))
    } catch (problem) {
      const message = String(problem.message || problem)
      const friendly = message.includes('403')
        ? t('grants.review.forbidden', { message }) : message
      setError(friendly)
      onError?.(friendly)
    } finally { setBusy(false) }
    return false
  }

  return (
    <Dialog open title={t('grants.review.title')} size="wide" onClose={onClose}
      onConfirm={approve} confirmLabel={busy ? t('grants.review.busy') : t('grants.action.approve')}>
      <div className="release-form">
        <p className="muted release-hint" style={{ margin: 0 }}>
          {t('grants.review.requestedBy')} <strong>{grant.requested_by || grant.issued_by}</strong>.{' '}
          {t('grants.review.hint')} <strong>{t('grants.review.only')}</strong>{' '}
          {t('grants.review.hintRest')}
        </p>

        <fieldset className="release-group">
          <legend>{t('grants.review.scope')}</legend>
          <div className="stack" style={{ gap: 6 }}>
            {(options.length ? options : [{ scope: 'exact', labelKey: 'grants.review.asRequested',
              targets: grant.targets }]).map((option) => (
              <label className="row release-check" key={option.scope}>
                <input type="radio" name="scope" checked={scope === option.scope}
                  onChange={() => setScope(option.scope)} />
                <span>{option.label || t(option.labelKey)}</span>
                <span className="muted mono" style={{ fontSize: 11.5 }}>
                  {option.targets.map((target) => target.value).join(' + ')}
                </span>
              </label>
            ))}
          </div>
          <p className="muted release-hint" style={{ marginBottom: 0 }}>
            {t('grants.review.apexBefore')} <em>{t('grants.review.apexAnd')}</em>{' '}
            {t('grants.review.apexIts')} <span className="mono">*.</span>{' '}
            {t('grants.review.apexPattern')}
          </p>
        </fieldset>

        <fieldset className="release-group">
          <legend>{t('grants.review.capabilities')}</legend>
          <div className="row grant-windows">
            {levels.map((entry) => (
              <button type="button" key={entry.id}
                className={`mini ${level === entry.id ? 'on' : ''}`}
                title={entry.risk}
                onClick={() => setLevel(entry.id)}>
                {entry.label || entry.id}
              </button>
            ))}
          </div>
          <p className="muted release-hint" style={{ marginBottom: 0 }}>
            {levelEntry
              ? `${levelEntry.collects}. ${levelEntry.risk}`
              : t('grants.review.levelFallback')}
          </p>
        </fieldset>

        <fieldset className="release-group">
          <legend>{t('grants.review.duration')}</legend>
          <div className="row grant-windows">
            {WINDOWS.map((option) => (
              <button type="button" key={option.hours}
                className={`mini ${Number(hours) === option.hours ? 'on' : ''}`}
                onClick={() => setHours(option.hours)}>{t(option.labelKey)}</button>
            ))}
            <label className="grant-hours">
              <input type="number" min="1" max="8760" value={hours}
                aria-label={t('grants.issue.windowHours')}
                onChange={(event) => setHours(event.target.value)} />
              <span className="muted">{t('grants.issue.hours')}</span>
            </label>
          </div>
          <div className="release-row">
            <label className="field">
              <span>{t('grants.review.approvedBy')}</span>
              <input value={actor}
                onChange={(event) => { setActor(event.target.value); setError('') }} />
            </label>
            <label className="field">
              <span>{t('grants.review.note')}</span>
              <input value={justification} placeholder={t('grants.review.notePlaceholder')}
                onChange={(event) => setJustification(event.target.value)} />
            </label>
          </div>
        </fieldset>

        <p className="grant-summary">
          <strong>{grant.principal}</strong>{' '}
          {t('grants.review.summary.may')}{' '}
          <strong>{levelEntry?.label || level}</strong>{' '}
          {t('grants.review.summary.against')}{' '}
          <strong>{targets.length
            ? tCount('grants.targets.count', targets.length)
            : t('grants.targets.none')}</strong>{' '}
          {t('grants.review.summary.for')}{' '}
          <strong>{humanWindow(hours, t, tCount)}</strong>
          {t('grants.review.summary.approvedBy')}{' '}
          <strong>{actor.trim() || t('common.nobody')}</strong>.
        </p>
        {error && <p role="alert" className="release-error">{error}</p>}
      </div>
    </Dialog>
  )
}

function RejectDialog({ grant, onClose, onConfirm }) {
  const { t } = useI18n()
  const [reason, setReason] = useState('')
  const [error, setError] = useState('')

  useEffect(() => { setReason(''); setError('') }, [grant])
  if (!grant) return null

  return (
    <Dialog open title={t('grants.reject.title')} destructive onClose={onClose}
      confirmLabel={t('grants.action.reject')}
      onConfirm={() => {
        if (reason.trim().length < 4) {
          setError(t('grants.reject.reasonRequired'))
          return false
        }
        onConfirm(reason.trim())
        return false
      }}>
      <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
        {t('grants.reject.body', {
          targets: grant.targets.map((target) => target.value).join(', '),
        })}
      </p>
      <label className="field" style={{ marginTop: 10 }}>
        <span>{t('grants.field.reason')}</span>
        <input value={reason}
          onChange={(event) => { setReason(event.target.value); setError('') }} />
      </label>
      {error && <p role="alert" className="release-error">{error}</p>}
    </Dialog>
  )
}

function RevokeDialog({ grant, onClose, onRevoked }) {
  const { t } = useI18n()
  const [reason, setReason] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit() {
    if (reason.trim().length < 4) {
      setError(t('grants.revoke.reasonRequired'))
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
    <Dialog open={Boolean(grant)} title={t('grants.revoke.title')}
      onClose={onClose} onConfirm={submit} destructive
      confirmLabel={busy ? t('grants.revoke.busy') : t('grants.action.revoke')}>
      <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
        {t('grants.revoke.body', {
          principal: grant?.principal,
          capabilities: grant?.capabilities?.join(' + '),
        })}
      </p>
      <label className="field" style={{ marginTop: 10 }}>
        <span>{t('grants.field.reason')}</span>
        <input value={reason}
          onChange={(event) => { setReason(event.target.value); setError('') }} />
      </label>
      {error && <p role="alert" className="release-error">{error}</p>}
    </Dialog>
  )
}
