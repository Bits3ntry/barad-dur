import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, Dialog } from './ui'

/* ─────────────────────────── verify the inventory ───────────────────────

   One question here: *is what we declared true, right now?* A DNS resolution
   and, when it is authorized, a TLS handshake. Facts with a timestamp — no
   fingerprinting, no ASN, no geo, no "probably WordPress": that is profiling,
   a different surface fed by a different runner.

   Two things the panel must keep apart anyway:

     allowed   — the grant decision for the capability and tool the collector
                 uses (a grant is permission to run, not scope membership)
     observed  — the newest snapshot, with its timestamp

   `verify` runs whatever is authorized: DNS alone, or DNS + TLS.
   ─────────────────────────────────────────────────────────────────────── */

const CAPABILITY_LABEL = {
  passive_discovery: 'DNS',
  active_verification: 'TLS',
}

function isoDate(value) {
  return value ? new Date(value).toLocaleString() : null
}

function age(days) {
  if (days === null || days === undefined) return null
  if (days === 0) return 'today'
  if (days === 1) return 'yesterday'
  return `${days}d ago`
}

/* A TLS failure is a finding, not a stack trace. The collector reports the
   underlying SSL error; the reader gets what it means, with the raw text kept
   in the tooltip. */
/* What the table exists to answer: is this verified?
   Grey is not a failure — "never observed" is unknown, and calling it red would
   turn a missing fact into a finding the product never made. */
export function verificationState(row) {
  const passive = row.permissions?.passive_discovery || {}
  if (passive.excluded) {
    return { tone: 'unknown', label: 'excluded', detail: 'inventoried, never touched' }
  }
  const observation = row.observation
  if (!observation) {
    return { tone: 'unknown', label: 'not verified', detail: 'no observation yet' }
  }
  const addresses = (observation.ipv4 || 0) + (observation.ipv6 || 0)
  if (!addresses) {
    return { tone: 'bad', label: 'no answer', detail: 'DNS returned no address' }
  }
  if (observation.tls && observation.tls.error) {
    return { tone: 'warn', label: 'TLS failed', detail: observation.tls.error }
  }
  if ((observation.age_days || 0) > 30) {
    return { tone: 'warn', label: 'stale',
      detail: `last confirmed ${observation.age_days} days ago` }
  }
  return { tone: 'good', label: 'verified',
    detail: `${addresses} address${addresses === 1 ? '' : 'es'} on ${isoDate(observation.observed_at)}` }
}

export function describeTls(tls) {
  if (!tls) return null
  if (tls.error) {
    const raw = String(tls.error)
    if (/UNRECOGNIZED_NAME/i.test(raw)) {
      return 'no certificate served for this name (SNI rejected)'
    }
    if (/CERTIFICATE_VERIFY_FAILED|certificate verification failed/i.test(raw)) {
      return 'certificate not trusted'
    }
    if (/timed out|timeout/i.test(raw)) return 'no TLS answer on 443 (timeout)'
    if (/refused|unreachable/i.test(raw)) return 'no TLS on 443 (connection refused)'
    return 'TLS handshake failed'
  }
  return [tls.version, tls.not_after ? `certificate to ${tls.not_after}` : null]
    .filter(Boolean).join(' · ') || 'TLS answered'
}

function PermissionCell({ permission, capability }) {
  const label = CAPABILITY_LABEL[capability] || capability
  if (permission.allowed) {
    return (
      <>
        <span className="pill good" title={permission.reason}>{label} allowed</span>
        {permission.grant && (
          <div className="muted" style={{ fontSize: 11 }}>
            grant {permission.grant.id.slice(0, 8)}
            {permission.grant.environment ? ` · ${permission.grant.environment}` : ''}
            {permission.grant.valid_until
              ? ` · to ${new Date(permission.grant.valid_until).toLocaleDateString()}`
              : ''}
          </div>
        )}
      </>
    )
  }
  if (permission.excluded) {
    return (
      <span className="pill denied"
        title={`${permission.reason} — an exclusion wins over any grant`}>
        {label} excluded
      </span>
    )
  }
  return <span className="pill denied" title={permission.reason}>{label} denied</span>
}

export default function ProjectVerification({ slug, onAdd, onOpenGrants }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [excludeRow, setExcludeRow] = useState(null)
  const [reason, setReason] = useState('')
  const [excludeError, setExcludeError] = useState('')
  const [editRow, setEditRow] = useState(null)
  const [editForm, setEditForm] = useState({ value: '', type: 'domain', notes: '' })
  const [editError, setEditError] = useState('')
  const [restoreRow, setRestoreRow] = useState(null)

  function load() {
    setError('')
    return api.get(`/api/v1/projects/${encodeURIComponent(slug)}/verification`)
      .then((r) => setData(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(() => { load() }, [slug])

  async function verify(row) {
    const tls = row.permissions.passive_discovery.allowed
      && row.permissions.active_verification.allowed
    setBusy(row.id)
    setNotice('')
    try {
      const result = await api.post(`/api/v1/assets/${row.id}/collect`,
        { tls, actor: 'console' })
      const observation = result?.data?.observation || {}
      const dns = observation.dns || {}
      const parts = [`${(dns.ipv4 || []).length} A`, `${(dns.ipv6 || []).length} AAAA`]
      if (observation.tls) parts.push(describeTls(observation.tls))
      setNotice(`${row.value}: ${parts.filter(Boolean).join(' · ')} — observed `
        + `${isoDate(result?.data?.observed_at)}.`)
      await load()
    } catch (e) {
      const message = String(e.message || e)
      setNotice(/grant|authoriz|forbidden|403/i.test(message)
        ? `Nothing was sent: ${message}. Authorize the capability first.`
        : `Collection failed: ${message}`)
    } finally { setBusy('') }
  }

  function openEdit(row) {
    setEditError('')
    setEditForm({ value: row.value, type: row.type, notes: row.notes || '' })
    setEditRow(row)
  }

  function submitEdit() {
    const value = editForm.value.trim()
    if (!value) {
      setEditError('The value cannot be empty — that is the record itself.')
      return false
    }
    applyEdit(value)
    return false               // the request closes the dialog on success
  }

  async function applyEdit(value) {
    setBusy(`edit:${editRow.id}`)
    setEditError('')
    try {
      await api.patch(`/api/v1/assets/${editRow.id}`, {
        value, type: editForm.type, notes: editForm.notes, actor: 'console',
      })
      setNotice(`${editRow.value} → ${value}. Scope targets and grants keep the old `
        + 'value: they are separate records, not a rename.')
      setEditRow(null)
      await load()
    } catch (e) {
      setEditError(String(e.message || e))
    } finally { setBusy('') }
  }

  async function restoreExclusion() {
    const permission = restoreRow.permissions.passive_discovery
    const exclusion = permission.exclusion
    if (!exclusion) return
    setBusy(`restore:${restoreRow.id}`)
    try {
      await api.patch(`/api/v1/scope/exclusions/${exclusion.id}`,
        { status: 'disabled', actor: 'console' })
      setNotice(`Exclusion lifted for ${exclusion.value}. The decision stays in Scope `
        + 'as disabled — nothing is erased.')
      setRestoreRow(null)
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  function submitExclusion() {
    if (reason.trim().length < 4) {
      setExcludeError('A reason is required: an exclusion with no reason is unauditable.')
      return false
    }
    setExcludeError('')
    excludeTarget()       // closes only on success, so a failure stays readable
    return false
  }

  async function excludeTarget() {
    if (!excludeRow) return
    setBusy(`exclude:${excludeRow.id}`)
    setError('')
    try {
      await api.post('/api/v1/scope/exclusions', {
        target_type: 'domain', value: excludeRow.value,
        reason: reason.trim(), actor: 'console',
      })
      setNotice(`${excludeRow.value} stays in the inventory and is excluded from every `
        + 'collection: an exclusion wins over any grant.')
      setExcludeRow(null)
      setReason('')
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  const summary = data?.summary
  const rows = data?.assets || []
  const counts = rows.reduce((acc, row) => {
    const tone = verificationState(row).tone
    acc[tone] = (acc[tone] || 0) + 1
    return acc
  }, { good: 0, warn: 0, bad: 0, unknown: 0 })

  return (
    <>
      <Card title="Declared assets"
        actions={(
          <div className="row">
            <button className="mini" onClick={onOpenGrants}>grants ›</button>
            {onAdd && <button className="mini" onClick={onAdd}>add asset</button>}
          </div>
        )}>

        {error && <p className="muted" style={{ color: 'var(--err-fg)' }}>{error}</p>}
        {notice && <p className="muted" role="status">{notice}</p>}

        {!data && !error && <p className="muted">Reading what is declared, allowed and observed…</p>}

        {data && !rows.length && (
          <div className="onb-empty-state" style={{ padding: '20px 16px 24px' }}>
            <h2>Nothing recorded yet</h2>
            <p>
              Record what you already know: a domain, a URL, an IP. Nothing here has been
              observed yet — declaring a host authorizes nothing.
            </p>
            {onAdd && <button className="btn-primary" onClick={onAdd}>add the first domain</button>}
          </div>
        )}

        {rows.length > 0 && (
          <>
            <p className="verify-summary">
              <span className="state-pill good">
                <i className="state-dot" />{counts.good} verified
              </span>
              {counts.warn > 0 && (
                <span className="state-pill warn">
                  <i className="state-dot" />{counts.warn} need attention
                </span>
              )}
              {counts.bad > 0 && (
                <span className="state-pill bad">
                  <i className="state-dot" />{counts.bad} no answer
                </span>
              )}
              <span className="state-pill unknown">
                <i className="state-dot" />{counts.unknown} not verified
              </span>
              <span className="muted">
                {summary.assets} declared · {summary.authorized} allowed to collect
                {summary.excluded ? ` · ${summary.excluded} excluded` : ''}
              </span>
            </p>
            <table className="verification-table">
              <thead>
                <tr>
                  <th className="state-col">state</th>
                  <th>value</th><th>environment</th>
                  <th>collection</th><th>last observed</th><th>action</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const passive = row.permissions.passive_discovery
                  const active = row.permissions.active_verification
                  const observation = row.observation
                  const state = verificationState(row)
                  return (
                    <tr key={row.id} className={`state-${state.tone}`}>
                      <td className="state-cell">
                        <span className={`state-pill ${state.tone}`} title={state.detail}>
                          <i className="state-dot" />{state.label}
                        </span>
                      </td>
                      <td className="title mono">
                        {row.value}
                        {row.component && (
                          <div className="muted" style={{ fontSize: 11.5 }}>{row.component}</div>
                        )}
                      </td>
                      <td>{row.environment
                        ? <span className="pill">{row.environment}</span>
                        : <span className="muted">—</span>}</td>
                      <td>
                        <PermissionCell permission={passive} capability="passive_discovery" />
                        {' '}
                        <PermissionCell permission={active} capability="active_verification" />
                      </td>
                      <td className="muted">
                        {observation ? (
                          <>
                            {isoDate(observation.observed_at)}
                            <div style={{ fontSize: 11.5 }}>
                              {age(observation.age_days)} ·{' '}
                              <span title="A records resolved at observation time">
                                {observation.ipv4} A
                              </span>
                              {observation.ipv6 ? ` · ${observation.ipv6} AAAA` : ''}
                              {observation.tls ? (
                                <span className={observation.tls.error ? 'obs-warn' : ''}
                                  title={observation.tls.error || ''}>
                                  {' · '}{describeTls(observation.tls)}
                                </span>
                              ) : null}
                            </div>
                          </>
                        ) : <span className="muted">never — no observation</span>}
                      </td>
                      <td>
                        <div className="row">
                          <button className="mini" disabled={busy !== '' || !passive.allowed}
                            title={passive.allowed
                              ? (active.allowed
                                ? 'Runs a DNS lookup and a TLS handshake'
                                : `Runs a DNS lookup only — TLS not authorized: ${active.reason}`)
                              : passive.reason}
                            onClick={() => verify(row)}>
                            {busy === row.id ? 'verifying…' : 'verify'}
                          </button>
                          {/* The plan lives in the tooltip: a second label beside
                              the button reads as a second action. */}

                          <button className="mini" title="Correct the value, its type or its notes"
                            onClick={() => openEdit(row)}>
                            edit
                          </button>
                          {passive.excluded ? (
                            <button className="mini"
                              title="Lift the exclusion — the decision stays in Scope as disabled"
                              onClick={() => setRestoreRow(row)}>
                              restore
                            </button>
                          ) : (
                            <button className="mini"
                              title="Keep it in the inventory but forbid collection"
                              onClick={() => {
                                setExcludeRow(row); setReason(''); setExcludeError('')
                              }}>
                              exclude…
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </>
        )}
      </Card>

      <p className="muted" style={{ margin: 0, fontSize: 12 }}>
        Collection is read-only: a DNS lookup, and optionally a TLS handshake to read the
        certificate. Nothing is written to the target. A host with no observation is
        <strong> never observed</strong>, not clean and not unreachable.
        {' '}Collection runs only where a grant allows it — grants are issued in
        {' '}<a href="#grants">Authorization grants</a>, not here: this screen declares,
        {' '}excludes and verifies. <strong>Scope</strong> is a third ledger, the universe
        {' '}automated cycles sweep, declared in <a href="#scope">Scope</a>.
      </p>

      <Dialog open={Boolean(editRow)} title={`Edit ${editRow?.value || ''}`}
        onClose={() => setEditRow(null)} onConfirm={submitEdit}
        confirmLabel={busy === `edit:${editRow?.id}` ? 'saving…' : 'save'}>
        <div className="stack" style={{ gap: 10 }}>
          <label className="field">
            <span>value</span>
            <input value={editForm.value}
              onChange={(event) => { setEditForm((f) => ({ ...f, value: event.target.value })); setEditError('') }} />
          </label>
          <label className="field">
            <span>type</span>
            <select value={editForm.type}
              onChange={(event) => setEditForm((f) => ({ ...f, type: event.target.value }))}>
              {['domain', 'subdomain', 'url', 'ip', 'api', 'mobile_app'].map((kind) => (
                <option key={kind} value={kind}>{kind}</option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>notes</span>
            <textarea rows="2" value={editForm.notes}
              onChange={(event) => setEditForm((f) => ({ ...f, notes: event.target.value }))} />
          </label>
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>
            Renaming keeps the asset&apos;s links, snapshots and history. Scope targets and
            grants record the value they were written with, so a rename does not move them.
          </p>
          {editError && (
            <p role="alert" style={{ margin: 0, fontSize: 12.5, color: 'var(--err-fg)' }}>
              {editError}
            </p>
          )}
        </div>
      </Dialog>

      <Dialog open={Boolean(restoreRow)} title="Lift this exclusion"
        onClose={() => setRestoreRow(null)} onConfirm={restoreExclusion}
        confirmLabel={busy.startsWith('restore:') ? 'lifting…' : 'lift exclusion'}>
        <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
          {restoreRow?.permissions.passive_discovery.exclusion?.value} will be collectable
          again, and it stays in the inventory. The exclusion row is not deleted: it stays in
          Scope as <strong>disabled</strong>, with its reason and who lifted it.
          {' '}If the exclusion came from a wildcard rule, lifting it affects every host that
          rule covers.
        </p>
      </Dialog>

      <Dialog open={Boolean(excludeRow)} title={`Exclude ${excludeRow?.value || ''}`}
        onClose={() => setExcludeRow(null)}
        onConfirm={submitExclusion}
        confirmLabel={busy.startsWith('exclude:') ? 'excluding…' : 'exclude from collection'}>
        <div className="stack" style={{ gap: 10 }}>
          <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
            The host stays in the inventory and in the graph — it is not deleted. What
            stops is every request against it: an exclusion wins over any grant, current
            or future, for this exact host.
          </p>
          <label className="field">
            <span>reason (audited)</span>
            <input value={reason} placeholder="e.g. production payment endpoint — read-only contract"
              onChange={(event) => { setReason(event.target.value); setExcludeError('') }} />
          </label>
          {excludeError && (
            <p role="alert" style={{ margin: 0, fontSize: 12.5, color: 'var(--err-fg)' }}>
              {excludeError}
            </p>
          )}
        </div>
      </Dialog>
    </>
  )
}
