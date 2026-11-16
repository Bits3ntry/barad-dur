import React, { useEffect, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
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

function age(days, t) {
  if (days === null || days === undefined) return null
  if (days === 0) return t('verification.age.today')
  if (days === 1) return t('verification.age.yesterday')
  return t('verification.age.days', { n: days })
}

/* A TLS failure is a finding, not a stack trace. The collector reports the
   underlying SSL error; the reader gets what it means, with the raw text kept
   in the tooltip. */
/* What the table exists to answer: is this verified?
   Grey is not a failure — "never observed" is unknown, and calling it red would
   turn a missing fact into a finding the product never made. */
export function verificationState(row, t, tCount) {
  const passive = row.permissions?.passive_discovery || {}
  if (passive.excluded) {
    return { tone: 'unknown', label: t('verification.state.excluded'),
      detail: t('verification.state.excludedDetail') }
  }
  const observation = row.observation
  if (!observation) {
    return { tone: 'unknown', label: t('verification.state.notVerified'),
      detail: t('verification.state.noObservation') }
  }
  const addresses = (observation.ipv4 || 0) + (observation.ipv6 || 0)
  if (!addresses) {
    return { tone: 'bad', label: t('verification.state.noAnswer'),
      detail: t('verification.state.noAnswerDetail') }
  }
  if (observation.tls && observation.tls.error) {
    return { tone: 'warn', label: t('verification.state.tlsFailed'), detail: observation.tls.error }
  }
  if ((observation.age_days || 0) > 30) {
    return { tone: 'warn', label: t('verification.state.stale'),
      detail: t('verification.state.staleDetail', { n: observation.age_days }) }
  }
  return { tone: 'good', label: t('verification.state.verified'),
    detail: tCount('verification.state.addresses', addresses,
      { when: isoDate(observation.observed_at) }) }
}

export function describeTls(tls, t) {
  if (!tls) return null
  if (tls.error) {
    const raw = String(tls.error)
    if (/UNRECOGNIZED_NAME/i.test(raw)) {
      return t('verification.tls.noCert')
    }
    if (/CERTIFICATE_VERIFY_FAILED|certificate verification failed/i.test(raw)) {
      return t('verification.tls.untrusted')
    }
    if (/timed out|timeout/i.test(raw)) return t('verification.tls.timeout')
    if (/refused|unreachable/i.test(raw)) return t('verification.tls.refused')
    return t('verification.tls.failed')
  }
  return [tls.version, tls.not_after
    ? t('verification.tls.certificateTo', { date: tls.not_after }) : null]
    .filter(Boolean).join(' · ') || t('verification.tls.answered')
}

function PermissionCell({ permission, capability }) {
  const { t } = useI18n()
  const label = CAPABILITY_LABEL[capability] || capability
  if (permission.allowed) {
    return (
      <>
        <span className="pill good" title={permission.reason}>
          {t('verification.perm.allowed', { capability: label })}
        </span>
        {permission.grant && (
          <div className="muted" style={{ fontSize: 11 }}>
            {t('verification.perm.grant', { id: permission.grant.id.slice(0, 8) })}
            {permission.grant.environment ? ` · ${permission.grant.environment}` : ''}
            {permission.grant.valid_until
              ? ` · ${t('verification.perm.validUntil', {
                date: new Date(permission.grant.valid_until).toLocaleDateString() })}`
              : ''}
          </div>
        )}
      </>
    )
  }
  if (permission.excluded) {
    return (
      <span className="pill denied"
        title={t('verification.perm.exclusionWins', { reason: permission.reason })}>
        {t('verification.perm.excluded', { capability: label })}
      </span>
    )
  }
  return (
    <span className="pill denied" title={permission.reason}>
      {t('verification.perm.denied', { capability: label })}
    </span>
  )
}

export default function ProjectVerification({ slug, onAdd, onOpenGrants }) {
  const { t, tCount } = useI18n()
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
      if (observation.tls) parts.push(describeTls(observation.tls, t))
      setNotice(t('verification.notice.observed', {
        value: row.value,
        parts: parts.filter(Boolean).join(' · '),
        when: isoDate(result?.data?.observed_at),
      }))
      await load()
    } catch (e) {
      const message = String(e.message || e)
      setNotice(/grant|authoriz|forbidden|403/i.test(message)
        ? t('verification.notice.nothingSent', { message })
        : t('verification.notice.collectionFailed', { message }))
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
      setEditError(t('verification.error.emptyValue'))
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
      setNotice(t('verification.notice.renamed', { from: editRow.value, to: value }))
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
      setNotice(t('verification.notice.exclusionLifted', { value: exclusion.value }))
      setRestoreRow(null)
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  function submitExclusion() {
    if (reason.trim().length < 4) {
      setExcludeError(t('verification.error.reasonRequired'))
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
      setNotice(t('verification.notice.excluded', { value: excludeRow.value }))
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
    const tone = verificationState(row, t, tCount).tone
    acc[tone] = (acc[tone] || 0) + 1
    return acc
  }, { good: 0, warn: 0, bad: 0, unknown: 0 })

  return (
    <>
      <Card title={t('verification.title')}
        actions={(
          <div className="row">
            <button className="mini" onClick={onOpenGrants}>{t('verification.openGrants')}</button>
            {onAdd && <button className="mini" onClick={onAdd}>{t('verification.addAsset')}</button>}
          </div>
        )}>

        {error && <p className="muted" style={{ color: 'var(--err-fg)' }}>{error}</p>}
        {notice && <p className="muted" role="status">{notice}</p>}

        {!data && !error && <p className="muted">{t('verification.reading')}</p>}

        {data && !rows.length && (
          <div className="onb-empty-state" style={{ padding: '20px 16px 24px' }}>
            <h2>{t('verification.empty.title')}</h2>
            <p>{t('verification.empty.body')}</p>
            {onAdd && (
              <button className="btn-primary" onClick={onAdd}>{t('verification.empty.action')}</button>
            )}
          </div>
        )}

        {rows.length > 0 && (
          <>
            <p className="verify-summary">
              <span className="state-pill good">
                <i className="state-dot" />{t('verification.summary.verified', { n: counts.good })}
              </span>
              {counts.warn > 0 && (
                <span className="state-pill warn">
                  <i className="state-dot" />{t('verification.summary.attention', { n: counts.warn })}
                </span>
              )}
              {counts.bad > 0 && (
                <span className="state-pill bad">
                  <i className="state-dot" />{t('verification.summary.noAnswer', { n: counts.bad })}
                </span>
              )}
              <span className="state-pill unknown">
                <i className="state-dot" />{t('verification.summary.notVerified', { n: counts.unknown })}
              </span>
              <span className="muted">
                {t('verification.summary.declared', {
                  assets: summary.assets, authorized: summary.authorized })}
                {summary.excluded
                  ? ` · ${t('verification.summary.excluded', { n: summary.excluded })}` : ''}
              </span>
            </p>
            <table className="verification-table">
              <thead>
                <tr>
                  <th className="state-col">{t('verification.col.state')}</th>
                  <th>{t('verification.col.value')}</th>
                  <th>{t('verification.col.environment')}</th>
                  <th>{t('verification.col.collection')}</th>
                  <th>{t('verification.col.lastObserved')}</th>
                  <th>{t('verification.col.action')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const passive = row.permissions.passive_discovery
                  const active = row.permissions.active_verification
                  const observation = row.observation
                  const state = verificationState(row, t, tCount)
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
                              {age(observation.age_days, t)} ·{' '}
                              <span title={t('verification.obs.aRecordsHint')}>
                                {observation.ipv4} A
                              </span>
                              {observation.ipv6 ? ` · ${observation.ipv6} AAAA` : ''}
                              {observation.tls ? (
                                <span className={observation.tls.error ? 'obs-warn' : ''}
                                  title={observation.tls.error || ''}>
                                  {' · '}{describeTls(observation.tls, t)}
                                </span>
                              ) : null}
                            </div>
                          </>
                        ) : <span className="muted">{t('verification.obs.never')}</span>}
                      </td>
                      <td>
                        <div className="row">
                          <button className="mini" disabled={busy !== '' || !passive.allowed}
                            title={passive.allowed
                              ? (active.allowed
                                ? t('verification.action.verifyTlsHint')
                                : t('verification.action.verifyDnsHint', { reason: active.reason }))
                              : passive.reason}
                            onClick={() => verify(row)}>
                            {busy === row.id
                              ? t('verification.action.verifying') : t('verification.action.verify')}
                          </button>
                          {/* The plan lives in the tooltip: a second label beside
                              the button reads as a second action. */}

                          <button className="mini" title={t('verification.action.editHint')}
                            onClick={() => openEdit(row)}>
                            {t('verification.action.edit')}
                          </button>
                          {passive.excluded ? (
                            <button className="mini"
                              title={t('verification.action.restoreHint')}
                              onClick={() => setRestoreRow(row)}>
                              {t('verification.action.restore')}
                            </button>
                          ) : (
                            <button className="mini"
                              title={t('verification.action.excludeHint')}
                              onClick={() => {
                                setExcludeRow(row); setReason(''); setExcludeError('')
                              }}>
                              {t('verification.action.exclude')}
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
        {t('verification.footnote.a')}
        <strong> {t('verification.footnote.neverObserved')}</strong>
        {t('verification.footnote.b')}
        {' '}<a href="#grants">{t('verification.footnote.grantsLink')}</a>
        {t('verification.footnote.c')}
        {' '}<strong>{t('verification.footnote.scopeWord')}</strong>
        {' '}{t('verification.footnote.d')}
        {' '}<a href="#scope">{t('verification.footnote.scopeLink')}</a>.
      </p>

      <Dialog open={Boolean(editRow)}
        title={t('verification.dialog.edit', { value: editRow?.value || '' })}
        onClose={() => setEditRow(null)} onConfirm={submitEdit}
        confirmLabel={busy === `edit:${editRow?.id}`
          ? t('verification.action.saving') : t('verification.action.save')}>
        <div className="stack" style={{ gap: 10 }}>
          <label className="field">
            <span>{t('verification.field.value')}</span>
            <input value={editForm.value}
              onChange={(event) => { setEditForm((f) => ({ ...f, value: event.target.value })); setEditError('') }} />
          </label>
          <label className="field">
            <span>{t('verification.field.type')}</span>
            <select value={editForm.type}
              onChange={(event) => setEditForm((f) => ({ ...f, type: event.target.value }))}>
              {['domain', 'subdomain', 'url', 'ip', 'api', 'mobile_app'].map((kind) => (
                <option key={kind} value={kind}>{kind}</option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>{t('verification.field.notes')}</span>
            <textarea rows="2" value={editForm.notes}
              onChange={(event) => setEditForm((f) => ({ ...f, notes: event.target.value }))} />
          </label>
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>
            {t('verification.dialog.editHint')}
          </p>
          {editError && (
            <p role="alert" style={{ margin: 0, fontSize: 12.5, color: 'var(--err-fg)' }}>
              {editError}
            </p>
          )}
        </div>
      </Dialog>

      <Dialog open={Boolean(restoreRow)} title={t('verification.dialog.restore')}
        onClose={() => setRestoreRow(null)} onConfirm={restoreExclusion}
        confirmLabel={busy.startsWith('restore:')
          ? t('verification.action.lifting') : t('verification.action.liftExclusion')}>
        <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
          {t('verification.dialog.restoreA', {
            value: restoreRow?.permissions.passive_discovery.exclusion?.value })}{' '}
          <strong>{t('verification.dialog.restoreDisabled')}</strong>
          {t('verification.dialog.restoreB')}
        </p>
      </Dialog>

      <Dialog open={Boolean(excludeRow)}
        title={t('verification.dialog.exclude', { value: excludeRow?.value || '' })}
        onClose={() => setExcludeRow(null)}
        onConfirm={submitExclusion}
        confirmLabel={busy.startsWith('exclude:')
          ? t('verification.action.excluding') : t('verification.action.excludeFromCollection')}>
        <div className="stack" style={{ gap: 10 }}>
          <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
            {t('verification.dialog.excludeIntro')}
          </p>
          <label className="field">
            <span>{t('verification.field.reason')}</span>
            <input value={reason} placeholder={t('verification.field.reasonPlaceholder')}
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
