import React, { useState } from 'react'
import { api } from './api'
import { ErrorBanner } from './ui'
import { useI18n } from './i18n'

/* The gate, from the console (F3): four independent axes, and the API refuses the
   move when the artifact behind a claim does not exist. The panel does not
   pre-validate — it shows the refusal, because that refusal is the product.

   It lives here, not inside the list screen, because the finding page is where a
   claim is judged: the queue is where it is noticed. */
export default function TriagePanel({ detail, onChanged }) {
  const { t } = useI18n()
  const [move, setMove] = useState({ status: '', level: '', note: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  async function send() {
    setBusy(true)
    setError('')
    setNotice('')
    const payload = { actor: 'console' }
    if (move.status) payload.triage_status = move.status
    if (move.level) payload.evidence_level = move.level
    if (move.status && move.note) payload.note = move.note
    try {
      await api.post(`/api/v1/findings/${detail.id}/triage`, payload)
      setNotice(t('findings.triage.recorded', {
        fields: Object.keys(payload).filter((k) => k !== 'actor').join(', '),
      }))
      setMove({ status: '', level: '', note: '' })
      onChanged?.()
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  /* The flow the finding is actually for: one click opens the task that closes
     it, with the finding already attached, and lands on the board where the work
     is tracked. Two calls, and the refusal (a finding can only be in one open
     task) is the server's, shown as-is. */
  async function openRemediation() {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const created = await api.post('/api/v1/remediation/tasks', {
        title: (detail.title || '').slice(0, 200),
        owner: detail.assignee || null,
        actor: 'console',
      })
      await api.post(`/api/v1/remediation/tasks/${created.data.id}/findings`,
        { finding_id: detail.id, actor: 'console' })
      onChanged?.()
      window.location.hash = 'remediation'
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  const axes = [
    ['findings.triage.axis.origin', detail.origin],
    ['findings.triage.axis.triage', detail.triage_status],
    ['findings.triage.axis.proof', detail.evidence_level],
    ['findings.triage.axis.impact', detail.exploit_state],
  ]

  return (
    <div className="detail">
      {/* Where it came from, when it came from an exercise: the cycle owns the
          window and the scope, so the page points at it instead of printing
          "manual" over a pentest finding. */}
      {detail.cycle && (
        <p className="muted" style={{ margin: '0 0 6px' }}>
          {t('findings.triage.fromCycle', { kind: detail.cycle.kind })}{' '}
          <button className="linkish"
            onClick={() => { window.location.hash = `cycles::${detail.cycle.id}` }}>
            {detail.cycle.name}
          </button>
        </p>
      )}
      <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
        {axes.map(([labelKey, value]) => (
          <span key={labelKey} className={`pill triage-${value}`} title={t(labelKey)}>
            {t(labelKey)}: {value || '—'}
          </span>
        ))}
        {detail.triaged_by && (
          <span className="muted" style={{ fontSize: 11.5 }}>
            {t('findings.triage.by', { who: detail.triaged_by })}
            {detail.triaged_at ? ` · ${new Date(detail.triaged_at).toLocaleString()}` : ''}
          </span>
        )}
      </div>
      {detail.triage_note && <p className="muted">“{detail.triage_note}”</p>}
      <div className="row" style={{ gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
        <select value={move.status} onChange={(e) => setMove({ ...move, status: e.target.value })}>
          <option value="">{t('findings.triage.verdict')}</option>
          <option value="triaged">{t('findings.triage.verdict.triaged')}</option>
          <option value="accepted">{t('findings.triage.verdict.accepted')}</option>
          <option value="rejected">{t('findings.triage.verdict.rejected')}</option>
          <option value="duplicate">{t('findings.triage.verdict.duplicate')}</option>
        </select>
        <select value={move.level} onChange={(e) => setMove({ ...move, level: e.target.value })}>
          <option value="">{t('findings.triage.proof')}</option>
          <option value="hypothesis">{t('findings.triage.level.hypothesis')}</option>
          <option value="static">{t('findings.triage.level.static')}</option>
          <option value="observed">{t('findings.triage.level.observed')}</option>
          <option value="demonstrated">{t('findings.triage.level.demonstrated')}</option>
        </select>
        <input placeholder={t('findings.triage.notePlaceholder')} value={move.note}
          onChange={(e) => setMove({ ...move, note: e.target.value })} />
        <button className="mini" disabled={busy || (!move.status && !move.level)}
          onClick={send}>{t('findings.triage.record')}</button>
        {/* The other half of triage: a confirmed finding needs a task, and making
            the reader walk to Remediación and retype the title is how a board
            stays empty. */}
        <button className="mini" disabled={busy} onClick={openRemediation}>
          {t('findings.triage.remediation')}
        </button>
      </div>
      {error && <ErrorBanner error={error} />}
      {notice && <p className="muted ok">{notice}</p>}
      <p className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>
        {t('findings.triage.rule')}
      </p>
    </div>
  )
}
