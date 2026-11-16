import React, { useEffect, useState } from 'react'
import { api, actorName } from './api'
import { useI18n } from './i18n'
import { Card, PageHeader, ErrorBanner } from './ui'

/* The review queue for what the agents propose.

   A candidate is a claim, not a finding: it names the request it thinks proves
   something. Validating it runs the gates (evidence, authorised target, replay) and
   only then does a finding exist. This screen exists so that step is a decision a
   person makes on evidence they can read — and so an empty cycle does not look like
   a broken engine. */

const STATE_TONE = {
  proposed: 'warn',
  validated: 'ok',
  promoted: 'ok',
  refuted: 'err',
  rejected: 'err',
}

export default function Candidates({ cycleId = '' }) {
  const { t } = useI18n()
  const [rows, setRows] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [outcome, setOutcome] = useState({})

  useEffect(() => { load() }, [cycleId])

  async function load() {
    try {
      const query = cycleId ? `?limit=100&cycle_id=${encodeURIComponent(cycleId)}` : '?limit=100'
      const response = await api.get(`/api/v1/agents/candidates${query}`)
      setRows(response.data || [])
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function promote(row, { acceptObservation = false } = {}) {
    setBusy(row.id)
    setError('')
    try {
      const response = await api.post(`/api/v1/agent/candidates/${row.id}/promote`, {
        validate: true,
        accept_observation: acceptObservation,
        actor: actorName(),
      })
      const data = response.data || {}
      const refuted = (data.gates?.stages || [])
        .filter((stage) => stage.confirmed === false && !String(stage.reason).startsWith('skipped'))
      const reasonText = data.reason
        || refuted.map((stage) => `${stage.stage}: ${stage.reason}`).join(' · ')
      setOutcome((prev) => ({
        ...prev,
        [row.id]: {
          state: data.promoted ? 'promoted' : 'refuted',
          findingId: data.finding_id,
          reason: reasonText,
        },
      }))
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="stack">
      <PageHeader title={t('candidates.title')} subtitle={t('candidates.lead')}
        actions={cycleId ? (
          <a className="mini" href={`#cycles::${cycleId}`}>{t('candidates.backToCycle')}</a>
        ) : null} />
      {error && <ErrorBanner error={error} />}

      <Card band>
        {rows === null ? (
          <p className="muted">{t('trace.loading')}</p>
        ) : rows.length === 0 ? (
          <div className="empty">
            <strong>{t('candidates.empty')}</strong>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t('candidates.col.title')}</th>
                <th>{t('candidates.col.state')}</th>
                <th>{t('candidates.col.evidence')}</th>
                <th>{t('candidates.col.mission')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const done = outcome[row.id]
                return (
                  <tr key={row.id}>
                    <td>
                      <div className="candidate-claim">{row.title}</div>
                      {done?.reason && (
                        <div className="muted">
                          {t('candidates.refuted', { reason: done.reason })}
                        </div>
                      )}
                    </td>
                    <td>
                      <span className={`chip ${STATE_TONE[row.state] || ''}`}>{row.state}</span>
                    </td>
                    <td className="muted">{(row.evidence || []).length}</td>
                    <td className="mono muted">{(row.mission_id || '—').slice(0, 8)}</td>
                    <td>
                      {/* A promoted candidate points at its finding: re-running the
                          gates on it would only create a second one. */}
                      {row.finding_id || done?.findingId ? (
                        <a href={`#findings::${row.finding_id || done.findingId}`}>
                          {t('candidates.open')}
                        </a>
                      ) : (row.claim_kind === 'observation' || row.state === 'rejected') ? (
                        /* Reachability, not exploitation: the gate will not file it as
                           a vulnerability, but a person may want the evidence kept —
                           as an exposure. */
                        <button className="mini" disabled={busy === row.id}
                          title={t('candidates.observationHint')}
                          onClick={() => promote(row, { acceptObservation: true })}>
                          {busy === row.id ? t('candidates.promoting') : t('candidates.acceptObservation')}
                        </button>
                      ) : (
                        <button className="primary-action" disabled={busy === row.id}
                          onClick={() => promote(row)}>
                          {busy === row.id ? t('candidates.promoting') : t('candidates.promote')}
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
