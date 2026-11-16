import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, Table, Tabs, usePage,
} from './ui'
import { useI18n } from './i18n'

/* Attack surface shows what was observed and never upgrades it into a claim:
   a 200 is an observed response, an excluded path is not evaluated, a lookalike
   is an external domain and confirming ownership is not a scan grant. */

const STATE_TONE = {
  candidate: 'muted',
  observed: 'pill',
  confirmed_finding: 'sev sev-high',
  excluded: 'sev sev-medium',
  not_evaluated: 'sev sev-medium',
  confirmed: 'pill',
  external: 'sev sev-medium',
  dismissed: 'muted',
}

export default function AttackSurface({ onNavigate }) {
  const { t, tOr } = useI18n()
  const [tab, setTab] = useState('web')
  const [endpoints, setEndpoints] = useState([])
  const [webCounters, setWebCounters] = useState({})
  const [note, setNote] = useState('')
  const [noteKey, setNoteKey] = useState('')
  const [lookalikes, setLookalikes] = useState([])
  const [lookCounts, setLookCounts] = useState({})
  const [weekly, setWeekly] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [decide, setDecide] = useState(null)
  const [decision, setDecision] = useState({ action: 'external', reason: '' })
  const [endpointState, setEndpointState] = useState(null)
  const [endpointForm, setEndpointForm] = useState({ state: 'observed', reason: '', finding_id: '' })

  // Each list arrives whole — it is what the last collector import produced, not
  // a window over something bigger — so the page is a reading aid, and every
  // table keeps its own place while the reader moves between tabs.
  const pagedEndpoints = usePage(endpoints, 25)
  const pagedLookalikes = usePage(lookalikes, 25)


  useEffect(() => {
    if (tab === 'web') loadWeb()
    if (tab === 'lookalikes') loadLookalikes()
    if (tab === 'weekly') loadWeekly()
  }, [tab])

  function loadWeb() {
    api.get('/api/v1/attack-surface/web-endpoints')
      .then((r) => { setEndpoints(r.data || []); setWebCounters(r.counters || {}); setNote(r.note || ''); setNoteKey(r.note_key || '') })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadLookalikes() {
    api.get('/api/v1/attack-surface/lookalikes')
      .then((r) => { setLookalikes(r.data || []); setLookCounts(r.counts || {}) })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadWeekly() {
    api.get('/api/v1/attack-surface/summary/weekly')
      .then((r) => setWeekly(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  async function submitEndpointState() {
    if (!endpointState) return
    try {
      await api.post(`/api/v1/attack-surface/web-endpoints/${endpointState.id}/state`, {
        state: endpointForm.state,
        reason: endpointForm.reason || null,
        finding_id: endpointForm.finding_id || null,
        actor: 'console',
      })
      setNotice(`${endpointState.path} → ${endpointForm.state}`)
      setEndpointState(null)
      loadWeb()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function submitLookalike() {
    if (!decide) return
    try {
      await api.post(`/api/v1/attack-surface/lookalikes/${decide.id}/decide`, {
        action: decision.action, reason: decision.reason || null, actor: 'console',
      })
      setNotice(`${decide.candidate} → ${decision.action}`)
      setDecide(null)
      loadLookalikes()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const stateLabel = (value) => tOr(`attackSurface.state.${value}`,
    String(value || '').replaceAll('_', ' '))

  return (
    <div className="stack">
      <PageHeader
        title={t('attackSurface.title')}
        subtitle={t('attackSurface.subtitle')}
        actions={onNavigate && (
          // This screen was a sidebar door of its own; the surface of the estate
          // is read from Assets, and the ownership queue it used to duplicate
          // lives in Assets → Needs attention.
          <button className="btn-ghost" onClick={() => onNavigate('assets')}>
            {t('nav.assets')} ←
          </button>
        )}
      />

      <Tabs
        tabs={[
          { id: 'web', label: t('attackSurface.tab.web') },
          { id: 'lookalikes', label: t('attackSurface.tab.lookalikes') },
          { id: 'weekly', label: t('attackSurface.tab.weekly') },
        ]}
        active={tab}
        onChange={setTab}
      />

      <p className="muted">{t('attackSurface.review.moved')}</p>

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {tab === 'web' && (
        <>
          <div className="toolbar">
            <span className="pill">{t('attackSurface.counter.endpoints', { n: webCounters.endpoints || 0 })}</span>
            <span className="pill">{t('attackSurface.counter.origins', { n: webCounters.origins || 0 })}</span>
            <span className="pill">{t('attackSurface.counter.new7d', { n: webCounters.new_last_7d || 0 })}</span>
            <span className="pill">{t('attackSurface.counter.notEvaluated', { n: webCounters.not_evaluated || 0 })}</span>
            <span className="pill">{t('attackSurface.counter.confirmed', { n: webCounters.confirmed || 0 })}</span>
            <span className="spacer" />
            <button className="mini" onClick={loadWeb}>{t('common.refresh')}</button>
            <Pager page={pagedEndpoints.page} pages={pagedEndpoints.pages}
              onChange={pagedEndpoints.setPage} total={pagedEndpoints.total}
              perPage={pagedEndpoints.perPage} unit={t('attackSurface.unit.endpoints')} className="row-end" />
          </div>
          {note && <p className="muted">{tOr(noteKey, note)}</p>}
          {endpoints.length ? (
            <Table head={[t('attackSurface.col.origin'), t('attackSurface.col.path'),
              t('attackSurface.col.method'), t('attackSurface.col.status'),
              t('attackSurface.col.state'), t('attackSurface.col.lastObserved'), '']}>
              {pagedEndpoints.rows.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.origin}</td>
                  <td className="title mono">{row.path}</td>
                  <td>{row.method}</td>
                  <td className="muted">{row.status_code || '—'}</td>
                  <td>
                    <span className={STATE_TONE[row.state] || 'pill'}>
                      {stateLabel(row.state)}
                    </span>
                    {row.evidence && (
                      <div className="muted" style={{ fontSize: 11.5 }}>{row.evidence}</div>
                    )}
                  </td>
                  <td className="muted">
                    {new Date(row.last_observed_at).toLocaleDateString()}
                  </td>
                  <td>
                    <button className="mini" onClick={() => {
                      setEndpointState(row)
                      setEndpointForm({ state: row.state, reason: '', finding_id: row.finding_id || '' })
                    }}>{t('attackSurface.web.state')}</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('attackSurface.web.empty.title')}
              hint={t('attackSurface.web.empty.hint')} />
          )}
          <Pager page={pagedEndpoints.page} pages={pagedEndpoints.pages}
            onChange={pagedEndpoints.setPage} total={pagedEndpoints.total}
            perPage={pagedEndpoints.perPage} unit={t('attackSurface.unit.endpoints')} className="row-end" />
        </>
      )}

      {tab === 'lookalikes' && (
        <>
          <div className="toolbar">
            {Object.entries(lookCounts).map(([key, value]) => (
              <span key={key} className="pill">{key} {value}</span>
            ))}
            <span className="spacer" />
            <span className="muted">{t('attackSurface.lookalikes.note')}</span>
            <Pager page={pagedLookalikes.page} pages={pagedLookalikes.pages}
              onChange={pagedLookalikes.setPage} total={pagedLookalikes.total}
              perPage={pagedLookalikes.perPage} unit={t('attackSurface.unit.candidates')} className="row-end" />
          </div>
          {lookalikes.length ? (
            <Table head={[t('attackSurface.lookalikes.col.root'),
              t('attackSurface.lookalikes.col.candidate'),
              t('attackSurface.lookalikes.col.similarity'),
              t('attackSurface.lookalikes.col.registration'),
              t('attackSurface.lookalikes.col.state'), '']}>
              {pagedLookalikes.rows.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.root_domain}</td>
                  <td className="title mono">{row.candidate}</td>
                  <td className="muted">{row.similarity || '—'}</td>
                  <td className="muted">
                    {row.registration_state}
                    {row.last_checked_at && (
                      <div style={{ fontSize: 11.5 }}>
                        {t('attackSurface.lookalikes.checked',
                          { date: new Date(row.last_checked_at).toLocaleDateString() })}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className={STATE_TONE[row.state] || 'pill'}>{stateLabel(row.state)}</span>
                    {row.review_reason && (
                      <div className="muted" style={{ fontSize: 11.5 }}>{row.review_reason}</div>
                    )}
                  </td>
                  <td>
                    <button className="mini" onClick={() => {
                      setDecide(row)
                      setDecision({ action: 'external', reason: '' })
                    }}>{t('attackSurface.lookalikes.review')}</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('attackSurface.lookalikes.empty.title')}
              hint={t('attackSurface.lookalikes.empty.hint')} />
          )}
          <Pager page={pagedLookalikes.page} pages={pagedLookalikes.pages}
            onChange={pagedLookalikes.setPage} total={pagedLookalikes.total}
            perPage={pagedLookalikes.perPage} unit={t('attackSurface.unit.candidates')} className="row-end" />
        </>
      )}


      {tab === 'weekly' && weekly && (
        <div className="detail">
          <dl>
            <dt>{t('attackSurface.weekly.window')}</dt>
            <dd className="muted">{t('attackSurface.weekly.lastDays', { n: weekly.window_days })}</dd>
            <dt>{t('attackSurface.weekly.changes')}</dt>
            <dd>
              {Object.entries(weekly.changes).length
                ? Object.entries(weekly.changes).map(([key, value]) => (
                  <span key={key} className="pill">{stateLabel(key)} {value}</span>
                ))
                : <span className="muted">{t('attackSurface.weekly.noChanges')}</span>}
            </dd>
            <dt>{t('attackSurface.weekly.newPaths')}</dt><dd>{weekly.new_paths}</dd>
            <dt>{t('attackSurface.weekly.lookalikes')}</dt><dd>{weekly.lookalike_candidates}</dd>
            <dt>{t('attackSurface.weekly.exposures')}</dt><dd>{weekly.open_exposures}</dd>
            <dt>{t('attackSurface.weekly.coverageGaps')}</dt><dd>{weekly.coverage_notes}</dd>
            <dt>{t('attackSurface.weekly.delivery')}</dt>
            <dd>
              {/* A sentence never wears a badge: `.sev` is nowrap, and a long
                  reason pushed the page sideways at 700px. */}
              <span className={weekly.delivery.configured ? 'pill' : 'sev sev-medium'}>
                {weekly.delivery.configured
                  ? t('attackSurface.weekly.configured')
                  : t('attackSurface.weekly.deliveryOff')}
              </span>
              {!weekly.delivery.configured && (
                <span className="muted"> {tOr(weekly.delivery.reason_key,
                  t('attackSurface.weekly.notConfigured', { reason: weekly.delivery.reason }))}</span>
              )}
            </dd>
          </dl>
        </div>
      )}

      <Dialog open={Boolean(endpointState)}
        title={t('attackSurface.stateDialog.title', { path: endpointState?.path || '' })}
        onClose={() => setEndpointState(null)} onConfirm={submitEndpointState}
        confirmLabel={t('attackSurface.stateDialog.confirm')}>
        <div className="stack">
          <select value={endpointForm.state}
            onChange={(e) => setEndpointForm((s) => ({ ...s, state: e.target.value }))}>
            <option value="candidate">{stateLabel('candidate')}</option>
            <option value="observed">{stateLabel('observed')}</option>
            <option value="confirmed_finding">{stateLabel('confirmed_finding')}</option>
            <option value="excluded">{stateLabel('excluded')}</option>
            <option value="not_evaluated">{stateLabel('not_evaluated')}</option>
          </select>
          <Input label={t('attackSurface.stateDialog.findingId')}
            value={endpointForm.finding_id}
            onChange={(value) => setEndpointForm((s) => ({ ...s, finding_id: value }))} />
          <Input label={t('attackSurface.stateDialog.reason')} textarea rows={2}
            value={endpointForm.reason}
            onChange={(value) => setEndpointForm((s) => ({ ...s, reason: value }))} />
        </div>
      </Dialog>

      <Dialog open={Boolean(decide)}
        title={t('attackSurface.reviewDialog.title', { name: decide?.candidate || '' })}
        onClose={() => setDecide(null)} onConfirm={submitLookalike}
        confirmLabel={t('attackSurface.apply')}>
        <div className="stack">
          <select value={decision.action}
            onChange={(e) => setDecision((d) => ({ ...d, action: e.target.value }))}>
            <option value="confirm">{t('attackSurface.lookalikeDialog.confirm')}</option>
            <option value="external">{t('attackSurface.lookalikeDialog.external')}</option>
            <option value="dismiss">{t('attackSurface.lookalikeDialog.dismiss')}</option>
          </select>
          <Input label={t('attackSurface.lookalikeDialog.reason')} textarea rows={3}
            value={decision.reason}
            onChange={(value) => setDecision((d) => ({ ...d, reason: value }))} />
          <span className="muted">{t('attackSurface.lookalikeDialog.note')}</span>
        </div>
      </Dialog>
    </div>
  )
}
