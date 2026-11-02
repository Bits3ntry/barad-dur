import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Table, Tabs,
} from './ui'

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

export default function AttackSurface() {
  const [tab, setTab] = useState('web')
  const [endpoints, setEndpoints] = useState([])
  const [webCounters, setWebCounters] = useState({})
  const [note, setNote] = useState('')
  const [lookalikes, setLookalikes] = useState([])
  const [lookCounts, setLookCounts] = useState({})
  const [review, setReview] = useState([])
  const [weekly, setWeekly] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [decide, setDecide] = useState(null)
  const [decision, setDecision] = useState({ action: 'external', reason: '' })
  const [endpointState, setEndpointState] = useState(null)
  const [endpointForm, setEndpointForm] = useState({ state: 'observed', reason: '', finding_id: '' })

  useEffect(() => {
    if (tab === 'web') loadWeb()
    if (tab === 'lookalikes') loadLookalikes()
    if (tab === 'review') loadReview()
    if (tab === 'weekly') loadWeekly()
  }, [tab])

  function loadWeb() {
    api.get('/api/v1/attack-surface/web-endpoints')
      .then((r) => { setEndpoints(r.data || []); setWebCounters(r.counters || {}); setNote(r.note || '') })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadLookalikes() {
    api.get('/api/v1/attack-surface/lookalikes')
      .then((r) => { setLookalikes(r.data || []); setLookCounts(r.counts || {}) })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadReview() {
    api.get('/api/v1/attack-surface/review')
      .then((r) => setReview(r.data || []))
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

  async function submitReview() {
    if (!decide?.asset) return
    try {
      await api.post(`/api/v1/attack-surface/review/${decide.asset.id}`, {
        action: decision.action, reason: decision.reason || null, actor: 'console',
      })
      setNotice(`${decide.asset.value} → ${decision.action}`)
      setDecide(null)
      loadReview()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Attack surface"
        subtitle="Observed surface and pending ownership decisions · no screen here runs a collector"
      />

      <Tabs
        tabs={[
          { id: 'web', label: 'Web surface' },
          { id: 'lookalikes', label: 'Lookalikes' },
          { id: 'review', label: `Review${review.length ? ` (${review.length})` : ''}` },
          { id: 'weekly', label: 'Weekly summary' },
        ]}
        active={tab}
        onChange={setTab}
      />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {tab === 'web' && (
        <>
          <div className="toolbar">
            <span className="pill">{webCounters.endpoints || 0} endpoints</span>
            <span className="pill">{webCounters.origins || 0} origins</span>
            <span className="pill">{webCounters.new_last_7d || 0} new in 7d</span>
            <span className="pill">{webCounters.not_evaluated || 0} not evaluated</span>
            <span className="pill">{webCounters.confirmed || 0} confirmed</span>
            <span className="spacer" />
            <button className="mini" onClick={loadWeb}>refresh</button>
          </div>
          {note && <p className="muted">{note}</p>}
          {endpoints.length ? (
            <Table head={['origin', 'path', 'method', 'status', 'state', 'last observed', '']}>
              {endpoints.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.origin}</td>
                  <td className="title mono">{row.path}</td>
                  <td>{row.method}</td>
                  <td className="muted">{row.status_code || '—'}</td>
                  <td>
                    <span className={STATE_TONE[row.state] || 'pill'}>
                      {row.state.replaceAll('_', ' ')}
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
                    }}>state</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="No web paths imported"
              hint="Use POST /api/v1/attack-surface/web-endpoints with a crawler or report output. An empty list means no crawling has been imported." />
          )}
        </>
      )}

      {tab === 'lookalikes' && (
        <>
          <div className="toolbar">
            {Object.entries(lookCounts).map(([key, value]) => (
              <span key={key} className="pill">{key} {value}</span>
            ))}
            <span className="spacer" />
            <span className="muted">
              passive only: DNS/CT evidence, never an HTTP contact
            </span>
          </div>
          {lookalikes.length ? (
            <Table head={['root', 'candidate', 'similarity', 'registration', 'state', '']}>
              {lookalikes.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.root_domain}</td>
                  <td className="title mono">{row.candidate}</td>
                  <td className="muted">{row.similarity || '—'}</td>
                  <td className="muted">
                    {row.registration_state}
                    {row.last_checked_at && (
                      <div style={{ fontSize: 11.5 }}>
                        checked {new Date(row.last_checked_at).toLocaleDateString()}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className={STATE_TONE[row.state] || 'pill'}>{row.state}</span>
                    {row.review_reason && (
                      <div className="muted" style={{ fontSize: 11.5 }}>{row.review_reason}</div>
                    )}
                  </td>
                  <td>
                    <button className="mini" onClick={() => {
                      setDecide(row)
                      setDecision({ action: 'external', reason: '' })
                    }}>review</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="No lookalikes"
              hint="Import a watched root domain and its candidates; DNS resolving alone is never treated as registration or malice." />
          )}
        </>
      )}

      {tab === 'review' && (
        <>
          <p className="muted">
            Assets whose ownership is unsettled. Confirming an asset is ours does not
            authorize testing it, and an IP observed under a domain may belong to a CDN.
          </p>
          {review.length ? (
            <Table head={['asset', 'type', 'source', 'classification', 'observations', '']}>
              {review.map((row) => (
                <tr key={row.asset.id}>
                  <td className="title mono">{row.asset.value}</td>
                  <td className="muted">{row.asset.type}</td>
                  <td className="muted">{row.asset.source}</td>
                  <td>
                    <span className="sev sev-medium">{row.asset.classification_status}</span>
                  </td>
                  <td>{row.observations}</td>
                  <td>
                    <button className="mini" onClick={() => {
                      setDecide(row)
                      setDecision({ action: 'confirm', reason: '' })
                    }}>decide</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="Nothing to review"
              hint="Every asset has a settled ownership decision." />
          )}
        </>
      )}

      {tab === 'weekly' && weekly && (
        <div className="detail">
          <dl>
            <dt>window</dt><dd className="muted">last {weekly.window_days} days</dd>
            <dt>changes</dt>
            <dd>
              {Object.entries(weekly.changes).length
                ? Object.entries(weekly.changes).map(([key, value]) => (
                  <span key={key} className="pill">{key.replaceAll('_', ' ')} {value}</span>
                ))
                : <span className="muted">no comparable changes in the window</span>}
            </dd>
            <dt>new paths</dt><dd>{weekly.new_paths}</dd>
            <dt>lookalike candidates</dt><dd>{weekly.lookalike_candidates}</dd>
            <dt>open exposures</dt><dd>{weekly.open_exposures}</dd>
            <dt>coverage gaps</dt><dd>{weekly.coverage_notes}</dd>
            <dt>delivery</dt>
            <dd className={weekly.delivery.configured ? '' : 'sev sev-medium'}>
              {weekly.delivery.configured
                ? 'configured'
                : `not configured — ${weekly.delivery.reason}`}
            </dd>
          </dl>
        </div>
      )}

      <Dialog open={Boolean(endpointState)} title={`State for ${endpointState?.path || ''}`}
        onClose={() => setEndpointState(null)} onConfirm={submitEndpointState}
        confirmLabel="set state">
        <div className="stack">
          <select value={endpointForm.state}
            onChange={(e) => setEndpointForm((s) => ({ ...s, state: e.target.value }))}>
            <option value="candidate">candidate</option>
            <option value="observed">observed</option>
            <option value="confirmed_finding">confirmed finding</option>
            <option value="excluded">excluded</option>
            <option value="not_evaluated">not evaluated</option>
          </select>
          <Input label="finding id (required for confirmed finding)"
            value={endpointForm.finding_id}
            onChange={(value) => setEndpointForm((s) => ({ ...s, finding_id: value }))} />
          <Input label="reason (required for excluded / not evaluated)" textarea rows={2}
            value={endpointForm.reason}
            onChange={(value) => setEndpointForm((s) => ({ ...s, reason: value }))} />
        </div>
      </Dialog>

      <Dialog open={Boolean(decide) && Boolean(decide?.asset)}
        title={`Review ${decide?.asset?.value || ''}`}
        onClose={() => setDecide(null)} onConfirm={submitReview} confirmLabel="apply">
        <div className="stack">
          <select value={decision.action}
            onChange={(e) => setDecision((d) => ({ ...d, action: e.target.value }))}>
            <option value="confirm">confirm ownership</option>
            <option value="external">external / not ours</option>
            <option value="discard">discard</option>
          </select>
          <Input label="reason (required for external / discard)" textarea rows={3}
            value={decision.reason}
            onChange={(value) => setDecision((d) => ({ ...d, reason: value }))} />
          <span className="muted">
            Ownership is inventory truth, not authorization.
          </span>
        </div>
      </Dialog>

      <Dialog open={Boolean(decide) && !decide?.asset}
        title={`Review ${decide?.candidate || ''}`}
        onClose={() => setDecide(null)} onConfirm={submitLookalike} confirmLabel="apply">
        <div className="stack">
          <select value={decision.action}
            onChange={(e) => setDecision((d) => ({ ...d, action: e.target.value }))}>
            <option value="confirm">confirm impersonation</option>
            <option value="external">external — not ours</option>
            <option value="dismiss">dismiss</option>
          </select>
          <Input label="reason (required for external / dismiss)" textarea rows={3}
            value={decision.reason}
            onChange={(value) => setDecision((d) => ({ ...d, reason: value }))} />
          <span className="muted">
            Lookalikes are never contacted and never added to scope.
          </span>
        </div>
      </Dialog>
    </div>
  )
}
