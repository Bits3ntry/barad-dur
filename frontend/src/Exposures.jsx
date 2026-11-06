import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, Select, SeverityBadge,
  Table, Tabs, usePage,
} from './ui'

/* Exposures manages the condition that needs a decision; Changes is the
   technical chronology derived from observations. They share observations but
   never duplicate an event per scan: the same condition bumps `occurrences`. */

const DECISION_LABEL = {
  resolve: 'resolve', accept: 'accept with validity', false_positive: 'false positive',
  reopen: 'reopen',
}

/* The endpoints answer these lists whole, so the screen slices them. A page
   this size keeps the toolbar and the first rows in one glance. */
const PER_PAGE = 25

export default function Exposures() {
  const [tab, setTab] = useState('overview')
  const [events, setEvents] = useState([])
  const [counts, setCounts] = useState({})
  const [changes, setChanges] = useState([])
  const [changeCounts, setChangeCounts] = useState({})
  const [notes, setNotes] = useState([])
  const [summaries, setSummaries] = useState([])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [filter, setFilter] = useState({ state: 'open', kind: '' })
  const [decide, setDecide] = useState(null)
  const [decision, setDecision] = useState({ action: 'resolve', reason: '', valid_until: '' })

  // Each tab's list is sliced on its own: paging the changes table must not
  // move the exposures page. The hook clamps itself when a load shrinks a list.
  const pagedEvents = usePage(events, PER_PAGE)
  const pagedChanges = usePage(changes, PER_PAGE)

  // A new filter is a new question, not the fourth page of the old answer.
  useEffect(() => { pagedEvents.setPage(0) }, [filter.state, filter.kind])

  useEffect(() => { loadExposures() }, [filter.state, filter.kind])
  useEffect(() => { if (tab === 'changes') loadChanges() }, [tab])
  useEffect(() => { if (tab === 'summaries') loadSummaries() }, [tab])

  function loadExposures() {
    const params = new URLSearchParams()
    if (filter.state) params.set('state', filter.state)
    if (filter.kind) params.set('kind', filter.kind)
    api.get(`/api/v1/exposures?${params}`)
      .then((r) => { setEvents(r.data || []); setCounts(r.counts || {}) })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadChanges() {
    api.get('/api/v1/attack-surface/changes?days=14')
      .then((r) => {
        setChanges(r.data || [])
        setChangeCounts(r.counts || {})
        setNotes(r.coverage_notes || [])
      })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadSummaries() {
    api.get('/api/v1/exposures/summary/findings')
      .then((r) => setSummaries(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  async function submitDecision() {
    if (!decide) return
    setError('')
    try {
      await api.post(`/api/v1/exposures/${decide.id}/decide`, {
        action: decision.action,
        reason: decision.reason || null,
        valid_until: decision.action === 'accept' && decision.valid_until
          ? `${decision.valid_until}T00:00:00+00:00` : null,
        actor: 'console',
      })
      setNotice(`${decision.action} applied to ${decide.kind} on ${decide.asset?.value || 'asset'}`)
      setDecide(null)
      setDecision({ action: 'resolve', reason: '', valid_until: '' })
      loadExposures()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Exposures"
        subtitle={`${counts.open || 0} open · ${counts.accepted || 0} accepted · ${counts.resolved || 0} resolved`}
      />

      <Tabs
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'changes', label: 'Changes' },
          { id: 'summaries', label: 'Secrets · Code · Misconfig · CVEs' },
        ]}
        active={tab}
        onChange={setTab}
      />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {tab === 'overview' && (
        <>
          <div className="toolbar">
            <select value={filter.state}
              onChange={(e) => setFilter((f) => ({ ...f, state: e.target.value }))}>
              <option value="open">open</option>
              <option value="accepted">accepted</option>
              <option value="resolved">resolved</option>
              <option value="false_positive">false positive</option>
              <option value="">every state</option>
            </select>
            <select value={filter.kind}
              onChange={(e) => setFilter((f) => ({ ...f, kind: e.target.value }))}>
              <option value="">every kind</option>
              <option value="open_port">open port</option>
              <option value="new_host">new host</option>
              <option value="certificate_expiring">certificate expiring</option>
              <option value="dangling_dns">dangling DNS</option>
              <option value="host_disappeared">host disappeared</option>
              <option value="dns_changed">DNS changed</option>
              <option value="technology_changed">technology changed</option>
            </select>
            <button className="mini" onClick={loadExposures}>refresh</button>
            <Pager page={pagedEvents.page} pages={pagedEvents.pages}
              onChange={pagedEvents.setPage} total={pagedEvents.total}
              perPage={PER_PAGE} unit="exposures" className="row-end" />
          </div>

          {events.length ? (
            <Table head={['kind', 'asset', 'severity', 'seen', 'occurrences', 'state', '']}>
              {pagedEvents.rows.map((row) => (
                <tr key={row.id}>
                  <td className="title">
                    {row.kind.replaceAll('_', ' ')}
                    <div className="muted" style={{ fontSize: 11.5 }}>{row.title}</div>
                  </td>
                  <td className="mono">{row.asset?.value || '—'}</td>
                  <td><SeverityBadge severity={row.severity} /></td>
                  <td className="muted">
                    {new Date(row.last_seen_at).toLocaleDateString()}
                    <div style={{ fontSize: 11.5 }}>
                      first {new Date(row.first_seen_at).toLocaleDateString()}
                    </div>
                  </td>
                  <td>{row.occurrences}</td>
                  <td>
                    <span className={row.state === 'open' ? 'sev sev-medium' : 'pill'}>
                      {row.state}
                    </span>
                    {row.decision_reason && (
                      <div className="muted" style={{ fontSize: 11.5 }}>
                        {row.decision_reason}
                      </div>
                    )}
                  </td>
                  <td>
                    <button className="mini" onClick={() => setDecide(row)}>decide</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="No exposure events"
              hint="Events appear when an imported observation shows a new host, a newly open port, a dangling alias or an expiring certificate." />
          )}

          <Pager page={pagedEvents.page} pages={pagedEvents.pages}
            onChange={pagedEvents.setPage} total={pagedEvents.total}
            perPage={PER_PAGE} unit="exposures" className="row-end" />
        </>
      )}

      {tab === 'changes' && (
        <>
          <div className="toolbar">
            {Object.entries(changeCounts).map(([key, value]) => (
              <span key={key} className="pill">{key.replaceAll('_', ' ')} {value}</span>
            ))}
            <span className="spacer" />
            <span className="muted">last 14 days · derived from observations</span>
            <Pager page={pagedChanges.page} pages={pagedChanges.pages}
              onChange={pagedChanges.setPage} total={pagedChanges.total}
              perPage={PER_PAGE} unit="changes" className="row-end" />
          </div>
          {changes.length ? (
            <Table head={['when', 'category', 'asset', 'before', 'after', 'source']}>
              {pagedChanges.rows.map((row, index) => (
                <tr key={`${row.asset_id}-${row.category}-${index}`}>
                  <td className="muted">{new Date(row.observed_at).toLocaleString()}</td>
                  <td><span className="pill">{row.category.replaceAll('_', ' ')}</span></td>
                  <td className="mono">{row.asset?.value || row.subject}</td>
                  <td className="muted mono">
                    {Array.isArray(row.before) ? row.before.join(', ') : (row.before ?? '—')}
                  </td>
                  <td className="mono">
                    {Array.isArray(row.after) ? row.after.join(', ') : (row.after ?? '—')}
                  </td>
                  <td className="muted">{row.source}</td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="No changes in the window"
              hint="Import observations twice: the first establishes a baseline, the second produces comparable changes." />
          )}

          <Pager page={pagedChanges.page} pages={pagedChanges.pages}
            onChange={pagedChanges.setPage} total={pagedChanges.total}
            perPage={PER_PAGE} unit="changes" className="row-end" />

          {notes.length > 0 && (
            <div className="detail">
              <dl>
                <dt>coverage gaps</dt>
                <dd className="muted">
                  {notes.map((note, index) => (
                    <div key={index} className="occ-row">{note.asset_id}: {note.note}</div>
                  ))}
                </dd>
              </dl>
            </div>
          )}
        </>
      )}

      {tab === 'summaries' && (
        <>
          <p className="muted">
            These four are filtered views over the same findings, not copies. Opening a
            row means the same record the Findings screen manages.
          </p>
          {summaries.length ? (
            <Table head={['kind', 'total', 'open', 'by severity', 'findings']}>
              {summaries.map((row) => (
                <tr key={row.kind}>
                  <td className="title">{row.kind.replaceAll('-', ' ')}</td>
                  <td>{row.total}</td>
                  <td>{row.open}</td>
                  <td className="muted">
                    {Object.entries(row.severity).map(([severity, count]) => (
                      <span key={severity} className="pill">{severity} {count}</span>
                    ))}
                  </td>
                  <td className="muted mono">
                    {row.finding_ids.slice(0, 3).map((id) => id.slice(0, 8)).join(', ')}
                    {row.finding_ids.length > 3 ? '…' : ''}
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="No findings to summarise yet"
              hint="Secrets, code weaknesses and misconfigurations come from imports and manual findings; vulnerabilities from advisory matching." />
          )}
        </>
      )}

      <Dialog open={Boolean(decide)} title={`Decide on ${decide?.kind || ''}`}
        onClose={() => setDecide(null)} onConfirm={submitDecision}
        confirmLabel={DECISION_LABEL[decision.action]}>
        <div className="stack">
          <p className="muted">
            {decide?.asset?.value} · seen {decide?.occurrences} time(s)
          </p>
          <Select label="action" value={decision.action}
            options={Object.entries(DECISION_LABEL).map(([value, label]) => ({ value, label }))}
            onChange={(value) => setDecision((d) => ({ ...d, action: value }))} />
          <Input label="reason (required for a decision)" textarea rows={3}
            value={decision.reason}
            onChange={(value) => setDecision((d) => ({ ...d, reason: value }))} />
          {decision.action === 'accept' && (
            <Input label="accepted until" type="date" value={decision.valid_until}
              hint="reopens automatically after this date"
              onChange={(value) => setDecision((d) => ({ ...d, valid_until: value }))} />
          )}
          <span className="muted">
            Accepting keeps the condition out of the open queue only for the chosen window;
            the event and its history are kept either way.
          </span>
        </div>
      </Dialog>
    </div>
  )
}
