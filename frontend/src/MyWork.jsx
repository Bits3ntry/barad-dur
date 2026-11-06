import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, SeverityBadge, Table,
  Tabs, usePage,
} from './ui'

/* My work is six trays over persisted rows: findings assigned to me, work items
   awaiting my review, requests I made, acceptances about to expire and my
   tasks. A tray count is the length of the list beside it, always. */

const TRAYS = [
  { id: 'assigned_to_me', label: 'Assigned to me' },
  { id: 'awaiting_my_review', label: 'Awaiting my review' },
  { id: 'requested_by_me', label: 'Requested by me' },
  { id: 'acceptances_expiring', label: 'Acceptances expiring' },
  { id: 'my_tasks', label: 'My tasks' },
  { id: 'my_team', label: 'Organization queue' },
]

export default function MyWork() {
  const [actor, setActor] = useState(
    () => localStorage.getItem('barad.actor') || 'console')
  const [trays, setTrays] = useState({})
  const [tab, setTab] = useState('assigned_to_me')
  const [window72, setWindow72] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({
    kind: 'task', title: '', assignee: '', reviewer: '', due_at: '',
  })
  const [decide, setDecide] = useState(null)
  const [decision, setDecision] = useState({ action: 'approve', reason: '' })

  useEffect(() => { load() }, [])

  function load() {
    const params = new URLSearchParams({ actor: actor.trim() || 'console' })
    if (window72) params.set('due_within_hours', '72')
    api.get(`/api/v1/my-work?${params}`)
      .then((r) => setTrays(r.data.trays || {}))
      .catch((e) => setError(String(e.message || e)))
  }

  function remember(value) {
    setActor(value)
    localStorage.setItem('barad.actor', value)
  }

  async function createItem() {
    if (!form.title.trim()) return
    try {
      await api.post('/api/v1/my-work/items', {
        kind: form.kind,
        title: form.title.trim(),
        assignee: form.assignee || null,
        requested_by: actor,
        reviewer: form.reviewer || null,
        due_at: form.due_at ? `${form.due_at}T00:00:00+00:00` : null,
        actor,
      })
      setCreating(false)
      setForm({ kind: 'task', title: '', assignee: '', reviewer: '', due_at: '' })
      setNotice('work item created')
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function submitDecision() {
    if (!decide) return
    try {
      await api.post(`/api/v1/my-work/items/${decide.id}/decide`, {
        action: decision.action, reason: decision.reason || null, actor,
      })
      setNotice(`${decision.action} applied`)
      setDecide(null)
      setDecision({ action: 'approve', reason: '' })
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const current = trays[tab] || { count: 0, items: [] }
  // A tray arrives whole — it is one person's queue, not the organization's
  // findings — so paging it here costs no extra request and no server contract.
  const paged = usePage(tab === 'assigned_to_me'
    ? (current.findings || []) : (current.items || []), 25)
  const pagerNode = (
    <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
      total={paged.total} perPage={paged.perPage} unit="rows" />
  )

  return (
    <div className="stack">
      <PageHeader
        title="My work"
        subtitle="Queues built from assignments, requests, tasks and acceptances — no static mock"
        actions={<button className="primary-action" onClick={() => setCreating(true)}>new work item</button>}
      />

      <div className="toolbar">
        <label className="field-label" htmlFor="actor">acting as</label>
        <input id="actor" value={actor} style={{ minWidth: 180 }}
          onChange={(e) => remember(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && load()} />
        <label className="check">
          <input type="checkbox" checked={window72}
            onChange={(e) => { setWindow72(e.target.checked) }} />
          <span>next 72h (including overdue)</span>
        </label>
        <button className="mini" onClick={load}>refresh</button>
        <span className="row-end">{pagerNode}</span>
      </div>

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      <Tabs
        tabs={TRAYS.map((tray) => ({
          id: tray.id, label: `${tray.label} (${(trays[tray.id] || {}).count || 0})`,
        }))}
        active={tab}
        onChange={setTab}
      />

      {tab === 'assigned_to_me' && (
        (current.findings || []).length ? (
          <Table head={['finding', 'severity', 'status', 'SLA']}>
            {paged.rows.map((row) => (
              <tr key={row.id}>
                <td className="title">{row.title || row.id.slice(0, 8)}</td>
                <td><SeverityBadge severity={row.severity} /></td>
                <td className="muted">{row.status}</td>
                <td className="muted">
                  {row.sla_deadline
                    ? new Date(row.sla_deadline).toLocaleDateString() : 'no SLA'}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          !error && <EmptyState title="Nothing assigned to you"
            hint="Assign a finding to this identity and it appears here." />
        )
      )}
      {tab === 'assigned_to_me' && paged.pages > 1 && (
        <div className="row row-end">{pagerNode}</div>
      )}

      {tab !== 'assigned_to_me' && (
        <>
          {trays[tab]?.note && <p className="muted">{trays[tab].note}</p>}
          {trays[tab]?.window_days && (
            <p className="muted">
              acceptances are listed when they expire within {trays[tab].window_days} days
            </p>
          )}
          {(current.items || []).length ? (
            <Table head={['title', 'kind', 'status', 'due', 'assignee', 'reviewer', '']}>
              {paged.rows.map((row) => (
                <tr key={row.id}>
                  <td className="title">
                    {row.title}
                    {row.finding && (
                      <div className="muted" style={{ fontSize: 11.5 }}>
                        finding: {row.finding.title}
                      </div>
                    )}
                  </td>
                  <td><span className="pill">{row.kind}</span></td>
                  <td className="muted">{row.status}</td>
                  <td className="muted">
                    {row.due_at ? new Date(row.due_at).toLocaleString() : '—'}
                    {row.valid_until && (
                      <div style={{ fontSize: 11.5 }}>
                        valid until {new Date(row.valid_until).toLocaleDateString()}
                      </div>
                    )}
                  </td>
                  <td className="muted">{row.assignee || '—'}</td>
                  <td className="muted">{row.reviewer || '—'}</td>
                  <td>
                    <button className="mini" onClick={() => {
                      setDecide(row)
                      setDecision({ action: row.reviewer === actor ? 'approve' : 'remind',
                        reason: '' })
                    }}>act</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="This tray is empty"
              hint="A tray shows only rows you are entitled to see for this identity." />
          )}
        </>
      )}
      {tab !== 'assigned_to_me' && paged.pages > 1 && (
        <div className="row row-end">{pagerNode}</div>
      )}

      <Dialog open={creating} title="New work item"
        onClose={() => setCreating(false)} onConfirm={createItem} confirmLabel="create">
        <div className="stack">
          <select value={form.kind}
            onChange={(e) => setForm((s) => ({ ...s, kind: e.target.value }))}>
            <option value="task">task</option>
            <option value="request">decision request</option>
            <option value="acceptance">acceptance</option>
            <option value="review">review</option>
          </select>
          <Input label="title" value={form.title}
            onChange={(v) => setForm((s) => ({ ...s, title: v }))} />
          <Input label="assignee" value={form.assignee}
            onChange={(v) => setForm((s) => ({ ...s, assignee: v }))} />
          <Input label="reviewer" value={form.reviewer}
            hint="must be somebody other than the requester"
            onChange={(v) => setForm((s) => ({ ...s, reviewer: v }))} />
          <Input label="due" type="date" value={form.due_at}
            onChange={(v) => setForm((s) => ({ ...s, due_at: v }))} />
        </div>
      </Dialog>

      <Dialog open={Boolean(decide)} title={`Act on ${decide?.title || ''}`}
        onClose={() => setDecide(null)} onConfirm={submitDecision}
        confirmLabel={decision.action}>
        <div className="stack">
          <select value={decision.action}
            onChange={(e) => setDecision((d) => ({ ...d, action: e.target.value }))}>
            <option value="approve">approve</option>
            <option value="reject">reject</option>
            <option value="withdraw">withdraw (requester)</option>
            <option value="remind">remind (requester, once an hour)</option>
            <option value="start">start</option>
            <option value="complete">complete</option>
          </select>
          <Input label="reason (required for approve / reject)" textarea rows={3}
            value={decision.reason}
            onChange={(v) => setDecision((d) => ({ ...d, reason: v }))} />
          <span className="muted">
            Self-approval is refused by the backend, not by hiding the button.
          </span>
        </div>
      </Dialog>
    </div>
  )
}
