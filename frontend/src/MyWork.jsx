import React, { useEffect, useState } from 'react'
import { api, actorName } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, SeverityBadge, Table,
  Tabs, usePage,
} from './ui'
import { useI18n } from './i18n'

/* My work is six trays over persisted rows: findings assigned to me, work items
   awaiting my review, requests I made, acceptances about to expire and my
   tasks. A tray count is the length of the list beside it, always. */

const TRAYS = [
  { id: 'assigned_to_me', labelKey: 'myWork.tray.assigned' },
  { id: 'awaiting_my_review', labelKey: 'myWork.tray.awaitingReview' },
  { id: 'requested_by_me', labelKey: 'myWork.tray.requested' },
  { id: 'acceptances_expiring', labelKey: 'myWork.tray.acceptancesExpiring' },
  { id: 'my_tasks', labelKey: 'myWork.tray.myTasks' },
  { id: 'my_team', labelKey: 'myWork.tray.team' },
]

/* The decision verbs are values in the payload and labels on screen: the table
   stays, the label is resolved at render. */
const ACTIONS = [
  { value: 'approve', labelKey: 'myWork.decide.action.approve' },
  { value: 'reject', labelKey: 'myWork.decide.action.reject' },
  { value: 'withdraw', labelKey: 'myWork.decide.action.withdraw' },
  { value: 'remind', labelKey: 'myWork.decide.action.remind' },
  { value: 'start', labelKey: 'myWork.decide.action.start' },
  { value: 'complete', labelKey: 'myWork.decide.action.complete' },
]
const ACTION_LABEL_KEY = Object.fromEntries(ACTIONS.map((a) => [a.value, a.labelKey]))

export default function MyWork() {
  const { t, tOr } = useI18n()
  // Default to the person signed in. A tray asked as "console" is empty by
  // construction: the work is assigned to an address, and the address is the session.
  const [actor, setActor] = useState(
    () => localStorage.getItem('barad.actor') || actorName())
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
      .then((r) => {
        const next = r.data.trays || {}
        setTrays(next)
        // Open on a tray that has something in it: landing on an empty "assigned
        // to me" while 600 tasks wait one tab over reads like a broken screen.
        setTab((current) => {
          if ((next[current]?.count || 0) > 0) return current
          const first = TRAYS.find((tray) => (next[tray.id]?.count || 0) > 0)
          return first ? first.id : current
        })
      })
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
      setNotice(t('myWork.notice.created'))
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
      setNotice(t('myWork.notice.decisionApplied', {
        action: ACTION_LABEL_KEY[decision.action] ? t(ACTION_LABEL_KEY[decision.action]) : decision.action,
      }))
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
      total={paged.total} perPage={paged.perPage} unit={t('unit.rows')} />
  )

  return (
    <div className="stack">
      <PageHeader
        title={t('myWork.title')}
        subtitle={t('myWork.subtitle')}
        actions={<button className="primary-action" onClick={() => setCreating(true)}>{t('myWork.newItem')}</button>}
      />

      <div className="toolbar">
        <label className="field-label" htmlFor="actor">{t('myWork.actingAs')}</label>
        <input id="actor" value={actor} style={{ minWidth: 180 }}
          onChange={(e) => remember(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && load()} />
        <label className="check">
          <input type="checkbox" checked={window72}
            onChange={(e) => { setWindow72(e.target.checked) }} />
          <span>{t('myWork.window72')}</span>
        </label>
        <button className="mini" onClick={load}>{t('common.refresh')}</button>
        <span className="row-end">{pagerNode}</span>
      </div>

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      <Tabs
        tabs={TRAYS.map((tray) => ({
          id: tray.id, label: `${t(tray.labelKey)} (${(trays[tray.id] || {}).count || 0})`,
        }))}
        active={tab}
        onChange={setTab}
      />

      {tab === 'assigned_to_me' && (
        (current.findings || []).length ? (
          <Table head={[t('myWork.col.finding'), t('common.severity'), t('common.status'), t('myWork.col.sla')]}>
            {paged.rows.map((row) => (
              <tr key={row.id}>
                <td className="title">{row.title || row.id.slice(0, 8)}</td>
                <td><SeverityBadge severity={row.severity} /></td>
                <td className="muted">{tOr('status.' + row.status, row.status)}</td>
                <td className="muted">
                  {row.sla_deadline
                    ? new Date(row.sla_deadline).toLocaleDateString() : t('myWork.noSla')}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          !error && <EmptyState title={t('myWork.empty.assigned.title')}
            hint={t('myWork.empty.assigned.hint')} />
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
              {t('myWork.acceptancesWindow', { n: trays[tab].window_days })}
            </p>
          )}
          {(current.items || []).length ? (
            <Table head={[t('myWork.col.title'), t('myWork.col.kind'), t('common.status'),
              t('myWork.col.due'), t('myWork.col.assignee'), t('myWork.col.reviewer'), '']}>
              {paged.rows.map((row) => (
                <tr key={row.id}>
                  <td className="title">
                    {row.title}
                    {row.finding && (
                      <div className="muted" style={{ fontSize: 11.5 }}>
                        {t('myWork.item.finding', { title: row.finding.title })}
                      </div>
                    )}
                  </td>
                  <td><span className="pill">{tOr('myWork.kind.' + row.kind, row.kind)}</span></td>
                  <td className="muted">{tOr('status.' + row.status, row.status)}</td>
                  <td className="muted">
                    {row.due_at ? new Date(row.due_at).toLocaleString() : '—'}
                    {row.valid_until && (
                      <div style={{ fontSize: 11.5 }}>
                        {t('myWork.item.validUntil', { date: new Date(row.valid_until).toLocaleDateString() })}
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
                    }}>{t('myWork.action.act')}</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('myWork.empty.tray.title')}
              hint={t('myWork.empty.tray.hint')} />
          )}
        </>
      )}
      {tab !== 'assigned_to_me' && paged.pages > 1 && (
        <div className="row row-end">{pagerNode}</div>
      )}

      <Dialog open={creating} title={t('myWork.dialog.newTitle')}
        onClose={() => setCreating(false)} onConfirm={createItem} confirmLabel={t('myWork.dialog.create')}>
        <div className="stack">
          <select value={form.kind}
            onChange={(e) => setForm((s) => ({ ...s, kind: e.target.value }))}>
            <option value="task">{t('myWork.kind.task')}</option>
            <option value="request">{t('myWork.kind.request')}</option>
            <option value="acceptance">{t('myWork.kind.acceptance')}</option>
            <option value="review">{t('myWork.kind.review')}</option>
          </select>
          <Input label={t('myWork.field.title')} value={form.title}
            onChange={(v) => setForm((s) => ({ ...s, title: v }))} />
          <Input label={t('myWork.field.assignee')} value={form.assignee}
            onChange={(v) => setForm((s) => ({ ...s, assignee: v }))} />
          <Input label={t('myWork.field.reviewer')} value={form.reviewer}
            hint={t('myWork.field.reviewerHint')}
            onChange={(v) => setForm((s) => ({ ...s, reviewer: v }))} />
          <Input label={t('myWork.field.due')} type="date" value={form.due_at}
            onChange={(v) => setForm((s) => ({ ...s, due_at: v }))} />
        </div>
      </Dialog>

      <Dialog open={Boolean(decide)} title={t('myWork.decide.title', { title: decide?.title || '' })}
        onClose={() => setDecide(null)} onConfirm={submitDecision}
        confirmLabel={ACTION_LABEL_KEY[decision.action]
          ? t(ACTION_LABEL_KEY[decision.action]) : decision.action}>
        <div className="stack">
          <select value={decision.action}
            onChange={(e) => setDecision((d) => ({ ...d, action: e.target.value }))}>
            {ACTIONS.map((action) => (
              <option key={action.value} value={action.value}>{t(action.labelKey)}</option>
            ))}
          </select>
          <Input label={t('myWork.decide.reason')} textarea rows={3}
            value={decision.reason}
            onChange={(v) => setDecision((d) => ({ ...d, reason: v }))} />
          <span className="muted">
            {t('myWork.decide.selfApproval')}
          </span>
        </div>
      </Dialog>
    </div>
  )
}
