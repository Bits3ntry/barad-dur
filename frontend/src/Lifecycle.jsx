import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import {
  Banner, Card, ConfirmButton, Drawer, EmptyState, ErrorBanner, Loading, PageHeader,
  Pill, SeverityBadge, Table, Tabs,
} from './ui'
import { useI18n } from './i18n'

/* Remediación is two questions about one object, so it is one screen with two
   tabs — not two sidebar doors that opened the same component through an
   internal `<select>`. `initialTab` stays for the legacy `#priority-rules` link.

   The screen's own rule drives its layout: a task is the change that closes a
   group of findings, and a task with nothing attached is a diligence. So the
   row leads with the work (title), then the claims it closes, and the action
   that moves it forward is the only primary button on the row. "Sin hallazgo"
   is not a quieter state — it is the one thing on this page that needs fixing
   before anything else can be said about it. */

const PRIORITY_CLASSES = ['P0', 'P1', 'P2', 'P3']
const STATUSES = ['open', 'in_progress', 'resolved']

const KIND_LABELS = Object.fromEntries([
  ['secret', 'lifecycle.kind.secret'],
  ['misconfiguration', 'lifecycle.kind.misconfiguration'],
  ['code-weakness', 'lifecycle.kind.codeWeakness'],
  ['vulnerability', 'lifecycle.kind.vulnerability'],
])

const KINDS = [
  { value: 'secret', labelKey: 'lifecycle.kind.secret' },
  { value: 'misconfiguration', labelKey: 'lifecycle.kind.misconfiguration' },
  { value: 'code-weakness', labelKey: 'lifecycle.kind.codeWeakness' },
  { value: 'vulnerability', labelKey: 'lifecycle.kind.vulnerability' },
]

/* A policy that does not exist yet has to be writable from here, with a starting
   point: the editor used to render only when a policy was already in the
   database, so a fresh organisation had no way to define the first one. */
const DRAFT_POLICY = {
  id: null, name: 'Standard', p0_days: 7, p1_days: 30, p2_days: 90,
  p3_days: 180, is_default: true,
}

/* ── attaching a finding ──────────────────────────────────────────────────────
   The task form only asks for a title, and a title closes no finding. This
   picker is the missing half: search the estate, pick the claim, link it. */
function FindingSearch({ task, onLinked }) {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [rows, setRows] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const timer = useRef(null)

  useEffect(() => {
    clearTimeout(timer.current)
    // Same pause-then-ask as the scan wizard: one request per search, not per key.
    timer.current = setTimeout(() => {
      api.get(`/api/v1/findings?limit=12${query.trim() ? `&q=${encodeURIComponent(query.trim())}` : ''}`)
        .then((body) => setRows((body.data || body.findings || []).slice(0, 12)))
        .catch((caught) => setError(String(caught.message || caught)))
    }, 300)
    return () => clearTimeout(timer.current)
  }, [query])

  async function link(finding) {
    setBusy(true); setError('')
    try {
      await api.post(`/api/v1/remediation/tasks/${task.id}/findings`,
                     { finding_id: finding.id, actor: 'console' })
      // The search does not own the drawer: it reports, and whoever mounted it
      // decides whether that means closing (the row's drawer) or staying open
      // (inside the task sheet, where you may attach a second finding).
      onLinked?.()
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setBusy(false) }
  }

  return (
    <div className="stack">
      <input className="pick-search" autoFocus value={query}
             placeholder={t('lifecycle.attach.search')}
             onChange={(event) => setQuery(event.target.value)} />
        {error && <ErrorBanner error={error} />}
        {rows === null && <Loading />}
        {rows !== null && rows.length === 0 && (
          <EmptyState title={t('lifecycle.attach.empty')} hint={t('lifecycle.attach.empty.hint')} />
        )}
        {rows !== null && rows.length > 0 && (
          <ul className="pick-list">
            {rows.map((finding) => (
              <li key={finding.id}>
                <button type="button" className="pick-row" disabled={busy}
                        onClick={() => link(finding)}>
                  <SeverityBadge severity={finding.severity} />
                  <span className="pick-title" title={finding.title}>{finding.title}</span>
                  <span className="muted mono">
                    {finding.rule_id || finding.cve_id || finding.kind || ''}
                  </span>
                  {finding.priority && (
                    <span className={`prio prio-${String(finding.priority).toLowerCase()}`}>
                      {finding.priority}
                    </span>
                  )}
                  <span className="pick-go">{t('lifecycle.attach.pick')}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
    </div>
  )
}

function FindingsPicker({ open, task, onClose, onLinked }) {
  const { t } = useI18n()
  return (
    <Drawer open={open} title={t('lifecycle.attach.title', { task: task?.title || '' })}
            onClose={onClose}>
      <FindingSearch task={task}
                     onLinked={() => { onLinked?.(); onClose() }} />
    </Drawer>
  )
}

/* ── the task sheet ───────────────────────────────────────────────────────────
   What the list cannot hold: the owner, a title worth fixing once you know the
   work, and the task's own history. The history is the audit chain filtered to
   this row — a sheet that tells its own story is a story nobody can verify. */
const EVENTS = {
  'remediation.created': 'lifecycle.event.created',
  'remediation.status': 'lifecycle.event.status',
  'remediation.owner': 'lifecycle.event.owner',
  'remediation.renamed': 'lifecycle.event.renamed',
  'remediation.linked': 'lifecycle.event.linked',
  'remediation.unlinked': 'lifecycle.event.unlinked',
}

function stamp(value) {
  if (!value) return '—'
  try { return new Date(value).toLocaleString() } catch { return value }
}

function TaskSheet({ taskId, onClose, onChanged }) {
  const { t, tOr, tCount } = useI18n()
  const [task, setTask] = useState(null)
  const [form, setForm] = useState({ title: '', owner: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [saved, setSaved] = useState(false)
  const [attaching, setAttaching] = useState(false)

  useEffect(() => {
    if (!taskId) return
    setTask(null); setError(''); setAttaching(false)
    reload()
  }, [taskId])  // eslint-disable-line react-hooks/exhaustive-deps

  function reload() {
    api.get(`/api/v1/remediation/tasks/${taskId}`)
      .then((body) => {
        setTask(body.data)
        setForm({ title: body.data.title, owner: body.data.owner || '' })
      })
      .catch((caught) => setError(String(caught.message || caught)))
  }

  async function patch(body) {
    setBusy(true); setError('')
    try {
      await api.patch(`/api/v1/remediation/tasks/${taskId}`,
                      { ...body, changed_by: 'console' })
      reload(); onChanged?.()
      setSaved(true)
      setTimeout(() => setSaved(false), 3500)
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setBusy(false) }
  }

  async function unlink(finding) {
    setBusy(true)
    try {
      await api.del(`/api/v1/remediation/tasks/${taskId}/findings/${finding.id}`)
      reload(); onChanged?.()
    } catch (caught) { setError(String(caught.message || caught)) } finally { setBusy(false) }
  }

  if (!task) {
    return (
      <Drawer open title={t('lifecycle.sheet.title')} onClose={onClose}>
        {error ? <ErrorBanner error={error} /> : <Loading />}
      </Drawer>
    )
  }

  const dirty = form.title.trim() !== task.title
    || (form.owner || '').trim() !== (task.owner || '')

  return (
    <Drawer open title={t('lifecycle.sheet.title')} onClose={onClose}>
      <div className="stack">
        {error && <ErrorBanner error={error} />}

        <label className="sheet-field">
          <span className="muted">{t('lifecycle.sheet.field.title')}</span>
          <input value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} />
        </label>
        <label className="sheet-field">
          <span className="muted">{t('lifecycle.sheet.field.owner')}</span>
          <input value={form.owner} placeholder={t('lifecycle.sheet.field.owner.ph')}
                 onChange={(event) => setForm({ ...form, owner: event.target.value })} />
        </label>
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          <button className="btn-primary" disabled={!dirty || busy}
                  onClick={() => patch({
                    ...(form.title.trim() !== task.title ? { title: form.title.trim() } : {}),
                    ...((form.owner || '').trim() !== (task.owner || '')
                      ? { owner: form.owner.trim() } : {}),
                  })}>
            {t('lifecycle.sheet.save')}
          </button>
          {saved && <span className="muted">{t('lifecycle.sheet.saved')}</span>}
        </div>

        <div>
          <span className="muted">{t('lifecycle.sheet.status')}</span>
          <div className="row" style={{ gap: 6, marginTop: 4 }}>
            {STATUSES.map((status) => (
              <button key={status} type="button"
                      className={`pill rem-count${task.status === status ? ' is-on' : ''}`}
                      disabled={busy}
                      onClick={() => patch({ status })}>
                {tOr(`remediation.status.${status}`, status)}
              </button>
            ))}
          </div>
        </div>

        <div>
          <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline' }}>
            <span className="muted">{tCount('lifecycle.sheet.claims', task.findings.length)}</span>
            {task.status !== 'resolved' && (
              <button className="btn-ghost rem-attach" onClick={() => setAttaching((v) => !v)}>
                + {t('lifecycle.action.attach')}
              </button>
            )}
          </div>
          {task.findings.length === 0 && (
            <p className="muted">{t('lifecycle.sheet.claims.empty')}</p>
          )}
          <ul className="sheet-claims">
            {task.findings.map((finding) => (
              <li key={finding.id}>
                <SeverityBadge severity={finding.severity} />
                <button className="linkish sheet-claim-title" title={finding.title}
                        onClick={() => { window.location.hash = `findings::${finding.id}` }}>
                  {finding.title}
                </button>
                <span className="muted mono">{finding.rule_id || finding.kind}</span>
                {finding.priority && (
                  <span className={`prio prio-${String(finding.priority).toLowerCase()}`}>{finding.priority}</span>
                )}
                {task.status !== 'resolved' && (
                  <ConfirmButton confirmLabel={t('lifecycle.action.unlink')}
                                 onConfirm={() => unlink(finding)}>×</ConfirmButton>
                )}
              </li>
            ))}
          </ul>
          {attaching && (
            <div style={{ marginTop: 10 }}>
              <FindingSearch task={task}
                             onLinked={() => { setAttaching(false); reload(); onChanged?.() }} />
            </div>
          )}
        </div>

        <div>
          <span className="muted">{t('lifecycle.sheet.history')}</span>
          {task.history.length === 0
            ? <p className="muted">{t('lifecycle.sheet.history.empty')}</p>
            : (
              <ul className="sheet-history">
                {task.history.map((row, index) => (
                  <li key={index}>
                    <span className="muted">{stamp(row.at)}</span>
                    <span>{tOr(EVENTS[row.action], row.action.replace('remediation.', ''))}</span>
                    {row.detail && (
                      <span className="mono muted">
                        {row.detail === '-' ? t('lifecycle.sheet.owner.none') : row.detail}
                      </span>
                    )}
                    <span className="muted">{row.actor}</span>
                  </li>
                ))}
              </ul>
            )}
          <p className="muted">
            {t('lifecycle.sheet.times', { created: stamp(task.created_at), updated: stamp(task.updated_at) })}
          </p>
        </div>
      </div>
    </Drawer>
  )
}

/* ── one row ────────────────────────────────────────────────────────────────── */

function nextAction(task) {
  if (task.status === 'open') return { status: 'in_progress', key: 'lifecycle.action.start' }
  if (task.status === 'in_progress') return { status: 'resolved', key: 'lifecycle.action.resolve' }
  return { status: 'open', key: 'lifecycle.action.reopen' }
}

function TaskRow({ task, onStatus, onUnlink, onAttach, onOpen }) {
  const { t, tOr } = useI18n()
  const step = nextAction(task)
  const loose = task.findings.length === 0
  return (
    <tr className={loose ? 'is-loose' : ''}>
      <td className="title">
        {/* The title is the row's door: the sheet is where a task is renamed,
            assigned and read, and burying that behind a "⋯" hides the object. */}
        <button className="linkish rem-title" title={task.title}
                onClick={() => onOpen(task)}>{task.title}</button>
        {task.owner && <span className="muted rem-owner">{task.owner}</span>}
      </td>
      <td>
        <span className={`status st-${task.status}`}>
          {tOr(`remediation.status.${task.status}`, task.status)}
        </span>
      </td>
      <td className="rem-findings">
        {loose && <Pill tone="warn">{t('lifecycle.noFindings')}</Pill>}
        {task.findings.map((finding) => (
          <span key={finding.id} className="pill rem-claim">
            <button className="linkish"
                    title={finding.title || finding.kind}
                    onClick={() => { window.location.hash = `findings::${finding.id}` }}>
              {finding.rule_id || finding.cve_id || finding.kind}
            </button>
            {finding.priority && <span className="muted"> {finding.priority}</span>}
            {task.status !== 'resolved' && (
              <ConfirmButton confirmLabel={t('lifecycle.action.unlink')}
                             onConfirm={() => onUnlink(task, finding)}>
                ×
              </ConfirmButton>
            )}
          </span>
        ))}
        {task.status !== 'resolved' && (
          <button className="btn-ghost rem-attach" onClick={() => onAttach(task)}>
            + {t('lifecycle.action.attach')}
          </button>
        )}
      </td>
      <td className="rem-actions">
        <button className="btn-primary" onClick={() => onStatus(task, step.status)}>
          {t(step.key)}
        </button>
      </td>
    </tr>
  )
}

/* ── the screen ─────────────────────────────────────────────────────────────── */

export default function Lifecycle({ initialTab = 'tasks' }) {
  const { t, tCount, tOr } = useI18n()
  const [tab, setTab] = useState(initialTab)
  const [tasks, setTasks] = useState(null)
  const [rules, setRules] = useState([])
  const [policy, setPolicy] = useState(null)
  const [policySaved, setPolicySaved] = useState(false)
  const [newTask, setNewTask] = useState('')
  const [filter, setFilter] = useState('all')
  const [attaching, setAttaching] = useState(null)
  const [sheet, setSheet] = useState(null)
  const [newRule, setNewRule] = useState({ kind: 'secret', priority: 'P0', reason: '' })
  const [error, setError] = useState('')
  const [reload, setReload] = useState(0)

  useEffect(() => { load() }, [tab, reload])  // eslint-disable-line react-hooks/exhaustive-deps

  function load() {
    setError('')
    if (tab === 'tasks') {
      api.get('/api/v1/remediation/tasks')
        .then((r) => setTasks(r.data || []))
        .catch((e) => setError(String(e.message || e)))
    } else if (tab === 'rules') {
      api.get('/api/v1/priority-rules').then((r) => setRules(r.data)).catch((e) => setError(String(e.message || e)))
      api.get('/api/v1/sla/policies')
        .then((r) => setPolicy(r.data.find(p => p.is_default) || r.data[0] || { ...DRAFT_POLICY }))
        .catch(() => setPolicy({ ...DRAFT_POLICY }))
    }
  }

  async function createTask() {
    if (!newTask.trim()) return
    try {
      const created = await api.post('/api/v1/remediation/tasks',
                                     { title: newTask.trim(), actor: 'console' })
      setNewTask('')
      setReload((n) => n + 1)
      // A task born empty is the one state the screen calls a diligence: open the
      // picker straight away instead of leaving the person with a warning.
      if (created?.data?.id) setAttaching({ id: created.data.id, title: created.data.title, findings: [] })
    } catch (caught) { setError(String(caught.message || caught)) }
  }

  async function setTaskStatus(task, status) {
    await api.patch(`/api/v1/remediation/tasks/${task.id}`, { status, changed_by: 'console' })
    setReload((n) => n + 1)
  }

  async function unlink(task, finding) {
    await api.del(`/api/v1/remediation/tasks/${task.id}/findings/${finding.id}`)
    setReload((n) => n + 1)
  }

  async function createRule() {
    if (!newRule.reason.trim()) { setError(t('lifecycle.error.reasonRequired')); return }
    await api.post('/api/v1/priority-rules', {
      match_kind: newRule.kind, priority: newRule.priority,
      reason: newRule.reason.trim(), position: 100,
    })
    setNewRule((r) => ({ ...r, reason: '' })); load()
  }

  async function savePolicy() {
    setError('')
    try {
      // One save for both cases: a policy that exists is edited, one that does
      // not is created. Posting the same name again was a 409, which read as
      // "the policy is there" while the days never changed.
      if (policy.id) {
        await api.patch(`/api/v1/sla/policies/${policy.id}`, {
          name: policy.name, p0_days: policy.p0_days, p1_days: policy.p1_days,
          p2_days: policy.p2_days, p3_days: policy.p3_days, make_default: true,
          actor: 'console',
        })
      } else {
        await api.post('/api/v1/sla/policies', {
          name: policy.name, p0_days: policy.p0_days, p1_days: policy.p1_days,
          p2_days: policy.p2_days, p3_days: policy.p3_days, make_default: true,
        })
      }
      setPolicySaved(true)
      setTimeout(() => setPolicySaved(false), 3500)
      load()
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }

  const counts = useMemo(() => ({
    open: (tasks || []).filter((task) => task.status === 'open').length,
    in_progress: (tasks || []).filter((task) => task.status === 'in_progress').length,
    resolved: (tasks || []).filter((task) => task.status === 'resolved').length,
    loose: (tasks || []).filter((task) => !task.findings.length).length,
  }), [tasks])

  const visible = useMemo(() => (tasks || [])
    .filter((task) => filter === 'all' || task.status === filter), [tasks, filter])

  return (
    <div className="stack">
      <PageHeader
        title={tab === 'rules' ? t('lifecycle.title.rules') : t('lifecycle.title.remediation')}
        subtitle={tab === 'rules' ? t('lifecycle.subtitle.rules') : t('lifecycle.subtitle.tasks')} />
      <Tabs
        tabs={[
          { id: 'tasks', label: t('lifecycle.tab.tasks') },
          { id: 'rules', label: t('lifecycle.tab.rules') },
        ]}
        active={tab}
        onChange={setTab}
      />
      {error && <Banner kind="error">{error}</Banner>}

      {tab === 'tasks' && (
        <>
          {tasks === null ? <Loading /> : (
            <>
              {/* The board is worked by exception: the counts are the states still
                  moving, and a task with no finding is called out separately
                  because it is not a state — it is a task that cannot close. */}
              <div className="row rem-strip">
                {STATUSES.map((status) => (
                  <button key={status} type="button"
                          className={`pill rem-count${filter === status ? ' is-on' : ''}`}
                          onClick={() => setFilter(filter === status ? 'all' : status)}>
                    {tOr(`remediation.status.${status}`, status)} · {counts[status]}
                  </button>
                ))}
                {counts.loose > 0 && (
                  <Pill tone="warn">{t('lifecycle.loose.count', { n: counts.loose })}</Pill>
                )}
                {filter !== 'all' && (
                  <button className="btn-ghost" onClick={() => setFilter('all')}>
                    {t('lifecycle.filter.clear')}
                  </button>
                )}
              </div>

              <div className="toolbar rem-new">
                <input placeholder={t('lifecycle.placeholder.newTask')} value={newTask}
                       aria-label={t('lifecycle.placeholder.newTask')}
                       onChange={(e) => setNewTask(e.target.value)}
                       onKeyDown={(e) => e.key === 'Enter' && createTask()} />
                <button className="btn-primary" onClick={createTask} disabled={!newTask.trim()}>
                  {t('lifecycle.action.createTask')}
                </button>
              </div>

              {tasks.length === 0 ? (
                <EmptyState title={t('lifecycle.empty.title')} hint={t('lifecycle.empty.tasks')} />
              ) : visible.length === 0 ? (
                <EmptyState title={t('lifecycle.empty.filtered')} hint={t('lifecycle.filter.clear.hint')} />
              ) : (
                <Table className="rem-tasks"
                       head={[t('lifecycle.col.title'), t('common.status'),
                              t('lifecycle.col.findings'), t('common.actions')]}>
                  {visible.map((task) => (
                    <TaskRow key={task.id} task={task}
                             onStatus={setTaskStatus} onUnlink={unlink}
                             onAttach={(row) => setAttaching(row)}
                             onOpen={(row) => setSheet(row.id)} />
                  ))}
                </Table>
              )}
            </>
          )}
        </>
      )}

      {tab === 'rules' && (
        <>
          <Card title={t('lifecycle.rule.new')}>
            <div className="toolbar">
              <select value={newRule.kind} onChange={(e) => setNewRule((r) => ({ ...r, kind: e.target.value }))}
                      aria-label={t('lifecycle.col.when')}>
                {KINDS.map((kind) => (
                  <option key={kind.value} value={kind.value}>{t(kind.labelKey)}</option>
                ))}
              </select>
              <select value={newRule.priority} onChange={(e) => setNewRule((r) => ({ ...r, priority: e.target.value }))}
                      aria-label={t('lifecycle.col.becomes')}>
                {PRIORITY_CLASSES.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
              <input placeholder={t('lifecycle.placeholder.reason')} value={newRule.reason}
                     aria-label={t('lifecycle.placeholder.reason')}
                     onChange={(e) => setNewRule((r) => ({ ...r, reason: e.target.value }))} />
              <button className="btn-primary" onClick={createRule} disabled={!newRule.reason.trim()}>
                {t('lifecycle.action.addRule')}
              </button>
            </div>
          </Card>

          <span className="count">{tCount('lifecycle.count.rules', rules.length)}</span>
          <Table head={[t('lifecycle.col.pos'), t('lifecycle.col.when'),
                        t('lifecycle.col.becomes'), t('lifecycle.col.reason')]}>
            {rules.map((r) => (
              <tr key={r.id}>
                <td className="muted">{r.position}</td>
                <td>
                  <Pill>{t(KIND_LABELS[r.match_kind] || r.match_kind)}</Pill>
                  {r.match_source && <span className="muted"> · {r.match_source}</span>}
                </td>
                <td><span className={`prio prio-${r.priority.toLowerCase()}`}>{r.priority}</span></td>
                <td className="muted">{r.reason}</td>
              </tr>
            ))}
          </Table>

          {policy && (
            <Card title={t('lifecycle.sla.card')}
                  actions={(
                    <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                      {policySaved && <span className="muted">{t('lifecycle.sla.saved')}</span>}
                      <button className="btn-primary" onClick={savePolicy}>
                        {t('lifecycle.action.savePolicy')}
                      </button>
                    </div>
                  )}>
              <p className="muted">
                {policy.id ? t('lifecycle.sla.label') : t('lifecycle.sla.unset')}
              </p>
              <div className="rem-sla">
                {PRIORITY_CLASSES.map((priority) => {
                  const field = `${priority.toLowerCase()}_days`
                  return (
                    <label key={priority} className="rem-sla-field">
                      <span className={`prio prio-${priority.toLowerCase()}`}>{priority}</span>
                      <input type="number" min="1" max="365" value={policy[field]}
                             onChange={(e) => setPolicy({ ...policy, [field]: +e.target.value })} />
                      <span className="muted">{t('lifecycle.sla.days')}</span>
                    </label>
                  )
                })}
              </div>
              {!policy.id && <p className="muted">{t('lifecycle.sla.hint')}</p>}
            </Card>
          )}
        </>
      )}

      {sheet && (
        <TaskSheet taskId={sheet} onClose={() => setSheet(null)}
                   onChanged={() => setReload((n) => n + 1)} />
      )}

      {attaching && (
        <FindingsPicker open onClose={() => setAttaching(null)}
                        task={attaching}
                        onLinked={() => setReload((n) => n + 1)} />
      )}
    </div>
  )
}
