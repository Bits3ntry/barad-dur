import React, { useEffect, useState } from 'react'
import { api } from './api'
import { PageHeader } from './ui'

const PRIORITY_CLASSES = ['P0', 'P1', 'P2', 'P3']

/** `initialTab` lets a dedicated menu entry open straight into its own view
    (Prioritization rules) instead of duplicating the screen. */
export default function Lifecycle({ initialTab = 'tasks' }) {
  const [tab, setTab] = useState(initialTab)
  const [tasks, setTasks] = useState([])
  const [rules, setRules] = useState([])
  const [policy, setPolicy] = useState(null)
  const [newTask, setNewTask] = useState('')
  const [newRule, setNewRule] = useState({ kind: 'secret', priority: 'P0', reason: '' })
  const [error, setError] = useState('')

  useEffect(() => { load() }, [tab])

  function load() {
    setError('')
    if (tab === 'tasks') {
      api.get('/api/v1/remediation/tasks').then((r) => setTasks(r.data)).catch((e) => setError(String(e.message || e)))
    } else if (tab === 'rules') {
      api.get('/api/v1/priority-rules').then((r) => setRules(r.data)).catch((e) => setError(String(e.message || e)))
      api.get('/api/v1/sla/policies').then((r) => setPolicy(r.data.find(p => p.is_default) || r.data[0] || null)).catch(() => {})
    }
  }

  async function createTask() {
    if (!newTask.trim()) return
    await api.post('/api/v1/remediation/tasks', { title: newTask.trim(), actor: 'console' })
    setNewTask(''); load()
  }

  async function setTaskStatus(task, status) {
    await api.patch(`/api/v1/remediation/tasks/${task.id}`, { status, changed_by: 'console' })
    load()
  }

  async function unlink(task, finding) {
    await api.del(`/api/v1/remediation/tasks/${task.id}/findings/${finding.id}`)
    load()
  }

  async function createRule() {
    if (!newRule.reason.trim()) { setError('rule reason required'); return }
    await api.post('/api/v1/priority-rules', {
      match_kind: newRule.kind, priority: newRule.priority,
      reason: newRule.reason.trim(), position: 100,
    })
    setNewRule((r) => ({ ...r, reason: '' })); load()
  }

  async function savePolicy() {
    await api.post('/api/v1/sla/policies', { ...policy, make_default: true })
    load()
  }

  return (
    <div className="stack">
      <PageHeader
        title={initialTab === 'rules' ? 'Prioritization rules' : 'Remediation'}
        subtitle={initialTab === 'rules'
          ? 'First match wins; a finding with no match keeps the severity fallback and shows it'
          : undefined} />
      <div className="toolbar">
        <select value={tab} onChange={(e) => setTab(e.target.value)}>
          <option value="tasks">remediation tasks</option>
          <option value="rules">priority rules</option>
        </select>
        <span className="count">{tab === 'tasks'
          ? `${tasks.length} task${tasks.length === 1 ? '' : 's'}`
          : `${rules.length} rule${rules.length === 1 ? '' : 's'}`}</span>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      {tab === 'tasks' && (
        <>
          <div className="toolbar">
            <input placeholder="new task title" value={newTask}
              onChange={(e) => setNewTask(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && createTask()} />
            <button onClick={createTask}>create task</button>
          </div>
          <table>
            <thead>
              <tr><th>title</th><th>status</th><th>findings</th><th>actions</th></tr>
            </thead>
            <tbody>
              {tasks.map((t) => (
                <tr key={t.id}>
                  <td className="title">{t.title}</td>
                  <td><span className={`status st-${t.status}`}>{t.status}</span></td>
                  <td>
                    {t.findings.length === 0 && <span className="muted">—</span>}
                    {t.findings.map((f) => (
                      <span key={f.id} className="pill">
                        {f.rule_id || f.kind} ({f.priority || '?'})
                        {t.status !== 'resolved' &&
                          <button className="mini" onClick={() => unlink(t, f)}>×</button>}
                      </span>
                    ))}
                  </td>
                  <td>
                    {t.status === 'open' && <button onClick={() => setTaskStatus(t, 'in_progress')}>start</button>}
                    {t.status !== 'resolved' && <button onClick={() => setTaskStatus(t, 'resolved')}>resolve</button>}
                    {t.status === 'resolved' && <button onClick={() => setTaskStatus(t, 'open')}>reopen</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {tab === 'rules' && (
        <>
          <div className="toolbar">
            <select value={newRule.kind} onChange={(e) => setNewRule((r) => ({ ...r, kind: e.target.value }))}>
              <option value="secret">secret</option>
              <option value="misconfiguration">misconfiguration</option>
              <option value="code-weakness">code-weakness</option>
              <option value="vulnerability">vulnerability</option>
            </select>
            <select value={newRule.priority} onChange={(e) => setNewRule((r) => ({ ...r, priority: e.target.value }))}>
              {PRIORITY_CLASSES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
            <input placeholder="reason (auditable)" value={newRule.reason}
              onChange={(e) => setNewRule((r) => ({ ...r, reason: e.target.value }))} />
            <button className="primary-action" onClick={createRule}>add rule</button>
          </div>
          <table>
            <thead><tr><th>pos</th><th>when</th><th>becomes</th><th>reason</th></tr></thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td>{r.position}</td>
                  <td>{r.match_kind}{r.match_source && ` src=${r.match_source}`}{r.match_severities && ` sev∈${r.match_severities}`}</td>
                  <td><span className={`prio prio-${r.priority.toLowerCase()}`}>{r.priority}</span></td>
                  <td>{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {policy && (
            <div className="toolbar">
              <span className="muted">SLA default policy:</span>
              <label>P0→<input type="number" size="2" value={policy.p0_days} onChange={(e) => setPolicy({ ...policy, p0_days: +e.target.value })} />d</label>
              <label>P1→<input type="number" size="2" value={policy.p1_days} onChange={(e) => setPolicy({ ...policy, p1_days: +e.target.value })} />d</label>
              <label>P2→<input type="number" size="2" value={policy.p2_days} onChange={(e) => setPolicy({ ...policy, p2_days: +e.target.value })} />d</label>
              <label>P3→<input type="number" size="2" value={policy.p3_days} onChange={(e) => setPolicy({ ...policy, p3_days: +e.target.value })} />d</label>
              <button onClick={savePolicy}>save policy</button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
