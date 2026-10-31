import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function Jira() {
  const [links, setLinks] = useState([])
  const [configured, setConfigured] = useState(true)
  const [error, setError] = useState('')
  const [recon, setRecon] = useState(null)
  const [form, setForm] = useState({ finding_id: '', project_key: '' })

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/jira/links')
      .then((r) => { setLinks(r.data); setConfigured(r.jira_configured) })
      .catch((e) => setError(String(e.message || e)))
  }

  async function createLink() {
    try {
      await api.post('/api/v1/jira/links', { ...form, actor: 'console' })
      setForm({ finding_id: '', project_key: '' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function sync(row, to_status) {
    try {
      await api.post(`/api/v1/jira/links/${row.id}/sync`,
        { actor: 'console', to_status })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function reconcile() {
    try {
      const r = await api.post('/api/v1/jira/reconcile', { actor: 'console' })
      setRecon(r.data)
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  return (
    <div>
      <div className="bar">
        <span className="count">{links.length} links</span>
        {!configured && <span className="pill warn">Jira not configured (JIRA_BASE_URL / JIRA_TOKEN)</span>}
        <button onClick={reconcile} disabled={!configured}>reconcile now</button>
      </div>
      {error && <p className="error">{error}</p>}
      {recon && (
        <p className="muted">
          checked {recon.checked} · drifted {recon.drifted} · errors {recon.errors} ·
          verification required: {recon.verification_required.length}
        </p>
      )}
      <table>
        <thead><tr><th>finding</th><th>issue</th><th>jira status</th><th>assignee</th><th>state</th><th></th></tr></thead>
        <tbody>
          {links.map((row) => (
            <tr key={row.id}>
              <td className="title">{row.finding_id.slice(0, 8)}</td>
              <td>{row.issue_key
                ? <a href={row.issue_url} target="_blank" rel="noreferrer">{row.issue_key}</a>
                : <span className="muted">pending</span>}</td>
              <td>{row.external_status || '—'}</td>
              <td>{row.external_assignee || '—'}</td>
              <td><span className={`status st-${row.sync_state}`}>{row.sync_state}</span></td>
              <td>
                <button className="mini" onClick={() => sync(row, 'In Progress')}
                  disabled={!configured || !row.issue_key}>→ in progress</button>{' '}
                <button className="mini" onClick={() => sync(row, 'Done')}
                  disabled={!configured || !row.issue_key}>→ done</button>
                {row.last_error && <div className="error small">{row.last_error}</div>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!links.length && !error && <p className="empty">No Jira links yet.</p>}
      <h2 className="section">link a finding</h2>
      <div className="card">
        <input placeholder="finding id" value={form.finding_id}
          onChange={(e) => setForm((f) => ({ ...f, finding_id: e.target.value }))} />
        <input placeholder="Jira project key (e.g. SEC)" value={form.project_key}
          onChange={(e) => setForm((f) => ({ ...f, project_key: e.target.value }))} />
        <button onClick={createLink} disabled={!configured}>create issue + link</button>
      </div>
      <p className="muted small">
        Jira is the source of truth only for its own workflow. A ticket moved to Done
        flags the link as verification_required — it never closes the finding.
      </p>
    </div>
  )
}
