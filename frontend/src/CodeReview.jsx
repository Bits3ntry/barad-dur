import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function CodeReview({ projects }) {
  const [prs, setPrs] = useState([])
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [context, setContext] = useState({})
  const [diffs, setDiffs] = useState({})
  const [error, setError] = useState('')
  const [form, setForm] = useState({ number: '', title: '', project: '', version: '' })

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/code/pull-requests')
      .then((r) => setPrs(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  async function open(pr) {
    if (selected === pr.id) { setSelected(null); setDetail(null); return }
    setSelected(pr.id)
    try {
      const r = await api.get(`/api/v1/code/pull-requests/${pr.id}/findings`)
      setDetail(r.data)
    } catch (e) { setError(String(e.message || e)) }
  }

  async function showContext(finding) {
    if (context[finding.finding_id]) {
      setContext((c) => { const next = { ...c }; delete next[finding.finding_id]; return next })
      return
    }
    try {
      const r = await api.get(`/api/v1/code/findings/${finding.finding_id}/context?radius=4`)
      setContext((c) => ({ ...c, [finding.finding_id]: r.data }))
    } catch (e) { setError(String(e.message || e)) }
  }

  async function showDiff(path) {
    if (diffs[path]) {
      setDiffs((d) => { const next = { ...d }; delete next[path]; return next })
      return
    }
    try {
      const r = await api.get(`/api/v1/code/pull-requests/${selected}/diff`)
      const file = (r.data.files || []).find((f) => f.path === path)
      setDiffs((d) => ({ ...d, [path]: file }))
    } catch (e) { setError(String(e.message || e)) }
  }

  async function createPr() {
    try {
      await api.post('/api/v1/code/pull-requests', {
        number: Number(form.number), title: form.title, project: form.project,
        version: form.version, actor: 'console',
      })
      setForm({ number: '', title: '', project: '', version: '' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function publish(pr) {
    try {
      const r = await api.post(`/api/v1/code/pull-requests/${pr.id}/publish`,
        { actor: 'console' })
      window.alert(`published ${r.data.state} to ${r.data.repository}`)
    } catch (e) { setError(String(e.message || e)) }
  }

  async function setStatus(pr, status) {
    try {
      await api.post(`/api/v1/code/pull-requests/${pr.id}/status`, { status, actor: 'console' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  const project = projects.find((p) => p.name === form.project)

  return (
    <div>
      <div className="bar">
        <span className="count">{prs.length} pull requests</span>
        <button onClick={load}>refresh</button>
      </div>
      {error && <p className="error">{error}</p>}
      <table>
        <thead><tr><th>PR</th><th>title</th><th>gate</th><th>new / existing</th><th>status</th><th></th></tr></thead>
        <tbody>
          {prs.map((pr) => (
            <React.Fragment key={pr.id}>
              <tr className={selected === pr.id ? 'selected' : ''}>
                <td className="title">#{pr.number}</td>
                <td>{pr.title || '—'}</td>
                <td>{pr.gate_verdict
                  ? <span className={`status st-${pr.gate_verdict}`}>{pr.gate_verdict}</span>
                  : <span className="muted">not scanned</span>}</td>
                <td>{pr.counts?.new || 0} / {pr.counts?.existing || 0}</td>
                <td><span className={`status st-${pr.status}`}>{pr.status}</span></td>
                <td>
                  <button className="mini" onClick={() => open(pr)}>review</button>{' '}
                  {pr.status === 'open' && <button className="mini" onClick={() => setStatus(pr, 'merged')}>merge</button>}{' '}
                  {pr.gate_verdict && (
                    <button className="mini" onClick={() => publish(pr)}>publish</button>
                  )}
                </td>
              </tr>
              {selected === pr.id && detail && (
                <tr className="detail-row"><td colSpan={6}>
                  <div className="detail">
                    {detail.files.length === 0 && <p className="muted">No findings linked to this PR yet.</p>}
                    {detail.files.map((file) => (
                      <div key={file.path}>
                        <h3 className="section">{file.path}{' '}
                          <button className="mini" onClick={() => showDiff(file.path)}>
                            {diffs[file.path] ? 'hide diff' : 'show diff'}
                          </button>
                        </h3>
                        {diffs[file.path] && (
                          diffs[file.path].status === 'diff' ? (
                            <pre className="code">
                              {diffs[file.path].rows.map((row, index) => (
                                <div key={index}
                                  className={row.type === 'added' ? 'code-add'
                                    : row.type === 'removed' ? 'code-del' : ''}>
                                  <span className="code-n">
                                    {row.type === 'added' ? '+' : row.type === 'removed' ? '-' : ' '}
                                  </span>{row.text}
                                </div>
                              ))}
                            </pre>
                          ) : (
                            <p className="muted">
                              diff unavailable: {diffs[file.path].status} —
                              {diffs[file.path].detail}
                            </p>
                          )
                        )}
                        {file.findings.map((finding) => (
                          <div key={finding.finding_id} className="occ-row">
                            <span className={`sev sev-${(finding.severity || 'low').toLowerCase()}`}>
                              {finding.severity}
                            </span>{' '}
                            <strong>{finding.rule_id}</strong> line {finding.line} — {finding.title}{' '}
                            <span className={`pill ${finding.classification === 'new' ? 'warn' : ''}`}>
                              {finding.classification}
                            </span>{' '}
                            <button className="mini" onClick={() => showContext(finding)}>
                              {context[finding.finding_id] ? 'hide code' : 'show code'}
                            </button>
                            {context[finding.finding_id] && (
                              <pre className="code">
                                {context[finding.finding_id].lines.map((line) => (
                                  <div key={line.number}
                                    className={line.number === finding.line ? 'code-hit' : ''}>
                                    <span className="code-n">{line.number}</span>{line.text}
                                  </div>
                                ))}
                              </pre>
                            )}
                          </div>
                        ))}
                      </div>
                    ))}
                    {detail.pull_request.comment && (
                      <details>
                        <summary>PR comment payload</summary>
                        <pre className="code">{detail.pull_request.comment}</pre>
                      </details>
                    )}
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      {!prs.length && !error && <p className="empty">No pull requests registered.</p>}

      <h2 className="section">register pull request</h2>
      <div className="card">
        <input type="number" placeholder="PR number" value={form.number}
          onChange={(e) => setForm((f) => ({ ...f, number: e.target.value }))} />
        <input placeholder="title" value={form.title}
          onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} />
        <select value={form.project}
          onChange={(e) => setForm((f) => ({ ...f, project: e.target.value, version: '' }))}>
          <option value="">project</option>
          {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
        <select value={form.version} onChange={(e) => setForm((f) => ({ ...f, version: e.target.value }))}
          disabled={!(project?.versions?.length)}>
          <option value="">all versions</option>
          {(project?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <button onClick={createPr}>register</button>
      </div>
    </div>
  )
}
