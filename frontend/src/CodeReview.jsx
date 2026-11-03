import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Dialog, Input, PageHeader, Tabs, Drawer } from './ui'

export default function CodeReview({ projects }) {
  const [prs, setPrs] = useState([])
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [context, setContext] = useState({})
  const [diffs, setDiffs] = useState({})
  const [error, setError] = useState('')
  const [form, setForm] = useState({ number: '', title: '', project: '', version: '' })
  const [baselines, setBaselines] = useState([])
  const [reviewer, setReviewer] = useState('')
  const [baselineName, setBaselineName] = useState('')
  const [baselineOpen, setBaselineOpen] = useState(false)
  const [reviewerName, setReviewerName] = useState('')
  const [reviewerOpen, setReviewerOpen] = useState(false)
  const [publishResult, setPublishResult] = useState('')
  const [publishOpen, setPublishOpen] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => { load(); loadBaselines() }, [])

  function load() {
    setError('')
    api.get('/api/v1/code/pull-requests')
      .then((r) => setPrs(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  function loadBaselines() {
    api.get('/api/v1/code/baselines')
      .then((r) => setBaselines(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  async function snapshotBaseline(pr) {
    setBaselineName(`baseline-${pr.number}`)
    setBaselineOpen(true)
  }

  async function confirmSnapshotBaseline() {
    const name = baselineName.trim()
    if (!name) { setError('Baseline name is required.'); return }
    try {
      await api.post('/api/v1/code/baselines', {
        name, repository_id: pr.repository_id, from_pr_id: pr.id, actor: 'console',
      })
      setBaselineName('')
      setBaselineOpen(false)
      loadBaselines()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function decideBaseline(baseline, action) {
    setReviewerName(reviewer || '')
    setReviewerOpen(true)
  }

  async function confirmDecideBaseline(action) {
    const who = reviewerName.trim()
    if (!who) { setError('Reviewer identity is required.'); return }
    try {
      await api.post(`/api/v1/code/baselines/${baseline.id}/${action}`, { actor: who })
      setReviewerName('')
      setReviewerOpen(false)
      loadBaselines()
    } catch (e) { setError(String(e.message || e)) }
  }

  // The dialog needs the pull request it was opened for; reading a `pr` that
  // only exists inside the table's map crashed the whole screen.
  const [publishFor, setPublishFor] = useState(null)

  async function publish(pr) {
    setPublishFor(pr.id)
    setPublishResult('')
    setPublishOpen(true)
  }

  async function confirmPublish() {
    if (!publishFor) { setPublishOpen(false); return }
    try {
      const r = await api.post(`/api/v1/code/pull-requests/${publishFor}/publish`,
        { actor: 'console' })
      setPublishResult(`published ${r.data.state} to ${r.data.repository}`)
      setPublishOpen(false)
    } catch (e) { setError(String(e.message || e)) }
  }

  async function open(pr) {
    if (selected === pr.id) { setSelected(null); setDetail(null); setDrawerOpen(false); return }
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

  async function setStatus(pr, status) {
    try {
      await api.post(`/api/v1/code/pull-requests/${pr.id}/status`, { status, actor: 'console' })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  const project = projects.find((p) => p.name === form.project)

  return (
    <div className="stack">
      <PageHeader title="Pull requests" />
      <div className="toolbar">
        <span className="count">{prs.length} pull requests</span>
        <button onClick={load}>refresh</button>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      <div className="panel">
        <div className="toolbar">
          <span className="count">{baselines.length} SAST baselines</span>
          <input placeholder="reviewer" value={reviewer}
            onChange={(e) => setReviewer(e.target.value)} />
          <button className="mini" onClick={loadBaselines}>refresh</button>
        </div>
        {baselines.length === 0 && (
          <p className="muted">No baselines yet. Snapshot a reviewed PR to accept its
            current findings; approval needs a second person.</p>
        )}
        {baselines.map((baseline) => (
          <div key={baseline.id} className="muted">
            <strong>{baseline.name}</strong>{' '}
            <span className={`status st-${baseline.status}`}>{baseline.status}</span>{' '}
            {baseline.counters?.entries || 0} entries
            {baseline.approved_by ? ` · approved by ${baseline.approved_by}` : ''}{' '}
            {baseline.status === 'draft' && (
              <>
                <button className="mini" onClick={() => decideBaseline(baseline, 'approve')}>approve</button>{' '}
                <button className="mini" onClick={() => decideBaseline(baseline, 'reject')}>reject</button>
              </>
            )}
          </div>
        ))}
      </div>
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
                <td>{pr.counts?.new || 0} new / {pr.counts?.existing || 0} existing / {pr.counts?.baselined || 0} baselined</td>
                <td><span className={`status st-${pr.status}`}>{pr.status}</span></td>
                <td>
                  <button className="mini" onClick={() => open(pr)}>review</button>{' '}
                  {pr.status === 'open' && <button className="mini" onClick={() => setStatus(pr, 'merged')}>merge</button>}{' '}
                  {pr.gate_verdict && (
                    <button className="mini" onClick={() => publish(pr)}>publish</button>
                  )}{' '}
                  <button className="mini" onClick={() => snapshotBaseline(pr)}>baseline</button>
                </td>
              </tr>
              {selected === pr.id && detail && (
                <tr className="detail-row"><td colSpan={6}>
                  <Drawer open={drawerOpen} title={`PR #${selected}`} onClose={() => setDrawerOpen(false)}>
                    <Tabs tabs={tabs} active={activeTab} onChange={setActiveTab} />
                    <div className="detail">
                      {activeTab === 'overview' && (
                        <>
                          {detail.files.length === 0 && <p className="muted">No findings linked to this PR yet.</p>}
                          {detail.files.map((file) => (
                            <div key={file.path}>
                              <h3 className="section">{file.path}</h3>
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
                        </>
                      )}
                      {activeTab === 'diff' && (
                        <div className="detail">
                          {detail.files.map((file) => (
                            <div key={file.path}>
                              <h3 className="section">{file.path}</h3>
                              {diffs[file.path] ? (
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
                              ) : (
                                <button className="mini" onClick={() => showDiff(file.path)}>
                                  show diff
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                      {activeTab === 'context' && (
                        <div className="detail">
                          {detail.files.map((file) => (
                            <div key={file.path}>
                              <h3 className="section">{file.path}</h3>
                              {file.findings.map((finding) => (
                                <div key={finding.finding_id} className="occ-row">
                                  <span className={`sev sev-${(finding.severity || 'low').toLowerCase()}`}>
                                    {finding.severity}
                                  </span>{' '}
                                  <strong>{finding.rule_id}</strong> line {finding.line} — {finding.title}{' '}
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
                        </div>
                      )}
                      {activeTab === 'comment' && (
                        <div className="detail">
                          {detail.pull_request.comment && (
                            <pre className="code">{detail.pull_request.comment}</pre>
                          )}
                        </div>
                      )}
                    </div>
                  </Drawer>
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
      <Dialog open={baselineOpen} title="Name this baseline"
        onClose={() => setBaselineOpen(false)}
        confirmLabel="Snapshot" onConfirm={confirmSnapshotBaseline}>
        <Input label="Baseline name" value={baselineName}
          onChange={(v) => setBaselineName(v)} placeholder="baseline name" />
      </Dialog>
      <Dialog open={reviewerOpen} title="Enter reviewer identity"
        onClose={() => setReviewerOpen(false)}
        confirmLabel="Confirm" onConfirm={() => confirmDecideBaseline('')}>
        <Input label="Reviewer" value={reviewerName}
          onChange={(v) => setReviewerName(v)} placeholder="who is reviewing" />
      </Dialog>
      <Dialog open={publishOpen} title="Publish result"
        onClose={() => setPublishOpen(false)}
        confirmLabel="Dismiss">
        {publishResult ? <p className="muted">{publishResult}</p> : <p className="muted">Publish result</p>}
      </Dialog>
    </div>
  )
}
