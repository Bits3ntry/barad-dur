import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Dialog, Input, PageHeader, Tabs, Drawer } from './ui'
import { useI18n } from './i18n'

export default function CodeReview({ projects }) {
  const { t, tOr } = useI18n()
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
    if (!name) { setError(t('code.error.baselineName')); return }
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
    if (!who) { setError(t('code.error.reviewer')); return }
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
      setPublishResult(t('code.published', { state: r.data.state, repository: r.data.repository }))
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

  // The drawer's tabs: four readings of the same pull request, and the labels
  // follow the console's language like every other tab in it.
  const tabs = [
    { id: 'overview', label: t('code.tab.overview') },
    { id: 'diff', label: t('code.tab.diff') },
    { id: 'context', label: t('code.tab.context') },
    { id: 'comment', label: t('code.tab.comment') },
  ]

  return (
    <div className="stack">
      <PageHeader title={t('code.title')} />
      <div className="toolbar">
        <span className="count">{t('code.count.prs', { n: prs.length })}</span>
        <button onClick={load}>{t('common.refresh')}</button>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      <div className="panel">
        <div className="toolbar">
          <span className="count">{t('code.count.baselines', { n: baselines.length })}</span>
          <input placeholder={t('code.reviewer')} value={reviewer}
            onChange={(e) => setReviewer(e.target.value)} />
          <button className="mini" onClick={loadBaselines}>{t('common.refresh')}</button>
        </div>
        {baselines.length === 0 && (
          <p className="muted">{t('code.baselines.empty')}</p>
        )}
        {baselines.map((baseline) => (
          <div key={baseline.id} className="muted">
            <strong>{baseline.name}</strong>{' '}
            <span className={`status st-${baseline.status}`}>{baseline.status}</span>{' '}
            {t('code.count.entries', { n: baseline.counters?.entries || 0 })}
            {baseline.approved_by ? t('code.approvedBy', { name: baseline.approved_by }) : ''}{' '}
            {baseline.status === 'draft' && (
              <>
                <button className="mini" onClick={() => decideBaseline(baseline, 'approve')}>{t('code.approve')}</button>{' '}
                <button className="mini" onClick={() => decideBaseline(baseline, 'reject')}>{t('code.reject')}</button>
              </>
            )}
          </div>
        ))}
      </div>
      <table>
        <thead><tr><th>{t('code.col.pr')}</th><th>{t('code.col.title')}</th><th>{t('code.col.gate')}</th><th>{t('code.col.ratio')}</th><th>{t('common.status')}</th><th></th></tr></thead>
        <tbody>
          {prs.map((pr) => (
            <React.Fragment key={pr.id}>
              <tr className={selected === pr.id ? 'selected' : ''}>
                <td className="title">#{pr.number}</td>
                <td>{pr.title || '—'}</td>
                <td>{pr.gate_verdict
                  ? <span className={`status st-${pr.gate_verdict}`}>{pr.gate_verdict}</span>
                  : <span className="muted">{t('code.notScanned')}</span>}</td>
                <td>{t('code.count.triage', { new: pr.counts?.new || 0, existing: pr.counts?.existing || 0,
                  baselined: pr.counts?.baselined || 0 })}</td>
                <td><span className={`status st-${pr.status}`}>{pr.status}</span></td>
                <td>
                  <button className="mini" onClick={() => open(pr)}>{t('code.review')}</button>{' '}
                  {pr.status === 'open' && <button className="mini" onClick={() => setStatus(pr, 'merged')}>{t('code.merge')}</button>}{' '}
                  {pr.gate_verdict && (
                    <button className="mini" onClick={() => publish(pr)}>{t('code.publish')}</button>
                  )}{' '}
                  <button className="mini" onClick={() => snapshotBaseline(pr)}>{t('code.baseline')}</button>
                </td>
              </tr>
              {selected === pr.id && detail && (
                <tr className="detail-row"><td colSpan={6}>
                  <Drawer open={drawerOpen} title={t('code.drawerTitle', { id: selected })} onClose={() => setDrawerOpen(false)}>
                    <Tabs tabs={tabs} active={activeTab} onChange={setActiveTab} />
                    <div className="detail">
                      {activeTab === 'overview' && (
                        <>
                          {detail.files.length === 0 && <p className="muted">{t('code.empty.findings')}</p>}
                          {detail.files.map((file) => (
                            <div key={file.path}>
                              <h3 className="section">{file.path}</h3>
                              {file.findings.map((finding) => (
                                <div key={finding.finding_id} className="occ-row">
                                  <span className={`sev sev-${(finding.severity || 'low').toLowerCase()}`}>
                                    {finding.severity}
                                  </span>{' '}
                                  <strong>{finding.rule_id}</strong> {t('code.line', { n: finding.line })} — {finding.title}{' '}
                                  <span className={`pill ${finding.classification === 'new' ? 'warn' : ''}`}>
                                    {tOr('code.class.' + finding.classification, finding.classification)}
                                  </span>{' '}
                                  <button className="mini" onClick={() => showContext(finding)}>
                                    {context[finding.finding_id] ? t('code.hideCode') : t('code.showCode')}
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
                                    {t('code.diffUnavailable', { status: diffs[file.path].status,
                                      detail: diffs[file.path].detail })}
                                  </p>
                                )
                              ) : (
                                <button className="mini" onClick={() => showDiff(file.path)}>
                                  {t('code.showDiff')}
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
                                  <strong>{finding.rule_id}</strong> {t('code.line', { n: finding.line })} — {finding.title}{' '}
                                  <button className="mini" onClick={() => showContext(finding)}>
                                    {context[finding.finding_id] ? t('code.hideCode') : t('code.showCode')}
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
      {!prs.length && !error && <p className="empty">{t('code.empty.prs')}</p>}

      <h2 className="section">{t('code.registerTitle')}</h2>
      <div className="card">
        <input type="number" placeholder={t('code.form.number')} value={form.number}
          onChange={(e) => setForm((f) => ({ ...f, number: e.target.value }))} />
        <input placeholder={t('code.form.title')} value={form.title}
          onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} />
        <select value={form.project}
          onChange={(e) => setForm((f) => ({ ...f, project: e.target.value, version: '' }))}>
          <option value="">{t('code.form.project')}</option>
          {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
        <select value={form.version} onChange={(e) => setForm((f) => ({ ...f, version: e.target.value }))}
          disabled={!(project?.versions?.length)}>
          <option value="">{t('code.form.allVersions')}</option>
          {(project?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <button onClick={createPr}>{t('code.form.register')}</button>
      </div>
      <Dialog open={baselineOpen} title={t('code.dialog.baselineTitle')}
        onClose={() => setBaselineOpen(false)}
        confirmLabel={t('code.dialog.snapshot')} onConfirm={confirmSnapshotBaseline}>
        <Input label={t('code.field.baselineName')} value={baselineName}
          onChange={(v) => setBaselineName(v)} placeholder={t('code.field.baselineNamePlaceholder')} />
      </Dialog>
      <Dialog open={reviewerOpen} title={t('code.dialog.reviewerTitle')}
        onClose={() => setReviewerOpen(false)}
        confirmLabel={t('common.confirm')} onConfirm={() => confirmDecideBaseline('')}>
        <Input label={t('code.field.reviewer')} value={reviewerName}
          onChange={(v) => setReviewerName(v)} placeholder={t('code.field.reviewerPlaceholder')} />
      </Dialog>
      <Dialog open={publishOpen} title={t('code.dialog.publishTitle')}
        onClose={() => setPublishOpen(false)}
        confirmLabel={t('common.dismiss')}>
        {publishResult ? <p className="muted">{publishResult}</p> : <p className="muted">{t('code.dialog.publishBody')}</p>}
      </Dialog>
    </div>
  )
}
