import React, { useEffect, useState } from 'react'
import { api, actorName } from './api'
import {
  Banner, Card, Dialog, Drawer, EmptyState, ErrorBanner, Input, Loading, Pill,
  SeverityBadge, Table, Tabs,
} from './ui'
import { VexSection } from './Vex'
import TriagePanel from './FindingTriage'
import FindingRepeat from './FindingRepeat'
import AgentTrace from './AgentTrace'
import FindingRelations from './FindingRelations'
import { useI18n } from './i18n'

/* A finding is an object with its own address, not a row that unfolds.

   The page answers one question at a time. The first screen is the decision:
   what it is, how bad, and the one action that moves it. Everything else —
   the package's other advisories, where it was seen, activity, the triage gate
   and VEX — sits behind tabs, because ten equally-weighted cards is not a page,
   it is a pile. */

function slaLine(deadline, t) {
  if (!deadline) return t('findings.sla.none')
  const days = Math.floor((new Date(deadline) - new Date()) / 86400000)
  if (days < 0) return t('findings.sla.overdue', { n: -days })
  return t('findings.sla.left', { n: days })
}

/* Postgres hands numeric columns back as Decimal, which JSON serialises as a
   string: `toFixed` on "0.27" throws and React unmounts the page. One helper, so
   no score is ever formatted straight off the wire. */
function score(value, digits = 1) {
  const number = Number(value)
  return Number.isFinite(number) ? number.toFixed(digits) : null
}

function when(value) {
  if (!value) return '—'
  try { return new Date(value).toLocaleString() } catch { return value }
}

/* The address a repeater needs, without spelling the path twice.

   A finding carries `url` and `endpoint` separately, and for an agent finding the
   URL is already the full request — so concatenating blindly printed
   `…/rest/user/login/rest/user/login`. When the URL already ends where the endpoint
   does, the URL is the answer; otherwise the endpoint is appended to the origin. */
function requestTarget(detail) {
  const url = (detail.url || '').trim()
  const endpoint = (detail.endpoint || '').trim()
  if (!url) return endpoint || '—'
  if (!endpoint || url.endsWith(endpoint)) return url
  return `${url.replace(/\/+$/, '')}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`
}

function Fact({ label, children }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children || '—'}</dd>
    </>
  )
}

export default function FindingPage({ id, onBack, onOpenAnalysis }) {
  const { t, tOr, tCount } = useI18n()
  const [detail, setDetail] = useState(null)
  const [occurrences, setOccurrences] = useState([])
  const [history, setHistory] = useState([])
  const [versionRows, setVersionRows] = useState(null)
  // The package the finding is about: its sheet lists every advisory that
  // applies to this exact version — a different question from "what else does
  // this build carry", and the one a dependency finding is opened to answer.
  const [sheet, setSheet] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [assignee, setAssignee] = useState('')
  const [jiraKey, setJiraKey] = useState('')
  const [jiraOpen, setJiraOpen] = useState(false)
  const [jiraResult, setJiraResult] = useState('')
  const [statusOpen, setStatusOpen] = useState(false)
  const [statusDraft, setStatusDraft] = useState({ status: 'resolved', reason: '' })
  const [reload, setReload] = useState(0)
  // Which project this finding belongs to: a cycle's findings are about hosts, and
  // the estate is organised by projects — the link has to be possible by hand.
  const [projects, setProjects] = useState([])
  const [tab, setTab] = useState('summary')
  const [more, setMore] = useState(false)
  const [overflow, setOverflow] = useState(false)
  const summaryRef = React.useRef(null)
  const [allRows, setAllRows] = useState(false)
  const [comments, setComments] = useState(null)
  const [attachments, setAttachments] = useState(null)
  const [comment, setComment] = useState('')
  const [commentBusy, setCommentBusy] = useState(false)
  const [fileError, setFileError] = useState('')
  const [viewing, setViewing] = useState(null)
  const fileInput = React.useRef(null)
  // A file input fires `change` once per selection, but a double-click or a
  // second drop of the same file is the same evidence twice — and the store has
  // no delete, so the duplicate would be permanent.
  const uploading = React.useRef('')

  useEffect(() => {
    api.get('/api/v1/projects')
      .then((body) => setProjects(body.data || []))
      .catch(() => setProjects([]))
  }, [])

  async function attachProject(slug) {
    setBusy(true)
    try {
      await api.patch(`/api/v1/findings/${id}/project`, { project: slug || null,
        actor: actorName() })
      setDetail((current) => (current ? {
        ...current,
        project_slug: slug || null,
        project: slug ? (projects.find((row) => row.slug === slug) || {}).name || slug : null,
      } : current))
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    if (!id) return
    setDetail(null); setError(''); setVersionRows(null); setTab('summary')
    let cancelled = false
    ;(async () => {
      try {
        const { data } = await api.get(`/api/v1/findings/${id}`)
        if (cancelled) return
        const enriched = { ...data }
        if (data.cve_id) {
          const [kev, epss] = await Promise.all([
            api.get(`/api/v1/intel/kev/${data.cve_id}`).catch(() => null),
            api.get(`/api/v1/intel/epss/${data.cve_id}`).catch(() => null),
          ])
          if (kev?.known_exploited) enriched.kev = kev.data
          if (epss?.data) enriched.epss = epss.data
        }
        setDetail(enriched)
        setAssignee(data.assignee || '')
        if (data.component_id) {
          api.get(`/api/v1/components/${data.component_id}`)
            .then((body) => { if (!cancelled) setSheet(body.data) })
            .catch(() => { if (!cancelled) setSheet(null) })
        } else {
          setSheet(null)
        }
        if (data.last_seen_version_id) {
          api.get(`/api/v1/findings?version_id=${data.last_seen_version_id}&limit=200&sort=severity`)
            .then((body) => { if (!cancelled) setVersionRows(body.data || []) })
            .catch(() => { if (!cancelled) setVersionRows([]) })
        } else {
          setVersionRows([])
        }
        api.get(`/api/v1/findings/${id}/occurrences`)
          .then((body) => { if (!cancelled) setOccurrences(body.data || []) })
          .catch(() => {})
        api.get(`/api/v1/findings/${id}/history`)
          .then((body) => { if (!cancelled) setHistory(body.data || []) })
          .catch(() => {})
        api.get(`/api/v1/findings/${id}/comments`)
          .then((body) => { if (!cancelled) setComments(body.data || []) })
          .catch(() => { if (!cancelled) setComments([]) })
        api.get(`/api/v1/findings/${id}/attachments`)
          .then((body) => { if (!cancelled) setAttachments(body.data || []) })
          .catch(() => { if (!cancelled) setAttachments([]) })
      } catch (caught) {
        if (!cancelled) setError(String(caught.message || caught))
      }
    })()
    return () => { cancelled = true }
  }, [id, reload])

  async function act(path, body, options = { method: 'POST' }) {
    setBusy(true); setError('')
    try {
      await api[options.method === 'PATCH' ? 'patch' : 'post'](path, body)
      setReload((n) => n + 1)
      return true
    } catch (caught) {
      setError(String(caught.message || caught))
      return false
    } finally { setBusy(false) }
  }

  async function createTask() {
    if (!detail) return
    setBusy(true); setError('')
    try {
      const created = await api.post('/api/v1/remediation/tasks', {
        title: (detail.title || '').slice(0, 200), actor: 'console',
      })
      await api.post(`/api/v1/remediation/tasks/${created.data.id}/findings`,
                     { finding_id: detail.id, actor: 'console' })
      setReload((n) => n + 1)
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setBusy(false) }
  }

  async function addComment() {
    const body = comment.trim()
    if (!body) return
    setCommentBusy(true); setError('')
    try {
      const created = await api.post(`/api/v1/findings/${detail.id}/comments`,
                                     { author: 'console', body })
      setComments((rows) => [...(rows || []), created.data])
      setComment('')
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setCommentBusy(false) }
  }

  /* Evidence is text on purpose: the store is bounded and marked unreviewed, so
     the console says "text" instead of pretending to hold a binary. A file that
     is not text is refused here rather than stored as mojibake. */
  async function attach(file) {
    if (!file) return
    const key = `${file.name}:${file.size}:${file.lastModified}`
    if (uploading.current === key) return
    uploading.current = key
    setFileError(''); setError('')
    try {
      const content = await file.text()
      if (content.length > 200000) {
        setFileError(t('findingPage.attachments.tooBig', { mb: 0.2 }))
        return
      }
      const created = await api.post(`/api/v1/findings/${detail.id}/attachments`, {
        name: file.name, media_type: file.type || 'text/plain',
        content, added_by: 'console',
      })
      setAttachments((rows) => [...(rows || []), created.data])
    } catch (caught) {
      setFileError(String(caught.message || caught))
    } finally {
      uploading.current = ''
      if (fileInput.current) fileInput.current.value = ''
    }
  }

  async function openAttachment(row) {
    try {
      const body = await api.get(`/api/v1/findings/${detail.id}/attachments/${row.id}`)
      setViewing(body.data)
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }

  /* "leer completo" is only honest when something is actually hidden: measured,
     not assumed from the character count. */
  React.useLayoutEffect(() => {
    const node = summaryRef.current
    if (!node || more) return
    // A pixel of rounding is not a hidden paragraph: only claim there is more
    // when a whole line of it is out of sight.
    setOverflow(node.scrollHeight > node.clientHeight + 6)
  }, [detail, more])

  if (error && !detail) return <ErrorBanner error={error} onRetry={() => setReload((n) => n + 1)} />
  if (!detail) return <Loading rows={6} />

  const sameComponent = (row) => row.component_name === detail.component_name
    && row.component_version === detail.component_version
  const packageLabel = sheet
    ? `${sheet.component.name}@${sheet.component.version || ''}` : null
  const advisoryCount = sheet?.advisories?.length || 0
  const activityCount = occurrences.length + history.length
    + (comments?.length || 0) + (attachments?.length || 0)
  const seenOnce = detail.first_seen_at && detail.first_seen_at === detail.last_seen_at
  // Scanner titles are advisory paragraphs, and their first sentence is usually
  // a preamble ("node-tar is a tar archive manipulation library…"). The identity
  // is the CVE (or the rule), so that leads; the paragraph sits under it, clamped,
  // and Resumen keeps it whole.
  const identifier = detail.cve_id || detail.rule_id || ''
  const heading = identifier || detail.title
  const clamps = Boolean(identifier && detail.title)

  return (
    <div className="stack finding-page">
      <div className="fp-head">
        <button className="btn-ghost fp-back" onClick={onBack}>← {t('findings.title')}</button>
        <div className="fp-badges">
          <SeverityBadge severity={detail.severity} />
          <span className={`prio prio-${(detail.priority || 'p3').toLowerCase()}`}>
            {detail.priority || 'P3'}
          </span>
          <span className={`status st-${detail.status}`}>
            {tOr(`status.${detail.status}`, detail.status)}
          </span>
          <span className="muted">SLA · {slaLine(detail.sla_deadline, t)}</span>
        </div>
        <h1 className={`fp-title${identifier ? ' mono' : ''}`} title={detail.title}>
          {heading}
        </h1>
        {clamps && (
          <p ref={summaryRef} className={`fp-summary${more ? '' : ' is-clamped'}`}>
            {detail.title}
          </p>
        )}
        {clamps && (overflow || more) && (
          <button className="fp-more" onClick={() => setMore((open) => !open)}>
            {more ? t('findingPage.less') : t('findingPage.more')}
          </button>
        )}
        <p className="fp-where">
          {[detail.project, detail.version, packageLabel]
            .filter(Boolean).join('  ·  ')}
        </p>
      </div>

      {error && <ErrorBanner error={error} />}

      <div className="fp-grid">
        <Card title={t('findingPage.identity')}>
          <dl className="fp-facts">
            <Fact label={t('findings.field.component')}>
              <span className="mono">{detail.component_purl || detail.component_name || '—'}</span>
            </Fact>
            <Fact label={t('findingPage.project')}>
              <select value={detail.project_slug || ''} disabled={busy}
                onChange={(event) => attachProject(event.target.value)}>
                <option value="">{t('findingPage.projectNone')}</option>
                {projects.map((project) => (
                  <option key={project.slug} value={project.slug}>{project.name}</option>
                ))}
              </select>
            </Fact>
            <Fact label={t('findingPage.cvss')} title={detail.cvss_vector || ''}>
              {score(detail.cvss_score) || '—'}
            </Fact>
            {(detail.path || detail.endpoint) && (
              <Fact label={t('findings.field.location')}>
                <span className="mono">
                  {detail.endpoint
                    ? `${detail.http_method || ''} ${detail.endpoint}`
                    : `${detail.path}${detail.line ? `:${detail.line}` : ''}`}
                </span>
              </Fact>
            )}
            {detail.cwe && <Fact label={t('findings.field.cwe')}>{detail.cwe}</Fact>}
            <Fact label={t('findings.field.tool')}>{detail.tool || detail.source}</Fact>
            <Fact label={seenOnce ? t('findingPage.seen') : t('findingPage.lastSeen')}>
              {when(detail.last_seen_at)}
              {!seenOnce && (
                <span className="muted"> · {t('findingPage.firstSeenShort', {
                  when: when(detail.first_seen_at),
                })}</span>
              )}
            </Fact>
          </dl>
          <div className="row fp-signals">
            {detail.kev
              ? <Pill tone="warn">{t('findings.kev.exploited', { date: detail.kev.date_added })}</Pill>
              : <span className="muted">{t('findings.kev.notListed')}</span>}
            {detail.epss && <Pill>EPSS {score(detail.epss.epss ?? detail.epss.score, 2)}</Pill>}
            {/* The two things a reader opens an autonomous finding to learn: did a
                machine claim it, and has the claim been reproduced. */}
            {detail.origin === 'shauron-ai' && <Pill tone="warn">{t('findingPage.agentChip')}</Pill>}
            {detail.exploit_state === 'reproduced' && (
              <Pill tone="ok">{t('trace.usableChip')}</Pill>
            )}
            {detail.exploit_state === 'observed' && (
              <Pill>{t('findingPage.observedChip')}</Pill>
            )}
          </div>
        </Card>

        <Card title={t('findingPage.actions')}>
          <div className="fp-actions">
            {detail.fixed_version ? (
              <p className="fp-fix">
                {t('findingPage.fix', { version: detail.fixed_version })}
              </p>
            ) : detail.recommendation ? (
              <p className="muted">{detail.recommendation}</p>
            ) : null}
            <button className="btn-primary" disabled={busy || detail.status === 'resolved'}
                    onClick={createTask}>
              {t('findingPage.createTask')}
            </button>
            <label className="fp-field">
              <span className="muted">{t('common.owner')}</span>
              <span className="row" style={{ gap: 6 }}>
                <input value={assignee} placeholder={t('findings.assign.placeholder')}
                       onChange={(event) => setAssignee(event.target.value)} />
                <button className="btn-ghost" disabled={busy}
                        onClick={() => act(`/api/v1/findings/${detail.id}/assignee`,
                                           { assignee: assignee.trim(), actor: 'console' },
                                           { method: 'PATCH' })}>
                  {t('findings.assign.action')}
                </button>
              </span>
            </label>
            <div className="fp-quiet">
              <button className="linkish" onClick={() => setJiraOpen(true)}>
                {t('findings.jira.link')}
              </button>
              <button className="linkish"
                      onClick={() => { setStatusDraft({ status: 'acknowledged', reason: '' }); setStatusOpen(true) }}>
                {t('findings.action.acknowledge')}
              </button>
              <button className="linkish"
                      onClick={() => { setStatusDraft({ status: 'resolved', reason: '' }); setStatusOpen(true) }}>
                {t('findings.action.resolve')}
              </button>
              {detail.status !== 'open' && (
                <button className="linkish"
                        onClick={() => { setStatusDraft({ status: 'open', reason: '' }); setStatusOpen(true) }}>
                  {t('findings.action.reopen')}
                </button>
              )}
              {detail.analysis_run && (
                <button className="linkish" onClick={() => onOpenAnalysis?.({
                  runId: detail.analysis_run.id, path: detail.path, line: detail.line,
                })}>
                  {t('findings.analysis.open')}
                </button>
              )}
            </div>
            {jiraResult && <p className="muted">{jiraResult}</p>}
          </div>
        </Card>
      </div>

      <Tabs tabs={[
        { id: 'summary', label: t('findingPage.tab.summary') },
        { id: 'package', label: packageLabel
          ? t('findingPage.tab.package', { n: advisoryCount }) : t('findingPage.tab.build') },
        { id: 'repeat', label: t('findingPage.tab.repeat') },
        // The autonomous half: who authorised it and what the agent actually ran.
        { id: 'trace', label: t('findingPage.tab.trace') },
        { id: 'relations', label: t('findingPage.tab.relations') },
        { id: 'activity', label: t('findingPage.tab.activity', { n: activityCount }) },
        { id: 'decide', label: t('findingPage.tab.decide') },
      ]} active={tab} onChange={setTab} />

      {tab === 'summary' && (
        <Card>
          <div className="fp-prose">
            {/* Where it lives and how it is reached: the facts a repeater needs,
                stated before the prose that explains them. */}
            {(detail.endpoint || detail.url || detail.proof_request) && (
              <>
                <h4>{t('findingPage.request.title')}</h4>
                <dl className="fp-evidence">
                  <Fact label={t('findingPage.request.method')}>
                    <span className="mono">{detail.http_method || '—'}</span>
                  </Fact>
                  <Fact label={t('findingPage.request.where')}>
                    <span className="mono" style={{ overflowWrap: 'anywhere' }}>
                      {requestTarget(detail)}
                    </span>
                  </Fact>
                  <Fact label={t('findingPage.request.auth')}>
                    {detail.auth_required
                      ? (detail.auth_profile_name || t('findingPage.request.authNeeded'))
                      : t('findingPage.request.authNone')}
                  </Fact>
                  {detail.auth_required && (
                    <Fact label={t('findingPage.request.login')}>
                      {t('findingPage.request.loginHint')}
                    </Fact>
                  )}
                  {detail.expected_result && (
                    <Fact label={t('findingPage.request.expected')}>{detail.expected_result}</Fact>
                  )}
                  {detail.observed_result && (
                    <Fact label={t('findingPage.request.observed')}>{detail.observed_result}</Fact>
                  )}
                </dl>
                {detail.proof_request && (
                  <>
                    <h4>{t('findingPage.request.proof')}</h4>
                    <pre className="proof">{detail.proof_request}</pre>
                    {detail.proof_response && (
                      <pre className="proof">{detail.proof_response}</pre>
                    )}
                  </>
                )}
              </>
            )}
            {detail.impact && (<><h4>{t('findings.field.impact')}</h4><p>{detail.impact}</p></>)}
            {detail.reproduction && (
              <><h4>{t('findings.field.reproduction')}</h4><p>{detail.reproduction}</p></>)}
            {detail.recommendation && (
              <><h4>{t('findings.field.recommendation')}</h4><p>{detail.recommendation}</p></>)}
            {/* A scanner writes its `detail` as JSON: printed raw it is a wall.
                The keys it actually declares are shown as facts instead. */}
            {detail.detail && detail.detail.trim().startsWith('{') ? (
              <dl className="fp-evidence">
                {Object.entries(detail.evidence || {})
                  // These are already on screen, formatted: repeating them in the
                  // scanner's own casing is the noise this pass is removing.
                  .filter(([key]) => !['cve_id', 'cvss_score', 'cvss_vector',
                                       'fixed_version', 'source_id'].includes(key))
                  .map(([key, value]) => (
                    <Fact key={key} label={key.replace(/_/g, ' ')}>
                      {/^https?:\/\//.test(String(value)) ? (
                        <a href={String(value)} target="_blank" rel="noreferrer">{String(value)}</a>
                      ) : String(value)}
                    </Fact>
                  ))}
              </dl>
            ) : detail.detail && (
              <><h4>{t('findings.field.detail')}</h4><p>{detail.detail}</p></>
            )}
            {!detail.impact && !detail.reproduction && !detail.recommendation
              && !detail.detail && (
              <p className="muted">{t('findingPage.summary.empty')}</p>
            )}
          </div>
        </Card>
      )}

      {tab === 'repeat' && <Card><FindingRepeat detail={detail} /></Card>}
      {tab === 'trace' && <AgentTrace findingId={detail.id} />}
      {tab === 'relations' && <FindingRelations findingId={detail.id} />}

      {tab === 'package' && (sheet ? (
        <Card actions={(
          <button className="btn-ghost"
                  onClick={() => { window.location.hash = `component::${sheet.component.id}` }}>
            {t('findingPage.package.open')} →
          </button>
        )}>
          {sheet.advisories?.length ? (
            <Table head={[t('findings.col.sev'), t('findingPage.package.ref'),
                          t('findings.col.title'), t('findingPage.package.cvss'),
                          t('findingPage.package.fixedIn')]}>
              {sheet.advisories.map((row) => (
                <tr key={row.ref}>
                  <td><SeverityBadge severity={row.severity} /></td>
                  <td className="mono">
                    <span className="row" style={{ gap: 6 }}>
                      {row.cve_id || row.ref}
                      {row.kev && <Pill tone="warn">KEV</Pill>}
                    </span>
                  </td>
                  <td className="title">
                    <span className="rem-title" title={row.title}>{row.title || '—'}</span>
                  </td>
                  <td className="mono">{score(row.cvss?.score) || '—'}</td>
                  <td className="mono">{[...(row.fixed_versions || [])].join(', ') || '—'}</td>
                </tr>
              ))}
            </Table>
          ) : (
            <EmptyState title={t('findingPage.package.empty')}
                        hint={t('findingPage.package.empty.hint')} />
          )}

          <div className="fp-usage">
            <span className="muted">
              {tCount('findingPage.package.usage', sheet.usage?.totals?.builds || 0, {
                projects: sheet.usage?.totals?.projects || 0,
              })}
            </span>
            {(sheet.usage?.projects || []).map((entry) => (
              <span key={entry.project.id} className="pill">
                {entry.project.name}
                <span className="muted">
                  {entry.builds.map((build) => build.version.label).join(', ')}
                </span>
              </span>
            ))}
          </div>
        </Card>
      ) : (
        <Card>
          {versionRows === null ? <Loading rows={3} /> : versionRows.length === 0 ? (
            <EmptyState title={t('findingPage.version.empty')}
                        hint={t('findingPage.version.empty.hint')} />
          ) : (
            <Table head={[t('findings.col.sev'), t('findings.col.prio'),
                          t('findings.col.rule'), t('findings.col.title'),
                          t('findings.col.status')]}>
              {(allRows ? versionRows : versionRows.slice(0, 25)).map((row) => (
                <tr key={row.id} className={row.id === detail.id ? 'selected' : ''}
                    onClick={() => { window.location.hash = `findings::${row.id}` }}>
                  <td><SeverityBadge severity={row.severity} /></td>
                  <td>
                    <span className={`prio prio-${(row.priority || 'p3').toLowerCase()}`}>
                      {row.priority || 'P3'}
                    </span>
                  </td>
                  <td className="mono">{row.cve_id || row.rule_id || '—'}</td>
                  <td className="title">
                    <span className="rem-title" title={row.title}>{row.title}</span>
                    {sameComponent(row) && (
                      <Pill>{t('findingPage.version.sameComponent')}</Pill>
                    )}
                  </td>
                  <td>
                    <span className={`status st-${row.status}`}>
                      {tOr(`status.${row.status}`, row.status)}
                    </span>
                  </td>
                </tr>
              ))}
            </Table>
          )}
          {versionRows !== null && versionRows.length > 25 && !allRows && (
            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn-ghost" onClick={() => setAllRows(true)}>
                {t('findingPage.version.showAll', { n: versionRows.length })}
              </button>
            </div>
          )}
        </Card>
      ))}

      {tab === 'activity' && (
        <div className="stack">
          <div className="fp-grid">
            <Card title={t('findingPage.occurrences')}>
              {occurrences.length === 0 ? (
                <p className="muted">{t('findings.occurrences.empty')}</p>
              ) : (
                <ul className="fp-timeline">
                  {occurrences.map((row) => (
                    <li key={row.id} className="fp-event">
                      <time>{when(row.seen_at)}</time>
                      <div>
                        <strong>{row.tool || row.source || '—'}</strong>
                        {row.evidence && <p>{row.evidence}</p>}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <Card title={t('findingPage.history')}>
              {history.length === 0 ? (
                <p className="muted">{t('findings.history.empty')}</p>
              ) : (
                <ul className="fp-timeline">
                  {history.map((event) => (
                    <li key={event.ref} className="fp-event">
                      <time>{when(event.at)}</time>
                      <div>
                        <strong>{event.action}</strong>
                        <span className="muted">{event.actor || t('findings.history.system')}</span>
                        {event.detail && <p className="mono">{event.detail}</p>}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          <Card title={t('findingPage.comments')}
                actions={<span className="muted">{tCount('findingPage.comments.count', comments?.length || 0)}</span>}>
            {comments === null ? <Loading rows={2} /> : (
              <div className="stack" style={{ gap: 10 }}>
                {comments.length === 0 ? (
                  <p className="muted">{t('findingPage.comments.empty')}</p>
                ) : (
                  <ul className="fp-comments">
                    {comments.map((row) => (
                      <li key={row.id}>
                        <span className="muted">{row.author} · {when(row.created_at)}</span>
                        <p>{row.body}</p>
                      </li>
                    ))}
                  </ul>
                )}
                <div className="fp-comment-form">
                  <textarea rows={3} value={comment} placeholder={t('findingPage.comments.placeholder')}
                            onChange={(event) => setComment(event.target.value)} />
                  <button className="btn-primary" disabled={commentBusy || !comment.trim()}
                          onClick={addComment}>
                    {commentBusy ? t('findingPage.comments.sending') : t('findingPage.comments.send')}
                  </button>
                </div>
              </div>
            )}
          </Card>

          <Card title={t('findingPage.attachments')}
                actions={(
                  <span className="row" style={{ gap: 8 }}>
                    <input ref={fileInput} type="file" style={{ display: 'none' }}
                           accept=".txt,.log,.json,.md,.csv,.xml,.sarif,.yml,.yaml,.conf,.ini"
                           onChange={(event) => attach(event.target.files?.[0])} />
                    <button className="btn-ghost" onClick={() => fileInput.current?.click()}>
                      + {t('findingPage.attachments.add')}
                    </button>
                  </span>
                )}>
            <p className="muted">{t('findingPage.attachments.hint')}</p>
            {fileError && <Banner kind="error">{fileError}</Banner>}
            {attachments === null ? <Loading rows={2} /> : attachments.length === 0 ? (
              <p className="muted">{t('findingPage.attachments.empty')}</p>
            ) : (
              <Table head={[t('findingPage.attachments.name'), t('findingPage.attachments.size'),
                            t('findingPage.attachments.state'), t('findingPage.attachments.addedBy'),
                            '']}>
                {attachments.map((row) => (
                  <tr key={row.id}>
                    <td>
                      <button className="linkish" onClick={() => openAttachment(row)}>{row.name}</button>
                    </td>
                    <td className="muted mono">{row.size_bytes} B</td>
                    <td><Pill>{row.redaction_state || 'unreviewed'}</Pill></td>
                    <td className="muted">{row.added_by}</td>
                    <td>
                      <button className="btn-ghost" onClick={() => openAttachment(row)}>
                        {t('findingPage.attachments.view')} →
                      </button>
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        </div>
      )}

      {tab === 'decide' && (
        <div className="stack">
          <Card title={t('findingPage.triage')}>
            <TriagePanel detail={detail} onChanged={() => setReload((n) => n + 1)} />
          </Card>
          <Card title={t('findingPage.vex')}>
            <VexSection findingId={detail.id} />
          </Card>
        </div>
      )}

      <Drawer open={!!viewing} title={viewing?.name || ''} onClose={() => setViewing(null)}>
        {viewing && (
          <div className="stack">
            <p className="muted mono">
              {viewing.media_type} · {viewing.size_bytes} B · sha256 {String(viewing.sha256).slice(0, 12)}…
            </p>
            <pre className="fp-attachment">{viewing.content}</pre>
          </div>
        )}
      </Drawer>

      <Dialog open={jiraOpen} title={t('findings.jira.dialogTitle')}
              onClose={() => setJiraOpen(false)} confirmLabel={t('findings.jira.confirm')}
              onConfirm={async () => {
                if (!jiraKey.trim()) { setJiraResult(t('findings.jira.projectKeyRequired')); return }
                try {
                  const result = await api.post('/api/v1/jira/links',
                                                { finding_id: detail.id, project_key: jiraKey.trim(), actor: 'console' })
                  setJiraResult(result.data?.issue_key || result.data?.last_error || t('findings.jira.queued'))
                  setJiraKey('')
                  setJiraOpen(false)
                } catch (caught) {
                  setJiraResult(String(caught.message || caught))
                }
              }}>
        <Input label={t('findings.jira.projectKeyLabel')} value={jiraKey}
               onChange={setJiraKey} placeholder="SEC" />
      </Dialog>

      <Dialog open={statusOpen} title={t('findingPage.status.title')}
              onClose={() => setStatusOpen(false)} confirmLabel={t('findingPage.status.confirm')}
              onConfirm={async () => {
                const ok = await act(`/api/v1/findings/${detail.id}/status`,
                                     { status: statusDraft.status, reason: statusDraft.reason.trim() || 'console action', actor: 'console' },
                                     { method: 'PATCH' })
                if (ok) setStatusOpen(false)
              }}>
        <p className="muted">
          {t('findingPage.status.body', { status: tOr(`status.${statusDraft.status}`, statusDraft.status) })}
        </p>
        <Input label={t('findingPage.status.reason')} value={statusDraft.reason}
               onChange={(value) => setStatusDraft((draft) => ({ ...draft, reason: value }))} />
      </Dialog>
    </div>
  )
}
