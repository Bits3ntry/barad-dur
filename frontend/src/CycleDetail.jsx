import React, { useEffect, useMemo, useState } from 'react'
import { api, actorName } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Stat, Table, Tabs,
} from './ui'
import { useI18n } from './i18n'
import FindingIntake from './FindingIntake'

/* One cycle, in four questions:
     alcance  — what is this campaign about (scope, jewels, profiles)
     plan     — what would it execute, and what is blocked
     carta    — the charter, the notes, the documents
     resultado— what came out, and the decision on each claim
   Every control here is a checkbox or a field, never a multi-select: choosing one
   thing must never require a modifier key. */

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

function csv(value) {
  return String(value || '').split(',').map((item) => item.trim()).filter(Boolean)
}

function charterToForm(charter) {
  const value = charter || {}
  return {
    objectives: (value.objectives || []).join(', '),
    business_priorities: (value.business_priorities || []).join(', '),
    risk_appetite: value.risk_appetite || '',
    exclusions: (value.exclusions || []).join(', '),
    sponsor: value.sponsor || '',
    operator: value.operator || '',
    engineering_partner: value.engineering_partner || '',
    criteria: (value.success_criteria || []).map((item) => ({
      name: item.name || '', metric: item.metric || '', target: item.target || '',
    })),
  }
}

function formToCharter(form, base) {
  return {
    ...(base || {}),
    objectives: csv(form.objectives),
    business_priorities: csv(form.business_priorities),
    risk_appetite: form.risk_appetite || null,
    exclusions: csv(form.exclusions),
    sponsor: form.sponsor || null,
    operator: form.operator || null,
    engineering_partner: form.engineering_partner || null,
    success_criteria: form.criteria
      .filter((item) => item.name.trim())
      .map((item) => ({ name: item.name.trim(), metric: item.metric.trim(),
                        target: item.target.trim() })),
  }
}

function Fact({ label, value, empty, hint }) {
  const has = Array.isArray(value) ? value.length > 0 : Boolean(value)
  return (
    <>
      <dt>{label}</dt>
      <dd className={has ? '' : 'muted'}>
        {has ? (Array.isArray(value) ? value.join(' · ') : value) : (empty || '—')}
        {hint && <div className="muted" style={{ fontSize: 11.5 }}>{hint}</div>}
      </dd>
    </>
  )
}

function Toggle({ checked, label, hint, onChange, disabled }) {
  return (
    <label className={`toggle-row${disabled ? ' is-disabled' : ''}`}>
      <input type="checkbox" checked={!!checked} disabled={disabled}
        onChange={(e) => onChange(e.target.checked)} />
      <span>
        <strong>{label}</strong>
        {hint && <span className="muted"> · {hint}</span>}
      </span>
    </label>
  )
}

export default function CycleDetail({ cycleId, onBack }) {
  const { t, tOr } = useI18n()
  const [cycle, setCycle] = useState(null)
  const [preview, setPreview] = useState(null)
  const [findings, setFindings] = useState([])
  const [jewels, setJewels] = useState([])
  const [profiles, setProfiles] = useState([])
  const [projects, setProjects] = useState([])
  const [docs, setDocs] = useState([])
  const [tab, setTab] = useState('alcance')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  const [form, setForm] = useState(charterToForm(null))
  const [recordOpen, setRecordOpen] = useState(false)
  const [detail, setDetail] = useState(null)
  const [reviewOpen, setReviewOpen] = useState(false)
  const [review, setReview] = useState({ results: '', learnings: '', criteria: [] })
  const [candidates, setCandidates] = useState([])
  const [candidatesLoaded, setCandidatesLoaded] = useState(false)
  const [claims, setClaims] = useState([])
  const [scan, setScan] = useState(null)
  const [scanBusy, setScanBusy] = useState(false)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [labels, setLabels] = useState({})

  useEffect(() => { load() }, [cycleId])

  async function load() {
    setError('')
    try {
      const [detail, previewResponse, ledger, jewelList, threat, projectList, docList,
        claims] = await Promise.all([
          api.get(`/api/v1/cycles/${cycleId}`),
          api.post(`/api/v1/cycles/${cycleId}/preview`, {}),
          api.get(`/api/v1/findings?cycle=${cycleId}&limit=200`),
          api.get('/api/v1/threat-model/crown-jewels'),
          api.get('/api/v1/threat-model'),
          api.get('/api/v1/projects'),
          api.get(`/api/v1/cycles/${cycleId}/documents`),
          // What the agents proposed and nobody accepted: it stays attached to the
          // campaign instead of disappearing with the run.
          api.get(`/api/v1/agents/candidates?cycle_id=${cycleId}&limit=200`)
            .catch(() => ({ data: [] })),
        ])
      setCycle(detail.data)
      setPreview(previewResponse.data)
      setFindings(ledger.data || [])
      setJewels(jewelList.data || [])
      setProfiles(threat.profiles || [])
      setProjects(projectList.data || [])
      setDocs(docList.data || [])
      setClaims(claims.data || [])
      setForm(charterToForm(detail.data.charter))
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  /* The button the whole flow hangs from: it dispatches the mission and lets the
     lane do the work. Nothing here talks to the agent — the platform queues the
     tasks and the worker claims them, which is what makes it autonomous. */
  async function startAutonomous() {
    setScanBusy(true)
    setError('')
    setNotice('')
    try {
      const response = await api.post(`/api/v1/agent/cycles/${cycleId}/scan`, {
        capability: 'validate',
        // No goal from here: the platform briefs the run from the deployed stack
        // (versions, technologies, open advisories) and derives the objective from
        // it. A hardcoded sentence made every campaign ask the same vague question.
        tools: ['curl'],
        auto_approve: true,
        actor: actorName(),
      })
      setScan(response.data)
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setScanBusy(false)
    }
  }

  const pendingClaims = claims.filter((row) => row.state === 'proposed').length
  // A mission is "in flight" from approval until it finishes; the banner is the
  // answer to "did my scan start".
  const LIVE = ['approved', 'running', 'dispatching']
  const liveMission = (cycle?.agent_missions || []).find((row) => LIVE.includes(row.status))
  const lastMission = (cycle?.agent_missions || [])[0]

  const charter = cycle?.charter || {}
  const selection = cycle?.selection || {}
  const editing = cycle?.state !== 'closed'
  const plan = preview?.plan
  const counters = useMemo(() => {
    const claims = findings.filter((row) => (row.triageStatus || row.triage_status) === 'new')
    return { total: findings.length, claims: claims.length }
  }, [findings])

  const environments = useMemo(() => {
    const set = new Set()
    projects.forEach((project) => {
      ;((project.counts || {}).environments || []).forEach((env) => set.add(env))
    })
    return [...set].sort()
  }, [projects])

  useEffect(() => {
    if (!query.trim()) { setResults(null); return }
    const timer = setTimeout(() => {
      api.get(`/api/v1/cycles/scope-search?q=${encodeURIComponent(query.trim())}`)
        .then((r) => setResults(r))
        .catch((e) => setError(String(e.message || e)))
    }, 220)
    return () => clearTimeout(timer)
  }, [query])

  // Labels come from the preview and from whatever the search returned, so a
  // selected asset reads as a host, not as a uuid.
  useEffect(() => {
    const next = { ...labels }
    ;((preview && preview.members_preview) || []).forEach((member) => {
      next[member.entity_id] = member.label
    })
    setLabels(next)
  }, [preview])

  async function writeSelection(next) {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/cycles/${cycleId}`, {
        selection: next, actor: 'console',
      })
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  function toggleList(field, value) {
    const current = selection[field] || []
    const next = current.includes(value)
      ? current.filter((item) => item !== value)
      : [...current, value]
    writeSelection({ ...selection, [field]: next })
  }

  function addTo(field, value, label) {
    const current = selection[field] || []
    if (current.includes(value)) return
    setLabels((prev) => ({ ...prev, [value]: label || prev[value] }))
    writeSelection({ ...selection, [field]: [...current, value] })
    setQuery('')
    setResults(null)
  }

  function removeFrom(field, value) {
    const current = selection[field] || []
    writeSelection({ ...selection, [field]: current.filter((item) => item !== value) })
  }

  function toggleWholeOrg(checked) {
    writeSelection({ ...selection, whole_org: checked })
  }

  async function writeProfileIds(next) {
    setBusy(true)
    setError('')
    try {
      await api.patch(`/api/v1/cycles/${cycleId}`, {
        charter: { ...charter, profile_ids: next }, actor: 'console',
      })
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  function toggleProfile(id) {
    const current = charter.profile_ids || []
    writeProfileIds(current.includes(id)
      ? current.filter((item) => item !== id)
      : [...current, id])
  }

  async function activate() {
    setBusy(true)
    try {
      const result = await api.post(
        `/api/v1/cycles/${cycleId}/activate?actor=console`, {})
      setNotice(t('cycles.notice.activated', { n: result.membership }))
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function saveCharter() {
    setBusy(true)
    try {
      await api.patch(`/api/v1/cycles/${cycleId}`, {
        charter: formToCharter(form, charter), actor: 'console',
      })
      setNotice(t('cycles.notice.charterSaved'))
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function saveNotes(value) {
    try {
      await api.patch(`/api/v1/cycles/${cycleId}`, { notes: value, actor: 'console' })
      setNotice(t('cycles.notice.notesSaved'))
      await load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function decide(finding, decision) {
    setBusy(true)
    try {
      await api.post(
        `/api/v1/cycles/${cycleId}/findings/${finding.id}/decide`,
        { decision, actor: 'console' })
      setNotice(t(`cycles.notice.${decision === 'validate' ? 'confirmed'
        : decision === 'dismiss' ? 'rejected' : 'accepted'}`))
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  function openReview() {
    const frozen = (cycle.frozen_charter || charter).success_criteria || []
    setReview({
      results: '', learnings: '',
      criteria: frozen.map((item) => ({ name: item.name, verdict: 'pending', note: '' })),
    })
    setReviewOpen(true)
  }

  async function submitReview() {
    setBusy(true)
    try {
      await api.post(`/api/v1/cycles/${cycleId}/review`, {
        results: review.results || null, learnings: review.learnings || null,
        criteria: review.criteria, actor: 'console',
      })
      setReviewOpen(false)
      setNotice(t('cycles.notice.reviewRecorded'))
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function closeCycle() {
    setBusy(true)
    try {
      await api.post(`/api/v1/cycles/${cycleId}/close?actor=console`, {})
      setNotice(t('cycles.notice.closed'))
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function loadCandidates() {
    try {
      const result = await api.get(`/api/v1/cycles/${cycleId}/candidates`)
      setCandidates(result.data || [])
      setCandidatesLoaded(true)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function uploadDocument(event) {
    const file = event.target.files && event.target.files[0]
    if (!file) return
    setBusy(true)
    try {
      const params = new URLSearchParams({
        filename: file.name, media_type: file.type || 'application/octet-stream',
        actor: 'console',
      })
      await api.postRaw(`/api/v1/cycles/${cycleId}/documents?${params}`, file)
      setNotice(t('cycles.notice.documentAdded'))
      event.target.value = ''
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function downloadDocument(doc) {
    try {
      const blob = await api.getBlob(`/api/v1/cycles/${cycleId}/documents/${doc.id}`)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = doc.filename
      link.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function removeDocument(doc) {
    setBusy(true)
    try {
      await api.del(`/api/v1/cycles/${cycleId}/documents/${doc.id}`)
      setNotice(t('cycles.notice.documentRemoved'))
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  if (!cycle) {
    return (
      <div className="stack">
        <PageHeader title={t('cycles.detail.title')}
          subtitle={t('cycles.detail.subtitle')}
          actions={<button className="mini" onClick={onBack}>
            {t('cycles.detail.back')}</button>} />
        {error ? <ErrorBanner error={error} /> : null}
      </div>
    )
  }

  if (recordOpen) {
    return (
      <FindingIntake cycleId={cycleId} jewels={jewels}
        onCancel={() => setRecordOpen(false)}
        onDone={() => {
          setRecordOpen(false)
          setNotice(t('cycles.notice.recorded'))
          setTab('outcome')
          load()
        }} />
    )
  }

  const criteria = charter.success_criteria || []
  // Not `window`: naming this after the global shadows it for the whole component,
  // and the first `window.location.hash = ...` in here then throws "cannot set
  // properties of undefined" — silently, because the click has nowhere to report it.
  const windowLabel = (cycle.starts_on || cycle.ends_on)
    ? `${cycle.starts_on ? new Date(cycle.starts_on).toLocaleDateString() : '—'} → `
      + `${cycle.ends_on ? new Date(cycle.ends_on).toLocaleDateString() : '—'}`
    : t('cycles.detail.noDates')
  const scopeCount = cycle.snapshot_at ? cycle.members : (preview?.members || 0)

  return (
    <div className="stack">
      <PageHeader
        title={cycle.name}
        subtitle={`${tOr(`cycles.kind.${cycle.kind}`, cycle.kind)} · `
          + `${tOr(`cycles.state.${cycle.state}`, cycle.state)} · ${windowLabel}`}
        actions={<>
          {cycle.state === 'planning' && (
            <button className="primary-action" disabled={busy || !preview?.members}
              onClick={activate}>{t('cycles.action.activate')}</button>
          )}
          {cycle.state === 'active' && (
            <>
              <button className="primary-action" disabled={scanBusy} onClick={startAutonomous}>
                {scanBusy ? t('cycle.scan.busy') : t('cycle.scan.start')}
              </button>
              <button className="mini" onClick={openReview}>
                {t('cycles.action.recordReview')}</button>
            </>
          )}
          {cycle.state === 'review' && (
            <button className="mini" disabled={busy} onClick={closeCycle}>
              {t('cycles.action.close')}</button>
          )}
          <button className="mini" onClick={onBack}>{t('cycles.detail.back')}</button>
        </>}
      />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}
      {scan && (
        <div className={scan.tasks?.length ? 'banner banner-ok' : 'banner banner-warn'}>
          <div>
            {scan.tasks?.length
              ? t('cycle.scan.created', {
                tasks: scan.tasks.length, targets: (scan.targets || []).length })
              : t('cycle.scan.empty')}
            {scan.mission?.goal && (
              <div className="muted">“{scan.mission.goal}”</div>
            )}
            {scan.briefing?.counts && (
              <div className="muted">
                {t('cycle.scan.briefed', {
                  components: scan.briefing.counts.components,
                  versions: scan.briefing.counts.versions,
                  advisories: scan.briefing.counts.advisories })}
              </div>
            )}
            {(scan.refused || []).length > 0 && (
              <div className="muted">
                {t('cycle.scan.refused', {
                  list: scan.refused.map((row) => row.target || row.value).join(', ') })}
              </div>
            )}
          </div>
          <a className="row-end" href={`#candidates::${cycleId}`}>{t('cycle.scan.candidates')}</a>
        </div>
      )}
      {cycle.amended && (
        <div className="banner banner-warn">{t('cycles.detail.amendedNote')}</div>
      )}

      {liveMission && (
        <div className="banner banner-warn">
          <div>
            {t('cycle.scan.running', {
              done: liveMission.done, tasks: liveMission.tasks })}
          </div>
          <a className="row-end" href="#missions">{t('cycle.scan.openMissions')}</a>
        </div>
      )}
      {!liveMission && lastMission && (
        <div className="banner banner-info">
          <div>
            {t('cycle.scan.lastMission', {
              status: lastMission.status, done: lastMission.done,
              tasks: lastMission.tasks })}
          </div>
          <a className="row-end" href="#missions">{t('cycle.scan.openMissions')}</a>
        </div>
      )}

      {pendingClaims > 0 && (
        <div className="banner banner-info">
          <div>{t('cycle.scan.pending', { n: pendingClaims })}</div>
          <a className="row-end" href={`#candidates::${cycleId}`}>
            {t('cycle.scan.candidates')}
          </a>
        </div>
      )}

      <div className="metrics">
        <Stat value={scopeCount} label={t('cycles.detail.kpi.scope')}
          hint={t('cycles.detail.kpi.scopeHint')} />
        <Stat value={(selection.components || []).length}
          label={t('cycles.detail.kpi.jewels')}
          hint={t('cycles.detail.kpi.jewelsHint')} />
        <Stat value={(charter.profile_ids || []).length}
          label={t('cycles.detail.kpi.profiles')}
          hint={t('cycles.detail.kpi.profilesHint')} />
        <Stat value={counters.claims} label={t('cycles.detail.kpi.claims')}
          hint={t('cycles.detail.kpi.claimsHint', { n: counters.total })} />
      </div>

      <Tabs active={tab} onChange={setTab} tabs={[
        { id: 'alcance', label: t('cycles.detail.tab.scope') },
        { id: 'plan', label: t('cycles.detail.tab.plan') },
        { id: 'carta', label: t('cycles.detail.tab.charter') },
        { id: 'outcome', label: t('cycles.detail.tab.outcome') },
      ]} />

      {tab === 'alcance' && (
        <div className="stack">
          <p className="muted">{t('cycles.detail.scope.note')}</p>

          <div className="scope-search">
            <input value={query} disabled={!editing}
              placeholder={t('cycles.detail.scope.searchPlaceholder')}
              onChange={(e) => setQuery(e.target.value)} />
            <span className="muted">{t('cycles.detail.scope.searchHint')}</span>
          </div>

          {results && (
            <div className="scope-results">
              {['assets', 'projects', 'repositories'].map((group) => (
                results[group] && results[group].length > 0 && (
                  <div key={group} className="scope-result-group">
                    <div className="toggle-group-title">
                      {t(`cycles.detail.scope.kind.${group}`)}
                    </div>
                    {results[group].map((item) => (
                      <button type="button" key={item.id} className="scope-result"
                        onClick={() => addTo(group, item.id, item.label)}>
                        <span>{item.label}</span>
                        <span className="muted">
                          {item.project || item.slug || item.provider || item.type || ''}
                        </span>
                        <span className="scope-add">+</span>
                      </button>
                    ))}
                  </div>
                )
              ))}
              {['assets', 'projects', 'repositories'].every(
                (group) => !((results[group] || []).length)) && (
                <div className="muted">{t('cycles.detail.scope.noMatch')}</div>
              )}
            </div>
          )}

          <div className="toggle-group">
            <div className="toggle-group-title">{t('cycles.detail.scope.selected')}</div>
            <label className="toggle-row">
              <input type="checkbox" checked={!!selection.whole_org} disabled={!editing}
                onChange={(e) => toggleWholeOrg(e.target.checked)} />
              <span><strong>{t('cycles.field.wholeOrg')}</strong>
                <span className="muted"> · {t('cycles.detail.scope.wholeOrgHint')}</span>
              </span>
            </label>
            {['assets', 'projects', 'repositories', 'environments'].map((field) => (
              (selection[field] || []).map((value) => (
                <div className="chip-row" key={`${field}:${value}`}>
                  <span className="chip chip-kind">{t(`cycles.detail.scope.kind.${field}`)}</span>
                  <span className="chip chip-value">{labels[value] || value}</span>
                  {editing && (
                    <button className="mini" onClick={() => removeFrom(field, value)}>×</button>
                  )}
                </div>
              ))
            ))}
            {!selection.whole_org
              && !['assets', 'projects', 'repositories', 'environments']
                .some((field) => (selection[field] || []).length) && (
              <span className="muted">{t('cycles.detail.scope.nothingSelected')}</span>
            )}
          </div>

          <div className="toggle-grid">
            <div className="toggle-group">
              <div className="toggle-group-title">{t('cycles.detail.scope.jewels')}</div>
              {jewels.length ? jewels.map((jewel) => (
                <Toggle key={jewel.id}
                  checked={(selection.components || []).includes(jewel.id)}
                  label={`${jewel.project_name ? `${jewel.project_name} › ` : ''}${jewel.name}`}
                  hint={`${jewel.criticality || 'crown'} · ${jewel.techniques} `
                    + t('cycles.detail.scope.techniques')}
                  disabled={!editing || busy}
                  onChange={() => toggleList('components', jewel.id)} />
              )) : (
                <span className="muted">{t('cycles.detail.scope.noJewels')}</span>
              )}
            </div>
            <div className="toggle-group">
              <div className="toggle-group-title">{t('cycles.detail.scope.profiles')}</div>
              {profiles.length ? profiles.map((profile) => (
                <Toggle key={profile.id}
                  checked={(charter.profile_ids || []).includes(profile.id)}
                  label={profile.name}
                  hint={`${t(`threat.profile.origin.${profile.origin || 'custom'}`)}`
                    + ` · ${(profile.techniques || []).length} `
                    + t('cycles.detail.scope.techniques')}
                  disabled={!editing || busy}
                  onChange={() => toggleProfile(profile.id)} />
              )) : (
                <span className="muted">{t('cycles.detail.scope.noProfiles')}</span>
              )}
            </div>
          </div>

          <div className="banner">
            {t('cycles.detail.scope.summary', {
              members: preview?.members ?? 0, memberships: cycle.members,
            })}
          </div>
          {preview?.gaps?.length ? (
            <div className="banner banner-warn">
              {preview.gaps.slice(0, 8).map((gap) => <div key={gap}>{gap}</div>)}
            </div>
          ) : null}
        </div>
      )}

      {tab === 'plan' && (
        <div className="stack">
          <p className="muted">{t('cycles.detail.plan.note')}</p>
          {plan ? (
            <>
              <p className="verdict-line">{t('cycles.detail.plan.coverage', plan.coverage)}</p>
              <p className="muted">
                {t('cycles.detail.plan.scope', plan.scope)}
                {' · '}
                {t('cycles.detail.plan.granted', {
                  list: (plan.granted_capabilities || []).join(', ') || '—',
                })}
              </p>
              {plan.techniques.length ? (
                <Table head={[t('threat.col.tactic'), t('threat.col.technique'),
                  t('threat.col.capability'), t('threat.col.state'),
                  t('cycles.detail.plan.jewels')]}>
                  {plan.techniques.map((row) => (
                    <tr key={row.id}>
                      <td className="muted">
                        {tOr(`threat.tactic.${row.tactic}`, row.tactic)}
                      </td>
                      <td className="title">
                        <span className="muted" style={{ marginRight: 6 }}>{row.id}</span>
                        {row.name}
                      </td>
                      <td className="muted">
                        {row.capability
                          ? tOr(`threat.capability.${row.capability}`, row.capability)
                          : t('threat.capability.none')}
                      </td>
                      <td className="muted">{t(`threat.state.${row.state}`)}</td>
                      <td className="muted">{(row.jewels || []).join(', ') || '—'}</td>
                    </tr>
                  ))}
                </Table>
              ) : (
                <EmptyState title={t('cycles.detail.plan.empty')}
                  hint={t('cycles.detail.plan.emptyHint')} />
              )}
            </>
          ) : null}
        </div>
      )}

      {tab === 'carta' && (
        <div className="stack">
          <p className="muted">
            {editing ? t('cycles.detail.charterEditable')
              : t('cycles.detail.charterAmendable')}
          </p>

          <section className="form-section">
            <h3>{t('cycles.detail.section.objectives')}</h3>
            <p className="muted">{t('cycles.detail.charter.objectivesHint')}</p>
            <label className="field">
              <span className="field-label">{t('cycles.detail.field.objectives')}</span>
              <textarea rows={2} value={form.objectives} disabled={!editing}
                placeholder={t('cycles.detail.charter.objectivesPlaceholder')}
                onChange={(e) => setForm((f) => ({ ...f, objectives: e.target.value }))} />
            </label>
            <label className="field">
              <span className="field-label">{t('cycles.detail.field.businessPriorities')}</span>
              <textarea rows={2} value={form.business_priorities} disabled={!editing}
                placeholder={t('cycles.detail.charter.prioritiesPlaceholder')}
                onChange={(e) => setForm((f) => ({ ...f, business_priorities: e.target.value }))} />
            </label>
            <div className="row">
              <label className="field" style={{ flex: 1 }}>
                <span className="field-label">{t('cycles.detail.field.riskAppetite')}</span>
                <select value={form.risk_appetite} disabled={!editing}
                  onChange={(e) => setForm((f) => ({ ...f, risk_appetite: e.target.value }))}>
                  <option value="">{t('cycles.detail.charter.risk.none')}</option>
                  <option value="low">{t('cycles.detail.charter.risk.low')}</option>
                  <option value="medium">{t('cycles.detail.charter.risk.medium')}</option>
                  <option value="high">{t('cycles.detail.charter.risk.high')}</option>
                </select>
              </label>
              <label className="field" style={{ flex: 1 }}>
                <span className="field-label">{t('cycles.detail.field.exclusions')}</span>
                <input value={form.exclusions} disabled={!editing}
                  placeholder={t('cycles.hint.csv')}
                  onChange={(e) => setForm((f) => ({ ...f, exclusions: e.target.value }))} />
              </label>
            </div>
          </section>

          <section className="form-section">
            <h3>{t('cycles.detail.field.successCriteria')}</h3>
            <p className="muted">{t('cycles.detail.charter.criteriaHint')}</p>
            {form.criteria.map((item, index) => (
              <div className="row" key={index}>
                <input value={item.name} disabled={!editing}
                  placeholder={t('cycles.detail.criteria.name')}
                  onChange={(e) => setForm((f) => {
                    const criteria = [...f.criteria]
                    criteria[index] = { ...criteria[index], name: e.target.value }
                    return { ...f, criteria }
                  })} />
                <input value={item.metric} disabled={!editing}
                  placeholder={t('cycles.detail.criteria.metric')}
                  onChange={(e) => setForm((f) => {
                    const criteria = [...f.criteria]
                    criteria[index] = { ...criteria[index], metric: e.target.value }
                    return { ...f, criteria }
                  })} />
                <input value={item.target} disabled={!editing}
                  placeholder={t('cycles.detail.criteria.target')}
                  onChange={(e) => setForm((f) => {
                    const criteria = [...f.criteria]
                    criteria[index] = { ...criteria[index], target: e.target.value }
                    return { ...f, criteria }
                  })} />
                {editing && (
                  <button className="mini" onClick={() => setForm((f) => ({
                    ...f,
                    criteria: f.criteria.filter((_row, i) => i !== index),
                  }))}>×</button>
                )}
              </div>
            ))}
            {!form.criteria.length && (
              <span className="muted">{t('cycles.detail.criteriaEmpty')}</span>
            )}
            {editing && (
              <button className="mini" onClick={() => setForm((f) => ({
                ...f, criteria: [...f.criteria, { name: '', metric: '', target: '' }],
              }))}>{t('cycles.detail.addCriterion')}</button>
            )}
          </section>

          <section className="form-section">
            <h3>{t('cycles.detail.section.roles')}</h3>
            <div className="row">
              <label className="field" style={{ flex: 1 }}>
                <span className="field-label">{t('cycles.detail.field.sponsor')}</span>
                <input value={form.sponsor} disabled={!editing}
                  onChange={(e) => setForm((f) => ({ ...f, sponsor: e.target.value }))} />
              </label>
              <label className="field" style={{ flex: 1 }}>
                <span className="field-label">{t('cycles.detail.field.operator')}</span>
                <input value={form.operator} disabled={!editing}
                  onChange={(e) => setForm((f) => ({ ...f, operator: e.target.value }))} />
              </label>
              <label className="field" style={{ flex: 1 }}>
                <span className="field-label">{t('cycles.detail.field.engineeringPartner')}</span>
                <input value={form.engineering_partner} disabled={!editing}
                  onChange={(e) => setForm((f) => ({ ...f, engineering_partner: e.target.value }))} />
              </label>
            </div>
          </section>

          <section className="form-section">
            <h3>{t('cycles.detail.field.notes')}</h3>
            {cycle.state === 'closed' ? (
              <p className="muted">{cycle.notes || t('cycles.detail.notSet')}</p>
            ) : (
              <textarea rows={3} defaultValue={cycle.notes || ''}
                placeholder={t('cycles.detail.notesHint')}
                onBlur={(e) => {
                  if (e.target.value !== (cycle.notes || '')) saveNotes(e.target.value)
                }} />
            )}
            <h3>{t('cycles.detail.field.documents')}</h3>
            <div className="stack">
              {docs.length ? docs.map((doc) => (
                <div className="row" key={doc.id}>
                  <button className="mini" onClick={() => downloadDocument(doc)}>
                    {doc.filename}
                  </button>
                  <span className="muted">
                    {Math.max(1, Math.round((doc.size || 0) / 1024))} KB
                  </span>
                  {cycle.state !== 'closed' && (
                    <button className="mini" disabled={busy}
                      onClick={() => removeDocument(doc)}>×</button>
                  )}
                </div>
              )) : (
                <span className="muted">{t('cycles.detail.docsEmpty')}</span>
              )}
              {cycle.state !== 'closed' && (
                <input type="file" disabled={busy} onChange={uploadDocument} />
              )}
            </div>
          </section>

          {editing && (
            <div className="row">
              <button className="primary-action" disabled={busy} onClick={saveCharter}>
                {t('cycles.detail.saveCharter')}
              </button>
              <span className="muted">{t('cycles.detail.charter.saveHint')}</span>
            </div>
          )}
        </div>
      )}

      {tab === 'outcome' && (
        <div className="stack">
          <p className="muted">{t('cycles.detail.outcomeNote', {
            claims: counters.claims, total: counters.total,
          })}</p>
          <div className="row">
            {cycle.state !== 'closed' && (
              <button className="mini" onClick={() => setRecordOpen(true)}>
                {t('cycles.detail.record')}
              </button>
            )}
            {cycle.snapshot_at && (
              <button className="mini" onClick={loadCandidates}>
                {t('cycles.action.candidates')}
              </button>
            )}
            <a className="mini" href={`#candidates::${cycleId}`}>{t('cycle.scan.candidates')}</a>
            <a className="mini" href={`#findings::cycle=${cycleId}`}>{t('cycles.detail.seeFindings')}</a>
            <span className="muted">{t('cycles.detail.candidatesNote')}</span>
          </div>
          {findings.length ? (() => {
            // The gate is the point of this screen, so the two states are two
            // lists: what a pentester claimed (not a finding yet) and what a
            // person accepted. One mixed table made the difference invisible,
            // which is exactly the "ya está listada en findings" confusion.
            const triageOf = (row) => row.triageStatus || row.triage_status
            const claims = findings.filter((row) => triageOf(row) === 'new')
            const settled = findings.filter((row) => triageOf(row) !== 'new')
            const render = (row) => {
              const triage = triageOf(row)
              return (
                <tr key={row.id}>
                  <td className="title">
                    {/* The finding has its own address, and a claim is a finding:
                        an unconfirmed row must open the same page a confirmed one
                        does, or the operator has to confirm a claim to read it. */}
                    <button className="link-button"
                            onClick={() => { window.location.hash = `findings::${row.id}` }}>
                      {row.title}
                    </button>
                    {(row.endpoint || row.url) && (
                      <div className="muted" style={{ fontSize: 11.5 }}>
                        {row.http_method ? `${row.http_method} ` : ''}
                        {row.endpoint || row.url}
                      </div>
                    )}
                    {row.component_name && (
                      <div className="muted mono" style={{ fontSize: 11.5 }}>
                        {row.component_name}{row.component_version
                          ? ` ${row.component_version}` : ''}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className={`sev sev-${String(row.severity || 'info').toLowerCase()}`}>
                      {row.severity || 'info'}
                    </span>
                  </td>
                  <td className="muted">{tOr(`cycles.triage.${triage}`, triage)}</td>
                  <td className="muted">{row.origin || row.source || '—'}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {triage === 'new' && cycle.state !== 'closed' && (
                      <>
                        <button className="mini" disabled={busy}
                          onClick={() => decide(row, 'validate')}>
                          {t('cycles.detail.confirm')}
                        </button>
                        <button className="mini" disabled={busy}
                          onClick={() => decide(row, 'dismiss')}>
                          {t('cycles.detail.reject')}
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              )
            }
            const head = [t('cycles.col.name'), t('cycles.detail.col.severity'),
              t('cycles.detail.col.state'), t('cycles.detail.col.origin'), '']
            return (
              <>
                <div className="stack">
                  <h4 className="ledger-head">
                    {t('cycles.detail.claims.title', { n: claims.length })}
                  </h4>
                  <p className="muted">{t('cycles.detail.claims.hint')}</p>
                  {claims.length
                    ? <Table head={head}>{claims.map(render)}</Table>
                    : <p className="muted">{t('cycles.detail.claims.none')}</p>}
                </div>
                {settled.length > 0 && (
                  <div className="stack">
                    <h4 className="ledger-head">
                      {t('cycles.detail.confirmed.title', { n: settled.length })}
                    </h4>
                    <Table head={head}>{settled.map(render)}</Table>
                  </div>
                )}
              </>
            )
          })() : (
            <EmptyState title={t('cycles.detail.ledgerEmpty')}
              hint={t('cycles.detail.ledgerEmptyHint')} />
          )}
          {candidatesLoaded && (
            candidates.length > 0 ? (
              <Table head={[t('cycles.detail.col.value'),
                t('cycles.detail.col.included')]}>
                {candidates.map((item) => (
                  <tr key={item.asset.id}>
                    <td className="title">{item.asset.value}</td>
                    <td className="muted">
                      {new Date(item.discovered_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              /* A button that shows nothing reads as broken: the answer here is
                 "no new assets appeared", not silence. */
              <p className="muted">{t('cycles.detail.candidatesEmpty')}</p>
            )
          )}
        </div>
      )}

      <Dialog open={!!detail} title={detail?.title || ''}
        onClose={() => setDetail(null)} onConfirm={() => setDetail(null)}
        confirmLabel={t('finding.close')}>
        {detail && (
          <div className="detail">
            <dl>
              <dt>{t('finding.field.cwe')}</dt>
              <dd>{detail.cwe || '—'}</dd>
              <dt>{t('finding.field.severity')}</dt>
              <dd>{detail.severity || '—'}</dd>
              <dt>{t('finding.field.product')}</dt>
              <dd>{detail.product_component_name || '—'}</dd>
              <dt>{t('finding.field.where')}</dt>
              <dd>
                {detail.http_method ? `${detail.http_method} ` : ''}
                {detail.url || '—'}{detail.endpoint || ''}
              </dd>
              <dt>{t('finding.field.auth')}</dt>
              <dd>
                {detail.auth_required ? t('finding.yes') : t('finding.no')}
                {detail.auth_profile_name ? ` · ${detail.auth_profile_name}` : ''}
              </dd>
              <dt>{t('finding.field.expected')}</dt>
              <dd>{detail.expected_result || '—'}</dd>
              <dt>{t('finding.field.observed')}</dt>
              <dd>{detail.observed_result || '—'}</dd>
              <dt>{t('finding.field.output')}</dt>
              <dd>{detail.validation_output || '—'}</dd>
              <dt>{t('finding.field.impact')}</dt>
              <dd>{detail.impact || '—'}</dd>
              <dt>{t('finding.field.reproduction')}</dt>
              <dd style={{ whiteSpace: 'pre-wrap' }}>{detail.reproduction || '—'}</dd>
              <dt>{t('finding.section.proof')}</dt>
              <dd>
                <pre className="proof">{detail.proof_request || '—'}</pre>
                <pre className="proof">{detail.proof_response || '—'}</pre>
              </dd>
              <dt>{t('finding.when')}</dt>
              <dd>{detail.first_seen_at
                ? new Date(detail.first_seen_at).toLocaleString() : '—'}</dd>
            </dl>
          </div>
        )}
      </Dialog>

      <Dialog open={reviewOpen} title={t('cycles.dialog.review.title')}
        onClose={() => setReviewOpen(false)} onConfirm={submitReview}
        confirmLabel={t('cycles.action.saveReview')}>
        <div className="stack">
          <Input label={t('cycles.field.results')} textarea rows={3} value={review.results}
            onChange={(v) => setReview((s) => ({ ...s, results: v }))} />
          <Input label={t('cycles.field.learnings')} textarea rows={2} value={review.learnings}
            onChange={(v) => setReview((s) => ({ ...s, learnings: v }))} />
          {review.criteria.map((item, index) => (
            <div className="row" key={item.name || index}>
              <span className="muted">{item.name}</span>
              <select value={item.verdict}
                onChange={(e) => setReview((s) => {
                  const criteria = [...s.criteria]
                  criteria[index] = { ...criteria[index], verdict: e.target.value }
                  return { ...s, criteria }
                })}>
                {['met', 'not_met', 'not_measurable', 'pending'].map((value) => (
                  <option key={value} value={value}>{t(`cycles.verdict.${value}`)}</option>
                ))}
              </select>
            </div>
          ))}
          <span className="muted">{t('cycles.review.note')}</span>
        </div>
      </Dialog>
    </div>
  )
}
