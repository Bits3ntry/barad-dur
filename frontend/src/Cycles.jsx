import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, Table, Tabs, usePage,
} from './ui'

/* A cycle is a time-boxed evaluation: charter, explicit selection, a frozen
   reference on activation, criteria verdicts on review. It grants nothing. */

const STATES = ['planning', 'active', 'review', 'closed']
const VERDICTS = [
  { value: 'met', label: 'met' },
  { value: 'not_met', label: 'not met' },
  { value: 'not_measurable', label: 'not measurable' },
  { value: 'pending', label: 'pending' },
]

const EMPTY = {
  name: '', description: '', owner: '', starts_on: '', ends_on: '',
  objectives: '', success_criteria: '', projects: '', groups: '',
  environments: '', whole_org: false,
}

export default function Cycles() {
  const [cycles, setCycles] = useState([])
  const [cycle, setCycle] = useState(null)
  const [preview, setPreview] = useState(null)
  const [candidates, setCandidates] = useState([])
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ ...EMPTY })
  const [reviewOpen, setReviewOpen] = useState(false)
  const [review, setReview] = useState({ results: '', learnings: '', criteria: [] })
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  // A cycle closes but is never deleted, so the index only grows: it pages.
  const paged = usePage(cycles, 25)

  useEffect(() => { load() }, [])

  function load() {
    api.get('/api/v1/cycles')
      .then((r) => setCycles(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  function csv(value) {
    return value.split(',').map((item) => item.trim()).filter(Boolean)
  }

  async function createCycle() {
    if (!form.name.trim()) return
    try {
      const body = {
        name: form.name.trim(),
        description: form.description || null,
        owner: form.owner || null,
        starts_on: form.starts_on ? `${form.starts_on}T00:00:00+00:00` : null,
        ends_on: form.ends_on ? `${form.ends_on}T00:00:00+00:00` : null,
        charter: {
          objectives: csv(form.objectives),
          success_criteria: csv(form.success_criteria),
        },
        selection: {
          projects: csv(form.projects),
          groups: csv(form.groups),
          environments: csv(form.environments),
          whole_org: form.whole_org,
        },
        actor: 'console',
      }
      const created = await api.post('/api/v1/cycles', body)
      setCreating(false)
      setForm({ ...EMPTY })
      setNotice(`created ${created.data.name} in planning`)
      load()
      openCycle(created.data.id)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function openCycle(cycleId) {
    if (cycle?.id === cycleId) { setCycle(null); setPreview(null); return }
    try {
      const [{ data }, previewResponse] = await Promise.all([
        api.get(`/api/v1/cycles/${cycleId}`),
        api.post(`/api/v1/cycles/${cycleId}/preview`, {}),
      ])
      setCycle(data)
      setPreview(previewResponse.data)
      setCandidates([])
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function activate() {
    if (!cycle) return
    try {
      const result = await api.post(
        `/api/v1/cycles/${cycle.id}/activate?actor=console`, {})
      setNotice(`activated: ${result.membership} members frozen`)
      openCycle(cycle.id)
      setCycle(null)
      load()
      setTimeout(() => openCycle(cycle.id), 50)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function linkAuto() {
    try {
      const result = await api.post(`/api/v1/cycles/${cycle.id}/link-findings`,
        { auto: true, actor: 'console' })
      setNotice(`${result.data.linked} findings linked from the frozen projects`)
      openCycle(cycle.id)
      setCycle(null)
      load()
      setTimeout(() => openCycle(cycle.id), 50)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function loadCandidates() {
    try {
      const result = await api.get(`/api/v1/cycles/${cycle.id}/candidates`)
      setCandidates(result.data || [])
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function submitReview() {
    try {
      await api.post(`/api/v1/cycles/${cycle.id}/review`, {
        results: review.results || null,
        learnings: review.learnings || null,
        criteria: review.criteria.map((item) => ({
          name: item.name, verdict: item.verdict, note: item.note || null,
        })),
        actor: 'console',
      })
      setReviewOpen(false)
      setReview({ results: '', learnings: '', criteria: [] })
      setNotice('review recorded; the cycle is in review')
      openCycle(cycle.id)
      setCycle(null)
      load()
      setTimeout(() => openCycle(cycle.id), 50)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function close() {
    try {
      await api.post(`/api/v1/cycles/${cycle.id}/close?actor=console`, {})
      setNotice('cycle closed; history kept and the inventory keeps running')
      openCycle(cycle.id)
      setCycle(null)
      load()
      setTimeout(() => openCycle(cycle.id), 50)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Cycles"
        subtitle="Time-boxed evaluations · a cycle freezes a reference and grants no authorization"
        actions={<>
          <button className="primary-action" onClick={() => setCreating(true)}>new cycle</button>
          <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
            total={paged.total} perPage={paged.perPage} unit="cycles" />
        </>}
      />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {cycles.length ? (
        <>
          <Table head={['name', 'state', 'owner', 'window', 'members', 'findings', '']}>
            {paged.rows.map((row) => (
              <tr key={row.id} className={cycle?.id === row.id ? 'selected' : ''}>
                <td className="title">{row.name}
                  <div className="muted" style={{ fontSize: 11.5 }}>{row.description}</div>
                </td>
                <td><span className={row.state === 'active' ? 'pill' : 'muted'}>{row.state}</span></td>
                <td className="muted">{row.owner || '—'}</td>
                <td className="muted">
                  {row.starts_on ? new Date(row.starts_on).toLocaleDateString() : '—'}
                  {' → '}
                  {row.ends_on ? new Date(row.ends_on).toLocaleDateString() : '—'}
                </td>
                <td>{row.members}</td>
                <td>{row.linked_findings}</td>
                <td>
                  <button className="mini" onClick={() => openCycle(row.id)}>
                    {cycle?.id === row.id ? 'hide' : 'open'}
                  </button>
                </td>
              </tr>
            ))}
          </Table>
          <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
            total={paged.total} perPage={paged.perPage} unit="cycles" className="row-end" />
        </>
      ) : (
        !error && <EmptyState title="No cycles yet"
          hint="Create one with an explicit selection: projects, groups or environments. An empty selection is incomplete, and 'whole organization' must be explicit." />
      )}

      {cycle && (
        <div className="detail" style={{ marginTop: 12 }}>
          <dl>
            <dt>state</dt>
            <dd>
              <span className="pill">{cycle.state}</span>
              {cycle.snapshot_at && (
                <span className="muted"> frozen {new Date(cycle.snapshot_at).toLocaleString()}</span>
              )}
            </dd>
            <dt>charter</dt>
            <dd className="muted">
              {(cycle.charter.objectives || []).join(' · ') || 'no objectives recorded'}
            </dd>
            <dt>selection</dt>
            <dd className="muted">
              {JSON.stringify(cycle.selection)}
            </dd>
            {preview && (
              <>
                <dt>preview</dt>
                <dd>
                  {preview.members} members
                  {preview.incomplete && <span className="sev sev-medium"> · incomplete</span>}
                  {preview.gaps.map((gap) => (
                    <div key={gap} className="muted" style={{ fontSize: 11.5 }}>{gap}</div>
                  ))}
                  <div className="muted" style={{ fontSize: 11.5 }}>{preview.note}</div>
                </dd>
              </>
            )}
            <dt>actions</dt>
            <dd>
              <div className="row">
                {cycle.state === 'planning' && (
                  <button className="mini" disabled={preview?.incomplete} onClick={activate}>
                    activate and freeze
                  </button>
                )}
                {['active', 'review'].includes(cycle.state) && (
                  <button className="mini" onClick={linkAuto}>link project findings</button>
                )}
                {cycle.state === 'active' && (
                  <button className="mini" onClick={() => {
                    setReview({ results: '', learnings: '', criteria: [
                      { name: 'no critical open', verdict: 'pending', note: '' },
                    ] })
                    setReviewOpen(true)
                  }}>record review</button>
                )}
                {cycle.state === 'review' && (
                  <button className="mini" onClick={close}>close cycle</button>
                )}
                {cycle.snapshot_at && (
                  <button className="mini" onClick={loadCandidates}>candidates</button>
                )}
              </div>
            </dd>
            {cycle.review?.results && (
              <>
                <dt>review</dt>
                <dd className="muted">
                  {cycle.review.results}
                  {(cycle.review.criteria || []).map((item) => (
                    <div key={item.name} style={{ fontSize: 11.5 }}>
                      {item.name}: <strong>{item.verdict}</strong>
                    </div>
                  ))}
                </dd>
              </>
            )}
            {candidates.length > 0 && (
              <>
                <dt>outside the reference</dt>
                <dd className="muted">
                  {candidates.map((item) => (
                    <div key={item.asset.id} className="occ-row">
                      {item.asset.value} · discovered {new Date(item.discovered_at).toLocaleDateString()}
                    </div>
                  ))}
                  <div style={{ fontSize: 11.5 }}>these belong to the next cycle</div>
                </dd>
              </>
            )}
          </dl>
        </div>
      )}

      <Dialog open={creating} title="New cycle"
        onClose={() => setCreating(false)} onConfirm={createCycle} confirmLabel="create">
        <div className="stack">
          <Input label="name" value={form.name}
            onChange={(v) => setForm((s) => ({ ...s, name: v }))} />
          <Input label="description" value={form.description}
            onChange={(v) => setForm((s) => ({ ...s, description: v }))} />
          <Input label="owner" value={form.owner}
            onChange={(v) => setForm((s) => ({ ...s, owner: v }))} />
          <div className="row">
            <Input label="starts on" type="date" value={form.starts_on}
              onChange={(v) => setForm((s) => ({ ...s, starts_on: v }))} />
            <Input label="ends on" type="date" value={form.ends_on}
              onChange={(v) => setForm((s) => ({ ...s, ends_on: v }))} />
          </div>
          <Input label="objectives" value={form.objectives} hint="comma separated"
            onChange={(v) => setForm((s) => ({ ...s, objectives: v }))} />
          <Input label="success criteria" value={form.success_criteria} hint="comma separated"
            onChange={(v) => setForm((s) => ({ ...s, success_criteria: v }))} />
          <Input label="projects (slugs)" value={form.projects} hint="aurea, aurea-web"
            onChange={(v) => setForm((s) => ({ ...s, projects: v }))} />
          <Input label="inventory groups" value={form.groups}
            onChange={(v) => setForm((s) => ({ ...s, groups: v }))} />
          <Input label="environments" value={form.environments} hint="production, staging"
            onChange={(v) => setForm((s) => ({ ...s, environments: v }))} />
          <label className="check">
            <input type="checkbox" checked={form.whole_org}
              onChange={(e) => setForm((s) => ({ ...s, whole_org: e.target.checked }))} />
            <span>whole organization (explicit)</span>
          </label>
        </div>
      </Dialog>

      <Dialog open={reviewOpen} title="Record the cycle review"
        onClose={() => setReviewOpen(false)} onConfirm={submitReview} confirmLabel="save review">
        <div className="stack">
          <Input label="results" textarea rows={3} value={review.results}
            onChange={(v) => setReview((s) => ({ ...s, results: v }))} />
          <Input label="learnings" textarea rows={2} value={review.learnings}
            onChange={(v) => setReview((s) => ({ ...s, learnings: v }))} />
          {review.criteria.map((item, index) => (
            <div key={index} className="row">
              <input value={item.name} placeholder="criterion"
                onChange={(e) => setReview((s) => {
                  const criteria = [...s.criteria]
                  criteria[index] = { ...criteria[index], name: e.target.value }
                  return { ...s, criteria }
                })} />
              <select value={item.verdict}
                onChange={(e) => setReview((s) => {
                  const criteria = [...s.criteria]
                  criteria[index] = { ...criteria[index], verdict: e.target.value }
                  return { ...s, criteria }
                })}>
                {VERDICTS.map((verdict) => (
                  <option key={verdict.value} value={verdict.value}>{verdict.label}</option>
                ))}
              </select>
            </div>
          ))}
          <span className="muted">
            "not measurable" is a legitimate verdict: it says the cycle could not
            measure the criterion, which is different from failing it.
          </span>
        </div>
      </Dialog>
    </div>
  )
}
