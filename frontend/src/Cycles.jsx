import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, Select, Table, usePage,
} from './ui'
import { useI18n } from './i18n'

/* The cycles list is an index, not a workspace: a cycle is a screen of its own
   (#cycles::<uuid>) where its charter, scope, ledger and outcome live. Creating
   one lands you there, because a cycle with nothing filled in is a draft you are
   about to work on. */

const KINDS = ['sweep', 'campaign', 'pentest_external', 'pentest_internal',
  'supply_chain', 'ai_redteam']

const EMPTY = {
  name: '', description: '', notes: '', owner: '', kind: 'sweep',
  starts_on: '', ends_on: '', projects: '', groups: '', environments: '',
  whole_org: false, components: [], profile_ids: [],
}

export default function Cycles() {
  const { t, tOr } = useI18n()
  const [cycles, setCycles] = useState([])
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ ...EMPTY })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [jewels, setJewels] = useState([])
  const [profiles, setProfiles] = useState([])
  const [plan, setPlan] = useState(null)

  // A cycle closes but is never deleted, so the index only grows: it pages.
  const paged = usePage(cycles, 25)

  useEffect(() => { load() }, [])

  useEffect(() => {
    if (!creating) return
    Promise.all([
      api.get('/api/v1/threat-model/crown-jewels'),
      api.get('/api/v1/threat-model'),
    ]).then(([jewelList, threat]) => {
      setJewels(jewelList.data || [])
      setProfiles(threat.profiles || [])
    }).catch((e) => setError(String(e.message || e)))
  }, [creating])

  // What the cycle would execute, computed before it exists: the plan is the
  // reason the form asks for jewels and profiles at all.
  useEffect(() => {
    if (!creating) return
    const timer = setTimeout(() => {
      if (!form.components.length && !form.profile_ids.length) {
        setPlan(null)
        return
      }
      api.post('/api/v1/threat-model/plan', {
        components: form.components, profile_ids: form.profile_ids,
      }).then((r) => setPlan(r.data || null))
        .catch((e) => setError(String(e.message || e)))
    }, 250)
    return () => clearTimeout(timer)
  }, [creating, form.components, form.profile_ids])

  function load() {
    api.get('/api/v1/cycles')
      .then((r) => setCycles(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  function csv(value) {
    return value.split(',').map((item) => item.trim()).filter(Boolean)
  }

  function open(cycleId) {
    window.location.hash = `cycles::${cycleId}`
  }

  async function createCycle() {
    if (!form.name.trim()) return
    setBusy(true)
    setError('')
    try {
      const created = await api.post('/api/v1/cycles', {
        name: form.name.trim(),
        description: form.description || null,
        owner: form.owner || null,
        kind: form.kind,
        starts_on: form.starts_on ? `${form.starts_on}T00:00:00+00:00` : null,
        ends_on: form.ends_on ? `${form.ends_on}T00:00:00+00:00` : null,
        notes: form.notes || null,
        charter: { objectives: [], success_criteria: [],
                   profile_ids: form.profile_ids },
        selection: {
          projects: csv(form.projects),
          groups: csv(form.groups),
          environments: csv(form.environments),
          components: form.components,
          whole_org: form.whole_org,
        },
        actor: 'console',
      })
      setCreating(false)
      setForm({ ...EMPTY })
      load()
      open(created.data.id)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title={t('cycles.title')}
        subtitle={t('cycles.subtitle')}
        actions={<>
          <button className="primary-action" onClick={() => setCreating(true)}>
            {t('cycles.action.new')}
          </button>
          <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
            total={paged.total} perPage={paged.perPage} unit="cycles" />
        </>}
      />

      {error && <ErrorBanner error={error} />}

      {cycles.length ? (
        <>
          <Table head={[t('cycles.col.name'), t('cycles.col.kind'), t('cycles.col.state'),
            t('common.owner'), t('cycles.col.window'), t('cycles.col.members'),
            t('cycles.col.findings'), '']}>
            {paged.rows.map((row) => (
              <tr key={row.id}>
                <td className="title">{row.name}
                  <div className="muted" style={{ fontSize: 11.5 }}>{row.description}</div>
                </td>
                <td className="muted">{tOr(`cycles.kind.${row.kind}`, row.kind || 'sweep')}</td>
                <td><span className={row.state === 'active' ? 'pill' : 'muted'}>
                  {tOr(`cycles.state.${row.state}`, row.state)}</span></td>
                <td className="muted">{row.owner || '—'}</td>
                <td className="muted">
                  {row.starts_on ? new Date(row.starts_on).toLocaleDateString() : '—'}
                  {' → '}
                  {row.ends_on ? new Date(row.ends_on).toLocaleDateString() : '—'}
                </td>
                <td>{row.members}</td>
                <td>{row.linked_findings}</td>
                <td className="nowrap">
                  <button className="mini" onClick={() => open(row.id)}>
                    {t('common.open')}
                  </button>
                </td>
              </tr>
            ))}
          </Table>
          <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
            total={paged.total} perPage={paged.perPage} unit="cycles" className="row-end" />
        </>
      ) : (
        !error && <EmptyState title={t('cycles.empty.title')}
          hint={t('cycles.empty.hint')} />
      )}

      <Dialog open={creating} title={t('cycles.dialog.new.title')}
        onClose={() => setCreating(false)} onConfirm={createCycle}
        confirmLabel={busy ? t('common.saving') : t('cycles.action.create')}>
        <div className="stack">
          <Input label={t('cycles.field.name')} value={form.name}
            onChange={(v) => setForm((s) => ({ ...s, name: v }))} />
          <Input label={t('cycles.field.description')} value={form.description}
            onChange={(v) => setForm((s) => ({ ...s, description: v }))} />
          <div className="field">
            <label className="field-label">{t('cycles.field.jewels')}</label>
            <select multiple size={4} value={form.components}
              onChange={(e) => setForm((s) => ({
                ...s, components: [...e.target.selectedOptions].map((o) => o.value),
              }))}>
              {jewels.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.project_name ? `${item.project_name} › ` : ''}{item.name}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label className="field-label">{t('cycles.field.profiles')}</label>
            <select multiple size={3} value={form.profile_ids}
              onChange={(e) => setForm((s) => ({
                ...s, profile_ids: [...e.target.selectedOptions].map((o) => o.value),
              }))}>
              {profiles.map((item) => (
                <option key={item.id} value={item.id}>{item.name}</option>
              ))}
            </select>
          </div>
          {plan && (
            <div className="banner">
              {t('cycles.dialog.plan', plan.coverage)}
            </div>
          )}
          <Input label={t('cycles.field.notes')} textarea rows={3} value={form.notes}
            hint={t('cycles.field.notesHint')}
            onChange={(v) => setForm((s) => ({ ...s, notes: v }))} />
          <Select label={t('cycles.field.kind')} value={form.kind}
            options={KINDS.map((value) => ({
              value, label: tOr(`cycles.kind.${value}`, value),
            }))}
            onChange={(v) => setForm((s) => ({ ...s, kind: v }))} />
          <Input label={t('cycles.field.owner')} value={form.owner}
            onChange={(v) => setForm((s) => ({ ...s, owner: v }))} />
          <div className="row">
            <Input label={t('cycles.field.startsOn')} type="date" value={form.starts_on}
              onChange={(v) => setForm((s) => ({ ...s, starts_on: v }))} />
            <Input label={t('cycles.field.endsOn')} type="date" value={form.ends_on}
              onChange={(v) => setForm((s) => ({ ...s, ends_on: v }))} />
          </div>
          <Input label={t('cycles.field.projects')} value={form.projects}
            hint="aurea, aurea-web"
            onChange={(v) => setForm((s) => ({ ...s, projects: v }))} />
          <Input label={t('cycles.field.groups')} value={form.groups}
            onChange={(v) => setForm((s) => ({ ...s, groups: v }))} />
          <Input label={t('cycles.field.environments')} value={form.environments}
            hint="production, staging"
            onChange={(v) => setForm((s) => ({ ...s, environments: v }))} />
          <label className="check">
            <input type="checkbox" checked={form.whole_org}
              onChange={(e) => setForm((s) => ({ ...s, whole_org: e.target.checked }))} />
            <span>{t('cycles.field.wholeOrg')}</span>
          </label>
          <span className="muted">{t('cycles.dialog.new.hint')}</span>
        </div>
      </Dialog>
    </div>
  )
}
