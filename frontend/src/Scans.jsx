import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import {
  Banner, Card, ConfirmButton, Drawer, EmptyState, ErrorBanner, Field, Input,
  Loading, PageHeader, Pager, Pill, Select, StatusBadge, Table, Tabs, usePage,
} from './ui'
import { useI18n } from './i18n'
import WorkflowEditor from './WorkflowEditor'

/* Scans is one question with four answers, so it is one screen with four tabs:
   the definitions that recur, the runs they produce, the workflows those runs
   execute, and the decisions waiting on a person.

   A scan definition is a row in `scan_schedules`; a run is a `ScanJob`; a
   workflow is a profile from the published catalog — imported by reference, so
   the console can never show a workflow the runner does not have. */

const TABS = ['scans', 'runs', 'workflows', 'approvals']
const INTERVALS = [
  ['', 'scans.once'],
  ['60', 'scans.every.hour'],
  ['360', 'scans.every.6h'],
  ['1440', 'scans.every.day'],
  ['10080', 'scans.every.week'],
]

const INTENSITY = {
  simple: 'scans.intensity.active',
  advanced: 'scans.intensity.advanced',
  redteam: 'scans.intensity.intrusive',
}

function when(value) {
  if (!value) return '—'
  try { return new Date(value).toLocaleString() } catch { return value }
}

/* ------------------------------------------------------------------ wizard */

function Wizard({ open, workflows, onClose, onDone, onOpenScope }) {
  const { t, tCount } = useI18n()
  const [step, setStep] = useState(0)
  const [name, setName] = useState('')
  const [level, setLevel] = useState('simple')
  const [pick, setPick] = useState('')
  const [targets, setTargets] = useState('')
  const [interval, setInterval] = useState('')
  const [plan, setPlan] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const timer = useRef(null)

  // Catalog profiles and the organisation's own workflows, in one list: to the
  // person launching a scan they answer the same question, and the difference
  // (who can edit it) belongs in the Workflows tab, not in this choice.
  const domainProfiles = useMemo(
    () => workflows.filter((row) => (row.target_kind || 'domain') === 'domain'), [workflows])
  // Least intense first: the wizard must never open on the profile that fuzzes.
  const levels = useMemo(() => {
    const rank = { simple: 0, advanced: 1, redteam: 2 }
    return Array.from(new Set(domainProfiles.map((row) => row.level).filter(Boolean)))
      .sort((a, b) => (rank[a] ?? 9) - (rank[b] ?? 9) || String(a).localeCompare(String(b)))
  }, [domainProfiles])
  const offered = domainProfiles.filter((row) => row.level === level)
  const selected = domainProfiles.find((row) => row.key === pick) || null

  useEffect(() => {
    if (!open) return
    setStep(0); setName(''); setTargets(''); setInterval(''); setPlan(null); setError('')
    const first = domainProfiles.find((row) => row.level === (levels[0] || 'simple'))
    setLevel(levels[0] || 'simple'); setPick(first ? first.key : '')
  }, [open])  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!open || !selected || !targets.trim()) { setPlan(null); return }
    const parsed = targets.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
    if (!parsed.length) { setPlan(null); return }
    clearTimeout(timer.current)
    // One request per pause, not per keystroke: `/plan` resolves grants and the
    // catalog, and a preview that fires on every letter is a preview nobody reads.
    timer.current = setTimeout(() => {
      api.post('/api/v1/surface/plan', {
        ...(selected.origin === 'org' ? { workflow_id: selected.id }
                                      : { profile: selected.slug }),
        plane: 'cloud',
        targets: parsed.map((value) => ({ type: 'domain', value })),
      }).then(setPlan).catch((caught) => setPlan({ error: String(caught.message || caught) }))
    }, 400)
    return () => clearTimeout(timer.current)
  }, [open, pick, targets])  // eslint-disable-line react-hooks/exhaustive-deps

  const parsed = targets.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
  const blocked = plan?.plan?.blocked_targets || []
  const verdict = plan?.verdict || ''
  const counts = plan?.states || {}
  // A plan can be legal and still send nothing: every step may be outside the
  // grant. Advancing on `!refused` alone let the wizard reach Review and fail on
  // launch, which is the worst place to learn the target is not covered.
  const allowed = counts.allow || 0
  const canLeaveTargets = parsed.length > 0 && !plan?.error && allowed > 0

  async function launch() {
    setBusy(true); setError('')
    const list = parsed.map((value) => ({ type: 'domain', value }))
    try {
      const target = selected.origin === 'org'
        ? { workflow_id: selected.id } : { profile: selected.slug }
      if (interval) {
        await api.post('/api/v1/orchestration/schedules', {
          name: name.trim() || `${selected.slug} · ${parsed[0]}`,
          scanner: 'shauron-surface', principal: 'console',
          targets: list, profile: { name: selected.slug },
          interval_minutes: Number(interval), actor: 'console',
        })
      } else {
        await api.post('/api/v1/surface/runs', { ...target, plane: 'cloud', targets: list })
      }
      onDone?.()
      onClose()
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setBusy(false) }
  }

  const steps = ['scans.step.what', 'scans.step.targets', 'scans.step.options',
                 'scans.step.schedule', 'scans.step.review']

  return (
    <Drawer open={open} title={t('scans.new')} onClose={onClose} fullScreen>
      <div className="wizard">
        <ol className="wizard-rail">
          {steps.map((key, index) => (
            <li key={key}
                className={`wizard-stop${index === step ? ' is-current' : ''}${index < step ? ' is-done' : ''}`}>
              <button type="button" disabled={index >= step} onClick={() => setStep(index)}>
                <span className="wizard-dot">{index + 1}</span>
                <span className="wizard-label">{t(key)}</span>
              </button>
            </li>
          ))}
        </ol>

        {error && <ErrorBanner error={error} />}

        {step === 0 && (
          <div className="stack">
            <Field label={t('scans.field.name')}>
              <Input value={name} onChange={setName} placeholder={t('scans.field.name.ph')} />
            </Field>
            <div>
              <p className="muted">{t('scans.intensity.hint')}</p>
              <div className="options">
                {levels.map((value) => (
                  <button key={value} type="button"
                          className={`option${value === level ? ' is-on' : ''}`}
                          onClick={() => {
                            setLevel(value)
                            const first = domainProfiles.find((row) => row.level === value)
                            setPick(first ? first.key : '')
                          }}>
                    <span className="option-mark">{value === level ? '✓' : ''}</span>
                    <span>{t(INTENSITY[value] || 'scans.intensity.other', { level: value })}</span>
                  </button>
                ))}
              </div>
            </div>
            {offered.length === 0 && <Banner kind="warn">{t('scans.no.workflow.at.level')}</Banner>}
            <div className="options">
              {offered.map((row) => (
                <button key={row.key} type="button"
                        className={`option${row.key === pick ? ' is-on' : ''}`}
                        onClick={() => setPick(row.key)}>
                  <span className="option-mark">{row.key === pick ? '✓' : ''}</span>
                  <span className="option-copy">
                    <strong>{row.label || row.slug}</strong>
                    <span className="muted">{row.question}</span>
                    <span className="muted">
                      {tCount('scans.stages', row.stages.length)} ·{' '}
                      {tCount('scans.tools', (row.tools || []).length)} ·{' '}
                      {row.origin === 'org' ? t('scans.workflow.mine') : t('scans.workflow.system')}
                    </span>
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="stack">
            <Field label={t('scans.field.targets')} hint={t('scans.field.targets.hint')}>
              <textarea className="input" rows={4} value={targets}
                        onChange={(event) => setTargets(event.target.value)}
                        placeholder="example.com, api.example.com" />
            </Field>
            {plan && !plan.error && (
              <div className="stack" style={{ gap: 6 }}>
                <Banner kind={blocked.length ? 'warn' : 'info'}>{verdict}</Banner>
                <div className="row" style={{ gap: 6 }}>
                  {Object.entries(counts).map(([state, total]) => (
                    <Pill key={state} tone={state === 'allow' ? 'ok' : 'warn'}>
                      {state} · {total}
                    </Pill>
                  ))}
                </div>
                {allowed === 0 && !blocked.length && (
                  <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                    <span className="muted">{t('scans.no.scope')}</span>
                    {onOpenScope && (
                      <button className="btn-ghost" onClick={onOpenScope}>
                        {t('scans.open.scope')} →
                      </button>
                    )}
                  </div>
                )}
                {blocked.length > 0 && (
                  <div className="stack" style={{ gap: 4 }}>
                    {blocked.map((row) => (
                      <div className="row" key={row.value} style={{ gap: 8 }}>
                        <span className="mono">{row.value}</span>
                        <span className="muted">{row.reason}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {plan?.error && <Banner kind="error">{plan.error}</Banner>}
          </div>
        )}

        {step === 2 && (
          <div className="stack">
            <p className="muted">{t('scans.options.intro')}</p>
            <div className="row" style={{ gap: 8 }}>
              <span className="mono">cloud</span>
              <span className="muted">{t('scans.options.cloud')}</span>
            </div>
            <p className="muted">{t('scans.options.limit')}</p>
          </div>
        )}

        {step === 3 && (
          <div className="stack">
            <Field label={t('scans.field.schedule')} hint={t('scans.field.schedule.hint')}>
              <Select value={interval} onChange={setInterval}
                      options={INTERVALS.map(([value, key]) => ({ value, label: t(key) }))} />
            </Field>
            {interval === '' && <Banner kind="info">{t('scans.schedule.once')}</Banner>}
          </div>
        )}

        {step === 4 && (
          <div className="stack">
            <dl>
              <dt>{t('scans.review.name')}</dt><dd>{name || `${selected?.slug} · ${parsed[0]}`}</dd>
              <dt>{t('scans.review.workflow')}</dt>
              <dd>{selected?.label || selected?.slug}</dd>
              <dt>{t('scans.review.targets')}</dt><dd>{parsed.join(', ')}</dd>
              <dt>{t('scans.review.verdict')}</dt><dd>{verdict || '—'}</dd>
              <dt>{t('scans.review.schedule')}</dt>
              <dd>{interval ? t('scans.every.minutes', { n: Number(interval) }) : t('scans.once')}</dd>
            </dl>
            <p className="muted">{t('scans.review.note')}</p>
          </div>
        )}

        <div className="wizard-actions">
          <button className="btn-ghost" onClick={onClose}>{t('scans.cancel')}</button>
          <span style={{ flex: 1 }} />
          {step > 0 && (
            <button className="btn-ghost" onClick={() => setStep(step - 1)}>← {t('scans.back')}</button>
          )}
          {step < 4 && (
            <button className="btn-primary"
                    disabled={(step === 0 && !selected) || (step === 1 && !canLeaveTargets)}
                    onClick={() => setStep(step + 1)}>
              {t('scans.next')} →
            </button>
          )}
          {step === 4 && (
            <button className="btn-primary" onClick={launch} disabled={busy}>
              {busy ? t('scans.launching') : interval ? t('scans.save') : t('scans.launch')}
            </button>
          )}
        </div>
      </div>
    </Drawer>
  )
}

/* -------------------------------------------------------------------- tabs */

function WorkflowsPanel({ library, tools, rules, loading, onChanged }) {
  const { t, tCount } = useI18n()
  const [editing, setEditing] = useState(null)
  const [error, setError] = useState('')

  if (loading || !library) return <Loading />

  async function archive(row) {
    setError('')
    try {
      await api.del(`/api/v1/surface/workflows/${row.id}?actor=console`)
      onChanged?.()
    } catch (caught) { setError(String(caught.message || caught)) }
  }

  const card = (row, mine) => (
    <Card key={`${row.origin}:${row.slug}`}
          title={row.label || row.slug}
          actions={mine ? (
            <div className="row" style={{ gap: 6 }}>
              <button className="btn-ghost" onClick={() => setEditing(row)}>{t('workflows.edit')}</button>
              <ConfirmButton confirmLabel={t('workflows.archive.confirm')}
                             onConfirm={() => archive(row)}>
                {t('workflows.archive')}
              </ConfirmButton>
            </div>
          ) : (
            <button className="btn-ghost" onClick={() => setEditing({ ...row, from_clone: true })}>
              {t('workflows.clone')}
            </button>
          )}>
      <p className="muted">{row.question}</p>
      <div className="row" style={{ gap: 6, marginBottom: 8 }}>
        <Pill>{t(INTENSITY[row.level] || 'scans.intensity.other', { level: row.level })}</Pill>
        <Pill>{row.plane.join(' / ')}</Pill>
        <Pill>{tCount('scans.stages', row.stages.length)}</Pill>
        {mine && <Pill tone="ok">{t('scans.workflow.mine')}</Pill>}
      </div>
      <ul className="repo-cards">
        {row.stages.map((stage, index) => (
          <li key={stage.id}>
            <span className="repo-head">
              <span className="muted">{t('scans.stage')} {index + 1}</span>
              <span className="repo-name mono">{stage.id}</span>
              <span className="muted">← {stage.from || 'targets'}</span>
            </span>
            <span className="repo-remote">
              {(stage.tools || []).map((tool) => (
                <span key={tool} className="mono" style={{ marginRight: 8 }}>{tool}</span>
              ))}
            </span>
          </li>
        ))}
      </ul>
    </Card>
  )

  return (
    <div className="stack">
      {error && <ErrorBanner error={error} />}
      <Banner kind="info">{t('scans.workflows.intro')}</Banner>

      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
        <strong>{t('workflows.mine')}</strong>
        <button className="btn-primary" onClick={() => setEditing({ from_clone: false })}>
          + {t('workflows.new')}
        </button>
      </div>
      {library.mine.length === 0
        ? <p className="muted">{t('workflows.mine.empty')}</p>
        : library.mine.map((row) => card(row, true))}

      <strong style={{ marginTop: 8 }}>{t('workflows.system')}</strong>
      {library.system.filter((row) => row.target_kind === 'domain').map((row) => card(row, false))}

      <WorkflowEditor open={!!editing}
                      tools={tools} rules={rules}
                      initial={editing ? {
                        id: editing.from_clone ? undefined : editing.id,
                        slug: editing.from_clone ? '' : editing.slug,
                        label: editing.from_clone
                          ? `${editing.label}${t('workflows.clone.suffix')}`
                          : editing.label,
                        question: editing.question, level: editing.level,
                        target_kind: editing.target_kind, plane: editing.plane,
                        stages: editing.stages, limits: editing.limits,
                        clone_from: editing.from_clone ? editing.slug : undefined,
                      } : null}
                      onClose={() => setEditing(null)}
                      onSaved={() => { onChanged?.() }} />
    </div>
  )
}


function Approvals() {
  const { t } = useI18n()
  const [rows, setRows] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api.get('/api/v1/agents/inbox')
      .then((body) => setRows(body.data || []))
      .catch((caught) => setError(String(caught.message || caught)))
  }, [])
  if (error) return <ErrorBanner error={error} />
  if (!rows) return <Loading />
  if (!rows.length) {
    return (
      <div className="stack">
        {/* The limitation stays on screen even when the queue is empty: an empty
            inbox is not the same promise as a gate that exists. */}
        <p className="muted">{t('scans.approvals.intro')}</p>
        <EmptyState title={t('scans.approvals.empty')} hint={t('scans.approvals.empty.hint')} />
      </div>
    )
  }
  return (
    <div className="stack">
      <p className="muted">{t('scans.approvals.intro')}</p>
      <Table head={[t('scans.approvals.what'), t('scans.approvals.kind'), t('scans.approvals.who')]}>
        {rows.map((row) => (
          <tr key={`${row.kind}:${row.id}`}>
            <td>{row.title}</td>
            <td><Pill>{row.kind}</Pill></td>
            <td className="muted">{row.actor || '—'}</td>
          </tr>
        ))}
      </Table>
    </div>
  )
}

export default function Scans({ initialTab = 'scans', onNavigate }) {
  const { t } = useI18n()
  const [tab, setTab] = useState(TABS.includes(initialTab) ? initialTab : 'scans')
  const [library, setLibrary] = useState(null)
  const [tools, setTools] = useState([])
  const [rules, setRules] = useState(null)
  const [schedules, setSchedules] = useState(null)
  const [runs, setRuns] = useState(null)
  const [catalogLoading, setCatalogLoading] = useState(true)
  const [error, setError] = useState('')
  const [wizard, setWizard] = useState(false)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    // One read for the three questions the screen asks about workflows: what
    // shipped, what this org wrote, and which rules both are judged by.
    api.get('/api/v1/surface/workflows')
      .then((body) => { setLibrary({ system: body.system || [], mine: body.mine || [] }); setRules(body.rules) })
      .catch((caught) => setError(String(caught.message || caught)))
      .finally(() => setCatalogLoading(false))
    api.get('/api/v1/surface/workflows/tools')
      .then((body) => setTools(body.tools || []))
      .catch((caught) => setError(String(caught.message || caught)))
  }, [reload])

  useEffect(() => {
    api.get('/api/v1/orchestration/schedules')
      .then((body) => setSchedules((body.data || body.schedules || []).filter((row) => row.scanner === 'shauron-surface')))
      .catch((caught) => setError(String(caught.message || caught)))
    api.get('/api/v1/surface/runs?limit=50')
      .then((body) => setRuns(body.runs || []))
      .catch((caught) => setError(String(caught.message || caught)))
  }, [reload])

  const pager = usePage(schedules || [], 25)
  // Catalog and organisation workflows, one shape: the wizard and the run list
  // do not care which of the two a name came from.
  const workflows = useMemo(() => [
    ...((library?.system) || []).map((row) => ({
      ...row, key: `system:${row.slug}`, origin: 'system',
      tools: (row.stages || []).flatMap((stage) => stage.tools || []),
    })),
    ...((library?.mine) || []).map((row) => ({
      ...row, key: `org:${row.id}`, origin: 'org',
      tools: (row.stages || []).flatMap((stage) => stage.tools || []),
    })),
  ], [library])
  const byName = useMemo(
    () => Object.fromEntries(workflows.map((row) => [row.slug, row])), [workflows])

  return (
    <div className="stack">
      <PageHeader
        title={t('nav.scans')}
        subtitle={t('scans.subtitle')}
        actions={
          <button className="btn-primary" onClick={() => setWizard(true)}>
            + {t('scans.new')}
          </button>
        }
      />
      <Tabs tabs={TABS.map((id) => ({ id, label: t(`scans.tab.${id}`) }))}
            active={tab} onChange={setTab} />

      {error && <ErrorBanner error={error} />}

      {tab === 'scans' && (
        schedules === null ? <Loading /> : (
          <>
            {!schedules.length && (
              <EmptyState title={t('scans.empty.title')} hint={t('scans.empty.hint')}
                          action={<button className="btn-primary" onClick={() => setWizard(true)}>
                            + {t('scans.new')}
                          </button>} />
            )}
            {!!schedules.length && (
              <>
                <Table head={[t('scans.col.name'), t('scans.col.workflow'), t('scans.col.targets'),
                              t('scans.col.every'), t('scans.col.next'), t('scans.col.last'),
                              t('scans.col.state'), '']}>
                  {pager.rows.map((row) => (
                    <tr key={row.id}>
                      <td>{row.name}</td>
                      <td className="muted">{byName[row.profile?.name]?.label || row.profile?.name || '—'}</td>
                      <td className="muted">{(row.targets || []).map((target) => target.value).join(', ') || '—'}</td>
                      <td className="muted">{t('scans.every.minutes', { n: row.interval_minutes })}</td>
                      <td className="muted">{when(row.next_run_at)}</td>
                      <td className="muted">{row.last_error ? <Pill tone="warn">{t('scans.last.error')}</Pill> : when(row.last_run_at)}</td>
                      <td>{row.enabled ? <Pill tone="ok">{t('scans.on')}</Pill> : <Pill>{t('scans.off')}</Pill>}</td>
                      <td>
                        <ConfirmButton confirmLabel={t('scans.delete.confirm')}
                                       onConfirm={async () => {
                                         await api.patch(`/api/v1/orchestration/schedules/${row.id}`,
                                                          { enabled: false, actor: 'console' })
                                         setReload((n) => n + 1)
                                       }}>
                          {t('scans.disable')}
                        </ConfirmButton>
                      </td>
                    </tr>
                  ))}
                </Table>
                <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
                       total={pager.total} perPage={25} unit={t('scans.unit')} />
              </>
            )}
          </>
        )
      )}

      {tab === 'runs' && (
        runs === null ? <Loading /> : !runs.length ? (
          <EmptyState title={t('scans.runs.empty')} hint={t('scans.runs.empty.hint')} />
        ) : (
          <Table head={[t('scans.col.started'), t('scans.col.workflow'), t('scans.col.targets'),
                        t('scans.col.origin'), t('scans.col.state'), '']}>
            {runs.map((row) => (
              <tr key={row.id}>
                <td className="muted">{when(row.created_at)}</td>
                <td className="mono">{row.profile || '—'}</td>
                <td className="muted">{(row.targets || []).map((target) => target.value).join(', ')}</td>
                <td className="muted">{row.origin || row.principal || '—'}</td>
                <td><StatusBadge status={row.status} /></td>
                <td>
                  <button className="btn-ghost"
                          onClick={() => { window.location.hash = `surface::${row.id}` }}>
                    {t('scans.open')} →
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        )
      )}

      {tab === 'workflows' && (
        <WorkflowsPanel library={library} tools={tools} rules={rules}
                        loading={catalogLoading} onChanged={() => setReload((n) => n + 1)} />
      )}
      {tab === 'approvals' && <Approvals />}

      <Wizard open={wizard} workflows={workflows}
              onClose={() => setWizard(false)}
              onDone={() => setReload((n) => n + 1)}
              onOpenScope={() => onNavigate?.('scope')} />
    </div>
  )
}