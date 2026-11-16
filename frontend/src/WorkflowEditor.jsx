import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Banner, Drawer, ErrorBanner, Field, Input, Loading, Pill } from './ui'
import { useI18n } from './i18n'

/* Writing a workflow is composing a document the engine already understands.

   Three rules make the editor honest:

   - The tool list is the catalog's, filtered by what a step may actually use:
     the target kind it accepts, and the level the workflow declares. A tool that
     cannot run here is shown disabled with the reason, never hidden — an operator
     who cannot find `nuclei` assumes it does not exist.
   - A stage reads from `targets` or from a stage that came before it. The select
     offers exactly those, so an invalid graph is not something you can type.
   - The server validates the whole document again. This form is a convenience;
     the engine's rules are the authority and they are the same ones. */

const DEFAULT_LIMITS = { rate_per_second: 20, timeout_s: 300, concurrency: 4 }

function slugify(value) {
  return String(value || '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40)
}

function rank(rules, level) {
  return (rules?.level_rank || {})[level] ?? 99
}

export default function WorkflowEditor({ open, initial, tools, rules, onClose, onSaved }) {
  const { t } = useI18n()
  const [document, setDocument] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setError(''); setBusy(false)
    setDocument(initial ? {
      ...initial,
      stages: (initial.stages || []).map((stage) => ({
        id: stage.id, from: stage.from || 'targets', tools: [...(stage.tools || [])],
      })),
      limits: { ...DEFAULT_LIMITS, ...(initial.limits || {}) },
      plane: initial.plane?.length ? [...initial.plane] : ['cloud'],
    } : {
      slug: '', label: '', question: '', target_kind: 'domain', level: 'simple',
      plane: ['cloud'], stages: [{ id: 'discover', from: 'targets', tools: [] }],
      limits: { ...DEFAULT_LIMITS },
    })
  }, [open, initial])

  const levelRank = rank(rules, document?.level)
  const domainTools = useMemo(
    () => (tools || []).filter((tool) => (tool.targets || []).includes('domain')), [tools])

  if (!open) return null
  if (!document) return <Drawer open={open} title={t('workflows.new')} onClose={onClose}><Loading /></Drawer>

  const stages = document.stages
  const problems = []
  if ((document.label || '').trim().length < 2) problems.push(t('workflows.check.label'))
  stages.forEach((stage, index) => {
    if (!/^[a-z0-9][a-z0-9._-]{2,95}$/.test(stage.id || '')) {
      problems.push(t('workflows.check.stage_id', { index: index + 1 }))
    }
    if (index === 0 && stage.from !== 'targets') {
      problems.push(t('workflows.check.first_stage'))
    }
    if (!stage.tools.length) problems.push(t('workflows.check.tools', { stage: stage.id }))
    stage.tools.forEach((name) => {
      const tool = domainTools.find((row) => row.name === name)
      if (!tool) problems.push(t('workflows.check.unknown_tool', { tool: name }))
      else if (rank(rules, tool.level) > levelRank) {
        problems.push(t('workflows.check.above_level',
                        { tool: name, level: tool.level, mine: document.level }))
      }
    })
  })

  function update(patch) { setDocument((current) => ({ ...current, ...patch })) }
  function updateStage(index, patch) {
    setDocument((current) => ({
      ...current,
      stages: current.stages.map((stage, at) => (at === index ? { ...stage, ...patch } : stage)),
    }))
  }
  function addStage() {
    setDocument((current) => {
      const previous = current.stages[current.stages.length - 1]
      return {
        ...current,
        stages: [...current.stages, {
          id: `stage-${current.stages.length + 1}`,
          from: previous ? previous.id : 'targets', tools: [],
        }],
      }
    })
  }
  function removeStage(index) {
    setDocument((current) => ({
      ...current,
      stages: current.stages.filter((_, at) => at !== index),
    }))
  }
  function toggleTool(index, name) {
    const stage = stages[index]
    updateStage(index, {
      tools: stage.tools.includes(name)
        ? stage.tools.filter((tool) => tool !== name)
        : [...stage.tools, name],
    })
  }

  async function save() {
    setBusy(true); setError('')
    const body = {
      label: document.label, question: document.question || '',
      level: document.level, target_kind: document.target_kind || 'domain',
      plane: document.plane, stages, limits: document.limits, actor: 'console',
      // Provenance, not inheritance: it names where the first draft came from.
      ...(document.clone_from ? { clone_from: document.clone_from } : {}),
    }
    try {
      const saved = document.id
        ? await api.patch(`/api/v1/surface/workflows/${document.id}`, body)
        : await api.post('/api/v1/surface/workflows',
                         { ...body, slug: document.slug || slugify(document.label) })
      onSaved?.(saved.data)
      onClose()
    } catch (caught) {
      // The API answers with a code and the value that failed; the message is a
      // translation, so the operator sees which stage, not "invalid workflow".
      const detail = caught.detail || caught.body?.detail
      if (detail?.code) {
        setError(t(`workflows.error.${detail.code.replace(/^workflow\\./, '')}`, detail))
      } else {
        setError(String(caught.message || caught))
      }
    } finally { setBusy(false) }
  }

  const fromOptions = (index) => [
    { value: 'targets', label: t('workflows.from.targets') },
    ...stages.slice(0, index).map((stage) => ({ value: stage.id, label: stage.id })),
  ]

  return (
    <Drawer open={open} title={document.id ? t('workflows.edit') : t('workflows.new')}
            onClose={onClose} fullScreen>
      <div className="wizard">
        {error && <ErrorBanner error={error} />}

        <div className="wizard-fields">
          <Field label={t('workflows.field.label')}>
            <Input value={document.label} onChange={(value) => update({ label: value })}
                   placeholder={t('workflows.field.label.ph')} />
          </Field>
          <Field label={t('workflows.field.level')} hint={t('workflows.field.level.hint')}>
            <select className="input" value={document.level}
                    onChange={(event) => update({ level: event.target.value })}>
              {(rules?.levels || ['simple', 'advanced', 'redteam']).map((level) => (
                <option key={level} value={level}>{t(`workflows.level.${level}`)}</option>
              ))}
            </select>
          </Field>
        </div>

        <Field label={t('workflows.field.question')} hint={t('workflows.field.question.hint')}>
          <Input value={document.question || ''} onChange={(value) => update({ question: value })}
                 placeholder={t('workflows.field.question.ph')} />
        </Field>

        <div className="row" style={{ gap: 6, alignItems: 'center' }}>
          <span className="muted">{t('workflows.field.plane')}</span>
          {(rules?.planes || ['cli', 'cloud']).map((plane) => {
            const on = document.plane.includes(plane)
            return (
              <button key={plane} type="button"
                      className={`pill${on ? ' is-on' : ''}`}
                      onClick={() => update({
                        plane: on ? document.plane.filter((item) => item !== plane)
                                  : [...document.plane, plane],
                      })}>
                {plane}
              </button>
            )
          })}
          <span className="muted">{t('workflows.field.plane.hint')}</span>
        </div>

        <div className="stack">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <strong>{t('workflows.steps')}</strong>
            <button className="btn-ghost" onClick={addStage}>+ {t('workflows.add.stage')}</button>
          </div>
          {stages.map((stage, index) => (
            <div className="wf-stage" key={`${stage.id}-${index}`}>
              <div className="row" style={{ gap: 8, alignItems: 'flex-end' }}>
                <Field label={t('workflows.stage.id')}>
                  <Input value={stage.id} onChange={(value) => updateStage(index, { id: value })} />
                </Field>
                <Field label={t('workflows.stage.from')}>
                  <select className="input" value={stage.from}
                          onChange={(event) => updateStage(index, { from: event.target.value })}>
                    {fromOptions(index).map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </Field>
                <button className="btn-ghost" onClick={() => removeStage(index)}
                        disabled={stages.length === 1}>−</button>
              </div>
              <div className="wf-tools">
                {domainTools.map((tool) => {
                  const selected = stage.tools.includes(tool.name)
                  const tooHigh = rank(rules, tool.level) > levelRank
                  return (
                    <button key={tool.name} type="button"
                            className={`pill${selected ? ' is-on' : ''}${tooHigh ? ' is-off' : ''}`}
                            disabled={tooHigh && !selected}
                            title={tooHigh
                              ? t('workflows.tool.needs', { tool: tool.name, level: tool.level })
                              : tool.purpose}
                            onClick={() => toggleTool(index, tool.name)}>
                      <span className="mono">{tool.name}</span>
                      {tool.capability && (
                        <span className="muted">{t(`workflows.capability.${tool.capability}`)}</span>
                      )}
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </div>

        <div className="wizard-fields">
          {['rate_per_second', 'timeout_s', 'concurrency'].map((key) => (
            <Field key={key} label={t(`workflows.limit.${key}`)}>
              <Input type="number" value={document.limits[key]}
                     onChange={(value) => update({
                       limits: { ...document.limits, [key]: Number(value) || 0 },
                     })} />
            </Field>
          ))}
        </div>

        {problems.length > 0 && (
          <Banner kind="warn">
            <ul style={{ margin: 0, paddingLeft: 16 }}>
              {problems.slice(0, 6).map((problem, index) => <li key={index}>{problem}</li>)}
            </ul>
          </Banner>
        )}

        <div className="wizard-actions">
          <button className="btn-ghost" onClick={onClose}>{t('scans.cancel')}</button>
          <span style={{ flex: 1 }} />
          <button className="btn-primary" onClick={save}
                  disabled={busy || problems.length > 0}>
            {busy ? t('workflows.saving') : t('workflows.save')}
          </button>
        </div>
      </div>
    </Drawer>
  )
}
