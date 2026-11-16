import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, ErrorBanner, Loading, PageHeader } from './ui'
import { useI18n } from './i18n'

/* The first thing an owner needs is not a dashboard: it is the ordered path
   from an empty organization to a working pipeline. Every step reads live
   state, so the guide doubles as a status page. */

const STEPS = [
  {
    key: 'scope',
    labelKey: 'setup.step.scope.label',
    titleKey: 'setup.step.scope.title',
    hintKey: 'setup.step.scope.hint',
    count: (d) => d.scopeTargets,
    unitKey: 'unit.targets',
  },
  {
    key: 'projects',
    labelKey: 'setup.step.projects.label',
    titleKey: 'setup.step.projects.title',
    hintKey: 'setup.step.projects.hint',
    count: (d) => d.projects,
    unitKey: 'unit.projects',
  },
  {
    key: 'assets',
    labelKey: 'setup.step.assets.label',
    titleKey: 'setup.step.assets.title',
    hintKey: 'setup.step.assets.hint',
    count: (d) => d.assets,
    unitKey: 'unit.assets',
  },
  {
    key: 'grants',
    labelKey: 'setup.step.grants.label',
    titleKey: 'setup.step.grants.title',
    hintKey: 'setup.step.grants.hint',
    count: (d) => d.grants,
    unitKey: 'unit.grants',
  },
  {
    key: 'findings',
    labelKey: 'setup.step.findings.label',
    titleKey: 'setup.step.findings.title',
    hintKey: 'setup.step.findings.hint',
    count: (d) => d.components,
    unitKey: 'setup.unit.componentsTracked',
  },
  {
    key: 'cycles',
    labelKey: 'setup.step.cycles.label',
    titleKey: 'setup.step.cycles.title',
    hintKey: 'setup.step.cycles.hint',
    count: (d) => d.cycles,
    unitKey: 'unit.cycles',
  },
]

const EMPTY = { grants: 0, projects: 0, components: 0, assets: 0,
  scopeTargets: 0, cycles: 0 }

async function safeCount(path, pick) {
  try {
    const body = await api.get(path)
    return pick(body)
  } catch {
    return 0
  }
}

export default function SetupGuide({ onNavigate }) {
  const { t } = useI18n()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  function load() {
    setError('')
    Promise.all([
      safeCount('/api/v1/authorization/grants', (b) => (b.data || []).length),
      safeCount('/api/v1/projects', (b) => (b.data || []).length),
      safeCount('/api/v1/components?limit=1', (b) => b.total ?? (b.data || []).length),
      safeCount('/api/v1/assets?limit=1', (b) => b.total ?? (b.data || []).length),
      safeCount('/api/v1/scope/targets', (b) => (b.data || []).length),
      safeCount('/api/v1/cycles', (b) => (b.data || []).length),
    ])
      .then(([grants, projects, components, assets, scopeTargets, cycles]) =>
        setData({ grants, projects, components, assets, scopeTargets, cycles }))
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(load, [])

  if (!data) {
    return (
      <div className="stack">
        <PageHeader title={t('setup.title')} subtitle={t('setup.subtitle')} />
        <Card>{error ? <ErrorBanner error={error} onRetry={load} /> : <Loading rows={5} />}</Card>
      </div>
    )
  }

  const done = STEPS.filter((step) => step.count(data) > 0)
  const pct = Math.round((done.length / STEPS.length) * 100)
  const next = STEPS.find((step) => step.count(data) === 0)

  return (
    <div className="stack">
      <PageHeader
        title={t('setup.title')}
        subtitle={t('setup.subtitleLive')}
        actions={<>
          <button className="ghost" onClick={() => onNavigate && onNavigate('guide')}>
            {t('setup.readGuide')}
          </button>
          <button onClick={load}>{t('common.refresh')}</button>
        </>}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      <Card>
        <div className="setup-head">
          <div>
            <div className="setup-title">
              {t('setup.progress.steps', { done: done.length, total: STEPS.length })}
            </div>
            <div className="setup-hint">
              {next
                ? t('setup.progress.next', { step: t(next.titleKey) })
                : t('setup.progress.done')}
            </div>
          </div>
          <div className="setup-progress" role="progressbar" aria-valuenow={pct}
            aria-valuemin={0} aria-valuemax={100} aria-label={t('setup.progress.label')}>
            <span style={{ width: `${pct}%` }} />
          </div>
          <div className="setup-meta">{pct}%</div>
        </div>
      </Card>

      <ol className="setup-steps">
        {STEPS.map((step, index) => {
          const count = step.count(data)
          const isDone = count > 0
          const isCurrent = !isDone && step.key === next?.key
          const className = `setup-step${isDone ? ' done' : ''}${isCurrent ? ' current' : ''}`
          return (
            <li key={step.key} className={className}>
              <span className="setup-num" aria-hidden="true">{isDone ? '✓' : index + 1}</span>
              <div>
                <div className="setup-title">{t(step.titleKey)}</div>
                <div className="setup-hint">{t(step.hintKey)}</div>
              </div>
              <div className="row">
                <span className="setup-meta">{count} {t(step.unitKey)}</span>
                <button className={isCurrent ? 'btn-primary mini' : 'mini'}
                  onClick={() => onNavigate && onNavigate(step.key)}>
                  {isDone ? t('setup.action.open') : t('setup.action.start')}
                </button>
              </div>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
