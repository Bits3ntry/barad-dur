import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Stat } from './ui'
import { useI18n } from './i18n'

/* The CTEM cycle as a working surface, not a noun: five phases, each one
   answered with counts and a status derived from them (see /api/v1/ctem/overview).
   A phase is never reported healthy because its table is empty. */

const ORDER = ['scoping', 'discovery', 'prioritization', 'validation', 'mobilization']

const STATUS_COPY = {
  done: { labelKey: 'ctem.phaseStatus.done', tone: 'good' },
  partial: { labelKey: 'ctem.phaseStatus.partial', tone: 'warn' },
  empty: { labelKey: 'ctem.phaseStatus.empty', tone: '' },
}

/* The API answers with `title_key` / `question_key` / `label_key` / `hint_key`
   when the deployment speaks the current catalogue, and with plain English when
   it is older. Both are the same statement, so the screen derives the key from
   the payload's own identifiers (`phase.key`, the metric's label) instead of
   printing English on a Spanish console. A deployment that ships the keys wins;
   this is the floor, not a second source of truth. */
const METRIC_KEY = {
  'projects': 'projects',
  'assets observed': 'assetsObserved',
  'scope targets': 'scopeTargets',
  'components': 'components',
  'imports 30d': 'imports30d',
  'assets': 'assets',
  'open findings': 'openFindings',
  'ranked': 'ranked',
  'known exploited': 'knownExploited',
  'hypotheses': 'hypotheses',
  'pentest engagements': 'pentests',
  'regression tests': 'regressionTests',
  'pull requests reviewed': 'pullRequests',
  'open': 'open',
  'resolved': 'resolved',
  'tickets': 'tickets',
}

/* Hints are the only metric text with a number inside, so the fallback parses
   the sentence the API built (`{n} exclusions`) and re-composes it through the
   catalogue. A hint nobody can parse is printed as it arrived. */
const HINT_PATTERNS = [
  [/^(\d+) with a scanned version$/, 'ctem.hint.withScanned', (m) => ({ n: m[1] })],
  [/^(\d+) exclusions$/, 'ctem.hint.exclusions', (m) => ({ n: m[1] })],
  [/^(\d+) total$/, 'ctem.hint.total', (m) => ({ n: m[1] })],
  [/^(\d+) open, (\d+) awaiting triage$/, 'ctem.hint.openAwaiting',
    (m) => ({ open: m[1], awaiting: m[2] })],
  [/^(\d+) without priority$/, 'ctem.hint.withoutPriority', (m) => ({ n: m[1] })],
  [/^not counted until triaged$/, 'ctem.hint.notCounted', () => ({})],
  [/^(\d+) past SLA$/, 'ctem.hint.pastSla', (m) => ({ n: m[1] })],
]

function metricHint(metric, t) {
  if (metric.hint_key) return t(metric.hint_key, metric.hint_params || {})
  if (!metric.hint) return undefined
  for (const [pattern, key, params] of HINT_PATTERNS) {
    const match = pattern.exec(metric.hint)
    if (match) return t(key, params(match))
  }
  return metric.hint
}

function PhaseCard({ phase, index, focused, onNavigate }) {
  const { t, tOr } = useI18n()
  const status = STATUS_COPY[phase.status] || STATUS_COPY.empty
  const statusLabel = t(status.labelKey)
  const titleKey = phase.title_key || `ctem.phase.${phase.key}.title`
  const questionKey = phase.question_key || `ctem.phase.${phase.key}.question`
  return (
    <section className={`phase${focused ? ' focused' : ''}`} id={`phase-${phase.key}`}
      aria-label={`${tOr(titleKey, phase.title)}: ${statusLabel}`}>
      <header className="phase-head">
        <span className="phase-index">{index + 1}</span>
        <div className="phase-titles">
          <h3>{tOr(titleKey, phase.title)}</h3>
          <p>{tOr(questionKey, phase.question)}</p>
        </div>
        <span className={`phase-status ${status.tone}`}>{statusLabel}</span>
      </header>

      <div className="phase-metrics">
        {phase.metrics.map((metric) => (
          <Stat key={metric.label}
            label={tOr(metric.label_key || `ctem.metric.${METRIC_KEY[metric.label] || ''}`,
              metric.label)}
            value={metric.value}
            hint={metricHint(metric, t)} />
        ))}
      </div>

      <div className="phase-progress" role="progressbar" aria-valuenow={phase.progress}
        aria-valuemin={0} aria-valuemax={100}>
        <span className="track">
          <span style={{ width: `${phase.progress}%` }} className={status.tone} />
        </span>
        <span className="percent">{phase.progress}%</span>
      </div>

      <footer className="phase-links">
        {phase.links.map((link) => (
          <button key={link.screen} className="mini"
            onClick={() => onNavigate && onNavigate(link.screen)}>
            {tOr(`nav.${link.screen}`, tOr(`title.${link.screen}`, link.label))} →
          </button>
        ))}
      </footer>
    </section>
  )
}

export default function CtemCycle({ focus, onNavigate }) {
  const { t } = useI18n()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  function load() {
    setError('')
    api.get('/api/v1/ctem/overview')
      .then((response) => setData(response.data))
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(load, [])

  const phases = useMemo(() => {
    const list = data?.phases || []
    // Sidebar entries open the cycle on their phase: that one goes first so the
    // reader lands on what they clicked, without losing the rest of the loop.
    if (!focus) return list
    const sorted = [...list].sort((left, right) => ORDER.indexOf(left.key) - ORDER.indexOf(right.key))
    const target = sorted.find((phase) => phase.key === focus)
    return target ? [target, ...sorted.filter((phase) => phase.key !== focus)] : sorted
  }, [data, focus])

  if (!data) {
    return (
      <div className="stack">
        <PageHeader title={t('ctem.title')} subtitle={t('ctem.loading')} />
        <Card>{error ? <ErrorBanner error={error} onRetry={load} /> : <Loading rows={4} />}</Card>
      </div>
    )
  }

  const done = phases.filter((phase) => phase.status === 'done').length

  return (
    <div className="stack">
      <PageHeader
        title={focus ? t('ctem.title.focused', { phase: focus }) : t('ctem.title')}
        subtitle={t('ctem.subtitle', {
          done, total: phases.length, org: data.organization.name,
        })}
        actions={<button onClick={load}>{t('common.refresh')}</button>}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      {!phases.length && (
        <EmptyState title={t('ctem.empty.title')}
          hint={t('ctem.empty.hint')} />
      )}

      <div className="phase-list">
        {phases.map((phase, index) => (
          <PhaseCard key={phase.key} phase={phase}
            index={ORDER.indexOf(phase.key)} focused={phase.key === focus}
            onNavigate={onNavigate} />
        ))}
      </div>

      <p className="muted">
        {t('ctem.footnote')}
      </p>
    </div>
  )
}
