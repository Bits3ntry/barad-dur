import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Pill } from './ui'

/* A pipeline is built in four steps, one question at a time: what it belongs to,
   what it checks, when it runs, and the file that carries all three. A wizard
   earns its clicks here because step two is not a form — it is the catalog, and
   the actions a pipeline may not run need room to say why.

   Nothing here scans. A pipeline ANNOUNCES a commit and waits on the flow's own
   verdict; the daemon does the work with the ticket it was handed. The file is
   the pipeline: this screen creates nothing on the platform. */

const STEPS = [
  { id: 'where', labelKey: 'builder.step.where' },
  { id: 'what', labelKey: 'builder.step.what' },
  { id: 'when', labelKey: 'builder.step.when' },
  { id: 'file', labelKey: 'builder.step.file' },
]

const TRIGGER_LABEL = {
  push: 'builder.trigger.push',
  pull_request: 'builder.trigger.pullRequest',
  manual: 'builder.trigger.manual',
}

const PROVIDER_CHOICES = [
  { value: '', labelKey: 'builder.provider.detect' },
  { value: 'github', labelKey: 'builder.provider.github' },
  { value: 'gitea', labelKey: 'builder.provider.gitea' },
  { value: 'gitlab', labelKey: 'builder.provider.gitlab' },
  { value: 'generic', labelKey: 'builder.provider.generic' },
]

function ActionOption({ row, on, onToggle, t }) {
  const blocked = !row.ci_allowed
  return (
    <button type="button" onClick={() => !blocked && onToggle(row.name)}
      disabled={blocked}
      className={`option${on ? ' is-on' : ''}${blocked ? ' is-blocked' : ''}`}>
      <span className="option-mark" aria-hidden="true">
        {blocked ? '—' : on ? '✓' : ''}
      </span>
      <span className="option-copy">
        <span className="option-title">
          {row.label}
          {row.network && <span className="pill">{t('builder.action.network')}</span>}
          {blocked && <span className="pill">{t('builder.action.consoleOnly')}</span>}
        </span>
        <span className="option-desc">{row.description}</span>
        <span className="option-meta mono">
          {row.tasks_detail.map((task) => `${task.task} → ${task.contract}`).join('  ·  ')}
        </span>
        {blocked && <span className="option-why">{row.blocked_reason}</span>}
      </span>
    </button>
  )
}

export default function PipelineBuilder({ onBack, onDone }) {
  const { t } = useI18n()
  const [step, setStep] = useState(0)
  const [projects, setProjects] = useState([])
  const [project, setProject] = useState('')
  const [component, setComponent] = useState('')
  const [blueprint, setBlueprint] = useState(null)
  const [actions, setActions] = useState(['supply-chain'])
  const [triggers, setTriggers] = useState(['push', 'pull_request'])
  const [provider, setProvider] = useState('')
  const [apiUrl, setApiUrl] = useState('')
  const [branch, setBranch] = useState('main')
  const [snippet, setSnippet] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    api.get('/api/v1/projects')
      .then((response) => {
        const rows = response.data || []
        setProjects(rows)
        if (rows.length) setProject(rows[0].slug)
        setLoading(false)
      })
      .catch((failure) => {
        setError(String(failure.message || failure))
        setLoading(false)
      })
  }, [])

  // The catalog is per project: components carry their own remotes, and which CI
  // a file targets is a property of the repository, not a preference.
  useEffect(() => {
    if (!project) return undefined
    let cancelled = false
    setBlueprint(null)
    setError('')
    api.get(`/api/v1/pipeline/blueprint?project=${encodeURIComponent(project)}`)
      .then((response) => {
        if (cancelled) return
        const data = response.data
        setBlueprint(data)
        if (data.api_url) setApiUrl(data.api_url)
        setComponent((current) => {
          if (current && data.components.some((row) => row.id === current)) return current
          // Land on the component that can actually run: one with a remote.
          const withCode = data.components.find((row) => row.repositories.length)
          return (withCode || data.components[0] || {}).id || ''
        })
      })
      .catch((failure) => {
        if (!cancelled) setError(String(failure.message || failure))
      })
    return () => { cancelled = true }
  }, [project])

  const selected = useMemo(
    () => (blueprint?.components || []).find((row) => row.id === component) || null,
    [blueprint, component])

  const repositories = selected?.repositories || []
  const detectedLabel = repositories[0]?.ci_label || t('builder.detect.portableScript')
  const hasCode = repositories.length > 0

  // Two actions can ask for the same task (secrets lives in both `code` and
  // `supply-chain`), and each one is a separate flow: the scanner runs twice.
  // Saying it is cheaper than being asked why the count doubled.
  const repeatedTasks = useMemo(() => {
    const counts = {}
    ;(blueprint?.actions || [])
      .filter((row) => actions.includes(row.name))
      .forEach((row) => row.tasks.forEach((task) => {
        counts[task] = (counts[task] || 0) + 1
      }))
    return Object.keys(counts).filter((task) => counts[task] > 1)
  }, [blueprint, actions])

  // The file is fetched when the last step opens: the first three cost no
  // request, and the fourth always renders the current selection.
  useEffect(() => {
    if (step !== STEPS.length - 1 || !project || !actions.length) return undefined
    const timer = setTimeout(() => {
      const params = new URLSearchParams({
        project, actions: actions.join(','), triggers: triggers.join(','), branch,
      })
      if (component) params.set('component', component)
      if (provider) params.set('provider', provider)
      if (apiUrl.trim()) params.set('api_url', apiUrl.trim())
      api.get(`/api/v1/pipeline/snippet?${params}`)
        .then((response) => { setSnippet(response.data); setError('') })
        .catch((failure) => { setSnippet(null); setError(String(failure.message || failure)) })
    }, 180)
    return () => clearTimeout(timer)
  }, [step, project, component, actions, triggers, provider, apiUrl, branch])

  const toggleIn = (setList) => (name) => setList((current) => (
    current.includes(name) ? current.filter((item) => item !== name) : [...current, name]))

  async function copy() {
    if (!snippet) return
    try {
      await navigator.clipboard.writeText(snippet.body)
      setCopied(true)
      setTimeout(() => setCopied(false), 2500)
    } catch {
      setError(t('builder.error.clipboard'))
    }
  }

  if (loading) return <Loading rows={6} label={t('builder.loading.catalog')} />

  if (!projects.length) {
    return (
      <div className="stack">
        <PageHeader title={t('builder.title')}
          subtitle={t('builder.subtitle')} />
        <EmptyState title={t('builder.empty.noProject.title')}
          hint={t('builder.empty.noProject.hint')} />
      </div>
    )
  }

  // What each step needs before it can be left behind.
  const blocked = {
    where: !component || !hasCode,
    what: actions.length === 0,
    when: triggers.length === 0,
    file: false,
  }[STEPS[step].id]

  const last = step === STEPS.length - 1

  return (
    <div className="wizard">
      <PageHeader
        title={t('builder.title')}
        subtitle={t('builder.subtitleFull')}
        actions={<button className="mini" onClick={onBack}>← {t('builder.back')}</button>}
      />

      <ol className="wizard-rail">
        {STEPS.map((row, index) => (
          <li key={row.id}
            className={`wizard-stop${index === step ? ' is-current' : ''}${index < step ? ' is-done' : ''}`}>
            <button type="button" onClick={() => index < step && setStep(index)}
              disabled={index > step}>
              <span className="wizard-dot">{index < step ? '✓' : index + 1}</span>
              <span className="wizard-label">{t(row.labelKey)}</span>
            </button>
          </li>
        ))}
      </ol>

      {error && <ErrorBanner error={error} />}

      {step === 0 && (
        <Card title={t('builder.step.where')}>
          <div className="wizard-fields">
            <label className="field-block">
              <span>{t('builder.field.project')}</span>
              <select value={project} onChange={(event) => setProject(event.target.value)}>
                {projects.map((row) => (
                  <option key={row.slug} value={row.slug}>{row.name}</option>
                ))}
              </select>
            </label>
            <label className="field-block">
              <span>{t('builder.field.component')}</span>
              <select value={component} onChange={(event) => setComponent(event.target.value)}
                disabled={!blueprint}>
                {(blueprint?.components || []).map((row) => (
                  <option key={row.id} value={row.id}>
                    {row.name}{row.repositories.length ? '' : t('builder.field.noRepository')}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {hasCode ? (
            <ul className="repo-cards">
              {repositories.map((repo) => (
                <li key={repo.id}>
                  <span className="repo-head">
                    <span className="repo-name">{repo.name}</span>
                    <Pill>{repo.ci_label}</Pill>
                    {repo.last_commit_sha && (
                      <span className="muted mono">{String(repo.last_commit_sha).slice(0, 8)}…</span>
                    )}
                  </span>
                  <span className="repo-remote mono">{repo.remote_url}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="wizard-warning">
              {t('builder.warning.noRepository', {
                project: blueprint?.project.name || project,
              })}
            </p>
          )}

          <div className="wizard-inline">
            <span>{t('builder.field.targetCi')}</span>
            <select value={provider} onChange={(event) => setProvider(event.target.value)}>
              {PROVIDER_CHOICES.map((row) => (
                <option key={row.value} value={row.value}>{t(row.labelKey)}</option>
              ))}
            </select>
            {!provider && <span className="muted">→ {detectedLabel}</span>}
          </div>
        </Card>
      )}

      {step === 1 && (
        <Card title={t('builder.step.what')}>
          <div className="options">
            {(blueprint?.actions || []).map((row) => (
              <ActionOption key={row.name} row={row} on={actions.includes(row.name)}
                onToggle={toggleIn(setActions)} t={t} />
            ))}
          </div>
          <p className="wizard-note">
            {t('builder.note.catalog')}
            {repeatedTasks.length > 0 && (
              <>
                {' '}{t('builder.note.repeatedBefore')}
                <span className="mono">{repeatedTasks.join(', ')}</span>
                {t('builder.note.repeatedAfter')}
              </>
            )}
          </p>
        </Card>
      )}

      {step === 2 && (
        <Card title={t('builder.step.when')}>
          <div className="chip-row">
            {(blueprint?.triggers || []).map((row) => (
              <button key={row.name} type="button"
                className={`chip${triggers.includes(row.name) ? ' is-on' : ''}`}
                onClick={() => toggleIn(setTriggers)(row.name)}
                title={row.detail}>
                {triggers.includes(row.name) ? '✓ ' : ''}
                {TRIGGER_LABEL[row.name] ? t(TRIGGER_LABEL[row.name]) : row.label}
              </button>
            ))}
          </div>

          {triggers.includes('push') && (
            <label className="field-block" style={{ marginTop: 16 }}>
              <span>{t('builder.field.branch')}</span>
              <input value={branch} onChange={(event) => setBranch(event.target.value)}
                placeholder="main" />
            </label>
          )}

          <label className="field-block" style={{ marginTop: 16 }}>
            <span>{t('builder.field.apiUrl')}</span>
            <input value={apiUrl} onChange={(event) => setApiUrl(event.target.value)}
              placeholder="https://barad.example.com:8090" />
          </label>
          <p className="wizard-note">
            {t('builder.note.networkBefore')}<code>127.0.0.1</code>{t('builder.note.networkAfter')}
          </p>
        </Card>
      )}

      {step === 3 && (
        <div className="wizard-result">
          {!snippet ? (
            <Card title={t('builder.step.file')}>
              <EmptyState title={t('builder.file.building.title')}
                hint={error ? t('builder.file.building.refused')
                  : t('builder.file.building.hint')} />
            </Card>
          ) : (
            <>
              <Card title={snippet.path}
                actions={(
                  <div className="row">
                    <span className="muted">{snippet.label}</span>
                    <button className="primary-action" onClick={copy}>
                      {copied ? t('builder.copy.done') : t('builder.copy.action')}
                    </button>
                  </div>
                )}>
                <pre className="wizard-code mono">{snippet.body}</pre>
                <p className="wizard-note">
                  {t('builder.note.file')}
                </p>
              </Card>

              <Card title={t('builder.card.howItWorks')}>
                <ol className="wizard-notes">
                  {snippet.notes.map((note) => <li key={note}>{note}</li>)}
                </ol>
                <div className="chip-row">
                  {snippet.secrets.map((name) => (
                    <span key={name} className="pill mono">{t('builder.secret', { name })}</span>
                  ))}
                  {snippet.variables.map((name) => (
                    <span key={name} className="pill mono">{t('builder.variable', { name })}</span>
                  ))}
                </div>
                <p className="wizard-note">
                  {selected?.name || t('builder.field.component')} · {actions.join(' + ')} ·{' '}
                  {triggers.map((name) => (TRIGGER_LABEL[name] ? t(TRIGGER_LABEL[name]) : name))
                    .join(t('builder.join.and'))}
                </p>
              </Card>
            </>
          )}
        </div>
      )}

      <div className="wizard-foot">
        <button className="mini" onClick={step === 0 ? onBack : () => setStep(step - 1)}>
          {step === 0 ? t('common.cancel') : `← ${t('common.back')}`}
        </button>
        <span className="muted">
          {t('builder.footer.step', { current: step + 1, total: STEPS.length })}
          {blocked ? t('builder.footer.blocked') : ''}
        </span>
        <span className="row-end">
          {last ? (
            <button className="primary-action" onClick={() => (onDone ? onDone() : onBack())}>
              {t('builder.footer.done')}
            </button>
          ) : (
            <button className="primary-action" disabled={blocked}
              onClick={() => setStep(step + 1)}>
              {t('builder.footer.continue')}
            </button>
          )}
        </span>
      </div>
    </div>
  )
}
