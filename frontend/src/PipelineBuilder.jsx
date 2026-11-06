import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Pill } from './ui'

/* A pipeline is built in four steps, one question at a time: what it belongs to,
   what it checks, when it runs, and the file that carries all three. A wizard
   earns its clicks here because step two is not a form — it is the catalog, and
   the actions a pipeline may not run need room to say why.

   Nothing here scans. A pipeline ANNOUNCES a commit and waits on the flow's own
   verdict; the daemon does the work with the ticket it was handed. The file is
   the pipeline: this screen creates nothing on the platform. */

const STEPS = [
  { id: 'where', label: 'Where it runs' },
  { id: 'what', label: 'What it checks' },
  { id: 'when', label: 'When it runs' },
  { id: 'file', label: 'The file' },
]

const TRIGGER_LABEL = {
  push: 'on every push',
  pull_request: 'on every pull request',
  manual: 'on demand',
}

const PROVIDER_CHOICES = [
  { value: '', label: 'detect from the repository' },
  { value: 'github', label: 'GitHub Actions' },
  { value: 'gitea', label: 'Gitea Actions' },
  { value: 'gitlab', label: 'GitLab CI' },
  { value: 'generic', label: 'any other CI (portable script)' },
]

function ActionOption({ row, on, onToggle }) {
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
          {row.network && <span className="pill">touches the network</span>}
          {blocked && <span className="pill">console only</span>}
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
  const detectedLabel = repositories[0]?.ci_label || 'portable script'
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
      setError('the clipboard refused the file; select it and copy by hand')
    }
  }

  if (loading) return <Loading rows={6} label="reading the catalog" />

  if (!projects.length) {
    return (
      <div className="stack">
        <PageHeader title="New pipeline"
          subtitle="A pipeline announces a commit; the platform scans it and the build waits on the verdict." />
        <EmptyState title="No project to attach a pipeline to"
          hint="A pipeline belongs to a component of a project, and a component needs a repository. Create the project first." />
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
        title="New pipeline"
        subtitle="Four steps, and the file your repository needs at the end. Its runs land in Pipelines as commit rows with their verdict."
        actions={<button className="mini" onClick={onBack}>← pipelines</button>}
      />

      <ol className="wizard-rail">
        {STEPS.map((row, index) => (
          <li key={row.id}
            className={`wizard-stop${index === step ? ' is-current' : ''}${index < step ? ' is-done' : ''}`}>
            <button type="button" onClick={() => index < step && setStep(index)}
              disabled={index > step}>
              <span className="wizard-dot">{index < step ? '✓' : index + 1}</span>
              <span className="wizard-label">{row.label}</span>
            </button>
          </li>
        ))}
      </ol>

      {error && <ErrorBanner error={error} />}

      {step === 0 && (
        <Card title="Where it runs">
          <div className="wizard-fields">
            <label className="field-block">
              <span>project</span>
              <select value={project} onChange={(event) => setProject(event.target.value)}>
                {projects.map((row) => (
                  <option key={row.slug} value={row.slug}>{row.name}</option>
                ))}
              </select>
            </label>
            <label className="field-block">
              <span>component</span>
              <select value={component} onChange={(event) => setComponent(event.target.value)}
                disabled={!blueprint}>
                {(blueprint?.components || []).map((row) => (
                  <option key={row.id} value={row.id}>
                    {row.name}{row.repositories.length ? '' : ' — no repository'}
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
              This component has no repository bound, and every action here reads a
              checkout: the repository binding is the authorization a CI run relies
              on. Attach it in Projects → {blueprint?.project.name || project} → components.
            </p>
          )}

          <div className="wizard-inline">
            <span>target CI</span>
            <select value={provider} onChange={(event) => setProvider(event.target.value)}>
              {PROVIDER_CHOICES.map((row) => (
                <option key={row.value} value={row.value}>{row.label}</option>
              ))}
            </select>
            {!provider && <span className="muted">→ {detectedLabel}</span>}
          </div>
        </Card>
      )}

      {step === 1 && (
        <Card title="What it checks">
          <div className="options">
            {(blueprint?.actions || []).map((row) => (
              <ActionOption key={row.name} row={row} on={actions.includes(row.name)}
                onToggle={toggleIn(setActions)} />
            ))}
          </div>
          <p className="wizard-note">
            The catalog is closed: these are the actions this platform knows how to
            run, and each names the tasks it must produce. An action that reaches the
            network is the platform acting alone, so it needs a grant and runs from
            the console — a pipeline can announce, but it cannot authorize. Every flow
            fails closed: HIGH and above block the build, and a run that did not
            deliver all its tasks certifies nothing.
            {repeatedTasks.length > 0 && (
              <> A task in two actions runs once per flow: <span className="mono">{
                repeatedTasks.join(', ')
              }</span> appears in both selections.</>
            )}
          </p>
        </Card>
      )}

      {step === 2 && (
        <Card title="When it runs">
          <div className="chip-row">
            {(blueprint?.triggers || []).map((row) => (
              <button key={row.name} type="button"
                className={`chip${triggers.includes(row.name) ? ' is-on' : ''}`}
                onClick={() => toggleIn(setTriggers)(row.name)}
                title={row.detail}>
                {triggers.includes(row.name) ? '✓ ' : ''}
                {TRIGGER_LABEL[row.name] || row.label}
              </button>
            ))}
          </div>

          {triggers.includes('push') && (
            <label className="field-block" style={{ marginTop: 16 }}>
              <span>branch the push trigger watches</span>
              <input value={branch} onChange={(event) => setBranch(event.target.value)}
                placeholder="main" />
            </label>
          )}

          <label className="field-block" style={{ marginTop: 16 }}>
            <span>API root the runner calls — written into the file as BARAD_URL</span>
            <input value={apiUrl} onChange={(event) => setApiUrl(event.target.value)}
              placeholder="https://barad.example.com:8090" />
          </label>
          <p className="wizard-note">
            A CI runner does not share this console's network: <code>127.0.0.1</code> is
            the runner's own machine. Left empty, the file reads a repository variable
            instead of carrying an address that only works here.
          </p>
        </Card>
      )}

      {step === 3 && (
        <div className="wizard-result">
          {!snippet ? (
            <Card title="The file">
              <EmptyState title="Building the file…"
                hint={error ? 'The platform refused the selection; read the banner above.'
                  : 'The workflow is generated from the three previous steps.'} />
            </Card>
          ) : (
            <>
              <Card title={snippet.path}
                actions={(
                  <div className="row">
                    <span className="muted">{snippet.label}</span>
                    <button className="primary-action" onClick={copy}>
                      {copied ? 'copied ✓' : 'copy the file'}
                    </button>
                  </div>
                )}>
                <pre className="wizard-code mono">{snippet.body}</pre>
                <p className="wizard-note">
                  This screen creates nothing on the platform: the file is the
                  pipeline. Commit it and the next push announces itself — the run
                  appears under Pipelines as a commit row with its verdict.
                </p>
              </Card>

              <Card title="What makes it work">
                <ol className="wizard-notes">
                  {snippet.notes.map((note) => <li key={note}>{note}</li>)}
                </ol>
                <div className="chip-row">
                  {snippet.secrets.map((name) => (
                    <span key={name} className="pill mono">{name} · secret</span>
                  ))}
                  {snippet.variables.map((name) => (
                    <span key={name} className="pill mono">{name} · variable</span>
                  ))}
                </div>
                <p className="wizard-note">
                  {selected?.name || 'component'} · {actions.join(' + ')} ·{' '}
                  {triggers.map((name) => TRIGGER_LABEL[name] || name).join(' and ')}
                </p>
              </Card>
            </>
          )}
        </div>
      )}

      <div className="wizard-foot">
        <button className="mini" onClick={step === 0 ? onBack : () => setStep(step - 1)}>
          {step === 0 ? 'cancel' : '← back'}
        </button>
        <span className="muted">
          step {step + 1} of {STEPS.length}
          {blocked ? ' · finish this step to continue' : ''}
        </span>
        <span className="row-end">
          {last ? (
            <button className="primary-action" onClick={() => (onDone ? onDone() : onBack())}>
              done — go to pipelines
            </button>
          ) : (
            <button className="primary-action" disabled={blocked}
              onClick={() => setStep(step + 1)}>
              continue →
            </button>
          )}
        </span>
      </div>
    </div>
  )
}
