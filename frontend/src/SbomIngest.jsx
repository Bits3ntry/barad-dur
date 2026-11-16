import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Banner, Drawer, Tabs } from './ui'
import { useI18n } from './i18n'

/* One door for a build that arrives without a pipeline.

   The pipeline inherits the project and the component from the repository it
   builds; a person handing over a file has neither, and Trivy writes the scanned
   path (`.`) as the document's root. So the flow is: read the document, show what
   it says and what we guessed, let the operator correct the guess, then write the
   build through the same ingestion the pipeline uses — same rows, same screen,
   minus the source weaknesses only a code scan can produce.

   The second tab is the same thing performed by the scanner itself, because a
   file a person exported by hand is the fallback, not the recommendation. */

const CLI_ACTION = 'supply-chain'

function reasonKey(reason) {
  return `sbom.ingest.reason.${reason || 'none'}`
}

function Stage({ number, title, subtitle, children }) {
  return (
    <section className="ingest-stage">
      <header className="ingest-stage-head">
        <span className="ingest-num" aria-hidden="true">{number}</span>
        <div>
          <strong>{title}</strong>
          {subtitle ? <span className="muted">{subtitle}</span> : null}
        </div>
      </header>
      {children}
    </section>
  )
}

function Command({ text }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { setCopied(false) }
  }
  return (
    <div className="ingest-cmd">
      <pre>{text}</pre>
      <button className="mini" onClick={copy} type="button">
        {copied ? t('sbom.ingest.cli.copied') : t('sbom.ingest.cli.copy')}
      </button>
    </div>
  )
}

/* Four numbers, each labelled underneath: the reader decides whether this file is
   the right one from the count alone before reading a single field. */
function Facts({ analysis }) {
  const { tCount } = useI18n()
  const counts = analysis.counts || {}
  const cells = [
    { key: 'components', value: counts.components || 0 },
    { key: 'direct', value: counts.direct || 0 },
    { key: 'advisories', value: counts.vulnerabilities || 0 },
    { key: 'containers', value: counts.containers || 0 },
  ]
  return (
    <div className="ingest-facts">
      {cells.map((cell) => (
        <div className="ingest-fact" key={cell.key}>
          <b>{cell.value}</b>
          <span>{tCount(`sbom.ingest.fact.long.${cell.key}`, cell.value)}</span>
        </div>
      ))}
    </div>
  )
}

function CliTab({ platform, project, component, version }) {
  const { t } = useI18n()
  const url = platform || '<platform-url>'
  const target = [
    `--project ${project || '<project>'}`,
    component ? `--component ${component}` : '--component <component>',
    version ? `--version ${version}` : '--version <version>',
  ].join(' ')
  return (
    <div className="ingest">
      <p className="ingest-lead">{t('sbom.ingest.cli.intro')}</p>

      <Stage number="1" title={t('sbom.ingest.cli.install')}>
        <Command text="pipx install shauron    # or: pip install -e /path/to/shauron" />
      </Stage>

      <Stage number="2" title={t('sbom.ingest.cli.check')}>
        <Command text={`shauron doctor --platform ${url}`} />
      </Stage>

      <Stage number="3" title={t('sbom.ingest.cli.run')}>
        <Command text={`export SHAURON_BARAD_KEY='<your key>'\nshauron scan --platform ${url} --api-key "$SHAURON_BARAD_KEY" \\\n  ${target} --action ${CLI_ACTION} --path .`} />
      </Stage>

      <p className="ingest-lead">{t('sbom.ingest.cli.note')}</p>
    </div>
  )
}

export default function SbomIngest({
  open, onClose, projects = [], defaultProject = '', defaultComponent = '',
  onUploaded, onOpenBuild,
  // Same-origin by construction: the console reaches `/api` through the address it
  // is read at, so that is the address a terminal can post to as well.
  platform = typeof window !== 'undefined' ? window.location.origin : '',
}) {
  const { t } = useI18n()
  const [tab, setTab] = useState('upload')
  const [file, setFile] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [busy, setBusy] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [note, setNote] = useState('')
  const [receipt, setReceipt] = useState(null)

  const [projectSlug, setProjectSlug] = useState('')
  const [newProject, setNewProject] = useState('')
  const [componentSlug, setComponentSlug] = useState(defaultComponent || '')
  const [newComponent, setNewComponent] = useState('')
  const [version, setVersion] = useState('')
  const [components, setComponents] = useState([])
  const [loadComponents, setLoadComponents] = useState(false)

  function reset() {
    setFile(null); setAnalysis(null); setNote(''); setReceipt(null)
    setProjectSlug(defaultProject || ''); setNewProject('')
    setComponentSlug(defaultComponent || ''); setNewComponent('')
    setVersion(''); setComponents([]); setBusy(false); setDragging(false)
  }

  useEffect(() => {
    if (open) { reset(); setTab('upload') }
    // A reopened drawer starts from the caller's context, never the last attempt.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const projectOptions = useMemo(
    () => projects.map((row) => ({ slug: row.slug, name: row.name })), [projects])

  // The component list follows the chosen project. Fetching it here keeps the
  // picker honest: a component belongs to one project and cannot be typed from
  // another project's catalogue.
  useEffect(() => {
    if (!projectSlug) { setComponents([]); return undefined }
    let cancelled = false
    setLoadComponents(true)
    api.get(`/api/v1/projects/${encodeURIComponent(projectSlug)}/inventory`)
      .then((response) => {
        if (!cancelled) setComponents(response.data?.components || [])
      })
      .catch(() => { if (!cancelled) setComponents([]) })
      .finally(() => { if (!cancelled) setLoadComponents(false) })
    return () => { cancelled = true }
  }, [projectSlug])

  async function pickFile(chosen) {
    if (!chosen) return
    setFile(chosen); setNote(''); setReceipt(null); setAnalysis(null)
    setBusy(true)
    try {
      const params = new URLSearchParams({ filename: chosen.name })
      const data = await api.postRaw(`/api/v1/sbom/analyze?${params}`,
        await chosen.arrayBuffer())
      const found = data.data
      setAnalysis(found)
      const detected = found.detected || {}
      if (detected.project?.slug) {
        setProjectSlug(detected.project.slug); setNewProject('')
      } else {
        // Nothing in the document names a project: keep whatever the screen was
        // opened with, and let the operator type the new one.
        setProjectSlug(defaultProject || '')
      }
      setComponentSlug(detected.component?.slug || '')
      setVersion(detected.version || '')
    } catch (problem) {
      setNote(String(problem.message || problem))
    } finally { setBusy(false) }
  }

  // Choosing "create a new project" is the empty option, so the name field is
  // shown whenever nothing existing is selected — gating it on already-typed
  // text hides the only input that could receive the name.
  const creatingProject = !projectSlug
  const resolvedProject = projectSlug || newProject.trim()
  const wantsNewComponent = !creatingProject && componentSlug === '__new__'
  // A project that does not exist yet has no component list to pick from, so the
  // first build of a new project names its component instead of selecting one.
  const resolvedComponent = creatingProject
    ? newComponent.trim()
    : (wantsNewComponent ? newComponent.trim() : componentSlug)
  const creatingComponent = creatingProject
    ? newComponent.trim() !== ''
    : wantsNewComponent

  async function submit() {
    if (!file) { setNote(t('sbom.ingest.note.pickFile')); return }
    if (!resolvedProject) { setNote(t('sbom.ingest.note.projectRequired')); return }
    if (wantsNewComponent && !newComponent.trim()) {
      setNote(t('sbom.ingest.note.componentName')); return
    }
    if (!version.trim()) { setNote(t('sbom.ingest.note.versionRequired')); return }
    setBusy(true); setNote('')
    try {
      const params = new URLSearchParams({
        source: 'web', project: resolvedProject, version: version.trim(),
        filename: file.name,
      })
      if (resolvedComponent) params.set('component', resolvedComponent)
      if (creatingComponent) params.set('create_component', 'true')
      const response = await api.postRaw(`/api/v1/sbom?${params}`,
        await file.arrayBuffer())
      setReceipt(response)
      if (onUploaded) await onUploaded(response)
    } catch (problem) {
      setNote(String(problem.message || problem))
    } finally { setBusy(false) }
  }

  const warnings = analysis?.warnings || []
  const duplicate = analysis?.duplicate
  const detected = analysis?.detected || {}
  const spec = analysis ? [analysis.format?.bom_format, analysis.format?.spec_version]
    .filter(Boolean).join(' ') : ''

  return (
    <Drawer open={open} onClose={onClose} title={t('sbom.ingest.title')}>
      <div className="ingest">
        <Tabs tabs={[
          { id: 'upload', label: t('sbom.ingest.tab.upload') },
          { id: 'cli', label: t('sbom.ingest.tab.cli') },
        ]} active={tab} onChange={setTab} />

        {tab === 'cli' && <CliTab platform={platform} project={resolvedProject}
          component={resolvedComponent} version={version.trim()} />}

        {tab === 'upload' && (
          <>
            <p className="ingest-lead">{t('sbom.ingest.lead')}</p>

            <Stage number="1" title={t('sbom.ingest.stage.document')}
              subtitle={t('sbom.ingest.stage.documentHint')}>
              <label className={`ingest-drop${file ? ' has-file' : ''}${dragging ? ' is-over' : ''}`}
                onDragOver={(event) => { event.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => {
                  event.preventDefault(); setDragging(false)
                  pickFile(event.dataTransfer.files?.[0])
                }}>
                <input type="file" accept=".json,application/json"
                  onChange={(event) => pickFile(event.target.files[0])} />
                <span className="ingest-drop-icon" aria-hidden="true">⇪</span>
                <span className="ingest-drop-name">
                  {file ? file.name : t('sbom.ingest.drop.title')}
                </span>
                <span className="ingest-drop-hint">
                  {busy ? t('sbom.ingest.reading')
                    : file ? t('sbom.ingest.drop.again') : t('sbom.ingest.drop.hint')}
                </span>
              </label>
            </Stage>

            {analysis && (
              <>
                <Stage number="2" title={t('sbom.ingest.stage.place')}
                  subtitle={[spec, analysis.filename].filter(Boolean).join(' · ')}>
                  <Facts analysis={analysis} />

                  <div className={`ingest-verdict ${detected.project ? 'is-ok' : 'is-warn'}`}>
                    <span className="ingest-verdict-mark" aria-hidden="true">
                      {detected.project ? '✓' : '!'}
                    </span>
                    <div>
                      {detected.project ? (
                        <>
                          <strong>{t('sbom.ingest.verdict.detected', { project: detected.project.name })}</strong>
                          <span className="muted"> · {t(reasonKey(detected.project.reason))}</span>
                          {detected.component ? (
                            <span className="muted"> · {t('sbom.ingest.verdict.component', { component: detected.component.name })}</span>
                          ) : null}
                          {detected.version ? (
                            <span className="muted"> · {t('sbom.ingest.verdict.version', { version: detected.version })}</span>
                          ) : null}
                        </>
                      ) : (
                        <>
                          <strong>{t('sbom.ingest.verdict.none')}</strong>
                          <span className="muted"> {t('sbom.ingest.hint.noProjectShort')}</span>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="ingest-fields">
                    <div className="field">
                      <label className="field-label">{t('sbom.ingest.field.project')}</label>
                      <select value={projectSlug}
                        onChange={(event) => { setProjectSlug(event.target.value); setNewProject('') }}>
                        <option value="">{t('sbom.ingest.project.new')}</option>
                        {projectOptions.map((row) => (
                          <option key={row.slug} value={row.slug}>{row.name}</option>
                        ))}
                      </select>
                    </div>
                    {creatingProject && (
                      <div className="field">
                        <label className="field-label">{t('sbom.ingest.field.newProject')}</label>
                        <input value={newProject}
                          placeholder={analysis.document?.root_names_nothing
                            ? t('sbom.ingest.field.newProjectPlaceholder')
                            : analysis.document?.root_name || t('sbom.ingest.field.newProjectPlaceholder')}
                          onChange={(event) => setNewProject(event.target.value)} />
                        <span className="muted">{t('sbom.ingest.hint.newProject')}</span>
                      </div>
                    )}

                    <div className="field">
                      <label className="field-label">{t('sbom.ingest.field.component')}</label>
                      {creatingProject ? (
                        <input value={newComponent}
                          placeholder={analysis.document?.root_names_nothing
                            ? t('sbom.ingest.field.newComponentPlaceholder')
                            : analysis.document?.root_name || t('sbom.ingest.field.newComponentPlaceholder')}
                          onChange={(event) => setNewComponent(event.target.value)} />
                      ) : (
                        <select value={componentSlug} onChange={(event) => {
                          setComponentSlug(event.target.value); setNewComponent('')
                        }} disabled={loadComponents}>
                          <option value="">{t('sbom.ingest.component.none')}</option>
                          {components.map((row) => (
                            <option key={row.id} value={row.slug}>{row.name}</option>
                          ))}
                          <option value="__new__">{t('sbom.ingest.component.new')}</option>
                        </select>
                      )}
                      <span className="muted">
                        {creatingProject ? t('sbom.ingest.hint.componentNewProject')
                          : t('sbom.ingest.hint.component')}
                      </span>
                    </div>
                    {!creatingProject && componentSlug === '__new__' && (
                      <div className="field">
                        <label className="field-label">{t('sbom.ingest.field.newComponent')}</label>
                        <input value={newComponent}
                          placeholder={analysis.document?.root_names_nothing
                            ? t('sbom.ingest.field.newComponentPlaceholder')
                            : analysis.document?.root_name || t('sbom.ingest.field.newComponentPlaceholder')}
                          onChange={(event) => setNewComponent(event.target.value)} />
                        <span className="muted">{t('sbom.ingest.hint.newComponent')}</span>
                      </div>
                    )}

                    <div className="field">
                      <label className="field-label">{t('sbom.ingest.field.version')}</label>
                      <input value={version} onChange={(event) => setVersion(event.target.value)} />
                      <span className="muted">
                        {detected.version_from === 'filename'
                          ? t('sbom.ingest.hint.versionFromFilename')
                          : t('sbom.ingest.hint.version')}
                      </span>
                    </div>
                  </div>

                  <div className="ingest-actions">
                    <button className="btn-primary" onClick={submit}
                      disabled={busy || !resolvedProject || !version.trim()}>
                      {busy ? t('sbom.ingest.saving') : t('sbom.ingest.save')}
                    </button>
                  </div>
                  <p className="ingest-hint">{t('sbom.ingest.saveHint')}</p>
                </Stage>

                {duplicate && <Banner kind="warn">{t('sbom.ingest.duplicate')}</Banner>}
                {warnings.includes('no_components') && (
                  <Banner kind="info">{t('sbom.ingest.hint.noComponents')}</Banner>
                )}
              </>
            )}

            {note && <div className="banner banner-error">{note}</div>}

            {receipt && (
              <div className="ingest-receipt">
                <div className="ingest-receipt-head">
                  <span aria-hidden="true">✓</span>
                  <span>
                    {receipt.status === 'duplicate'
                      ? t('sbom.ingest.result.unchangedTitle')
                      : t('sbom.ingest.result.savedTitle')}
                  </span>
                </div>
                <p className="ingest-lead">
                  {receipt.status === 'duplicate'
                    ? t('sbom.ingest.result.unchangedBody')
                    : t('sbom.ingest.result.savedBody', {
                      created: receipt.receipt?.counts?.components_created ?? 0,
                      updated: receipt.receipt?.counts?.components_updated ?? 0,
                    })}
                </p>
                {receipt.build && onOpenBuild && (
                  <button className="btn-primary" onClick={() => onOpenBuild(receipt.build)}>
                    {t('sbom.ingest.result.open')}
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </Drawer>
  )
}
