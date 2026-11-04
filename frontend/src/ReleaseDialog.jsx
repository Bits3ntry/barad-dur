import React, { useMemo, useState } from 'react'
import { api } from './api'
import { Dialog } from './ui'

/* One form for the whole release intent: which part, which build, where it runs,
   which domain faces it and how we learn its version. Splitting this into
   "add component → name version → deploy → add asset → configure probe" is five
   dialogs for one decision, and four of them are meaningless without the fifth.

   The write itself is a sequence of the existing endpoints (component, version,
   deployment, asset, probe). A failure names the step that broke. */

const ENVIRONMENTS = ['DEV', 'PRE', 'PRO', 'production', 'staging', 'preview']

const EMPTY = {
  componentId: '', componentName: '', componentKind: 'backend',
  versionId: '', versionLabel: '', versionAuto: false,
  environment: 'DEV',
  exposure: 'unknown', requiresAuth: false,
  assetId: '', domain: '',
  probe: true, probePath: '/health', intervalHours: 24, versionPath: 'auto',
}

export default function ReleaseDialog({ open, onClose, slug, components = [],
                                      versions = [], assets = [], onDone }) {
  const [form, setForm] = useState(EMPTY)
  const [error, setError] = useState('')
  const [step, setStep] = useState('')
  const [busy, setBusy] = useState(false)

  const component = components.find((row) => row.id === form.componentId)
  const componentVersions = useMemo(
    () => versions.filter((row) => row.component_id === form.componentId),
    [versions, form.componentId])

  function set(patch) {
    setForm((current) => ({ ...current, ...patch }))
    setError('')
  }

  // Returns false to veto the Dialog close while the request runs; the success
  // path closes it explicitly.
  function submit() {
    if (!form.componentId && !form.componentName.trim()) {
      setError('Choose a component or name a new one.')
      return false
    }
    if (!form.environment.trim()) {
      setError('An environment is required — DEV, PRE, PRO…')
      return false
    }
    if (!form.versionId && !form.versionLabel.trim() && !form.versionAuto) {
      setError('Pick an existing version, name a new one, or let the endpoint read it.')
      return false
    }
    if (form.probe && !form.domain.trim() && !form.assetId) {
      setError('A probe needs a domain to ask. Choose or type one, or turn the probe off.')
      return false
    }
    run()
    return false
  }

  async function run() {
    setBusy(true)
    setError('')
    // A local copy: state updates are async, and the catch has to name the step
    // that actually broke, not the one the previous render knew about.
    let at = 'component'
    const mark = (next) => { at = next; setStep(next) }
    mark('component')
    try {
      let componentId = form.componentId
      if (!componentId) {
        const created = await api.post(`/api/v1/projects/${encodeURIComponent(slug)}/components`, {
          name: form.componentName.trim(), kind: form.componentKind, actor: 'console',
        })
        componentId = created.data.id
      }

      mark('version')
      let versionId = form.versionId || undefined
      let versionLabel = form.versionLabel.trim() || undefined
      if (!versionId && !versionLabel && !form.versionAuto) {
        versionLabel = undefined
      }
      if (!versionId && versionLabel) {
        const created = await api.post(`/api/v1/projects/${encodeURIComponent(slug)}/versions`,
          { version: versionLabel, component_id: componentId, actor: 'console' })
        versionId = created.data.id
      }

      mark('environment')
      const deployment = await api.post(
        `/api/v1/projects/${encodeURIComponent(slug)}/deployments`, {
          component_id: componentId,
          environment: form.environment.trim(),
          version_id: versionId,
          version_label: versionId ? undefined : versionLabel,
          exposure: form.exposure,
          requires_auth: form.requiresAuth,
          actor: 'console',
        })
      const deploymentId = deployment.data.id

      let domain = form.domain.trim()
      if (form.assetId) {
        const chosen = assets.find((row) => row.id === form.assetId)
        domain = chosen ? chosen.value : domain
      }

      mark('domain')
      if (domain) {
        await api.post(`/api/v1/projects/${encodeURIComponent(slug)}/assets`, {
          type: 'domain', value: domain, deployment_id: deploymentId, actor: 'console',
        })
      }

      mark('probe')
      if (form.probe && domain) {
        const path = form.probePath.startsWith('/') ? form.probePath : `/${form.probePath}`
        await api.put(`/api/v1/deployments/${deploymentId}/health-probe`, {
          url: `https://${domain}${path}`,
          version_path: form.versionPath || 'auto',
          interval_minutes: Math.max(60, Math.round(Number(form.intervalHours) * 60)) || 1440,
          enabled: true,
          actor: 'console',
        })
      }

      setStep('')
      onDone?.(`${component?.name || form.componentName} ${form.versionLabel || ''}`
        + ` · ${form.environment}${domain ? ` · ${domain}` : ''}`
        + `${form.probe && domain ? ' · probe daily' : ''}`)
      setForm(EMPTY)
      onClose()
    } catch (problem) {
      setError(`${at}: ${String(problem.message || problem)}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} title="New environment" size="wide"
      onClose={() => { if (!busy) onClose() }} onConfirm={submit}
      confirmLabel={busy ? `saving ${step || '…'}` : 'create'}>
      <div className="release-form">
        <p className="muted release-intro">
          One submission creates the pieces that only make sense together: the component if
          you name a new one, the version, the environment, the domain that faces it and
          the endpoint we ask for its version.
        </p>

        <fieldset className="release-group">
          <legend>What it is</legend>
          <label className="field">
            <span>component</span>
            <select value={form.componentId}
              onChange={(event) => set({ componentId: event.target.value, versionId: '' })}>
              <option value="">— new component —</option>
              {components.map((row) => (
                <option key={row.id} value={row.id}>{row.name} · {row.kind}</option>
              ))}
            </select>
          </label>
          {!form.componentId && (
            <div className="release-row">
              <label className="field">
                <span>name</span>
                <input value={form.componentName} placeholder="backend"
                  onChange={(event) => set({ componentName: event.target.value })} />
              </label>
              <label className="field">
                <span>kind</span>
                <select value={form.componentKind}
                  onChange={(event) => set({ componentKind: event.target.value })}>
                  {['backend', 'frontend', 'web', 'ios', 'android', 'worker',
                    'service', 'library', 'infrastructure', 'other'].map((kind) => (
                    <option key={kind} value={kind}>{kind}</option>
                  ))}
                </select>
              </label>
            </div>
          )}

          <label className="field">
            <span>version</span>
            <select value={form.versionAuto ? '__auto' : form.versionId}
              onChange={(event) => {
                const value = event.target.value
                if (value === '__auto') set({ versionAuto: true, versionId: '', versionLabel: '' })
                else if (value === '__new') set({ versionAuto: false, versionId: '', versionLabel: '' })
                else set({ versionAuto: false, versionId: value, versionLabel: '' })
              }}
              disabled={!form.componentId}>
              <option value="">— new version —</option>
              {componentVersions.map((row) => (
                <option key={row.id} value={row.id}>{row.version}</option>
              ))}
              <option value="__auto">read it from the endpoint</option>
            </select>
          </label>
          {!form.componentId && (
            <p className="muted release-hint">
              Pick the component first: versions belong to one part, not to the product.
            </p>
          )}
          {form.componentId && !form.versionId && !form.versionAuto && (
            <label className="field">
              <span>new version label</span>
              <input value={form.versionLabel} placeholder="1.9"
                onChange={(event) => set({ versionLabel: event.target.value })} />
            </label>
          )}
        </fieldset>

        <fieldset className="release-group">
          <legend>Where it runs</legend>
          <div className="release-row">
            <label className="field">
              <span>environment</span>
              <input list="release-environments" value={form.environment}
                onChange={(event) => set({ environment: event.target.value })} />
              <datalist id="release-environments">
                {ENVIRONMENTS.map((name) => <option key={name} value={name} />)}
              </datalist>
            </label>
            <label className="field">
              <span>exposure</span>
              <select value={form.exposure}
                onChange={(event) => set({ exposure: event.target.value })}>
                {['unknown', 'internal', 'public'].map((value) => (
                  <option key={value} value={value}>{value}</option>
                ))}
              </select>
            </label>
          </div>
          <label className="row release-check">
            <input type="checkbox" checked={form.requiresAuth}
              onChange={(event) => set({ requiresAuth: event.target.checked })} />
            requires authentication
          </label>
        </fieldset>

        <fieldset className="release-group">
          <legend>Domain</legend>
          <div className="release-row">
            <label className="field">
              <span>known asset</span>
              <select value={form.assetId}
                onChange={(event) => set({ assetId: event.target.value, domain: '' })}>
                <option value="">— new domain —</option>
                {assets.map((row) => (
                  <option key={row.id} value={row.id}>{row.value}</option>
                ))}
              </select>
            </label>
            {!form.assetId && (
              <label className="field">
                <span>hostname</span>
                <input value={form.domain} placeholder="api.dev.example.com"
                  onChange={(event) => set({ domain: event.target.value })} />
              </label>
            )}
          </div>
        </fieldset>

        <fieldset className="release-group">
          <legend>How we learn its version</legend>
          <label className="row release-check">
            <input type="checkbox" checked={form.probe}
              onChange={(event) => set({ probe: event.target.checked })} />
            ask the deployment for its version
          </label>
          {form.probe && (
            <>
              <div className="release-row">
                <label className="field">
                  <span>endpoint path</span>
                  <input value={form.probePath} placeholder="/health"
                    onChange={(event) => set({ probePath: event.target.value })} />
                </label>
                <label className="field">
                  <span>version field</span>
                  <input value={form.versionPath} placeholder="auto"
                    onChange={(event) => set({ versionPath: event.target.value })} />
                </label>
                <label className="field">
                  <span>every (hours)</span>
                  <input type="number" min="1" max="168" value={form.intervalHours}
                    onChange={(event) => set({ intervalHours: event.target.value })} />
                </label>
              </div>
              <p className="muted release-hint">
                A read-only GET against the domain above. If the version it returns is not
                named yet, it is created inside this component — never duplicated.
              </p>
            </>
          )}
        </fieldset>

        {error && (
          <p role="alert" className="release-error">{error}</p>
        )}
      </div>
    </Dialog>
  )
}
