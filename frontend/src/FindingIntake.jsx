import React, { useEffect, useState } from 'react'
import { api } from './api'
import { ErrorBanner, PageHeader } from './ui'
import { useI18n } from './i18n'

/* Registering a vulnerability is writing a record, not filing a ticket:
     what it is · where it lives · how we got in · what proves it · what we expected
   The order is the order of the investigation, and the HTTP block is the moment of
   the finding — a report nobody else can replay is not evidence.
   A session recipe is created once and reused: the token lives in `auth_profiles`,
   not pasted into forty findings. */

const CWES = [
  ['', 'sin clasificar'],
  ['CWE-79', 'CWE-79 · XSS'],
  ['CWE-89', 'CWE-89 · SQL injection'],
  ['CWE-78', 'CWE-78 · inyección de comandos'],
  ['CWE-22', 'CWE-22 · path traversal'],
  ['CWE-352', 'CWE-352 · CSRF'],
  ['CWE-639', 'CWE-639 · IDOR / acceso a objeto ajeno'],
  ['CWE-287', 'CWE-287 · bypass de autenticación'],
  ['CWE-863', 'CWE-863 · autorización incorrecta'],
  ['CWE-918', 'CWE-918 · SSRF'],
  ['CWE-611', 'CWE-611 · XXE'],
  ['CWE-502', 'CWE-502 · deserialización insegura'],
  ['CWE-434', 'CWE-434 · subida sin restricción'],
  ['CWE-798', 'CWE-798 · credenciales embebidas'],
  ['CWE-200', 'CWE-200 · exposición de información'],
  ['CWE-601', 'CWE-601 · open redirect'],
  ['CWE-319', 'CWE-319 · tráfico sin cifrar'],
  ['CWE-16', 'CWE-16 · configuración insegura'],
  ['CWE-1104', 'CWE-1104 · componente desactualizado'],
]

const AUTH_KINDS = ['cookie', 'bearer', 'header', 'basic', 'form_login', 'oauth', 'mtls', 'none']
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

const EMPTY = {
  title: '', cwe: '', severity: 'high', kind: 'vulnerability',
  product_component_id: '', url: '', http_method: 'GET', endpoint: '',
  auth_required: false, auth_profile_id: '',
  expected_result: '', observed_result: '', validation_output: '',
  proof_request: '', proof_response: '',
  impact: '', reproduction: '', description: '',
  asset_id: '', project: '', cycle_id: '', version_id: '',
}

function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="muted" style={{ fontSize: 11.5 }}>{hint}</span>}
    </label>
  )
}

export default function FindingIntake({ cycleId, jewels: givenJewels, seed = {}, onDone, onCancel }) {
  const { t } = useI18n()
  // The same form serves a cycle's ledger and the estate queue: what changes is the
  // subject it starts with, never the record it writes.
  const [form, setForm] = useState(() => ({
    ...EMPTY,
    ...(cycleId ? { cycle_id: cycleId } : {}),
    ...(seed.project ? { project: seed.project } : {}),
    ...(seed.cycle ? { cycle_id: seed.cycle } : {}),
    ...(seed.asset ? { asset_id: seed.asset } : {}),
    ...(seed.build ? { version_id: seed.build } : {}),
  }))
  const [jewels, setJewels] = useState(givenJewels || [])
  const [projects, setProjects] = useState([])
  const [cycles, setCycles] = useState([])
  const [builds, setBuilds] = useState([])
  const [profiles, setProfiles] = useState([])
  const [assets, setAssets] = useState([])
  const [assetQuery, setAssetQuery] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [newProfile, setNewProfile] = useState(null)

  useEffect(() => { load() }, [])

  async function load() {
    try {
      const list = await api.get('/api/v1/auth-profiles')
      setProfiles(list.data || [])
    } catch (e) {
      setError(String(e.message || e))
    }
    // The subjects this record can name. A failure here must not lock the form:
    // the record is still writable with what the operator types.
    if (!givenJewels) {
      api.get('/api/v1/threat-model/crown-jewels')
        .then((r) => setJewels(r.data || [])).catch(() => setJewels([]))
    }
    api.get('/api/v1/projects').then((r) => setProjects(r.data || [])).catch(() => setProjects([]))
    api.get('/api/v1/cycles').then((r) => setCycles(r.data || [])).catch(() => setCycles([]))
  }

  // A build belongs to a project: changing the owner drops the release it had.
  useEffect(() => {
    if (!form.project) { setBuilds([]); return }
    api.get(`/api/v1/projects/${encodeURIComponent(form.project)}/inventory`)
      .then((r) => setBuilds((r.data?.versions || []).map((row) => ({
        id: row.id,
        // Two components of one project ship the same label (`main`), so the build
        // says which one it is: picking the wrong `main` is picking another build.
        label: row.component ? `${row.version} · ${row.component}` : row.version,
      }))))
      .catch(() => setBuilds([]))
  }, [form.project])

  useEffect(() => {
    if (!assetQuery.trim() || assetQuery.trim().length < 2) { setAssets([]); return }
    const timer = setTimeout(() => {
      api.get(`/api/v1/cycles/scope-search?q=${encodeURIComponent(assetQuery.trim())}`)
        .then((r) => setAssets(r.assets || []))
        .catch(() => setAssets([]))
    }, 220)
    return () => clearTimeout(timer)
  }, [assetQuery])

  function set(key, value) {
    setForm((f) => ({ ...f, [key]: value }))
  }

  async function saveProfile() {
    if (!newProfile || !newProfile.name.trim()) return
    setBusy(true)
    try {
      const created = await api.post('/api/v1/auth-profiles', {
        ...newProfile, actor: 'console',
      })
      setProfiles((list) => [...list, created.data])
      set('auth_profile_id', created.data.id)
      setNewProfile(null)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function submit() {
    if (!form.title.trim()) { setError(t('finding.error.title')); return }
    // A record with no subject is a paragraph: name the product, the asset or the
    // engagement it came from, or it cannot be routed to anybody.
    if (!form.project && !form.asset_id && !form.cycle_id) {
      setError(t('finding.error.subject')); return
    }
    setBusy(true)
    setError('')
    try {
      const payload = { ...form, actor: 'console' }
      Object.keys(payload).forEach((key) => {
        if (payload[key] === '') payload[key] = null
      })
      // One endpoint for both doors: `cycle_id` is optional, and naming a cycle is
      // what files the claim in that ledger.
      await api.post('/api/v1/findings/record', payload)
      onDone()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="stack">
      <PageHeader title={t('finding.title')} subtitle={t('finding.subtitle')}
        actions={<button className="mini" onClick={onCancel}>{t('finding.cancel')}</button>} />

      {error && <ErrorBanner error={error} />}

      <section className="form-section">
        <h3>{t('finding.section.what')}</h3>
        <p className="muted">{t('finding.hint.what')}</p>
        <Field label={t('finding.field.name')}>
          <input value={form.title} placeholder={t('finding.placeholder.name')}
            onChange={(e) => set('title', e.target.value)} />
        </Field>
        <div className="row">
          <Field label={t('finding.field.cwe')} hint={t('finding.hint.cwe')}>
            <select value={form.cwe} onChange={(e) => set('cwe', e.target.value)}>
              {CWES.map(([value, label]) => (
                <option key={value || 'none'} value={value}>{label}</option>
              ))}
            </select>
          </Field>
          <Field label={t('finding.field.severity')}>
            <select value={form.severity} onChange={(e) => set('severity', e.target.value)}>
              {SEVERITIES.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </Field>
        </div>
      </section>

      <section className="form-section">
        <h3>{t('finding.section.where')}</h3>
        <p className="muted">{t('finding.hint.where')}</p>
        {/* The subject of the record: which product, which release, which
            engagement. A finding without these is a paragraph, not evidence. */}
        <div className="row">
          <Field label={t('finding.field.project')} hint={t('finding.hint.project')}>
            <select value={form.project}
              onChange={(e) => {
                set('project', e.target.value)
                set('version_id', '')
              }}>
              <option value="">{t('finding.none')}</option>
              {projects.map((project) => (
                <option key={project.id} value={project.slug}>{project.name}</option>
              ))}
            </select>
          </Field>
          <Field label={t('finding.field.build')} hint={t('finding.hint.build')}>
            <select value={form.version_id} disabled={!builds.length}
              onChange={(e) => set('version_id', e.target.value)}>
              <option value="">{t('finding.none')}</option>
              {builds.map((build) => (
                <option key={build.id} value={build.id}>{build.label}</option>
              ))}
            </select>
          </Field>
          {!cycleId && (
            <Field label={t('finding.field.cycle')} hint={t('finding.hint.cycle')}>
              <select value={form.cycle_id}
                onChange={(e) => set('cycle_id', e.target.value)}>
                <option value="">{t('finding.cycle.none')}</option>
                {cycles.map((cycle) => (
                  <option key={cycle.id} value={cycle.id}>{cycle.name}</option>
                ))}
              </select>
            </Field>
          )}
        </div>
        <div className="row">
          <Field label={t('finding.field.product')}>
            <select value={form.product_component_id}
              onChange={(e) => set('product_component_id', e.target.value)}>
              <option value="">{t('finding.none')}</option>
              {jewels.map((jewel) => (
                <option key={jewel.id} value={jewel.id}>
                  {jewel.project_name ? `${jewel.project_name} › ` : ''}{jewel.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label={t('finding.field.asset')} hint={t('finding.hint.asset')}>
            <input value={assetQuery} placeholder={t('finding.placeholder.asset')}
              onChange={(e) => setAssetQuery(e.target.value)} />
            {assets.length > 0 && (
              <div className="scope-results">
                {assets.map((asset) => (
                  <button type="button" key={asset.id} className="scope-result"
                    onClick={() => {
                      set('asset_id', asset.id)
                      set('url', form.url || `https://${asset.label}`)
                      set('endpoint', form.endpoint)
                      setAssetQuery(asset.label)
                      setAssets([])
                    }}>
                    <span>{asset.label}</span>
                    <span className="muted">{asset.project || asset.type}</span>
                  </button>
                ))}
              </div>
            )}
          </Field>
        </div>
        <Field label={t('finding.field.url')} hint={t('finding.hint.url')}>
          <input value={form.url} placeholder="https://api.cliente.com"
            onChange={(e) => set('url', e.target.value)} />
        </Field>
        <div className="row">
          <Field label={t('finding.field.method')}>
            <select value={form.http_method} onChange={(e) => set('http_method', e.target.value)}>
              {METHODS.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </Field>
          <Field label={t('finding.field.endpoint')} hint={t('finding.hint.endpoint')}>
            <input value={form.endpoint} placeholder="/api/v1/invoices/1042?debug=1"
              onChange={(e) => set('endpoint', e.target.value)} />
          </Field>
        </div>
      </section>

      <section className="form-section">
        <h3>{t('finding.section.auth')}</h3>
        <p className="muted">{t('finding.hint.auth')}</p>
        <label className="toggle-row">
          <input type="checkbox" checked={form.auth_required}
            onChange={(e) => set('auth_required', e.target.checked)} />
          <span><strong>{t('finding.field.authRequired')}</strong></span>
        </label>
        <div className="row">
          <Field label={t('finding.field.authProfile')} hint={t('finding.hint.authProfile')}>
            <select value={form.auth_profile_id}
              onChange={(e) => set('auth_profile_id', e.target.value)}>
              <option value="">{t('finding.none')}</option>
              {profiles.map((profile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.name} · {profile.kind}
                </option>
              ))}
            </select>
          </Field>
          <button className="mini" onClick={() => setNewProfile({
            name: '', kind: 'cookie', headers: '', login_steps: '',
          })}>{t('finding.action.newProfile')}</button>
        </div>
        {newProfile && (
          <div className="stack form-inset">
            <div className="row">
              <Field label={t('finding.field.profileName')}>
                <input value={newProfile.name} placeholder="cliente A"
                  onChange={(e) => setNewProfile({ ...newProfile, name: e.target.value })} />
              </Field>
              <Field label={t('finding.field.profileKind')}>
                <select value={newProfile.kind}
                  onChange={(e) => setNewProfile({ ...newProfile, kind: e.target.value })}>
                  {AUTH_KINDS.map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </Field>
            </div>
            <Field label={t('finding.field.profileHeaders')}
              hint={t('finding.hint.profileHeaders')}>
              <textarea rows={2} value={newProfile.headers}
                placeholder={'Cookie: session=…\nAuthorization: Bearer …'}
                onChange={(e) => setNewProfile({ ...newProfile, headers: e.target.value })} />
            </Field>
            <Field label={t('finding.field.profileSteps')}
              hint={t('finding.hint.profileSteps')}>
              <textarea rows={2} value={newProfile.login_steps}
                placeholder="POST /login {user, pass} → cookie session"
                onChange={(e) => setNewProfile({ ...newProfile, login_steps: e.target.value })} />
            </Field>
            <div className="row">
              <button className="mini" disabled={busy} onClick={saveProfile}>
                {t('finding.action.saveProfile')}</button>
              <button className="mini" onClick={() => setNewProfile(null)}>
                {t('finding.cancel')}</button>
            </div>
          </div>
        )}
      </section>

      <section className="form-section">
        <h3>{t('finding.section.proof')}</h3>
        <p className="muted">{t('finding.hint.proof')}</p>
        <Field label={t('finding.field.request')} hint={t('finding.hint.request')}>
          <textarea rows={6} className="mono" value={form.proof_request}
            placeholder={'GET /api/v1/invoices/1042 HTTP/1.1\nHost: api.cliente.com\nCookie: session=…'}
            onChange={(e) => set('proof_request', e.target.value)} />
        </Field>
        <Field label={t('finding.field.response')} hint={t('finding.hint.response')}>
          <textarea rows={5} className="mono" value={form.proof_response}
            placeholder={'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"invoice":…}'}
            onChange={(e) => set('proof_response', e.target.value)} />
        </Field>
      </section>

      <section className="form-section">
        <h3>{t('finding.section.validation')}</h3>
        <p className="muted">{t('finding.hint.validation')}</p>
        <Field label={t('finding.field.expected')}>
          <textarea rows={2} value={form.expected_result}
            placeholder={t('finding.placeholder.expected')}
            onChange={(e) => set('expected_result', e.target.value)} />
        </Field>
        <Field label={t('finding.field.observed')}>
          <textarea rows={2} value={form.observed_result}
            placeholder={t('finding.placeholder.observed')}
            onChange={(e) => set('observed_result', e.target.value)} />
        </Field>
        <Field label={t('finding.field.output')} hint={t('finding.hint.output')}>
          <textarea rows={2} value={form.validation_output}
            placeholder={t('finding.placeholder.output')}
            onChange={(e) => set('validation_output', e.target.value)} />
        </Field>
      </section>

      <section className="form-section">
        <h3>{t('finding.section.impact')}</h3>
        <Field label={t('finding.field.impact')}>
          <textarea rows={3} value={form.impact}
            placeholder={t('finding.placeholder.impact')}
            onChange={(e) => set('impact', e.target.value)} />
        </Field>
        <Field label={t('finding.field.reproduction')} hint={t('finding.hint.reproduction')}>
          <textarea rows={4} value={form.reproduction}
            placeholder={t('finding.placeholder.reproduction')}
            onChange={(e) => set('reproduction', e.target.value)} />
        </Field>
      </section>

      <div className="row">
        <button className="primary-action" disabled={busy} onClick={submit}>
          {t('finding.action.record')}
        </button>
        <span className="muted">{t('finding.hint.claim')}</span>
      </div>
    </div>
  )
}
