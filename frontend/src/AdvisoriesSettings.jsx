import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Card } from './ui'
import { useI18n } from './i18n'

/* The advisory clock.

   The SBOM screen reads one artefact: what the scanner knew the day it ran.
   This panel owns the second clock — the catalogue that keeps moving after the
   scan. Two rules the copy has to keep honest:

   1. Nothing here rewrites an import. The job adds findings and refreshes the
      ones it re-confirms; a finding whose advisory stopped matching stays
      where it is.
   2. "Never ran" and "ran, found nothing" are different states, so the last-run
      record is shown with its counters instead of a reassuring dash. */

const SOURCES = [
  { key: 'osv', labelKey: 'advisories.sources.osv.label', hintKey: 'advisories.sources.osv.hint' },
  { key: 'kev', labelKey: 'advisories.sources.kev.label', hintKey: 'advisories.sources.kev.hint' },
  { key: 'epss', labelKey: 'advisories.sources.epss.label', hintKey: 'advisories.sources.epss.hint' },
  { key: 'cpe', labelKey: 'advisories.sources.cpe.label', hintKey: 'advisories.sources.cpe.hint' },
]

function when(iso, t) {
  if (!iso) return t('advisories.when.never')
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return t('advisories.when.never')
  const hours = Math.round((Date.now() - date.getTime()) / 3600000)
  if (hours < 1) return t('advisories.when.hour')
  if (hours < 48) return t('advisories.when.hours', { hours })
  return t('advisories.when.days', { days: Math.round(hours / 24) })
}

export default function AdvisoriesSettings() {
  const { t } = useI18n()
  const [config, setConfig] = useState(null)
  const [form, setForm] = useState({ enabled: true, kev: true, epss: true, osv: true,
    cpe: true, interval_hours: 24, max_versions: 25, ecosystems: [] })
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [result, setResult] = useState(null)

  function apply(data) {
    setConfig(data)
    setForm({
      enabled: Boolean(data.enabled), kev: Boolean(data.kev), epss: Boolean(data.epss),
      osv: Boolean(data.osv), cpe: data.cpe !== false, interval_hours: data.interval_hours || 24,
      max_versions: data.max_versions || 25, ecosystems: data.ecosystems || [],
    })
  }

  function load() {
    return api.get('/api/v1/advisories/settings')
      .then((r) => apply(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  useEffect(() => { load() }, [])

  async function save(event) {
    event.preventDefault()
    setError(''); setNotice(''); setBusy('save')
    try {
      const r = await api.put('/api/v1/advisories/settings', {
        enabled: form.enabled, kev: form.kev, epss: form.epss, osv: form.osv,
        cpe: form.cpe,
        interval_hours: Number(form.interval_hours) || 24,
        max_versions: Number(form.max_versions) || 25,
        ecosystems: form.ecosystems,
        actor: 'console',
      })
      apply(r.data)
      setNotice(t('advisories.savedNotice'))
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  async function runNow() {
    setError(''); setNotice(''); setBusy('run'); setResult(null)
    try {
      const r = await api.post('/api/v1/advisories/tick', { actor: 'console', force: true })
      setResult(r.data)
      await load()
    } catch (e) {
      setError(String(e.message || e))
    } finally { setBusy('') }
  }

  function toggleSource(key) {
    setForm((current) => ({ ...current, [key]: !current[key] }))
  }

  function toggleEcosystem(key) {
    setForm((current) => ({
      ...current,
      ecosystems: current.ecosystems.includes(key)
        ? current.ecosystems.filter((item) => item !== key)
        : [...current.ecosystems, key],
    }))
  }

  if (!config) {
    return <div className="settings-body"><Card title={t('advisories.title')}><p className="settings-note">{error || t('advisories.loading')}</p></Card></div>
  }

  const last = config.last_tick || {}
  const lastAt = config.last_tick_at

  return (
    <div className="settings-body stack">
      <Card title={t('advisories.title')}>
        <p className="settings-intro">{t('advisories.intro')}</p>
        {error && <Banner kind="error">{error}</Banner>}
        {notice && <Banner kind="ok">{notice}</Banner>}
        {config.autorun === false && (
          <Banner kind="info">
            {t('advisories.autorun.before')} <code>POST /api/v1/advisories/tick</code>{t('advisories.autorun.after')}
          </Banner>
        )}
        <form className="settings-form" onSubmit={save}>
          <label className="settings-span check">
            <input type="checkbox" checked={form.enabled}
              onChange={() => setForm({ ...form, enabled: !form.enabled })} />
            {t('advisories.runEnabled')}
          </label>
          {SOURCES.map((source) => (
            <label className="settings-span check" key={source.key}>
              <input type="checkbox" checked={form[source.key]}
                onChange={() => toggleSource(source.key)} />
              <span><strong>{t(source.labelKey)}</strong><small>{t(source.hintKey)}</small></span>
            </label>
          ))}
          <label>{t('advisories.interval.label')}
            <input type="number" min="1" max="168" value={form.interval_hours}
              onChange={(e) => setForm({ ...form, interval_hours: e.target.value })} />
            <small>{t('advisories.interval.hint', { minutes: Math.round((config.poll_seconds || 300) / 60) || 1 })}</small>
          </label>
          <label>{t('advisories.maxVersions.label')}
            <input type="number" min="1" max="500" value={form.max_versions}
              onChange={(e) => setForm({ ...form, max_versions: e.target.value })} />
            <small>{t('advisories.maxVersions.hint')}</small>
          </label>
          <div className="settings-span">
            <p className="settings-note">{t('advisories.ecosystems.hint')}</p>
            <div className="settings-link-list">
              {(config.ecosystems_available || []).map((key) => (
                <button type="button" key={key} className={`mini${form.ecosystems.includes(key) ? ' primary' : ''}`}
                  onClick={() => toggleEcosystem(key)}>{key}</button>
              ))}
            </div>
          </div>
          <div className="settings-actions settings-span">
            <button className="btn-primary" disabled={busy === 'save'}>{t('common.save')}</button>
            <button type="button" className="btn-ghost" onClick={runNow} disabled={busy === 'run'}>
              {busy === 'run' ? t('advisories.running') : t('advisories.runNow')}
            </button>
          </div>
        </form>
      </Card>

      <Card title={t('advisories.last.title')}>
        {lastAt ? (
          <div className="stack">
            <p className="settings-note">
              {t('advisories.last.summary', {
                when: when(lastAt, t), status: last.status || 'ok',
                builds: last.versions_analyzed ?? 0, created: last.findings_created ?? 0,
                refreshed: last.findings_refreshed ?? 0, kev: last.kev_rows ?? 0, epss: last.epss_rows ?? 0,
              })}
            </p>
            {config.interval_hours && (
              <p className="settings-note">
                {t('advisories.last.next', { hours: Math.max(0, config.interval_hours - Math.round((Date.now() - new Date(lastAt).getTime()) / 3600000)) })}
              </p>
            )}
          </div>
        ) : (
          <p className="settings-note">
            {t('advisories.last.never')}
          </p>
        )}
        {result && (
          <div className="stack">
            <p className="settings-note">
              {t('advisories.result.summary', { status: result.status, builds: result.versions_analyzed,
                created: result.findings_created, refreshed: result.findings_refreshed,
                packages: result.components_queried })}
              {result.components_skipped_unmapped ? t('advisories.result.unmapped', { n: result.components_skipped_unmapped }) : ''}
            </p>
            {(result.errors || []).length > 0 && (
              <Banner kind="error">
                {result.errors.map((item) => `${item.source}${item.version ? ` (${item.version})` : ''}: ${item.error}`).join(' · ')}
              </Banner>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
