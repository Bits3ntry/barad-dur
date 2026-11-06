import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Card } from './ui'

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
  { key: 'osv', label: 'OSV.dev', hint: 'Re-asks the advisory database about every current build — this is what finds a CVE published after the scan.' },
  { key: 'kev', label: 'CISA KEV', hint: 'Known exploited vulnerabilities. A fact, so it outranks any score.' },
  { key: 'epss', label: 'EPSS', hint: 'Exploitation probability, refreshed for the advisories this workspace already holds.' },
  { key: 'cpe', label: 'NVD — runtime CVEs', hint: 'Node, Python, Go… matched by version range from NVD. OSV has no ecosystem for an interpreter, so this is the only source that answers for it.' },
]

function when(iso) {
  if (!iso) return 'never'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'never'
  const hours = Math.round((Date.now() - date.getTime()) / 3600000)
  if (hours < 1) return 'less than an hour ago'
  if (hours < 48) return `${hours}h ago`
  return `${Math.round(hours / 24)}d ago`
}

export default function AdvisoriesSettings() {
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
      setNotice('Saved. The scheduler will use this on its next tick.')
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
    return <div className="settings-body"><Card title="Advisory clock"><p className="settings-note">{error || 'Loading…'}</p></Card></div>
  }

  const last = config.last_tick || {}
  const lastAt = config.last_tick_at

  return (
    <div className="settings-body stack">
      <Card title="Advisory clock">
        <p className="settings-intro">
          A bill of materials is a photograph: it says what the scanner knew the day it ran.
          This clock keeps asking after the scan, so a CVE published tomorrow still lands on the
          build you shipped today. It only adds — no import is rewritten and nothing is deleted.
        </p>
        {error && <Banner kind="error">{error}</Banner>}
        {notice && <Banner kind="ok">{notice}</Banner>}
        {config.autorun === false && (
          <Banner kind="info">
            This deployment runs the clock externally: nothing will happen on its own until the
            scheduler calls <code>POST /api/v1/advisories/tick</code>. “Run now” still works.
          </Banner>
        )}
        <form className="settings-form" onSubmit={save}>
          <label className="settings-span check">
            <input type="checkbox" checked={form.enabled}
              onChange={() => setForm({ ...form, enabled: !form.enabled })} />
            Run the clock for this workspace
          </label>
          {SOURCES.map((source) => (
            <label className="settings-span check" key={source.key}>
              <input type="checkbox" checked={form[source.key]}
                onChange={() => toggleSource(source.key)} />
              <span><strong>{source.label}</strong><small>{source.hint}</small></span>
            </label>
          ))}
          <label>Every
            <input type="number" min="1" max="168" value={form.interval_hours}
              onChange={(e) => setForm({ ...form, interval_hours: e.target.value })} />
            <small>hours. The platform checks on its own (every {Math.round((config.poll_seconds || 300) / 60) || 1} min) and has this job decide whether it is due.</small>
          </label>
          <label>Builds per sweep
            <input type="number" min="1" max="500" value={form.max_versions}
              onChange={(e) => setForm({ ...form, max_versions: e.target.value })} />
            <small>The newest build of each component. Old builds keep their original evidence.</small>
          </label>
          <div className="settings-span">
            <p className="settings-note">Ecosystems to re-check — all of them when none is chosen.</p>
            <div className="settings-link-list">
              {(config.ecosystems_available || []).map((key) => (
                <button type="button" key={key} className={`mini${form.ecosystems.includes(key) ? ' primary' : ''}`}
                  onClick={() => toggleEcosystem(key)}>{key}</button>
              ))}
            </div>
          </div>
          <div className="settings-actions settings-span">
            <button className="btn-primary" disabled={busy === 'save'}>Save</button>
            <button type="button" className="btn-ghost" onClick={runNow} disabled={busy === 'run'}>
              {busy === 'run' ? 'Running…' : 'Run now'}
            </button>
          </div>
        </form>
      </Card>

      <Card title="Last run">
        {lastAt ? (
          <div className="stack">
            <p className="settings-note">
              {when(lastAt)} · {last.status || 'ok'} · {last.versions_analyzed ?? 0} builds re-checked ·{' '}
              {last.findings_created ?? 0} new findings · {last.findings_refreshed ?? 0} refreshed ·{' '}
              KEV {last.kev_rows ?? 0} · EPSS {last.epss_rows ?? 0}
            </p>
            {config.interval_hours && (
              <p className="settings-note">
                Next run in {Math.max(0, config.interval_hours - Math.round((Date.now() - new Date(lastAt).getTime()) / 3600000))}h
                unless someone runs it now.
              </p>
            )}
          </div>
        ) : (
          <p className="settings-note">
            Never ran. Until it does, the console only knows what each scanner reported on the day it ran —
            a CVE published afterwards will not appear.
          </p>
        )}
        {result && (
          <div className="stack">
            <p className="settings-note">
              This run: {result.status} · {result.versions_analyzed} builds · {result.findings_created} new ·{' '}
              {result.findings_refreshed} refreshed · {result.components_queried} packages asked
              {result.components_skipped_unmapped ? ` · ${result.components_skipped_unmapped} without a resolvable ecosystem` : ''}
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
