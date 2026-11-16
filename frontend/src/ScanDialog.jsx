import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { Dialog, Select } from './ui'

/* Launching a scan from the console asks three questions and only three: which
   asset, which profile, and what this run is for. The profile list is the
   catalog's, filtered to the ones this plane can actually run — a red-team
   profile shows up here because it runs in the cloud, and a `not accepted` tool
   shows up as a reason, never as a silent absence. */

export default function ScanDialog({ open, onClose, onStarted,
                                     initialTarget = '', targetKind = 'domain' }) {
  const { t } = useI18n()
  const [assets, setAssets] = useState([])
  const [catalog, setCatalog] = useState(null)
  const [asset, setAsset] = useState('')
  const [profile, setProfile] = useState('')
  const [engagement, setEngagement] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setError('')
    api.get('/api/v1/assets')
      .then((body) => {
        const rows = (body.data || body.assets || []).filter((row) => row.type === targetKind)
        if (initialTarget && !rows.some((row) => row.value === initialTarget)) {
          rows.unshift({ value: initialTarget, type: targetKind })
        }
        setAssets(rows)
        if (initialTarget) setAsset(initialTarget)
        else if (rows.length === 1) setAsset(rows[0].value)
      })
      .catch((err) => setError(err.message || String(err)))
    api.get(`/api/v1/surface/catalog?target_type=${targetKind}&plane=cloud`)
      .then(setCatalog)
      .catch((err) => setError(err.message || String(err)))
  }, [open, initialTarget, targetKind])

  const runnable = useMemo(
    () => (catalog?.profiles || []).filter((row) => row.runnable_here),
    [catalog])
  const blocked = useMemo(
    () => (catalog?.profiles || []).filter((row) => !row.runnable_here),
    [catalog])
  const chosen = runnable.find((row) => row.name === profile)

  async function start() {
    if (!asset || !profile) {
      setError(t('scanDialog.missingSelection'))
      return
    }
    setBusy(true)
    setError('')
    try {
      const started = await api.post('/api/v1/surface/runs', {
        profile,
        targets: [{ type: targetKind, value: asset }],
        plane: 'cloud',
        engagement: engagement || undefined,
      })
      onStarted(started.run_id, started.verdict)
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} title={t('scanDialog.title')} onClose={onClose}
            onConfirm={start}
            confirmLabel={busy ? t('scanDialog.queueing') : t('scanDialog.queue')}>
      <div className="scan-dialog">
        <Select label={t('scanDialog.asset')} value={asset} onChange={setAsset}
                options={assets.map((row) => ({ value: row.value, label: row.value }))}
                placeholder={assets.length
                  ? t('scanDialog.pickDomain') : t('scanDialog.noDomains')} />
        <Select label={t('scanDialog.profile')} value={profile} onChange={setProfile}
                options={runnable.map((row) => ({
                  value: row.name,
                  label: `${row.label} · ${row.level || 'code'}`,
                }))}
                placeholder={runnable.length
                  ? t('scanDialog.pickProfile') : t('scanDialog.nothingRunnable')} />
        <label className="field">
          <span className="field-label">{t('scanDialog.forLabel')}</span>
          <input value={engagement} onChange={(event) => setEngagement(event.target.value)}
                 placeholder={t('scanDialog.forPlaceholder')} />
        </label>

        {chosen && (
          <div className="scan-summary">
            <p><strong>{chosen.label}</strong> — {chosen.question}</p>
            <p className="hint">
              {chosen.stages.map((stage) => `${stage.id}: ${(stage.tools || []).join(', ')}`).join('  ·  ')}
            </p>
            <p className="hint">
              {t('scanDialog.summary', { n: chosen.tools.length })}
            </p>
          </div>
        )}
        {!runnable.length && catalog && (
          <p className="hint">
            {t('scanDialog.emptyCatalog')}
          </p>
        )}
        {blocked.length > 0 && (
          <p className="hint">
            {t('scanDialog.blocked', { names: blocked.map((row) => row.name).join(', ') })}
          </p>
        )}
        {error && <p className="scan-error">{error}</p>}
      </div>
    </Dialog>
  )
}
