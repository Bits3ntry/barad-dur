import React, { useCallback, useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Card, Loading, Stat } from './ui'
import { useI18n } from './i18n'

/* Settings → AI (§5): one provider list, one budget, one meter.
   The key is write-only: the API answers `key_set`, never the cipher, and this
   screen has nothing to reveal even if it wanted to. */

const KINDS = [
  { value: 'openai-compatible', labelKey: 'aiSettings.kind.openaiCompatible' },
  { value: 'anthropic', labelKey: 'aiSettings.kind.anthropic' },
]

const BLANK = {
  name: '', kind: 'openai-compatible', base_url: 'https://api.openai.com/v1',
  model: '', api_key: '', price_in: '', price_out: '', max_output_tokens: 1024,
  is_default: true,
}

/* Choosing a vendor fills the four fields nobody remembers, so the operator's only
   input is the key — or, for a local runtime, the model name. The list is a
   starting point; every field stays editable because vendors rename models faster
   than this screen can ship. */
export default function AiSettings() {
  const { t } = useI18n()
  const [providers, setProviders] = useState([])
  const [settings, setSettings] = useState(null)
  const [spend, setSpend] = useState(null)
  const [presets, setPresets] = useState([])
  const [preset, setPreset] = useState('')
  const [draft, setDraft] = useState(BLANK)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const [list, current, month, shapes] = await Promise.all([
        api.get('/api/v1/ai/providers'),
        api.get('/api/v1/ai/settings'),
        api.get('/api/v1/ai/spend'),
        api.get('/api/v1/ai/providers/presets'),
      ])
      setProviders(list.data || [])
      setSettings(current.data)
      setSpend(month.data)
      setPresets(shapes.data || [])
      setError('')
    } catch (caught) {
      setError(String(caught.message || caught))
    }
  }, [])

  useEffect(() => { load() }, [load])

  const chosen = presets.find((row) => row.key === preset) || null

  function applyPreset(shape) {
    setPreset(shape.key)
    setDraft({
      ...BLANK,
      name: shape.key,
      kind: shape.kind,
      base_url: shape.base_url,
      model: shape.default_model || '',
      // A vendor that ships a reasoning model declares its own output budget: a
      // 1024-token cap is spent thinking and the answer comes back empty.
      max_output_tokens: shape.max_output_tokens || BLANK.max_output_tokens,
      price_in: shape.price_in == null ? '' : String(shape.price_in),
      price_out: shape.price_out == null ? '' : String(shape.price_out),
    })
  }

  const saveProvider = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const body = { ...draft }
      if (!body.api_key) delete body.api_key
      body.price_in = body.price_in === '' ? null : Number(body.price_in)
      body.price_out = body.price_out === '' ? null : Number(body.price_out)
      body.max_output_tokens = Number(body.max_output_tokens) || 1024
      await api.post('/api/v1/ai/providers', body)
      setDraft(BLANK)
      setNotice(t('aiSettings.notice.providerSaved'))
      await load()
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  const test = async (row) => {
    setBusy(true)
    setNotice('')
    setError('')
    try {
      const result = await api.post(`/api/v1/ai/providers/${row.id}/test`, {})
      if (result.ok) setNotice(t('aiSettings.test.ok', { name: row.name, sample: (result.sample || '').slice(0, 60) }))
      else setError(t('aiSettings.test.error', { name: row.name, error: result.error }))
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  const makeDefault = async (row) => {
    await api.patch(`/api/v1/ai/providers/${row.id}`, { is_default: true })
    await load()
  }

  const saveSettings = async (event) => {
    event.preventDefault()
    setBusy(true)
    try {
      const payload = {
        monthly_token_cap: settings.monthly_token_cap === '' || settings.monthly_token_cap == null
          ? null : Number(settings.monthly_token_cap),
        monthly_cost_cap: settings.monthly_cost_cap === '' || settings.monthly_cost_cap == null
          ? null : Number(settings.monthly_cost_cap),
        max_steps: Number(settings.max_steps) || 6,
        redteam_allowed: Boolean(settings.redteam_allowed),
      }
      const body = await api.patch('/api/v1/ai/settings', payload)
      setSettings(body.data)
      setNotice(t('aiSettings.notice.limitsSaved'))
      await load()
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  if (!settings || !spend) return <Loading label={t('aiSettings.loading')} />

  return (
    <div className="settings-body stack">
      {error && <Banner kind="error">{error}</Banner>}
      {notice && <Banner kind="ok">{notice}</Banner>}

      <Card title={t('aiSettings.spend.title')}>
        <div className="ai-spend">
          <Stat
            value={`${spend.tokens ?? 0}`}
            label={t('aiSettings.spend.tokens')}
            hint={spend.token_cap
              ? t('aiSettings.spend.tokenCap', { pct: spend.token_used_pct, cap: spend.token_cap })
              : t('aiSettings.spend.noTokenCap')}
          />
          <Stat
            value={spend.price_known ? `$${(spend.cost_usd ?? 0).toFixed(4)}` : t('aiSettings.priceUnknown')}
            label={t('aiSettings.spend.cost')}
            hint={spend.cost_cap
              ? t('aiSettings.spend.costCap', { pct: spend.cost_used_pct, cap: spend.cost_cap })
              : t('aiSettings.spend.noCostCap')}
          />
          <Stat value={spend.period_start?.slice(0, 10) || '—'} label={t('aiSettings.spend.periodStart')} />
        </div>
        {/* One ledger, three spends: a lookup, a mission's field work, and the
            compaction that keeps a session cheap. Lumping them hid the half that
            touches targets behind the chat's cents. */}
        {spend.by_mode && Object.keys(spend.by_mode).length > 0 && (
          <table className="ai-spend-modes">
            <thead>
              <tr>
                <th>{t('aiSettings.spend.mode')}</th>
                <th>{t('aiSettings.spend.tokens')}</th>
                <th>{t('aiSettings.spend.steps')}</th>
                <th>{t('aiSettings.spend.cost')}</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(spend.by_mode)
                .sort((a, b) => b[1].tokens - a[1].tokens)
                .map(([mode, row]) => (
                  <tr key={mode}>
                    <td><code>{mode}</code></td>
                    <td>{row.tokens}</td>
                    <td>{row.steps}</td>
                    <td>{spend.price_known ? `$${(row.cost_usd || 0).toFixed(4)}`
                                           : t('aiSettings.priceUnknown')}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        )}
        {/* What the vendor reported about cost, verbatim. A flat plan meters an
            allowance instead of billing per token, and guessing whether `42` is a
            percentage or a count would be worse than showing the number it sent. */}
        {spend.provider_usage && Object.keys(spend.provider_usage).length > 0 && (
          <div className="ai-spend-usage">
            <span className="ai-spend-usage-label">{t('aiSettings.spend.providerUsage')}</span>
            <code>{JSON.stringify(spend.provider_usage)}</code>
          </div>
        )}
        {!spend.price_known && (
          <p className="settings-note">
            {t('aiSettings.spend.note')}
          </p>
        )}
        {spend.token_used_pct != null && spend.token_used_pct >= 80 && (
          <Banner kind="warn">
            {t('aiSettings.spend.nearCap', { pct: spend.token_used_pct })}
          </Banner>
        )}
      </Card>

      <Card title={t('aiSettings.providers.title')}>
        {providers.length === 0 && <p className="muted">{t('aiSettings.providers.empty')}</p>}
        {providers.map((row) => (
          <div className="ai-provider" key={row.id}>
            <div className="ai-provider-main">
              <strong>{row.name}</strong>
              <small>
                {row.kind} · {row.model || t('aiSettings.providers.noModel')} · {row.base_url || t('aiSettings.providers.noBaseUrl')}
              </small>
            </div>
            <div className="ai-provider-flags">
              <span className={`pill${row.key_set ? '' : ' pill-warn'}`}>
                {row.key_set ? t('aiSettings.providers.keySet') : t('aiSettings.providers.noKey')}
              </span>
              <span className="pill">
                {row.price_known
                  ? t('aiSettings.providers.price', { in: row.price_in, out: row.price_out })
                  : t('aiSettings.priceUnknown')}
              </span>
              {row.is_default && <span className="pill">{t('aiSettings.providers.default')}</span>}
            </div>
            <div className="ai-provider-actions">
              <button className="mini" disabled={busy} onClick={() => test(row)}>{t('aiSettings.providers.test')}</button>
              {!row.is_default && (
                <button className="mini" disabled={busy} onClick={() => makeDefault(row)}>
                  {t('aiSettings.providers.makeDefault')}
                </button>
              )}
            </div>
          </div>
        ))}

        <div className="ai-presets">
          {presets.map((shape) => (
            <button
              key={shape.key}
              type="button"
              className={`ai-preset${preset === shape.key ? ' active' : ''}`}
              onClick={() => applyPreset(shape)}
            >
              {shape.label}
              {shape.needs_key ? '' : t('aiSettings.presets.noKey')}
            </button>
          ))}
        </div>
        {chosen && (
          <p className="settings-note">
            {chosen.note}
            {chosen.docs && (
              <> <a href={chosen.docs} target="_blank" rel="noreferrer">{t('aiSettings.presets.getKey')}</a></>
            )}
          </p>
        )}

        <form className="settings-form ai-provider-form" onSubmit={saveProvider}>
          <label>{t('aiSettings.form.name')}<input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder={t('aiSettings.form.namePlaceholder')} /></label>
          <label>{t('aiSettings.form.kind')}
            <select value={draft.kind} onChange={(event) => setDraft({ ...draft, kind: event.target.value })}>
              {KINDS.map((kind) => <option key={kind.value} value={kind.value}>{t(kind.labelKey)}</option>)}
            </select>
          </label>
          <label className="settings-span">{t('aiSettings.form.baseUrl')}<input value={draft.base_url} onChange={(event) => setDraft({ ...draft, base_url: event.target.value })} placeholder={t('aiSettings.form.baseUrlPlaceholder')} /></label>
          <label>{t('aiSettings.form.model')}
            <input list="ai-models" value={draft.model}
              onChange={(event) => setDraft({ ...draft, model: event.target.value })}
              placeholder={chosen && chosen.models.length ? chosen.models[0] : t('aiSettings.form.modelPlaceholder')} />
            <datalist id="ai-models">
              {((chosen && chosen.models) || []).map((model) => (
                <option key={model} value={model} />
              ))}
            </datalist>
          </label>
          <label>{t('aiSettings.form.apiKey')}
            <input type="password" value={draft.api_key} autoComplete="off"
              disabled={Boolean(chosen && chosen.needs_key === false)}
              onChange={(event) => setDraft({ ...draft, api_key: event.target.value })}
              placeholder={chosen && chosen.needs_key === false
                ? t('aiSettings.form.apiKeyNotNeeded')
                : t('aiSettings.form.apiKeyPlaceholder')} />
          </label>
          <label>{t('aiSettings.form.priceIn')}<input value={draft.price_in} onChange={(event) => setDraft({ ...draft, price_in: event.target.value })} placeholder={t('aiSettings.form.pricePlaceholder')} /></label>
          <label>{t('aiSettings.form.priceOut')}<input value={draft.price_out} onChange={(event) => setDraft({ ...draft, price_out: event.target.value })} placeholder={t('aiSettings.form.pricePlaceholder')} /></label>
          <label>{t('aiSettings.form.maxOutput')}<input value={draft.max_output_tokens} onChange={(event) => setDraft({ ...draft, max_output_tokens: event.target.value })} /></label>
          <div className="settings-actions settings-span">
            <button className="btn-primary" disabled={busy || !draft.name}>{t('aiSettings.form.add')}</button>
          </div>
        </form>
      </Card>

      <Card title={t('aiSettings.limits.title')}>
        <form className="settings-form" onSubmit={saveSettings}>
          <label>{t('aiSettings.limits.tokenCap')}
            <input value={settings.monthly_token_cap ?? ''} onChange={(event) => setSettings({ ...settings, monthly_token_cap: event.target.value })} placeholder={t('aiSettings.limits.emptyCap')} />
          </label>
          <label>{t('aiSettings.limits.costCap')}
            <input value={settings.monthly_cost_cap ?? ''} onChange={(event) => setSettings({ ...settings, monthly_cost_cap: event.target.value })} placeholder={t('aiSettings.limits.emptyCap')} />
          </label>
          <label>{t('aiSettings.limits.maxSteps')}
            <input value={settings.max_steps} onChange={(event) => setSettings({ ...settings, max_steps: event.target.value })} />
          </label>
          <div className="settings-span">
            <label className="check-row">
              <input type="checkbox" checked={Boolean(settings.redteam_allowed)}
                onChange={(event) => setSettings({ ...settings, redteam_allowed: event.target.checked })} />
              {t('aiSettings.limits.redteam')}
            </label>
          </div>
          <div className="settings-actions settings-span">
            <button className="btn-primary" disabled={busy}>{t('aiSettings.limits.save')}</button>
          </div>
        </form>
        <p className="settings-note">
          {t('aiSettings.limits.note.before')}{' '}
          <em>{t('aiSettings.limits.note.emphasis')}</em>{' '}
          {t('aiSettings.limits.note.mid')}{' '}
          <code>{t('aiSettings.limits.note.code')}</code>{' '}
          {t('aiSettings.limits.note.after')}
        </p>
      </Card>
    </div>
  )
}
