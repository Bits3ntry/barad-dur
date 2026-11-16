import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { EmptyState, ErrorBanner } from './ui'
import { useI18n } from './i18n'

/* REPEAT — the finding's request, sent again with the login it needs.

   Burp's Repeater assumes a human moves the token between tabs. Here the chain is
   explicit: a step may extract a value (`token` from `authentication.token`) and a
   later step references it as `{{token}}` in its url, headers or body. The run is
   recorded, so the pair of panes that proved the bug survives the tab.

   What is shown is what was *written*: the injected value never reaches the record,
   it stays as `{{token}}` and the resolved value is reported by length only. The
   response keeps what came back — that is the proof. */

const BLANK_STEP = () => ({
  label: '', method: 'GET', url: '', headers: '{}', body: '', extract: '',
})

function parseProof(text) {
  // "POST /rest/user/login HTTP/1.1\nHeader: value\n\n{body}"
  // The HTTP version is optional: the proof we compose from a field agent's own tool
  // call is `POST /path` + headers + body, and requiring `HTTP/1.1` there dropped the
  // body — a POST replayed without its payload answers 401 and looks like a bad finding.
  if (!text || !/^[A-Z]+ \S+( HTTP\/1\.[01])?/.test(text.trim())) return null
  const [head, ...rest] = text.trim().split(/\r?\n\r?\n/)
  const lines = head.split(/\r?\n/)
  const [, path] = lines[0].split(' ')
  const method = lines[0].split(' ')[0]
  const headers = {}
  lines.slice(1).forEach((line) => {
    const at = line.indexOf(':')
    if (at > 0) headers[line.slice(0, at).trim()] = line.slice(at + 1).trim()
  })
  return { method, path, headers, body: rest.join('\n\n') }
}

function baseUrl(detail) {
  // The origin, not the URL: an agent finding's `url` already ends at the endpoint,
  // and appending `endpoint` to it produced `…/rest/user/login/rest/user/login`.
  const raw = (detail.url || '').split('#')[0].split('?')[0]
  const origin = raw.match(/^https?:\/\/[^/]+/i)
  if (origin) return origin[0]
  return raw.replace(/\/+$/, '')
}

function seed(detail) {
  const host = baseUrl(detail)
  const proof = parseProof(detail.proof_request)
  const path = proof?.path || detail.endpoint || ''
  const url = /^https?:\/\//.test(path)
    ? path
    : `${host}${path.startsWith('/') ? '' : '/'}${path}`
  const headers = proof?.headers
    || (detail.http_method && detail.http_method !== 'GET'
      ? { 'Content-Type': 'application/json' } : {})
  return [{
    label: 'the request the finding claims',
    method: (proof?.method || detail.http_method || 'GET').toUpperCase(),
    url,
    headers: JSON.stringify(headers, null, 1),
    body: proof?.body || '',
    extract: '',
  }]
}

function headersToObject(text) {
  if (!text || !text.trim()) return {}
  try {
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch (e) {
    // "Clave: valor" per line is how people actually paste headers.
    const out = {}
    text.split(/\r?\n/).forEach((line) => {
      const at = line.indexOf(':')
      if (at > 0) out[line.slice(0, at).trim()] = line.slice(at + 1).trim()
    })
    return out
  }
}

function extractToRules(text) {
  return (text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      // "token = json:authentication.token" / "sid = header:set-cookie"
      const [left, right] = line.split('=').map((part) => (part || '').trim())
      const [kind, ...rest] = (right || '').split(':')
      return { var: left, from: (kind || 'json').toLowerCase(), path: rest.join(':').trim() }
    })
}

export default function FindingRepeat({ detail }) {
  const { t } = useI18n()
  const [steps, setSteps] = useState(() => seed(detail))
  const [run, setRun] = useState(null)
  const [history, setHistory] = useState([])
  const [open, setOpen] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const findingId = detail.id

  useEffect(() => {
    let alive = true
    api.get(`/api/v1/findings/${findingId}/repeat`)
      .then((r) => { if (alive) setHistory(r.data || []) })
      .catch(() => {})
    return () => { alive = false }
  }, [findingId])

  const payloadSteps = useMemo(() => steps.map((step, index) => ({
    label: step.label || `step ${index + 1}`,
    method: step.method,
    url: step.url,
    headers: headersToObject(step.headers),
    body: step.body || null,
    extract: extractToRules(step.extract),
  })), [steps])

  function update(index, patch) {
    setSteps((rows) => rows.map((row, at) => (at === index ? { ...row, ...patch } : row)))
  }

  function addStep() {
    setSteps((rows) => [...rows, { ...BLANK_STEP(), label: `step ${rows.length + 1}` }])
  }

  function removeStep(index) {
    setSteps((rows) => rows.filter((_row, at) => at !== index))
  }

  async function execute() {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await api.post(`/api/v1/findings/${findingId}/repeat`, {
        steps: payloadSteps, actor: 'console',
      })
      setRun(result.data)
      setNotice(t(`findingPage.repeat.result.${result.data.result}`, { n: result.data.steps.length }))
      setHistory((rows) => [result.data, ...rows].slice(0, 10))
    } catch (e) {
      setError(String(e.message || e))
    }
    setBusy(false)
  }

  function renderResult(row) {
    const bad = row.error || (!row.authorized) || (row.status && row.status >= 400)
    return (
      <div className="rp-step" key={`${row.index}-${row.label}`}>
        <div className="rp-step-head">
          <span className={`pill ${row.authorized === false ? 'warn'
            : bad ? 'bad' : 'good'}`}>
            {row.method} {row.status == null ? '—' : row.status}
          </span>
          <strong>{row.label}</strong>
          <span className="row-end muted" style={{ fontSize: 11.5 }}>
            {row.latency_ms == null ? '' : `${row.latency_ms} ms`}
          </span>
        </div>
        {row.error && (
          <p className="muted" style={{ margin: '2px 0 6px', overflowWrap: 'anywhere' }}>
            {row.error}
          </p>
        )}
        <div className="rp-panes">
          <div>
            <h5>{t('findingPage.repeat.request')}</h5>
            <pre className="proof">{`${row.method} ${row.url}
${Object.entries(row.request_headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')}${row.request_body ? `\n\n${row.request_body}` : ''}`}</pre>
          </div>
          <div>
            <h5>{t('findingPage.repeat.response')}</h5>
            <pre className="proof">{`HTTP ${row.status == null ? '—' : row.status}
${Object.entries(row.response_headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')}${row.response_body ? `\n\n${row.response_body}` : ''}`}</pre>
          </div>
        </div>
        {Object.keys(row.extracted || {}).length > 0 && (
          <p className="muted" style={{ fontSize: 11.5, margin: '4px 0 0' }}>
            {t('findingPage.repeat.extracted')}:{' '}
            {Object.entries(row.extracted).map(([name, info]) => (
              <span className="pill good" key={name} style={{ marginRight: 6 }}>
                {name} · {info.chars} chars
              </span>
            ))}
          </p>
        )}
      </div>
    )
  }

  return (
    <div className="stack">
      <div className="toolbar">
        <span className="muted" style={{ fontSize: 12.5 }}>
          {t('findingPage.repeat.lead')}
        </span>
        <span className="row-end" />
        <button className="mini" onClick={addStep}>+ {t('findingPage.repeat.addStep')}</button>
        <button disabled={busy} onClick={execute}>
          {busy ? t('findingPage.repeat.running') : t('findingPage.repeat.run')}
        </button>
      </div>

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {steps.map((step, index) => (
        <div className="rp-editor" key={index}>
          <div className="row" style={{ gap: 8 }}>
            <select value={step.method}
              onChange={(e) => update(index, { method: e.target.value })}>
              {['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map((method) => (
                <option key={method} value={method}>{method}</option>
              ))}
            </select>
            <input style={{ flex: 1, minWidth: 240 }} value={step.url}
              placeholder="https://target/path" spellCheck={false}
              onChange={(e) => update(index, { url: e.target.value })} />
            <input style={{ maxWidth: 180 }} value={step.label}
              placeholder={t('findingPage.repeat.stepLabel')}
              onChange={(e) => update(index, { label: e.target.value })} />
            {steps.length > 1 && (
              <button className="mini" onClick={() => removeStep(index)}>✕</button>
            )}
          </div>
          <div className="rp-panes">
            <div>
              <label className="field-label">{t('findingPage.repeat.headers')}</label>
              <textarea rows={4} className="mono" value={step.headers} spellCheck={false}
                placeholder={'{"Authorization": "Bearer {{token}}"}'}
                onChange={(e) => update(index, { headers: e.target.value })} />
              <label className="field-label">{t('findingPage.repeat.body')}</label>
              <textarea rows={4} className="mono" value={step.body} spellCheck={false}
                onChange={(e) => update(index, { body: e.target.value })} />
            </div>
            <div>
              <label className="field-label">{t('findingPage.repeat.extract')}</label>
              <textarea rows={4} className="mono" value={step.extract} spellCheck={false}
                placeholder={'token = json:authentication.token\nsid = header:set-cookie'}
                onChange={(e) => update(index, { extract: e.target.value })} />
              <p className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>
                {t('findingPage.repeat.extractHint')}
              </p>
            </div>
          </div>
        </div>
      ))}

      {run && (
        <div className="stack">
          <h4 className="ledger-head">{t('findingPage.repeat.lastRun')}</h4>
          {run.steps.map(renderResult)}
        </div>
      )}

      <div className="stack">
        <h4 className="ledger-head">
          {t('findingPage.repeat.history', { n: history.length })}
        </h4>
        {!history.length ? (
          <EmptyState title={t('findingPage.repeat.empty.title')}
            hint={t('findingPage.repeat.empty.hint')} />
        ) : history.map((item) => (
          <div key={item.id}>
            <button className="link-button" onClick={() => setOpen(open === item.id ? '' : item.id)}>
              <span className={`pill ${item.result === 'ok' ? 'good'
                : item.result === 'denied' ? 'warn' : 'bad'}`}>{item.result}</span>{' '}
              {new Date(item.created_at).toLocaleString()} · {item.steps.length}{' '}
              {t('findingPage.repeat.steps')}
            </button>
            {open === item.id && (
              <div className="stack" style={{ marginTop: 8 }}>
                {item.error && <p className="muted">{item.error}</p>}
                {item.steps.map(renderResult)}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
