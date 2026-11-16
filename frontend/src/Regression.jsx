import React, { useEffect, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { PageHeader } from './ui'

export default function Regression() {
  const { t, tOr } = useI18n()
  const [tests, setTests] = useState([])
  const [runs, setRuns] = useState({})
  const [error, setError] = useState('')
  const [reintroduced, setReintroduced] = useState(false)
  const [reintroducedMsg, setReintroducedMsg] = useState('')
  const [form, setForm] = useState({
    name: '', url: '', method: 'GET', suite: 'default',
    expectStatus: 403, bodyMustNotContain: '',
  })

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/regression/tests')
      .then((r) => setTests(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  async function createTest() {
    const assertions = [{ type: 'status_equals', value: Number(form.expectStatus) }]
    if (form.bodyMustNotContain) {
      assertions.push({ type: 'body_not_contains', value: form.bodyMustNotContain })
    }
    try {
      await api.post('/api/v1/regression/tests', {
        name: form.name, url: form.url, method: form.method, suite: form.suite,
        assertions, actor: 'console',
      })
      setForm((f) => ({ ...f, name: '', url: '', bodyMustNotContain: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function run(row) {
    try {
      const result = await api.post(`/api/v1/regression/tests/${row.id}/run`,
        { actor: 'console', principal: 'console', environment: 'lab' })
      await history(row)
      if (result.reintroduced) {
        setReintroduced(true)
        setReintroducedMsg(t('regression.reintroducedMsg'))
      } else {
        setReintroduced(false)
        setReintroducedMsg('')
      }
    } catch (e) { setError(String(e.message || e)) }
  }

  async function history(row) {
    try {
      const r = await api.get(`/api/v1/regression/tests/${row.id}/runs`)
      setRuns((s) => ({ ...s, [row.id]: r.data }))
    } catch (e) { setError(String(e.message || e)) }
  }

  return (
    <div className="stack">
      <PageHeader title={t('regression.title')} subtitle={t('regression.lead')} />
      <div className="toolbar">
        <span className="count">{t('regression.checkCount', { n: tests.length })}</span>
        <button onClick={load}>{t('common.refresh')}</button>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      {/* A regression suite answers one question — did the fix survive — so the
          line below it is that answer, not a tally of checks. The vocabulary is
          the runner's (`passed` / `failed` / `error`), not the shorter one this
          screen assumed: comparing against `pass` counted every green check as a
          failure and printed "fallan: 3" beside three rows reading "passed". */}
      {tests.length > 0 && (
        <p className={`run-verdict ${tests.some((row) => row.last_run?.reintroduced) ? 'bad'
          : tests.some((row) => row.last_run && row.last_run.result !== 'passed') ? 'warn' : 'ok'}`}>
          {t('regression.verdict', {
            passing: tests.filter((row) => row.last_run?.result === 'passed').length,
            failing: tests.filter((row) => row.last_run?.result === 'failed').length,
            back: tests.filter((row) => row.last_run?.reintroduced).length,
            never: tests.filter((row) => !row.last_run).length,
          })}
          {tests.some((row) => row.last_run?.result === 'error')
            ? ` · ${t('regression.verdictErrors',
              { n: tests.filter((row) => row.last_run?.result === 'error').length })}`
            : ''}
        </p>
      )}
      <table>
        <thead><tr>
          <th>{t('regression.column.check')}</th>
          <th>{t('regression.column.suite')}</th>
          <th>{t('regression.column.method')}</th>
          <th>{t('regression.column.target')}</th>
          <th>{t('regression.column.lastRun')}</th>
          <th />
        </tr></thead>
        <tbody>
          {tests.map((row) => (
            <React.Fragment key={row.id}>
              <tr>
                <td className="title">{row.name}</td>
                <td><span className="pill">{row.suite}</span></td>
                <td>{row.method}</td>
                <td className="muted">{row.url}</td>
                <td>
                  {row.last_run
                    ? <span className={`status st-${row.last_run.result}`}>
                        {tOr(`regression.result.${row.last_run.result}`, row.last_run.result)}
                        {row.last_run.reintroduced ? t('regression.reintroducedTag') : ''}
                      </span>
                    : <span className="muted">{t('common.never')}</span>}
                </td>
                <td>
                  <button className="mini" onClick={() => run(row)}>{t('regression.run')}</button>{' '}
                  <button className="mini" onClick={() => history(row)}>{t('regression.history')}</button>
                </td>
              </tr>
              {runs[row.id] && (
                <tr className="detail-row"><td colSpan={6}>
                  <div className="detail">
                    <dl>
                      <dt>{t('regression.runsCount', { n: runs[row.id].length })}</dt>
                      <dd>
                        {runs[row.id].map((r) => (
                          <div key={r.id} className="occ-row">
                            {new Date(r.ran_at).toLocaleString()} — {' '}
                            <span className={`status st-${r.result}`}>
                              {tOr(`regression.result.${r.result}`, r.result)}
                            </span>{' '}
                            HTTP {r.http_status ?? '—'} · {r.latency_ms}ms
                            {r.reintroduced && (
                              <strong className="error"> {t('regression.reintroduced')}</strong>
                            )}
                            {r.error && <span className="muted"> · {r.error}</span>}
                          </div>
                        ))}
                      </dd>
                    </dl>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      {!tests.length && !error && <p className="empty">{t('regression.empty')}</p>}
      <h2 className="section">{t('regression.section.new')}</h2>
      <p className="muted small">
        {t('regression.authNote')}
      </p>
      <div className="card">
        <input placeholder={t('regression.field.name')} value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
        <input placeholder={t('regression.field.url')} value={form.url} style={{ minWidth: 320 }}
          onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} />
        <select value={form.method} onChange={(e) => setForm((f) => ({ ...f, method: e.target.value }))}>
          {['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <input placeholder={t('regression.field.suite')} value={form.suite}
          onChange={(e) => setForm((f) => ({ ...f, suite: e.target.value }))} />
        <input type="number" placeholder={t('regression.field.expectStatus')} value={form.expectStatus}
          onChange={(e) => setForm((f) => ({ ...f, expectStatus: e.target.value }))} />
        <input placeholder={t('regression.field.bodyMustNotContain')} value={form.bodyMustNotContain}
          onChange={(e) => setForm((f) => ({ ...f, bodyMustNotContain: e.target.value }))} />
        <button onClick={createTest}>{t('regression.create')}</button>
      </div>
    </div>
  )
}
