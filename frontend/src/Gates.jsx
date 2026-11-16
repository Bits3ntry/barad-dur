import React, { useEffect, useState } from 'react'
import { api } from './api'
import { useI18n } from './i18n'
import { PageHeader } from './ui'

export default function Gates({ projects }) {
  const { t, tOr } = useI18n()
  const [policies, setPolicies] = useState([])
  const [form, setForm] = useState({
    name: '', scope_type: 'org', scope_id: '', max_severity: 'HIGH',
    block_kev: false, block_license_denied: false,
  })
  const [evalState, setEvalState] = useState({ project: '', version: '', result: null, error: '' })
  const [error, setError] = useState('')

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/gate-policies').then((r) => setPolicies(r.data)).catch((e) => setError(String(e.message || e)))
  }

  async function create() {
    try {
      await api.post('/api/v1/gate-policies', {
        ...form,
        scope_id: form.scope_type === 'project' ? form.scope_id : undefined,
        actor: 'console',
      })
      setForm((f) => ({ ...f, name: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function evaluate() {
    setEvalState((s) => ({ ...s, error: '', result: null }))
    try {
      const body = { project: evalState.project }
      if (evalState.version) body.version = evalState.version
      const { data } = await api.post('/api/v1/gates/evaluate', body)
      setEvalState((s) => ({ ...s, result: data }))
    } catch (e) {
      setEvalState((s) => ({ ...s, error: String(e.message || e) }))
    }
  }

  const project = projects.find((p) => p.name === evalState.project)
  const result = evalState.result

  return (
    <div className="stack">
      <PageHeader title={t('gates.title')} />
      <div className="toolbar">
        <select value={evalState.project}
          onChange={(e) => setEvalState((s) => ({ ...s, project: e.target.value, version: '' }))}>
          <option value="">{t('gates.select.project')}</option>
          {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
        <select value={evalState.version}
          onChange={(e) => setEvalState((s) => ({ ...s, version: e.target.value }))}
          disabled={!(project?.versions?.length)}>
          <option value="">{t('gates.select.allVersions')}</option>
          {(project?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <button onClick={evaluate} disabled={!evalState.project}>{t('gates.evaluate')}</button>
        <span className="count">{t('gates.policyCount', { n: policies.length })}</span>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      {evalState.error && <div className="banner banner-error">{evalState.error}</div>}
      {result && (
        <>
          <div className="toolbar">
            <span className={`pill ${result.verdict === 'fail' ? 'sev sev-critical' : 'ok'}`}>
              {t('gates.verdict', { verdict: tOr(`gates.outcome.${result.verdict}`, result.verdict) })}
            </span>
            <span className="pill">
              {t('gates.policy', { name: result.policy?.name || t('gates.policy.default') })}
            </span>
            <span className="pill">{t('gates.policyVersion', { version: result.policy_version })}</span>
          </div>
          <table>
            <thead><tr>
              <th>{t('gates.column.rule')}</th>
              <th>{t('gates.column.status')}</th>
              <th>{t('gates.column.detail')}</th>
              <th>{t('gates.column.findings')}</th>
            </tr></thead>
            <tbody>
              {result.rules.map((rule) => (
                <tr key={rule.rule}>
                  <td className="title">{rule.rule}</td>
                  <td>
                    <span className={rule.status === 'fail' ? 'sev sev-critical' : 'ok'}>
                      {tOr(`gates.outcome.${rule.status}`, rule.status)}
                    </span>
                  </td>
                  <td>{rule.detail}</td>
                  <td className="muted">
                    {(rule.findings || []).slice(0, 4).map((f, index) => (
                      <div key={`${rule.rule}-${index}`}>
                        {f.title || f.component} {f.severity ? `(${f.severity})` : ''} {f.license ? `— ${f.license}` : ''}
                      </div>
                    ))}
                    {(rule.findings || []).length > 4 && (
                      <div>{t('gates.moreFindings', { n: rule.findings.length - 4 })}</div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      <h2 className="section">{t('gates.section.policies')}</h2>
      <table>
        <thead><tr>
          <th>{t('gates.column.name')}</th>
          <th>{t('gates.column.scope')}</th>
          <th>{t('gates.column.maxSeverity')}</th>
          <th>{t('gates.column.kevBlock')}</th>
          <th>{t('gates.column.licenseBlock')}</th>
          <th>{t('gates.column.status')}</th>
        </tr></thead>
        <tbody>
          {policies.map((p) => (
            <tr key={p.id}>
              <td className="title">{p.name}</td>
              <td>{p.scope_type}</td>
              <td>{p.max_severity}</td>
              <td>{p.block_kev ? t('common.yes') : t('common.no')}</td>
              <td>{p.block_license_denied ? t('common.yes') : t('common.no')}</td>
              <td><span className={`status st-${p.status}`}>{p.status}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="card">
        <input placeholder={t('gates.field.name')} value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
        <select value={form.scope_type} onChange={(e) => setForm((f) => ({ ...f, scope_type: e.target.value }))}>
          <option value="org">{t('gates.scope.org')}</option>
          <option value="project">{t('gates.scope.project')}</option>
        </select>
        {form.scope_type === 'project' && (
          <select value={form.scope_id} onChange={(e) => setForm((f) => ({ ...f, scope_id: e.target.value }))}>
            <option value="">{t('gates.select.project')}</option>
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        )}
        <select value={form.max_severity} onChange={(e) => setForm((f) => ({ ...f, max_severity: e.target.value }))}>
          <option value="CRITICAL">{t('gates.block.critical')}</option>
          <option value="HIGH">{t('gates.block.high')}</option>
          <option value="MEDIUM">{t('gates.block.medium')}</option>
          <option value="LOW">{t('gates.block.low')}</option>
        </select>
        <label className="check"><input type="checkbox" checked={form.block_kev}
          onChange={(e) => setForm((f) => ({ ...f, block_kev: e.target.checked }))} /> {t('gates.field.blockKev')}</label>
        <label className="check"><input type="checkbox" checked={form.block_license_denied}
          onChange={(e) => setForm((f) => ({ ...f, block_license_denied: e.target.checked }))} /> {t('gates.field.blockLicense')}</label>
        <button onClick={create}>{t('gates.create')}</button>
      </div>
      {!policies.length && !error && <p className="empty">{t('gates.empty.policies')}</p>}
    </div>
  )
}
