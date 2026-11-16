import React, { useEffect, useState } from 'react'
import { api } from './api'
import { PageHeader, Pager, usePage } from './ui'
import { useI18n } from './i18n'

export default function Licenses({ projects }) {
  const { t } = useI18n()
  const [policies, setPolicies] = useState([])
  const [exceptions, setExceptions] = useState([])
  const [form, setForm] = useState({
    name: '', allow_list: '', deny_list: '', unknown_action: 'warn',
    scope_type: 'org', scope_id: '',
  })
  const [evalState, setEvalState] = useState({ project: '', version: '', result: null, error: '' })
  const [exForm, setExForm] = useState({ component_identity: '', license_id: '', reason: '', approved_by: 'console' })
  const [error, setError] = useState('')

  // Three tables, three questions: the verdicts of the build just evaluated,
  // the org's policies, the org's exceptions. They grow independently, so each
  // keeps its own cursor instead of sharing one page number.
  const verdictPage = usePage(evalState.result?.results || [], 25)
  const policyPage = usePage(policies, 25)
  const exceptionPage = usePage(exceptions, 25)

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/license-policies').then((r) => setPolicies(r.data)).catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/license-exceptions').then((r) => setExceptions(r.data)).catch(() => {})
  }

  async function createPolicy() {
    try {
      await api.post('/api/v1/license-policies', {
        ...form,
        scope_id: form.scope_type === 'project' ? form.scope_id : undefined,
        actor: 'console',
      })
      setForm((f) => ({ ...f, name: '', allow_list: '', deny_list: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function evaluate() {
    setEvalState((s) => ({ ...s, error: '', result: null }))
    try {
      const { data } = await api.post('/api/v1/license-policies/evaluate', {
        project: evalState.project, version: evalState.version })
      setEvalState((s) => ({ ...s, result: data }))
    } catch (e) {
      setEvalState((s) => ({ ...s, error: String(e.message || e) }))
    }
  }

  async function togglePolicy(policy) {
    const next = policy.status === 'active' ? 'disabled' : 'active'
    await api.post(`/api/v1/license-policies/${policy.id}/status?status=${next}&actor=console`, {})
    load()
  }

  async function createException() {
    try {
      await api.post('/api/v1/license-exceptions', { ...exForm, expires_in_days: 90 })
      setExForm((f) => ({ ...f, component_identity: '', license_id: '', reason: '' }))
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  const project = projects.find((p) => p.name === evalState.project)
  const counts = evalState.result?.counts
  // The row key includes a position: paging must not hand a row the index its
  // neighbour had on the previous page.
  const verdictStart = verdictPage.page * verdictPage.perPage

  return (
    <div className="stack">
      <PageHeader title={t('licenses.title')} />
      <div className="toolbar">
        <select value={evalState.project}
          onChange={(e) => setEvalState((s) => ({ ...s, project: e.target.value, version: '' }))}>
          <option value="">{t('licenses.selectProject')}</option>
          {projects.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
        </select>
        <select value={evalState.version}
          onChange={(e) => setEvalState((s) => ({ ...s, version: e.target.value }))}
          disabled={!(project?.versions?.length)}>
          {(project?.versions || []).map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <button onClick={evaluate} disabled={!evalState.project || !evalState.version}>{t('licenses.evaluate')}</button>
        <span className="count">{t('licenses.count.policies', { n: policies.length })}</span>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      {evalState.error && <div className="banner banner-error">{evalState.error}</div>}
      {counts && (
        <>
          <div className="toolbar">
            <span className="pill">{t('licenses.policy', { name: evalState.result.policy?.name || t('common.none') })}</span>
            <span className="pill">{t('licenses.count.components', { n: counts.components })}</span>
            <span className={`pill ${counts.denied ? 'sev sev-critical' : ''}`}>{t('licenses.count.denied', { n: counts.denied })}</span>
            <span className="pill">{t('licenses.count.unknown', { n: counts.unknown })}</span>
            <span className="pill">{t('licenses.count.excepted', { n: counts.excepted })}</span>
            <span className="pill">{t('licenses.count.unlicensed', { n: counts.unlicensed })}</span>
            <Pager page={verdictPage.page} pages={verdictPage.pages}
              onChange={verdictPage.setPage} total={verdictPage.total}
              perPage={verdictPage.perPage} unit="components" className="row-end" />
          </div>
          <table>
            <thead><tr><th>{t('licenses.col.component')}</th><th>{t('licenses.col.version')}</th><th>{t('licenses.col.license')}</th><th>{t('licenses.col.verdict')}</th><th>{t('licenses.col.reason')}</th></tr></thead>
            <tbody>
              {verdictPage.rows.map((row, index) => (
                <tr key={`${row.identity_key}-${row.license}-${verdictStart + index}`} className={row.verdict === 'denied' ? '' : 'muted-row'}>
                  <td className="title">{row.component || '—'}</td>
                  <td>{row.version || '—'}</td>
                  <td>{row.license || '—'}</td>
                  <td>
                    <span className={`status st-${row.verdict === 'denied' ? 'open' : row.verdict === 'excepted' ? 'acknowledged' : 'resolved'}`}>
                      {row.verdict}
                    </span>
                  </td>
                  <td className="muted">{row.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={verdictPage.page} pages={verdictPage.pages}
            onChange={verdictPage.setPage} total={verdictPage.total}
            perPage={verdictPage.perPage} unit="components" className="row-end" />
        </>
      )}
      <div className="row">
        <h2 className="section">{t('licenses.policies')}</h2>
        <Pager page={policyPage.page} pages={policyPage.pages}
          onChange={policyPage.setPage} total={policyPage.total}
          perPage={policyPage.perPage} unit={t('licenses.unit.policies')} className="row-end" />
      </div>
      <table>
        <thead><tr><th>{t('licenses.col.name')}</th><th>{t('licenses.col.scope')}</th><th>{t('licenses.col.allow')}</th><th>{t('licenses.col.deny')}</th><th>{t('common.status')}</th><th></th></tr></thead>
        <tbody>
          {policyPage.rows.map((p) => (
            <tr key={p.id} className={p.status === 'disabled' ? 'muted-row' : ''}>
              <td className="title">{p.name}</td>
              <td>{p.scope_type}</td>
              <td>{p.allow_list || '—'}</td>
              <td>{p.deny_list || '—'}</td>
              <td><span className={`status st-${p.status}`}>{p.status}</span></td>
              <td><button onClick={() => togglePolicy(p)}>{p.status === 'active' ? t('licenses.disable') : t('licenses.enable')}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager page={policyPage.page} pages={policyPage.pages}
        onChange={policyPage.setPage} total={policyPage.total}
        perPage={policyPage.perPage} unit={t('licenses.unit.policies')} className="row-end" />
      <div className="card">
        <input placeholder={t('licenses.form.name')} value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
        <select value={form.scope_type} onChange={(e) => setForm((f) => ({ ...f, scope_type: e.target.value }))}>
          <option value="org">{t('licenses.scope.org')}</option>
          <option value="project">{t('licenses.scope.project')}</option>
        </select>
        {form.scope_type === 'project' && (
          <select value={form.scope_id} onChange={(e) => setForm((f) => ({ ...f, scope_id: e.target.value }))}>
            <option value="">{t('licenses.selectProject')}</option>
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        )}
        <input placeholder={t('licenses.form.allow')} value={form.allow_list}
          onChange={(e) => setForm((f) => ({ ...f, allow_list: e.target.value }))} />
        <input placeholder={t('licenses.form.deny')} value={form.deny_list}
          onChange={(e) => setForm((f) => ({ ...f, deny_list: e.target.value }))} />
        <select value={form.unknown_action} onChange={(e) => setForm((f) => ({ ...f, unknown_action: e.target.value }))}>
          <option value="warn">{t('licenses.unknown.warn')}</option>
          <option value="allow">{t('licenses.unknown.allow')}</option>
          <option value="deny">{t('licenses.unknown.deny')}</option>
        </select>
        <button onClick={createPolicy}>{t('licenses.createPolicy')}</button>
      </div>
      <div className="row">
        <h2 className="section">{t('licenses.exceptions')}</h2>
        <Pager page={exceptionPage.page} pages={exceptionPage.pages}
          onChange={exceptionPage.setPage} total={exceptionPage.total}
          perPage={exceptionPage.perPage} unit={t('licenses.unit.exceptions')} className="row-end" />
      </div>
      <table>
        <thead><tr><th>{t('licenses.col.componentIdentity')}</th><th>{t('licenses.col.license')}</th><th>{t('licenses.col.approvedBy')}</th><th>{t('licenses.col.expires')}</th><th>{t('licenses.col.reason')}</th></tr></thead>
        <tbody>
          {exceptionPage.rows.map((x) => (
            <tr key={x.id}>
              <td className="muted">{x.component_identity}</td>
              <td>{x.license_id}</td>
              <td>{x.approved_by}</td>
              <td>{x.expires_at ? new Date(x.expires_at).toLocaleDateString() : t('common.never')}</td>
              <td>{x.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager page={exceptionPage.page} pages={exceptionPage.pages}
        onChange={exceptionPage.setPage} total={exceptionPage.total}
        perPage={exceptionPage.perPage} unit={t('licenses.unit.exceptions')} className="row-end" />
      <div className="toolbar">
        <input placeholder={t('licenses.form.componentIdentity')} value={exForm.component_identity}
          onChange={(e) => setExForm((f) => ({ ...f, component_identity: e.target.value }))} />
        <input placeholder={t('licenses.form.licenseId')} value={exForm.license_id}
          onChange={(e) => setExForm((f) => ({ ...f, license_id: e.target.value }))} />
        <input placeholder={t('licenses.form.reason')} value={exForm.reason}
          onChange={(e) => setExForm((f) => ({ ...f, reason: e.target.value }))} />
        <input placeholder={t('licenses.form.approvedBy')} value={exForm.approved_by}
          onChange={(e) => setExForm((f) => ({ ...f, approved_by: e.target.value }))} />
        <button onClick={createException}>{t('licenses.createException')}</button>
      </div>
      {!policies.length && !error && <p className="empty">{t('licenses.empty.policies')}</p>}
    </div>
  )
}
