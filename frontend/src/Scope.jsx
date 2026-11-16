import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Banner, CheckBox, Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, Select,
  Table, Tabs, usePage,
} from './ui'
import { useI18n } from './i18n'

/* Scope is a declaration screen, not an inventory: it lists only what somebody
   wrote down. A `*.example.com` row is a rule and never becomes a host, which is
   why patterns show as patterns and concrete rows show the asset they linked. */

const TYPES = [
  { value: 'domain', labelKey: 'scope.type.domain' },
  { value: 'url', labelKey: 'scope.type.url' },
  { value: 'ip', labelKey: 'scope.type.ip' },
  { value: 'cidr', labelKey: 'scope.type.cidr' },
  { value: 'repository', labelKey: 'scope.type.repository' },
  { value: 'service', labelKey: 'scope.type.service' },
  { value: 'api', labelKey: 'scope.type.api' },
  { value: 'cloud_account', labelKey: 'scope.type.cloud_account' },
]

const CAPABILITIES = [
  { value: 'passive_discovery', labelKey: 'scope.capability.passive_discovery' },
  { value: 'active_verification', labelKey: 'scope.capability.active_verification' },
  { value: 'code_analysis', labelKey: 'scope.capability.code_analysis' },
]

const EMPTY = {
  target_type: 'domain', value: '', reason: '', owner: '', valid_until: '',
  capabilities: ['passive_discovery'], include_apex: false, note: '',
}

export default function Scope() {
  const { t, tCount, tOr } = useI18n()
  const [tab, setTab] = useState('targets')
  const [targets, setTargets] = useState([])
  const [exclusions, setExclusions] = useState([])
  const [form, setForm] = useState({ ...EMPTY })
  const [creating, setCreating] = useState(false)
  const [exclusionForm, setExclusionForm] = useState({ target_type: 'domain', value: '', reason: '' })
  const [exclusionOpen, setExclusionOpen] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [principal, setPrincipal] = useState(
    () => localStorage.getItem('barad.principal') || 'console')
  const [checkValue, setCheckValue] = useState('')
  const [checkType, setCheckType] = useState('')
  const [checkCapability, setCheckCapability] = useState('passive_discovery')
  const [decision, setDecision] = useState(null)
  // Declaring scope starts from what the estate already holds: typing a host from
  // memory is how one target ends up twice, once as an asset and once as a rule.
  const [candidateQuery, setCandidateQuery] = useState('')
  const [candidates, setCandidates] = useState([])
  const [picked, setPicked] = useState(null)

  // Nobody imports a scope: rows arrive one declaration at a time, so the whole
  // list is already here. Paging is a reading aid, not a limit on what is shown.
  const pagedTargets = usePage(targets, 25)
  const pagedExclusions = usePage(exclusions, 25)

  useEffect(() => { load() }, [])

  // Debounced: one request per pause, not per keystroke.
  useEffect(() => {
    const needle = candidateQuery.trim()
    if (needle.length < 2) { setCandidates([]); return undefined }
    const timer = setTimeout(() => {
      api.get(`/api/v1/scope/candidates?q=${encodeURIComponent(needle)}`)
        .then((r) => setCandidates(r.data || []))
        .catch(() => setCandidates([]))
    }, 220)
    return () => clearTimeout(timer)
  }, [candidateQuery])

  function pickCandidate(row) {
    if (row.in_scope) return
    setPicked(row)
    setCandidates([])
    setCandidateQuery('')
    setForm((state) => ({
      ...state, target_type: row.type, value: row.value,
      include_apex: row.value.startsWith('*.'),
    }))
  }

  function openDeclare() {
    setPicked(null)
    setCandidateQuery('')
    setCandidates([])
    setForm({ ...EMPTY })
    setCreating(true)
  }

  function chooseTargetType(value) {
    const capabilities = value === 'cloud_account'
      ? []
      : value === 'repository' ? ['code_analysis'] : ['passive_discovery']
    setForm((state) => ({ ...state, target_type: value, capabilities }))
  }

  function chooseExclusionType(value) {
    setExclusionForm((state) => ({ ...state, target_type: value }))
  }

  function load() {
    api.get('/api/v1/scope/targets').then((r) => setTargets(r.data || []))
      .catch((e) => setError(String(e.message || e)))
    api.get('/api/v1/scope/exclusions').then((r) => setExclusions(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  async function createTarget() {
    setError('')
    try {
      const result = await api.post('/api/v1/scope/targets', {
        target_type: form.target_type,
        value: form.value.trim(),
        reason: form.reason || null,
        owner: form.owner || null,
        note: form.note || null,
        capabilities: form.target_type === 'cloud_account' ? [] : form.capabilities,
        include_apex: form.include_apex,
        valid_until: form.valid_until ? `${form.valid_until}T00:00:00+00:00` : null,
        actor: principal,
      })
      setCreating(false)
      setForm({ ...EMPTY })
      setPicked(null)
      setCandidates([])
      setCandidateQuery('')
      setNotice(result.already_known
        ? t('scope.notice.alreadyDeclared')
        : result.data.asset
          ? t('scope.notice.declaredLinked',
            { type: result.data.target_type, value: result.data.value, asset: result.data.asset.value })
          : t('scope.notice.declaredRule',
            { type: result.data.target_type, value: result.data.value }))
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function patchTarget(row, body, label) {
    try {
      await api.patch(`/api/v1/scope/targets/${row.id}`, { ...body, actor: principal })
      setNotice(t('scope.notice.updated', { value: row.value, label }))
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function createExclusion() {
    if (!exclusionForm.value.trim() || !exclusionForm.reason.trim()) return
    try {
      await api.post('/api/v1/scope/exclusions', {
        ...exclusionForm, value: exclusionForm.value.trim(), actor: principal,
      })
      setExclusionOpen(false)
      setExclusionForm({ target_type: 'domain', value: '', reason: '' })
      setNotice(t('scope.notice.exclusionAdded'))
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function runCheck() {
    setDecision(null)
    setError('')
    try {
      const result = await api.post('/api/v1/scope/check', {
        value: checkValue.trim(),
        target_type: checkType || null,
        capability: checkCapability || null,
      })
      setDecision(result.data)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const patternCount = targets.filter((row) => row.is_pattern).length
  const activeCount = targets.filter((row) => row.status === 'active').length

  return (
    <div className="stack">
      <PageHeader
        title={t('scope.title')}
        subtitle={tCount('scope.subtitle', patternCount,
          { declared: targets.length, active: activeCount })}
        actions={<>
          <button className="mini" onClick={() => setExclusionOpen(true)}>{t('scope.addExclusion')}</button>
          {' '}
          <button className="primary-action" onClick={openDeclare}>{t('scope.declareTarget')}</button>
        </>}
      />

      <Tabs
        tabs={[
          { id: 'targets', label: t('scope.tab.targets') },
          { id: 'exclusions', label: t('scope.tab.exclusions', { n: exclusions.length }) },
          { id: 'check', label: t('scope.tab.check') },
        ]}
        active={tab}
        onChange={setTab}
      />

      <p className="scope-note">
        {t('scope.note.before')}<span className="mono">*.domain</span>{t('scope.note.afterPattern')}<span className="mono">apex</span>{t('scope.note.afterApex')}
      </p>

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {tab === 'targets' && (
        targets.length ? (
          <>
            <div className="toolbar">
              <Pager page={pagedTargets.page} pages={pagedTargets.pages}
                onChange={pagedTargets.setPage} total={pagedTargets.total}
                perPage={pagedTargets.perPage} unit={t('unit.targets')} className="row-end" />
            </div>
            <Table className="scope-table"
              head={[t('scope.col.value'), t('scope.col.capabilities'), t('scope.col.ownerReason'),
                t('scope.col.validity'), t('scope.col.asset'), '']}>
              {pagedTargets.rows.map((row) => (
                <tr key={row.id}>
                  <td>
                    <div className="scope-value">
                      <span className="scope-type">{row.target_type}</span>
                      <span className="title mono scope-target" title={row.value}>{row.value}</span>
                      {row.is_pattern && (
                        <button className={`pill pill-toggle ${row.include_apex ? 'on' : ''}`}
                          title={row.include_apex
                            ? t('scope.apex.coveredTitle')
                            : t('scope.apex.uncoveredTitle')}
                          onClick={() => patchTarget(row, { include_apex: !row.include_apex },
                            t(row.include_apex ? 'scope.notice.apexExcluded' : 'scope.notice.apexIncluded'))}>
                          {t('scope.apex.badge')}
                        </button>
                      )}
                    </div>
                  </td>
                  <td>
                    {(row.capabilities || []).length
                      ? row.capabilities.map((c) => (
                        <button key={c} className="pill pill-toggle on"
                          title={row.status === 'active'
                            ? t('scope.capability.permitsTitle', { capability: tOr(`scope.capability.${c}`, c) })
                            : t('scope.capability.disabledTitle')}
                          onClick={() => patchTarget(row, {
                            capabilities: row.capabilities.filter((x) => x !== c),
                          }, t('scope.notice.capabilityWithdrawn', { capability: tOr(`scope.capability.${c}`, c) }))}>
                          {tOr(`scope.capability.${c}`, c)}
                        </button>
                      ))
                      : <span className="muted">{t('scope.capability.none')}</span>}
                    {row.status === 'active' && (row.capabilities || []).length > 0
                      && !row.capabilities.includes('active_verification') && (
                      <button className="pill pill-toggle"
                        title={t('scope.capability.addVerificationTitle')}
                        onClick={() => patchTarget(row, {
                          capabilities: [...row.capabilities, 'active_verification'],
                        }, t('scope.notice.verificationAdded'))}>
                        {t('scope.capability.addVerification')}
                      </button>
                    )}
                  </td>
                  <td>
                    <div className="stack" style={{ gap: 2 }}>
                      <span className={row.owner ? '' : 'muted'}>{row.owner || t('scope.value.noOwner')}</span>
                      <span className="muted" style={{ fontSize: 11.5 }}>
                        {row.reason || t('scope.value.noReason')}
                      </span>
                    </div>
                  </td>
                  <td>
                    <span className={row.status === 'active' ? 'pill' : 'sev sev-medium'}>
                      {row.status}
                    </span>
                    {row.valid_until && (
                      <div className="muted" style={{ fontSize: 11.5 }}>
                        {t('scope.value.until', { date: new Date(row.valid_until).toLocaleDateString() })}
                      </div>
                    )}
                  </td>
                  <td>
                    {row.asset
                      ? <span className="mono">{row.asset.value}</span>
                      : <span className="muted">—</span>}
                  </td>
                  <td className="row-action">
                    <button className="mini" onClick={() => patchTarget(
                      row, { status: row.status === 'active' ? 'disabled' : 'active' },
                      t(row.status === 'active' ? 'scope.notice.disabled' : 'scope.notice.reEnabled'))}>
                      {t(row.status === 'active' ? 'scope.action.disable' : 'scope.action.enable')}
                    </button>
                  </td>
                </tr>
              ))}
            </Table>
            <Pager page={pagedTargets.page} pages={pagedTargets.pages}
              onChange={pagedTargets.setPage} total={pagedTargets.total}
              perPage={pagedTargets.perPage} unit={t('unit.targets')} className="row-end" />
          </>
        ) : (
          !error && <EmptyState title={t('scope.targets.empty.title')}
            hint={t('scope.targets.empty.hint')} />
        )
      )}

      {tab === 'exclusions' && (
        exclusions.length ? (
          <>
            <div className="toolbar">
              <Pager page={pagedExclusions.page} pages={pagedExclusions.pages}
                onChange={pagedExclusions.setPage} total={pagedExclusions.total}
                perPage={pagedExclusions.perPage} unit={t('scope.unit.exclusions')} className="row-end" />
            </div>
            <Table head={[t('scope.excl.col.type'), t('scope.excl.col.value'), t('scope.excl.col.reason'),
              t('scope.excl.col.expires'), t('scope.excl.col.status'), '']}>
              {pagedExclusions.rows.map((row) => (
                <tr key={row.id}>
                  <td><span className="pill">{row.target_type}</span></td>
                  <td className="title mono">{row.value}</td>
                  <td className="muted">{row.reason}</td>
                  <td className="muted">
                    {row.expires_at
                      ? new Date(row.expires_at).toLocaleDateString()
                      : t('scope.excl.noExpiry')}
                  </td>
                  <td>
                    <span className={row.status === 'active' ? 'pill' : 'sev sev-medium'}>
                      {row.status}
                    </span>
                  </td>
                  <td>
                    <button className="mini" onClick={async () => {
                      try {
                        await api.patch(`/api/v1/scope/exclusions/${row.id}`, {
                          status: row.status === 'active' ? 'disabled' : 'active',
                          actor: principal,
                        })
                        load()
                      } catch (e) { setError(String(e.message || e)) }
                    }}>
                      {t(row.status === 'active' ? 'scope.action.disable' : 'scope.action.enable')}
                    </button>
                  </td>
                </tr>
              ))}
            </Table>
            <Pager page={pagedExclusions.page} pages={pagedExclusions.pages}
              onChange={pagedExclusions.setPage} total={pagedExclusions.total}
              perPage={pagedExclusions.perPage} unit={t('scope.unit.exclusions')} className="row-end" />
          </>
        ) : (
          !error && <EmptyState title={t('scope.excl.empty.title')}
            hint={t('scope.excl.empty.hint')} />
        )
      )}

      {tab === 'check' && (
        <>
          <div className="toolbar">
            <input placeholder={t('scope.check.placeholder')} value={checkValue}
              onChange={(e) => setCheckValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runCheck()} />
            <select value={checkType} onChange={(e) => setCheckType(e.target.value)}>
              <option value="">{t('scope.check.detectType')}</option>
              {TYPES.map((type) => <option key={type.value} value={type.value}>{type.value}</option>)}
            </select>
            <select value={checkCapability} onChange={(e) => setCheckCapability(e.target.value)}>
              <option value="">{t('scope.check.anyCapability')}</option>
              {CAPABILITIES.map((c) => (
                <option key={c.value} value={c.value}>{t(c.labelKey)}</option>
              ))}
            </select>
            <button onClick={runCheck}>{t('scope.check.button')}</button>
          </div>
          {decision && (
            <Banner kind={decision.allowed ? 'ok' : 'error'}>
              <strong>{t(decision.allowed ? 'scope.check.covered' : 'scope.check.denied')}</strong> — {decision.reason}.
              {' '}
              {decision.matched_rule && (
                <span className="mono">
                  {t('scope.check.rule', { type: decision.matched_rule.type, value: decision.matched_rule.value })}
                </span>
              )}
              {decision.excluded_by && (
                <span className="mono">{' '}{t('scope.check.exclusion', { value: decision.excluded_by.value })}</span>
              )}
              {decision.capabilities.length > 0 && (
                <span className="muted"> {t('scope.check.permits', { capabilities: decision.capabilities.join(', ') })}</span>
              )}
            </Banner>
          )}
          <p className="muted">{t('scope.check.note')}</p>
        </>
      )}

      <Dialog open={creating} title={t('scope.declare.title')}
        onClose={() => setCreating(false)} onConfirm={createTarget}
        confirmLabel={t('scope.declare.confirm')}>
        <div className="stack">
          <Input label={t('scope.declare.searchLabel')} value={candidateQuery}
            placeholder={t('scope.declare.searchPlaceholder')}
            hint={t('scope.declare.searchHint')}
            onChange={setCandidateQuery} />
          {candidates.length > 0 && (
            <div className="scope-cand-list">
              {candidates.map((row) => (
                <button type="button" key={`${row.type}:${row.value}`}
                  className={`scope-cand${row.in_scope ? ' is-taken' : ''}`}
                  disabled={row.in_scope} onClick={() => pickCandidate(row)}>
                  <span className="scope-cand-name">
                    <span className="mono scope-cand-value">{row.value}</span>
                    {row.type !== 'domain'
                      ? <span className="scope-type">{row.type}</span> : null}
                  </span>
                  <span className="muted scope-cand-project">
                    {row.project || (row.source === 'grant' ? t('scope.candidate.fromGrant') : '—')}
                  </span>
                  <span className={row.authorized && !row.in_scope ? 'ok' : 'muted'}>
                    {row.in_scope ? t('scope.candidate.inScope')
                      : row.authorized
                        ? t('scope.candidate.granted', { level: row.authorized.level })
                        : t('scope.candidate.notGranted')}
                  </span>
                  <span className="scope-cand-add">
                    {row.in_scope ? null : t('scope.candidate.add')}
                  </span>
                </button>
              ))}
            </div>
          )}
          {picked && (
            <p className="scope-note">
              {picked.authorized
                ? t('scope.declare.pickedGranted', {
                  value: picked.value, level: picked.authorized.level,
                  date: picked.authorized.valid_until
                    ? new Date(picked.authorized.valid_until).toLocaleDateString()
                    : t('scope.declare.noExpiry'),
                })
                : t('scope.declare.pickedUngranted', { value: picked.value })}
            </p>
          )}

          <span className="field-label">{t('scope.declare.manualTitle')}</span>
          <Select label={t('scope.field.type')} value={form.target_type}
            options={TYPES.map((type) => ({ value: type.value, label: t(type.labelKey) }))}
            onChange={chooseTargetType} />
          <Input label={t('scope.field.value')} value={form.value}
            placeholder={form.target_type === 'domain' ? '*.bitsentry.xyz'
              : t('scope.field.valuePlaceholder')}
            hint={form.target_type === 'cloud_account'
              ? t('scope.declare.cloudHint')
              : form.target_type === 'url' ? t('scope.declare.urlHint')
                : null}
            onChange={(value) => {
              // Editing the value by hand ends the "this is the one you picked"
              // claim: the note must never describe a target it no longer names.
              setPicked(null)
              setForm((s) => ({ ...s, value }))
            }} />
          <Input label={t('scope.field.reason')} value={form.reason}
            placeholder={t('scope.declare.reasonPlaceholder')}
            onChange={(value) => setForm((s) => ({ ...s, reason: value }))} />
          <Input label={t('common.owner')} value={form.owner}
            placeholder={t('scope.field.emailOrPrincipal')}
            onChange={(value) => setForm((s) => ({ ...s, owner: value }))} />
          <Input label={t('scope.field.validUntil')} type="date" value={form.valid_until}
            hint={t('scope.declare.validUntilHint')}
            onChange={(value) => setForm((s) => ({ ...s, valid_until: value }))} />
          {form.target_type === 'domain' && form.value.trim().startsWith('*.') && (
            <CheckBox label={t('scope.declare.includeApex')} checked={form.include_apex}
              onChange={(checked) => setForm((s) => ({ ...s, include_apex: checked }))} />
          )}
          {form.target_type !== 'cloud_account' && (
            <div className="field">
              <label className="field-label">{t('scope.field.capabilities')}</label>
              {CAPABILITIES.map((c) => (
                <CheckBox key={c.value} label={t(c.labelKey)}
                  checked={form.capabilities.includes(c.value)}
                  onChange={(checked) => setForm((s) => ({
                    ...s,
                    capabilities: checked
                      ? [...s.capabilities, c.value]
                      : s.capabilities.filter((x) => x !== c.value),
                  }))} />
              ))}
              <span className="muted">{t('scope.declare.capabilitiesNote')}</span>
            </div>
          )}
        </div>
      </Dialog>

      <Dialog open={exclusionOpen} title={t('scope.exclusion.title')}
        onClose={() => setExclusionOpen(false)} onConfirm={createExclusion}
        confirmLabel={t('scope.exclusion.confirm')}>
        <div className="stack">
          <Select label={t('scope.field.type')} value={exclusionForm.target_type}
            options={TYPES.map((type) => ({ value: type.value, label: t(type.labelKey) }))}
            onChange={chooseExclusionType} />
          <Input label={t('scope.field.value')} value={exclusionForm.value}
            onChange={(value) => setExclusionForm((s) => ({ ...s, value }))} />
          <Input label={t('scope.exclusion.reasonRequired')} value={exclusionForm.reason}
            onChange={(value) => setExclusionForm((s) => ({ ...s, reason: value }))} />
          <span className="muted">{t('scope.exclusion.note')}</span>
        </div>
      </Dialog>
    </div>
  )
}
