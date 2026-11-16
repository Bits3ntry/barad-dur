import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Table, Tabs,
} from './ui'
import { useI18n } from './i18n'

/* A threat model belongs to one crown jewel. The techniques are ATT&CK's names for
   what would happen to it, the capability is the only thing that makes one testable,
   and coverage is arithmetic over declared × capability × grant — never a score.
   `ran` stays unmeasured until a run cites the technique it closed. */

export default function ThreatModel() {
  const { t, tOr } = useI18n()
  const [jewels, setJewels] = useState([])
  const [jewelId, setJewelId] = useState('')
  const [model, setModel] = useState(null)
  const [tab, setTab] = useState('techniques')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [addOpen, setAddOpen] = useState(false)
  const [catalog, setCatalog] = useState([])
  const [search, setSearch] = useState('')
  const [picked, setPicked] = useState(null)
  const [reason, setReason] = useState('')
  const [profileOpen, setProfileOpen] = useState(false)
  const [profileCatalog, setProfileCatalog] = useState([])
  const [profileForm, setProfileForm] = useState({
    name: '', description: '', origin: 'custom', tools: '', techniques: [],
  })

  useEffect(() => {
    api.get('/api/v1/threat-model/crown-jewels')
      .then((r) => {
        const rows = r.data || []
        setJewels(rows)
        if (rows.length) setJewelId((current) => current || rows[0].id)
      })
      .catch((e) => setError(String(e.message || e)))
  }, [])

  useEffect(() => { if (jewelId) load() }, [jewelId])

  useEffect(() => {
    if (!addOpen || !jewelId) return
    const timer = setTimeout(() => {
      api.get(`/api/v1/threat-model/catalog?jewel=${jewelId}&q=${encodeURIComponent(search)}`)
        .then((r) => setCatalog(r.data || []))
        .catch((e) => setError(String(e.message || e)))
    }, 200)
    return () => clearTimeout(timer)
  }, [addOpen, jewelId, search])

  useEffect(() => {
    if (!profileOpen) return
    // A profile is org-scoped: it may name a technique no jewel declares yet, so
    // the picker reads the whole catalogue, not this jewel's entries.
    api.get('/api/v1/threat-model/catalog?limit=200')
      .then((r) => setProfileCatalog(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }, [profileOpen])

  function load() {
    setError('')
    api.get(`/api/v1/threat-model?jewel=${jewelId}`)
      .then((r) => setModel(r))
      .catch((e) => setError(String(e.message || e)))
  }

  async function addTechnique() {
    if (!picked) return
    setBusy(true)
    try {
      await api.post('/api/v1/threat-model/entries', {
        component_id: jewelId, technique_id: picked.id,
        reason: reason || null, actor: 'console',
      })
      setAddOpen(false)
      setPicked(null)
      setSearch('')
      setReason('')
      setNotice(t('threat.notice.added', { id: picked.id }))
      load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function removeTechnique(entry) {
    setBusy(true)
    try {
      await api.del(`/api/v1/threat-model/entries/${entry.id}`)
      setNotice(t('threat.notice.removed'))
      load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  async function createProfile() {
    if (!profileForm.name.trim()) return
    setBusy(true)
    try {
      await api.post('/api/v1/threat-model/profiles', {
        name: profileForm.name.trim(),
        description: profileForm.description || null,
        origin: profileForm.origin,
        tools: profileForm.tools.split(',').map((item) => item.trim()).filter(Boolean),
        techniques: profileForm.techniques,
        actor: 'console',
      })
      setProfileOpen(false)
      setProfileForm({ name: '', description: '', origin: 'custom', tools: '', techniques: [] })
      setNotice(t('threat.notice.profileCreated'))
      load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const coverage = model?.coverage
  const entries = model?.entries || []
  const profiles = model?.profiles || []

  if (!jewels.length) {
    return (
      <div className="stack">
        <PageHeader title={t('threat.title')} subtitle={t('threat.subtitle')} />
        {error && <ErrorBanner error={error} />}
        <EmptyState title={t('threat.noJewels.title')} hint={t('threat.noJewels.hint')} />
      </div>
    )
  }

  return (
    <div className="stack">
      <PageHeader title={t('threat.title')} subtitle={t('threat.subtitle')}
        actions={<>
          <select value={jewelId} onChange={(e) => setJewelId(e.target.value)}>
            {jewels.map((item) => (
              <option key={item.id} value={item.id}>
                {item.project_name ? `${item.project_name} › ` : ''}{item.name}
              </option>
            ))}
          </select>
          <button className="primary-action" onClick={() => setAddOpen(true)}>
            {t('threat.add')}
          </button>
        </>} />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {coverage && (
        <p className="verdict-line">
          {t('threat.verdict', {
            declared: coverage.declared, testable: coverage.testable,
            ready: coverage.ready, blocked: coverage.blocked,
            untestable: coverage.untestable,
          })}
          {' '}
          <span className="muted">{t('threat.ran.unmeasured')}</span>
        </p>
      )}

      <Tabs active={tab} onChange={setTab} tabs={[
        { id: 'techniques', label: t('threat.tab.techniques') },
        { id: 'profiles', label: t('threat.tab.profiles', { n: profiles.length }) },
      ]} />

      {tab === 'techniques' && (
        entries.length ? (
          <Table head={[t('threat.col.tactic'), t('threat.col.technique'),
            t('threat.col.capability'), t('threat.col.state'), '']}>
            {entries.map((row) => (
              <tr key={row.id}>
                <td className="muted">{tOr(`threat.tactic.${row.tactic}`, row.tactic)}</td>
                <td className="title">
                  <span className="muted" style={{ marginRight: 6 }}>{row.technique_id}</span>
                  {row.name}
                  {row.reason && (
                    <div className="muted" style={{ fontSize: 11.5 }}>{row.reason}</div>
                  )}
                </td>
                <td className="muted">
                  {row.capability ? tOr(`threat.capability.${row.capability}`, row.capability)
                    : t('threat.capability.none')}
                </td>
                <td>
                  {row.state === 'ready' && (
                    <span className="status verdict-pass">{t('threat.state.ready')}</span>
                  )}
                  {row.state === 'blocked' && (
                    <span className="status verdict-fail">{t('threat.state.blocked')}</span>
                  )}
                  {row.state === 'untestable' && (
                    <span className="muted">{t('threat.state.untestable')}</span>
                  )}
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  <button className="mini" disabled={busy}
                    onClick={() => removeTechnique(row)}>
                    {t('threat.remove')}
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <EmptyState title={t('threat.empty.title')} hint={t('threat.empty.hint')} />
        )
      )}

      {tab === 'profiles' && (
        <div className="stack">
          <div className="row">
            <button className="mini" onClick={() => setProfileOpen(true)}>
              {t('threat.profile.add')}
            </button>
            <span className="muted">{t('threat.profile.note')}</span>
          </div>
          {profiles.length ? profiles.map((profile) => (
            <div className="bc-row" key={profile.id}>
              <div>
                <span className="bc-value">{profile.name}</span>
                <span className="muted bc-sub">
                  {t(`threat.profile.origin.${profile.origin || 'custom'}`)}
                  {profile.description ? ` · ${profile.description}` : ''}
                </span>
              </div>
              <div className="row" style={{ gridColumn: 'span 3' }}>
                {(profile.techniques || []).map((id) => (
                  <span className="pill" key={id}>{id}</span>
                ))}
                {(profile.tools || []).map((tool) => (
                  <span className="pill" key={tool}>{tool}</span>
                ))}
              </div>
            </div>
          )) : (
            <EmptyState title={t('threat.profiles.empty.title')}
              hint={t('threat.profiles.empty.hint')} />
          )}
        </div>
      )}

      <p className="muted">{t('threat.note')}</p>

      <Dialog open={addOpen} title={t('threat.dialog.add')}
        onClose={() => setAddOpen(false)} onConfirm={addTechnique}
        confirmLabel={picked ? t('threat.dialog.confirm', { id: picked.id })
          : t('threat.dialog.pick')}>
        <div className="stack">
          <Input label={t('threat.dialog.search')} value={search}
            onChange={setSearch} hint={t('threat.dialog.searchHint')} />
          {catalog.length ? (
            <Table head={[t('threat.col.technique'), t('threat.col.tactic'),
              t('threat.col.capability'), '']}>
              {catalog.slice(0, 12).map((item) => (
                <tr key={item.id}
                  className={picked?.id === item.id ? 'selected' : ''}>
                  <td className="title">
                    <span className="muted" style={{ marginRight: 6 }}>{item.id}</span>
                    {item.name}
                  </td>
                  <td className="muted">{tOr(`threat.tactic.${item.tactic}`, item.tactic)}</td>
                  <td className="muted">
                    {item.capability
                      ? tOr(`threat.capability.${item.capability}`, item.capability)
                      : t('threat.capability.none')}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="mini" onClick={() => setPicked(item)}>
                      {picked?.id === item.id ? t('threat.dialog.picked')
                        : t('threat.dialog.pickOne')}
                    </button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            <span className="muted">{t('threat.dialog.noResults')}</span>
          )}
          <Input label={t('threat.dialog.reason')} value={reason}
            onChange={setReason} hint={t('threat.dialog.reasonHint')} />
        </div>
      </Dialog>

      <Dialog open={profileOpen} title={t('threat.profile.dialog')}
        onClose={() => setProfileOpen(false)} onConfirm={createProfile}
        confirmLabel={t('threat.profile.create')}>
        <div className="stack">
          <Input label={t('threat.profile.name')} value={profileForm.name}
            onChange={(v) => setProfileForm((s) => ({ ...s, name: v }))} />
          <Input label={t('threat.profile.description')} value={profileForm.description}
            onChange={(v) => setProfileForm((s) => ({ ...s, description: v }))} />
          <div className="field">
            <label className="field-label">{t('threat.profile.origin')}</label>
            <select value={profileForm.origin}
              onChange={(e) => setProfileForm((s) => ({ ...s, origin: e.target.value }))}>
              {['custom', 'external', 'none'].map((value) => (
                <option key={value} value={value}>
                  {t(`threat.profile.origin.${value}`)}
                </option>
              ))}
            </select>
          </div>
          <Input label={t('threat.profile.tools')} value={profileForm.tools}
            hint={t('threat.profile.toolsHint')}
            onChange={(v) => setProfileForm((s) => ({ ...s, tools: v }))} />
          <div className="field">
            <label className="field-label">{t('threat.profile.techniques')}</label>
            <select multiple size={8} value={profileForm.techniques}
              onChange={(e) => setProfileForm((s) => ({
                ...s, techniques: [...e.target.selectedOptions].map((o) => o.value),
              }))}>
              {profileCatalog.map((row) => (
                <option key={row.id} value={row.id}>
                  {row.id} {row.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Dialog>
    </div>
  )
}
