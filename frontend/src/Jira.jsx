import React, { useEffect, useRef, useState } from 'react'
import { api } from './api'
import { PageHeader, SeverityBadge } from './ui'
import { useI18n } from './i18n'

/* The Jira ledger: what is linked, what Jira says, and the two ways a link is
   born. The screen used to be a table of eight hex characters and a raw uuid
   input — nobody could tell what a row was about, so nobody used it. */

const ID_SHAPE = /^[0-9a-f]{32}$/i

export default function Jira({ onOpenFinding }) {
  const { t, tCount, tOr } = useI18n()
  const [links, setLinks] = useState([])
  const [configured, setConfigured] = useState(true)
  const [target, setTarget] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [recon, setRecon] = useState(null)
  const [form, setForm] = useState({ finding_id: '', project_key: '' })
  const [chosen, setChosen] = useState(null)
  const [search, setSearch] = useState('')
  const [hits, setHits] = useState([])
  const [searching, setSearching] = useState(false)
  const ticket = useRef(0)

  useEffect(() => { load() }, [])

  function load() {
    setError('')
    api.get('/api/v1/jira/links')
      .then((r) => {
        setLinks(r.data || [])
        setConfigured(Boolean(r.jira_configured))
        setTarget(r.jira_target || null)
      })
      .catch((e) => setError(String(e.message || e)))
  }

  // The finding is chosen by what it says, not by a uuid nobody has at hand.
  // `type:finding` is the estate search's own grammar, so this reuses the
  // ranking the topbar already uses.
  useEffect(() => {
    const needle = search.trim()
    if (ID_SHAPE.test(needle)) {
      setForm((f) => ({ ...f, finding_id: needle }))
      setHits([])
      setSearching(false)
      return undefined
    }
    if (needle.length < 2) {
      setHits([])
      setSearching(false)
      return undefined
    }
    const mine = ++ticket.current
    setSearching(true)
    const timer = setTimeout(() => {
      api.get(`/api/v1/search?q=${encodeURIComponent(`${needle} type:finding`)}`)
        .then((data) => {
          if (mine !== ticket.current) return
          const group = (data.groups || []).find((g) => g.kind === 'finding')
          setHits((group?.items || []).slice(0, 6))
          setSearching(false)
        })
        .catch(() => { if (mine === ticket.current) { setHits([]); setSearching(false) } })
    }, 250)
    return () => clearTimeout(timer)
  }, [search])

  function choose(hit) {
    setForm((f) => ({ ...f, finding_id: hit.id }))
    setChosen(hit)
    setSearch('')
    setHits([])
  }

  async function createLink() {
    if (!form.finding_id || !form.project_key.trim()) return
    setNotice('')
    try {
      const result = await api.post('/api/v1/jira/links',
        { ...form, project_key: form.project_key.trim(), actor: 'console' })
      setNotice(result.data?.issue_key
        ? t('jira.created', { key: result.data.issue_key })
        : t('jira.queued'))
      setForm({ finding_id: '', project_key: '' })
      setChosen(null)
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function sync(row, to_status) {
    setError('')
    try {
      await api.post(`/api/v1/jira/links/${row.id}/sync`,
        { actor: 'console', to_status })
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  async function reconcile() {
    setError('')
    try {
      const r = await api.post('/api/v1/jira/reconcile', { actor: 'console' })
      setRecon(r.data)
      load()
    } catch (e) { setError(String(e.message || e)) }
  }

  const host = target?.base_url ? target.base_url.replace(/^https?:\/\//, '') : ''

  return (
    <div className="stack">
      <PageHeader title={t('jira.title')} />
      <div className="toolbar">
        <span className="count">{tCount('jira.count', links.length)}</span>
        {configured
          ? <span className="muted">{host}{target?.account ? ` · ${target.account}` : ''}</span>
          : <span className="pill warn">{t('jira.notConfigured')}</span>}
        <span className="row-end" />
        <button onClick={reconcile} disabled={!configured}>{t('jira.reconcile')}</button>
      </div>
      {error && <div className="banner banner-error">{error}</div>}
      {notice && <div className="banner banner-ok">{notice}</div>}
      {recon && (
        <p className="muted">
          {t('jira.recon', { checked: recon.checked, drifted: recon.drifted,
            errors: recon.errors, verification: recon.verification_required.length })}
        </p>
      )}
      <table>
        <thead><tr>
          <th>{t('jira.col.finding')}</th>
          <th>{t('jira.col.severity')}</th>
          <th>{t('jira.col.project')}</th>
          <th>{t('jira.col.issue')}</th>
          <th>{t('jira.col.status')}</th>
          <th>{t('jira.col.assignee')}</th>
          <th>{t('jira.col.state')}</th>
          <th></th>
        </tr></thead>
        <tbody>
          {links.map((row) => (
            <tr key={row.id}>
              <td className="title">
                <button className="link" onClick={() => onOpenFinding?.(row.finding_id)}>
                  {row.finding_title || row.finding_id.slice(0, 8)}
                </button>
                <div className="muted mono" style={{ fontSize: 11 }}>
                  {row.finding_id.slice(0, 8)}{row.finding_kind ? ` · ${row.finding_kind}` : ''}
                </div>
              </td>
              <td>{row.finding_severity
                ? <SeverityBadge severity={row.finding_severity} />
                : <span className="muted">—</span>}</td>
              <td className="muted">{row.project_slug || '—'}</td>
              <td>{row.issue_key
                ? <a href={row.issue_url} target="_blank" rel="noreferrer">{row.issue_key}</a>
                : <span className="muted">{t('jira.pending')}</span>}</td>
              <td>{row.external_status || '—'}</td>
              <td>{row.external_assignee || '—'}</td>
              <td><span className={`status st-${row.sync_state}`}>
                {tOr(`jira.sync.${row.sync_state}`, row.sync_state)}
              </span></td>
              <td>
                <button className="mini" onClick={() => sync(row, 'In Progress')}
                  disabled={!configured || !row.issue_key}>{t('jira.toInProgress')}</button>{' '}
                <button className="mini" onClick={() => sync(row, 'Done')}
                  disabled={!configured || !row.issue_key}>{t('jira.toDone')}</button>
                {row.last_error && <div className="error small">{row.last_error}</div>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!links.length && !error && (
        <p className="empty">{t('jira.empty')} {t('jira.empty.hint')}</p>
      )}
      <h2 className="section">{t('jira.linkTitle')}</h2>
      <div className="card">
        <div className="stack" style={{ gap: 8, flex: '1 1 320px', minWidth: 0 }}>
          <input value={search} placeholder={t('jira.searchPlaceholder')}
            onChange={(e) => { setSearch(e.target.value); setChosen(null) }} />
          {chosen && (
            <span className="muted">
              {t('jira.selected')} <strong>{chosen.title}</strong>
            </span>
          )}
          {searching && <span className="muted small">{t('search.loading')}</span>}
          {!searching && hits.length > 0 && (
            <div className="stack" style={{ gap: 2 }}>
              {hits.map((hit) => (
                <button key={hit.id} className="mini" style={{ textAlign: 'left' }}
                  onClick={() => choose(hit)}>
                  {hit.title} <span className="muted">
                    · {tOr('severity.' + String(hit.severity || '').toLowerCase(), hit.severity)}
                    {hit.project_slug ? ` · ${hit.project_slug}` : ''}
                  </span>
                </button>
              ))}
            </div>
          )}
          {!searching && search.trim().length >= 2 && !hits.length
            && !ID_SHAPE.test(search.trim()) && (
              <span className="muted small">{t('jira.searchEmpty')}</span>
            )}
        </div>
        <input placeholder={t('jira.projectKey')} value={form.project_key}
          onChange={(e) => setForm((f) => ({ ...f, project_key: e.target.value }))} />
        <button onClick={createLink}
          disabled={!configured || !form.finding_id || !form.project_key.trim()}>
          {t('jira.createLink')}
        </button>
      </div>
      <p className="muted small">{t('jira.note')}</p>
    </div>
  )
}
