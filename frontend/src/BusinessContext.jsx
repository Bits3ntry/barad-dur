import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, Stat, Table, serverPager,
} from './ui'
import { useI18n } from './i18n'

/* The crown jewels are *components* — AUREA > Backend — and the screen shows only
   the ones somebody designated, the way OpenCTEM does it: the registry is reached
   through a search, not printed as a wall of undecided rows. An unfiled asset never
   appears here; it belongs to Discovery → Assets. */

const LEVELS = ['crown', 'high', 'normal', 'low']

export default function BusinessContext({ onNavigate }) {
  const { t, tOr } = useI18n()
  const [rows, setRows] = useState([])
  const [projects, setProjects] = useState([])
  const [summary, setSummary] = useState(null)
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busyId, setBusyId] = useState('')
  const [designateOpen, setDesignateOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [candidates, setCandidates] = useState([])
  const [pickLevel, setPickLevel] = useState('crown')
  const perPage = 50
  const pager = serverPager(total, perPage, offset, setOffset)

  useEffect(() => { load() }, [offset])
  useEffect(() => {
    if (!designateOpen) return
    const timer = setTimeout(() => {
      api.get(`/api/v1/business-context/candidates?limit=30&q=${encodeURIComponent(search)}`)
        .then((r) => setCandidates(r.data || []))
        .catch((e) => setError(String(e.message || e)))
    }, 220)
    return () => clearTimeout(timer)
  }, [designateOpen, search])

  function load() {
    const params = new URLSearchParams()
    params.set('limit', String(perPage))
    params.set('offset', String(offset))
    api.get(`/api/v1/business-context?${params}`)
      .then((r) => {
        setRows(r.data || [])
        setProjects(r.projects || [])
        setTotal(r.total || 0)
        setSummary(r.summary || null)
      })
      .catch((e) => setError(String(e.message || e)))
  }

  async function save(row, patch) {
    setBusyId(row.id)
    setError('')
    try {
      await api.patch(`/api/v1/business-context/components/${row.id}`, {
        ...patch, actor: 'console',
      })
      setNotice(t('business.notice.saved'))
      load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusyId('')
    }
  }

  async function designate(component) {
    setBusyId(component.id)
    setError('')
    try {
      await api.patch(`/api/v1/business-context/components/${component.id}`, {
        criticality: pickLevel, actor: 'console',
      })
      setDesignateOpen(false)
      setSearch('')
      setNotice(t('business.notice.designated', { name: component.name }))
      load()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusyId('')
    }
  }

  // Designated rows grouped by project: a project is context, the component is the
  // judgement, and only designated components are here at all.
  const groups = useMemo(() => {
    const meta = new Map(projects.map((item) => [item.slug, item]))
    const order = []
    const byProject = new Map()
    rows.forEach((row) => {
      const slug = row.project_slug || '—'
      if (!byProject.has(slug)) { byProject.set(slug, []); order.push(slug) }
      byProject.get(slug).push(row)
    })
    return order.map((slug) => ({
      slug,
      name: meta.get(slug)?.name || rows.find((r) => r.project_slug === slug)?.project_name,
      findings: meta.get(slug)?.findings_open ?? null,
      rows: byProject.get(slug),
    }))
  }, [rows, projects])

  const crown = summary?.crown ?? 0
  const registered = summary?.registered ?? 0

  return (
    <div className="stack">
      <PageHeader title={t('business.title')} subtitle={t('business.subtitle')}
        actions={(
          <div className="row" style={{ gap: 8 }}>
            {/* The work behind each jewel is the same two projects this screen
                ranks; reading it is a view of the jewel, not a sibling door. */}
            {onNavigate && (
              <button className="btn-ghost" onClick={() => onNavigate('business-impact')}>
                {t('nav.business-impact')} →
              </button>
            )}
            <button className="primary-action" onClick={() => setDesignateOpen(true)}>
              {t('business.action.designate')}
            </button>
          </div>
        )} />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      <p className="verdict-line">
        {registered
          ? t('business.verdict', { crown, registered,
            designated: summary?.components ?? 0 })
          : t('business.verdict.empty')}
      </p>

      <div className="metrics">
        <Stat value={summary?.crown ?? 0} label={t('business.level.crown')}
          hint={t('business.hint.jewelAssets', { n: summary?.jewel_assets ?? 0 })} />
        <Stat value={summary?.high ?? 0} label={t('business.level.high')} />
        <Stat value={summary?.normal ?? 0} label={t('business.level.normal')} />
        <Stat value={summary?.low ?? 0} label={t('business.level.low')} />
      </div>

      {rows.length ? (
        <div className="stack">
          {groups.map((group) => (
            <div className="stack" key={group.slug}>
              <div className="bc-group">
                <span className="bc-group-name">{group.name || group.slug}</span>
                {group.findings !== null && (
                  <span className="muted">
                    {t('business.groupFindings', { n: group.findings })}
                  </span>
                )}
              </div>
              <div className="bc-list">
                {group.rows.map((row) => (
                  <div className="bc-row" key={row.id}>
                    <div>
                      <span className="bc-value">{row.name}</span>
                      <span className="muted bc-sub">
                        {row.kind}{row.deployments
                          ? ` · ${t('business.counts', {
                            deployments: row.deployments,
                            environments: (row.environments || []).join(', ') || '—',
                            assets: row.assets, observed: row.observed_assets,
                          })}`
                          : ` · ${t('business.noDeployment')}`}
                      </span>
                      {row.business_service && (
                        <span className="muted bc-sub">
                          {row.business_service}{row.reason ? ` — ${row.reason}` : ''}
                        </span>
                      )}
                    </div>
                    <select value={row.criticality}
                      className={`bc-level bc-level-${row.criticality}`}
                      disabled={busyId === row.id}
                      onChange={(e) => save(row, { criticality: e.target.value })}>
                      {LEVELS.map((value) => (
                        <option key={value} value={value}>
                          {tOr(`business.level.${value}`, value)}
                        </option>
                      ))}
                    </select>
                    <input defaultValue={row.business_service || ''}
                      placeholder={t('business.hint.service')}
                      disabled={busyId === row.id}
                      onBlur={(e) => {
                        if (e.target.value !== (row.business_service || '')) {
                          save(row, { business_service: e.target.value })
                        }
                      }} />
                    <input defaultValue={row.reason || ''}
                      placeholder={t('business.hint.reason')}
                      disabled={busyId === row.id}
                      onBlur={(e) => {
                        if (e.target.value !== (row.reason || '')) {
                          save(row, { reason: e.target.value })
                        }
                      }} />
                  </div>
                ))}
              </div>
            </div>
          ))}
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={perPage} unit="components" className="row-end" />
        </div>
      ) : (
        !error && <EmptyState title={t('business.empty.title')}
          hint={t('business.empty.hint')} />
      )}

      <p className="muted">{t('business.note')}</p>

      <Dialog open={designateOpen} title={t('business.dialog.designate')}
        onClose={() => setDesignateOpen(false)} onConfirm={() => setDesignateOpen(false)}
        confirmLabel={t('business.dialog.close')}>
        <div className="stack">
          <Input label={t('business.dialog.search')} value={search}
            onChange={setSearch} hint={t('business.dialog.searchHint')} />
          <div className="row">
            <select value={pickLevel} onChange={(e) => setPickLevel(e.target.value)}>
              {LEVELS.map((value) => (
                <option key={value} value={value}>
                  {tOr(`business.level.${value}`, value)}
                </option>
              ))}
            </select>
          </div>
          {candidates.length ? (
            <Table head={[t('business.col.component'), t('business.col.project'),
              t('business.col.deployments'), '']}>
              {candidates.map((item) => (
                <tr key={item.id}>
                  <td className="title">{item.name}
                    <div className="muted" style={{ fontSize: 11.5 }}>{item.kind}</div>
                  </td>
                  <td className="muted">{item.project_name || item.project_slug}</td>
                  <td className="muted">{item.deployments}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="mini" disabled={busyId === item.id}
                      onClick={() => designate(item)}>
                      {t('business.action.designateRow')}
                    </button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            <span className="muted">{t('business.dialog.noCandidates')}</span>
          )}
        </div>
      </Dialog>
    </div>
  )
}
