import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Pager, Stat, Table, usePage } from './ui'
import { useI18n } from './i18n'

/* Business impact answers one question per application: how much open work is
   there, how much is late, and what carries it. It is a count of real rows, not
   a score — the API says `criticality: not modelled` and the page repeats it,
   because a weighted number with no source is worse than no number. */

const PER_PAGE = 25

function priorityCells(row) {
  return ['P0', 'P1', 'P2', 'P3'].map((cls) => (
    <td key={cls} className={row.by_priority[cls] ? `prio prio-${cls.toLowerCase()}` : 'muted'}>
      {row.by_priority[cls] || '—'}
    </td>
  ))
}

export default function BusinessImpact({ onNavigate }) {
  const { t, tCount } = useI18n()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  function load() {
    setLoading(true)
    setError('')
    api.get('/api/v1/business-impact')
      .then((r) => setData(r))  // the endpoint answers {data, totals, coverage, model}
      .catch((e) => setError(String(e.message || e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const rows = data?.data || []
  const totals = data?.totals || {}
  const coverage = data?.coverage || {}
  // An org can have hundreds of applications; the ranking is the point, so the
  // top of the list is what loads, not the whole table.
  const paged = usePage(rows, PER_PAGE)

  return (
    <div className="stack">
      <PageHeader
        title={t('impact.title')}
        subtitle={t('impact.subtitle')}
        actions={<button className="mini" onClick={load}>{t('common.refresh')}</button>}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      {!error && loading && <Card><Loading rows={4} /></Card>}

      {!error && !loading && data && (
        <>
          <div className="row" style={{ flexWrap: 'wrap' }}>
            <Stat value={totals.projects ?? 0}
              label={tCount('impact.stat.applications', totals.projects ?? 0)} />
            <Stat value={totals.open_findings ?? 0}
              label={tCount('impact.stat.openFindings', totals.open_findings ?? 0)} />
            <Stat value={totals.assets ?? 0}
              label={tCount('impact.stat.assets', totals.assets ?? 0)} />
            <Stat value={totals.production_deployments ?? 0}
              label={tCount('impact.stat.deployments', totals.production_deployments ?? 0)} />
            <Stat value={coverage.assets_without_project ?? 0}
              label={tCount('impact.stat.assetsWithoutProject', coverage.assets_without_project ?? 0)}
              hint={t('impact.stat.assetsWithoutProject.hint')} />
          </div>

          <div className="toolbar">
            <span className="count">{tCount('impact.count.applications', rows.length)}</span>
            <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
              total={paged.total} perPage={paged.perPage} unit={t('impact.unit.applications')}
              className="row-end" />
          </div>

          <Card title={t('impact.table.title')}>
            <Table
              head={[t('impact.col.project'), t('impact.col.open'), 'P0', 'P1', 'P2', 'P3',
                t('impact.col.untriaged'), t('impact.col.late'), t('impact.col.unassigned'),
                t('impact.col.cves'), t('impact.col.assets'), t('impact.col.prodDeploys'),
                t('impact.col.lastSeen')]}
              empty={rows.length === 0}
            >
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={13}>
                    <EmptyState title={t('impact.empty.title')}
                      hint={t('impact.empty.hint')} />
                  </td>
                </tr>
              ) : paged.rows.map((row) => (
                <tr key={row.project}>
                  <td>
                    <button className="link" onClick={() => onNavigate && onNavigate('findings')}>
                      {row.name}
                    </button>
                    <div className="muted mono" style={{ fontSize: 11 }}>{row.project}</div>
                  </td>
                  <td><strong>{row.open_findings}</strong></td>
                  {priorityCells(row)}
                  <td className={row.untriaged ? '' : 'muted'}>{row.untriaged || '—'}</td>
                  <td className={row.sla_breached ? 'bad' : 'muted'}>{row.sla_breached || '—'}</td>
                  <td className={row.unassigned ? '' : 'muted'}>{row.unassigned || '—'}</td>
                  <td className="muted">{row.cves || '—'}</td>
                  <td className="muted">{row.assets || '—'}</td>
                  <td className="muted">{row.production_deployments || '—'}</td>
                  <td className="muted">
                    {row.last_seen_at ? new Date(row.last_seen_at).toLocaleDateString() : t('common.never')}
                  </td>
                </tr>
              ))}
            </Table>
          </Card>

          <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
            total={paged.total} perPage={paged.perPage} unit={t('impact.unit.applications')}
            className="row-end" />

          <Card title={t('impact.caveat.title')}>
            <p className="muted" style={{ margin: 0 }}>
              {t('impact.caveat.body', {
                note: data.model?.note || t('impact.caveat.note'),
                criticality: data.model?.criticality || t('common.unknown'),
                n: coverage.projects_without_assets ?? 0,
              })}
            </p>
          </Card>
        </>
      )}
    </div>
  )
}
