import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, PageHeader, Pager, Stat, Table, usePage } from './ui'

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
        title="Business impact"
        subtitle="Open work per application, counted from findings, assets and deployments"
        actions={<button className="mini" onClick={load}>refresh</button>}
      />

      {error && <ErrorBanner error={error} onRetry={load} />}

      {!error && loading && <Card><Loading rows={4} /></Card>}

      {!error && !loading && data && (
        <>
          <div className="row" style={{ flexWrap: 'wrap' }}>
            <Stat value={totals.projects ?? 0}
              label={totals.projects === 1 ? 'application' : 'applications'} />
            <Stat value={totals.open_findings ?? 0}
              label={totals.open_findings === 1 ? 'open finding' : 'open findings'} />
            <Stat value={totals.assets ?? 0}
              label={totals.assets === 1 ? 'asset' : 'assets'} />
            <Stat value={totals.production_deployments ?? 0}
              label={totals.production_deployments === 1
                ? 'production deployment' : 'production deployments'} />
            <Stat value={coverage.assets_without_project ?? 0}
              label={coverage.assets_without_project === 1
                ? 'asset without project' : 'assets without project'}
              hint="coverage gap, not a business signal" />
          </div>

          <div className="toolbar">
            <span className="count">{rows.length} application{rows.length === 1 ? '' : 's'}</span>
            <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
              total={paged.total} perPage={paged.perPage} unit="applications"
              className="row-end" />
          </div>

          <Card title="Per application">
            <Table
              head={['PROJECT', 'OPEN', 'P0', 'P1', 'P2', 'P3', 'UNTRIAGED', 'LATE', 'UNASSIGNED',
                'CVES', 'ASSETS', 'PROD DEPLOYS', 'LAST SEEN']}
              empty={rows.length === 0}
            >
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={13}>
                    <EmptyState title="No applications yet"
                      hint="Impact is counted per project; create one and import findings, assets or deployments." />
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
                    {row.last_seen_at ? new Date(row.last_seen_at).toLocaleDateString() : 'never'}
                  </td>
                </tr>
              ))}
            </Table>
          </Card>

          <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
            total={paged.total} perPage={paged.perPage} unit="applications"
            className="row-end" />

          <Card title="What this page does not claim">
            <p className="muted" style={{ margin: 0 }}>
              {data.model?.note || 'counts only'}.
              {' '}Criticality: {data.model?.criticality || 'unknown'} — so ranking
              applications here means “most open work”, not “most important”.
              {' '}{coverage.projects_without_assets ?? 0} application(s) have no asset
              linked; nothing was observed there, which is not the same as clean.
            </p>
          </Card>
        </>
      )}
    </div>
  )
}
