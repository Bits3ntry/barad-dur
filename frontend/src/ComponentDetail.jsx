import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, SeverityBadge, Table } from './ui'
import { useI18n } from './i18n'

/* One component, as a page: the mirror of the advisory screen. A component is a
   package@version, so the question here is "what does this thing carry, and where
   does it ship" — every advisory is a row, grouped because that is what somebody
   fixes, with the builds that carry it above it.

   The list under `#components` is the deployed tree (project → component →
   build); this is the sheet for the package itself, reached from an advisory or
   from a build, and it never invents a level the data does not have. */

function when(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString()
}

export default function ComponentDetail({ componentId, onBack, onOpenCve, onOpenVersion }) {
  const { t, tCount } = useI18n()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => { load() }, [componentId])

  async function load() {
    setLoading(true)
    setError('')
    try {
      const body = await api.get(`/api/v1/components/${encodeURIComponent(componentId)}`)
      setData(body.data || body)
    } catch (err) {
      setError(err.message || String(err))
      setData(null)
    } finally {
      setLoading(false)
    }
  }

  if (loading) return <Loading rows={5} label={t('componentSheet.loading')} />
  if (error) return <ErrorBanner error={error} onRetry={load} />
  if (!data) return (
    <EmptyState title={t('componentSheet.notFound.title')}
      hint={t('componentSheet.notFound.hint')} />
  )

  const component = data.component || {}
  const usage = data.usage || { projects: [], totals: {} }
  const counters = data.counters || {}
  const advisories = data.advisories || []
  const open = counters.open || 0
  const tone = open === 0 ? 'ok' : (counters.kev ? 'bad' : 'warn')

  return (
    <div className="stack">
      <header className="run-hero">
        <div className="run-hero-main">
          <div className="run-eyebrow">
            <button className="linkish" onClick={onBack}>‹ {t('componentSheet.back')}</button>
            <span className="run-dot">·</span>
            <span className="run-status">{t('componentSheet.eyebrow')}</span>
            {counters.kev > 0 && (
              <span className="run-health bad">{t('componentSheet.kevBadge')}</span>
            )}
          </div>
          <h1 className="run-title">
            {component.name || component.identity_key}
            {component.version && <span className="mono"> {component.version}</span>}
          </h1>
          <div className="run-chips">
            {component.purl && <span className="run-chip">{component.purl}</span>}
            {component.license && (
              <span className="run-chip">{t('componentSheet.license', { name: component.license })}</span>
            )}
          </div>
          <div className="run-meta">
            <span>{t('componentSheet.projects', { n: usage.totals?.projects || 0 })}</span>
            <span>{t('componentSheet.builds', { n: usage.totals?.builds || 0 })}</span>
            <span>{t('componentSheet.direct', { n: usage.totals?.direct || 0 })}</span>
          </div>
        </div>
      </header>

      <p className={`run-verdict ${tone}`}>
        {t('componentSheet.stat.advisories', { n: counters.advisories || 0 })}
        {' · '}{t('componentSheet.stat.open', { n: open })}
        {' · '}{t('componentSheet.stat.kev', { n: counters.kev || 0 })}
        {' · '}{t('componentSheet.stat.fixable', { n: counters.fixable || 0 })}
      </p>

      <Card
        title={t('componentSheet.usage.title')}
        actions={<span className="muted">{tCount('componentSheet.usage.count',
          usage.totals?.builds || 0)}</span>}>
        {usage.projects?.length ? (
          <Table head={[t('componentSheet.col.project'), t('componentSheet.col.build'),
            t('componentSheet.col.how'), t('componentSheet.col.manifest'),
            t('componentSheet.col.findings')]}>
            {usage.projects.flatMap((group) => group.builds.map((row) => (
              <tr key={row.version.id}>
                <td className="mono">{group.project.slug}</td>
                <td>
                  <button className="linkish mono"
                    onClick={() => onOpenVersion && onOpenVersion(
                      group.project.slug, undefined, row.version.label, row.version.id)}>
                    {row.version.label}
                  </button>
                </td>
                <td className="muted">
                  {/* The chain is the answer to "why do I have this": a package the
                      BOM hangs off another one is upgraded — or pinned — through
                      that parent, not by editing this manifest line. */}
                  {row.chain?.length
                    ? <span title={row.chain.map((hop) => (hop.version
                        ? `${hop.name} ${hop.version}` : hop.name)).join(' → ')}>
                        {t('componentSheet.how.via', {
                          path: [row.chain[0].name, row.chain[0].version]
                            .filter(Boolean).join(' '),
                        })}
                      </span>
                    : row.direct
                      ? t('componentSheet.how.direct')
                      : t('componentSheet.how.transitive')}
                </td>
                <td className="mono muted">{row.manifest || '—'}</td>
                <td>
                  {row.findings}
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {t('cve.openCount', { n: row.open_findings })}
                  </div>
                </td>
              </tr>
            )))}
          </Table>
        ) : (
          <EmptyState title={t('componentSheet.usage.empty.title')}
            hint={t('componentSheet.usage.empty.hint')} />
        )}
      </Card>

      <Card
        title={t('componentSheet.advisories.title')}
        actions={<span className="muted">{t('componentSheet.advisories.count',
          { n: counters.advisories || 0 })}</span>}>
        {advisories.length ? (
          <Table head={[t('cve.col.cve'), t('common.severity'), t('cve.col.score'),
            t('cve.col.kev'), t('cve.col.fix'), t('cve.col.findings'),
            t('cve.col.projects')]}>
            {advisories.map((row) => (
              <tr key={row.ref}>
                <td className="title mono">
                  <button className="linkish" onClick={() => onOpenCve && onOpenCve(row.ref)}>
                    {row.ref}
                  </button>
                  {row.title && (
                    /* The advisory's own paragraph: two clamped lines. A cell is
                       nowrap here, so without this the title widens every column
                       of the table instead of wrapping inside its own. */
                    <div className="muted cve-row-title vuln-title">{row.title}</div>
                  )}
                </td>
                <td><SeverityBadge severity={row.severity} /></td>
                <td className="mono muted">
                  {row.cvss?.score != null ? row.cvss.score : '—'}
                  {row.cvss?.derived && (
                    <span title={t('cve.score.derivedHint')}>*</span>
                  )}
                </td>
                <td>
                  {row.kev
                    ? <span className="sev sev-high">KEV</span>
                    : <span className="muted">—</span>}
                </td>
                <td className="mono">
                  {row.fix?.available
                    ? row.fix.versions.join(', ')
                    : <span className="muted">{t('cve.fix.none')}</span>}
                </td>
                <td>
                  {row.findings}
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {t('cve.openCount', { n: row.open_findings })}
                  </div>
                </td>
                <td className="muted mono">{row.projects?.join(', ') || '—'}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <EmptyState title={t('componentSheet.advisories.empty.title')}
            hint={t('componentSheet.advisories.empty.hint')} />
        )}
        <p className="muted cve-note">{data.coverage?.kind} · {data.coverage?.scanned}</p>
      </Card>
    </div>
  )
}
