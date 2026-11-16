import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import { Card, EmptyState, ErrorBanner, Loading, SeverityBadge, Table, queueHash } from './ui'
import { useI18n } from './i18n'

/* One advisory, as a page. The list groups by (signature, component) because the
   fix is one upgrade per package; this screen asks the other question — "what
   does this CVE touch here" — so it merges every package that names it and splits
   the answer into the two things a reader triages: affected components (or the
   asset itself when no component was ever attached) and the findings behind them.

   Everything is read from one endpoint so the three tables cannot disagree, and
   an absent answer states its reason: no finding is not the same as unaffected. */

const LEVEL = { N: 'none', L: 'low', H: 'high' }

/* `CVSS:3.1/AV:N/AC:L/…/C:H/I:H/A:N` — only the three impact metrics are read;
   the rest of the vector stays whole on the page, which is how it is quoted. */
function vectorParts(vector) {
  const out = {}
  for (const part of String(vector || '').split('/')) {
    const [key, value] = part.split(':')
    if (key && value && key.length === 2) out[key] = value
  }
  return out
}

function when(value, fallback) {
  if (!value) return fallback
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString()
}

/* "Affected: lodash" is a fact; "lodash came in through vite 5.4.0" is the
   decision. A direct package is upgraded in the manifest; a transitive one is
   upgraded — or pinned — through its parent, and the parent's own parent is what
   a full path would print. The cell names the hop you act on and counts the rest:
   a five-hop path in every row is a wall, and the build graph already draws it.
   A BOM that declares no parent is not the same as a top-level package. */
function chainPath(chain) {
  return (chain || []).map((hop) => (hop.version ? `${hop.name} ${hop.version}` : hop.name))
}

function howItGotIn(row, t) {
  const path = chainPath(row.chain)
  if (path.length) {
    return path.length > 1
      ? t('cve.how.viaMore', { path: path[0], n: path.length - 1 })
      : t('cve.how.via', { path: path[0] })
  }
  if (row.direct) return t('cve.how.direct')
  return t('cve.how.unknown')
}

export default function CveDetail({ cveId, onBack, onOpenComponent, onOpenAsset }) {
  const { t, tCount, tOr } = useI18n()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState([])
  const [preview, setPreview] = useState(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')

  useEffect(() => { load() }, [cveId])

  async function load() {
    setLoading(true)
    setError('')
    setPreview(null)
    setSelected([])
    try {
      const body = await api.get(`/api/v1/vulnerabilities/advisory/${encodeURIComponent(cveId)}`)
      setData(body.data || body)
    } catch (err) {
      setError(err.message || String(err))
      setData(null)
    } finally {
      setLoading(false)
    }
  }

  const kev = data?.enrichment?.kev || {}
  const epss = data?.enrichment?.epss || {}
  const totals = data?.affected?.totals || {}
  const components = data?.affected?.components || []
  const assets = data?.affected?.assets || []
  const findings = data?.findings || []
  const metrics = useMemo(() => vectorParts(data?.cvss?.vector), [data?.cvss?.vector])
  const openFindings = useMemo(() => findings.filter((row) => !row.settled), [findings])

  async function previewBulk() {
    if (!selected.length) return
    setBusy(true)
    try {
      const result = await api.post(
        `/api/v1/vulnerabilities/${encodeURIComponent(cveId)}/bulk-preview`,
        { finding_ids: selected, status: 'resolved' })
      setPreview(result.data)
    } catch (err) {
      setError(err.message || String(err))
    }
    setBusy(false)
  }

  async function applyBulk() {
    if (!preview) return
    setBusy(true)
    try {
      const result = await api.post(
        `/api/v1/vulnerabilities/${encodeURIComponent(cveId)}/bulk-status?actor=console`,
        { finding_ids: selected, status: 'resolved' })
      setNotice(t('vulnerabilities.notice.resolved', {
        changed: result.data.changed, cve: cveId,
      }) + (result.data.skipped.length
        ? t('vulnerabilities.notice.skipped', { n: result.data.skipped.length }) : ''))
      await load()
    } catch (err) {
      setError(err.message || String(err))
    }
    setBusy(false)
  }

  if (loading) return <Loading rows={5} label={t('cve.loading')} />
  if (error) return <ErrorBanner error={error} onRetry={load} />
  if (!data) return <EmptyState title={t('cve.notFound.title')} hint={t('cve.notFound.hint')} />

  const tone = data.risk?.label === 'critical' ? 'bad'
    : data.risk?.label === 'high' ? 'warn'
      : data.risk?.label === 'medium' ? 'warn' : 'ok'

  return (
    <div className="stack">
      <header className="run-hero">
        <div className="run-hero-main">
          <div className="run-eyebrow">
            <button className="linkish" onClick={onBack}>‹ {t('cve.back')}</button>
            <span className="run-dot">·</span>
            <span className="run-status">{t('cve.eyebrow')}</span>
            <span className={`run-health ${tone}`}>{t(`cve.risk.${data.risk?.label || 'low'}`)}</span>
            {kev.listed && <span className="run-live">{t('cve.kev.listed')}</span>}
          </div>
          <h1 className="run-title mono">{data.cve_id}</h1>
          <div className="run-meta">
            <span><SeverityBadge severity={data.severity} /></span>
            <span>{data.cvss?.score != null
              ? t(data.cvss.derived ? 'cve.score.derived' : 'cve.score',
                { score: data.cvss.score })
              : t('cve.score.unknown')}</span>
            <span>{epss.known
              ? t('cve.epss', { score: Math.round(Number(epss.score) * 100),
                percentile: epss.percentile })
              : t('cve.epss.unknown')}</span>
            <span>{t('cve.published', { when: when(data.published, t('cve.date.unknown')) })}</span>
          </div>
        </div>
        {data.url && (
          <div className="run-hero-actions">
            {/* Only a URL the advisory actually carries becomes a link. */}
            <a className="btn-ghost" href={data.url} target="_blank" rel="noreferrer">
              {t('cve.link.source')}
            </a>
          </div>
        )}
      </header>

      <p className={`run-verdict ${tone}`}>
        {t('cve.verdict.affected', { n: totals.rows || 0 })}
        {' · '}{t('cve.stat.components', { n: totals.components || 0 })}
        {' · '}{t('cve.stat.projects', { n: totals.projects || 0 })}
        {' · '}
        {/* The vulnerability is the fact; its findings are the instances. This is
            the door between the two, and it carries the advisory id so the queue
            opens on exactly these rows. */}
        <button className="linkish" title={t('findings.door')}
          onClick={() => { window.location.hash = queueHash({ q: data.cve_id, open: '1' }) }}>
          {t('cve.stat.open', { n: data.counters?.open || 0 })}
        </button>
      </p>

      <div className="cve-grid">
        <Card title={t('cve.description.title')}>
          {data.description
            ? <p className="cve-description">{data.description}</p>
            : <p className="muted">{t('cve.description.missing')}</p>}
          {kev.description && kev.description !== data.description && (
            <p className="cve-note muted">{kev.description}</p>
          )}
        </Card>

        <Card title={t('cve.impact.title')}>
          <dl className="asset-facts cve-facts">
            <dt>{t('cve.col.score')}</dt>
            <dd>
              {data.cvss?.score != null ? `${data.cvss.score} · ` : ''}
              {data.cvss?.vector
                ? <code className="cve-vector">{data.cvss.vector}</code>
                : <span className="muted">{data.cvss?.reason || t('cve.score.unknown')}</span>}
              {data.cvss?.derived && (
                <div className="muted cve-note">{t('cve.score.derivedHint')}</div>
              )}
            </dd>
            {metrics.C && (
              <>
                <dt>{t('cve.impact.metrics')}</dt>
                <dd className="asset-chips">
                  {['C', 'I', 'A'].filter((key) => metrics[key]).map((key) => (
                    <span key={key} className={`asset-chip cve-chip-${metrics[key]}`}>
                      {t(`cve.metric.${key}`)}: {t(`cve.level.${LEVEL[metrics[key]] || 'none'}`)}
                    </span>
                  ))}
                </dd>
              </>
            )}
            <dt>{t('cve.impact.epss')}</dt>
            <dd>{epss.known
              ? t('cve.epss', { score: Math.round(Number(epss.score) * 100),
                percentile: epss.percentile })
              : <span className="muted">{t('cve.epss.unknown')}</span>}</dd>
            <dt>{t('cve.col.kev')}</dt>
            <dd>
              {kev.listed
                ? t('cve.kev.dates', {
                  added: when(kev.date_added, t('cve.date.unknown')),
                  due: when(kev.due_date, t('cve.date.unknown')),
                })
                : <span className="muted">{kev.reason || t('cve.kev.notListed')}</span>}
              {kev.ransomware && kev.ransomware.toLowerCase() !== 'unknown' && (
                <div className="cve-alert">{t('cve.kev.ransomware', { value: kev.ransomware })}</div>
              )}
            </dd>
            {kev.required_action && (
              <>
                <dt>{t('cve.kev.action')}</dt>
                <dd>{kev.required_action}</dd>
              </>
            )}
            {kev.cwes && (<><dt>CWE</dt><dd className="mono">{kev.cwes}</dd></>)}
            {data.sources?.length > 0 && (
              <><dt>{t('cve.impact.sources')}</dt>
                <dd className="muted">{data.sources.join(' · ')}</dd></>
            )}
            {data.risk?.reasons?.length > 0 && (
              <><dt>{t('cve.impact.why')}</dt>
                <dd className="muted">{data.risk.reasons.join(' · ')}</dd></>
            )}
          </dl>
        </Card>
      </div>

      <Card
        title={t('cve.affected.title')}
        actions={<span className="muted">{t('cve.affected.count', {
          rows: totals.rows || 0, components: totals.components || 0 })}</span>}>
        {components.length ? (
          <Table head={[t('cve.col.project'), t('cve.col.component'), t('cve.col.version'),
            t('cve.col.build'), t('common.severity'), t('cve.col.findings'),
            t('cve.col.fix')]}>
            {components.map((row, index) => (
              <tr key={`${row.project?.slug || 'none'}-${row.component?.id || 'project'}-${index}`}>
                <td className="mono">{row.project?.slug || t('cve.project.none')}</td>
                <td>
                  {row.component ? (
                    <button className="linkish mono"
                      onClick={() => onOpenComponent && onOpenComponent(row.component.id)}>
                      {row.component.name}
                    </button>
                  ) : <span className="muted">{t('cve.affected.projectLevel')}</span>}
                  {row.chain?.length > 0 && (
                    /* The path rides with the package instead of owning a column:
                       it is one fact about this row, and it is what decides
                       whether the fix is a version bump or a different parent.
                       The whole chain is in the tooltip, not in the cell. */
                    <div className="muted" style={{ fontSize: 11.5, whiteSpace: 'normal' }}
                      title={chainPath(row.chain).join(' → ')}>
                      {howItGotIn(row, t)}
                    </div>
                  )}
                </td>
                <td className="mono muted">{row.component?.version || '—'}</td>
                <td className="mono muted">{row.build?.version || '—'}</td>
                <td><SeverityBadge severity={row.severity} /></td>
                <td>
                  {row.findings}
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {t('cve.openCount', { n: row.open_findings })}
                  </div>
                </td>
                <td className="mono">
                  {row.fixed_versions?.length
                    ? row.fixed_versions.join(', ')
                    : <span className="muted">{t('cve.fix.none')}</span>}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <EmptyState
            title={t('cve.affected.empty.title')}
            hint={data.coverage?.note || t('cve.affected.empty.hint')} />
        )}
      </Card>

      {assets.length > 0 && (
        <Card title={t('cve.assets.title')}
          actions={<span className="muted">{t('cve.assets.count', { n: assets.length })}</span>}>
          <Table head={[t('cve.col.project'), t('cve.col.asset'), t('common.severity'),
            t('cve.col.findings')]}>
            {assets.map((row) => (
              <tr key={row.id}>
                <td className="mono muted">{row.project?.slug || t('cve.project.none')}</td>
                <td>
                  <button className="linkish mono"
                    onClick={() => onOpenAsset && onOpenAsset(row.id)}>
                    {row.asset?.value || row.id}
                  </button>
                  {row.asset?.type && (
                    <div className="muted" style={{ fontSize: 11.5 }}>{row.asset.type}</div>
                  )}
                </td>
                <td><SeverityBadge severity={row.severity} /></td>
                <td>{row.findings}
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {t('cve.openCount', { n: row.open_findings })}
                  </div>
                </td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      <Card
        title={t('cve.findings.title')}
        actions={openFindings.length > 0 && (
          <div className="row">
            <button className="mini" disabled={!selected.length || busy}
              onClick={previewBulk}>
              {tCount('vulnerabilities.bulk.preview', selected.length)}
            </button>
            {preview && (
              <button className="mini" disabled={busy || !preview.would_change}
                onClick={applyBulk}>
                {t('vulnerabilities.bulk.apply', { n: preview.would_change })}
              </button>
            )}
          </div>
        )}>
        {notice && <div className="banner banner-ok">{notice}</div>}
        {preview && (
          <p className="muted cve-note">
            {t('vulnerabilities.bulk.summary', {
              changed: preview.would_change, unchanged: preview.unchanged,
              skipped: preview.skipped.length,
            })}
          </p>
        )}
        {findings.length ? (
          <Table head={['', t('cve.col.finding'), t('cve.col.project'),
            t('cve.col.component'), t('common.severity'), t('common.status'),
            t('cve.col.seen')]}>
            {findings.map((row) => (
              <tr key={row.id}>
                <td>
                  <input type="checkbox" checked={selected.includes(row.id)}
                    disabled={row.settled}
                    onChange={(event) => setSelected((current) => (
                      event.target.checked ? [...current, row.id]
                        : current.filter((id) => id !== row.id)))} />
                </td>
                <td className="mono">
                  <button className="linkish"
                    onClick={() => { window.location.hash = `findings::${row.id}` }}>
                    {row.id.slice(0, 8)}
                  </button>
                  <div className="muted vuln-title">{row.path || row.title}</div>
                </td>
                <td className="mono muted">{row.project || '—'}</td>
                <td>
                  {row.component
                    ? <span className="mono">{row.component}
                      <span className="muted"> {row.component_version}</span></span>
                    : row.asset
                      ? <span className="mono">{row.asset.value}</span>
                      : <span className="muted">—</span>}
                  {row.build && <div className="muted" style={{ fontSize: 11.5 }}>{row.build}</div>}
                </td>
                <td><SeverityBadge severity={row.severity} /></td>
                <td>
                  <span className={row.settled ? 'muted' : 'pill'}>
                    {tOr(`status.${row.status}`, row.status)}
                  </span>
                </td>
                <td className="muted">
                  {when(row.last_seen_at, '—')}
                  <div style={{ fontSize: 11.5 }}>{row.tool || '—'}</div>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <EmptyState title={t('cve.findings.empty.title')} hint={t('cve.findings.empty.hint')} />
        )}
      </Card>
    </div>
  )
}
