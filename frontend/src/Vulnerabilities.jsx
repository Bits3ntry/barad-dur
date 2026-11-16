import React, { useEffect, useRef, useState } from 'react'
import { api } from './api'
import { EmptyState, ErrorBanner, PageHeader, Pager, SeverityBadge, Table, Tabs,
         serverPager } from './ui'
import VulnWorld from './VulnWorld'
import { useI18n } from './i18n'

/* Vulnerabilities is an aggregate over findings this organization actually has,
   not a catalog browser. Every number links back to concrete finding ids, and
   anything v0 cannot know (version ranges, exploit availability) says unknown
   with the reason instead of rendering a zero. */

const EMPTY_FILTERS = { q: '', severity: '', kev: false, project: '' }
const PER_PAGE = 25
// The list used to keep its question in component state only, so opening an
// advisory and coming back reset every filter — the reader's work was lost on the
// one navigation this screen now makes. The question outlives the visit.
const FILTER_KEY = 'barad.vuln.filters'

function storedFilters() {
  try {
    const raw = JSON.parse(localStorage.getItem(FILTER_KEY) || 'null')
    return raw && typeof raw === 'object' ? { ...EMPTY_FILTERS, ...raw } : null
  } catch {
    return null
  }
}

function EnrichmentCell({ enrichment }) {
  const { t } = useI18n()
  const kev = enrichment.kev
  const epss = enrichment.epss
  return (
    <div className="stack" style={{ gap: 2 }}>
      <span className={kev.listed ? 'sev sev-high' : 'muted'}>
        {kev.listed
          ? t('vulnerabilities.kev.added', {
            date: kev.date_added || t('vulnerabilities.kev.dateUnknown'),
          })
          : t('vulnerabilities.kev.notListed')}
      </span>
      <span className="muted" style={{ fontSize: 11.5 }}>
        {epss.known
          ? t('vulnerabilities.epss.known', {
            score: Math.round(Number(epss.score) * 100), percentile: epss.percentile,
          })
          : t('vulnerabilities.epss.unknown')}
      </span>
      <span className="muted" style={{ fontSize: 11.5 }}>
        {commissioned(kev, epss, t)}
      </span>
    </div>
  )
}

function commissioned(kev, epss, t) {
  if (!kev.known && !epss.known) return t('vulnerabilities.enrichment.none')
  const stamp = kev.known ? kev.fetched_at : epss.fetched_at
  return stamp
    ? t('vulnerabilities.enrichment.enriched', { date: new Date(stamp).toLocaleDateString() })
    : t('vulnerabilities.enrichment.dateUnknown')
}

export default function Vulnerabilities({ onNavigate, onOpenCve, focus = {} }) {
  const { t, tCount, tOr } = useI18n()
  // Two readings of the same word: what this estate has (`estate`) and what the world
  // published (`world`). They are different questions with different filters, and
  // mixing them was the reason "¿me afecta?" could only be asked as "¿tengo el
  // finding?".
  const [scope, setScope] = useState(focus.scope === 'world' ? 'world' : 'estate')
  // A deep link may arrive with the question already asked (the dashboard's
  // "known exploited" KPI). The filter is the screen's own state; the hash only
  // seeds it, so the reader can clear it without leaving the list.
  const [filters, setFilters] = useState(() => {
    const seeded = {
      ...EMPTY_FILTERS,
      ...(focus.kev ? { kev: true } : {}),
      ...(focus.severity ? { severity: focus.severity } : {}),
      ...(focus.q ? { q: focus.q } : {}),
      ...(focus.project ? { project: focus.project } : {}),
    }
    // A link that names the question wins; otherwise the last one this reader
    // asked is still the question.
    const asked = focus.kev || focus.severity || focus.q || focus.project
    return asked ? seeded : (storedFilters() || seeded)
  })
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [projects, setProjects] = useState([])
  const [error, setError] = useState('')
  const [offset, setOffset] = useState(0)
  const pager = serverPager(total, PER_PAGE, offset, setOffset)

  // Paging and filtering share the offset: a new question starts at page one,
  // so `apply` only reloads when it is already there. The world tab owns its data.
  useEffect(() => { if (scope === 'estate') load() }, [offset, scope])
  useEffect(() => {
    api.get('/api/v1/projects').then((r) => setProjects(r.data || [])).catch(() => setProjects([]))
  }, [])

  // The screen can already be mounted when a second link arrives (search while
  // reading this list): the hash is the question, so it re-seeds the filter
  // instead of being ignored because the component did not remount.
  const appliedFocus = useRef('')
  useEffect(() => {
    if (!focus.cve && !focus.q) return
    const key = `${focus.q || ''}|${focus.cve || ''}|${focus.project || ''}`
    if (appliedFocus.current === key) return
    appliedFocus.current = key
    const next = { ...EMPTY_FILTERS, q: focus.q || focus.cve,
      severity: focus.severity || '', kev: Boolean(focus.kev),
      project: focus.project || '' }
    setFilters(next)
    setOffset(0)
    load(next, 0)
  }, [focus.cve, focus.q, focus.project])

  function load(overrides = filters, atOffset = offset) {
    const params = new URLSearchParams()
    if (overrides.q.trim()) params.set('q', overrides.q.trim())
    if (overrides.severity) params.set('severity', overrides.severity)
    if (overrides.kev) params.set('kev_only', 'true')
    if (overrides.project) params.set('project', overrides.project)
    params.set('limit', PER_PAGE)
    params.set('offset', atOffset)
    // Written before the request so the question survives a navigation that
    // happens while it is still in flight (click a row fast enough).
    try { localStorage.setItem(FILTER_KEY, JSON.stringify(overrides)) } catch { /* private mode */ }
    api.get(`/api/v1/vulnerabilities?${params}`)
      .then((r) => { setRows(r.data || []); setTotal(r.total || 0) })
      .catch((e) => setError(String(e.message || e)))
  }

  // One row is one problem: opening it is a page of its own (`/cve/<id>`), not a
  // drawer under the table — the advisory needs its description, its impact, the
  // components it touches and the findings behind it, and none of that fits in a
  // detail row without turning the list into two screens at once.
  function open(row) {
    if (onOpenCve) onOpenCve(row.cve_id || row.signature)
  }

  return (
    <div className="stack">
      <PageHeader
        title={t('vulnerabilities.title')}
        subtitle={scope === 'estate'
          ? tCount('vulnerabilities.subtitle', total)
          : t('vulnerabilities.world.lead')}
      />

      <Tabs
        tabs={[
          { id: 'estate', label: t('vulnerabilities.world.estateTab') },
          { id: 'world', label: t('vulnerabilities.world.tab') },
        ]}
        active={scope}
        onChange={setScope}
      />

      {scope === 'world' ? <VulnWorld onOpenCve={onOpenCve} /> : (<>
      <div className="toolbar">
        <input placeholder={t('vulnerabilities.searchPlaceholder')} value={filters.q}
          onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && load()} />
        <select value={filters.severity}
          onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}>
          <option value="">{t('vulnerabilities.filter.anySeverity')}</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((value) => (
            <option key={value} value={value}>
              {tOr('severity.' + value.toLowerCase(), value.toLowerCase())}
            </option>
          ))}
        </select>
        <select value={filters.project}
          onChange={(e) => setFilters((f) => ({ ...f, project: e.target.value }))}>
          <option value="">{t('vulnerabilities.filter.everyProject')}</option>
          {projects.map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}
        </select>
        <label className="check">
          <input type="checkbox" checked={filters.kev}
            onChange={(e) => setFilters((f) => ({ ...f, kev: e.target.checked }))} />
          <span>{t('vulnerabilities.filter.kevOnly')}</span>
        </label>
        <button onClick={() => (offset === 0 ? load() : setOffset(0))}>{t('vulnerabilities.apply')}</button>
        <span className="row-end">
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit={t('vulnerabilities.unit')} />
        </span>
      </div>

      {error && <ErrorBanner error={error} />}

      {rows.length ? (
        <Table className="vuln-table" head={[t('vulnerabilities.col.cve'), t('common.severity'),
          t('vulnerabilities.col.findings'), t('vulnerabilities.col.projects'),
          t('vulnerabilities.col.signals')]}>
          {rows.map((row) => (
            /* The row is the door: the id is the button for the keyboard, the row
               for the pointer, and the last column this replaces held nothing the
               first one did not. */
            <tr key={row.cve_id || row.id} className="row-link"
              onClick={() => open(row)}>
              <td className="title mono">
                <button className="linkish mono" onClick={() => open(row)}>
                  {row.cve_id || row.signature}
                </button>
                {/* Priority is a property of the advisory, so it rides with its
                    name instead of owning a column that is empty on most rows. */}
                {row.priority && (
                  <span className={`prio prio-${row.priority.toLowerCase()}`}>{row.priority}</span>
                )}
                {row.title && (
                  /* One line, clamped: the full description belongs to the
                     advisory page. A paragraph inside a nowrap table cell made the
                     table 2.8k wider than its card and every column slid. */
                  <div className="muted vuln-title">{row.title}</div>
                )}
              </td>
              <td><SeverityBadge severity={row.severity} /></td>
              <td>
                {row.findings}
                <div className="muted" style={{ fontSize: 11.5 }}>
                  {t('vulnerabilities.openCount', { n: row.open_findings })}
                </div>
                {/* The row is the vulnerability, not the package: when it takes
                    more than one package to close, the list says so here and the
                    advisory page is where each upgrade is a line. */}
                {row.components?.length > 1 && (
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {tCount('vulnerabilities.packages', row.components.length)}
                  </div>
                )}
              </td>
              <td className="muted wrap">
                {row.projects.map((p) => p.slug).join(', ') || '—'}
                <div style={{ fontSize: 11.5 }}>
                  {row.assets.count} · {row.assets.coverage === 'complete'
                    ? t('vulnerabilities.asset.linked')
                    : t('vulnerabilities.asset.none')}
                </div>
              </td>
              <td className="wrap"><EnrichmentCell enrichment={row.enrichment} /></td>
            </tr>
          ))}
        </Table>
      ) : (
        !error && <EmptyState title={t('vulnerabilities.empty.title')}
          hint={t('vulnerabilities.empty.hint')} />
      )}
      {pager.pages > 1 && (
        <div className="row row-end" style={{ marginTop: 10 }}>
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit={t('vulnerabilities.unit')} />
        </div>
      )}
      </>)}
    </div>
  )
}
