import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Drawer, EmptyState, ErrorBanner, Pager, Table, serverPager } from './ui'
import { useI18n } from './i18n'

/* World: the exploit catalog as it is published, not as it happens to match this
   estate. Two questions live here and they are deliberately separate:

   * "¿hay algo nuevo?" — answered by `since` over the feed's own date_added;
   * "¿me toca?" — a hint built from rows we already hold (a finding for that CVE, or
     the product's name in a purl / host observation). It says look here; it never
     says "you are affected", because that is the applicability question.

   The feed is the boundary: nothing here makes a model call or opens the estate. */

const PER_PAGE = 25
const ISO = (date) => date.toISOString().slice(0, 10)

/* The catalogues the mirror merges. The API returns slugs; the screen needs a
   word a reader recognises, so each one is a translation key rather than a
   label baked into the backend. */
const SOURCE_LABEL = (slug, t) => t(`vulnerabilities.world.source.${slug}`)

/* Statuses are tokens because the screen translates them; a status that is a
   sentence can only be shown in one language. */
const STATUS_KEY = {
  connected: 'ok',
  'never synced': 'never',
  'credentials missing': 'noCredentials',
  error: 'error',
}

function weekAgo() {
  const date = new Date()
  date.setDate(date.getDate() - 7)
  return ISO(date)
}

function dueLabel(row, t) {
  if (row.days_to_due == null) return <span className="muted">—</span>
  if (row.days_to_due < 0) return t('vulnerabilities.world.overdue', { n: Math.abs(row.days_to_due) })
  if (row.days_to_due === 0) return t('vulnerabilities.world.dueToday')
  return t('vulnerabilities.world.dueIn', { n: row.days_to_due })
}

function freshness(iso, t) {
  if (!iso) return t('vulnerabilities.world.sources.never')
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return t('vulnerabilities.world.sources.never')
  const hours = Math.round((Date.now() - date.getTime()) / 3600000)
  if (hours < 1) return t('vulnerabilities.world.sources.hour')
  if (hours < 48) return t('vulnerabilities.world.sources.hours', { hours })
  return t('vulnerabilities.world.sources.days', { days: Math.round(hours / 24) })
}

const PILL_TONE = {
  connected: 'good',
  'credentials missing': 'warn',
  error: 'bad',
}

function sourceStatus(item, t) {
  return item.status === 'connected'
    ? t('vulnerabilities.world.sourceStatus.ok')
    : t(`vulnerabilities.world.sourceStatus.${STATUS_KEY[item.status] || 'error'}`)
}

/* The sources panel: every catalogue the mirror merges, what it published, how
   much of the mirror it accounts for, and how much of that nobody else lists.
   The pills in the toolbar say *that* three feeds answered; this says what each
   one is worth — a catalogue with zero exclusive rows is a second opinion, not a
   second source. */
function SourcesDrawer({ open, onClose, sources = [] }) {
  const { t } = useI18n()
  return (
    <Drawer open={open} title={t('vulnerabilities.world.sources.title')} onClose={onClose}>
      <p className="muted" style={{ fontSize: 12.5, marginTop: 0 }}>
        {t('vulnerabilities.world.sources.lead')}
      </p>
      <ul className="source-list">
        {sources.map((item) => (
          <li key={item.source}>
            <div className="row" style={{ gap: 8 }}>
              <strong>{SOURCE_LABEL(item.source, t)}</strong>
              <span className={`pill ${PILL_TONE[item.status] || ''}`}>
                {sourceStatus(item, t)}
              </span>
              <span className="row-end muted" style={{ fontSize: 11.5 }}>
                {freshness(item.last_ok_at, t)}
              </span>
            </div>
            <div className="source-counts">
              {t('vulnerabilities.world.sources.counts', {
                advertised: item.advertised, listed: item.listed,
                exclusive: item.exclusive,
              })}
            </div>
            {item.credential && (
              <div className="source-counts">
                {t('vulnerabilities.world.sources.credential', { name: item.credential })}
              </div>
            )}
            {item.error && (
              <div className="source-counts" style={{ overflowWrap: 'anywhere' }}>
                {item.error}
              </div>
            )}
            {item.url && (
              <div>
                <a href={item.url} target="_blank" rel="noreferrer"
                  style={{ fontSize: 12 }}>
                  {t('vulnerabilities.world.sources.feed')} ↗
                </a>
              </div>
            )}
          </li>
        ))}
      </ul>
      <p className="hint" style={{ marginTop: 14 }}>
        {t('vulnerabilities.world.sources.authority')}
      </p>
    </Drawer>
  )
}

export default function VulnWorld({ onOpenCve }) {
  const { t } = useI18n()
  const [filters, setFilters] = useState({
    since: weekAgo(), q: '', product: '', source: '', ransomware: false, matched: false,
  })
  const [sort, setSort] = useState('date_added')
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [counts, setCounts] = useState(null)
  const [coverage, setCoverage] = useState(null)
  const [openCve, setOpenCve] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [syncing, setSyncing] = useState(false)
  const [sourcesOpen, setSourcesOpen] = useState(false)
  const [offset, setOffset] = useState(0)
  const pager = serverPager(total, PER_PAGE, offset, setOffset)

  useEffect(() => { load() }, [offset, sort])

  function load() {
    const params = new URLSearchParams()
    if (filters.since) params.set('since', filters.since)
    if (filters.q.trim()) params.set('q', filters.q.trim())
    if (filters.product.trim()) params.set('product', filters.product.trim())
    if (filters.source) params.set('source', filters.source)
    if (filters.ransomware) params.set('ransomware', 'true')
    if (filters.matched) params.set('matched', 'true')
    params.set('sort', sort)
    params.set('limit', PER_PAGE)
    params.set('offset', offset)
    api.get(`/api/v1/intel/kev?${params}`)
      .then((r) => {
        setRows(r.data || [])
        setTotal(r.total || 0)
        setCounts(r.counts || null)
        setCoverage(r.coverage || null)
        setError('')
      })
      .catch((e) => setError(String(e.message || e)))
  }

  function apply() {
    if (offset === 0) load()
    else setOffset(0)
  }

  async function sync() {
    setSyncing(true)
    setNotice('')
    setError('')
    try {
      const result = await api.post('/api/v1/intel/sync', {})
      // A feed that did not answer is said out loud: "refreshed" over a mirror
      // one catalogue short is the kind of silence that hides a broken source.
      const failed = (result.data.sources || []).filter((item) => !item.ok)
        .map((item) => SOURCE_LABEL(item.source, t))
      setNotice(t('vulnerabilities.world.synced', { n: result.data.kev_fetched })
        + (failed.length
          ? ` · ${t('vulnerabilities.world.syncedPartial', { list: failed.join(', ') })}`
          : ''))
      setOffset(0)
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
    setSyncing(false)
  }

  const neverSynced = coverage && coverage.feed === 'never synced'

  return (
    <>
      <div className="toolbar">
        <label className="check">
          <span className="muted">{t('vulnerabilities.world.since')}</span>
          <input type="date" value={filters.since}
            onChange={(e) => setFilters((f) => ({ ...f, since: e.target.value }))} />
        </label>
        <input placeholder={t('vulnerabilities.world.searchPlaceholder')}
          value={filters.q}
          onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && apply()} />
        <input placeholder={t('vulnerabilities.world.productPlaceholder')}
          value={filters.product}
          onChange={(e) => setFilters((f) => ({ ...f, product: e.target.value }))}
          onKeyDown={(e) => e.key === 'Enter' && apply()} />
        <select value={filters.source}
          onChange={(e) => setFilters((f) => ({ ...f, source: e.target.value }))}>
          <option value="">{t('vulnerabilities.world.source.all')}</option>
          {(coverage?.sources || []).map((item) => (
            <option key={item.source} value={item.source}>
              {SOURCE_LABEL(item.source, t)}
            </option>
          ))}
        </select>
        <select value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="date_added">{t('vulnerabilities.world.sort.newest')}</option>
          <option value="due_date">{t('vulnerabilities.world.sort.dueDate')}</option>
          <option value="epss">{t('vulnerabilities.world.sort.epss')}</option>
          <option value="cve">{t('vulnerabilities.world.sort.cve')}</option>
        </select>
        <label className="check">
          <input type="checkbox" checked={filters.matched}
            onChange={(e) => setFilters((f) => ({ ...f, matched: e.target.checked }))} />
          <span>{t('vulnerabilities.world.filter.matched')}</span>
        </label>
        <label className="check">
          <input type="checkbox" checked={filters.ransomware}
            onChange={(e) => setFilters((f) => ({ ...f, ransomware: e.target.checked }))} />
          <span>{t('vulnerabilities.world.filter.ransomware')}</span>
        </label>
        <button onClick={apply}>{t('vulnerabilities.apply')}</button>
        <button className="mini" disabled={syncing} onClick={sync}>
          {syncing ? t('vulnerabilities.world.syncing') : t('vulnerabilities.world.sync')}
        </button>
        <span className="row-end">
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit={t('vulnerabilities.unit')} />
        </span>
      </div>

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {coverage && !neverSynced && (
        <p className="settings-note">
          {t('vulnerabilities.world.subtitle', {
            n: total, since: filters.since || '—', rows: coverage.rows,
          })}
          {counts?.matched ? ` · ${t('vulnerabilities.world.matchedCount', { n: counts.matched })}` : ''}
          {counts?.due_within_7d
            ? ` · ${t('vulnerabilities.world.dueCount', { n: counts.due_within_7d })}` : ''}
        </p>
      )}

      {/* The merged total cannot say which publisher is stale, so each catalogue
          gets its own word here — a feed that stopped answering is invisible in
          "1.779 rows". The pill vocabulary is the console's own: good / warn /
          bad, so the one that needs a credential reads as a warning. */}
      {coverage?.sources?.length > 0 && (
        <div className="row" style={{ gap: 6, margin: '2px 0 8px' }}>
          {coverage.sources.map((item) => (
            <span
              key={item.source}
              className={`pill ${PILL_TONE[item.status] || ''}`}
              title={item.error || item.url || ''}
            >
              {SOURCE_LABEL(item.source, t)}
              {' '}
              {item.status === 'connected' ? item.listed : sourceStatus(item, t)}
            </span>
          ))}
          <button className="ghost mini" onClick={() => setSourcesOpen(true)}>
            {t('vulnerabilities.world.sources.open')}
          </button>
        </div>
      )}

      <SourcesDrawer open={sourcesOpen} onClose={() => setSourcesOpen(false)}
        sources={coverage?.sources || []} />

      {neverSynced ? (
        <EmptyState title={t('vulnerabilities.world.neverSynced.title')}
          hint={t('vulnerabilities.world.neverSynced.hint')} />
      ) : rows.length ? (
        <Table head={[t('vulnerabilities.world.col.cve'),
          t('vulnerabilities.world.col.product'),
          t('vulnerabilities.world.col.when'),
          t('vulnerabilities.world.col.epss'),
          t('vulnerabilities.world.col.estate'), '']}>
          {rows.map((row) => (
            <React.Fragment key={row.cve_id}>
              <tr className={openCve === row.cve_id ? 'selected' : ''}>
                <td className="title mono">
                  {/* The catalog row and the advisory page answer different
                      halves of one question; the id is the door between them. */}
                  <button className="linkish mono" onClick={() => onOpenCve
                    && onOpenCve(row.cve_id)}>
                    {row.cve_id}
                  </button>
                  {row.name && (
                    <div className="muted" style={{ fontSize: 11.5 }}>{row.name}</div>
                  )}
                  {/* Who says so. A row CISA alone lists is the default and needs
                      no decoration; a CVE the EU list or VulnCheck also carries is
                      the stronger claim, so it is the one worth printing. */}
                  {(row.sources || []).length > 1
                    || ((row.sources || []).length === 1
                      && row.sources[0] !== 'cisa-kev') ? (
                      <div className="muted" style={{ fontSize: 11 }}>
                        {row.sources.map((slug) => SOURCE_LABEL(slug, t)).join(' · ')}
                      </div>
                    ) : null}
                </td>
                <td className="wrap">
                  {row.vendor || <span className="muted">—</span>}
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {row.product || t('vulnerabilities.world.productUnknown')}
                  </div>
                </td>
                <td>
                  <span className="mono">{row.date_added || '—'}</span>
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {dueLabel(row, t)}
                  </div>
                </td>
                <td className="mono">
                  {row.epss == null
                    ? <span className="muted">{t('common.unknown')}</span>
                    : `${Math.round(Number(row.epss) * 100)}%`}
                </td>
                <td className="wrap">
                  {row.matched ? (
                    <span className="pill" style={{ whiteSpace: 'nowrap' }}>
                      {t('vulnerabilities.world.col.matched', { n: row.matches.length })}
                    </span>
                  ) : (
                    <span className="muted">{t('vulnerabilities.world.col.noMatch')}</span>
                  )}
                </td>
                <td>
                  <button className="mini" onClick={() => setOpenCve(
                    openCve === row.cve_id ? '' : row.cve_id)}>
                    {openCve === row.cve_id
                      ? t('vulnerabilities.action.hide')
                      : t('vulnerabilities.action.open')}
                  </button>
                </td>
              </tr>
              {openCve === row.cve_id && (
                <tr className="detail-row"><td colSpan={7}>
                  <div className="detail">
                    <dl>
                      <dt>{t('vulnerabilities.world.detail.what')}</dt>
                      <dd style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                        {row.description || <span className="muted">{t('common.unknown')}</span>}
                        {row.cwes && (
                          <div className="muted" style={{ marginTop: 4 }}>{row.cwes}</div>
                        )}
                      </dd>
                      <dt>{t('vulnerabilities.world.detail.action')}</dt>
                      <dd style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                        {row.required_action || <span className="muted">{t('common.unknown')}</span>}
                      </dd>
                      <dt>{t('vulnerabilities.world.detail.estate')}</dt>
                      <dd>
                        {row.matched ? (
                          <ul className="grant-targets">
                            {row.matches.map((match) => (
                              <li key={`${match.kind}-${match.id}`}>
                                <span className="muted">{match.kind}</span>{' '}
                                <code>{match.label}</code>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <span className="muted">{t('vulnerabilities.world.detail.noMatch')}</span>
                        )}
                      </dd>
                      <dt>{t('vulnerabilities.world.detail.ransomware')}</dt>
                      <dd className="muted">
                        {row.ransomware
                          ? t('vulnerabilities.world.detail.ransomwareYes')
                          : t('vulnerabilities.world.detail.ransomwareNo')}
                      </dd>
                      <dt>{t('vulnerabilities.world.detail.sources')}</dt>
                      <dd>
                        {(row.sources || []).map((slug) => SOURCE_LABEL(slug, t)).join(' · ')}
                        {row.exploitation_type && (
                          <div className="muted">
                            {t('vulnerabilities.world.detail.exploitation')}: {row.exploitation_type}
                            {row.euvd_id ? ` · ${row.euvd_id}` : ''}
                          </div>
                        )}
                        {/* The EU list names the report behind the claim; a link to
                            the exploitation is worth more than the assertion, so it
                            is kept apart from CISA's own notes. */}
                        {row.eu_evidence && (
                          <div className="muted" style={{ overflowWrap: 'anywhere' }}>
                            {t('vulnerabilities.world.detail.evidence')}:{' '}
                            {/^https?:\/\//.test(row.eu_evidence) ? (
                              <a href={row.eu_evidence} target="_blank" rel="noreferrer">
                                {row.eu_evidence}
                              </a>
                            ) : row.eu_evidence}
                          </div>
                        )}
                        {row.evidence && (
                          <div className="muted" style={{ overflowWrap: 'anywhere' }}>
                            {t('vulnerabilities.world.detail.cisaNotes')}: {row.evidence}
                          </div>
                        )}
                      </dd>
                    </dl>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </Table>
      ) : (
        !error && <EmptyState title={t('vulnerabilities.world.empty.title')}
          hint={t('vulnerabilities.world.empty.hint')} />
      )}

      {pager.pages > 1 && (
        <div className="row row-end" style={{ marginTop: 10 }}>
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit={t('vulnerabilities.unit')} />
        </div>
      )}
    </>
  )
}
