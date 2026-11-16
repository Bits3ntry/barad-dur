import React, { useEffect, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, Select, SeverityBadge,
  Table, Tabs, usePage,
} from './ui'
import { useI18n } from './i18n'

/* Exposures manages the condition that needs a decision; Changes is the
   technical chronology derived from observations. They share observations but
   never duplicate an event per scan: the same condition bumps `occurrences`. */

const DECISION_LABEL_KEY = {
  resolve: 'exposures.decision.resolve',
  accept: 'exposures.decision.accept',
  false_positive: 'exposures.decision.falsePositive',
  reopen: 'exposures.decision.reopen',
}

/* The endpoints answer these lists whole, so the screen slices them. A page
   this size keeps the toolbar and the first rows in one glance. */
const PER_PAGE = 25

/* The API names a kind `new_host`; the catalogue keys are camelCase. One
   converter, so a new kind needs a key and nothing else. */
const kindKey = (value) => String(value || '')
  .replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())

/* The API composes the row's one-line reason from a small set of detector
   sentences ("port 443 is reachable"). They are copy, not free text: a reader
   in Spanish should read the same fact in Spanish, so the known shapes are
   re-composed through the catalogue and anything unrecognised is printed as it
   arrived — a detector that learns a new sentence degrades to English, it never
   disappears. */
const TITLE_PATTERNS = [
  [/^asset observed for the first time$/i, 'exposures.title.firstObservation', () => ({})],
  [/^alias observed without an address behind it$/i, 'exposures.title.danglingAlias', () => ({})],
  [/^the address set changed$/i, 'exposures.title.addressesChanged', () => ({})],
  [/^the certificate identity changed$/i, 'exposures.title.certificateChanged', () => ({})],
  [/^the observed technology set changed$/i, 'exposures.title.technologyChanged', () => ({})],
  [/^no addresses observed in a complete collection$/i, 'exposures.title.noAddresses', () => ({})],
  [/^certificate expiry could not be read$/i, 'exposures.title.certUnknown', () => ({})],
  [/^certificate expires in (\d+) days$/i, 'exposures.title.certExpires', (m) => ({ n: m[1] })],
  [/^port (\d+) is reachable$/i, 'exposures.title.portReachable', (m) => ({ port: m[1] })],
]

function exposureTitle(title, t) {
  if (!title) return title
  for (const [pattern, key, params] of TITLE_PATTERNS) {
    const match = pattern.exec(String(title).trim())
    if (match) return t(key, params(match))
  }
  return title
}

export default function Exposures() {
  const { t, tCount, tOr } = useI18n()
  const [tab, setTab] = useState('overview')
  const [events, setEvents] = useState([])
  const [counts, setCounts] = useState({})
  const [changes, setChanges] = useState([])
  const [changeCounts, setChangeCounts] = useState({})
  const [notes, setNotes] = useState([])
  const [summaries, setSummaries] = useState([])
  // The weekly digest is a read over this screen's own change feed; it lives
  // here so Attack Surface stops owning a second copy of the same window.
  const [weekly, setWeekly] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [filter, setFilter] = useState({ state: 'open', kind: '' })
  const [decide, setDecide] = useState(null)
  const [decision, setDecision] = useState({ action: 'resolve', reason: '', valid_until: '' })

  // Each tab's list is sliced on its own: paging the changes table must not
  // move the exposures page. The hook clamps itself when a load shrinks a list.
  const pagedEvents = usePage(events, PER_PAGE)
  const pagedChanges = usePage(changes, PER_PAGE)

  // A new filter is a new question, not the fourth page of the old answer.
  useEffect(() => { pagedEvents.setPage(0) }, [filter.state, filter.kind])

  useEffect(() => { loadExposures() }, [filter.state, filter.kind])
  useEffect(() => { if (tab === 'changes') loadChanges() }, [tab])
  useEffect(() => { if (tab === 'summaries') loadSummaries() }, [tab])
  useEffect(() => { if (tab === 'weekly' && !weekly) loadWeekly() }, [tab])

  function loadExposures() {
    const params = new URLSearchParams()
    if (filter.state) params.set('state', filter.state)
    if (filter.kind) params.set('kind', filter.kind)
    api.get(`/api/v1/exposures?${params}`)
      .then((r) => { setEvents(r.data || []); setCounts(r.counts || {}) })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadChanges() {
    api.get('/api/v1/attack-surface/changes?days=14')
      .then((r) => {
        setChanges(r.data || [])
        setChangeCounts(r.counts || {})
        setNotes(r.coverage_notes || [])
      })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadSummaries() {
    api.get('/api/v1/exposures/summary/findings')
      .then((r) => setSummaries(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  function loadWeekly() {
    api.get('/api/v1/attack-surface/summary/weekly')
      .then((r) => setWeekly(r.data))
      .catch((e) => setError(String(e.message || e)))
  }

  async function submitDecision() {
    if (!decide) return
    setError('')
    try {
      await api.post(`/api/v1/exposures/${decide.id}/decide`, {
        action: decision.action,
        reason: decision.reason || null,
        valid_until: decision.action === 'accept' && decision.valid_until
          ? `${decision.valid_until}T00:00:00+00:00` : null,
        actor: 'console',
      })
      setNotice(t('exposures.notice.applied', {
        action: t(DECISION_LABEL_KEY[decision.action] || decision.action),
        kind: tOr('exposures.kind.' + kindKey(decide.kind), decide.kind),
        asset: decide.asset?.value || t('exposures.assetFallback'),
      }))
      setDecide(null)
      setDecision({ action: 'resolve', reason: '', valid_until: '' })
      loadExposures()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title={t('exposures.title')}
        subtitle={t('exposures.subtitle', {
          open: counts.open || 0,
          accepted: counts.accepted || 0,
          resolved: counts.resolved || 0,
        })}
      />

      <Tabs
        tabs={[
          { id: 'overview', label: t('exposures.tab.overview') },
          { id: 'changes', label: t('exposures.tab.changes') },
          { id: 'summaries', label: t('exposures.tab.summaries') },
          { id: 'weekly', label: t('attackSurface.tab.weekly') },
        ]}
        active={tab}
        onChange={setTab}
      />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {tab === 'overview' && (
        <>
          <div className="toolbar">
            <select value={filter.state}
              onChange={(e) => setFilter((f) => ({ ...f, state: e.target.value }))}>
              <option value="open">{t('exposures.state.open')}</option>
              <option value="accepted">{t('exposures.state.accepted')}</option>
              <option value="resolved">{t('exposures.state.resolved')}</option>
              <option value="false_positive">{t('exposures.state.falsePositive')}</option>
              <option value="">{t('exposures.filter.everyState')}</option>
            </select>
            <select value={filter.kind}
              onChange={(e) => setFilter((f) => ({ ...f, kind: e.target.value }))}>
              <option value="">{t('exposures.filter.everyKind')}</option>
              <option value="open_port">{t('exposures.kind.openPort')}</option>
              <option value="new_host">{t('exposures.kind.newHost')}</option>
              <option value="certificate_expiring">{t('exposures.kind.certificateExpiring')}</option>
              <option value="dangling_dns">{t('exposures.kind.danglingDns')}</option>
              <option value="host_disappeared">{t('exposures.kind.hostDisappeared')}</option>
              <option value="dns_changed">{t('exposures.kind.dnsChanged')}</option>
              <option value="technology_changed">{t('exposures.kind.technologyChanged')}</option>
            </select>
            <button className="mini" onClick={loadExposures}>{t('common.refresh')}</button>
            <Pager page={pagedEvents.page} pages={pagedEvents.pages}
              onChange={pagedEvents.setPage} total={pagedEvents.total}
              perPage={PER_PAGE} unit={t('exposures.unit.events')} className="row-end" />
          </div>

          {events.length ? (
            <Table head={[t('exposures.col.kind'), t('exposures.col.asset'), t('common.severity'),
              t('exposures.col.seen'), t('exposures.col.occurrences'), t('exposures.col.state'), '']}>
              {pagedEvents.rows.map((row) => (
                <tr key={row.id}>
                  <td className="title">
                    {tOr('exposures.kind.' + kindKey(row.kind), row.kind.replaceAll('_', ' '))}
                    <div className="muted" style={{ fontSize: 11.5 }}>{exposureTitle(row.title, t)}</div>
                  </td>
                  <td className="mono">{row.asset?.value || '—'}</td>
                  <td><SeverityBadge severity={row.severity} /></td>
                  <td className="muted">
                    {new Date(row.last_seen_at).toLocaleDateString()}
                    <div style={{ fontSize: 11.5 }}>
                      {t('exposures.firstSeen', { date: new Date(row.first_seen_at).toLocaleDateString() })}
                    </div>
                  </td>
                  <td>{row.occurrences}</td>
                  <td>
                    <span className={row.state === 'open' ? 'sev sev-medium' : 'pill'}>
                      {tOr('exposures.state.' + row.state, row.state)}
                    </span>
                    {row.decision_reason && (
                      <div className="muted" style={{ fontSize: 11.5 }}>
                        {row.decision_reason}
                      </div>
                    )}
                  </td>
                  <td>
                    <button className="mini" onClick={() => setDecide(row)}>{t('exposures.action.decide')}</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('exposures.empty.events.title')}
              hint={t('exposures.empty.events.hint')} />
          )}

          <Pager page={pagedEvents.page} pages={pagedEvents.pages}
            onChange={pagedEvents.setPage} total={pagedEvents.total}
            perPage={PER_PAGE} unit={t('exposures.unit.events')} className="row-end" />
        </>
      )}

      {tab === 'changes' && (
        <>
          <div className="toolbar">
            {Object.entries(changeCounts).map(([key, value]) => (
              <span key={key} className="pill">
                {tOr('exposures.kind.' + kindKey(key), key.replaceAll('_', ' '))} {value}
              </span>
            ))}
            <span className="spacer" />
            <span className="muted">{t('exposures.changes.windowNote')}</span>
            <Pager page={pagedChanges.page} pages={pagedChanges.pages}
              onChange={pagedChanges.setPage} total={pagedChanges.total}
              perPage={PER_PAGE} unit={t('exposures.unit.changes')} className="row-end" />
          </div>
          {changes.length ? (
            <Table head={[t('exposures.col.when'), t('exposures.col.category'),
              t('exposures.col.asset'), t('exposures.col.before'), t('exposures.col.after'),
              t('common.source')]}>
              {pagedChanges.rows.map((row, index) => (
                <tr key={`${row.asset_id}-${row.category}-${index}`}>
                  <td className="muted">{new Date(row.observed_at).toLocaleString()}</td>
                  <td>
                    <span className="pill">
                      {tOr('exposures.kind.' + kindKey(row.category), row.category.replaceAll('_', ' '))}
                    </span>
                  </td>
                  <td className="mono">{row.asset?.value || row.subject}</td>
                  <td className="muted mono">
                    {Array.isArray(row.before) ? row.before.join(', ') : (row.before ?? '—')}
                  </td>
                  <td className="mono">
                    {Array.isArray(row.after) ? row.after.join(', ') : (row.after ?? '—')}
                  </td>
                  <td className="muted">{row.source}</td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('exposures.empty.changes.title')}
              hint={t('exposures.empty.changes.hint')} />
          )}

          <Pager page={pagedChanges.page} pages={pagedChanges.pages}
            onChange={pagedChanges.setPage} total={pagedChanges.total}
            perPage={PER_PAGE} unit={t('exposures.unit.changes')} className="row-end" />

          {notes.length > 0 && (
            <div className="detail">
              <dl>
                <dt>{t('exposures.changes.coverageGaps')}</dt>
                <dd className="muted">
                  {notes.map((note, index) => (
                    <div key={index} className="occ-row">{note.asset_id}: {note.note}</div>
                  ))}
                </dd>
              </dl>
            </div>
          )}
        </>
      )}

      {tab === 'summaries' && (
        <>
          <p className="muted">
            {t('exposures.summaries.note')}
          </p>
          {summaries.length ? (
            <Table head={[t('exposures.col.kind'), t('exposures.col.total'),
              t('exposures.col.open'), t('exposures.col.bySeverity'),
              t('exposures.col.findings')]}>
              {summaries.map((row) => (
                <tr key={row.kind}>
                  <td className="title">
                    {tOr('exposures.summaryKind.' + row.kind, row.kind.replaceAll('-', ' '))}
                  </td>
                  <td>{row.total}</td>
                  <td>{row.open}</td>
                  <td className="muted">
                    {Object.entries(row.severity).map(([severity, count]) => (
                      <span key={severity} className="pill">
                        {tOr('severity.' + severity.toLowerCase(), severity)} {count}
                      </span>
                    ))}
                  </td>
                  <td className="muted mono">
                    {row.finding_ids.slice(0, 3).map((id) => id.slice(0, 8)).join(', ')}
                    {row.finding_ids.length > 3 ? '…' : ''}
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('exposures.empty.summaries.title')}
              hint={t('exposures.empty.summaries.hint')} />
          )}
        </>
      )}

      {tab === 'weekly' && weekly && (
        <div className="detail">
          <dl>
            <dt>{t('attackSurface.weekly.window')}</dt>
            <dd className="muted">{t('attackSurface.weekly.lastDays', { n: weekly.window_days })}</dd>
            <dt>{t('attackSurface.weekly.changes')}</dt>
            <dd>
              {Object.entries(weekly.changes || {}).length
                ? Object.entries(weekly.changes || {}).map(([key, value]) => (
                  <span key={key} className="pill">
                    {tOr(`attackSurface.state.${key}`, key.replaceAll('_', ' '))} {value}
                  </span>
                ))
                : <span className="muted">{t('attackSurface.weekly.noChanges')}</span>}
            </dd>
            <dt>{t('attackSurface.weekly.newPaths')}</dt><dd>{weekly.new_paths}</dd>
            <dt>{t('attackSurface.weekly.lookalikes')}</dt><dd>{weekly.lookalike_candidates}</dd>
            <dt>{t('attackSurface.weekly.exposures')}</dt><dd>{weekly.open_exposures}</dd>
            <dt>{t('attackSurface.weekly.coverageGaps')}</dt><dd>{weekly.coverage_notes}</dd>
            <dt>{t('attackSurface.weekly.delivery')}</dt>
            <dd>
              {/* A sentence never wears a badge: `.sev` is nowrap, and a long
                  reason pushed the page sideways at 700px. */}
              <span className={weekly.delivery?.configured ? 'pill' : 'sev sev-medium'}>
                {weekly.delivery?.configured
                  ? t('attackSurface.weekly.configured')
                  : t('attackSurface.weekly.deliveryOff')}
              </span>
              {!weekly.delivery?.configured && (
                <span className="muted"> {tOr(weekly.delivery?.reason_key,
                  t('attackSurface.weekly.notConfigured', { reason: weekly.delivery?.reason || '' }))}</span>
              )}
            </dd>
          </dl>
        </div>
      )}

      <Dialog open={Boolean(decide)}
        title={t('exposures.decide.title', {
          kind: decide?.kind
            ? tOr('exposures.kind.' + kindKey(decide.kind), decide.kind) : '',
        })}
        onClose={() => setDecide(null)} onConfirm={submitDecision}
        confirmLabel={t(DECISION_LABEL_KEY[decision.action] || decision.action)}>
        <div className="stack">
          <p className="muted">
            {tCount('exposures.decide.seen', decide?.occurrences || 0,
              { asset: decide?.asset?.value || '' })}
          </p>
          <Select label={t('exposures.decide.action')} value={decision.action}
            options={Object.entries(DECISION_LABEL_KEY).map(([value, key]) => ({
              value, label: t(key),
            }))}
            onChange={(value) => setDecision((d) => ({ ...d, action: value }))} />
          <Input label={t('exposures.decide.reason')} textarea rows={3}
            value={decision.reason}
            onChange={(value) => setDecision((d) => ({ ...d, reason: value }))} />
          {decision.action === 'accept' && (
            <Input label={t('exposures.decide.acceptedUntil')} type="date" value={decision.valid_until}
              hint={t('exposures.decide.acceptedUntilHint')}
              onChange={(value) => setDecision((d) => ({ ...d, valid_until: value }))} />
          )}
          <span className="muted">
            {t('exposures.decide.note')}
          </span>
        </div>
      </Dialog>
    </div>
  )
}
