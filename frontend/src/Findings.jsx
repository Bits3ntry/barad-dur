import React, { useEffect, useState } from 'react'
import { api } from './api'
import { EmptyState, ErrorBanner, Loading, PageHeader, Pager,
         Table, SeverityBadge, serverPager } from './ui'
import { useI18n } from './i18n'

/* The list is a queue, and the queue is the whole estate until the reader
   narrows it.

   It used to open already filtered to the first project and its first version:
   the door in the rail printed 576 of the estate's 866 findings and called it
   "in scope". That pre-filter is why this screen and Vulnerabilities read as two
   lists of the same thing instead of one queue plus one advisory rollup. A facet
   now arrives only from a link (`#findings::project=aurea&build=<id>`), and every
   active facet is a chip the reader can drop — the crumb cannot lie about the
   scope the numbers belong to.

   A finding has its own address (`#findings::<id>`) and its own page: what it is,
   what else the same version carries, where it was seen, who touched it and what
   closes it. */

function slaCell(deadline, t) {
  if (!deadline) return <span className="muted">{t('findings.sla.none')}</span>
  const days = Math.floor((new Date(deadline) - new Date()) / 86400000)
  const cls = days < 0 ? 'sev-critical' : days <= 2 ? 'sev-high' : 'muted'
  return (
    <span className={cls}>{days < 0
      ? t('findings.sla.overdue', { n: -days })
      : t('findings.sla.left', { n: days })}
    </span>
  )
}

const PER_PAGE = 25

/* An empty facet is absence of a question, not a value: the queue asks the whole
   estate until one arrives. `build` is a version id, never a label — two
   components of one monorepo ship as `main` and a label filter merges them. */
const EMPTY_FILTERS = { project: '', build: '', buildLabel: '', vector: '', kind: '', origin: '',
  cycle: '',
  q: '', open: '' }

/* The vectors the platform writes, in the order a reader closes them: the two
   that a dependency upgrade closes, then code, then the two that need a person
   to act somewhere else. A new vector the backend starts writing renders its raw
   value instead of disappearing from the list. */
const VECTORS = ['dependency-cve', 'runtime-cve', 'sast', 'credential', 'misconfig', 'network']

function filtersFromFocus(focus = {}) {
  const seeded = focus.queue || {}
  return {
    ...EMPTY_FILTERS,
    project: seeded.project || '',
    build: seeded.build || '',
    buildLabel: seeded.build_label || '',
    vector: seeded.vector || '',
    kind: seeded.kind || '',
    origin: seeded.origin || '',
    cycle: seeded.cycle || '',
    // A CVE or a rule id: the advisory page sends its own id here, so "the
    // findings behind this advisory" is a door instead of a second list.
    q: seeded.q || '',
    // "still open", which is what every count that sends a reader here means.
    open: seeded.open ? '1' : '',
  }
}

export default function Findings({ projects, focus = {} }) {
  const { t, tCount, tOr } = useI18n()
  const [filters, setFilters] = useState(() => filtersFromFocus(focus))
  // Cycles are a short list and the filter needs their names, not their ids.
  const [cycles, setCycles] = useState([])
  const [queueOnly, setQueueOnly] = useState(false)
  const [includeSuppressed, setIncludeSuppressed] = useState(false)
  const [state, setState] = useState({
    rows: [], total: 0, error: '', loading: false, queueCount: 0,
  })
  const [bump, setBump] = useState(0)
  const [offset, setOffset] = useState(0)
  const pager = serverPager(state.total, PER_PAGE, offset, setOffset)

  // A second link can arrive while the queue is mounted (search, a build's own
  // "see them in findings"): the facet in the address is the question, so it
  // re-seeds the filters instead of being ignored because nothing remounted.
  const seed = JSON.stringify(focus.queue || {})
  const lastSeed = React.useRef(seed)
  useEffect(() => {
    if (lastSeed.current === seed) return
    lastSeed.current = seed
    setFilters(filtersFromFocus(focus))
    setOffset(0)
  }, [seed])

  // A filter is a new question, so it starts on the first page; changing page
  // keeps the question. The reset keys off the filters themselves, because a
  // page change is also an offset change and must not snap back to page one.
  const signature = [filters.project, filters.build, filters.vector, filters.kind,
    filters.origin, filters.cycle, filters.q, filters.open, queueOnly,
    includeSuppressed, bump].join('|')
  const lastSignature = React.useRef(signature)

  useEffect(() => {
    api.get('/api/v1/cycles')
      .then((data) => setCycles((data.data || []).map((row) => ({ id: row.id, name: row.name }))))
      .catch(() => setCycles([]))
  }, [])

  const cycleLabel = (id) => (cycles.find((row) => row.id === id) || {}).name || id

  // Ordering is the platform's: the list is paginated, and a sort applied to the
  // page would only reorder the slice it can see.
  useEffect(() => {
    if (lastSignature.current !== signature) {
      lastSignature.current = signature
      if (offset !== 0) { setOffset(0); return }
    }
    const params = new URLSearchParams()
    if (filters.project) params.set('project', filters.project)
    if (filters.build) params.set('version_id', filters.build)
    if (filters.vector) params.set('vector', filters.vector)
    if (filters.kind) params.set('kind', filters.kind)
    if (filters.origin) params.set('origin', filters.origin)
    if (filters.cycle) params.set('cycle', filters.cycle)
    if (filters.q) params.set('q', filters.q)
    if (filters.open) params.set('open', 'true')
    if (queueOnly) params.set('queue', 'true')
    if (includeSuppressed) params.set('include_suppressed', 'true')
    params.set('sort', 'severity')
    params.set('limit', PER_PAGE)
    params.set('offset', offset)
    setState((s) => ({ ...s, loading: true, error: '' }))
    api.get(`/api/v1/findings?${params.toString()}`)
      .then((data) => setState((s) => ({ ...s, rows: data.data, total: data.total,
        queueCount: data.counters?.queue || 0, loading: false })))
      .catch((error) => setState((s) => ({ ...s, loading: false, error: String(error.message || error) })))
  }, [signature, offset])

  /* Every active facet is named here, with the unit it belongs to, and the chip
     is the way out: widening the question is one click and never a lost filter. */
  const facets = [
    filters.project && { key: 'project', label: t('findings.facet.project'),
      value: (projects.find((row) => row.slug === filters.project
        || row.name === filters.project) || {}).name || filters.project },
    filters.build && { key: 'build', label: t('findings.facet.build'),
      value: filters.buildLabel || filters.build.slice(0, 8) },
    filters.vector && { key: 'vector', label: t('findings.facet.vector'),
      value: tOr(`findings.vector.${filters.vector}`, filters.vector) },
    filters.kind && { key: 'kind', label: t('findings.facet.kind'),
      value: tOr(`findings.kind.${filters.kind}`, filters.kind) },
    filters.cycle && { key: 'cycle', label: t('findings.facet.cycle'),
      value: cycleLabel(filters.cycle) },
    filters.origin && { key: 'origin', label: t('findings.facet.origin'),
      value: tOr(`findings.origin.${filters.origin}`, filters.origin) },
    filters.q && { key: 'q', label: t('findings.facet.query'), value: filters.q },
    filters.open && { key: 'open', label: t('findings.facet.status'),
      value: t('findings.filter.openOnly') },
  ].filter(Boolean)

  // Dropping the project drops the build too: a build belongs to a project, and
  // keeping it would leave a chip nobody can explain.
  function dropFacet(key) {
    setFilters((current) => ({ ...current, [key]: '',
      ...(key === 'project' ? { build: '', buildLabel: '' } : {}) }))
  }

  return (
    <div>
      <PageHeader
        title={t('findings.title')}
        subtitle={state.error
          ? t('findings.subtitle.error')
          : tCount('findings.subtitle.count', state.total)}
        actions={(
          <div className="row">
            <button onClick={() => setBump((n) => n + 1)}>{t('common.refresh')}</button>
            {/* The form is a link, not a modal: the same record can be asked for
                twice, pasted to a colleague, or opened with the subject already in
                the address (`#findings::new&project=aurea`). */}
            <button className="primary-action" title={t('findings.create.linkHint')}
              onClick={() => { window.location.hash = 'findings::new' }}>
              {t('findings.new')}
            </button>
          </div>
        )}
      />
      {/* The scope is stated above the filters, and it is the only place the
          numbers below can be trusted from: the queue answers for the whole
          estate until a chip says otherwise, and the chip is how it widens. */}
      <div className="chip-row" style={{ marginBottom: 8 }}>
        {facets.length ? facets.map((facet) => (
          <button key={facet.key} className="chip" title={t('findings.facet.clear')}
            onClick={() => dropFacet(facet.key)}>
            <span className="muted">{facet.label}</span>{' '}
            {facet.value} <span aria-hidden="true">×</span>
          </button>
        )) : (
          <span className="muted" style={{ fontSize: 12 }}>{t('findings.scope.all')}</span>
        )}
      </div>
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <select value={filters.project}
          onChange={(e) => setFilters((f) => ({ ...f, project: e.target.value,
            build: '', buildLabel: '' }))}>
          <option value="">{t('findings.filter.everyProject')}</option>
          {projects.map((p) => <option key={p.id} value={p.slug}>{p.name}</option>)}
        </select>
        {/* The axis that separates "upgrade a package" from "fix the code". A
            queue where 97% of the rows are dependency CVEs and the rest are
            code, secrets and configuration has to say which is which before it
            asks anybody to triage them in one list. */}
        <select value={filters.vector}
          onChange={(e) => setFilters((f) => ({ ...f, vector: e.target.value }))}>
          <option value="">{t('findings.filter.anyVector')}</option>
          {VECTORS.map((value) => (
            <option key={value} value={value}>{tOr(`findings.vector.${value}`, value)}</option>
          ))}
        </select>
        <select value={filters.kind}
          onChange={(e) => setFilters((f) => ({ ...f, kind: e.target.value }))}>
          <option value="">{t('findings.filter.allKinds')}</option>
          <option value="vulnerability">{t('findings.kind.vulnerability')}</option>
          <option value="secret">{t('findings.kind.secret')}</option>
          <option value="misconfiguration">{t('findings.kind.misconfiguration')}</option>
          <option value="code-weakness">{t('findings.kind.codeWeakness')}</option>
        </select>
        <select value={filters.origin}
          onChange={(e) => setFilters((f) => ({ ...f, origin: e.target.value }))}>
          <option value="">{t('findings.filter.allOrigins')}</option>
          <option value="scanner">{t('findings.origin.scanner')}</option>
          <option value="pentest-external">{t('findings.origin.pentestExternal')}</option>
          <option value="pentest-internal">{t('findings.origin.pentestInternal')}</option>
          <option value="shauron-ai">{t('findings.origin.shauronAi')}</option>
          <option value="manual">{t('findings.origin.manual')}</option>
        </select>
        {/* A cycle's findings are a handful among hundreds: asking for them has to be
            one control, not a page hunt. */}
        <select value={filters.cycle}
          onChange={(e) => setFilters((f) => ({ ...f, cycle: e.target.value }))}>
          <option value="">{t('findings.filter.allCycles')}</option>
          {cycles.map((row) => (
            <option key={row.id} value={row.id}>{row.name}</option>
          ))}
        </select>
        <label className="check">
          <input
            type="checkbox"
            checked={queueOnly}
            onChange={(e) => setQueueOnly(e.target.checked)}
          />
          {t('findings.filter.awaitingTriage')}
          {state.queueCount > 0 && (
            <span className="group-count">{state.queueCount}</span>
          )}
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={includeSuppressed}
            onChange={(e) => setIncludeSuppressed(e.target.checked)}
          />
          {t('findings.filter.includeSuppressed')}
        </label>
        <span className="row-end">
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit={t('unit.findings')} />
        </span>
      </div>
      {state.error && <ErrorBanner error={state.error} onRetry={() => setBump((n) => n + 1)} />}
      {state.loading && !state.rows.length && <Loading rows={6} />}
      <Table head={[t('findings.col.prio'), t('findings.col.sev'), t('findings.col.kind'),
        t('findings.col.title'), t('findings.col.rule'), t('findings.col.path'),
        t('findings.col.sla'), t('findings.col.status')]}
        empty={!state.loading && !state.error && (facets.length
          ? <EmptyState title={t('findings.empty.title')}
              hint={t('findings.empty.hint')} />
          : <EmptyState title={t('findings.empty.estate.title')}
              hint={t('findings.empty.estate.hint')} />)}>
        {state.rows.map((row) => (
          <tr key={row.id} className="findings-row"
              onClick={() => { window.location.hash = `findings::${row.id}` }}>
            <td><span className={`prio prio-${(row.priority || 'p3').toLowerCase()}`}>{row.priority || 'P3'}</span></td>
            <td><SeverityBadge severity={row.severity} /></td>
            <td>{tOr('findings.kind.' + row.kind, row.kind)}</td>
            <td className="title">
              <span className="rem-title" title={row.title}>{row.title}</span>
              {row.origin && row.origin !== 'scanner' && (
                <span className={`pill origin origin-${row.origin}`}>{row.origin}</span>
              )}
              {row.triage_status === 'new' && (
                <span className="pill triage-new">{t('findings.pill.awaitingTriage')}</span>
              )}
              {row.evidence_level === 'hypothesis' && (
                <span className="pill triage-hypothesis">{t('findings.triage.level.hypothesis')}</span>
              )}
            </td>
            <td>{row.cve_id || row.rule_id || row.source_id || '—'}</td>
            <td>{row.path || row.component_purl || '—'}</td>
            <td>{slaCell(row.sla_deadline, t)}</td>
            <td><span className={`status st-${row.status}`}>{tOr('status.' + row.status, row.status)}</span></td>
          </tr>
        ))}
      </Table>
      {pager.pages > 1 && (
        <div className="row row-end" style={{ marginTop: 10 }}>
          <Pager page={pager.page} pages={pager.pages} onChange={pager.setPage}
            total={pager.total} perPage={PER_PAGE} unit={t('unit.findings')} />
        </div>
      )}


    </div>
  )
}
