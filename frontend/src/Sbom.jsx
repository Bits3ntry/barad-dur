import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import { Card, Drawer, EmptyState, ErrorBanner, Loading, Pager, PageHeader, SeverityBadge, Tabs } from './ui'
import SbomGraph from './SbomGraph'

/* Supply chain reads a BOM as a document about a build, not as a project tab.
   The index answers "which builds have a BOM"; opening one answers "what does
   this build ship, what is wrong with it, and is it getting worse" — the
   Dependency-Track screen, with this console's calm. Tabs with no data source
   say so instead of showing an empty table that looks like a clean result. */

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
const PER_PAGE = 25
const NUMERIC_SORTS = new Set(['risk', 'findings', 'epss', 'kev', 'internal'])

function relative(iso) {
  if (!iso) return 'never'
  const ms = Date.now() - new Date(iso).getTime()
  if (!Number.isFinite(ms)) return 'never'
  const minutes = Math.round(ms / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  return days === 1 ? 'yesterday' : `${days}d ago`
}

function severityClass(value) {
  const key = (value || 'UNKNOWN').toLowerCase()
  return SEVERITIES.includes((value || 'UNKNOWN').toUpperCase()) ? `sev-${key}` : 'sev-unknown'
}

/* 0.0016 must not read as "0%": most advisories sit under one percent, and
   rounding them all to zero makes the column look broken. */
function epssLabel(value) {
  if (value == null) return null
  const percent = value * 100
  if (percent >= 10) return `${Math.round(percent)}%`
  if (percent >= 1) return `${percent.toFixed(1)}%`
  return `${percent.toFixed(2)}%`
}

function SeverityVector({ counts }) {
  const total = SEVERITIES.reduce((sum, key) => sum + (counts?.[key] || 0), 0)
  if (!total) return <span className="sbom-clean">no findings</span>
  return (
    <div className="sbom-vector">
      {SEVERITIES.map((severity) => (
        <div className={`sbom-count sev-${severity.toLowerCase()}`} key={severity}>
          <span className={`sbom-count-value ${(counts?.[severity] ?? 0) === 0 ? 'is-zero' : ''}`}>
            {counts?.[severity] ?? 0}
          </span>
          <span className="sbom-count-label">{severity.toLowerCase()}</span>
        </div>
      ))}
    </div>
  )
}

/* The severity bar: one segment per severity that has findings, its width the
   count and its colour the severity. "1 high, 2 low" is one glance, not five
   badges to compare. */
function SeverityBar({ counts, compact = false }) {
  const total = SEVERITIES.reduce((sum, key) => sum + (counts?.[key] || 0), 0)
  if (!total) return <span className="sbom-clean">—</span>
  return (
    <div className={`sbom-bar${compact ? ' compact' : ''}`}
      title={SEVERITIES.filter((s) => counts?.[s])
        .map((s) => `${counts[s]} ${s.toLowerCase()}`).join(' · ')}>
      {SEVERITIES.filter((severity) => counts?.[severity]).map((severity) => (
        <span key={severity}
          className={`sbom-bar-seg sev-${severity.toLowerCase()}`}
          style={{ flexGrow: counts[severity] }}>
          {counts[severity]}
        </span>
      ))}
    </div>
  )
}

function RiskScore({ value }) {
  const score = Number(value || 0)
  const tone = score >= 40 ? 'bad' : score >= 15 ? 'warn' : score > 0 ? 'ok' : ''
  return <span className={`sbom-risk ${tone}`} title="severity weight × KEV × EPSS">
    {score ? score.toFixed(1) : '0'}
  </span>
}

/* ── the index: every build with a BOM ─────────────────────────────────────── */

export default function Sbom({ focus = {}, onOpen, onBack, embedded = false }) {
  const [index, setIndex] = useState(null)
  const [error, setError] = useState('')

  const projectSlug = focus.projectSlug || ''
  const component = focus.component || ''
  const version = focus.version || ''

  useEffect(() => {
    setError('')
    api.get('/api/v1/sbom/index')
      .then((r) => setIndex(r))
      .catch((e) => setError(String(e.message || e)))
  }, [])

  if (error) return <ErrorBanner error={error} />
  if (projectSlug && version) {
    return <BomView project={projectSlug} component={component} version={version}
      versionId={focus.versionId} onBack={onBack} embedded={embedded} />
  }
  if (index === null) return <Card><Loading rows={4} /></Card>

  const rows = index.data || []
  const totals = index.totals || {}

  return (
    <div className="stack">
      <PageHeader
        title="Builds"
        subtitle="Every build with a bill of materials, whichever project it belongs to. A BOM is a document about a version — this is the way in that does not start at Projects." />

      {!rows.length && (
        <Card>
          <EmptyState title="No BOMs yet"
            hint="Import one from the CLI or CI (`barad sbom`), or from a version inside a project. It attaches to that version, and appears here." />
        </Card>
      )}

      {rows.length > 0 && (
        <>
          <Card tight>
            <div className="sbom-totals">
              <div><strong>{totals.boms}</strong> builds</div>
              <div><strong>{totals.components}</strong> components</div>
              <div><strong>{totals.findings}</strong> findings</div>
              <div><strong>{totals.kev}</strong> in KEV</div>
              <SeverityVector counts={totals.by_severity} />
            </div>
          </Card>

          <Card tight>
            <table className="sbom-index">
              <thead>
                <tr>
                  <th>project</th><th>version</th><th>components</th>
                  <th>findings</th><th>kev</th><th>severity</th><th>last import</th><th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.project.slug}:${row.version}`}>
                    <td className="title">{row.project.name}</td>
                    <td className="mono">
                      {row.version}
                      {row.component ? <span className="muted sbom-sub">{row.component}</span> : null}
                      {row.is_latest ? <span className="pill sbom-latest">latest</span> : null}
                    </td>
                    <td>
                      {row.components}
                      <span className="muted sbom-sub">{row.direct} direct</span>
                    </td>
                    <td>{row.findings.total}</td>
                    <td>{row.findings.kev ? <span className="pill sev-critical">{row.findings.kev}</span>
                      : <span className="muted">0</span>}</td>
                    <td>
                      <SeverityVector counts={row.findings.by_severity} />
                    </td>
                    <td className="muted">{relative(row.last_import_at)}</td>
                    <td className="sbom-open">
                      <button className="mini"
                        onClick={() => onOpen && onOpen(row.project.slug,
                          row.component_slug || row.component, row.version, row.version_id)}>
                        open ›
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}
    </div>
  )
}

/* ── one build ─────────────────────────────────────────────────────────────── */

/* ── code findings: what the source says, apart from what it ships ─────────── */

/* Semgrep-style keys repeat their own tail (…&#8203;.dynamic-urllib-use-detected
   .dynamic-urllib-use-detected); the readable name is the tail, once. */
function shortRule(rule) {
  if (!rule) return '—'
  const parts = String(rule).split('.').filter(Boolean)
  const deduped = parts.filter((part, index) => part !== parts[index - 1])
  const tail = deduped.slice(-2).join('.')
  return tail.length > 34 ? `${tail.slice(0, 33)}…` : tail
}

/* SonarQube's shape, because that is how this gets read: the list of issues on
   the left to walk through, the code on the right with the flagged line lit, and
   the explanation above it. A table of fifteen rows makes you hunt; this one
   makes you read. */
/* What a sibling build carries, in the same words on every screen that points at
   it: open first, secrets named apart, settled ones named apart. */
function elsewhereText(row) {
  const open = (row.code || 0) + (row.secrets || 0)
  const parts = [`${open} open`]
  if (row.secrets) parts.push(`${row.secrets} secret${row.secrets === 1 ? '' : 's'}`)
  if (row.dismissed) parts.push(`${row.dismissed} settled`)
  return parts.join(' · ')
}

function CodeFindingsTab({ data, sort, onSort, onOpenVersion }) {
  const [needle, setNeedle] = useState('')
  const [severity, setSeverity] = useState('')
  const [klass, setKlass] = useState('')
  const [settled, setSettled] = useState('all')
  const [current, setCurrent] = useState(null)

  const all = data.code_findings || []
  const settledCount = data.code?.dismissed || 0

  const rows = useMemo(() => {
    const text = needle.trim().toLowerCase()
    return all.filter((row) => {
      if (severity && row.severity !== severity) return false
      if (klass && row.class !== klass) return false
      if (settled === 'open' && row.dismissed) return false
      if (settled === 'settled' && !row.dismissed) return false
      if (!text) return true
      return `${row.path || ''} ${row.rule || ''} ${row.title || ''}`
        .toLowerCase().includes(text)
    })
  }, [data, needle, severity, klass, settled])

  const total = all.length
  const active = rows.find((row) => row.finding_id === current) || rows[0] || null

  // The whole file at the scanned commit, so the issue has a place. Falls back
  // to the captured snippet when the repository cannot answer.
  const [source, setSource] = useState(null)
  useEffect(() => {
    if (!active?.path) { setSource(null); return undefined }
    let cancelled = false
    setSource({ status: 'loading' })
    api.get(`/api/v1/sbom/source?version_id=${encodeURIComponent(data.version_id)}`
      + `&path=${encodeURIComponent(active.path)}`)
      .then((r) => {
        if (cancelled) return
        setSource(r.data.found
          ? { status: 'ok', lines: r.data.lines, ref: r.data.ref, total: r.data.total,
              truncated: r.data.truncated }
          : { status: 'missing', reason: r.data.reason })
      })
      .catch(() => { if (!cancelled) setSource({ status: 'missing', reason: 'source unavailable' }) })
    return () => { cancelled = true }
  }, [active?.finding_id, active?.path, data.version_id])

  const flaggedRef = useRef(null)
  useEffect(() => {
    if (flaggedRef.current) flaggedRef.current.scrollIntoView({ block: 'center' })
  }, [source, active?.finding_id])
  const move = (step) => {
    if (!rows.length) return
    const index = Math.max(0, rows.findIndex((row) => row.finding_id === active?.finding_id))
    const next = rows[Math.min(rows.length - 1, Math.max(0, index + step))]
    if (next) setCurrent(next.finding_id)
  }

  if (!total) {
    const elsewhere = data.code?.elsewhere || []
    return (
      <Card>
        <EmptyState title="No source analysis for this build"
          hint="The action ran no SAST or secret scanner, or its results are not attached to this version yet. An empty list here means nothing was looked at, not that nothing was found." />
        {elsewhere.length > 0 && (
          <div className="sbom-elsewhere">
            <p className="muted">
              Attribution is per build, and this one has none. Other builds of this
              component do:
            </p>
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              {elsewhere.map((row) => (
                <button key={row.version_id} className="mini"
                  onClick={() => onOpenVersion?.(row.version)}>
                  {shortVersion(row.version)} · {elsewhereText(row)}
                </button>
              ))}
            </div>
          </div>
        )}
      </Card>
    )
  }

  // No snippet is a fact about the report, not an empty file: say so instead of
  // drawing one blank line where the code should be.
  const hasSnippet = Boolean(active?.snippet && active.snippet.trim())
  const lines = hasSnippet ? active.snippet.split('\n') : []
  const firstLine = active?.line || 1

  return (
    <>
      <div className="sbom-filters">
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">any severity</option>
          {SEVERITIES.map((value) => <option key={value} value={value}>{value.toLowerCase()}</option>)}
        </select>
        <select value={klass} onChange={(event) => setKlass(event.target.value)}>
          <option value="">weaknesses and secrets</option>
          <option value="weakness">weaknesses only</option>
          <option value="secret">secrets only</option>
        </select>
        <select value={settled} onChange={(event) => setSettled(event.target.value)}>
          <option value="all">open and settled</option>
          <option value="open">open only</option>
          <option value="settled">settled only</option>
        </select>
        <input placeholder="filter by file, rule or message" value={needle}
          onChange={(event) => setNeedle(event.target.value)}
          style={{ minWidth: 280, flex: '1 1 280px' }} />
        <select value={`${sort.key}:${sort.dir}`} onChange={(event) => {
          const [key, dir] = event.target.value.split(':')
          onSort(key, dir)
        }}>
          <option value="severity:asc">worst first</option>
          <option value="path:asc">by file</option>
          <option value="rule:asc">by rule</option>
          <option value="class:asc">secrets first</option>
        </select>
        <span className="muted">
          {rows.length} of {total} findings
          {data.code?.secrets ? ` · ${data.code.secrets} secret${data.code.secrets === 1 ? '' : 's'}` : ''}
          {settledCount ? ` · ${settledCount} settled by a decision` : ''}
        </span>
      </div>

      {/* Attribution is per build, so the component's other source results can
          live on a sibling: name them where the reader already is instead of
          leaving the answer one version away. */}
      {(data.code?.elsewhere || []).length > 0 && (
        <p className="sbom-elsewhere-hint muted">
          Other builds of this component carry source findings:{' '}
          {(data.code?.elsewhere || []).map((row) => (
            <button key={row.version_id} className="mini"
              onClick={() => onOpenVersion?.(row.version)}>
              {shortVersion(row.version)} · {elsewhereText(row)}
            </button>
          ))}
        </p>
      )}

      <div className="sbom-issues">
        <aside className="sbom-issue-list"
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') { event.preventDefault(); move(1) }
            if (event.key === 'ArrowUp') { event.preventDefault(); move(-1) }
          }}>
          {rows.map((row) => (
            <button key={row.finding_id} type="button"
              className={`sbom-issue${active && active.finding_id === row.finding_id ? ' is-active' : ''}`
                + (row.dismissed ? ' is-settled' : '')}
              onClick={() => setCurrent(row.finding_id)}>
              <span className={`sbom-issue-dot sev-${(row.severity || 'unknown').toLowerCase()}`} />
              <span className="sbom-issue-text" title={row.rule || ''}>
                <span className="mono sbom-issue-rule">{shortRule(row.rule)}</span>
                <span className="mono muted sbom-issue-loc">{row.path || '—'}{row.line ? `:${row.line}` : ''}</span>
              </span>
              {row.class === 'secret' && <span className="pill sev-critical">secret</span>}
              {row.dismissed && (
                <span className="pill" title={`status ${row.status}`}>
                  {String(row.status || '').replaceAll('_', ' ')}
                </span>
              )}
            </button>
          ))}
          {!rows.length && <p className="muted" style={{ padding: 12, margin: 0 }}>Nothing matches this filter.</p>}
        </aside>

        <section className="sbom-issue-detail">
          {active ? (
            <>
              <div className="sbom-issue-head">
                <span className={`pill ${severityClass(active.severity)}`}>{active.severity.toLowerCase()}</span>
                <span className="mono sbom-issue-title-rule">{active.rule}</span>
                <span className="row-end muted">
                  {active.class === 'secret' ? 'secret' : active.vector === 'misconfig' ? 'misconfiguration' : 'code weakness'}
                  {active.cwe ? ` · ${active.cwe}` : ''}
                </span>
              </div>

              <div className={`sbom-alert sev-${(active.severity || 'unknown').toLowerCase()}`}>
                <strong>{active.title || active.rule}</strong>
                <p>
                  {active.path}{active.line ? `:${active.line}` : ''} · detected by {active.tool || 'the scanner'} ·
                  {' '}status {active.status}
                </p>
              </div>

              <div className="sbom-code-file">
                <span className="mono">{active.path || '—'}</span>
                <span className="row-end muted">
                  {source?.status === 'ok'
                    ? `whole file · ${String(source.ref).slice(0, 8)}`
                    : 'code at the scanned commit'}
                  <button className="mini" style={{ marginLeft: 8 }}
                    onClick={() => move(-1)} disabled={active === rows[0]}>‹</button>
                  <button className="mini" onClick={() => move(1)}
                    disabled={active === rows[rows.length - 1]}>›</button>
                </span>
              </div>

              {source?.status === 'ok' ? (
                <ol className={`sbom-code-lines is-file sev-${(active.severity || 'unknown').toLowerCase()}`}
                  start={1}>
                  {source.lines.map((line, index) => {
                    const flagged = active.line === index + 1
                    return (
                      <li key={index} className={flagged ? 'is-flagged' : ''}
                        ref={flagged ? flaggedRef : undefined}>
                        <span className="sbom-code-num">{index + 1}</span>
                        <code>{line || ' '}</code>
                      </li>
                    )
                  })}
                </ol>
              ) : source?.status === 'loading' ? (
                <p className="muted" style={{ padding: '10px 12px', margin: 0 }}>loading the file…</p>
              ) : lines.length ? (
                <ol className={`sbom-code-lines sev-${(active.severity || 'unknown').toLowerCase()}`}
                  start={firstLine}>
                  {lines.map((line, index) => (
                    <li key={index} className={index === 0 ? 'is-flagged' : ''}
                      ref={index === 0 ? flaggedRef : undefined}>
                      <span className="sbom-code-num">{firstLine + index}</span>
                      <code>{line || ' '}</code>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="muted" style={{ padding: '10px 12px', margin: 0 }}>
                  {(source && source.reason) || 'The scanner reported no source region for this finding.'}
                </p>
              )}

              {active.url && (
                <p style={{ margin: 0, padding: '8px 12px' }}>
                  <a href={active.url} target="_blank" rel="noreferrer">rule documentation</a>
                </p>
              )}
            </>
          ) : null}
        </section>
      </div>
    </>
  )
}

/* ── dependency graph: what the build ships, and how it hangs together ─────── */

function mergeCounts(into, counts) {
  const next = { ...into }
  for (const severity of SEVERITIES) next[severity] = (next[severity] || 0) + (counts?.[severity] || 0)
  return next
}

function GraphNode({ row, depth, childrenOf, selected, onPick }) {
  const children = childrenOf.get(row.purl) || []
  const [open, setOpen] = useState(depth === 0)
  return (
    <li>
      <div
        className={`sbom-graph-node${selected && selected.component_id === row.component_id ? ' is-selected' : ''}`}
        style={depth ? { marginLeft: depth * 18 } : undefined}
        role="button"
        tabIndex={0}
        onClick={() => onPick(row)}
        onKeyDown={(event) => { if (event.key === 'Enter') onPick(row) }}>
        <span
          className="sbom-graph-twisty"
          onClick={(event) => { event.stopPropagation(); if (children.length) setOpen(!open) }}>
          {children.length ? (open ? '▾' : '▸') : ''}
        </span>
        <span className="mono">{row.name}</span>
        <span className="mono muted">{row.version || '—'}</span>
        <span />
        {row.direct ? <span className="pill sbom-graph-flag">direct</span> : <span />}
        <SeverityBar counts={row.by_severity} compact />
        <span className="mono muted sbom-graph-risk">{row.risk ? row.risk.toFixed(1) : '—'}</span>
      </div>
      {open && children.length > 0 && (
        <ul className="sbom-graph-list">
          {children.map((child) => (
            <GraphNode key={child.component_id} row={child} depth={depth + 1}
              childrenOf={childrenOf} selected={selected} onPick={onPick} />
          ))}
        </ul>
      )}
    </li>
  )
}

/* The BOM decides the shape. With resolved parents there is a tree to walk;
   with only a manifest there is a flat list grouped by where it was declared;
   with neither, saying so beats drawing 122 nodes that all say the same thing.
   A star of leaves is a table with worse aim. */
function DependencyGraphTab({ rows, data, selected, onPick, sort, onSort, comparable }) {
  const graph = useMemo(() => {
    const byPurl = new Map(rows.filter((row) => row.purl).map((row) => [row.purl, row]))
    const childrenOf = new Map()
    const roots = []
    for (const row of rows) {
      const parent = row.parent_purl ? byPurl.get(row.parent_purl) : null
      if (parent && parent.component_id !== row.component_id) {
        const list = childrenOf.get(parent.purl) || []
        list.push(row)
        childrenOf.set(parent.purl, list)
      } else {
        roots.push(row)
      }
    }
    const groups = new Map()
    for (const row of roots) {
      const label = row.manifest || 'declared by the application'
      const group = groups.get(label) || { label: label, rows: [], counts: {} }
      group.rows.push(row)
      group.counts = mergeCounts(group.counts, row.by_severity)
      groups.set(label, group)
    }
    const resolved = [...childrenOf.values()].reduce((sum, list) => sum + list.length, 0)
    return {
      childrenOf,
      resolved,
      roots: roots.length,
      groups: [...groups.values()].sort((a, b) => b.rows.length - a.rows.length),
    }
  }, [rows])

  // Two readings of the same data, and the reader picks: the constellation to see
  // shape and orphans, the table to sort and search. The choice sticks.
  const panelRef = useRef(null)
  useEffect(() => {
    // Clicking a node must show its answer, not park it below the fold.
    if (selected && panelRef.current) {
      panelRef.current.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    }
  }, [selected && selected.component_id])

  const [mode, setMode] = useState(() => {
    try { return localStorage.getItem('barad.depView') === 'table' ? 'table' : 'graph' } catch { return 'graph' }
  })
  const pickMode = (next) => {
    setMode(next)
    try { localStorage.setItem('barad.depView', next) } catch { /* private mode */ }
  }
  const [collapsed, setCollapsed] = useState({})
  const manifests = graph.groups.filter((group) => group.label !== 'declared by the application')
  // One manifest and no edges means there is no grouping to show: the header
  // row would be a caption over a list that is already flat. The manifest is
  // still the answer to "where does this come from", so it goes in the sentence.
  const flat = !graph.resolved && graph.groups.length === 1

  if (!rows.length) {
    return (
      <Card>
        <EmptyState title="Nothing to draw"
          hint="This build has no components yet: import a BOM and the graph starts here." />
      </Card>
    )
  }

  return (
    <>
      <div className="sbom-view-toggle">
        <button className={`mini${mode === 'graph' ? ' is-active' : ''}`}
          onClick={() => pickMode('graph')}>graph</button>
        <button className={`mini${mode === 'table' ? ' is-active' : ''}`}
          onClick={() => pickMode('table')}>table</button>
        <button className={`mini${mode === 'tree' ? ' is-active' : ''}`}
          onClick={() => pickMode('tree')} title="grouped by the manifest that declares each package">
          tree
        </button>
      </div>

      <p className="muted sbom-graph-head">
        {graph.resolved
          ? `${graph.roots} root package${graph.roots === 1 ? '' : 's'} · `
            + `${graph.resolved} transitive, resolved from the BOM's dependency list`
          : `${rows.length} packages, all direct · declared by `
            + `${manifests.length === 1 ? manifests[0].label : 'the manifests'} · `
            + 'this BOM resolves no package-to-package edges (no lockfile)'}
      </p>

      {mode === 'graph' && (
        <>
          <SbomGraph rows={rows} onPick={onPick} selected={selected} compact={!!selected} />
          {selected && (
            <section className="sbom-panel" ref={panelRef}>
              <div className="sbom-panel-head">
                <h2 className="card-title" style={{ margin: 0 }}>
                  {selected.name}{selected.version ? ` ${selected.version}` : ''}
                </h2>
                <button className="mini" onClick={() => onPick(null)}>close</button>
              </div>
              <PackageDetail data={data} row={selected} onPick={onPick} compact />
            </section>
          )}
        </>
      )}

      {/* The table is the components table: same search, same pager, same sort,
          same drawer. A second table here would only learn to disagree with it. */}
      {mode === 'table' && (
        <ComponentsTab data={data} rows={rows} selected={selected} onPick={onPick}
          comparable={comparable} sort={sort} onSort={onSort} />
      )}

      {mode === 'tree' && flat && (
        <Card tight>
          <ul className="sbom-graph-list">
            {graph.groups[0].rows.map((row) => (
              <GraphNode key={row.component_id} row={row} depth={0}
                childrenOf={graph.childrenOf} selected={selected} onPick={onPick} />
            ))}
          </ul>
        </Card>
      )}

      {mode === 'tree' && !flat && graph.groups.map((group) => (
        <Card key={group.label} tight>
          <div className="sbom-graph-group"
            onClick={() => setCollapsed({ ...collapsed, [group.label]: !collapsed[group.label] })}>
            <span className="sbom-graph-twisty">{collapsed[group.label] ? '▸' : '▾'}</span>
            <span className="mono sbom-graph-label">{group.label}</span>
            <span className="muted">{group.rows.length} package{group.rows.length === 1 ? '' : 's'}</span>
            <span />
            <span />
            <SeverityBar counts={group.counts} compact />
            <span />
          </div>
          {!collapsed[group.label] && (
            <ul className="sbom-graph-list">
              {group.rows.map((row) => (
                <GraphNode key={row.component_id} row={row} depth={0}
                  childrenOf={graph.childrenOf} selected={selected} onPick={onPick} />
              ))}
            </ul>
          )}
        </Card>
      ))}
    </>
  )
}

function BomView({ project, component, version, versionId, onBack, embedded }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState('overview')
  // One drawer for the whole screen: a package opened from "where to start" and
  // one opened from the table are the same question.
  const [selected, setSelected] = useState(null)
  // Ordering belongs to the platform: the table is paginated, and a page that
  // sorts itself only orders the rows that happen to be on it.
  const [componentSort, setComponentSort] = useState({ key: 'risk', dir: 'desc' })
  const [advisorySort, setAdvisorySort] = useState({ key: 'severity', dir: 'asc' })
  const [codeSort, setCodeSort] = useState({ key: 'severity', dir: 'asc' })

  useEffect(() => {
    setData(null)
    setError('')
    const params = new URLSearchParams({
      project, version,
      component_sort: componentSort.key, component_dir: componentSort.dir,
      advisory_sort: advisorySort.key, advisory_dir: advisorySort.dir,
      code_sort: codeSort.key, code_dir: codeSort.dir,
    })
    if (versionId) params.set('version_id', versionId)
    if (component) params.set('component', component)
    api.get(`/api/v1/sbom/version?${params.toString()}`)
      .then((r) => setData(r.data))
      .catch((e) => setError(String(e.message || e)))
  }, [project, component, version, versionId, componentSort.key, componentSort.dir,
      advisorySort.key, advisorySort.dir, codeSort.key, codeSort.dir])

  if (error) return <ErrorBanner error={error} />
  if (!data) return <Card><Loading rows={5} /></Card>

  const rows = data.component_rows || []
  const total = data.findings?.total || 0

  return (
    <div className="stack">
      <div className="sbom-head">
        <div>
          <p className="project-crumb" style={{ marginBottom: 6 }}>
            <button onClick={onBack}>‹ {embedded ? 'Components' : 'SBOMs'}</button>
          </p>
          <h1 className="page-title">{data.project.name} <span className="mono sbom-version">{data.version}</span></h1>
          <p className="page-sub">
            {data.components} components
            {data.direct ? ` · ${data.direct} direct` : ''} ·{' '}
            {total} open finding{total === 1 ? '' : 's'}
            {data.previous_version && trendContext(data).comparable
              ? ` · compared with ${shortVersion(data.previous_version)}` : ''}
          </p>
        </div>
      </div>

      <Tabs
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'components', label: `Components (${data.components})` },
          { id: 'vulnerabilities', label: `Audit vulnerabilities (${total})` },
          { id: 'graph', label: 'Dependency graph' },
          { id: 'policy', label: 'Policy violations' },
          // The label counts every row the tab holds: open plus the ones a
          // person settled. Hiding the settled ones made a dismissed secret
          // scan read as a build nobody scanned.
          { id: 'code', label: `Code findings (${(data.code?.total || 0) + (data.code?.dismissed || 0)})` },
        ]}
        active={tab}
        onChange={setTab} />

      {tab === 'overview' && (
        <Overview data={data} rows={rows} onPick={setSelected} onTab={setTab} />
      )}
      {tab === 'components' && (
        <ComponentsTab data={data} rows={rows} selected={selected} onPick={setSelected}
          comparable={trendContext(data).comparable}
          sort={componentSort} onSort={(key) => setComponentSort((current) => nextSort(current, key))} />
      )}
      {tab === 'vulnerabilities' && (
        <VulnerabilitiesTab data={data} rows={rows}
          sort={advisorySort} onSort={(key) => setAdvisorySort((current) => nextSort(current, key))} />
      )}

      {tab !== 'graph' && (
        <ComponentDrawer data={data} row={selected} onClose={() => setSelected(null)} onPick={setSelected} />
      )}

      {tab === 'graph' && (
        <DependencyGraphTab rows={rows} data={data} selected={selected} onPick={setSelected}
          sort={componentSort}
          onSort={(key) => setComponentSort((current) => nextSort(current, key))}
          comparable={trendContext(data).comparable} />
      )}

      {tab === 'policy' && (
        <Card>
          <EmptyState title="Policy violations — no policy engine yet"
            hint="Nothing to evaluate against: the rules that would say “no GPL in production” or “no CRITICAL in a public build” do not exist in this platform. This tab is where they will land." />
        </Card>
      )}

      {tab === 'code' && (
        <CodeFindingsTab data={data} sort={codeSort}
          onOpenVersion={(label) => {
            // A route change repaints the view; the in-app callback only pushes
            // state, which left the embedded screen reading the old build.
            const parts = [data.project?.slug || project,
              data.component_slug || data.component || component,
              label].filter(Boolean).map(encodeURIComponent)
            window.location.hash = `components::${parts.join('/')}`
          }}
          onSort={(key, dir) => setCodeSort((current) => (
            dir ? { key, dir } : nextSort(current, key)))} />
      )}
    </div>
  )
}

/* ── overview: the direction of travel ─────────────────────────────────────── */

/* Which build to compare against, and whether the comparison means anything.
   A previous build with no analysis at all makes every delta "+N": that is noise,
   not growth, and saying so is cheaper than explaining it later. */
function trendContext(data) {
  const trend = data.trend || []
  const current = trend.find((row) => row.version_id === data.version_id)
  const previous = [...trend].reverse().find((row) => row.version_id !== data.version_id
    && (!current || new Date(row.at) < new Date(current.at)))
  return {
    trend, current, previous,
    comparable: Boolean(previous && previous.findings > 0),
  }
}

function Overview({ data, rows, onPick, onTab }) {
  const { trend, current, previous, comparable } = trendContext(data)
  const counts = data.findings?.by_severity || {}
  const total = data.findings?.total || 0
  const worst = SEVERITIES.find((severity) => counts[severity]) || null
  const kev = (data.vulnerabilities || []).filter((row) => row.kev)
  const code = data.code || { total: 0, secrets: 0 }

  // The list is the answer to "what do I do now": worst risk first, and only
  // packages that carry something.
  const kevPurls = new Set(kev.map((row) => row.purl).filter(Boolean))
  const kevNames = new Set(kev.map((row) => row.component).filter(Boolean))
  const ranked = [...rows].filter((row) => row.findings > 0)
    .sort((a, b) => {
      // Exploited beats risky: a risk score is a model, a KEV entry is a fact.
      const aKev = kevPurls.has(a.purl) || kevNames.has(a.name) ? 1 : 0
      const bKev = kevPurls.has(b.purl) || kevNames.has(b.name) ? 1 : 0
      return (bKev - aKev) || (b.risk - a.risk)
    })
  const first = ranked.slice(0, 6)
  const lead = first[0] || null
  const leadCve = lead ? (kev.find((row) => row.purl === lead.purl
    || row.component === lead.name) || {}).vulnerability : null

  const licenceNames = Object.keys(data.licenses || {})
  const unknownLicence = (data.licenses || {}).unknown || 0
  const facts = [
    ['licenses', unknownLicence === data.components
      ? 'all unknown'
      : `${licenceNames.filter((name) => name !== 'unknown').length} distinct`,
      unknownLicence && unknownLicence !== data.components ? `${unknownLicence} unknown` : ''],
    ['code findings', `${code.total}`,
      [code.secrets ? `${code.secrets} secret${code.secrets === 1 ? '' : 's'}` : '',
        code.dismissed ? `${code.dismissed} settled` : ''].filter(Boolean).join(' · ')],
    ['imports', `${(data.imports || []).length}`, data.imports?.[0]?.source ? `· ${data.imports[0].source}` : ''],
  ]
  const analysed = trend.filter((row) => row.findings > 0).length

  return (
    <div className="ov">
      {/* One sentence first. Four equal KPI cards made the reader assemble the
          answer themselves; this states it and lets the details hang below. */}
      <section className="ov-hero">
        <p className="ov-eyebrow">
          {data.project.name} · {data.version}
          {data.component ? ` · ${data.component}` : ''} · {relative(data.last_import_at)}
        </p>
        <h2 className="ov-verdict">
          {leadCve
            ? <>Start with <span className="ov-name-lead mono">{lead.name}</span> — {leadCve} is exploited in the wild</>
            : lead
              ? <>Start with <span className="ov-name-lead mono">{lead.name}</span> — the highest risk here</>
              : <>Nothing to fix in this build</>}
        </h2>
        <p className="ov-lede">
          {total
            ? <><span className="ov-figure">{total}</span> dependency finding{total === 1 ? '' : 's'} across
              {' '}{data.components} packages{worst ? <> · worst is <b className={`ov-sev sev-${worst.toLowerCase()}`}>{worst.toLowerCase()}</b></> : null}
              {code.total ? <> · plus {code.total} code findings</> : null}</>
            : <>in {data.components} packages: the analysis found nothing to fix here.</>}
        </p>

        <div className="ov-sev-row">
          {SEVERITIES.slice(0, 4).map((severity) => (
            <span key={severity} className={`ov-sev-chip${counts[severity] ? '' : ' is-empty'} sev-${severity.toLowerCase()}`}>
              <b>{counts[severity] || 0}</b>
              <span>{severity.toLowerCase()}</span>
            </span>
          ))}
          {total > 0 && (
            <button className="mini ov-more" onClick={() => onTab && onTab('vulnerabilities')}>
              all {total} findings ›
            </button>
          )}
        </div>

        {kev.length > 0 && !leadCve && (
          <div className="ov-kev">
            <span className="pill sev-critical">known exploited</span>
            <span>
              {kev.length === 1 ? 'One advisory here is' : `${kev.length} advisories here are`} on CISA's
              exploited list:
              {' '}
              {kev.slice(0, 3).map((row, index) => (
                <React.Fragment key={row.finding_id}>
                  {index ? ', ' : ''}
                  <button className="ov-inline-link mono" onClick={() => {
                    const hit = rows.find((candidate) => candidate.purl && candidate.purl === row.purl)
                      || rows.find((candidate) => candidate.name === row.component)
                    if (hit) onPick(hit)
                  }}>{row.vulnerability}{row.component ? ` in ${row.component}` : ''}</button>
                </React.Fragment>
              ))}
            </span>
          </div>
        )}

        {leadCve && kev.length > 1 && (
          <div className="ov-kev">
            <span className="pill sev-critical">known exploited</span>
            <span>
              {kev.length - 1} more {kev.length - 1 === 1 ? 'advisory is' : 'advisories are'} on CISA's
              exploited list — <button className="ov-inline-link" onClick={() => onTab && onTab('vulnerabilities')}>
                see them in the audit
              </button>
            </span>
          </div>
        )}
      </section>

      <div className="ov-body">
        <section className="ov-queue">
          <h3 className="ov-title">
            Do these first
            <span className="muted">exploited first, then risk · click a row for its advisories</span>
          </h3>
          {first.length ? (
            <>
            <div className="ov-head muted">
              <span />
              <span />
              <span>package</span>
              <span>why</span>
              <span>severity mix</span>
              <span>risk</span>
            </div>
            <ul className="ov-list">
              {first.map((row, index) => (
                <li key={row.component_id}>
                  <button className="ov-row" onClick={() => onPick(row)}>
                    <span className="ov-rank mono">{String(index + 1).padStart(2, '0')}</span>
                    <span className={`ov-spine sev-${(row.worst || 'unknown').toLowerCase()}`} />
                    <span className="ov-name">
                      <span className="mono">{row.name}</span>
                      <span className="muted mono">{row.version || '—'}</span>
                      {(kevPurls.has(row.purl) || kevNames.has(row.name))
                        && <span className="pill sev-critical">KEV</span>}
                    </span>
                    <span className="ov-why muted">
                      {row.worst ? `${String(row.worst).toLowerCase()} worst` : 'no severity'}
                      {row.findings ? ` · ${row.findings} finding${row.findings === 1 ? '' : 's'}` : ''}
                      {row.direct ? '' : ' · transitive'}
                    </span>
                    <span className="ov-bar"><SeverityBar counts={row.by_severity} compact /></span>
                    <RiskScore value={row.risk} />
                  </button>
                </li>
              ))}
            </ul>
            </>
          ) : (
            <p className="muted" style={{ margin: 0 }}>
              No package in this build carries a finding. An SBOM is an inventory, not a
              verdict: analysing it is what turns packages into findings.
            </p>
          )}
          {ranked.length > first.length && (
            <button className="mini ov-more" onClick={() => onTab && onTab('components')}>
              {ranked.length - first.length} more packages with findings ›
            </button>
          )}
        </section>

        <aside className="ov-side">
          <h3 className="ov-title">This build</h3>
          <dl className="ov-facts">
            {facts.map(([label, value, extra]) => (
              <React.Fragment key={label}>
                <dt>{label}</dt>
                <dd><span className="mono">{value}</span> <span className="muted">{extra}</span></dd>
              </React.Fragment>
            ))}
          </dl>

          <h3 className="ov-title" style={{ marginTop: 20 }}>History</h3>
          {trend.length > 1 ? (
            <>
              <div className="ov-strip">
                {trend.map((row) => {
                  const rank = SEVERITIES.findIndex((severity) => row.by_severity?.[severity])
                  const worst = rank >= 0 ? SEVERITIES[rank] : null
                  return (
                    <span key={row.version_id}
                      className={`ov-tick${row.findings ? ` sev-${worst.toLowerCase()}` : ' is-empty'}`
                        + (row.version_id === data.version_id ? ' is-current' : '')}
                      style={{ height: row.findings ? Math.min(34, 8 + Math.sqrt(row.findings) * 4) : 6 }}
                      title={`${shortVersion(row.version)} · ${row.findings} finding${row.findings === 1 ? '' : 's'} · ${row.components} packages`} />
                  )
                })}
              </div>
              <p className="muted ov-note">
                {trend.length} builds, {analysed} analysed · the outlined tick is the one you are reading.
              </p>
            </>
          ) : (
            <p className="muted ov-note">Only one build of this project has a BOM.</p>
          )}

          <h3 className="ov-title" style={{ marginTop: 20 }}>Since {previous ? shortVersion(previous.version) : 'always'}</h3>
          {!previous ? (
            <p className="muted ov-note">This is the first build of {data.project.name} with a BOM — nothing to compare yet.</p>
          ) : !comparable ? (
            <p className="muted ov-note">
              {shortVersion(previous.version)} was imported but never analysed, so nothing here has
              a delta yet.
            </p>
          ) : (
            <ul className="ov-delta">
              {rows.filter((row) => row.findings_previous != null && row.findings !== row.findings_previous)
                .sort((a, b) => (b.findings - b.findings_previous) - (a.findings - a.findings_previous))
                .slice(0, 5)
                .map((row) => {
                  const change = row.findings - row.findings_previous
                  return (
                    <li key={row.component_id}>
                      <span className={`mono ${change > 0 ? 'ov-up' : 'ov-down'}`}>{change > 0 ? '+' : ''}{change}</span>
                      <span className="mono">{row.name}</span>
                      <span className="muted">{row.findings_previous} → {row.findings}</span>
                    </li>
                  )
                })}
            </ul>
          )}

          <p className="muted ov-note" style={{ marginTop: 18 }}>
            risk = severity weight × KEV × EPSS, capped at 100 · click any package for its advisories.
          </p>
        </aside>
      </div>
    </div>
  )
}


function TrendBars({ trend, currentId }) {
  const max = Math.max(...trend.map((row) => row.findings), 1)
  return (
    <div className="sbom-trend">
      {trend.map((row) => (
        <div key={row.version_id}
          className={`sbom-trend-col${row.version_id === currentId ? ' is-current' : ''}`}
          title={`${row.version} · ${row.findings} finding(s) · ${row.components} components`}>
          <div className="sbom-trend-area">
            <div className="sbom-trend-stack"
              style={{ height: row.findings ? `${Math.max(6, Math.round((row.findings / max) * 96))}px` : 2 }}>
              {SEVERITIES.filter((severity) => row.by_severity?.[severity]).map((severity) => (
                <span key={severity} className={`sbom-trend-seg sev-${severity.toLowerCase()}`}
                  style={{ flexGrow: row.by_severity[severity] }} />
              ))}
            </div>
          </div>
          <span className="sbom-trend-count">{row.findings}</span>
          <span className="sbom-trend-label mono">{shortVersion(row.version)}</span>
        </div>
      ))}
    </div>
  )
}

function shortVersion(value) {
  if (!value) return '—'
  return value.length > 8 ? `${value.slice(0, 8)}…` : value
}

/* Clicking a header asks the platform for a new order: numbers start descending
   (the biggest first is the question), text starts ascending (A→Z is the index). */
function nextSort(sort, field) {
  if (sort.key === field) {
    return { key: field, dir: sort.dir === 'asc' ? 'desc' : 'asc' }
  }
  return { key: field, dir: NUMERIC_SORTS.has(field) ? 'desc' : 'asc' }
}

/* "Which of my packages drags this one in?" — purl → parent name, built once per
   table so a CVE on a package nobody declared stops being a mystery. */
function parentNames(componentRows) {
  const byPurl = new Map(componentRows.filter((row) => row.purl).map((row) => [row.purl, row]))
  const parents = new Map()
  for (const row of componentRows) {
    // A declared package is not "brought in by" anything. Trivy's graph also
    // carries optional-peer edges (vite → @types/node), and taking the first
    // package edge as provenance labelled a root dependency as transitive.
    if (row.direct) continue
    const parent = row.parent_purl ? byPurl.get(row.parent_purl) : null
    if (parent) parents.set(row.purl, parent.name)
  }
  return parents
}

function SortHeader({ field, label, sort, onSort, className, title }) {
  const active = sort.key === field
  return (
    <th className={className} title={title}>
      <button type="button" className={`sbom-sort${active ? ' active' : ''}`}
        onClick={() => onSort(field)}>
        {label}
        <span className="sbom-sort-arrow" aria-hidden="true">
          {active ? (sort.dir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </button>
    </th>
  )
}

/* ── components: one table, one search, pages ──────────────────────────────── */

function ComponentsTab({ data, rows, selected, onPick, comparable = false, sort, onSort }) {
  const [needle, setNeedle] = useState('')
  const [onlyAffected, setOnlyAffected] = useState(false)
  const parents = useMemo(() => parentNames(rows), [rows])
  const [page, setPage] = useState(0)

  const filtered = useMemo(() => {
    const text = needle.trim().toLowerCase()
    return rows.filter((row) => {
      if (onlyAffected && !row.findings) return false
      if (!text) return true
      return `${row.name || ''} ${row.group || ''} ${row.license || ''} ${row.purl || ''}`
        .toLowerCase().includes(text)
    })
  }, [rows, needle, onlyAffected])

  const pages = Math.max(1, Math.ceil(filtered.length / PER_PAGE))
  const currentPage = Math.min(page, pages - 1)
  const visible = filtered.slice(currentPage * PER_PAGE, currentPage * PER_PAGE + PER_PAGE)

  useEffect(() => { setPage(0) }, [needle, onlyAffected, sort.key, sort.dir])

  return (
    <>
      <div className="sbom-filters">
        <input placeholder="filter by component, group, license or purl"
          value={needle} onChange={(event) => setNeedle(event.target.value)}
          style={{ minWidth: 340, flex: '1 1 340px' }} />
        <label className="check">
          <input type="checkbox" checked={onlyAffected}
            onChange={(event) => setOnlyAffected(event.target.checked)} />
          only with findings
        </label>
        <span className="muted">
          {filtered.length} of {rows.length} components
        </span>
<Pager page={currentPage} pages={pages} onChange={setPage} total={filtered.length} perPage={PER_PAGE} unit="components" className="row-end" />
      </div>

      <Card tight>
        <table className="sbom-components sbom-table">
          <thead>
            <tr>
              <SortHeader field="name" label="component" sort={sort} onSort={onSort} />
              <SortHeader field="version" label="version" sort={sort} onSort={onSort} />
              <SortHeader field="group" label="group" sort={sort} onSort={onSort} />
              <SortHeader field="internal" label="internal" sort={sort} onSort={onSort} />
              <SortHeader field="license" label="license" sort={sort} onSort={onSort} />
              <SortHeader field="risk" label="risk" sort={sort} onSort={onSort}
                title="severity weight × KEV × EPSS" />
              <SortHeader field="findings" label="vulnerabilities" sort={sort} onSort={onSort} />
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => (
              <tr key={row.component_id}
                className={`clickable${selected?.component_id === row.component_id ? ' selected' : ''}`}
                onClick={() => onPick(row)}>
                <td className="title mono">
                  {row.name || '—'}
                  {parents.get(row.purl) && (
                    <span className="sbom-via">via {parents.get(row.purl)}</span>
                  )}
                </td>
                <td className="mono muted">{row.version || '—'}</td>
                <td className="muted mono">{row.group || '—'}</td>
                <td className="muted">{row.internal ? 'yes' : 'no'}</td>
                <td className="muted">{row.license || '—'}</td>
                <td><RiskScore value={row.risk} /></td>
                <td className="sbom-cell-bar">
                  <SeverityBar counts={row.by_severity} />
                  {comparable && row.findings_previous != null
                    && row.findings !== row.findings_previous && (
                    <span className={`sbom-delta ${row.findings > row.findings_previous ? 'up' : 'down'}`}>
                      {row.findings > row.findings_previous ? '+' : ''}
                      {row.findings - row.findings_previous}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && (
          <p className="empty" style={{ margin: 0 }}>Nothing matches this filter.</p>
        )}
      </Card>

<Pager page={currentPage} pages={pages} onChange={setPage} total={filtered.length} perPage={PER_PAGE} unit="components" className="row-end" />

    </>
  )
}

/* ── the drawer: every advisory this package carries ───────────────────────── */

/* The package's story, shared by the drawer and by the panel under the graph:
   identity, how it got here, what it brings in, what is wrong with it. One body,
   two places — a second copy would drift the moment one of them changed. */
function PackageDetail({ data, row, onPick, compact = false }) {
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState('')

  // A hop in the chain, or a package it brings in, is a package too: clicking
  // one opens its drawer instead of making the reader go back to the table.
  const pick = (hop) => {
    if (!onPick || !hop) return
    const id = hop.id || hop.component_id
    const full = (data.component_rows || []).find((candidate) => candidate.component_id === id)
    if (full) onPick(full)
  }

  useEffect(() => {
    setDetail(null)
    setError('')
    if (!row?.component_id) return
    api.get(`/api/v1/sbom/component?version_id=${encodeURIComponent(data.version_id)}`
      + `&component_id=${encodeURIComponent(row.component_id)}`)
      .then((r) => setDetail(r.data))
      .catch((e) => setError(String(e.message || e)))
  }, [row?.component_id, data.version_id])

  const versions = detail?.versions || []
  // "Declared by" needs a name: the manifest when the BOM carries one, else the
  // package that pulls it in (the app itself for npm), else the application.
  const parentRow = (data.component_rows || []).find(
    (candidate) => candidate.purl && candidate.purl === row?.parent_purl)
  const declaredBy = row ? (row.manifest || parentRow?.name || 'the application') : 'the application'

  if (!row) return null

  return (
    <div className="stack">
          <Card title={compact ? undefined : 'Package'}>
            <div className="stack" style={{ gap: 8 }}>
              <Field label="group">{row.group || '—'}</Field>
              <Field label="version">{row.version || '—'}</Field>
              <Field label="license">{row.license || '—'}</Field>
              <Field label="purl">{row.purl || '—'}</Field>
              <Field label="internal">{row.internal ? 'first-party' : 'third-party'}</Field>
              <Field label="relationship">
                {row.direct ? 'direct' : row.parent_purl ? 'transitive' : '—'}
                {row.manifest ? <span className="muted"> · from {row.manifest}</span> : null}
              </Field>
              <Field label="risk"><RiskScore value={row.risk} /></Field>
              <Field label="findings">
                {row.findings ? <SeverityBar counts={row.by_severity} /> : 'none in this build'}
              </Field>
            </div>
          </Card>

          {(detail?.path || []).length > 0 && (
            <Card title="How it got here">
              <div className="sbom-path">
                <span className="mono">{row.name}{row.version ? ` ${row.version}` : ''}</span>
                {detail.path.map((hop) => (
                  <React.Fragment key={hop.id}>
                    <span className="muted">←</span>
                    <button type="button" className="sbom-path-hop mono"
                      onClick={() => pick(hop)}>{hop.name}</button>
                  </React.Fragment>
                ))}
                <span className="muted">←</span>
                <span className="muted">application</span>
              </div>
              <p className="muted" style={{ margin: '8px 0 0', fontSize: 12 }}>
                {row.direct
                  ? `Declared by ${declaredBy} — this one is yours to upgrade.`
                  : 'You never declared this package: it arrives through the chain above.'}
              </p>
            </Card>
          )}

          {(detail?.requires || []).length > 0 && (
            <Card title={`Brings in ${detail.requires.length} package${detail.requires.length === 1 ? '' : 's'}`}>
              <ul className="sbom-deps">
                {detail.requires.map((child) => (
                  <li key={child.id}>
                    <button type="button" className="sbom-dep-name mono"
                      onClick={() => pick(child)}>{child.name}</button>
                    <span className="mono muted">{child.version || '—'}</span>
                    <span className="row-end">
                      {child.findings
                        ? <span className={`pill ${severityClass(child.worst)}`}
                          title={`${child.findings} finding${child.findings === 1 ? '' : 's'}, worst ${String(child.worst).toLowerCase()}`}>
                          {child.findings}
                        </span>
                        : <span className="muted">clean</span>}
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {error && <ErrorBanner error={error} />}
          {!detail && !error && <Loading rows={3} label="loading advisories" />}

          {detail && (
            versions.length ? versions.map((version) => (
              <Card key={version.version_id}
                title={`${version.version} · ${version.findings.length} advisor${version.findings.length === 1 ? 'y' : 'ies'}`
                  + (version.is_current ? ' · this build' : '')}>
                <ul className="sbom-cves">
                  {version.findings.map((finding) => (
                    <li key={finding.id}>
                      <SeverityBadge severity={finding.severity} />
                      <span className="mono">
                        {finding.url
                          ? <a href={finding.url} target="_blank" rel="noreferrer">{finding.advisory}</a>
                          : finding.advisory || '—'}
                      </span>
                      {finding.kev && <span className="pill sev-critical">KEV</span>}
                      {finding.epss != null && (
                        <span className="muted">EPSS {epssLabel(finding.epss)}</span>
                      )}
                      <span className="muted sbom-cve-title">{finding.title || ''}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            )) : (
              <p className="muted" style={{ margin: 0 }}>
                This package carries no advisory in this build or any later one.
              </p>
            )
          )}
    </div>
  )
}

function ComponentDrawer({ data, row, onClose, onPick }) {
  return (
    <Drawer open={!!row} onClose={onClose}
      title={row ? `${row.name}${row.version ? ` ${row.version}` : ''}` : 'Component'}>
      <PackageDetail data={data} row={row} onPick={onPick} />
    </Drawer>
  )
}

function Field({ label, children }) {
  return (
    <div className="row" style={{ gap: 10, alignItems: 'baseline' }}>
      <span className="muted" style={{ flex: '0 0 92px' }}>{label}</span>
      <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>{children}</span>
    </div>
  )
}

/* ── audit vulnerabilities: the flat list ──────────────────────────────────── */

function VulnerabilitiesTab({ data, rows: componentRows = [], sort, onSort }) {
  const [severity, setSeverity] = useState('')
  const [needle, setNeedle] = useState('')
  const [onlyKev, setOnlyKev] = useState(false)
  const [page, setPage] = useState(0)
  const parents = useMemo(() => parentNames(componentRows), [componentRows])

  const rows = useMemo(() => {
    const text = needle.trim().toLowerCase()
    // The order arrives from the platform; filtering is the only thing this page
    // is allowed to do to it.
    return (data.vulnerabilities || []).filter((row) => {
      if (severity && row.severity !== severity) return false
      if (onlyKev && !row.kev) return false
      if (!text) return true
      return `${row.component || ''} ${row.vulnerability || ''} ${row.title || ''}`
        .toLowerCase().includes(text)
    })
  }, [data, severity, needle, onlyKev])

  const pages = Math.max(1, Math.ceil(rows.length / PER_PAGE))
  const currentPage = Math.min(page, pages - 1)
  const visible = rows.slice(currentPage * PER_PAGE, currentPage * PER_PAGE + PER_PAGE)

  useEffect(() => { setPage(0) }, [needle, severity, onlyKev, sort.key, sort.dir])

  return (
    <>
      <div className="sbom-filters">
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">any severity</option>
          {SEVERITIES.map((value) => <option key={value} value={value}>{value.toLowerCase()}</option>)}
        </select>
        <input placeholder="filter by component, CVE or title" value={needle}
          onChange={(event) => setNeedle(event.target.value)}
          style={{ minWidth: 320, flex: '1 1 320px' }} />
        <label className="check">
          <input type="checkbox" checked={onlyKev}
            onChange={(event) => setOnlyKev(event.target.checked)} />
          only KEV
        </label>
        <span className="muted">
          {rows.length} of {(data.vulnerabilities || []).length} advisories
        </span>
<Pager page={currentPage} pages={pages} onChange={setPage} total={rows.length} perPage={PER_PAGE} unit="advisories" className="row-end" />
      </div>
      <Card tight>
        {rows.length ? (
          <table className="sbom-vulns">
            <thead>
              <tr>
                <SortHeader field="component" label="component" sort={sort} onSort={onSort} />
                <SortHeader field="version" label="version" sort={sort} onSort={onSort} />
                <SortHeader field="vulnerability" label="vulnerability" sort={sort} onSort={onSort} />
                <SortHeader field="severity" label="severity" sort={sort} onSort={onSort} />
                <SortHeader field="epss" label="epss" sort={sort} onSort={onSort} className="num"
                  title="FIRST EPSS: probability this CVE is exploited in the wild" />
                <SortHeader field="kev" label="kev" sort={sort} onSort={onSort} />
                <SortHeader field="analyzer" label="analyzer" sort={sort} onSort={onSort} />
                <th>attributed on</th>
                <SortHeader field="status" label="analysis" sort={sort} onSort={onSort} />
              </tr>
            </thead>
            <tbody>
              {visible.map((row) => (
                <tr key={row.finding_id}>
                  <td className="title mono">
                    {row.component || '—'}
                    {parents.get(row.purl) && (
                      <span className="sbom-via">via {parents.get(row.purl)}</span>
                    )}
                  </td>
                  <td className="mono muted">{row.component_version || '—'}</td>
                  <td className="mono">
                    {row.url ? <a href={row.url} target="_blank" rel="noreferrer">{row.vulnerability}</a>
                      : row.vulnerability || row.title || '—'}
                  </td>
                  <td><span className={`pill ${severityClass(row.severity)}`}>{row.severity.toLowerCase()}</span></td>
                  <td className="num mono"
                    title={row.epss == null
                      ? 'not scored by FIRST EPSS'
                      : `EPSS: ${(row.epss * 100).toFixed(1)}% probability of exploitation`}>
                    {row.epss == null
                      ? <span className="muted">—</span>
                      : <span className={row.epss >= 0.1 ? 'sbom-epss hot' : 'sbom-epss'}>
                        {epssLabel(row.epss)}
                      </span>}
                  </td>
                  <td>{row.kev ? <span className="pill sev-critical">KEV</span> : <span className="muted">—</span>}</td>
                  <td className="muted">{row.analyzer}</td>
                  <td className="muted">{relative(row.attributed_on)}</td>
                  <td className="muted">
                    {row.analysis}
                    {row.suppressed ? <span className="pill">suppressed</span> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted" style={{ margin: 0 }}>
            {(data.vulnerabilities || []).length
              ? 'Nothing matches this filter.'
              : 'No findings attached to this version yet. Import a BOM and analyse it — an inventory alone has no vulnerabilities.'}
          </p>
        )}
      </Card>

<Pager page={currentPage} pages={pages} onChange={setPage} total={rows.length} perPage={PER_PAGE} unit="advisories" className="row-end" />
    </>
  )
}
