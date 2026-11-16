import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import AssetGraph from './AssetGraph'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Pager, Select, Table,
  Tabs, usePage,
} from './ui'
import { useI18n } from './i18n'

/* Assets answers four questions, so it has four tabs: what is declared, what is
   missing from it, how it is grouped, and what happened.

   The inventory is a TREE, because a domain estate is one: `dev.api.example`
   hangs from `api.example`, which hangs from `example`. The hierarchy is derived
   from the names that exist (server-side), so nothing has to be maintained when
   a subdomain appears.

   Every row answers what the operator asked for, in order: the address, is it
   alive, does the certificate expire and when — and `more data` opens the rest,
   including what the platform is allowed to do with it. Declaring a domain never
   grants anything: it opens a request in Grants, the only screen where
   permission is minted. */

const CLASSIFICATIONS = [
  { value: 'unclassified', labelKey: 'assets.class.unclassified' },
  { value: 'pending', labelKey: 'assets.class.pending' },
  { value: 'owned', labelKey: 'assets.class.owned' },
  { value: 'confirmed', labelKey: 'assets.class.confirmed' },
  { value: 'external', labelKey: 'assets.class.external' },
  { value: 'discarded', labelKey: 'assets.class.discarded' },
]

const LEVELS = [
  { value: 'simple', labelKey: 'assets.level.simple', hintKey: 'assets.level.simple.hint' },
  { value: 'advanced', labelKey: 'assets.level.advanced', hintKey: 'assets.level.advanced.hint' },
  { value: 'redteam', labelKey: 'assets.level.redteam', hintKey: 'assets.level.redteam.hint' },
]

const LEVEL_LABEL = Object.fromEntries(LEVELS.map((level) => [level.value, level.labelKey]))

const PER_PAGE = 25

/* A certificate is three facts, not one: who signed it, whether a browser would
   trust it, and when it stops being valid. A failed probe is a trust problem and
   says so — "no expiry" would hide exactly the thing worth reading. */
function certificateView(latest, t) {
  const cert = latest?.certificate
  const error = cert?.error || latest?.error
  if (error) {
    return { tone: 'sev sev-critical', label: t('assets.cert.notTrusted'), detail: String(error) }
  }
  if (!cert) return { tone: 'muted', label: t('assets.cert.notProbed'), detail: '' }
  const days = cert.days_left
  const tone = days === null || days === undefined ? 'pill'
    : days < 0 ? 'sev sev-critical'
      : days <= 14 ? 'sev sev-high'
        : days <= 30 ? 'sev sev-medium' : 'pill'
  const label = days === null || days === undefined ? t('assets.cert.noExpiry')
    : days < 0 ? t('assets.cert.expired', { n: Math.abs(days) })
      : t('assets.cert.daysLeft', { n: days })
  return {
    tone, label,
    detail: [cert.issuer || t('assets.cert.unknownIssuer'),
      cert.not_after
        ? t('assets.cert.validTo', { date: new Date(cert.not_after).toLocaleDateString() })
        : null,
      cert.tls_version].filter(Boolean).join(' · '),
  }
}

/* Alive means "the last observation got an address back". A domain nobody has
   observed is unknown, not down — storing coverage with the observation is what
   makes that distinction honest. */
function addressView(latest, t) {
  if (!latest) return { tone: '', label: t('assets.address.notObserved'), addresses: [] }
  const v4 = latest.ipv4 || []
  const v6 = latest.ipv6 || []
  if (!v4.length && !v6.length) {
    return { tone: 'denied', label: t('assets.address.noAnswer'), addresses: [] }
  }
  return { tone: 'good', label: t('assets.address.active'), addresses: [...v4, ...v6] }
}

function authorizationPill(asset, t, levelLabel) {
  const state = asset.authorization || {}
  if (state.pending_request_id) {
    return (
      <span className="pill" title={t('assets.auth.pendingTitle')}>
        {t('assets.auth.requested')}
      </span>
    )
  }
  if (state.level) {
    const level = levelLabel(state.level)
    return (
      <span className="pill good" title={t('assets.auth.grantedTitle', { level })}>
        {level}
      </span>
    )
  }
  return <span className="pill denied" title={t('assets.auth.noneTitle')}>{t('assets.auth.none')}</span>
}

/* ─────────────────────────── tree ordering ─────────────────────────── */

function buildTree(assets, collapsed) {
  const byId = new Map(assets.map((asset) => [asset.id, asset]))
  const byValue = new Map()
  for (const asset of assets) {
    if (asset.type === 'domain') byValue.set(String(asset.value).toLowerCase(), asset)
  }
  const children = new Map()
  const roots = []
  const sorted = [...assets].sort((left, right) => (
    String(left.value).localeCompare(String(right.value))))
  for (const asset of sorted) {
    const parentValue = asset.parent?.value
      ? String(asset.parent.value).toLowerCase() : null
    const parent = parentValue ? byValue.get(parentValue) : null
    if (parent && parent.id !== asset.id && byId.has(parent.id)) {
      children.set(parent.id, [...(children.get(parent.id) || []), asset])
    } else {
      roots.push(asset)
    }
  }
  const rows = []
  const walk = (list, depth) => {
    for (const asset of list) {
      const kids = children.get(asset.id) || []
      const isCollapsed = collapsed.has(asset.id)
      rows.push({ asset, depth, hasChildren: kids.length > 0, isCollapsed,
        children: kids.length })
      if (!isCollapsed) walk(kids, depth + 1)
    }
  }
  walk(roots, 0)
  // A child whose parent is filtered out is rendered at the top level instead of
  // disappearing: a filtered view must never look like a missing asset. But a
  // child hidden by *collapsing* its parent is not orphaned — it is put away, and
  // re-adding it here is what made a collapsed group leak its children as rows.
  const known = new Set(rows.map((row) => row.asset.id))
  const attached = new Set()
  for (const kids of children.values()) {
    for (const kid of kids) attached.add(kid.id)
  }
  for (const asset of sorted) {
    if (!known.has(asset.id) && !attached.has(asset.id)) {
      rows.push({ asset, depth: 0, hasChildren: false, isCollapsed: false,
        children: 0 })
    }
  }
  return rows
}

/* ─────────────────────────── the screen ─────────────────────────── */

export default function Assets({ onNavigate }) {
  const { t, tCount, tOr } = useI18n()
  const [tab, setTab] = useState('inventory')
  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState({ q: '', type: '', classification: '' })
  const [domain, setDomain] = useState('')
  const [manual, setManual] = useState({ type: 'domain', value: '', project: '' })
  const [principal, setPrincipal] = useState(
    () => localStorage.getItem('barad.principal') || 'collector')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [detail, setDetail] = useState(null)
  const [detailBusy, setDetailBusy] = useState(false)
  const [collapsed, setCollapsed] = useState(() => new Set())

  const [attention, setAttention] = useState([])
  const [groups, setGroups] = useState([])
  const [group, setGroup] = useState(null)
  const [groupDialog, setGroupDialog] = useState(false)
  const [groupForm, setGroupForm] = useState({ name: '', description: '', tags: '' })
  const [stakeholder, setStakeholder] = useState({ actor: '', role: 'owner' })
  const [activity, setActivity] = useState([])
  const [activityAsset, setActivityAsset] = useState('')
  const [edit, setEdit] = useState({ id: '', value: '', owner: '', project: '',
    classification_status: 'unclassified', notes: '', source: '' })
  const [projects, setProjects] = useState([])

  // One page state per tab, declared after every state it reads. The tree is not
  // paged: slicing a hierarchy in half is how a parent loses its children.
  const pagedAttention = usePage(attention, PER_PAGE)
  const pagedGroups = usePage(groups, PER_PAGE)
  const pagedActivity = usePage(activity, PER_PAGE)

  const tree = useMemo(() => buildTree(assets, collapsed), [assets, collapsed])
  // Level names are copy, the value is data: the catalogue wins, the raw value
  // is the honest fallback for a level a future backend adds.
  const levelLabel = (level) => tOr(LEVEL_LABEL[level] || `assets.level.${level}`, level)

  useEffect(() => { load() }, [])
  useEffect(() => {
    api.get('/api/v1/projects').then((r) => setProjects(r.data || [])).catch(() => setProjects([]))
  }, [])
  useEffect(() => { pagedActivity.setPage(0) }, [activityAsset])

  useEffect(() => {
    if (tab === 'attention') loadAttention()
    if (tab === 'groups') loadGroups()
    if (tab === 'activity') loadActivity()
  }, [tab, activityAsset])

  function rememberPrincipal(value) {
    setPrincipal(value)
    localStorage.setItem('barad.principal', value)
  }

  function load() {
    const params = new URLSearchParams({ limit: '500' })
    if (filters.q.trim()) params.set('q', filters.q.trim())
    if (filters.type) params.set('type', filters.type)
    if (filters.classification) params.set('classification', filters.classification)
    api.get(`/api/v1/assets?${params}`)
      .then((r) => { setAssets(r.data || []); setTotal(r.total || 0) })
      .catch((e) => setError(String(e.message || e)))
  }

  function loadAttention() {
    api.get('/api/v1/assets/needs-attention')
      .then((r) => setAttention(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  function loadGroups() {
    return api.get('/api/v1/inventory/groups')
      .then((r) => setGroups(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  function loadActivity() {
    const params = new URLSearchParams({ limit: '100' })
    if (activityAsset) params.set('asset_id', activityAsset)
    api.get(`/api/v1/activity?${params}`)
      .then((r) => setActivity(r.data || []))
      .catch((e) => setError(String(e.message || e)))
  }

  async function refreshDetail(assetId) {
    const [row, changes] = await Promise.all([
      api.get(`/api/v1/assets/${assetId}`),
      api.get(`/api/v1/assets/${assetId}/changes`).catch(() => ({ data: {} })),
    ])
    setDetail({ id: assetId, loading: false, data: row.data,
      changes: changes.data || {} })
    return row.data
  }

  async function openDetail(asset) {
    if (!asset) { setDetail(null); return }
    if (detail?.id === asset.id) { setDetail(null); return }
    setDetail({ id: asset.id, loading: true })
    try {
      await refreshDetail(asset.id)
    } catch (e) {
      setError(String(e.message || e))
      setDetail(null)
    }
  }

  async function collect(asset, withTls = true) {
    setBusy(asset.id)
    setError('')
    setNotice('')
    try {
      const result = await api.post(`/api/v1/assets/${asset.id}/collect`,
        { actor: principal, tls: withTls })
      const dns = result.data.observation.dns || {}
      const probe = result.data.observation.tls
      const certificateNote = probe
        ? (probe.error ? t('assets.notice.certRefused') : t('assets.notice.certRead'))
        : t('assets.notice.dnsOnly')
      setNotice(t('assets.notice.collected', {
        value: asset.value, ipv4: (dns.ipv4 || []).length, ipv6: (dns.ipv6 || []).length,
      }) + certificateNote)
      load()
      if (detail?.id === asset.id) await refreshDetail(asset.id)
    } catch (e) {
      const message = String(e.message || e)
      setError(message.includes('403')
        ? t('assets.error.notAuthorized', { principal, message })
        : message)
    }
    setBusy('')
  }

  async function requestAuthorization(asset) {
    setDetailBusy(true)
    setError('')
    try {
      // The ask is always the minimum; the level is the approver's decision and
      // it happens in Settings → Grants, never on the asset.
      const result = await api.post(`/api/v1/assets/${asset.id}/request`,
        { level: 'simple', actor: 'console' })
      const decision = result.data
      if (decision.covered) {
        setNotice(t('assets.notice.alreadyCovered', { value: asset.value }))
      } else if (decision.excluded) {
        setNotice(t('assets.notice.excludedFromScope', { value: asset.value }))
      } else {
        setNotice(t('assets.notice.requestSent', { value: asset.value }))
      }
      load()
      await refreshDetail(asset.id)
    } catch (e) {
      setError(String(e.message || e))
    }
    setDetailBusy(false)
  }

  async function sweep() {
    if (!domain.trim()) return
    setBusy('sweep')
    try {
      const result = await api.post('/api/v1/assets/discover',
        { domain: domain.trim(), actor: principal })
      setNotice(t('assets.notice.sweep',
        { created: result.data.created, refreshed: result.data.refreshed }))
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
    setBusy('')
  }

  async function addManual() {
    if (!manual.value.trim()) return
    setError('')
    try {
      const result = await api.post('/api/v1/assets', {
        type: manual.type,
        value: manual.value.trim(),
        project: manual.project || undefined,
        actor: 'console',
      })
      // `authorization` is a sibling of `data`: the platform answers what it did
      // to the asset and what it asked about it as two separate facts.
      const decision = result.authorization || {}
      const recorded = decision.request ? 'assets.notice.recordedRequested'
        : decision.excluded ? 'assets.notice.recordedExcluded'
          : decision.covered ? 'assets.notice.recordedCovered' : 'assets.notice.recorded'
      setNotice(t(recorded, { value: manual.value.trim() }))
      setManual((current) => ({ ...current, value: '' }))
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  function openEdit(asset) {
    setEdit({
      id: asset.id, value: asset.value, owner: asset.owner || '',
      project: asset.project || '',
      classification_status: asset.classification_status || 'unclassified',
      notes: asset.notes || '', source: asset.source,
    })
  }

  async function saveEdit() {
    setError('')
    try {
      await api.patch(`/api/v1/assets/${edit.id}`, {
        owner: edit.owner, project: edit.project,
        classification_status: edit.classification_status,
        notes: edit.notes, actor: principal,
      })
      setNotice(t('assets.notice.updated', { value: edit.value }))
      const editedId = edit.id
      setEdit({ id: '', value: '' })
      load()
      if (tab === 'attention') loadAttention()
      if (detail?.id === editedId) setDetail(null)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function toggleArchive(asset) {
    const action = asset.archived_at ? 'unarchive' : 'archive'
    try {
      await api.post(`/api/v1/assets/${asset.id}/${action}`
        + `?actor=${encodeURIComponent(principal)}`)
      setNotice(t(action === 'archive' ? 'assets.notice.archived' : 'assets.notice.unarchived',
        { value: asset.value }))
      setDetail(null)
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function createGroup() {
    if (!groupForm.name.trim()) return
    try {
      const created = await api.post('/api/v1/inventory/groups', {
        name: groupForm.name.trim(),
        description: groupForm.description || null,
        tags: groupForm.tags.split(',').map((t) => t.trim()).filter(Boolean),
        actor: principal,
      })
      setGroupDialog(false)
      setGroupForm({ name: '', description: '', tags: '' })
      await loadGroups()
      openGroup(created.data.id)
      setTab('groups')
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function openGroup(groupId) {
    try {
      const { data } = await api.get(`/api/v1/inventory/groups/${groupId}`)
      setGroup(data)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function addMember(assetId) {
    if (!group || !assetId) return
    try {
      const result = await api.post(`/api/v1/inventory/groups/${group.id}/assets`,
        { asset_ids: [assetId], actor: principal })
      setGroup(result.data)
      loadGroups()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function removeMember(assetId) {
    try {
      const result = await api.del(
        `/api/v1/inventory/groups/${group.id}/assets/${assetId}`
        + `?actor=${encodeURIComponent(principal)}`)
      setGroup(result.data)
      loadGroups()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function addStakeholder() {
    if (!group || !stakeholder.actor.trim()) return
    try {
      const result = await api.post(`/api/v1/inventory/groups/${group.id}/stakeholders`,
        { actor: stakeholder.actor.trim(), role: stakeholder.role, changed_by: principal })
      setGroup(result.data)
      setStakeholder({ actor: '', role: 'owner' })
      loadGroups()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function removeStakeholder(actor) {
    try {
      const result = await api.del(
        `/api/v1/inventory/groups/${group.id}/stakeholders/${encodeURIComponent(actor)}`
        + `?changed_by=${encodeURIComponent(principal)}`)
      setGroup(result.data)
      loadGroups()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function deleteGroup(row) {
    try {
      await api.del(`/api/v1/inventory/groups/${row.id}`
        + `?actor=${encodeURIComponent(principal)}`)
      if (group?.id === row.id) setGroup(null)
      setNotice(t('assets.notice.groupDeleted', { name: row.name }))
      loadGroups()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  function toggleCollapse(assetId) {
    setCollapsed((current) => {
      const next = new Set(current)
      if (next.has(assetId)) next.delete(assetId)
      else next.add(assetId)
      return next
    })
  }

  const memberIds = useMemo(
    () => new Set((group?.members || []).map((m) => m.asset_id)), [group])
  const addable = assets.filter((asset) => !memberIds.has(asset.id))

  return (
    <div className="stack">
      <PageHeader
        title={t('assets.title')}
        subtitle={tCount('assets.subtitle', total)}
        actions={(
          <div className="row" style={{ gap: 8 }}>
            {/* What the estate publishes to the internet, and the ownership
                queue that used to live on its own screen: same assets, same
                action, so it belongs to this object. */}
            {onNavigate && (
              <button className="btn-ghost" onClick={() => onNavigate('attack-surface')}>
                {t('nav.attack-surface')} →
              </button>
            )}
            <button className="primary-action" onClick={() => setGroupDialog(true)}>{t('assets.newGroup')}</button>
          </div>
        )}
      />

      <Tabs
        tabs={[
          { id: 'inventory', label: t('assets.tab.inventory') },
          { id: 'attention', label: t('assets.tab.attention') },
          { id: 'groups', label: t('assets.tab.groups') },
          { id: 'activity', label: t('assets.tab.activity') },
        ]}
        active={tab}
        onChange={setTab}
      />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {tab === 'inventory' && (
        <>
          <div className="toolbar">
            <input placeholder={t('assets.filter.search')} value={filters.q}
              onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && load()} />
            <select value={filters.type}
              onChange={(e) => setFilters((f) => ({ ...f, type: e.target.value }))}>
              <option value="">{t('assets.filter.everyType')}</option>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
              <option value="url">url</option>
              <option value="cidr">cidr</option>
            </select>
            <select value={filters.classification}
              onChange={(e) => setFilters((f) => ({ ...f, classification: e.target.value }))}>
              <option value="">{t('assets.filter.anyClassification')}</option>
              {CLASSIFICATIONS.map((c) => (
                <option key={c.value} value={c.value}>{t(c.labelKey)}</option>
              ))}
            </select>
            <button onClick={load}>{t('assets.filter.apply')}</button>
            <span className="spacer" />
            <span className="muted">
              {tCount('assets.rows', tree.length)}
              {total > assets.length
                ? t('assets.showing', { shown: assets.length, total })
                : ''}
            </span>
          </div>

          {assets.length ? (
            <Table head={[t('assets.col.domain'), t('assets.col.address'), t('assets.col.state'),
              t('assets.col.certificate'), t('assets.col.lastObserved'), '']}>
              {tree.map(({ asset, depth, hasChildren, isCollapsed, children }) => {
                const address = addressView(asset.latest, t)
                const certificate = certificateView(asset.latest, t)
                const selected = detail?.id === asset.id
                return (
                  <React.Fragment key={asset.id}>
                    <tr className={`${depth === 0 ? 'group-head' : 'group-child'}`
                      + (selected ? ' selected' : '')}>
                      <td className="title">
                        <div className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
                          {depth > 0 ? (
                            <span className="tree-join" aria-hidden="true">└</span>
                          ) : null}
                          {hasChildren ? (
                            <button className="mini"
                              aria-label={isCollapsed
                                ? t('assets.tree.expand') : t('assets.tree.collapse')}
                              onClick={() => toggleCollapse(asset.id)}>
                              {isCollapsed ? '▸' : '▾'}
                            </button>
                          ) : <span className="tree-gap" aria-hidden="true" />}
                          <span className="mono"
                            style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>
                            {depth > 0 && asset.parent?.value
                              && String(asset.value).toLowerCase()
                                .endsWith(String(asset.parent.value).toLowerCase())
                              ? <>
                                  <strong>{String(asset.value).slice(
                                    0, asset.value.length - asset.parent.value.length - 1)}</strong>
                                  <span className="muted">
                                    .{asset.parent.value}
                                  </span>
                                </>
                              : asset.value}
                          </span>
                          {hasChildren && (
                            <span className="group-count">
                              {tCount('assets.subdomains', children)}
                            </span>
                          )}
                        </div>
                        <div className="muted"
                          style={{ fontSize: 11.5, marginLeft: depth * 18 + 26 }}>
                          {asset.source} · {tOr(`assets.class.${asset.classification_status}`, asset.classification_status)}
                          {hasChildren && isCollapsed ? t('assets.tree.below', { n: children }) : ''}
                          {asset.project ? ` · ${asset.project}` : ` · ${t('assets.standalone')}`}
                        </div>
                        <div style={{ marginLeft: depth * 18 + 26, marginTop: 2 }}>
                          {authorizationPill(asset, t, levelLabel)}
                        </div>
                      </td>
                      <td>
                        {address.addresses.length ? (
                          <div className="stack" style={{ gap: 2 }}>
                            {address.addresses.slice(0, 3).map((ip) => (
                              <span key={ip} className="mono">{ip}</span>
                            ))}
                            {address.addresses.length > 3 && (
                              <span className="muted">+{address.addresses.length - 3}</span>
                            )}
                          </div>
                        ) : <span className="muted">—</span>}
                      </td>
                      <td>
                        <span className={`state-pill state-${address.tone || 'unknown'}`}>
                          <i className="state-dot" aria-hidden="true" />
                          {address.label}
                        </span>
                      </td>
                      <td>
                        <div className="stack" style={{ gap: 2 }}>
                          <span className={certificate.tone}>{certificate.label}</span>
                          {certificate.detail && (
                            <span className="muted" style={{ fontSize: 11.5 }}
                              title={certificate.detail}>
                              {certificate.detail}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="muted">
                        {asset.latest
                          ? new Date(asset.latest.observed_at).toLocaleString()
                          : new Date(asset.last_seen_at).toLocaleDateString()}
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <button className="mini"
                                onClick={() => { window.location.hash = `asset::${asset.id}` }}>
                          {t('assets.moreData')}
                        </button>
                      </td>
                    </tr>
                    {selected && (
                      <tr className="detail-row"><td colSpan={6}>
                        <AssetDetail
                          detail={detail}
                          principal={principal}
                          onPrincipal={rememberPrincipal}
                          busy={busy === asset.id}
                          requestBusy={detailBusy}
                          onCollect={() => collect(asset, true)}
                          onEdit={() => openEdit(asset)}
                          onArchive={() => toggleArchive(asset)}
                          onRequest={() => requestAuthorization(asset)}
                        />
                      </td></tr>
                    )}
                  </React.Fragment>
                )
              })}
            </Table>
          ) : (
            !error && <EmptyState title={t('assets.empty.title')}
              hint={t('assets.empty.hint')} />
          )}

          <div className="toolbar">
            <input placeholder={t('assets.add.placeholder')} value={manual.value}
              onChange={(e) => setManual((m) => ({ ...m, value: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && addManual()} />
            <select value={manual.type}
              onChange={(e) => setManual((m) => ({ ...m, type: e.target.value }))}>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
              <option value="url">url</option>
              <option value="cidr">cidr</option>
            </select>
            <select value={manual.project}
              onChange={(e) => setManual((m) => ({ ...m, project: e.target.value }))}>
              <option value="">{t('assets.add.noProject')}</option>
              {projects.map((p) => (
                <option key={p.slug} value={p.slug}>{p.name} ({p.slug})</option>
              ))}
            </select>
            <button className="primary-action" onClick={addManual}>{t('assets.add.button')}</button>
            <span className="spacer" />
            <input placeholder={t('assets.sweep.placeholder')} value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && sweep()} />
            <button onClick={sweep} disabled={busy === 'sweep'}>
              {busy === 'sweep' ? t('assets.sweep.busy') : t('assets.sweep.button')}
            </button>
          </div>

          <AssetGraph assets={assets} selectedId={detail?.id}
            onPick={(asset) => (asset ? openDetail(asset) : setDetail(null))} />
        </>
      )}

      {tab === 'attention' && (
        <>
          {/* No filter row here, so the sentence that explains the table and the
              pager share the line above it instead of adding a bar of their own. */}
          <div className="toolbar">
            <p className="muted" style={{ margin: 0, flex: '1 1 360px' }}>
              {t('assets.attention.note')}
            </p>
            <Pager page={pagedAttention.page} pages={pagedAttention.pages}
              onChange={pagedAttention.setPage} total={pagedAttention.total}
              perPage={PER_PAGE} unit={t('unit.assets')} className="row-end" />
          </div>
          {attention.length ? (
            <Table head={[t('assets.attention.col.asset'), t('assets.attention.col.why'),
              t('assets.attention.col.fix'), '']}>
              {pagedAttention.rows.map((row) => (
                <tr key={row.asset.id}>
                  <td className="title">
                    {row.asset.value}
                    <div className="muted" style={{ fontSize: 11.5 }}>
                      {row.asset.type} · {row.observation}
                    </div>
                  </td>
                  <td>
                    {row.reasons.map((reason) => (
                      <div key={reason.code} className="occ-row">
                        <strong>{reason.code}</strong>: {reason.what}
                      </div>
                    ))}
                  </td>
                  <td className="muted">{row.reasons[0].action}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="mini" onClick={() => openEdit(row.asset)}>{t('assets.attention.fix')}</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('assets.attention.empty.title')}
              hint={t('assets.attention.empty.hint')} />
          )}

          <Pager page={pagedAttention.page} pages={pagedAttention.pages}
            onChange={pagedAttention.setPage} total={pagedAttention.total}
            perPage={PER_PAGE} unit={t('unit.assets')} className="row-end" />
        </>
      )}

      {tab === 'groups' && (
        <>
          <div className="toolbar">
            <span className="muted">{t('assets.groups.note')}</span>
            <span className="spacer" />
            <button onClick={() => setGroupDialog(true)}>{t('assets.newGroup')}</button>
            <Pager page={pagedGroups.page} pages={pagedGroups.pages}
              onChange={pagedGroups.setPage} total={pagedGroups.total}
              perPage={PER_PAGE} unit={t('assets.unit.groups')} className="row-end" />
          </div>
          {groups.length ? (
            <Table head={[t('assets.groups.col.group'), t('assets.groups.col.description'),
              t('assets.groups.col.members'), t('assets.groups.col.stakeholders'), '']}>
              {pagedGroups.rows.map((row) => (
                <tr key={row.id} className={group?.id === row.id ? 'selected' : ''}>
                  <td className="title">
                    {row.name}
                    <div className="muted" style={{ fontSize: 11.5 }}>
                      {(row.tags || []).join(' · ') || t('assets.groups.noTags')}
                    </div>
                  </td>
                  <td className="muted">{row.description || '—'}</td>
                  <td>{row.member_count}</td>
                  <td className="muted">
                    {(row.stakeholders || []).length
                      ? row.stakeholders.map((s) => `${s.actor} (${s.role})`).join(', ')
                      : t('common.none')}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <div className="row">
                      <button className="mini" onClick={() => openGroup(row.id)}>
                        {group?.id === row.id ? t('assets.groups.reload') : t('common.open')}
                      </button>
                      <button className="mini" onClick={() => deleteGroup(row)}>{t('assets.groups.delete')}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('assets.groups.empty.title')}
              hint={t('assets.groups.empty.hint')} />
          )}

          <Pager page={pagedGroups.page} pages={pagedGroups.pages}
            onChange={pagedGroups.setPage} total={pagedGroups.total}
            perPage={PER_PAGE} unit={t('assets.unit.groups')} className="row-end" />

          {group && (
            <div className="detail" style={{ marginTop: 12 }}>
              <dl>
                <dt>{group.name}</dt>
                <dd className="muted">{group.description || t('assets.groups.noDescription')}</dd>
                <dt>{t('assets.groups.members')}</dt>
                <dd>
                  {group.members.length
                    ? group.members.map((member) => (
                      <div key={member.asset_id} className="occ-row">
                        <span className="mono">{member.value || member.asset_id}</span>
                        {' '}
                        <button className="mini" onClick={() => removeMember(member.asset_id)}>
                          {t('assets.groups.removeMember')}
                        </button>
                      </div>
                    ))
                    : <span className="muted">{t('assets.groups.noMembers')}</span>}
                  <div className="row" style={{ marginTop: 8 }}>
                    <select defaultValue="" onChange={(e) => {
                      const value = e.target.value
                      e.target.value = ''
                      addMember(value)
                    }}>
                      <option value="">{t('assets.groups.addAsset')}</option>
                      {addable.map((asset) => (
                        <option key={asset.id} value={asset.id}>{asset.value}</option>
                      ))}
                    </select>
                  </div>
                </dd>
                <dt>{t('assets.groups.stakeholders')}</dt>
                <dd>
                  {group.stakeholders.length
                    ? group.stakeholders.map((s) => (
                      <div key={s.actor} className="occ-row">
                        {s.actor} ({s.role})
                        {' '}
                        <button className="mini" onClick={() => removeStakeholder(s.actor)}>
                          {t('assets.groups.remove')}
                        </button>
                      </div>
                    ))
                    : <span className="muted">{t('assets.groups.noStakeholders')}</span>}
                  <div className="row" style={{ marginTop: 8 }}>
                    <input placeholder={t('assets.field.emailOrPrincipal')} value={stakeholder.actor}
                      onChange={(e) => setStakeholder((s) => ({ ...s, actor: e.target.value }))} />
                    <select value={stakeholder.role}
                      onChange={(e) => setStakeholder((s) => ({ ...s, role: e.target.value }))}>
                      <option value="owner">{t('assets.role.owner')}</option>
                      <option value="collaborator">{t('assets.role.collaborator')}</option>
                    </select>
                    <button className="mini" onClick={addStakeholder}>{t('assets.groups.add')}</button>
                  </div>
                </dd>
                {(group.removed_members || []).length > 0 && (
                  <>
                    <dt>{t('assets.groups.previouslyMember')}</dt>
                    <dd className="muted">
                      {t('assets.groups.removedNote',
                        { names: group.removed_members.map((m) => m.value).join(', ') })}
                    </dd>
                  </>
                )}
              </dl>
            </div>
          )}
        </>
      )}

      {tab === 'activity' && (
        <>
          <div className="toolbar">
            <input placeholder={t('assets.activity.filter')} value={activityAsset}
              onChange={(e) => setActivityAsset(e.target.value.trim())} />
            <span className="muted">{t('assets.activity.note')}</span>
            <Pager page={pagedActivity.page} pages={pagedActivity.pages}
              onChange={pagedActivity.setPage} total={pagedActivity.total}
              perPage={PER_PAGE} unit={t('assets.unit.entries')} className="row-end" />
          </div>
          {activity.length ? (
            <Table head={[t('assets.activity.col.when'), t('assets.activity.col.actor'),
              t('assets.activity.col.action'), t('assets.activity.col.resource'),
              t('assets.activity.col.detail')]}>
              {pagedActivity.rows.map((row) => (
                <tr key={row.id}>
                  <td className="muted">{new Date(row.at).toLocaleString()}</td>
                  <td>{row.actor}</td>
                  <td><span className="pill">{row.action}</span></td>
                  <td className="muted">{row.resource_type}</td>
                  <td className="muted">{row.detail || '—'}</td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title={t('assets.activity.empty.title')}
              hint={t('assets.activity.empty.hint')} />
          )}

          <Pager page={pagedActivity.page} pages={pagedActivity.pages}
            onChange={pagedActivity.setPage} total={pagedActivity.total}
            perPage={PER_PAGE} unit={t('assets.unit.entries')} className="row-end" />
        </>
      )}

      <Dialog open={Boolean(edit.id)} title={t('assets.edit.title', { value: edit.value })}
        onClose={() => setEdit({ id: '', value: '' })} onConfirm={saveEdit}
        confirmLabel={t('assets.edit.save')}>
        <div className="stack">
          <Input label={t('common.owner')} value={edit.owner}
            placeholder={t('assets.field.emailOrPrincipal')}
            onChange={(value) => setEdit((s) => ({ ...s, owner: value }))} />
          <Select label={t('assets.field.project')} value={edit.project}
            options={projects.map((project) => ({ value: project.slug,
              label: `${project.name} (${project.slug})` }))}
            placeholder={t('assets.field.noProject')}
            onChange={(value) => setEdit((s) => ({ ...s, project: value }))} />
          <Select label={t('assets.field.classification')} value={edit.classification_status}
            options={CLASSIFICATIONS.map((c) => ({ value: c.value, label: t(c.labelKey) }))}
            onChange={(value) => setEdit((s) => ({ ...s, classification_status: value }))} />
          <Input label={t('assets.field.notes')} textarea rows={3} value={edit.notes}
            onChange={(value) => setEdit((s) => ({ ...s, notes: value }))} />
          <span className="muted">{t('assets.edit.note')}</span>
        </div>
      </Dialog>

      <Dialog open={groupDialog} title={t('assets.groupDialog.title')}
        onClose={() => setGroupDialog(false)} onConfirm={createGroup}
        confirmLabel={t('assets.groupDialog.confirm')}>
        <div className="stack">
          <Input label={t('assets.field.name')} value={groupForm.name}
            onChange={(value) => setGroupForm((s) => ({ ...s, name: value }))} />
          <Input label={t('assets.field.description')} value={groupForm.description}
            onChange={(value) => setGroupForm((s) => ({ ...s, description: value }))} />
          <Input label={t('assets.field.tags')} value={groupForm.tags}
            placeholder="prod, customer, eu"
            hint={t('assets.field.tagsHint')}
            onChange={(value) => setGroupForm((s) => ({ ...s, tags: value }))} />
        </div>
      </Dialog>
    </div>
  )
}

/* ─────────────────────────── the detail panel ───────────────────────────

   The five questions about one host, in the order they matter: where it is, what
   it serves, what runs there, what we know about it, and what we are allowed to
   do with it. Every fact carries when it was observed — an expiry without its
   reading time is a rumour. */

function Fact({ label, value, when }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <div className="occ-row">
      <span className="muted">{label}</span>{' '}
      <span style={{ overflowWrap: 'anywhere' }}>{value}</span>
      {when && <span className="muted" style={{ fontSize: 11 }}> · {when}</span>}
    </div>
  )
}

function AssetDetail({ detail, principal, onPrincipal, busy,
                       requestBusy, onCollect, onEdit, onArchive, onRequest }) {
  const { t, tCount, tOr } = useI18n()
  const levelLabel = (level) => tOr(LEVEL_LABEL[level] || `assets.level.${level}`, level)
  if (!detail || detail.loading) {
    return <div className="detail"><span className="muted">{t('assets.detail.loading')}</span></div>
  }
  const asset = detail.data || {}
  const latest = asset.latest || {}
  const snapshot = asset.latest_snapshot || {}
  const tls = snapshot.tls || {}
  const dns = snapshot.dns || {}
  const certificate = latest.certificate || {}
  const authorization = asset.authorization || {}
  const observed = asset.latest ? new Date(asset.latest.observed_at).toLocaleString() : null
  const grants = asset.grants || []
  const pending = grants.find((grant) => grant.status === 'requested')
  const certificateError = certificate.error || tls.error
  const changes = detail.changes?.latest_changes || []
  const addresses = [...(dns.ipv4 || latest.ipv4 || []), ...(dns.ipv6 || latest.ipv6 || [])]

  return (
    <div className="detail">
      <div className="row" style={{ flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
        <button className="mini" disabled={busy} onClick={onCollect}>
          {busy ? t('assets.detail.collecting') : t('assets.detail.collect')}
        </button>
        <button className="mini" onClick={onEdit}>{t('assets.detail.editOwnership')}</button>
        <button className="mini" onClick={onArchive}>
          {asset.archived_at ? t('assets.detail.restore') : t('assets.detail.archive')}
        </button>
        <span className="spacer" />
        <label className="field-label" htmlFor={`principal-${asset.id}`}>{t('assets.detail.collectAs')}</label>
        <input id={`principal-${asset.id}`} value={principal} style={{ minWidth: 140 }}
          onChange={(event) => onPrincipal(event.target.value)}
          title={t('assets.detail.collectAsTitle')} />
      </div>

      <div className="onb-grid" style={{ alignItems: 'start' }}>
        <div>
          <strong style={{ fontSize: 12.5 }}>{t('assets.detail.where')}</strong>
          <Fact label={t('assets.fact.address')} value={addresses.join(', ') || null}
            when={observed} />
          <Fact label={t('common.source')} value={asset.source} />
          <Fact label={t('assets.fact.project')}
            value={asset.project || t('assets.standalone')} />
          <Fact label={t('common.owner')}
            value={asset.owner || t('assets.detail.noOwner')} />
          {(asset.context || []).map((entry) => (
            <Fact key={entry.link_id} label={entry.kind}
              value={[entry.name, entry.environment, entry.version_label, entry.project]
                .filter(Boolean).join(' · ')} />
          ))}
        </div>
        <div>
          <strong style={{ fontSize: 12.5 }}>{t('assets.detail.certificate')}</strong>
          {certificateError && (
            <div className="occ-row" style={{ color: 'var(--critical)' }}>{certificateError}</div>
          )}
          <Fact label={t('assets.fact.issuer')} value={certificate.issuer} when={observed} />
          <Fact label={t('assets.fact.subject')} value={certificate.subject} />
          <Fact label={t('assets.fact.expires')} value={certificate.not_after
            ? `${new Date(certificate.not_after).toLocaleString()} (${certificate.days_left}d)`
            : null} />
          <Fact label={t('assets.fact.tls')} value={certificate.tls_version} />
          <Fact label={t('assets.fact.trust')}
            value={certificateError ? t('assets.detail.notTrusted')
              : certificate.issuer ? t('assets.detail.publicCert') : null} />
        </div>
        <div>
          <strong style={{ fontSize: 12.5 }}>{t('assets.detail.technologies')}</strong>
          {(latest.tech || []).length
            ? (latest.tech || []).map((tech) => (
              <Fact key={tech} label={t('assets.fact.detected')} value={tech} when={observed} />
            ))
            : (
              <div className="muted">{t('assets.detail.techNotCollected')}</div>
            )}
          <Fact label={t('assets.fact.observations')}
            value={tCount('assets.detail.snapshots', asset.observations || 0)}
            when={asset.latest_source} />
        </div>
        <div>
          <strong style={{ fontSize: 12.5 }}>{t('assets.detail.metadata')}</strong>
          <Fact label={t('assets.fact.classification')}
            value={tOr(`assets.class.${asset.classification_status}`, asset.classification_status)} />
          <Fact label={t('assets.fact.groups')}
            value={(asset.groups || []).map((g) => g.name).join(', ') || null} />
          <Fact label={t('assets.fact.firstSeen')}
            value={new Date(asset.discovered_at).toLocaleString()} />
          <Fact label={t('assets.fact.lastObserved')} value={observed || t('common.never')} />
          <Fact label={t('assets.fact.notes')} value={asset.notes} />
        </div>
      </div>

      <div className="stack" style={{ marginTop: 10 }}>
        <strong style={{ fontSize: 12.5 }}>{t('assets.detail.authorization')}</strong>
        <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
          {authorization.level
            ? <span className="pill good">
              {t('assets.detail.approved', { level: levelLabel(authorization.level) })}
            </span>
            : pending
              ? <span className="pill">
                {t('assets.detail.pendingSince',
                  { date: new Date(pending.valid_from).toLocaleDateString() })}
              </span>
              : <span className="pill denied">{t('assets.auth.none')}</span>}
          <span className="muted">{t('assets.detail.authNote')}</span>
        </div>
        {grants.length > 0 && (
          <div className="stack" style={{ gap: 4 }}>
            {grants.slice(0, 4).map((grant) => (
              <div key={grant.id} className="occ-row">
                <span className={`pill ${grant.status === 'active' ? 'good'
                  : grant.status === 'requested' ? '' : 'denied'}`}>{grant.status}</span>{' '}
                <span>{grant.level}</span>{' '}
                <span className="muted">
                  {(grant.targets || []).map((target) => target.value).join(', ')}
                  {grant.approved_by ? ` ${t('assets.detail.by', { name: grant.approved_by })}` : ''}
                  {` ${t('assets.detail.until', { date: new Date(grant.valid_until).toLocaleDateString() })}`}
                </span>
              </div>
            ))}
          </div>
        )}
        <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
          <button className="primary-action" disabled={requestBusy} onClick={onRequest}>
            {requestBusy ? t('assets.detail.sending') : t('assets.detail.request')}
          </button>
          <span className="muted">{t('assets.detail.requestNote')}</span>
        </div>
      </div>

      {changes.length > 0 && (
        <div className="stack" style={{ marginTop: 10 }}>
          <strong style={{ fontSize: 12.5 }}>{t('assets.detail.changes')}</strong>
          {changes.map((change, index) => (
            <div key={index} className="occ-row">
              <strong>{change.field}</strong>: {String(change.before ?? '—')}
              {' → '}{String(change.after ?? '—')}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
