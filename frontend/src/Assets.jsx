import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api'
import {
  Dialog, EmptyState, ErrorBanner, Input, PageHeader, Select, Table, Tabs,
} from './ui'

/* Assets answers four different questions, so it has four tabs: what is in the
   inventory, what is missing from it, how it is grouped, and what happened.
   Addresses and certificates still come from the latest observation — the
   reader never decodes a snapshot blob. */

const CLASSIFICATIONS = [
  { value: 'unclassified', label: 'unclassified' },
  { value: 'pending', label: 'pending' },
  { value: 'confirmed', label: 'confirmed ours' },
  { value: 'external', label: 'external / not ours' },
  { value: 'discarded', label: 'discarded' },
]

function certificateTone(days) {
  if (days === null || days === undefined) return ''
  if (days < 0) return 'sev sev-critical'
  if (days <= 14) return 'sev sev-high'
  if (days <= 30) return 'sev sev-medium'
  return 'pill'
}

function CertCell({ latest }) {
  const cert = latest?.certificate
  if (!cert) return <span className="muted">not probed</span>
  return (
    <div className="stack" style={{ gap: 2 }}>
      <span className="muted">{cert.issuer || 'unknown issuer'}</span>
      <span className={certificateTone(cert.days_left)}>
        {cert.days_left === null || cert.days_left === undefined
          ? 'no expiry'
          : `${cert.days_left}d left`}
      </span>
      {cert.not_after && (
        <span className="muted" style={{ fontSize: 11.5 }}>
          {new Date(cert.not_after).toLocaleDateString()} · {cert.tls_version || '—'}
        </span>
      )}
    </div>
  )
}

function AddressCell({ latest }) {
  if (!latest) return <span className="muted">never observed</span>
  const v4 = latest.ipv4 || []
  const v6 = latest.ipv6 || []
  if (!v4.length && !v6.length) return <span className="muted">no addresses</span>
  return (
    <div className="stack" style={{ gap: 2 }}>
      {v4.map((ip) => <span key={ip} className="mono">{ip}</span>)}
      {v6.slice(0, 2).map((ip) => <span key={ip} className="mono muted">{ip}</span>)}
      {v6.length > 2 && <span className="muted">+{v6.length - 2} ipv6</span>}
    </div>
  )
}

const EMPTY_EDIT = {
  id: '', value: '', owner: '', project: '', classification_status: 'unclassified',
  notes: '', source: '',
}

export default function Assets() {
  const [tab, setTab] = useState('inventory')
  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState({ q: '', type: '', classification: '' })
  const [domain, setDomain] = useState('')
  const [manual, setManual] = useState({ type: 'domain', value: '' })
  const [principal, setPrincipal] = useState(
    () => localStorage.getItem('barad.principal') || 'console')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')
  const [history, setHistory] = useState(null)

  const [attention, setAttention] = useState([])
  const [groups, setGroups] = useState([])
  const [group, setGroup] = useState(null)
  const [groupDialog, setGroupDialog] = useState(false)
  const [groupForm, setGroupForm] = useState({ name: '', description: '', tags: '' })
  const [stakeholder, setStakeholder] = useState({ actor: '', role: 'owner' })
  const [activity, setActivity] = useState([])
  const [activityAsset, setActivityAsset] = useState('')
  const [edit, setEdit] = useState({ ...EMPTY_EDIT })
  const [projects, setProjects] = useState([])

  useEffect(() => { load() }, [])
  useEffect(() => {
    api.get('/api/v1/projects').then((r) => setProjects(r.data || [])).catch(() => setProjects([]))
  }, [])

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
    const params = new URLSearchParams()
    if (filters.q.trim()) params.set('q', filters.q.trim())
    if (filters.type) params.set('type', filters.type)
    if (filters.classification) params.set('classification', filters.classification)
    const suffix = params.toString() ? `?${params}` : ''
    api.get(`/api/v1/assets${suffix}`)
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

  async function openHistory(asset) {
    if (history?.assetId === asset.id) { setHistory(null); return }
    try {
      const { data } = await api.get(`/api/v1/assets/${asset.id}/changes`)
      setHistory({ assetId: asset.id, asset: asset.value, ...data })
    } catch (e) {
      setError(String(e.message || e))
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
      const tls = result.data.observation.tls
      setNotice(`collected ${asset.value}: ${(dns.ipv4 || []).length} ipv4, `
        + `${(dns.ipv6 || []).length} ipv6${tls ? ', certificate read' : ', DNS only'}`)
      load()
    } catch (e) {
      const message = String(e.message || e)
      setError(message.includes('403')
        ? `Not authorized for ${principal}: issue a grant for that principal `
          + `(passive_discovery, and active_verification for the TLS probe). ${message}`
        : message)
    }
    setBusy('')
  }

  async function sweep() {
    if (!domain.trim()) return
    setBusy('sweep')
    try {
      const result = await api.post('/api/v1/assets/discover',
        { domain: domain.trim(), actor: principal })
      setNotice(`crt.sh sweep: ${result.data.created} new / ${result.data.refreshed} refreshed`)
      load()
    } catch (e) {
      setError(String(e.message || e))
    }
    setBusy('')
  }

  async function addManual() {
    if (!manual.value.trim()) return
    await api.post('/api/v1/assets',
      { ...manual, value: manual.value.trim(), actor: principal })
    setManual((m) => ({ ...m, value: '' }))
    load()
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
      setNotice(`updated ${edit.value}`)
      setEdit({ ...EMPTY_EDIT })
      load()
      if (tab === 'attention') loadAttention()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function toggleArchive(asset) {
    const action = asset.archived_at ? 'unarchive' : 'archive'
    try {
      await api.post(`/api/v1/assets/${asset.id}/${action}`
        + `?actor=${encodeURIComponent(principal)}`)
      setNotice(`${action}d ${asset.value} (relations and history kept)`)
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
      setNotice(`deleted group ${row.name}; its assets are untouched`)
      loadGroups()
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const memberIds = useMemo(
    () => new Set((group?.members || []).map((m) => m.asset_id)), [group])
  const addable = assets.filter((asset) => !memberIds.has(asset.id))

  return (
    <div className="stack">
      <PageHeader
        title="Assets"
        subtitle={`${total} asset${total === 1 ? '' : 's'} in this organization · ownership here never grants a scan`}
        actions={<button className="primary-action" onClick={() => setGroupDialog(true)}>new group</button>}
      />

      <Tabs
        tabs={[
          { id: 'inventory', label: 'Inventory' },
          { id: 'attention', label: 'Needs attention' },
          { id: 'groups', label: 'Groups' },
          { id: 'activity', label: 'Activity' },
        ]}
        active={tab}
        onChange={setTab}
      />

      {error && <ErrorBanner error={error} />}
      {notice && <div className="banner banner-ok">{notice}</div>}

      {tab === 'inventory' && (
        <>
          <div className="toolbar">
            <input placeholder="search value…" value={filters.q}
              onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && load()} />
            <select value={filters.type}
              onChange={(e) => setFilters((f) => ({ ...f, type: e.target.value }))}>
              <option value="">every type</option>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
              <option value="url">url</option>
              <option value="cidr">cidr</option>
            </select>
            <select value={filters.classification}
              onChange={(e) => setFilters((f) => ({ ...f, classification: e.target.value }))}>
              <option value="">any classification</option>
              {CLASSIFICATIONS.map((c) => (
                <option key={c.value} value={c.value}>{c.label}</option>
              ))}
            </select>
            <button onClick={load}>apply</button>
            <span className="spacer" />
            <label className="field-label" htmlFor="principal">principal</label>
            <input id="principal" value={principal} style={{ minWidth: 150 }}
              onChange={(e) => rememberPrincipal(e.target.value)}
              title="The identity grants are issued to; collection is authorized per principal" />
          </div>

          {assets.length ? (
            <Table head={['type', 'value', 'owner · project', 'groups', 'addresses',
              'certificate', 'last observed', '']}>
              {assets.map((asset) => (
                <React.Fragment key={asset.id}>
                  <tr className={history?.assetId === asset.id ? 'selected' : ''}>
                    <td><span className="pill">{asset.type}</span></td>
                    <td className="title">
                      {asset.value}
                      <div className="muted" style={{ fontSize: 11.5 }}>
                        {asset.source} · {asset.classification_status}
                      </div>
                    </td>
                    <td>
                      <div className="stack" style={{ gap: 2 }}>
                        <span className={asset.owner ? '' : 'muted'}>
                          {asset.owner || 'no owner'}
                        </span>
                        <span className={asset.project ? 'muted' : 'pill'}>
                          {asset.project || 'no project'}
                        </span>
                      </div>
                    </td>
                    <td>
                      {(asset.groups || []).length
                        ? asset.groups.map((g) => (
                          <span key={g.id} className="pill">{g.name}</span>
                        ))
                        : <span className="muted">—</span>}
                    </td>
                    <td><AddressCell latest={asset.latest} /></td>
                    <td><CertCell latest={asset.latest} /></td>
                    <td className="muted">
                      {asset.latest
                        ? new Date(asset.latest.observed_at).toLocaleString()
                        : new Date(asset.last_seen_at).toLocaleDateString()}
                    </td>
                    <td>
                      <div className="row">
                        <button className="mini" onClick={() => openEdit(asset)}>edit</button>
                        <button className="mini" disabled={busy === asset.id}
                          onClick={() => collect(asset, true)}>
                          {busy === asset.id ? 'collecting…' : 'collect'}
                        </button>
                        <button className="mini" onClick={() => openHistory(asset)}>
                          {history?.assetId === asset.id ? 'hide' : 'history'}
                        </button>
                        <button className="mini" onClick={() => toggleArchive(asset)}>
                          {asset.archived_at ? 'restore' : 'archive'}
                        </button>
                      </div>
                    </td>
                  </tr>
                  {history?.assetId === asset.id && (
                    <tr className="detail-row"><td colSpan={8}>
                      <div className="detail">
                        <dl>
                          <dt>observations</dt><dd>{history.snapshots}</dd>
                          <dt>changes</dt>
                          <dd>
                            {(!history.latest_changes || !history.latest_changes.length)
                              && <span className="muted">none between the last two observations</span>}
                            {(history.latest_changes || []).map((change, index) => (
                              <div key={index} className="occ-row">
                                <strong>{change.field}</strong>: {String(change.before ?? '—')}
                                {' → '}{String(change.after ?? '—')}
                              </div>
                            ))}
                          </dd>
                        </dl>
                      </div>
                    </td></tr>
                  )}
                </React.Fragment>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="No assets yet"
              hint="Sweep a seed domain to discover hosts, or add one manually below." />
          )}

          <div className="toolbar">
            <input placeholder="seed domain, e.g. bitsentry.xyz" value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && sweep()} />
            <button onClick={sweep} disabled={busy === 'sweep'}>
              {busy === 'sweep' ? 'sweeping…' : 'sweep crt.sh'}
            </button>
            <span className="spacer" />
            <select value={manual.type}
              onChange={(e) => setManual((m) => ({ ...m, type: e.target.value }))}>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
              <option value="url">url</option>
              <option value="cidr">cidr</option>
            </select>
            <input placeholder="add an asset manually" value={manual.value}
              onChange={(e) => setManual((m) => ({ ...m, value: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && addManual()} />
            <button className="primary-action" onClick={addManual}>add asset</button>
          </div>
        </>
      )}

      {tab === 'attention' && (
        <>
          <p className="muted">
            Computed from the inventory on every load. Each row names what is missing;
            &ldquo;never observed&rdquo; is a coverage gap, not a statement that the host is gone.
          </p>
          {attention.length ? (
            <Table head={['asset', 'why it needs attention', 'fix', '']}>
              {attention.map((row) => (
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
                  <td>
                    <button className="mini" onClick={() => openEdit(row.asset)}>fix</button>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="Nothing needs attention"
              hint="Every asset has an owner, a project, a confirmed classification and a deployment relation." />
          )}
        </>
      )}

      {tab === 'groups' && (
        <>
          <div className="toolbar">
            <span className="muted">
              Inventory groups organize resources. They are not access groups and grant nobody a permission.
            </span>
            <span className="spacer" />
            <button onClick={() => setGroupDialog(true)}>new group</button>
          </div>
          {groups.length ? (
            <Table head={['group', 'description', 'members', 'stakeholders', '']}>
              {groups.map((row) => (
                <tr key={row.id} className={group?.id === row.id ? 'selected' : ''}>
                  <td className="title">
                    {row.name}
                    <div className="muted" style={{ fontSize: 11.5 }}>
                      {(row.tags || []).join(' · ') || 'no tags'}
                    </div>
                  </td>
                  <td className="muted">{row.description || '—'}</td>
                  <td>{row.member_count}</td>
                  <td className="muted">
                    {(row.stakeholders || []).length
                      ? row.stakeholders.map((s) => `${s.actor} (${s.role})`).join(', ')
                      : 'none'}
                  </td>
                  <td>
                    <div className="row">
                      <button className="mini" onClick={() => openGroup(row.id)}>
                        {group?.id === row.id ? 'reload' : 'open'}
                      </button>
                      <button className="mini" onClick={() => deleteGroup(row)}>delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            !error && <EmptyState title="No groups yet"
              hint="Create one for the assets you read together — production domains, a customer estate, an acquisition." />
          )}

          {group && (
            <div className="detail" style={{ marginTop: 12 }}>
              <dl>
                <dt>{group.name}</dt>
                <dd className="muted">{group.description || 'no description'}</dd>
                <dt>members</dt>
                <dd>
                  {group.members.length
                    ? group.members.map((member) => (
                      <div key={member.asset_id} className="occ-row">
                        <span className="mono">{member.value || member.asset_id}</span>
                        {' '}
                        <button className="mini" onClick={() => removeMember(member.asset_id)}>
                          remove from group
                        </button>
                      </div>
                    ))
                    : <span className="muted">no members</span>}
                  <div className="row" style={{ marginTop: 8 }}>
                    <select defaultValue="" onChange={(e) => {
                      const value = e.target.value
                      e.target.value = ''
                      addMember(value)
                    }}>
                      <option value="">add an asset…</option>
                      {addable.map((asset) => (
                        <option key={asset.id} value={asset.id}>{asset.value}</option>
                      ))}
                    </select>
                  </div>
                </dd>
                <dt>stakeholders</dt>
                <dd>
                  {group.stakeholders.length
                    ? group.stakeholders.map((s) => (
                      <div key={s.actor} className="occ-row">
                        {s.actor} ({s.role})
                        {' '}
                        <button className="mini" onClick={() => removeStakeholder(s.actor)}>
                          remove
                        </button>
                      </div>
                    ))
                    : <span className="muted">no stakeholders</span>}
                  <div className="row" style={{ marginTop: 8 }}>
                    <input placeholder="email or principal" value={stakeholder.actor}
                      onChange={(e) => setStakeholder((s) => ({ ...s, actor: e.target.value }))} />
                    <select value={stakeholder.role}
                      onChange={(e) => setStakeholder((s) => ({ ...s, role: e.target.value }))}>
                      <option value="owner">owner</option>
                      <option value="collaborator">collaborator</option>
                    </select>
                    <button className="mini" onClick={addStakeholder}>add</button>
                  </div>
                </dd>
                {(group.removed_members || []).length > 0 && (
                  <>
                    <dt>previously member</dt>
                    <dd className="muted">
                      {group.removed_members.map((m) => m.value).join(', ')}
                      {' '}— removed, still in the inventory
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
            <input placeholder="filter by asset id (optional)" value={activityAsset}
              onChange={(e) => setActivityAsset(e.target.value.trim())} />
            <span className="muted">
              The same ledger the Audit trail reads; every row says who, what and when.
            </span>
          </div>
          {activity.length ? (
            <Table head={['when', 'actor', 'action', 'resource', 'detail']}>
              {activity.map((row) => (
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
            !error && <EmptyState title="No activity recorded yet"
              hint="Adding an asset, editing ownership or moving it between groups writes a row here." />
          )}
        </>
      )}

      <Dialog open={Boolean(edit.id)} title={`Edit ${edit.value}`}
        onClose={() => setEdit({ ...EMPTY_EDIT })} onConfirm={saveEdit} confirmLabel="save">
        <div className="stack">
          <Input label="owner" value={edit.owner} placeholder="email or principal"
            onChange={(value) => setEdit((s) => ({ ...s, owner: value }))} />
          <Select label="project" value={edit.project}
            options={projects.map((p) => ({ value: p.slug, label: `${p.name} (${p.slug})` }))}
            placeholder="no project"
            onChange={(value) => setEdit((s) => ({ ...s, project: value }))} />
          <Select label="classification" value={edit.classification_status}
            options={CLASSIFICATIONS}
            onChange={(value) => setEdit((s) => ({ ...s, classification_status: value }))} />
          <Input label="notes" textarea rows={3} value={edit.notes}
            onChange={(value) => setEdit((s) => ({ ...s, notes: value }))} />
          <span className="muted">
            Classification records ownership. It is not an authorization: active testing still
            needs a scope entry and a grant.
          </span>
        </div>
      </Dialog>

      <Dialog open={groupDialog} title="New inventory group"
        onClose={() => setGroupDialog(false)} onConfirm={createGroup} confirmLabel="create group">
        <div className="stack">
          <Input label="name" value={groupForm.name}
            onChange={(value) => setGroupForm((s) => ({ ...s, name: value }))} />
          <Input label="description" value={groupForm.description}
            onChange={(value) => setGroupForm((s) => ({ ...s, description: value }))} />
          <Input label="tags" value={groupForm.tags} placeholder="prod, customer, eu"
            hint="comma separated"
            onChange={(value) => setGroupForm((s) => ({ ...s, tags: value }))} />
        </div>
      </Dialog>
    </div>
  )
}
