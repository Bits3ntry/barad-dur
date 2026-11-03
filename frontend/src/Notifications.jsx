import React, { useEffect, useState } from 'react'
import { api } from './api'
import { PageHeader, Card, StatusBadge, EmptyState, ErrorBanner, Loading,
         Dialog, Input, CheckBox, Toggle, Banner, Table } from './ui'

export default function Notifications() {
  const [notifications, setNotifications] = useState([])
  const [preferences, setPreferences] = useState({
    email_enabled: true, push_enabled: true,
    sla_breach: true, assignment: true,
    retest_request: true, jira_sync_error: true,
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [markOpen, setMarkOpen] = useState(false)
  const [markId, setMarkId] = useState('')
  const [markResult, setMarkResult] = useState('')
  const [channels, setChannels] = useState([])
  const [channelError, setChannelError] = useState('')
  const [channelNote, setChannelNote] = useState('')
  const [draft, setDraft] = useState({ name: '', kind: 'slack', url: '' })

  useEffect(() => {
    load()
    loadPrefs()
    loadChannels()
  }, [])

  async function loadChannels() {
    try {
      const r = await api.get('/api/v1/notifications/channels')
      setChannels(r.data || [])
    } catch {
      setChannels([])   // viewers cannot read channels; the card says so
    }
  }

  async function createChannel() {
    setChannelError('')
    setChannelNote('')
    try {
      const { data } = await api.post('/api/v1/notifications/channels', {
        name: draft.name.trim(), kind: draft.kind, url: draft.url.trim(),
        events: ['sla.breached'], actor: 'console',
      })
      setChannelNote(data.secret
        ? `channel created · signing secret (shown once): ${data.secret}`
        : 'channel created')
      setDraft({ name: '', kind: 'slack', url: '' })
      loadChannels()
    } catch (e) {
      setChannelError(String(e.message || e))
    }
  }

  async function testChannel(row) {
    setChannelError('')
    setChannelNote('')
    try {
      const r = await api.post(`/api/v1/notifications/channels/${row.id}/test`,
        { actor: 'console' })
      setChannelNote(r.data.delivered
        ? `test delivered to ${row.name} (HTTP ${r.data.http_status})`
        : `test failed for ${row.name}: ${r.data.error}`)
    } catch (e) {
      setChannelError(String(e.message || e))
    }
  }

  async function toggleChannel(row) {
    try {
      await api.patch(`/api/v1/notifications/channels/${row.id}`,
        { enabled: !row.enabled, actor: 'console' })
      loadChannels()
    } catch (e) {
      setChannelError(String(e.message || e))
    }
  }

  async function load() {
    setError('')
    setLoading(true)
    try {
      const r = await api.get('/api/v1/notifications/notifications')
      setNotifications(r.data || [])
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  async function loadPrefs() {
    try {
      const r = await api.get('/api/v1/notifications/preferences')
      setPreferences(r.data || {})
    } catch (e) {
      // preferences may not exist yet; use defaults
    }
  }

  async function savePrefs() {
    setError('')
    try {
      await api.patch('/api/v1/notifications/preferences', preferences)
      setError('')
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  async function markRead(id) {
    setMarkId(id)
    setMarkResult('')
    try {
      await api.patch(`/api/v1/notifications/notifications/${id}`, { actor: 'console' })
      setMarkResult('marked read')
      load()
    } catch (e) {
      setMarkResult(String(e.message || e))
    } finally {
      setMarkOpen(false)
      setMarkId('')
    }
  }

  const unread = notifications.filter((n) => !n.read).length

  return (
    <div className="stack">
      <PageHeader
        title="Notifications"
        subtitle={`${unread} unread`}
        actions={
          <>
            <button className="mini" onClick={load}>refresh</button>
            {unread > 0 && <span className="count" style={{ fontWeight: 600 }}>{unread} new</span>}
          </>
        }
      />
      {error && <Banner kind="error">{error}</Banner>}
      {loading && !notifications.length && <Loading rows={6} />}

      <div className="grid grid-2">
        {/* Notification center */}
        <Card title="Notification center">
          {notifications.length === 0 && !loading && (
            <EmptyState title="No notifications"
              hint="Notifications appear here when events occur (SLA breaches, assignments, retest requests, etc.)." />
          )}
          {notifications.map((n) => (
            <div key={n.id} className={`notification ${n.read ? 'read' : 'unread'}`}>
              <span className={`pill pill-${n.event.split('.')[0]}`}>{n.event}</span>
              <div className="notification-body">
                <div className="notification-main">
                  <span className="notification-event">{n.event}</span>
                  <span className="notification-time">{new Date(n.created_at).toLocaleString()}</span>
                </div>
                <div className="notification-meta">
                  {n.count > 1 && <span className="count">{n.count} events</span>}
                  {!n.read && <span className="pill warn">unread</span>}
                  <button
                    className="mini"
                    onClick={() => markRead(n.id)}
                  >
                    {n.read ? 'show' : 'mark read'}
                  </button>
                </div>
              </div>
            </div>
          ))}
          {notifications.length > 0 && notifications.every((n) => n.read) && (
            <p className="muted">All notifications read.</p>
          )}
        </Card>

        {/* Notification preferences */}
        <Card title="Notification preferences">
          <div className="field-check">
            <CheckBox
              label="Email notifications"
              checked={preferences.email_enabled}
              onChange={(v) => setPreferences({ ...preferences, email_enabled: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label="Push notifications"
              checked={preferences.push_enabled}
              onChange={(v) => setPreferences({ ...preferences, push_enabled: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label="SLA breach alerts"
              checked={preferences.sla_breach}
              onChange={(v) => setPreferences({ ...preferences, sla_breach: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label="Assignment notifications"
              checked={preferences.assignment}
              onChange={(v) => setPreferences({ ...preferences, assignment: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label="Retest request notifications"
              checked={preferences.retest_request}
              onChange={(v) => setPreferences({ ...preferences, retest_request: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label="Jira sync error alerts"
              checked={preferences.jira_sync_error}
              onChange={(v) => setPreferences({ ...preferences, jira_sync_error: v })}
            />
          </div>
          <button className="mini" onClick={savePrefs}>Save preferences</button>
        </Card>
      </div>

      <Card title="Delivery channels" actions={<span className="muted">{channels.length} configured</span>}>
        <p className="muted" style={{ marginTop: 0 }}>
          A channel receives the SLA digest and test messages. Slack expects an
          incoming-webhook URL; webhooks receive a signed JSON envelope.
        </p>
        {channelError && <Banner kind="error">{channelError}</Banner>}
        {channelNote && <p className="ok">{channelNote}</p>}
        <div className="row">
          <Input label="Name" value={draft.name}
            onChange={(v) => setDraft((d) => ({ ...d, name: v }))} placeholder="sec-alerts" />
          <label className="field">
            <span>Kind</span>
            <select value={draft.kind}
              onChange={(e) => setDraft((d) => ({ ...d, kind: e.target.value }))}>
              <option value="slack">slack</option>
              <option value="webhook">webhook</option>
              <option value="email">email</option>
            </select>
          </label>
          <Input label={draft.kind === 'email' ? 'Address' : 'URL'} value={draft.url}
            onChange={(v) => setDraft((d) => ({ ...d, url: v }))}
            placeholder={draft.kind === 'slack'
              ? 'https://hooks.slack.com/services/…'
              : draft.kind === 'email' ? 'sec@example.com' : 'https://example.com/hook'} />
          <button className="primary-action" disabled={!draft.name.trim() || !draft.url.trim()}
            onClick={createChannel}>add channel</button>
        </div>
        {channels.length ? (
          <Table head={['name', 'kind', 'target', 'events', 'state', '']}>
            {channels.map((row) => (
              <tr key={row.id}>
                <td>{row.name}</td>
                <td><span className="pill">{row.kind}</span></td>
                <td className="mono muted" style={{ fontSize: 11.5 }}>{row.url}</td>
                <td className="muted">{(row.events || []).join(', ') || '—'}</td>
                <td><span className={`status st-${row.enabled ? 'active' : 'disabled'}`}>
                  {row.enabled ? 'active' : 'paused'}
                </span></td>
                <td>
                  <button className="mini" onClick={() => testChannel(row)}>test</button>
                  <button className="mini" onClick={() => toggleChannel(row)}>
                    {row.enabled ? 'pause' : 'resume'}
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <EmptyState title="No channel yet"
            hint="Slack: create an incoming webhook in the Slack app and paste its URL here." />
        )}
      </Card>

      {markResult && <p className={markResult.includes('error') ? 'error' : 'ok'}>{markResult}</p>}
    </div>
  )
}
