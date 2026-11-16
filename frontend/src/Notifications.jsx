import React, { useEffect, useState } from 'react'
import { api } from './api'
import { PageHeader, Card, StatusBadge, EmptyState, ErrorBanner, Loading,
         Dialog, Input, CheckBox, Toggle, Banner, Table, Pager, usePage } from './ui'
import { useI18n } from './i18n'

/* What a channel can be subscribed to. Raw event ids stay in the title attribute
   so an operator can match them against a webhook receiver. */
const EVENT_LABEL_KEY = {
  'sla.breached': 'notifications.event.slaBreached',
  'advisory.new': 'notifications.event.advisoryNew',
}


export default function Notifications() {
  const { t, tCount } = useI18n()
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
  const [draft, setDraft] = useState({ name: '', kind: 'slack', url: '',
    events: ['sla.breached', 'advisory.new'] })

  // The center keeps one row per event forever; channels are a handful of
  // configured destinations, so only the feed pages.
  const paged = usePage(notifications, 25)

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
        // Both by default: a channel that only hears about SLAs is a channel
        // that stays quiet the day a new CVE lands on a shipped build.
        events: draft.events, actor: 'console',
      })
      setChannelNote(data.secret
        ? t('notifications.channels.createdSecret', { secret: data.secret })
        : t('notifications.channels.created'))
      setDraft({ name: '', kind: 'slack', url: '', events: ['sla.breached', 'advisory.new'] })
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
        ? t('notifications.channels.testDelivered', {
          name: row.name, status: r.data.http_status,
        })
        : t('notifications.channels.testFailed', {
          name: row.name, error: r.data.error,
        }))
    } catch (e) {
      setChannelError(String(e.message || e))
    }
  }

  async function toggleEvent(row, event) {
    const current = row.events || []
    const next = current.includes(event)
      ? current.filter((item) => item !== event)
      : [...current, event]
    try {
      await api.patch(`/api/v1/notifications/channels/${row.id}`,
        { events: next, actor: 'console' })
      loadChannels()
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
      setMarkResult(t('notifications.markedRead'))
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
        title={t('notifications.title')}
        subtitle={t('notifications.unread', { n: unread })}
        actions={
          <>
            <button className="mini" onClick={load}>{t('common.refresh')}</button>
            {unread > 0 && (
              <span className="count" style={{ fontWeight: 600 }}>
                {tCount('notifications.new', unread)}
              </span>
            )}
          </>
        }
      />
      {error && <Banner kind="error">{error}</Banner>}
      {loading && !notifications.length && <Loading rows={6} />}

      <div className="grid grid-2">
        {/* Notification center */}
        <Card title={t('notifications.center.title')} actions={
          <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
            total={paged.total} perPage={paged.perPage} unit="notifications" />
        }>
          {notifications.length === 0 && !loading && (
            <EmptyState title={t('notifications.center.empty.title')}
              hint={t('notifications.center.empty.hint')} />
          )}
          {paged.rows.map((n) => (
            <div key={n.id} className={`notification ${n.read ? 'read' : 'unread'}`}>
              <span className={`pill pill-${n.event.split('.')[0]}`}>{n.event}</span>
              <div className="notification-body">
                <div className="notification-main">
                  <span className="notification-event">{n.event}</span>
                  <span className="notification-time">{new Date(n.created_at).toLocaleString()}</span>
                </div>
                <div className="notification-meta">
                  {n.count > 1 && <span className="count">{tCount('notifications.center.events', n.count)}</span>}
                  {!n.read && <span className="pill warn">{t('notifications.center.unread')}</span>}
                  <button
                    className="mini"
                    onClick={() => markRead(n.id)}
                  >
                    {n.read ? t('notifications.action.show') : t('notifications.action.markRead')}
                  </button>
                </div>
              </div>
            </div>
          ))}
          {notifications.length > 0 && notifications.every((n) => n.read) && (
            <p className="muted">{t('notifications.center.allRead')}</p>
          )}
          {/* The card is a grid cell beside preferences, so the second pager
              stays inside it instead of becoming a third cell under the grid. */}
          {paged.pages > 1 && (
            <div className="row" style={{ justifyContent: 'flex-end', marginTop: 8 }}>
              <Pager page={paged.page} pages={paged.pages} onChange={paged.setPage}
                total={paged.total} perPage={paged.perPage} unit="notifications" />
            </div>
          )}
        </Card>

        {/* Notification preferences */}
        <Card title={t('notifications.prefs.title')}>
          <div className="field-check">
            <CheckBox
              label={t('notifications.prefs.email')}
              checked={preferences.email_enabled}
              onChange={(v) => setPreferences({ ...preferences, email_enabled: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label={t('notifications.prefs.push')}
              checked={preferences.push_enabled}
              onChange={(v) => setPreferences({ ...preferences, push_enabled: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label={t('notifications.prefs.sla')}
              checked={preferences.sla_breach}
              onChange={(v) => setPreferences({ ...preferences, sla_breach: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label={t('notifications.prefs.assignment')}
              checked={preferences.assignment}
              onChange={(v) => setPreferences({ ...preferences, assignment: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label={t('notifications.prefs.retest')}
              checked={preferences.retest_request}
              onChange={(v) => setPreferences({ ...preferences, retest_request: v })}
            />
          </div>
          <div className="field-check">
            <CheckBox
              label={t('notifications.prefs.jira')}
              checked={preferences.jira_sync_error}
              onChange={(v) => setPreferences({ ...preferences, jira_sync_error: v })}
            />
          </div>
          <button className="mini" onClick={savePrefs}>{t('notifications.prefs.save')}</button>
        </Card>
      </div>

      <Card title={t('notifications.channels.title')} actions={
        <span className="muted">
          {t('notifications.channels.configured', { n: channels.length })}
        </span>
      }>
        <p className="muted" style={{ marginTop: 0 }}>{t('notifications.channels.help')}</p>
        {channelError && <Banner kind="error">{channelError}</Banner>}
        {channelNote && <p className="ok">{channelNote}</p>}
        <div className="row">
          <Input label={t('notifications.channels.name')} value={draft.name}
            onChange={(v) => setDraft((d) => ({ ...d, name: v }))} placeholder="sec-alerts" />
          <label className="field">
            <span>{t('notifications.channels.kind')}</span>
            <select value={draft.kind}
              onChange={(e) => setDraft((d) => ({ ...d, kind: e.target.value }))}>
              <option value="slack">slack</option>
              <option value="webhook">webhook</option>
              <option value="email">email</option>
            </select>
          </label>
          <Input label={draft.kind === 'email'
            ? t('notifications.channels.address')
            : t('notifications.channels.url')} value={draft.url}
            onChange={(v) => setDraft((d) => ({ ...d, url: v }))}
            placeholder={draft.kind === 'slack'
              ? 'https://hooks.slack.com/services/…'
              : draft.kind === 'email' ? 'sec@example.com' : 'https://example.com/hook'} />
          <div className="check" style={{ flexWrap: 'wrap' }}>
            {Object.entries(EVENT_LABEL_KEY).map(([key, labelKey]) => (
              <label className="check" key={key} title={key}>
                <input type="checkbox" checked={draft.events.includes(key)}
                  onChange={() => setDraft((d) => ({ ...d, events: d.events.includes(key)
                    ? d.events.filter((item) => item !== key) : [...d.events, key] }))} />
                {t(labelKey)}
              </label>
            ))}
          </div>
          <button className="primary-action" disabled={!draft.name.trim() || !draft.url.trim()}
            onClick={createChannel}>{t('notifications.channels.add')}</button>
        </div>
        {channels.length ? (
          <Table head={[
            t('notifications.channels.col.name'),
            t('notifications.channels.col.kind'),
            t('notifications.channels.col.target'),
            t('notifications.channels.col.events'),
            t('notifications.channels.col.state'),
            '',
          ]}>
            {channels.map((row) => (
              <tr key={row.id}>
                <td>{row.name}</td>
                <td><span className="pill">{row.kind}</span></td>
                <td className="mono muted" style={{ fontSize: 11.5 }}>{row.url}</td>
                <td className="muted">
                  {Object.entries(EVENT_LABEL_KEY).map(([key, labelKey]) => (
                    <button key={key} className={`mini${(row.events || []).includes(key) ? ' primary' : ''}`}
                      onClick={() => toggleEvent(row, key)}
                      title={t('notifications.channels.toggle', {
                        event: key,
                        action: (row.events || []).includes(key)
                          ? t('notifications.channels.stop')
                          : t('notifications.channels.start'),
                      })}>
                      {t(labelKey)}
                    </button>
                  ))}
                </td>
                <td><span className={`status st-${row.enabled ? 'active' : 'disabled'}`}>
                  {row.enabled
                    ? t('notifications.channels.active')
                    : t('notifications.channels.paused')}
                </span></td>
                <td>
                  <button className="mini" onClick={() => testChannel(row)}>
                    {t('notifications.action.test')}
                  </button>
                  <button className="mini" onClick={() => toggleChannel(row)}>
                    {row.enabled
                      ? t('notifications.action.pause')
                      : t('notifications.action.resume')}
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <EmptyState title={t('notifications.channels.empty.title')}
            hint={t('notifications.channels.empty.hint')} />
        )}
      </Card>

      {markResult && <p className={markResult.includes('error') ? 'error' : 'ok'}>{markResult}</p>}
    </div>
  )
}
