import React, { useEffect, useState } from 'react'
import { api } from './api'
import { PageHeader, Card, StatusBadge, EmptyState, ErrorBanner, Loading,
         Dialog, Input, CheckBox, Toggle, Banner } from './ui'

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

  useEffect(() => {
    load()
    loadPrefs()
  }, [])

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

      {markResult && <p className={markResult.includes('error') ? 'error' : 'ok'}>{markResult}</p>}
    </div>
  )
}
