import React, { useEffect, useMemo, useRef, useState } from 'react'
import Icon from './icons'
import { api } from './api'
import { useI18n } from './i18n'
import { PageHeader, Card } from './ui'

/* The search page: the dropdown answers "where do I go", this screen answers
   "show me everything you know about this word". Same endpoint, a much larger
   `limit`, and the one column the dropdown has no room for — when the platform
   first learned about the row.

   The date is per kind and named for the fact it is: an asset was *discovered*, a
   build was *imported*, a package *arrived* with some SBOM. Flattening all of
   them into "created" prints one word for four different events. */

const KIND_ORDER = ['project', 'component', 'version', 'asset', 'vulnerability', 'finding']

const KIND_ICON = {
  project: 'applications',
  component: 'components',
  version: 'pipelines',
  asset: 'assets',
  vulnerability: 'vulnerabilities',
  finding: 'findings',
}

// Literal keys on purpose: the i18n checker reads `t('…')` calls, so a
// concatenated label ships as a raw key the first time a kind appears.
const GROUP_LABEL = {
  project: 'search.group.project',
  component: 'search.group.component',
  version: 'search.group.version',
  asset: 'search.group.asset',
  vulnerability: 'search.group.vulnerability',
  finding: 'search.group.finding',
}

const PAGE_LIMIT = 200

function when(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString()
}

export default function SearchResults({ query = '', onQuery, onOpenResult }) {
  const { t, tCount } = useI18n()
  const [term, setTerm] = useState(query)
  const [state, setState] = useState({ groups: [], total: 0, loading: false, error: '' })
  const ticket = useRef(0)

  useEffect(() => { setTerm(query) }, [query])

  useEffect(() => {
    const needle = query.trim()
    if (!needle) {
      setState({ groups: [], total: 0, loading: false, error: '' })
      return undefined
    }
    const mine = ++ticket.current
    setState((current) => ({ ...current, loading: true, error: '' }))
    api.get(`/api/v1/search?q=${encodeURIComponent(needle)}&limit=${PAGE_LIMIT}`)
      .then((data) => {
        if (mine !== ticket.current) return
        setState({ groups: data.groups || [], total: data.total || 0,
          loading: false, error: '' })
      })
      .catch((error) => {
        if (mine !== ticket.current) return
        setState({ groups: [], total: 0, loading: false,
          error: String(error.message || error) })
      })
    return undefined
  }, [query])

  const groups = useMemo(() => {
    const byKind = new Map(state.groups.map((group) => [group.kind, group]))
    return KIND_ORDER
      .map((kind) => byKind.get(kind))
      .filter((group) => group && (group.items || []).length)
  }, [state.groups])

  const needle = query.trim()

  return (
    <div className="stack">
      <PageHeader title={t('search.page.title')}
        subtitle={needle ? tCount('search.page.found', state.total)
          : t('search.page.prompt')} />

      <div className="toolbar">
        <input value={term} onChange={(event) => setTerm(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') onQuery?.(term.trim())
          }}
          placeholder={t('shell.search')} aria-label={t('shell.search')} />
        <button type="button" className="btn"
          onClick={() => onQuery?.(term.trim())}>{t('search.page.run')}</button>
        <span className="count">{t('search.hint')}</span>
      </div>

      {state.loading && <div className="empty">{t('search.loading')}</div>}
      {state.error && <div className="banner banner-error">
        {t('search.error', { error: state.error })}
      </div>}
      {!state.loading && !state.error && needle && !groups.length && (
        <div className="empty">{t('shell.searchEmpty', { query: needle })}</div>
      )}

      {groups.map((group) => (
        <Card key={group.kind} band
          title={(
            <span className="row">
              <Icon name={KIND_ICON[group.kind] || 'search'} size={14} />
              {t(GROUP_LABEL[group.kind] || 'search.group.finding')}
              <span className="count">
                {group.total > group.items.length
                  ? t('search.count', { shown: group.items.length, total: group.total })
                  : group.total}
              </span>
            </span>
          )}>
          <table>
            <thead>
              <tr>
                <th>{t('search.page.column.what')}</th>
                <th>{t('search.page.column.where')}</th>
                <th>{t('search.page.column.registered')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {group.items.map((item) => (
                <tr key={`${group.kind}:${item.id}`}>
                  <td>
                    <button type="button" className="btn-ghost"
                      onClick={() => onOpenResult?.(item)}>
                      {item.title || item.id}
                    </button>
                  </td>
                  <td className="muted">
                    {item.subtitle || item.project_name || item.project_slug
                      || item.owner || '—'}
                  </td>
                  <td className="muted" title={item.registered_at || ''}>
                    {when(item.registered_at)}
                  </td>
                  <td className="row row-end">
                    <button type="button" className="btn"
                      onClick={() => onOpenResult?.(item)}>
                      {t('search.page.open')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ))}
    </div>
  )
}
