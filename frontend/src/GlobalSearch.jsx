import React, { useEffect, useMemo, useRef, useState } from 'react'
import Icon from './icons'
import { api } from './api'
import { useI18n } from './i18n'

/* The topbar search reads two sources at once: the screens the console already
   knows (no round trip, answers "where do I go") and the estate behind
   `/api/v1/search` (projects, dependencies, assets, advisories, findings).
   One flat list keeps the keyboard honest: ↑/↓ cross group headers, Enter
   opens the highlighted row, and the hint at the bottom teaches the grammar
   without a settings screen.

   The query language lives on the server; this component only renders what it
   returns and turns each hit into a deep link through `onResult`. */

const KIND_ICON = {
  project: 'applications',
  component: 'components',
  asset: 'assets',
  vulnerability: 'vulnerabilities',
  finding: 'findings',
  screen: 'search',
}

// Literal keys: the i18n checker reads `t('…')` calls, and a concatenated key
// (`t('search.group.' + kind)`) is invisible to it — which is how a group label
// ships as a raw key the first time a new kind appears.
const GROUP_LABEL = {
  screen: 'search.group.screen',
  project: 'search.group.project',
  component: 'search.group.component',
  asset: 'search.group.asset',
  vulnerability: 'search.group.vulnerability',
  finding: 'search.group.finding',
}

const DEBOUNCE_MS = 220
const MIN_CHARS = 2

export default function GlobalSearch({ screens = [], onScreen, onResult, onSeeAll }) {
  const { t, tCount, tOr } = useI18n()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(-1)
  const [estate, setEstate] = useState({ groups: [], loading: false, error: '' })
  const inputRef = useRef(null)
  const ticket = useRef(0)

  // ⌘K / Ctrl+K is the shortcut to the box; Escape closes without navigating.
  useEffect(() => {
    const onKey = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        inputRef.current?.focus()
        inputRef.current?.select()
        setOpen(true)
      }
      if (event.key === 'Escape') {
        setQuery('')
        setOpen(false)
        inputRef.current?.blur()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    const needle = query.trim()
    if (needle.length < MIN_CHARS) {
      setEstate({ groups: [], loading: false, error: '' })
      return undefined
    }
    const mine = ++ticket.current
    setEstate((state) => ({ ...state, loading: true, error: '' }))
    const timer = setTimeout(() => {
      api.get(`/api/v1/search?q=${encodeURIComponent(needle)}`)
        .then((data) => {
          if (mine !== ticket.current) return
          setEstate({ groups: data.groups || [], loading: false, error: '' })
        })
        .catch((error) => {
          if (mine !== ticket.current) return
          setEstate({ groups: [], loading: false,
            error: String(error.message || error) })
        })
    }, DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [query])

  const screenMatches = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return []
    return screens
      .filter((item) => t(item.label).toLowerCase().includes(needle))
      .slice(0, 5)
  }, [query, screens, t])

  function metaOf(item) {
    if (item.kind === 'screen') return t('search.openScreen')
    if (item.kind === 'project') return item.subtitle || item.slug
    if (item.kind === 'component') {
      const scope = item.project_count > 1
        ? tCount('search.projects', item.project_count)
        : (item.project_name || '')
      return [item.version, scope].filter(Boolean).join(' · ')
    }
    if (item.kind === 'asset') {
      return [item.asset_type, item.project_name || item.owner]
        .filter(Boolean).join(' · ')
    }
    if (item.kind === 'vulnerability') {
      const severity = tOr('severity.' + String(item.severity || '').toLowerCase(),
        item.severity)
      return [severity, tCount('search.hits', item.findings), item.subtitle]
        .filter(Boolean).join(' · ')
    }
    if (item.kind === 'finding') {
      const severity = tOr('severity.' + String(item.severity || '').toLowerCase(),
        item.severity)
      const component = [item.component, item.component_version]
        .filter(Boolean).join(' ')
      return [severity, component, item.project_slug].filter(Boolean).join(' · ')
    }
    return ''
  }

  const rows = useMemo(() => {
    const out = []
    if (screenMatches.length) {
      out.push({ type: 'header', key: 'h:screen', label: t(GROUP_LABEL.screen) })
      screenMatches.forEach((item) => out.push({
        type: 'item', kind: 'screen', key: 'screen:' + item.key,
        screenKey: item.key, icon: item.icon, title: t(item.label),
        meta: t('search.openScreen'),
      }))
    }
    estate.groups.forEach((group) => {
      if (!group.items?.length) return
      out.push({ type: 'header', key: 'h:' + group.kind,
        label: t(GROUP_LABEL[group.kind] || GROUP_LABEL.finding), total: group.total,
        shown: group.items.length })
      group.items.forEach((item) => out.push({
        ...item, type: 'item', key: item.kind + ':' + item.id,
        icon: KIND_ICON[item.kind] || 'search', meta: metaOf(item),
      }))
    })
    return out
    // metaOf depends on t/tCount/tOr, all derived from the language.
  }, [screenMatches, estate.groups, t, tCount, tOr])

  const selectable = useMemo(
    () => rows.map((row, index) => (row.type === 'item' ? index : -1))
      .filter((index) => index >= 0),
    [rows])
  // Nothing is highlighted until the keyboard picks a row: Enter on a bare query
  // means "open the whole list", not "open whichever row happens to be first".
  const highlighted = selectable.includes(active) ? active : -1

  function choose(index) {
    const row = rows[index]
    if (!row || row.type !== 'item') return
    setQuery('')
    setOpen(false)
    setActive(-1)
    inputRef.current?.blur()
    if (row.kind === 'screen') onScreen?.(row.screenKey)
    else onResult?.(row)
  }

  function onKeyDown(event) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (!selectable.length) return
      event.preventDefault()
      // `active` is what the keyboard owns; before the first arrow nothing is
      // active, so moving down must land on the first row, not skip it.
      const at = selectable.indexOf(active)
      const step = event.key === 'ArrowDown' ? 1 : -1
      const next = at < 0
        ? selectable[step > 0 ? 0 : selectable.length - 1]
        : selectable[(at + step + selectable.length) % selectable.length]
      setActive(next)
      return
    }
    if (event.key === 'Enter') {
      const needle = query.trim()
      if (!needle) return
      event.preventDefault()
      if (highlighted >= 0) {
        choose(highlighted)
        return
      }
      setQuery('')
      setOpen(false)
      setActive(-1)
      inputRef.current?.blur()
      onSeeAll?.(needle)
    }
  }

  const showPanel = open && Boolean(query.trim())
  const empty = showPanel && !estate.loading && !estate.error
    && rows.every((row) => row.type !== 'item')

  return (
    <div className="topbar-search">
      <Icon name="search" size={14} />
      <input
        ref={inputRef}
        value={query}
        onChange={(event) => { setQuery(event.target.value); setOpen(true); setActive(-1) }}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onKeyDown={onKeyDown}
        placeholder={t('shell.search')}
        aria-label={t('shell.search')}
        aria-expanded={showPanel}
        role="combobox"
        aria-controls="estate-search-results"
        aria-autocomplete="list"
      />
      {!query && <kbd className="kbd">⌘K</kbd>}
      {showPanel && (
        <div className="search-results" id="estate-search-results" role="listbox"
          onMouseDown={(event) => event.preventDefault()}>
          {rows.map((row, index) => row.type === 'header' ? (
            <div className="search-group" key={row.key}>
              <span>{row.label}</span>
              {row.total > row.shown && (
                <span className="search-group-count">
                  {t('search.count', { shown: row.shown, total: row.total })}
                </span>
              )}
            </div>
          ) : (
            <button
              key={row.key}
              role="option"
              aria-selected={highlighted === index}
              className={highlighted === index ? 'active' : ''}
              onMouseEnter={() => setActive(index)}
              onClick={() => choose(index)}
            >
              <Icon name={row.icon} size={14} />
              <span className="search-result-copy">
                <span className="search-result-title">{row.title || row.id}</span>
                {row.meta && <span className="search-result-meta">{row.meta}</span>}
              </span>
            </button>
          ))}
          {estate.loading && (
            <div className="search-empty">{t('search.loading')}</div>
          )}
          {estate.error && (
            <div className="search-empty">{t('search.error', { error: estate.error })}</div>
          )}
          {empty && (
            <div className="search-empty">{t('shell.searchEmpty', { query: query.trim() })}</div>
          )}
          {estate.groups.some((group) => group.items?.length) && (
            <button type="button" className="search-see-all"
              onClick={() => {
                const needle = query.trim()
                setQuery('')
                setOpen(false)
                setActive(-1)
                inputRef.current?.blur()
                onSeeAll?.(needle)
              }}>
              <Icon name="search" size={13} />
              {t('search.page.all', { total: estate.groups
                .reduce((sum, group) => sum + (group.total || 0), 0) })}
            </button>
          )}
          <div className="search-hint">{t('search.hint')}</div>
        </div>
      )}
    </div>
  )
}
