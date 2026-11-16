import React, { useEffect, useMemo, useState } from 'react'
import Icon from './icons'
import { PageHeader } from './ui'
import { CHAPTERS, GUIDE_BY_ID, GUIDE_GROUPS, bodyFor, hasTranslation } from './guideContent'
import { useI18n } from './i18n'

/* ──────────────────────────────── guide ────────────────────────────────

   The product's own documentation, inside the product. Two reasons it lives
   here instead of in a wiki: a reader who is stuck is already in the console,
   and the document ships and versions with the screens it describes.

   The content is markdown (`./guide/*.md`) so a chapter is edited as prose,
   not as JSX. This file only renders a deliberately small subset — headings,
   paragraphs, lists, fenced code, tables, notes and two directives:

     [[screen:<nav key>|label]]   a door to a screen
     [[chapter:<id>|label]]       a door to another chapter

   Anything else is left as text on purpose: a docs renderer that silently
   swallows markup is worse than one that prints it. */

const DOOR = /^\[\[(screen|chapter):([^|\]]+)\|([^\]]+)\]\]$/

function inline(text, roots) {
  const tokens = String(text).split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`|\[\[(?:screen|chapter):[^\]]+\]\])/g)
  return tokens.map((token, index) => {
    if (!token) return null
    if (token.startsWith('**') && token.endsWith('**') && token.length > 4) {
      return <strong key={index}>{token.slice(2, -2)}</strong>
    }
    if (token.startsWith('*') && token.endsWith('*') && token.length > 2) {
      return <em key={index}>{token.slice(1, -1)}</em>
    }
    if (token.startsWith('`') && token.endsWith('`') && token.length > 2) {
      return <code key={index}>{token.slice(1, -1)}</code>
    }
    const door = token.match(DOOR)
    if (door) {
      const [, kind, target, label] = door
      const onClick = kind === 'screen' ? () => roots.onNavigate(target) : () => roots.onChapter(target)
      return (
        <button key={index} type="button" className="guide-door" onClick={onClick}>
          {label}<span aria-hidden="true">→</span>
        </button>
      )
    }
    return token
  })
}

function cells(line) {
  return line.replace(/^\|/, '').replace(/\|$/, '').split('|').map((cell) => cell.trim())
}

/* A line scanner, not a markdown library: the subset is fixed and the cost of
   a dependency here is a bundle nobody audits. */
function parseBlocks(markdown) {
  const lines = String(markdown).split('\n')
  const blocks = []
  let index = 0

  while (index < lines.length) {
    const line = lines[index]

    if (/^```/.test(line)) {
      const body = []
      index += 1
      while (index < lines.length && !/^```/.test(lines[index])) {
        body.push(lines[index])
        index += 1
      }
      index += 1
      blocks.push({ kind: 'code', body: body.join('\n') })
      continue
    }

    if (/^\|/.test(line) && /^\|[-:\s|]+\|?$/.test(lines[index + 1] || '')) {
      const head = cells(line)
      const rows = []
      index += 2
      while (index < lines.length && /^\|/.test(lines[index])) {
        rows.push(cells(lines[index]))
        index += 1
      }
      blocks.push({ kind: 'table', head, rows })
      continue
    }

    if (/^###\s+/.test(line)) {
      blocks.push({ kind: 'h3', text: line.replace(/^###\s+/, '') })
      index += 1
      continue
    }

    if (/^####\s+/.test(line)) {
      blocks.push({ kind: 'h4', text: line.replace(/^####\s+/, '') })
      index += 1
      continue
    }

    if (/^>\s?/.test(line)) {
      const quote = []
      while (index < lines.length && /^>\s?/.test(lines[index])) {
        quote.push(lines[index].replace(/^>\s?/, ''))
        index += 1
      }
      blocks.push({ kind: 'note', text: quote.join(' ') })
      continue
    }

    if (/^-\s+/.test(line)) {
      const items = []
      while (index < lines.length && /^-\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^-\s+/, ''))
        index += 1
      }
      blocks.push({ kind: 'ul', items })
      continue
    }

    if (/^\d+\.\s+/.test(line)) {
      const items = []
      while (index < lines.length && /^\d+\.\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\d+\.\s+/, ''))
        index += 1
      }
      blocks.push({ kind: 'ol', items })
      continue
    }

    if (!line.trim()) {
      index += 1
      continue
    }

    const paragraph = []
    while (index < lines.length && lines[index].trim()
           && !/^([-*]\s|\d+\.\s|#{2,4}\s|>|\||```)/.test(lines[index])) {
      paragraph.push(lines[index])
      index += 1
    }
    blocks.push({ kind: 'p', text: paragraph.join(' ') })
  }

  return blocks
}

function Body({ markdown, roots }) {
  const blocks = useMemo(() => parseBlocks(markdown), [markdown])
  return blocks.map((block, index) => {
    const key = `b${index}`
    if (block.kind === 'h3') return <h3 key={key} className="guide-h3">{inline(block.text, roots)}</h3>
    if (block.kind === 'h4') return <h4 key={key} className="guide-h4">{inline(block.text, roots)}</h4>
    if (block.kind === 'note') {
      return <aside key={key} className="guide-note">{inline(block.text, roots)}</aside>
    }
    if (block.kind === 'code') return <pre key={key} className="guide-code">{block.body}</pre>
    if (block.kind === 'ul') {
      return (
        <ul key={key} className="guide-list">
          {block.items.map((item, itemIndex) => (
            <li key={itemIndex}>{inline(item, roots)}</li>
          ))}
        </ul>
      )
    }
    if (block.kind === 'ol') {
      return (
        <ol key={key} className="guide-list guide-list-numbered">
          {block.items.map((item, itemIndex) => (
            <li key={itemIndex}>{inline(item, roots)}</li>
          ))}
        </ol>
      )
    }
    if (block.kind === 'table') {
      return (
        <div key={key} className="guide-table">
          <table>
            <thead>
              <tr>{block.head.map((cell, cellIndex) => <th key={cellIndex}>{inline(cell, roots)}</th>)}</tr>
            </thead>
            <tbody>
              {block.rows.map((row, rowIndex) => (
                <tr key={rowIndex}>
                  {block.head.map((_, cellIndex) => (
                    <td key={cellIndex}>{inline(row[cellIndex] || '', roots)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
    }
    return <p key={key} className="guide-p">{inline(block.text, roots)}</p>
  })
}

export default function Guide({ chapter, onNavigate }) {
  const { t, tCount, lang } = useI18n()
  const [active, setActive] = useState(
    () => (chapter && GUIDE_BY_ID[chapter] ? chapter : CHAPTERS[0].id))
  const [query, setQuery] = useState('')

  useEffect(() => {
    if (chapter && GUIDE_BY_ID[chapter] && chapter !== active) setActive(chapter)
    // `active` is intentionally out of the dependency list: it is the value
    // being compared, and including it would fight the reader's own clicks.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chapter])

  useEffect(() => { window.scrollTo({ top: 0, behavior: 'auto' }) }, [active])

  const open = (id) => {
    if (!GUIDE_BY_ID[id] || id === active) return
    setActive(id)
    // pushState, not `location.hash = …`: the App's route listener re-resolves
    // on popstate, so the back button walks back through chapters.
    window.history.pushState({}, '', `/#guide::${id}`)
  }

  /* A target with `::` is a full fragment (`settings::ai`): the App resolves it
     as an address, while a bare key goes through `go()`. One rule, so a door
     never lands on the dashboard because the key was a settings section. */
  const navigate = (target) => {
    if (!target) return
    if (target.includes('::')) { window.location.hash = target; return }
    if (onNavigate) onNavigate(target)
  }

  const needle = query.trim().toLowerCase()
  const matches = useMemo(() => {
    if (!needle) return CHAPTERS
    return CHAPTERS.filter((entry) => (
      t(entry.label).toLowerCase().includes(needle)
      || t(entry.hint).toLowerCase().includes(needle)
      || bodyFor(entry, lang).toLowerCase().includes(needle)))
  }, [needle, t, lang])

  const roots = { onNavigate: navigate, onChapter: open }
  const current = GUIDE_BY_ID[active] || CHAPTERS[0]
  const position = CHAPTERS.findIndex((entry) => entry.id === current.id)
  const previous = position > 0 ? CHAPTERS[position - 1] : null
  const next = position >= 0 && position < CHAPTERS.length - 1 ? CHAPTERS[position + 1] : null

  return (
    <div className="guide-page">
      <PageHeader
        title={t('guide.title')}
        subtitle={t('guide.subtitle')}
      />

      <div className="settings-layout guide-layout">
        <nav className="settings-nav guide-nav" aria-label={t('guide.chaptersAria')}>
          <label className="guide-search">
            <Icon name="search" size={14} />
            <input value={query} onChange={(event) => setQuery(event.target.value)}
              placeholder={t('guide.search')} aria-label={t('guide.search')} />
            {query && (
              <button className="mini quiet" type="button" onClick={() => setQuery('')}
                aria-label={t('guide.searchClear')}>✕</button>
            )}
          </label>
          <p className="guide-search-hint">
            {needle
              ? tCount('guide.matches', matches.length, { q: query.trim() })
              : tCount('guide.chapters', CHAPTERS.length)}
          </p>

          {GUIDE_GROUPS.map((group) => {
            const rows = matches.filter((entry) => entry.group === group)
            if (!rows.length) return null
            return (
              <div className="settings-nav-group" key={group}>
                <div className="settings-nav-label">{t(group)}</div>
                {rows.map((entry) => (
                  <button key={entry.id} className={active === entry.id ? 'active' : ''}
                    onClick={() => open(entry.id)} aria-current={active === entry.id ? 'page' : undefined}>
                    <Icon name={entry.icon} />
                    <span>
                      <strong>{t(entry.label)}</strong>
                      <small>{t(entry.hint)}</small>
                    </span>
                  </button>
                ))}
              </div>
            )
          })}

          {needle && matches.length === 0 && (
            <p className="guide-search-hint">{t('guide.noMatch')}</p>
          )}
        </nav>

        <div className="settings-body">
          <article className="guide-article" aria-label={`${t(current.label)} — ${t('guide.title')}`}>
            <div className="guide-kicker">{t(current.group)}</div>
            <h2 className="guide-title">{t(current.label)}</h2>
            {lang !== 'en' && !hasTranslation(current, lang) && (
              <p className="guide-note guide-lang-note">{t('guide.englishOnly')}</p>
            )}
            <Body markdown={bodyFor(current, lang)} roots={roots} />

            {current.links?.length > 0 && (
              <nav className="guide-doors" aria-label={`${t('guide.whereToGo')} — ${t(current.label)}`}>
                <div className="guide-kicker">{t('guide.whereToGo')}</div>
                <div className="guide-door-row">
                  {current.links.map(([kind, target, label]) => (
                    <button key={`${kind}-${target}`} type="button" className="guide-door"
                      onClick={() => (kind === 'chapter' ? open(target) : navigate(target))}>
                      {t(label)}<span aria-hidden="true">→</span>
                    </button>
                  ))}
                </div>
              </nav>
            )}

            <footer className="guide-foot">
              {previous ? (
                <button type="button" className="guide-step"
                  onClick={() => open(previous.id)}>
                  <span aria-hidden="true">←</span>
                  <span><small>{t('guide.previous')}</small><strong>{t(previous.label)}</strong></span>
                </button>
              ) : <span />}
              {next ? (
                <button type="button" className="guide-step guide-step-next"
                  onClick={() => open(next.id)}>
                  <span><small>{t('guide.next')}</small><strong>{t(next.label)}</strong></span>
                  <span aria-hidden="true">→</span>
                </button>
              ) : <span />}
            </footer>
          </article>
        </div>
      </div>
    </div>
  )
}
