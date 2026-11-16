/* ──────────────────────────────── i18n ────────────────────────────────

   One provider, one hook, JSON catalogues. The point of the design is that a
   new language is a directory, not a code change:

     src/i18n/locales/en/nav.json
     src/i18n/locales/es/nav.json
     src/i18n/locales/pt/nav.json      ← adding Portuguese is these three steps
                                          1. copy `en/` to `pt/`
                                          2. translate the values
                                          3. nothing else — the provider, the
                                             selector and the checker discover
                                             the folder at build time

   Usage:

     const { t, tCount, lang, setLang } = useI18n()
     t('nav.dashboard')                       → "Dashboard" / "Panel"
     t('findings.open', { n: 3 })             → "Open 3 findings"
     tCount('findings.count', 3)              → uses `findings.count.one` / `.other`

   Rules that keep it honest:
   - A missing key returns the key itself (`nav.dashboard`), never an empty
     string: a raw key on screen is a bug report you can read.
   - A missing translation for the active language falls back to English, then
     to the key. That is why English is the source of truth and never optional.
   - `scripts/i18n-check.mjs` (npm run i18n) fails when the two catalogues drift
     apart, when a key used in code does not exist, and it lists the files that
     still hold hardcoded prose — the coverage report for the migration. */

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

const MODULES = import.meta.glob('./locales/*/*.json', { eager: true, import: 'default' })

const STORAGE_KEY = 'barad.lang'
const FALLBACK = 'en'

/* The catalogue code is short (`es`); the document declares the full tag, so a
   screen reader, a spell-checker and a browser's hyphenation know *which* Spanish
   this is. Adding a language adds one line here, and omitting it is harmless. */
const HTML_LANG = { es: 'es-ES' }

/* Language names are written in their own language on purpose: a selector that
   says "Spanish" is useless to the person who only reads Spanish. */
export const LANGUAGE_NAMES = {
  en: 'English',
  es: 'Español',
  pt: 'Português',
  fr: 'Français',
  de: 'Deutsch',
  it: 'Italiano',
}

function buildCatalogs() {
  const catalogs = {}
  const owners = {}
  Object.keys(MODULES).forEach((path) => {
    const match = path.match(/\.\/locales\/([\w-]+)\/([\w-]+)\.json$/)
    if (!match) return
    const [, lang, namespace] = match
    catalogs[lang] = catalogs[lang] || {}
    const entries = MODULES[path] || {}
    Object.keys(entries).forEach((key) => {
      if (import.meta.env?.DEV && owners[`${lang}:${key}`] && owners[`${lang}:${key}`] !== namespace) {
        console.warn(`[i18n] duplicate key "${key}" in ${lang}: ${owners[`${lang}:${key}`]} and ${namespace}`)
      }
      owners[`${lang}:${key}`] = namespace
      catalogs[lang][key] = entries[key]
    })
  })
  return catalogs
}

const CATALOGS = buildCatalogs()

export const AVAILABLE_LANGUAGES = Object.keys(CATALOGS).sort((a, b) => (
  a === FALLBACK ? -1 : b === FALLBACK ? 1 : a.localeCompare(b)))

export function languageName(code) {
  return LANGUAGE_NAMES[code] || code.toUpperCase()
}

function detectLanguage() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && CATALOGS[stored]) return stored
  } catch { /* storage may be unavailable */ }
  const fromBrowser = (navigator.language || FALLBACK).slice(0, 2).toLowerCase()
  return CATALOGS[fromBrowser] ? fromBrowser : FALLBACK
}

function interpolate(value, vars) {
  if (!vars) return value
  return value.replace(/\{(\w+)\}/g, (whole, name) => (
    vars[name] === undefined || vars[name] === null ? whole : String(vars[name])))
}

function lookup(lang, key) {
  const own = CATALOGS[lang] || {}
  if (own[key] !== undefined) return own[key]
  const fallback = CATALOGS[FALLBACK] || {}
  return fallback[key]
}

export function translate(lang, key, vars) {
  const value = lookup(lang, key)
  if (value === undefined) return key
  return interpolate(value, vars)
}

/* Plurals: `key.one` / `key.other`, which is enough for every language this
   product ships today and degrades to `key` for a language that would need more
   forms (a future `ru` adds `.few`/`.many` in its own catalogue and a rule
   here — the catalogue never has to know about code). */
export function translateCount(lang, key, count, vars) {
  const form = count === 1 ? 'one' : 'other'
  const value = lookup(lang, `${key}.${form}`) ?? lookup(lang, key)
  if (value === undefined) return key
  return interpolate(value, { n: count, ...vars })
}

/* `tOr` is for values that are *data* rather than copy: a table's unit
   ("targets"), a status a backend returned. If the catalogue has no name for
   it, the raw value is the honest thing to print — a missing translation must
   never turn a real status into a key. */
export function translateOr(lang, key, fallback, vars) {
  const value = lookup(lang, key)
  if (value === undefined) return interpolate(String(fallback), vars)
  return interpolate(value, vars)
}

const I18nContext = createContext({
  lang: FALLBACK,
  setLang: () => {},
  t: (key) => key,
  tCount: (key, count) => `${count}`,
  fmt: (value) => String(value),
})

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(detectLanguage)

  useEffect(() => {
    document.documentElement.setAttribute('lang', HTML_LANG[lang] || lang)
    try { localStorage.setItem(STORAGE_KEY, lang) } catch { /* private mode */ }
  }, [lang])

  // A language switch must repaint every consumer, so the value is rebuilt when
  // the language changes — memoised on `lang` alone, never on callers.
  const value = useMemo(() => {
    const locale = lang
    return {
      lang,
      setLang: setLangState,
      t: (key, vars) => translate(locale, key, vars),
      tOr: (key, fallback, vars) => translateOr(locale, key, fallback, vars),
      tCount: (key, count, vars) => translateCount(locale, key, count, vars),
      fmt: (number, options) => new Intl.NumberFormat(locale, options).format(number),
      date: (value, options) => new Date(value).toLocaleString(locale, options),
    }
  }, [lang])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n() {
  return useContext(I18nContext)
}

/* The common case: a component that only needs the translator. */
export function useT() {
  const { t } = useContext(I18nContext)
  return t
}

/* For code outside React (a fetch error handler, a module-level table): the
   language is whatever the document says it is. Prefer the hook in components. */
export function tStatic(key, vars) {
  const lang = document.documentElement.getAttribute('lang') || FALLBACK
  return translate(CATALOGS[lang] ? lang : FALLBACK, key, vars)
}

export function hasKey(lang, key) {
  return CATALOGS[lang] !== undefined && CATALOGS[lang][key] !== undefined
}

export function catalogFor(lang) {
  return CATALOGS[lang] || {}
}

export const DEFAULT_LANGUAGE = FALLBACK

/* Re-export so a screen can list languages without importing the glob twice. */
export function useLanguages() {
  return useMemo(() => AVAILABLE_LANGUAGES.map((code) => ({
    code, name: languageName(code),
  })), [])
}
