#!/usr/bin/env node
/* Guard and coverage report for the translations.

   Three jobs, in order of how loudly they fail:

   1. PARITY — every language must hold exactly the keys English holds. A key
      that exists in `en` and not in `es` renders English inside a Spanish
      screen, which is exactly the bug nobody reports. Exit 1.
   2. USED KEYS — a `t('key')` in code that no catalogue defines prints the key
      itself on screen. Exit 1.
   3. COVERAGE — files that still hold hardcoded prose. Reported, never fatal:
      it is the migration's to-do list, and it shrinks as screens move.

   Run it with `npm run i18n` after touching a catalogue or a screen. */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = join(here, '..', 'src')
const localesDir = join(src, 'i18n', 'locales')
const sourceLanguage = 'en'

function walk(dir, suffix, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) walk(path, suffix, out)
    else if (name.endsWith(suffix)) out.push(path)
  }
  return out
}

/* ── catalogues ─────────────────────────────────────────────────────────── */
const catalogs = {}
const keyOwner = {}
for (const path of walk(localesDir, '.json')) {
  const [, lang, file] = path.match(/locales\/([\w-]+)\/([\w-]+)\.json$/) || []
  if (!lang) continue
  catalogs[lang] = catalogs[lang] || {}
  const entries = JSON.parse(readFileSync(path, 'utf8'))
  for (const [key, value] of Object.entries(entries)) {
    const owner = `${lang}/${file}`
    if (catalogs[lang][key] !== undefined) {
      console.error(`duplicate key "${key}" in ${owner} (already in ${keyOwner[`${lang}:${key}`]})`)
      process.exitCode = 1
    }
    keyOwner[`${lang}:${key}`] = owner
    catalogs[lang][key] = value
  }
}

const languages = Object.keys(catalogs).sort()
const base = catalogs[sourceLanguage] || {}
const baseKeys = new Set(Object.keys(base))

let failed = false
for (const lang of languages) {
  if (lang === sourceLanguage) continue
  const keys = new Set(Object.keys(catalogs[lang]))
  const missing = [...baseKeys].filter((key) => !keys.has(key))
  const extra = [...keys].filter((key) => !baseKeys.has(key))
  if (missing.length) {
    failed = true
    console.error(`\n${lang}: ${missing.length} key(s) missing (falls back to ${sourceLanguage}):`)
    for (const key of missing.slice(0, 40)) console.error(`  - ${key}`)
    if (missing.length > 40) console.error(`  … and ${missing.length - 40} more`)
  }
  if (extra.length) {
    failed = true
    console.error(`\n${lang}: ${extra.length} key(s) that ${sourceLanguage} does not have:`)
    for (const key of extra.slice(0, 20)) console.error(`  - ${key}`)
  }
}

/* ── keys used in code ──────────────────────────────────────────────────── */
const files = walk(src, '.jsx')
const literal = /(?:^|[^\w.])t\(\s*(['"])([^'"]+)\1/g
const used = new Map()          // key → first file that uses it
const dynamic = []              // t(`appearance.${value}`) — not statically checkable
const stripComments = (code) => code
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1')
for (const path of files) {
  const code = stripComments(readFileSync(path, 'utf8'))
  for (const match of code.matchAll(literal)) {
    if (!used.has(match[2])) used.set(match[2], relative(src, path))
  }
  for (const match of code.matchAll(/(?:^|[^\w.])t\(\s*`/g)) dynamic.push(relative(src, path))
}

const unknown = [...used].filter(([key]) => !baseKeys.has(key))
if (unknown.length) {
  failed = true
  console.error(`\n${unknown.length} key(s) used in code but missing from ${sourceLanguage}:`)
  for (const [key, file] of unknown.slice(0, 40)) console.error(`  - ${key}   (${file})`)
}

/* ── helpers taken from the hook but never destructured ────────────────────
   `const { t } = useI18n()` in a component that then calls `tOr(...)` compiles
   fine and blanks the whole app at render time ("tOr is not defined"). The
   identifier has to come from the same destructuring, or be a parameter the
   file defines itself. */
const HELPERS = ['tOr', 'tCount', 'fmt', 'date']
const helperProblems = []
for (const path of files) {
  if (path.endsWith('i18n/index.jsx')) continue
  const code = stripComments(readFileSync(path, 'utf8'))
  const destructured = new Set()
  for (const match of code.matchAll(/const\s*\{([^}]*)\}\s*=\s*useI18n\(\)/g)) {
    for (const part of match[1].split(',')) {
      const name = part.trim().split(':')[0].trim()
      if (name) destructured.add(name)
    }
  }
  for (const helper of HELPERS) {
    if (!new RegExp(`\\b${helper}\\(`).test(code)) continue
    if (destructured.has(helper)) continue
    // a parameter of the file's own function (a helper that receives the translator)
    const asParam = new RegExp(`function\\s+\\w+\\([^)]*\\b${helper}\\b`).test(code)
    if (asParam) continue
    helperProblems.push(`${relative(src, path)}: calls ${helper}() but never takes it from useI18n()`)
  }
}
if (helperProblems.length) {
  failed = true
  console.error(`\n${helperProblems.length} file(s) use a translator helper they never destructured:`)
  for (const line of helperProblems) console.error(`  - ${line}`)
}

/* ── coverage: prose still hardcoded ────────────────────────────────────── */
const PROSE = /^[A-Z][^<>{}`$&|]{3,}[.!?…]?$/
const ATTR = /(?:placeholder|title|aria-label|label|subtitle|hint)="([^"]{4,})"/g
const TEXT = />([^<>{}\n]{4,})</g

const coverage = []
for (const path of files) {
  const name = relative(src, path)
  if (name === 'i18n/index.jsx') continue
  const code = readFileSync(path, 'utf8')
  const hits = new Set()
  for (const match of code.matchAll(ATTR)) {
    if (PROSE.test(match[1].trim())) hits.add(match[1].trim())
  }
  for (const match of code.matchAll(TEXT)) {
    const text = match[1].trim()
    if (PROSE.test(text) && /[A-Za-z]/.test(text)) hits.add(text)
  }
  if (hits.size) coverage.push({ file: name, count: hits.size, samples: [...hits].slice(0, 3) })
}
coverage.sort((a, b) => b.count - a.count)

const totalStrings = coverage.reduce((sum, row) => sum + row.count, 0)
console.log(`\ncatalogues: ${languages.map((lang) => `${lang} (${Object.keys(catalogs[lang]).length})`).join(', ')}`)
console.log(`keys used in code: ${used.size} static, ${new Set(dynamic).size} file(s) with dynamic keys`)
console.log(`translation coverage: ${files.length - coverage.length}/${files.length} screens clean, ${totalStrings} hardcoded strings left`)
if (coverage.length) {
  console.log('\nfiles still holding prose (top 25):')
  for (const row of coverage.slice(0, 25)) {
    console.log(`  ${String(row.count).padStart(4)}  ${row.file}   e.g. “${row.samples[0]}”`)
  }
  if (coverage.length > 25) console.log(`  … and ${coverage.length - 25} more files`)
}

const unused = [...baseKeys].filter((key) => !used.has(key))
if (unused.length) {
  console.log(`\n${unused.length} key(s) defined and not used yet (fine while migrating; prune later):`)
  for (const key of unused.slice(0, 20)) console.log(`  - ${key}`)
}

if (failed) {
  console.error('\ni18n check FAILED')
  process.exit(1)
}
console.log('\ni18n check passed')
