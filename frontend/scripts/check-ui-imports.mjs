#!/usr/bin/env node
/* Guard: every component rendered as <Name ...> in a screen must be imported
   or defined in that file.

   This exists because two screens shipped referencing helpers they never
   imported (Dialog in Grants.jsx, and a module-scope hook in ui.jsx). A build
   with Vite cannot catch either: JSX compiles fine and the failure only
   appears in the browser when that screen mounts. Runs on `prebuild` and as
   `npm run check:ui`. */

import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = join(here, '..', 'src')

const UI_EXPORTS = readFileSync(join(src, 'ui.jsx'), 'utf8')
  .matchAll(/export function (\w+)/g)
const CHART_EXPORTS = readFileSync(join(src, 'Charts.jsx'), 'utf8')
  .matchAll(/export function (\w+)/g)

const shared = new Set([...UI_EXPORTS].map((m) => m[1]))
const charts = new Set([...CHART_EXPORTS].map((m) => m[1]))

const files = readdirSync(src).filter((name) => name.endsWith('.jsx'))
const problems = []

for (const name of files) {
  const code = readFileSync(join(src, name), 'utf8')
  const imported = new Set()
  for (const match of code.matchAll(/import\s*\{([^}]+)\}\s*from\s*'\.\/[\w.]+'/g)) {
    for (const part of match[1].split(',')) {
      const clean = part.trim().split(/\s+as\s+/)[0].trim()
      if (clean) imported.add(clean)
    }
  }
  const defined = new Set([...code.matchAll(/function (\w+)/g)].map((m) => m[1]))
  const declared = new Set([...code.matchAll(/const (\w+)\s*=/g)].map((m) => m[1]))

  for (const group of [shared, charts]) {
    for (const symbol of group) {
      const used = new RegExp(`<${symbol}[\\s/>]`).test(code)
      if (!used) continue
      if (imported.has(symbol) || defined.has(symbol) || declared.has(symbol)) continue
      if (name === 'ui.jsx' || name === 'Charts.jsx') continue
      problems.push(`${name}: <${symbol}> is used but never imported`)
    }
  }
}

/* Second guard, learned the hard way: the primitives in ui.jsx call
   `onChange(value)`, while native elements hand over an event. Passing an
   event-shaped handler (`set('field')`, `(e) => …e.target…`) to <Input>,
   <Select> or <CheckBox> reads `undefined.value` and unmounts the whole app. */
const PRIMITIVES = /<(Input|Select|CheckBox|Textarea)\b/
for (const name of files) {
  const lines = readFileSync(join(src, name), 'utf8').split('\n')
  lines.forEach((line, index) => {
    if (!PRIMITIVES.test(line)) return
    const window = lines.slice(index, index + 8).join(' ')
    const onChange = window.match(/onChange=\{([^}]+)\}/)
    if (!onChange) return
    const handler = onChange[1].trim()
    const eventShaped = handler.includes('target') || /^set\(/.test(handler) || /^\(?\s*e(v|vent)?\s*\)?\s*=>/.test(handler)
    if (eventShaped) {
      problems.push(`${name}:${index + 1}: <${line.match(PRIMITIVES)[1]}> onChange expects a value, got "${handler}"`)
    }
  })
}

if (problems.length) {
  console.error('UI import check failed:')
  for (const problem of problems) console.error('  - ' + problem)
  console.error('\nImport it from ./ui or ./Charts, or define it in the file.')
  process.exit(1)
}

console.log(`UI import check passed (${files.length} screens).`)
