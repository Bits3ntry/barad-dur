import React from 'react'

/* A deliberately small highlighter.

   The viewer exists to show the line a scanner pointed at, so the colour has to
   serve reading, not decoration: comments, strings, numbers and keywords, one
   token stream per line, no HTML assembly (React escapes every fragment, so a
   report can never inject markup). If a language is unknown, the line renders
   as plain text — never as a guessed grammar. */

const KEYWORDS = new Set([
  'def', 'class', 'return', 'if', 'else', 'elif', 'for', 'while', 'try', 'except',
  'finally', 'with', 'as', 'import', 'from', 'lambda', 'yield', 'raise', 'pass',
  'break', 'continue', 'and', 'or', 'not', 'in', 'is', 'None', 'True', 'False',
  'global', 'nonlocal', 'assert', 'del', 'const', 'let', 'var', 'function',
  'await', 'async', 'export', 'default', 'new', 'typeof', 'instanceof', 'this',
  'throw', 'catch', 'switch', 'case', 'do', 'of', 'func', 'defer', 'go', 'range',
  'package', 'type', 'struct', 'interface', 'nil', 'true', 'false', 'null',
  'public', 'private', 'static', 'void', 'final', 'extends', 'implements',
])

const LANGUAGES = {
  py: 'python', python: 'python',
  js: 'js', jsx: 'js', ts: 'js', tsx: 'js', mjs: 'js', cjs: 'js',
  go: 'go', java: 'java', rb: 'ruby', php: 'php',
  json: 'json', yml: 'yaml', yaml: 'yaml',
}

export function languageOf(path = '') {
  const ext = String(path).split('.').pop().toLowerCase()
  return LANGUAGES[ext] || null
}


function push(tokens, text, cls) {
  if (text) tokens.push({ text, cls })
}

/** Split one line into coloured fragments. Unknown languages stay plain. */
export function tokenize(line, language) {
  if (!language || language === 'json' || language === 'yaml') {
    // Values and keys still benefit from string colouring; keywords do not.
    return scan(line, { keywords: false, comment: language === 'yaml' ? '#' : null })
  }
  return scan(line, { keywords: true, comment: language === 'python' || language === 'ruby' ? '#' : '//' })
}

function scan(line, options) {
  const tokens = []
  let i = 0
  const startComment = options.comment
  while (i < line.length) {
    const rest = line.slice(i)
    if (startComment && rest.startsWith(startComment)) {
      push(tokens, rest, 'hl-c')
      break
    }
    const ch = line[i]
    if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1
      while (j < line.length) {
        if (line[j] === '\\') { j += 2; continue }
        if (line[j] === ch) { j += 1; break }
        j += 1
      }
      push(tokens, line.slice(i, j), 'hl-s')
      i = j
      continue
    }
    if (/\d/.test(ch)) {
      let j = i + 1
      while (j < line.length && /[\d._xXa-fA-F]/.test(line[j])) j += 1
      push(tokens, line.slice(i, j), 'hl-n')
      i = j
      continue
    }
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i + 1
      while (j < line.length && /[A-Za-z0-9_$]/.test(line[j])) j += 1
      const word = line.slice(i, j)
      const cls = options.keywords && KEYWORDS.has(word) ? 'hl-k' : null
      push(tokens, word, cls)
      i = j
      continue
    }
    // punctuation and whitespace, one character at a time
    push(tokens, ch, null)
    i += 1
  }
  return tokens
}

export default function Highlight({ code = '', path = '' }) {
  const language = languageOf(path)
  if (!language) return <>{code || ' '}</>
  return (
    <>
      {tokenize(code, language).map((token, index) => (
        token.cls
          ? <span key={index} className={token.cls}>{token.text}</span>
          : <React.Fragment key={index}>{token.text}</React.Fragment>
      ))}
    </>
  )
}
