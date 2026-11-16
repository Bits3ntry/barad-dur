/* The guide is markdown, not JSX: the documentation lives in ./guide/<lang>/*.md
   so anyone can edit a chapter without touching React, and Vite inlines the text
   at build time — no request, no backend route, and the console always ships the
   document it was built with.

   The order of this list is the reading order. A chapter is one subject, and the
   ids are what `#guide::<id>` addresses, so renaming one is a broken link.

   Translation: `label`, `hint`, `group` and the door labels are catalogue keys.
   The body is resolved per language — a chapter translated into Spanish is a
   file under ./guide/es/ with the same name; when it is missing the English body
   is shown and the screen says so, instead of pretending. Adding a language is
   copying the folder and translating it: no code. */

const BODIES = import.meta.glob('./guide/*/*.md', {
  eager: true, import: 'default', query: '?raw',
})
const SOURCE_LANGUAGE = 'en'

const CHAPTERS_BASE = [
  { id: 'start', group: 'guide.group.start', label: 'guide.chapter.start', icon: 'help',
    hint: 'guide.chapter.start.hint', file: '01-start.md' },
  { id: 'first-hour', group: 'guide.group.start', label: 'guide.chapter.firstHour', icon: 'discovery',
    hint: 'guide.chapter.firstHour.hint', file: '02-first-hour.md' },
  { id: 'concepts', group: 'guide.group.start', label: 'guide.chapter.concepts', icon: 'organization',
    hint: 'guide.chapter.concepts.hint', file: '03-concepts.md' },

  { id: 'inventory', group: 'guide.group.platform', label: 'guide.chapter.inventory', icon: 'components',
    hint: 'guide.chapter.inventory.hint', file: '04-inventory.md' },
  { id: 'surface', group: 'guide.group.platform', label: 'guide.chapter.surface', icon: 'assets',
    hint: 'guide.chapter.surface.hint', file: '05-surface.md' },
  { id: 'findings', group: 'guide.group.platform', label: 'guide.chapter.findings', icon: 'findings',
    hint: 'guide.chapter.findings.hint', file: '06-findings.md' },
  { id: 'delivery', group: 'guide.group.platform', label: 'guide.chapter.delivery', icon: 'pipelines',
    hint: 'guide.chapter.delivery.hint', file: '07-delivery.md' },
  { id: 'orchestration', group: 'guide.group.platform', label: 'guide.chapter.orchestration', icon: 'orchestration',
    hint: 'guide.chapter.orchestration.hint', file: '08-orchestration.md' },

  { id: 'shauron', group: 'guide.group.execution', label: 'guide.chapter.shauron', icon: 'analysis',
    hint: 'guide.chapter.shauron.hint', file: '09-shauron.md' },
  { id: 'ai', group: 'guide.group.execution', label: 'guide.chapter.ai', icon: 'chat',
    hint: 'guide.chapter.ai.hint', file: '10-ai.md' },
  { id: 'automation', group: 'guide.group.execution', label: 'guide.chapter.automation', icon: 'key',
    hint: 'guide.chapter.automation.hint', file: '11-automation.md' },

  { id: 'settings', group: 'guide.group.operating', label: 'guide.chapter.settings', icon: 'setup',
    hint: 'guide.chapter.settings.hint', file: '12-settings.md' },
  { id: 'access', group: 'guide.group.operating', label: 'guide.chapter.access', icon: 'members',
    hint: 'guide.chapter.access.hint', file: '13-access.md' },
  { id: 'troubleshooting', group: 'guide.group.operating', label: 'guide.chapter.troubleshooting', icon: 'cycle',
    hint: 'guide.chapter.troubleshooting.hint', file: '14-troubleshooting.md' },
  { id: 'reference', group: 'guide.group.operating', label: 'guide.chapter.reference', icon: 'audit',
    hint: 'guide.chapter.reference.hint', file: '15-reference.md' },
]

/* Where each chapter sends the reader when it ends. Screen targets are nav keys
   — a target containing `::` is a full fragment (`settings::ai`), which the App
   resolves as an address rather than as a key. Keeping these here means a
   chapter can be rewritten without hunting for the doors inside its prose. */
const DOORS = {
  start: [['screen', 'dashboard', 'nav.dashboard'], ['screen', 'setup', 'nav.setup'],
          ['chapter', 'first-hour', 'guide.chapter.firstHour']],
  'first-hour': [['screen', 'scope', 'nav.scope'], ['screen', 'projects', 'nav.projects'],
                 ['screen', 'assets', 'nav.assets'], ['screen', 'settings::grants', 'guide.door.grants'],
                 ['screen', 'settings::runtime', 'guide.door.runtime']],
  concepts: [['screen', 'projects', 'nav.projects'], ['screen', 'assets', 'nav.assets'],
             ['screen', 'findings', 'nav.findings'], ['screen', 'settings::grants', 'guide.door.grants']],
  inventory: [['screen', 'projects', 'nav.projects'], ['screen', 'components', 'nav.components'],
              ['screen', 'sbom', 'nav.sbom'], ['screen', 'licenses', 'nav.licenses']],
  surface: [['screen', 'assets', 'nav.assets'], ['screen', 'scope', 'nav.scope'],
            ['screen', 'settings::grants', 'guide.door.grants'],
            ['screen', 'orchestration', 'nav.orchestration']],
  findings: [['screen', 'findings', 'nav.findings'], ['screen', 'my-work', 'nav.my-work'],
             ['screen', 'vulnerabilities', 'nav.vulnerabilities'], ['screen', 'exposures', 'nav.exposures'],
             ['screen', 'priority-rules', 'nav.priority-rules'],
             ['screen', 'business-impact', 'nav.business-impact']],
  delivery: [['screen', 'pipeline', 'nav.pipeline'], ['screen', 'gates', 'nav.gates'],
             ['screen', 'pentest', 'nav.pentest'], ['screen', 'regression', 'nav.regression'],
             ['screen', 'jira', 'nav.jira']],
  orchestration: [['screen', 'orchestration', 'nav.orchestration'],
                  ['screen', 'settings::runtime', 'guide.door.runtime'],
                  ['chapter', 'troubleshooting', 'guide.chapter.troubleshooting']],
  shauron: [['screen', 'orchestration', 'nav.orchestration'], ['screen', 'assets', 'nav.assets'],
            ['screen', 'missions', 'nav.missions']],
  ai: [['screen', 'chat', 'nav.chat'], ['screen', 'ai-runs', 'nav.ai-runs'],
       ['screen', 'missions', 'nav.missions'], ['screen', 'settings::ai', 'guide.door.ai']],
  automation: [['screen', 'settings::keys', 'guide.door.serviceIdentities'],
               ['screen', 'settings::delivery', 'guide.door.delivery'],
               ['screen', 'notifications', 'nav.notifications'], ['screen', 'jira', 'nav.jira']],
  settings: [['screen', 'settings::grants', 'guide.door.grants'],
             ['screen', 'settings::runtime', 'guide.door.runtime'],
             ['screen', 'members', 'nav.members'], ['screen', 'audit', 'guide.door.audit'],
             ['screen', 'setup', 'nav.setup']],
  access: [['screen', 'members', 'nav.members'], ['screen', 'audit', 'guide.door.audit'],
           ['screen', 'settings::keys', 'guide.door.serviceIdentities'],
           ['screen', 'settings::security', 'guide.door.mySecurity']],
  troubleshooting: [['screen', 'orchestration', 'nav.orchestration'],
                    ['screen', 'settings::runtime', 'guide.door.runtime'],
                    ['chapter', 'reference', 'guide.chapter.reference']],
  reference: [['chapter', 'concepts', 'guide.chapter.concepts'],
              ['chapter', 'start', 'guide.chapter.start']],
}

export const CHAPTERS = CHAPTERS_BASE.map((chapter) => ({
  ...chapter, links: DOORS[chapter.id] || [],
}))

export const GUIDE_GROUPS = [...new Set(CHAPTERS.map((chapter) => chapter.group))]

export const GUIDE_BY_ID = Object.fromEntries(
  CHAPTERS.map((chapter) => [chapter.id, chapter]))

/* The body in the reader's language, or English as the honest fallback. */
export function bodyFor(chapter, lang) {
  return BODIES[`./guide/${lang}/${chapter.file}`]
    || BODIES[`./guide/${SOURCE_LANGUAGE}/${chapter.file}`]
    || ''
}

export function hasTranslation(chapter, lang) {
  return Boolean(BODIES[`./guide/${lang}/${chapter.file}`])
}
