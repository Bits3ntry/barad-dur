import React from 'react'

/* Inline stroke icons (lucide geometry, 24px grid) — the console ships without
   an icon dependency, and a list of paths is smaller than a font. Every icon is
   drawn with the same 1.7 stroke so the sidebar reads as one set. */

const PATHS = {
  dashboard: [
    ['rect', { x: 3, y: 3, width: 7, height: 7, rx: 1 }],
    ['rect', { x: 14, y: 3, width: 7, height: 7, rx: 1 }],
    ['rect', { x: 14, y: 14, width: 7, height: 7, rx: 1 }],
    ['rect', { x: 3, y: 14, width: 7, height: 7, rx: 1 }],
  ],
  'my-work': [
    ['path', { d: 'M22 12h-6l-2 3h-4l-2-3H2' }],
    ['path', { d: 'M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z' }],
  ],
  findings: [
    ['path', { d: 'm8 2 1.88 1.88' }],
    ['path', { d: 'M14.12 3.88 16 2' }],
    ['path', { d: 'M9 7.13v-1a3 3 0 1 1 6 0v1' }],
    ['path', { d: 'M12 20a6 6 0 0 0 6-6v-3a4 4 0 0 0-4-4h-4a4 4 0 0 0-4 4v3a6 6 0 0 0 6 6Z' }],
    ['path', { d: 'M12 20v-9' }],
    ['path', { d: 'M6.53 9C4.6 8.8 3 7.1 3 5' }],
    ['path', { d: 'M6 13H2' }],
    ['path', { d: 'M3 21c0-2.1 1.7-3.9 3.8-4' }],
  ],
  vulnerabilities: [
    ['path', { d: 'M20 13c0 5-3.5 7.4-7.7 8.9a1 1 0 0 1-.6 0C7.5 20.4 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z' }],
    ['path', { d: 'M12 8v4' }],
    ['path', { d: 'M12 16h.01' }],
  ],
  cycle: [
    ['path', { d: 'M3 12a9 9 0 0 1 9-9 9.8 9.8 0 0 1 6.7 2.7L21 8' }],
    ['path', { d: 'M21 3v5h-5' }],
    ['path', { d: 'M21 12a9 9 0 0 1-9 9 9.8 9.8 0 0 1-6.7-2.7L3 16' }],
    ['path', { d: 'M8 16H3v5' }],
  ],
  cycles: [
    ['path', { d: 'M8 2v4' }],
    ['path', { d: 'M16 2v4' }],
    ['rect', { x: 3, y: 4, width: 18, height: 18, rx: 2 }],
    ['path', { d: 'M3 10h18' }],
  ],
  scope: [
    ['circle', { cx: 12, cy: 12, r: 10 }],
    ['circle', { cx: 12, cy: 12, r: 6 }],
    ['circle', { cx: 12, cy: 12, r: 2 }],
  ],
  discovery: [
    ['circle', { cx: 12, cy: 12, r: 10 }],
    ['path', { d: 'm16.2 7.8-2.1 6.3-6.3 2.1 2.1-6.3z' }],
  ],
  assets: [
    ['rect', { x: 2, y: 2, width: 20, height: 8, rx: 2 }],
    ['rect', { x: 2, y: 14, width: 20, height: 8, rx: 2 }],
    ['path', { d: 'M6 6h.01' }],
    ['path', { d: 'M6 18h.01' }],
  ],
  'attack-surface': [
    ['circle', { cx: 12, cy: 12, r: 10 }],
    ['path', { d: 'M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20' }],
    ['path', { d: 'M2 12h20' }],
  ],
  components: [
    ['path', { d: 'M11 21.7a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.7z' }],
    ['path', { d: 'M12 22V12' }],
    ['path', { d: 'm3.3 7 8.7 5 8.7-5' }],
  ],
  exposures: [
    ['path', { d: 'm21.7 18-8-14a2 2 0 0 0-3.4 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3' }],
    ['path', { d: 'M12 9v4' }],
    ['path', { d: 'M12 17h.01' }],
  ],
  applications: [
    ['path', { d: 'M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9L9.6 3.9A2 2 0 0 0 7.9 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z' }],
  ],
  prioritization: [
    ['path', { d: 'M4 21v-7' }],
    ['path', { d: 'M4 10V3' }],
    ['path', { d: 'M12 21v-9' }],
    ['path', { d: 'M12 8V3' }],
    ['path', { d: 'M20 21v-5' }],
    ['path', { d: 'M20 12V3' }],
    ['path', { d: 'M1 14h6' }],
    ['path', { d: 'M9 8h6' }],
    ['path', { d: 'M17 16h6' }],
  ],
  'business-impact': [
    ['path', { d: 'M3 3v18h18' }],
    ['path', { d: 'M8 17v-5' }],
    ['path', { d: 'M13 17V8' }],
    ['path', { d: 'M18 17v-9' }],
  ],
  analysis: [
    ['path', { d: 'm16 18 6-6-6-6' }],
    ['path', { d: 'm8 6-6 6 6 6' }],
  ],
  code: [
    ['circle', { cx: 18, cy: 18, r: 3 }],
    ['circle', { cx: 6, cy: 6, r: 3 }],
    ['path', { d: 'M13 6h3a2 2 0 0 1 2 2v7' }],
    ['path', { d: 'M6 9v12' }],
  ],
  pipelines: [
    ['rect', { x: 3, y: 3, width: 8, height: 8, rx: 2 }],
    ['path', { d: 'M7 11v4a2 2 0 0 0 2 2h4' }],
    ['rect', { x: 13, y: 13, width: 8, height: 8, rx: 2 }],
  ],
  gates: [
    ['path', { d: 'M20 13c0 5-3.5 7.4-7.7 8.9a1 1 0 0 1-.6 0C7.5 20.4 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z' }],
    ['path', { d: 'm9 12 2 2 4-4' }],
  ],
  pentest: [
    ['circle', { cx: 12, cy: 12, r: 10 }],
    ['path', { d: 'M22 12h-4' }],
    ['path', { d: 'M6 12H2' }],
    ['path', { d: 'M12 6V2' }],
    ['path', { d: 'M12 22v-4' }],
  ],
  regression: [
    ['path', { d: 'M3 12a9 9 0 1 0 9-9 9.8 9.8 0 0 0-6.7 2.7L3 8' }],
    ['path', { d: 'M3 3v5h5' }],
  ],
  licenses: [
    ['path', { d: 'M7 21h10' }],
    ['path', { d: 'M12 3v18' }],
    ['path', { d: 'm16 16 3-8 3 8a4 4 0 0 1-6 0' }],
    ['path', { d: 'm2 16 3-8 3 8a4 4 0 0 1-6 0' }],
    ['path', { d: 'M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2' }],
  ],
  orchestration: [
    ['rect', { x: 16, y: 16, width: 6, height: 6, rx: 1 }],
    ['rect', { x: 2, y: 16, width: 6, height: 6, rx: 1 }],
    ['rect', { x: 9, y: 2, width: 6, height: 6, rx: 1 }],
    ['path', { d: 'M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3' }],
    ['path', { d: 'M12 12V8' }],
  ],
  jira: [
    ['path', { d: 'M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z' }],
    ['path', { d: 'M13 5v2' }],
    ['path', { d: 'M13 17v2' }],
    ['path', { d: 'M13 11v2' }],
  ],
  remediation: [
    ['path', { d: 'M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.8-3.8a6 6 0 0 1-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 1-3-3l6.9-6.9a6 6 0 0 1 7.9-7.9z' }],
  ],
  notifications: [
    ['path', { d: 'M10.3 21a2 2 0 0 0 3.4 0' }],
    ['path', { d: 'M3.3 15.3A1 1 0 0 0 4 17h16a1 1 0 0 0 .7-1.7C19.4 14 18 12.5 18 8A6 6 0 0 0 6 8c0 4.5-1.4 6-2.7 7.3' }],
  ],
  grants: [
    ['path', { d: 'm15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4' }],
    ['path', { d: 'm21 2-9.6 9.6' }],
    ['circle', { cx: 7.5, cy: 15.5, r: 5.5 }],
  ],
  members: [
    ['path', { d: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2' }],
    ['circle', { cx: 9, cy: 7, r: 4 }],
    ['path', { d: 'M22 21v-2a4 4 0 0 0-3-3.9' }],
    ['path', { d: 'M16 3.1a4 4 0 0 1 0 7.8' }],
  ],
  audit: [
    ['path', { d: 'M15 12h-5' }],
    ['path', { d: 'M15 8h-5' }],
    ['path', { d: 'M19 17V5a2 2 0 0 0-2-2H4' }],
    ['path', { d: 'M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3' }],
  ],
  setup: [
    ['path', { d: 'm3 17 2 2 4-4' }],
    ['path', { d: 'm3 7 2 2 4-4' }],
    ['path', { d: 'M13 6h8' }],
    ['path', { d: 'M13 12h8' }],
    ['path', { d: 'M13 18h8' }],
  ],
  search: [
    ['circle', { cx: 11, cy: 11, r: 8 }],
    ['path', { d: 'm21 21-4.3-4.3' }],
  ],
}

export default function Icon({ name, size = 15, className = '', strokeWidth = 1.7 }) {
  const shapes = PATHS[name]
  if (!shapes) return null
  return (
    <svg
      className={`icon ${className}`.trim()}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {shapes.map(([tag, attrs], index) => React.createElement(tag, { key: index, ...attrs }))}
    </svg>
  )
}
