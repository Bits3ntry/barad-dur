import React from 'react'
import { useI18n } from './i18n'

/* ── SVG chart primitives (lightweight, no third-party dependency) ──
   Every colour comes from a semantic token, so a chart reads the same in both
   themes and a severity hue is never invented locally. `tone` names a severity
   (critical | high | medium | low | info) or a state (accent | ok | muted). */

const ink = (tone) => {
  if (!tone || tone === 'accent') return 'var(--action-bg)'
  if (tone === 'ok') return 'var(--sev-low)'
  if (tone === 'muted') return 'var(--fg-subtle)'
  return `var(--sev-${tone})`
}

const GRID = 'var(--border-subtle)'
const LABEL = 'var(--fg-subtle)'
const SURFACE = 'var(--surface-card)'

const AXIS_FONT = 10

/* Single axis + gridline chart. */
export function LineChart({ data, height = 160, tone = 'accent', color,
                           gridColor = GRID }) {
  const { t } = useI18n()
  const stroke = color || ink(tone)
  const w = 600
  const h = height
  const pad = { top: 12, bottom: 26, left: 46, right: 12 }
  const innerW = w - pad.left - pad.right
  const innerH = h - pad.top - pad.bottom

  const values = data.map((d) => d.value)
  const min = Math.min(...values, 0)
  const max = Math.max(...values, 1)
  const range = max - min || 1

  const points = data.map((d, i) => {
    const x = pad.left + (i / (data.length - 1 || 1)) * innerW
    const y = pad.top + innerH - ((d.value - min) / range) * innerH
    return { x, y, ...d }
  })

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ')
  const areaPath = `${linePath} L ${points[points.length - 1].x} ${pad.top + innerH}`
    + ` L ${points[0].x} ${pad.top + innerH} Z`

  const gridLines = []
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (i / 4) * innerH
    gridLines.push(
      <line key={i} x1={pad.left} y1={y} x2={w - pad.right} y2={y}
        style={{ stroke: gridColor }} strokeDasharray="3 3" strokeWidth="1" />
    )
  }

  const xLabels = []
  for (let i = 0; i < points.length; i += Math.max(1, Math.floor(points.length / 5))) {
    xLabels.push(
      <text key={i} x={points[i].x} y={h - 8} textAnchor="middle" fontSize={AXIS_FONT}
        style={{ fill: LABEL }}>{points[i].label || ''}</text>
    )
  }

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="chart" role="img" aria-label={t('chart.lineAria')}>
      <g>{gridLines}</g>
      <path d={areaPath} style={{ fill: stroke }} opacity="0.10" />
      <path d={linePath} fill="none" style={{ stroke }} strokeWidth="2.5"
        strokeLinejoin="round" strokeLinecap="round" />
      {points.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r={p.value >= max ? 3.5 : 2.5}
          style={{ fill: p.value >= max ? stroke : SURFACE, stroke }} strokeWidth="2" />
      ))}
      {xLabels}
      <text x={pad.left - 8} y={pad.top + 4} textAnchor="end" fontSize={AXIS_FONT}
        style={{ fill: LABEL }}>{max}</text>
      <text x={pad.left - 8} y={pad.top + innerH + 4} textAnchor="end" fontSize={AXIS_FONT}
        style={{ fill: LABEL }}>{min}</text>
      <text x={w - pad.right} y={pad.top - 1} textAnchor="end" fontSize={AXIS_FONT + 1}
        style={{ fill: LABEL }} fontFamily="ui-monospace, monospace">
        {data[data.length - 1].value}
      </text>
    </svg>
  )
}

/* Bar chart with categorical tones (one per bar, in order). */
export function BarChart({ data, height = 160, tones = ['critical', 'high', 'medium', 'low', 'info'],
                           colors }) {
  const { t } = useI18n()
  const w = 600
  const h = height
  const pad = { top: 12, bottom: 26, left: 46, right: 12 }
  const innerW = w - pad.left - pad.right
  const innerH = h - pad.top - pad.bottom

  const max = Math.max(...data.map((d) => d.value), 1)
  const barWidth = Math.min(46, (innerW / Math.max(data.length, 1)) * 0.66)
  const gap = (innerW - barWidth * data.length) / (data.length + 1)

  const bars = data.map((d, i) => {
    const barH = (d.value / max) * innerH
    const x = pad.left + gap + i * (barWidth + gap)
    const y = pad.top + innerH - barH
    const tone = d.tone || tones[i % tones.length]
    return { x, y, barH, tone, ...d }
  })

  const gridLines = []
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (i / 4) * innerH
    gridLines.push(
      <line key={i} x1={pad.left} y1={y} x2={w - pad.right} y2={y}
        style={{ stroke: GRID }} strokeDasharray="3 3" strokeWidth="1" />
    )
  }

  const xLabels = bars.map((b, i) => (
    <text key={i} x={b.x + barWidth / 2} y={h - 8} textAnchor="middle" fontSize={AXIS_FONT}
      style={{ fill: LABEL }}>{b.label || ''}</text>
  ))

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="chart" role="img" aria-label={t('chart.barAria')}>
      <g>{gridLines}</g>
      {bars.map((b, i) => (
        <g key={i}>
          <rect x={b.x} y={b.y} width={barWidth} height={Math.max(b.barH, b.value ? 2 : 0)}
            rx="3" style={{ fill: colors ? colors[i % colors.length] : ink(b.tone) }}>
            <title>{b.label}: {b.value}</title>
          </rect>
          <text x={b.x + barWidth / 2} y={Math.max(b.y - 6, 10)} textAnchor="middle"
            fontSize={AXIS_FONT + 1} fontWeight="620"
            style={{ fill: b.value ? 'var(--fg-strong)' : LABEL }}>{b.value}</text>
        </g>
      ))}
      {xLabels}
    </svg>
  )
}

/* Donut for a distribution. Each datum may name its own `tone`. */
export function DonutChart({ data, height = 160 }) {
  const { t } = useI18n()
  const w = 600
  const h = height
  const cx = w / 2
  const cy = h / 2
  const radius = Math.min(w, h) / 2 - 18
  const innerRadius = radius * 0.62

  const total = data.reduce((sum, d) => sum + d.value, 0)
  const fallback = ['critical', 'high', 'medium', 'low', 'info']
  const legend = []

  let angle = -Math.PI / 2
  const arcs = data.map((d, i) => {
    const frac = total > 0 ? d.value / total : 0
    const startAngle = angle
    const endAngle = angle + frac * 2 * Math.PI
    const largeArc = frac > 0.5 ? 1 : 0
    angle = endAngle

    const tone = d.tone || fallback[i % fallback.length]
    const x1 = cx + radius * Math.cos(startAngle)
    const y1 = cy + radius * Math.sin(startAngle)
    const x2 = cx + radius * Math.cos(endAngle)
    const y2 = cy + radius * Math.sin(endAngle)

    legend.push(
      <li key={i} className="chart-legend-row">
        <i className={`chart-swatch sev-bar-${tone}`} aria-hidden="true" />
        <span>{d.label}</span>
        <strong>{d.value}</strong>
      </li>
    )

    return { x1, y1, x2, y2, startAngle, endAngle, largeArc, tone, value: d.value }
  })

  const arcPaths = arcs.map((a, i) => {
    if (a.value === 0 || total <= 0) return null
    return (
      <path key={i}
        d={`M ${cx} ${cy} L ${a.x1} ${a.y1} A ${radius} ${radius} 0 ${a.largeArc} 1 ${a.x2} ${a.y2} Z`}
        style={{ fill: ink(a.tone) }} stroke={SURFACE} strokeWidth="1.5">
        <title>{a.value}</title>
      </path>
    )
  })

  return (
    <div className="chart-donut">
      <svg viewBox={`0 0 ${w} ${h}`} className="chart" role="img" aria-label={t('chart.donutAria')}>
        {arcPaths}
        {total <= 0 && (
          <circle cx={cx} cy={cy} r={(radius + innerRadius) / 2} fill="none"
            style={{ stroke: GRID }} strokeWidth={radius - innerRadius} />
        )}
        <circle cx={cx} cy={cy} r={(radius + innerRadius) / 2} fill="none"
          style={{ stroke: GRID }} strokeWidth={radius - innerRadius}
          strokeDasharray={total > 0 ? 'none' : '4 4'} />
        <text x={cx} y={cy + 2} textAnchor="middle" fontSize="26" fontWeight="650"
          style={{ fill: 'var(--fg-strong)' }}>{total}</text>
        <text x={cx} y={cy + 20} textAnchor="middle" fontSize="10"
          style={{ fill: LABEL, letterSpacing: '0.08em' }}>{t('chart.open')}</text>
      </svg>
      <ul className="chart-legend">{legend}</ul>
    </div>
  )
}

/* Simple stat with progress bar for SLA/remediation. */
export function ProgressBar({ label, value, max, tone = 'info' }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0
  return (
    <div className="progress">
      <span className="progress-label">{label}</span>
      <div className="progress-bar">
        <div className={`progress-fill ${tone}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="progress-value">{value} / {max}</span>
    </div>
  )
}
