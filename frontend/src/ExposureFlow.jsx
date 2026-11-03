import React from 'react'

/* Exposure flow, drawn rather than tabulated: sources on the left feed a
   priority donut, which branches into current outcomes on the right.

   Every number comes from /api/v1/dashboard/exposure-flow — no estimates. A
   stage with no data (nothing closed yet, nothing in progress) is drawn at zero
   instead of being hidden, so "none" and "not tracked" stay different readings.

   Geometry is fixed on purpose: both columns occupy the same vertical band
   (SOURCE_TOP..SOURCE_BOTTOM) so the flow reads as one line, and every label has
   room to breathe — the first draft clipped the donut caption and collided the
   legend. */

const PRIORITY = [
  { key: 'P0', label: 'P0', color: 'var(--critical)' },
  { key: 'P1', label: 'P1', color: 'var(--high)' },
  { key: 'P2', label: 'P2', color: 'var(--medium)' },
  { key: 'P3', label: 'P3', color: 'var(--low)' },
  { key: 'unranked', label: 'no priority', color: 'var(--line-strong)' },
]

const WIDTH = 1040
const HEIGHT = 372
const SOURCE_X = 16
const SOURCE_W = 252
const SOURCE_TOP = 74
const SOURCE_BOTTOM = 344
const DONUT = { cx: 604, cy: 206, r: 58, width: 22 }
const OUTCOME_X = 796

function polar(cx, cy, radius, angle) {
  return [cx + radius * Math.cos(angle), cy + radius * Math.sin(angle)]
}

function arcPath(cx, cy, radius, start, end) {
  const [x1, y1] = polar(cx, cy, radius, start)
  const [x2, y2] = polar(cx, cy, radius, end)
  const large = end - start > Math.PI ? 1 : 0
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${radius} ${radius} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`
}

function curve(fromX, fromY, toX, toY, dashed, tone) {
  const midX = (fromX + toX) / 2
  return (
    <path
      d={`M ${fromX} ${fromY} C ${midX} ${fromY}, ${midX} ${toY}, ${toX} ${toY}`}
      fill="none"
      className={`flow-link${dashed ? ' flow-link-in' : ''}${tone ? ` flow-link-${tone}` : ''}`}
    />
  )
}

export default function ExposureFlow({ flow, onNavigate }) {
  if (!flow) return null

  const sources = (flow.sources || []).slice(0, 5)
  const received = flow.received || 0
  const actionable = flow.actionable || 0
  const byPriority = flow.by_priority || {}
  const outcomes = flow.outcomes || {}

  const priorities = PRIORITY.filter((entry) => (byPriority[entry.key] || 0) > 0)
  const totalPriority = priorities.reduce((sum, entry) => sum + (byPriority[entry.key] || 0), 0)

  // The source block is centred on the donut and the dashed box hugs the rows,
  // instead of stretching to the full height and leaving dead space.
  const sourceGap = sources.length > 3 ? 44 : 56
  const blockHeight = Math.max(sources.length - 1, 0) * sourceGap
  const rowsTop = DONUT.cy - blockHeight / 2 - 12
  const sourceY = (index) => rowsTop + index * sourceGap
  const boxTop = rowsTop - 44
  const boxHeight = blockHeight + 88

  // Donut segments: P0 first, clockwise from 12 o'clock.
  let cursor = -Math.PI / 2
  const segments = priorities.map((entry) => {
    const share = totalPriority ? (byPriority[entry.key] || 0) / totalPriority : 0
    const sweep = share * Math.PI * 2
    const start = cursor + 0.02
    const end = cursor + Math.max(sweep - 0.02, 0.01)
    cursor += sweep
    return { ...entry, value: byPriority[entry.key] || 0, start, end }
  })

  const outcomeRows = [
    { label: 'Open', value: outcomes.open || 0, tone: 'ink', thick: true, link: true },
    { label: 'Past SLA', value: outcomes.past_sla || 0, tone: 'bad', link: true },
    { label: 'In progress', value: outcomes.in_progress || 0, tone: 'muted', link: true },
    { label: 'Suppressed', value: outcomes.suppressed || 0, tone: 'muted', link: true },
    { label: 'Resolved', value: outcomes.resolved || 0, tone: 'muted', link: true,
      hint: outcomes.closed_in_window
        ? `${outcomes.closed_in_window} in the last ${flow.window_days}d` : null },
  ]

  const outcomeGap = 54
  const outcomeY = (index) => DONUT.cy - ((outcomeRows.length - 1) / 2) * outcomeGap
    + index * outcomeGap

  // Legend centred under the ring, spaced by measured text length.
  const legendWidths = segments.map((segment) => 18 + `${segment.label} ${segment.value}`.length * 6.4)
  const legendTotal = legendWidths.reduce((sum, width) => sum + width, 0)
  let legendCursor = DONUT.cx - legendTotal / 2

  return (
    <svg className="flow-chart" viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      role="img"
      aria-label={`Exposure flow: ${received} received, ${actionable} actionable, `
        + `${outcomes.past_sla || 0} past SLA`}>
      {/* sources panel */}
      <text className="flow-caption" x={SOURCE_X} y={30}>
        Sources received in {flow.window_days} days
      </text>
      <rect className="flow-source-box" x={SOURCE_X} y={sources.length ? boxTop : SOURCE_TOP}
        width={SOURCE_W} height={sources.length ? boxHeight : 120} rx={12} />

      {sources.map((source, index) => {
        const y = sourceY(index)
        return (
          <g key={`${source.kind}-${source.tool}`}>
            <text className="flow-source-name" x={SOURCE_X + 16} y={y}>{source.kind}</text>
            <text className="flow-source-detail" x={SOURCE_X + 16} y={y + 15}>{source.tool}</text>
            <text className="flow-source-count" x={SOURCE_X + SOURCE_W - 16} y={y + 8}
              textAnchor="end">
              {source.count}
            </text>
            {curve(SOURCE_X + SOURCE_W, y + 4,
              DONUT.cx - DONUT.r - 6, DONUT.cy + (index - (sources.length - 1) / 2) * 7, true)}
          </g>
        )
      })}
      {!sources.length && (
        <text className="flow-source-detail" x={SOURCE_X + 16} y={SOURCE_TOP + 48}>
          nothing received in this window
        </text>
      )}

      {/* received -> new, above the merge */}
      <text className="flow-caption" x={DONUT.cx - DONUT.r - 22} y={46} textAnchor="middle">
        received
      </text>
      <text className="flow-count" x={DONUT.cx - DONUT.r - 22} y={68} textAnchor="middle">
        {received}
      </text>
      <text className="flow-caption" x={DONUT.cx + 10} y={46} textAnchor="middle">
        new or reopened
      </text>
      <text className="flow-count" x={DONUT.cx + 10} y={68} textAnchor="middle">
        {received}
      </text>

      {/* donut */}
      {segments.map((segment) => (
        <path key={segment.key}
          d={arcPath(DONUT.cx, DONUT.cy, DONUT.r, segment.start, segment.end)}
          stroke={segment.color} strokeWidth={DONUT.width} fill="none" />
      ))}
      {!segments.length && (
        <circle cx={DONUT.cx} cy={DONUT.cy} r={DONUT.r} fill="none"
          stroke="var(--line-strong)" strokeWidth={DONUT.width} />
      )}
      <text className="flow-center-label" x={DONUT.cx} y={DONUT.cy - 20} textAnchor="middle">
        actionable
      </text>
      <text className="flow-center" x={DONUT.cx} y={DONUT.cy + 10} textAnchor="middle">
        {actionable}
      </text>
      <text className="flow-center-label" x={DONUT.cx} y={DONUT.cy + 30} textAnchor="middle">
        by priority
      </text>

      {/* priority key under the ring */}
      {segments.map((segment, index) => {
        const x = legendCursor
        legendCursor += legendWidths[index]
        return (
          <g key={`key-${segment.key}`}>
            <circle cx={x + 4} cy={DONUT.cy + DONUT.r + 34} r={4} fill={segment.color} />
            <text className="flow-legend" x={x + 14} y={DONUT.cy + DONUT.r + 38}>
              {segment.label} {segment.value}
            </text>
          </g>
        )
      })}

      {/* outcomes column */}
      <text className="flow-caption" x={OUTCOME_X} y={30}>outcomes</text>
      {outcomeRows.map((row, index) => {
        const y = outcomeY(index)
        return (
          <g key={row.label}
            className={row.link ? 'flow-outcome' : ''}
            onClick={row.link && onNavigate ? () => onNavigate('findings') : undefined}>
            {row.link && curve(DONUT.cx + DONUT.r + 4, DONUT.cy + (index - 2) * 5,
              OUTCOME_X - 12, y, false, row.tone === 'bad' ? 'bad' : '')}
            <circle cx={OUTCOME_X} cy={y} r={row.thick ? 5 : 3.5}
              fill={row.tone === 'bad' ? 'var(--critical)'
                : row.tone === 'muted' ? 'var(--line-strong)' : 'var(--text)'} />
            <text className="flow-outcome-label" x={OUTCOME_X + 16} y={y + 4}>
              {row.label}
            </text>
            {row.hint && (
              <text className="flow-outcome-hint" x={OUTCOME_X + 16} y={y + 19}>
                {row.hint}
              </text>
            )}
            <text className={`flow-outcome-count${row.tone === 'bad' ? ' bad' : ''}`}
              x={WIDTH - 6} y={y + 4} textAnchor="end">
              {row.value}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
