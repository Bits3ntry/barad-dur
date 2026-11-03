import React from 'react'

/* ── SVG chart primitives (lightweight, no third-party dependency) ── */

/* Single axis + gridline chart. */
export function LineChart({ data, height = 160, color = '#ff7b00', gridColor = 'var(--line)' }) {
  const w = 600
  const h = height
  const pad = { top: 10, bottom: 24, left: 44, right: 10 }
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
  const areaPath = `${linePath} L ${points[points.length - 1].x} ${pad.top + innerH} L ${points[0].x} ${pad.top + innerH} Z`

  const gridLines = []
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (i / 4) * innerH
    gridLines.push(
      <line key={i} x1={pad.left} y1={y} x2={w - pad.right} y2={y}
        stroke={gridColor} strokeDasharray="3 3" strokeWidth="1" />
    )
  }

  const xLabels = []
  for (let i = 0; i < points.length; i += Math.max(1, Math.floor(points.length / 5))) {
    xLabels.push(
      <text key={i} x={points[i].x} y={h - 6} textAnchor="middle" fontSize="9"
        fill="#8b949e">{points[i].label || ''}</text>
    )
  }

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="chart" role="img" aria-label="line chart">
      <g>{gridLines}</g>
      <path d={areaPath} fill={color} opacity="0.12" />
      <path d={linePath} fill="none" stroke={color} strokeWidth="2.5"
        strokeLinejoin="round" strokeLinecap="round" />
      {points.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r={p.value >= max ? 4 : 3}
          fill={p.value >= max ? '#180606' : '#fff'}
          stroke={color} strokeWidth="2" />
      ))}
      {xLabels}
      <text x={w - pad.right} y={pad.top + innerH + 14} textAnchor="end" fontSize="9"
        fill="#8b949e" fontFamily="monospace">
        {data[data.length - 1].value}
      </text>
    </svg>
  )
}

/* Bar chart with categorical colors. */
export function BarChart({ data, height = 160, colors = ['#6bcb77', '#ffd166', '#ff9c3f', '#ff5a5a', '#8b949e'] }) {
  const w = 600
  const h = height
  const pad = { top: 10, bottom: 24, left: 44, right: 10 }
  const innerW = w - pad.left - pad.right
  const innerH = h - pad.top - pad.bottom

  const max = Math.max(...data.map((d) => d.value), 1)
  const barWidth = Math.min(44, (innerW / data.length) * 0.7)
  const gap = (innerW - barWidth * data.length) / (data.length + 1)

  const bars = data.map((d, i) => {
    const barH = (d.value / max) * innerH
    const x = pad.left + gap + i * (barWidth + gap)
    const y = pad.top + innerH - barH
    return { x, y, barH, ...d }
  })

  const gridLines = []
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (i / 4) * innerH
    gridLines.push(
      <line key={i} x1={pad.left} y1={y} x2={w - pad.right} y2={y}
        stroke="#30363d" strokeDasharray="3 3" strokeWidth="1" />
    )
  }

  const xLabels = bars.map((b, i) => (
    <text key={i} x={b.x + barWidth / 2} y={h - 6} textAnchor="middle" fontSize="9"
      fill="#8b949e">{b.label || ''}</text>
  ))

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="chart" role="img" aria-label="bar chart">
      <g>{gridLines}</g>
      {bars.map((b, i) => (
        <rect key={i} x={b.x} y={b.y} width={barWidth} height={b.barH}
          fill={colors[i % colors.length]} rx="2">
          <title>{b.label}: {b.value}</title>
        </rect>
      ))}
      {xLabels}
    </svg>
  )
}

/* Donut/pie chart for severity distribution. */
export function DonutChart({ data, height = 160 }) {
  const w = 600
  const h = height
  const pad = { top: 10, bottom: 10, left: 10, right: 10 }
  const cx = w / 2
  const cy = h / 2
  const radius = Math.min(w, h) / 2 - 16
  const innerRadius = radius * 0.6

  const total = data.reduce((sum, d) => sum + d.value, 0)
  const colors = ['#ff5a5a', '#ff9c3f', '#ffd166', '#6bcb77', '#8b949e']
  const legend = []

  let angle = -Math.PI / 2
  const arcs = data.map((d, i) => {
    const frac = total > 0 ? d.value / total : 0
    const startAngle = angle
    const endAngle = angle + frac * 2 * Math.PI
    const largeArc = frac > 0.5 ? 1 : 0
    angle = endAngle

    const x1 = cx + radius * Math.cos(startAngle)
    const y1 = cy + radius * Math.sin(startAngle)
    const x2 = cx + radius * Math.cos(endAngle)
    const y2 = cy + radius * Math.sin(endAngle)

    legend.push(
      <li key={i} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <span style={{ width: 10, height: 10, borderRadius: '2px', display: 'inline-block',
          background: colors[i % colors.length] }} />
        <span style={{ fontSize: 12.5 }}>{d.label}: {d.value}</span>
      </li>
    )

    return {
      x1, y1, x2, y2, startAngle, endAngle, largeArc,
      color: colors[i % colors.length], value: d.value,
    }
  })

  const arcPaths = arcs.map((a, i) => {
    if (a.value === 0 || total <= 0) return null
    return (
      <path key={i} d={`M ${cx} ${cy} L ${a.x1} ${a.y1} A ${radius} ${radius} 0 ${a.largeArc} 1 ${a.x2} ${a.y2} Z`}
        fill={a.color} stroke="var(--panel)" strokeWidth="1">
        <title>{a.value}</title>
      </path>
    )
  })

  return (
    <div>
      <svg viewBox={`0 0 ${w} ${h}`} className="chart" role="img" aria-label="donut chart">
        {arcPaths}
        {total <= 0 && (
          <circle cx={cx} cy={cy} r={(radius + innerRadius) / 2} fill="none"
            stroke="var(--line-strong)" strokeWidth={radius - innerRadius} />
        )}
        <circle cx={cx} cy={cy} r={radius} fill="none" stroke="var(--line)" strokeWidth="8" />
        <circle cx={cx} cy={cy} r={innerRadius} fill="none" stroke="var(--panel)" strokeWidth="8" />
      </svg>
      <ul style={{ listStyle: 'none', padding: 0, margin: 8  } }
        className="chart-legend">{legend}</ul>
    </div>
  )
}

/* Simple stat with progress bar for SLA/remediation. */
export function ProgressBar({ label, value, max, tone = 'info' }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0
  const barColor = tone === 'bad' ? '#ff5a5a' : tone === 'warn' ? '#ffd166' : '#6bcb77'
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


