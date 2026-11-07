import React, { useMemo } from 'react'
import world from './world.json'

/* ────────────────────────────── where is this thing ──────────────────────────────

   A map that never lies. The land is a bundled 110m outline (no tile server, no
   third party learning which of your hosts you are looking at), the projection is
   plain equirectangular, and the marker is the address itself.

   When there is no location — no geolocator configured, no address observed, an
   answer the provider could not give — the panel says so in words and blurs the
   plate instead of drawing a pin somewhere plausible. An invented coordinate is
   the one mistake this page cannot afford. */

const W = 720
const H = 300

function project(lon, lat) {
  return [((lon + 180) / 360) * W, ((90 - lat) / 180) * H]
}

export default function AssetMap({ points = [], reason = '', address = '' }) {
  const paths = useMemo(() => world.rings.map((ring) => {
    const d = ring.map(([lon, lat], index) => {
      const [x, y] = project(lon, lat)
      return `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
    }).join(' ')
    return `${d} Z`
  }), [])

  const markers = points
    .filter((point) => Number.isFinite(point.latitude) && Number.isFinite(point.longitude))
    .map((point) => ({ ...point, ...(project(point.longitude, point.latitude) && {
      x: project(point.longitude, point.latitude)[0],
      y: project(point.longitude, point.latitude)[1],
    }) }))

  const located = markers.length > 0
  const primary = located ? markers[0] : null

  /* A world plate answers "where on the planet" and nothing else: at 720 units
     wide, a country is a smudge and the pin is the only readable thing. When
     there is a location the plate zooms to the region around it — six times
     closer — and the outline keeps its hairline through non-scaling strokes, so
     close-up geography stays a background instead of a thick tangle. */
  const ZOOM = 6
  const spanX = W / ZOOM
  const spanY = H / ZOOM
  const clamp = (value, min, max) => Math.min(Math.max(value, min), max)
  const view = located
    ? { x: clamp(primary.x - spanX / 2, 0, W - spanX),
        y: clamp(primary.y - spanY / 2, 0, H - spanY),
        w: spanX, h: spanY }
    : { x: 0, y: 0, w: W, h: H }
  const dot = located ? 4 / Math.sqrt(ZOOM) : 4
  const ring = located ? 9 / Math.sqrt(ZOOM) : 9

  return (
    <div className={`asset-map${located ? '' : ' unlocated'}`}>
      <svg viewBox={`${view.x} ${view.y} ${view.w} ${view.h}`} role="img"
           aria-label={located ? `location of ${address}` : 'location unknown'}>
        <defs>
          <linearGradient id="mapFade" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.20" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0.06" />
          </linearGradient>
        </defs>

        <g className="map-plate">
          {paths.map((d, index) => (
            <path key={index} d={d} fill="url(#mapFade)" stroke="currentColor"
                  strokeOpacity="0.34" strokeWidth="0.6"
                  vectorEffect="non-scaling-stroke" />
          ))}
        </g>

        {located && markers.map((marker, index) => (
          <g key={marker.address || index} className="map-marker">
            <circle cx={marker.x} cy={marker.y} r={ring * 1.6} className="map-pulse" />
            <circle cx={marker.x} cy={marker.y} r={dot} className="map-dot" />
            {index === 0 && (
              <circle cx={marker.x} cy={marker.y} r={ring} className="map-ring" />
            )}
          </g>
        ))}
      </svg>

      {located ? (
        <div className="map-caption">
          <span className="map-place">
            {[primary.city, primary.region, primary.country].filter(Boolean).join(' · ')
              || 'location resolved'}
          </span>
          <span className="map-coords mono">
            {primary.latitude.toFixed(3)}, {primary.longitude.toFixed(3)}
          </span>
          {primary.organisation && (
            <span className="map-org">{primary.organisation}
              {primary.asn ? ` · ${String(primary.asn).split(' ')[0]}` : ''}</span>
          )}
        </div>
      ) : (
        <div className="map-caption">
          <span className="map-place">location unknown</span>
          <span className="map-org">
            {reason || 'no geolocator is configured for this deployment'}
          </span>
        </div>
      )}
    </div>
  )
}
