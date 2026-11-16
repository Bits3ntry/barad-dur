import React, { useEffect, useMemo, useState } from 'react'
import Icon from './icons'
import { api } from './api'
import { useI18n } from './i18n'
import { Card } from './ui'

/* What this object touches.

   The relations are already in the catalogue — 222 foreign keys and five bridge
   tables — but until now they could only be read one join at a time. This panel walks
   them: three columns, the object here, what it points at, and what those point at.
   Clicking a node says how it was reached and where it opens in the console. */

const TYPE_ICON = {
  project: 'projects',
  asset: 'assets',
  finding: 'findings',
  component: 'components',
  application_component: 'projects',
  project_version: 'version',
  cycle: 'cycle',
  work_item: 'remediation',
  deployment: 'deployments',
  organization: 'businessContext',
  vulnerability: 'vulnerabilities',
  repository: 'repositories',
  agent_mission: 'agents',
  agent_task: 'orchestration',
}

function iconOf(type) {
  return TYPE_ICON[type] || 'search'
}

export default function FindingRelations({ findingId }) {
  const { t } = useI18n()
  const [graph, setGraph] = useState(null)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(null)
  const [reload, setReload] = useState(0)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let alive = true
    setGraph(null)
    setSelected(null)
    api.get(`/api/v1/graph/neighbors?type=finding&id=${encodeURIComponent(findingId)}&depth=2`)
      .then((body) => { if (alive) setGraph(body.data) })
      .catch((caught) => { if (alive) setError(String(caught.message || caught)) })
    return () => { alive = false }
  }, [findingId, reload])

  /* The graph is a projection: a finding promoted a minute ago is not in it yet.
     Rebuilding is cheap (one pass over the catalogue), so the reader can ask. */
  async function refresh() {
    setBusy(true)
    try {
      await api.post('/api/v1/graph/rebuild', {})
      setReload((value) => value + 1)
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally {
      setBusy(false)
    }
  }

  const columns = useMemo(() => {
    if (!graph) return []
    return [0, 1, 2].map((depth) => ({
      depth,
      nodes: (graph.nodes || []).filter((node) => node.depth === depth),
    })).filter((column) => column.nodes.length > 0)
  }, [graph])

  if (error) return <div className="banner banner-error">{error}</div>
  if (!graph) return <div className="empty">{t('relations.loading')}</div>
  if ((graph.nodes || []).length <= 1) {
    return (
      <div className="empty">
        <strong>{t('relations.none.title')}</strong>
        <span>{t('relations.none.body')}</span>
      </div>
    )
  }

  return (
    <div className="stack">
      <Card title={t('relations.title')} band
        actions={<>
          <span className="muted">
            {t('relations.counts', {
              n: graph.nodes.length - 1,
              d1: graph.by_depth?.[1] || 0,
              d2: graph.by_depth?.[2] || 0,
            })}
          </span>
          <button className="mini" disabled={busy} onClick={refresh}>
            {busy ? t('relations.refreshing') : t('relations.refresh')}
          </button>
        </>}>
        <div className="relations-flow">
          {columns.map((column) => (
            <section key={column.depth} className="relations-column">
              <h5>
                {column.depth === 0
                  ? t('relations.here')
                  : t(`relations.hop${column.depth}`, { n: column.nodes.length })}
              </h5>
              <ul>
                {column.nodes.map((node) => (
                  <li key={`${node.type}:${node.id}`}>
                    <button type="button"
                      className={`relation-node ${selected && selected.id === node.id
                        && selected.type === node.type ? 'is-on' : ''}`}
                      onClick={() => setSelected(node)}>
                      <span className="relation-icon">
                        <Icon name={iconOf(node.type)} size={13} />
                      </span>
                      <span className="relation-body">
                        <span className="relation-type">{node.type}</span>
                        <span className="relation-label">{node.label}</span>
                        {node.rel && (
                          <span className="relation-rel">
                            {t('relations.via', { rel: node.rel })}
                          </span>
                        )}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
              {column.depth === 2 && graph.truncated && (
                <p className="muted">{t('relations.truncated')}</p>
              )}
            </section>
          ))}

          <aside className="relation-detail">
            {selected ? (
              <>
                <header>
                  <span className="trace-kind">{selected.type}</span>
                  {selected.depth > 0 && (
                    <span className="trace-at">
                      {t('relations.hopN', { n: selected.depth })}
                    </span>
                  )}
                </header>
                <p className="relation-detail-label">{selected.label}</p>
                {selected.rel && selected.from && (
                  <p className="muted">
                    {t('relations.viaFrom', {
                      rel: selected.rel,
                      from: (graph.nodes || []).find((node) => node.id === selected.from.id
                        && node.type === selected.from.type)?.label || selected.from.type,
                    })}
                  </p>
                )}
                <pre className="trace-code">{`${selected.type}:${selected.id}`}</pre>
                {selected.route && (
                  <a className="mini" href={selected.route}>{t('relations.open')}</a>
                )}
              </>
            ) : (
              <p className="muted">{t('relations.pick')}</p>
            )}
          </aside>
        </div>
      </Card>
    </div>
  )
}
