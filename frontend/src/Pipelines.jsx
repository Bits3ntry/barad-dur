import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function Pipelines() {
  const [state, setState] = useState({ pipelines: [], runs: [], error: '', loading: false, detail: null })

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }))
    Promise.all([
      api.get('/api/v1/ci/pipelines'),
      api.get('/api/v1/ci/runs'),
    ])
      .then(([pipelines, runs]) => setState((s) => ({
        ...s, pipelines: pipelines.data, runs: runs.data, loading: false,
      })))
      .catch((error) => setState((s) => ({ ...s, loading: false, error: String(error.message || error) })))
  }, [])

  async function openRun(run) {
    if (state.detail?.id === run.id) {
      setState((s) => ({ ...s, detail: null }))
      return
    }
    try {
      const { data } = await api.get(`/api/v1/ci/runs/${run.id}`)
      setState((s) => ({ ...s, detail: data }))
    } catch (error) {
      setState((s) => ({ ...s, error: String(error.message || error) }))
    }
  }

  return (
    <div>
      <div className="bar">
        <span className="count">{state.pipelines.length} pipelines</span>
        <span className="count">{state.runs.length} runs</span>
      </div>
      {state.error && <p className="error">{state.error}</p>}
      <table>
        <thead><tr><th>provider</th><th>repository</th><th>workflow</th><th>retired</th></tr></thead>
        <tbody>
          {state.pipelines.map((p) => (
            <tr key={p.id}>
              <td>{p.provider}</td>
              <td className="mono">{p.repository}</td>
              <td className="mono">{p.workflow_path || '—'}</td>
              <td>{p.retired ? 'yes' : 'no'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <table>
        <thead><tr><th>started</th><th>ref</th><th>commit</th><th>event</th><th>actor</th><th>verdict</th><th>findings</th></tr></thead>
        <tbody>
          {state.runs.map((run) => (
            <React.Fragment key={run.id}>
              <tr className={state.detail?.id === run.id ? 'selected' : ''} onClick={() => openRun(run)}>
                <td>{(run.started_at || '').replace('T', ' ').slice(0, 19)}</td>
                <td className="mono">{run.ref || '—'}</td>
                <td className="mono">{run.commit_sha ? `${run.commit_sha.slice(0, 8)}…` : '—'}</td>
                <td>{run.event || '—'}</td>
                <td>{run.actor || '—'}</td>
                <td><span className={`status verdict-${run.verdict}`}>{run.verdict || 'running'}</span></td>
                <td>{run.findings_count}</td>
              </tr>
              {state.detail?.id === run.id && (
                <tr className="detail-row"><td colSpan={7}>
                  <div className="detail">
                    <strong>gate reasons</strong>
                    <pre>{(state.detail.verdict_reasons || []).join('\n') || '—'}</pre>
                    <strong>findings in run</strong>
                    <ul className="plain">
                      {state.detail.findings.map((f) => (
                        <li key={f.id}>{f.severity || '—'} {f.kind} {f.rule_id || ''} {f.path || ''} · {f.status}</li>
                      ))}
                    </ul>
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      {!state.runs.length && !state.loading && !state.error && (
        <p className="empty">No CI runs yet — the CLI registers one inside a GitHub Actions context.</p>
      )}
    </div>
  )
}
