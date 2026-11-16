import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Banner, Card, ErrorBanner, Loading } from './ui'
import { useI18n } from './i18n'

/* Connecting an external agent is three artefacts, not one prompt.

   The MCP server runs where the agent runs (a laptop client over stdio, or hosted
   with the HTTP transport), so the platform's half is: an identity, the address,
   and the catalogue it exposes. This panel prints all three, plus the sentence the
   server already sends on `initialize` — most clients do not forward it to the
   model, so it is offered as something to paste.

   The key is issued here and shown once. It is never stored in this panel: a sheet
   that can reprint a key is a key that ends up in a screenshot. */

function Block({ text }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { setCopied(false) }
  }
  return (
    <div className="ingest-cmd">
      <pre>{text}</pre>
      <button className="mini" type="button" onClick={copy}>
        {copied ? t('mcp.copied') : t('mcp.copy')}
      </button>
    </div>
  )
}

export default function McpSettings({ onOpenSection }) {
  const { t, tCount } = useI18n()
  const [sheet, setSheet] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [fresh, setFresh] = useState('')

  useEffect(() => {
    api.get('/api/v1/agents/mcp')
      .then((body) => setSheet(body.data))
      .catch((caught) => setError(String(caught.message || caught)))
  }, [])

  async function issueKey() {
    setBusy(true); setError(''); setFresh('')
    try {
      const body = await api.post('/api/v1/org/keys', { label: 'mcp', actor: 'console' })
      setFresh(body.key || body.data?.key || '')
    } catch (caught) {
      setError(String(caught.message || caught))
    } finally { setBusy(false) }
  }

  if (error && !sheet) return <ErrorBanner error={error} />
  if (!sheet) return <Loading label={t('mcp.loading')} />

  const url = sheet.api_url || (typeof window !== 'undefined' ? window.location.origin : '<barad-url>')
  const key = fresh || '<tu key>'

  const stdio = JSON.stringify({
    mcpServers: {
      'barad-dur': {
        command: 'python',
        args: ['-m', 'barad_mcp.server'],
        env: {
          PYTHONPATH: '<ruta-al-repo>/backend/src:<ruta-al-repo>/mcp',
          BARAD_URL: url,
          BARAD_API_KEY: key,
        },
      },
    },
  }, null, 2)

  const http = [
    `export BARAD_MCP_TRANSPORT=streamable-http   # or: sse`,
    `export BARAD_URL=${url}`,
    `export BARAD_API_KEY=${key}   # lives in the client or the host, never here`,
    `python -m barad_mcp.server`,
  ].join('\n')

  const prompt = t('mcp.prompt.body', { instructions: sheet.instructions })

  return (
    <div className="settings-body stack">
      <Card title={t('mcp.title')}>
        <p className="settings-intro">{t('mcp.intro')}</p>
        <p className="muted">{t('mcp.verdict')}</p>
      </Card>

      {error && <Banner kind="error">{error}</Banner>}

      <Card title={t('mcp.identity.title')}>
        <p className="settings-intro">{t('mcp.identity.intro')}</p>
        <div className="row" style={{ gap: 8 }}>
          <button className="btn-primary" onClick={issueKey} disabled={busy}>
            {busy ? t('mcp.identity.issuing') : t('mcp.identity.issue')}
          </button>
          {onOpenSection && (
            <button className="btn-ghost" onClick={() => onOpenSection('keys')}>
              {t('mcp.identity.manage')} →
            </button>
          )}
        </div>
        {fresh && (
          <>
            <p className="receipt">{t('mcp.identity.shownOnce')}</p>
            <Block text={fresh} />
          </>
        )}
        <p className="muted">{t('mcp.identity.warning')}</p>
      </Card>

      <Card title={t('mcp.local.title')}>
        <p className="settings-intro">{t('mcp.local.intro')}</p>
        <Block text={stdio} />
        <p className="muted">{t('mcp.local.note')}</p>
      </Card>

      <Card title={t('mcp.remote.title')}>
        <p className="settings-intro">{t('mcp.remote.intro')}</p>
        <Block text={http} />
        <p className="muted">{t('mcp.remote.note', { url })}</p>
      </Card>

      <Card title={t('mcp.prompt.title')}>
        <p className="settings-intro">{t('mcp.prompt.intro')}</p>
        <Block text={prompt} />
        <p className="muted">{t('mcp.prompt.note')}</p>
      </Card>

      <Card title={t('mcp.exposes.title')}>
        <p className="settings-intro">{t('mcp.exposes.intro', {
          mcp: sheet.mcp_tools.length, n: sheet.catalogue.length,
          server: sheet.server.entrypoint,
        })}</p>
        <div className="stack" style={{ gap: 4 }}>
          {sheet.mcp_tools.map((name) => (
            <div className="row" key={name} style={{ gap: 8, alignItems: 'baseline' }}>
              <span className="mono">{name}</span>
              <span className="pill">{t(`mcp.tool.${name}`)}</span>
            </div>
          ))}
        </div>
        <details className="mcp-catalogue">
          <summary>{tCount('mcp.exposes.catalogue', sheet.catalogue.length)}</summary>
          <div className="stack" style={{ gap: 3 }}>
            {sheet.catalogue.map((tool) => (
              <div className="row" key={tool.name} style={{ gap: 8, alignItems: 'baseline' }}>
                <span className="mono">{tool.name}</span>
                <span className="muted">{tool.risk}</span>
              </div>
            ))}
          </div>
        </details>
      </Card>
    </div>
  )
}
