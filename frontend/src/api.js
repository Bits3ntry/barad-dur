// `org` is the organisation the console is working in. It travels as `X-Org` on
// every request and is only meaningful for a signed-in person: an API key is
// bound to one organisation, and the API refuses to be pointed elsewhere.
const DEFAULTS = { url: '', key: '', token: '', refresh_token: '', expires_at: '', org: '' }

function read() {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem('barad.ui') || '{}') }
  } catch {
    return { ...DEFAULTS }
  }
}

function save(settings) {
  const current = read()
  localStorage.setItem('barad.ui', JSON.stringify({ ...current, ...settings }))
}

/* Endpoints that must work with no credential yet: the entrance needs them to
   obtain one. Sending them through the credential guard made sign-in
   impossible — it answered "Set the API key or sign in from Settings" to the
   login request itself. */
const PUBLIC_PATHS = [
  '/api/v1/auth/login',
  '/api/v1/auth/bootstrap',
  '/api/v1/auth/password/reset',
  '/api/v1/auth/oidc/',
  '/api/v1/auth/invitations/',
  '/healthz',
  '/api/v1/auth/refresh',
]

// A single in-flight renewal prevents parallel screen loads from rotating the
// same refresh token twice. It must be module state, not an implicit global.
let refreshPromise = null

function isPublic(path) {
  return PUBLIC_PATHS.some((prefix) => path.startsWith(prefix))
}

async function refreshSession() {
  const { refresh_token } = read()
  // With an API key there is no refresh token: a 401 means the key itself was
  // rejected, and saying "no refresh token" hides that from the operator.
  if (!refresh_token) throw new Error('HTTP 401: the API key or session was rejected.')
  if (refreshPromise) return refreshPromise
  refreshPromise = (async () => {
    try {
      const data = await api.post('/api/v1/auth/refresh', {
        refresh_token,
      })
      save({
        token: data.data.access_token,
        refresh_token: data.data.refresh_token,
        expires_at: data.data.expires_at,
      })
      return data.data
    } catch (error) {
      save({ token: '', refresh_token: '', expires_at: '' })
      throw error
    } finally {
      refreshPromise = null
    }
  })()
  const result = await refreshPromise
  refreshPromise = null
  return result
}

/* FastAPI answers two shapes on failure: a string (HTTPException) or an array
   of {loc, msg} (pydantic validation). Stringifying the array put
   `[{"type":"string_too_short","loc":["body","justification"],...}]` in front of
   the reader; every screen now gets "justification: String should have at
   least 4 characters" instead. */
function describeError(detail) {
  if (!detail) return ''
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail.map((item) => {
      const field = (item.loc || []).filter((part) => part !== 'body').join('.')
      const message = item.msg || item.type || 'invalid'
      return field ? `${field}: ${message}` : message
    }).join(' · ')
  }
  return JSON.stringify(detail)
}

async function request(path, options = {}) {
  const { url, key, token, org } = read()
  // Empty URL = same-origin: in dev the Vite proxy forwards /api to the
  // platform (no CORS); a full URL addresses a remote deployment directly.
  const base = (url || '').replace(/\/$/, '')
  const anonymous = isPublic(path)
  if (!key && !token && !anonymous) {
    throw new Error('Set the API key or sign in from Settings.')
  }
  const headers = {
    ...(token ? { Authorization: `Bearer ${token}` } : key ? { 'X-API-Key': key } : {}),
    // Sent only when a person chose an organisation: a key's own org is the
    // answer for a key, and the API rejects the header when it disagrees.
    ...(org && token ? { 'X-Org': org } : {}),
    ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
    ...(options.headers || {}),
  }
  const init = { ...options, headers }
  const response = await fetch(`${base}${path}`, init)
  if (response.ok) return await response.json()

  // Unauthenticated routes must never be attempted against our own app.
  if (response.status === 401 && !anonymous) {
    let renewed = false
    try {
      await refreshSession()
      renewed = true
    } catch (error) {
      // refresh failed: credentials already cleared; surface the server's own
      // message so the UI can steer back to sign-in.
      throw new Error(String(error.message || error))
    }
    if (renewed) {
      const retry = await fetch(`${base}${path}`, init)
      if (retry.ok) return await retry.json()
      // The renewed token was rejected anyway (e.g. revoked server-side):
      // surface the new status, then let the caller fall back to sign-in.
      let message = `HTTP ${retry.status}`
      try {
        const body = await retry.json()
        message += `: ${describeError(body.detail)}`
      } catch { /* bounded */ }
      throw new Error(message)
    }
    // Renewable but we were not given a refresh token: fall through to the
    // generic 401 handling below (existing tokens are still valid).
  }

  let message = `HTTP ${response.status}`
  let detail = null
  try {
    const body = await response.json()
    // The reason codes travel on the error: the API answers with `{code, at}`
    // so the console can translate, and a screen that only had a message would
    // have to parse prose to find out which stage it was.
    detail = body.detail ?? null
    message += `: ${describeError(body.detail)}`
  } catch { /* bounded: keep the status as the reason */ }
  const error = new Error(message)
  error.status = response.status
  error.detail = detail
  throw error
}

/* Who is pressing this button.

   The session stores `email` when the person signed in with a password, but a
   session restored from one API key has no address — and an empty actor fails
   server-side validation with "String should have at least 1 character", which is
   what a promote clicked from such a session used to answer. The identity is a
   label for the audit row, so it falls back to the console, never to nothing. */
export function actorName() {
  const settings = read()
  return (settings.email || settings.user || settings.actor || 'console').trim() || 'console'
}

export const api = {
  settings: read,
  save,
  /* Switching is a reload, not a re-render: every screen holds data resolved for
     the previous organisation, and a console that keeps a cached projects list
     from the old one is worse than a second of white. */
  setOrg: (id) => save({ org: id || '' }),
  get: (path) => request(path),
  post: (path, body, options = {}) => request(path, {
    ...options,
    method: 'POST',
    body: JSON.stringify(body),
  }),
  patch: (path, body) => request(path, { method: 'PATCH', body: JSON.stringify(body) }),
  put: (path, body) => request(path, { method: 'PUT', body: JSON.stringify(body) }),
  postRaw: (path, raw) => request(path, { method: 'POST', body: raw, headers: { 'Content-Type': 'application/octet-stream' } }),
  del: (path, body) => request(path, { method: 'DELETE', ...(body ? { body: JSON.stringify(body) } : {}) }),
  // A document is fetched as bytes, not JSON, and the credential travels in a
  // header — which a plain <a href> cannot carry. Same origin, same credentials.
  getBlob: async (path) => {
    const settings = read()
    const headers = settings.key ? { 'X-API-Key': settings.key }
      : settings.token ? { Authorization: `Bearer ${settings.token}` } : {}
    const response = await fetch(`${settings.url}${path}`, { headers })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    return response.blob()
  },
}
