const DEFAULTS = { url: '', key: '', token: '', refresh_token: '', expires_at: '' }

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

async function request(path, options = {}) {
  const { url, key, token } = read()
  // Empty URL = same-origin: in dev the Vite proxy forwards /api to the
  // platform (no CORS); a full URL addresses a remote deployment directly.
  const base = (url || '').replace(/\/$/, '')
  const anonymous = isPublic(path)
  if (!key && !token && !anonymous) {
    throw new Error('Set the API key or sign in from Settings.')
  }
  const headers = {
    ...(token ? { Authorization: `Bearer ${token}` } : key ? { 'X-API-Key': key } : {}),
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
        message += `: ${typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)}`
      } catch { /* bounded */ }
      throw new Error(message)
    }
    // Renewable but we were not given a refresh token: fall through to the
    // generic 401 handling below (existing tokens are still valid).
  }

  let message = `HTTP ${response.status}`
  try {
    const body = await response.json()
    message += `: ${typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)}`
  } catch { /* bounded: keep the status as the reason */ }
  throw new Error(message)
}

export const api = {
  settings: read,
  save,
  get: (path) => request(path),
  post: (path, body) => request(path, { method: 'POST', body: JSON.stringify(body) }),
  patch: (path, body) => request(path, { method: 'PATCH', body: JSON.stringify(body) }),
  postRaw: (path, raw) => request(path, { method: 'POST', body: raw, headers: { 'Content-Type': 'application/octet-stream' } }),
  del: (path, body) => request(path, { method: 'DELETE', ...(body ? { body: JSON.stringify(body) } : {}) }),
}
