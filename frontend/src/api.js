const DEFAULTS = { url: '', key: '' }

function read() {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem('barad.ui') || '{}') }
  } catch {
    return { ...DEFAULTS }
  }
}

function save(settings) {
  localStorage.setItem('barad.ui', JSON.stringify(settings))
}

async function request(path, options = {}) {
  const { url, key } = read()
  // Empty URL = same-origin: in dev the Vite proxy forwards /api to the
  // platform (no CORS); a full URL addresses a remote deployment directly.
  const base = (url || '').replace(/\/$/, '')
  if (!key) throw new Error('Set the API key in Settings.')
  const response = await fetch(`${base}${path}`, {
    ...options,
    headers: {
      'X-API-Key': key,
      ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...(options.headers || {}),
    },
  })
  if (!response.ok) {
    let message = `HTTP ${response.status}`
    try {
      const body = await response.json()
      message += `: ${typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)}`
    } catch { /* bounded: keep the status as the reason */ }
    throw new Error(message)
  }
  return response.json()
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
