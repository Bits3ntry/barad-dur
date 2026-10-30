import React, { useEffect, useState } from 'react'
import { api } from './api'

export default function Settings({ onClose }) {
  const [form, setForm] = useState(api.settings())

  function save(event) {
    event.preventDefault()
    api.save({ url: form.url.trim(), key: form.key.trim() })
    onClose(true)
  }

  return (
    <div className="card">
      <h3>Connection</h3>
      <form onSubmit={save}>
        <label>
          Platform URL
          <input
            value={form.url}
            onChange={(e) => setForm({ ...form, url: e.target.value })}
            placeholder="http://127.0.0.1:8090"
            autoComplete="off"
          />
        </label>
        <label>
          API key
          <input
            value={form.key}
            onChange={(e) => setForm({ ...form, key: e.target.value })}
            placeholder="raw key (stored in this browser's localStorage)"
            autoComplete="off"
          />
        </label>
        <button type="submit">save</button>
      </form>
      <p className="hint">The key stays local to this browser and rides the X-API-Key header.</p>
    </div>
  )
}
