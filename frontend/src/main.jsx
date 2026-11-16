import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { I18nProvider } from './i18n'
import './styles.css'
import './components-discovery.css'

/* The provider wraps the whole tree, so every screen — including the sign-in
   gate, which renders before any session exists — reads the same language. */
createRoot(document.getElementById('root')).render(
  <I18nProvider>
    <App />
  </I18nProvider>,
)
