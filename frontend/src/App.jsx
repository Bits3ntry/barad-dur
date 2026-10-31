import React, { useEffect, useState } from 'react'
import Audit from './Audit'
import Dashboard from './Dashboard'
import Gates from './Gates'
import Grants from './Grants'
import Licenses from './Licenses'
import Lifecycle from './Lifecycle'
import Members from './Members'
import Assets from './Assets'
import Components from './Components'
import Findings from './Findings'
import Pentest from './Pentest'
import Pipelines from './Pipelines'
import Settings from './Settings'
import { api } from './api'

const TABS = ['dashboard', 'findings', 'gates', 'licenses', 'pentest', 'grants', 'audit', 'remediation', 'members', 'assets', 'components', 'pipelines']

export default function App() {
  const [tab, setTab] = useState('dashboard')
  const [projects, setProjects] = useState([])
  const [projectsError, setProjectsError] = useState('')
  const [showingSettings, setShowingSettings] = useState(true)
  const [, forceRender] = useState(0)

  useEffect(() => {
    const { key } = api.settings()
    setShowingSettings(!key)
  }, [])

  useEffect(() => {
    setProjectsError('')
    api.get('/api/v1/projects')
      .then((data) => setProjects(data.data))
      .catch((error) => setProjectsError(String(error.message || error)))
  }, [showingSettings === false])

  return (
    <div className="app">
      <header>
        <h1>BARAD-DÛR <span className="subtitle">vulnerability management</span></h1>
        <nav>
          {TABS.map((name) => (
            <button key={name} className={`tab ${tab === name ? 'active' : ''}`} onClick={() => setTab(name)}>
              {name}
            </button>
          ))}
          <button className="tab" onClick={() => setShowingSettings(true)}>settings</button>
        </nav>
      </header>
      {projectsError && !showingSettings && (
        <p className="error">{projectsError} — check settings.</p>
      )}
      {showingSettings && <Settings onClose={() => setShowingSettings(false)} />}
      {!showingSettings && (
        <main>
          {tab === 'dashboard' && <Dashboard projects={projects} />}
          {tab === 'findings' && <Findings projects={projects} />}
          {tab === 'gates' && <Gates projects={projects} />}
          {tab === 'licenses' && <Licenses projects={projects} />}
          {tab === 'pentest' && <Pentest projects={projects} />}
          {tab === 'grants' && <Grants />}
          {tab === 'audit' && <Audit />}
          {tab === 'remediation' && <Lifecycle />}
          {tab === 'members' && <Members />}
          {tab === 'assets' && <Assets />}
          {tab === 'components' && <Components projects={projects} />}
          {tab === 'pipelines' && <Pipelines />}
        </main>
      )}
    </div>
  )
}
