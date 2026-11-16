import React from 'react'

/* One screen's render error must not empty the console.

   React unmounts the whole tree when a component throws during render, and until
   now that meant a blank page with no address to reload: the shell, the sidebar
   and the error were all gone together. This boundary keeps the failure inside
   the screen and says what happened, because "the console is blank" is a bug
   report nobody can act on. */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    // Kept in the console on purpose: the message is for the person fixing it,
    // the panel below is for the person who hit it.
    // eslint-disable-next-line no-console
    console.error('screen crashed', error, info)
  }

  render() {
    if (!this.state.error) return this.props.children
    const message = String(this.state.error?.message || this.state.error)
    return (
      <div className="crash">
        <h2>Esta pantalla no pudo dibujarse</h2>
        <p className="muted">
          El resto de la consola sigue funcionando. El error queda en la consola del navegador.
        </p>
        <pre>{message}</pre>
        <div className="row" style={{ gap: 8 }}>
          <button className="btn-primary" onClick={() => this.setState({ error: null })}>
            Reintentar
          </button>
          <button className="btn-ghost" onClick={() => window.location.reload()}>
            Recargar la consola
          </button>
        </div>
      </div>
    )
  }
}
