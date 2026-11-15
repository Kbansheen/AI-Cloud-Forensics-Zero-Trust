import React from 'react'

/**
 * Catches render errors in the subtree.
 *
 * Without this, a single bad reference inside any component unmounts the whole
 * React tree and the dashboard goes completely blank — no header, no panels, no
 * clue what went wrong. Wrapping each major region means the failure is
 * contained: the rest of the dashboard keeps working and the broken region says
 * what happened.
 *
 * Usage: <ErrorBoundary label="Event Trace"><TraceViewer/></ErrorBoundary>
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    // Surfaces in the browser console with the component stack, which is what
    // you need to fix it.
    console.error(`[${this.props.label || 'panel'}] render error:`, error, info)
  }

  componentDidUpdate(prev) {
    // Recover automatically when the caller mounts something new.
    if (this.state.error && prev.children !== this.props.children) {
      this.setState({ error: null })
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{
          margin: 12, padding: '12px 14px', borderRadius: 5,
          background: 'var(--z-red)14', border: '1px solid var(--z-red)55',
          fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.6,
        }}>
          <div style={{ color: 'var(--z-red)', fontWeight: 700, marginBottom: 4 }}>
            {this.props.label || 'This panel'} failed to render
          </div>
          <div style={{ color: '#e8eef8' }}>
            {String(this.state.error?.message || this.state.error)}
          </div>
          <div style={{ color: '#8ea3c0', marginTop: 6 }}>
            The rest of the dashboard is unaffected. Open the browser console for the
            component stack, and check the terminal running the frontend.
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
