import { Component, type ReactNode } from "react";

/**
 * Swallows render errors from a (decorative) subtree so a failure there — e.g.
 * WebGL/three.js refusing to start — can never blank the whole app.
 */
export default class SafeBoundary extends Component<
  { children: ReactNode; fallback?: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch() {
    /* decorative subtree — intentionally silent */
  }
  render() {
    if (this.state.failed) return this.props.fallback ?? null;
    return this.props.children;
  }
}
