import { html } from 'htm/preact';
import { useState } from 'preact/hooks';

function ProofPill({ label, value }) {
  return html`
    <div class="proof-pill">
      <span class="proof-label">${label}</span>
      <strong class="proof-value">${value}</strong>
    </div>
  `;
}

export function App() {
  const [renders, setRenders] = useState(0);

  return html`
    <div class="landing">
      <div class="landing-glow" aria-hidden="true"></div>

      <header class="landing-header">
        <span class="brand-mark">OA</span>
        <span class="brand-name">Oasis</span>
        <span class="brand-tag">Frontend preview</span>
      </header>

      <main class="hero">
        <div class="stack-badge" role="status">
          <span class="stack-dot"></span>
          PREACT + HTM ONLINE
        </div>

        <h1>PREACT + HTM works</h1>
        <p class="hero-copy">
          This screen is rendered by the isolated <code>web/ui</code> bundle:
          Preact components written with HTM template literals, bundled by esbuild
          and hosted inside the native shell. No Qt widgets are drawn here.
        </p>

        <div class="hero-actions">
          <button
            class="primary-action"
            type="button"
            onClick=${() => setRenders(renders + 1)}
          >
            ${renders === 0 ? 'Click to prove interactivity' : `Re-rendered ${renders} time${renders === 1 ? '' : 's'}`}
          </button>
          <span class="action-hint">State and event handlers are live.</span>
        </div>

        <section class="proof-grid" aria-label="Bundle facts">
          <${ProofPill} label="Renderer" value="Preact 10" />
          <${ProofPill} label="Templating" value="HTM" />
          <${ProofPill} label="Bundler" value="esbuild" />
          <${ProofPill} label="Host" value="WebView2" />
        </section>
      </main>

      <footer class="landing-footer">
        <span class="footer-dot"></span>
        Standalone UI bundle · no backend calls, no Qt widget dependencies
      </footer>
    </div>
  `;
}
