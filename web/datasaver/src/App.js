import { html } from 'htm/preact';
import { useState } from 'preact/hooks';
import { mockData } from './mockData.js';

function MetricCard({ label, value, detail, tone = 'neutral' }) {
  return html`
    <article class="metric-card">
      <span class="eyebrow">${label}</span>
      <strong class=${`metric-value ${tone}`}>${value}</strong>
      <span class="metric-detail">${detail}</span>
    </article>
  `;
}

function ModeControl({ value, onChange }) {
  return html`
    <div class="mode-control" role="group" aria-label="Data Saver mode">
      ${['off', 'enforce'].map((mode) => html`
        <button
          class=${value === mode ? 'mode-button active' : 'mode-button'}
          type="button"
          aria-pressed=${value === mode}
          onClick=${() => onChange(mode)}
        >
          <span class=${`mode-dot ${mode}`}></span>
          ${mode === 'off' ? 'Off' : 'Enforce'}
        </button>
      `)}
    </div>
  `;
}

function DetectionTable() {
  return html`
    <section class="panel detections-panel">
      <div class="panel-heading">
        <div>
          <span class="eyebrow">Recent activity</span>
          <h2>Detection queue</h2>
        </div>
        <span class="panel-count">${mockData.detections.length} tracked</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Application</th><th>Category</th><th>Traffic</th><th>State</th></tr>
          </thead>
          <tbody>
            ${mockData.detections.map((detection) => html`
              <tr>
                <td>
                  <div class="process-cell">
                    <span class="process-icon">${detection.icon}</span>
                    <span><strong>${detection.name}</strong><small>${detection.path}</small></span>
                  </div>
                </td>
                <td><span class="category">${detection.category}</span></td>
                <td class="traffic">${detection.traffic}</td>
                <td><span class=${`state ${detection.stateTone}`}>${detection.state}</span></td>
              </tr>
            `)}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

export function App() {
  const [mode, setMode] = useState('off');

  return html`
    <div class="app-shell">
      <header class="page-header">
        <div class="title-block">
          <div class="breadcrumb"><span class="breadcrumb-mark">NG</span> Workspace <span>/</span> Data Saver</div>
          <h1>Data Saver</h1>
          <p>Keep background traffic visible and ready for policy control.</p>
        </div>
        <${ModeControl} value=${mode} onChange=${setMode} />
      </header>

      <section class=${mode === 'enforce' ? 'status-banner enforce' : 'status-banner'}>
        <span class="status-pulse"></span>
        <div><strong>${mode === 'enforce' ? 'Enforcement staged' : 'Data Saver is off'}</strong>
          <span>${mode === 'enforce' ? 'Automatic controls are ready for the next integration phase.' : 'Monitoring data remains available in the Activity workspace.'}</span>
        </div>
        <span class="status-tag">Preview</span>
      </section>

      <section class="metrics-grid">
        <${MetricCard} label="Network source" value=${mockData.network} detail="Current connection" />
        <${MetricCard} label="Processes observed" value=${mockData.processes} detail="Across this session" />
        <${MetricCard} label="Traffic deferred" value=${mockData.deferred} detail="Estimated this session" tone="accent" />
        <${MetricCard} label="Last refresh" value=${mockData.refresh} detail="Static preview data" />
      </section>

      <${DetectionTable} />

      <footer class="page-footer">
        <span class="footer-mark"></span>
        <span>Layout preview · Backend controls are not connected</span>
      </footer>
    </div>
  `;
}