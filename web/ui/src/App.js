import { useEffect, useState } from 'preact/hooks';
import { html } from 'htm/preact';
import { Sidebar } from './components/Sidebar.js';
import { SummaryCard } from './components/SummaryCard.js';
import { TrafficChart } from './components/TrafficChart.js';
import { ProcessTable } from './components/ProcessTable.js';
import { advanceTelemetry, createInitialTelemetry } from './state/overviewStore.js';
import { formatBytes } from './utils/formatters.js';

export function App() {
  const [telemetry, setTelemetry] = useState(createInitialTelemetry);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (paused) return undefined;
    const timer = setInterval(() => setTelemetry(advanceTelemetry), 1000);
    return () => clearInterval(timer);
  }, [paused]);

  const total = formatBytes(telemetry.summary.totalBytes);
  const download = formatBytes(telemetry.summary.downloadBytes);
  const upload = formatBytes(telemetry.summary.uploadBytes);

  return html`
    <div class="app-shell">
      <${Sidebar} paused=${paused} onTogglePause=${() => setPaused((value) => !value)} />

      <main class="workspace">
        <header class="workspace-header">
          <h1 class="workspace-title">Overview</h1>
          <span class=${`status-pill${paused ? ' is-paused' : ''}`} role="status">
            <span class="status-dot"></span>
            ${paused ? 'Monitoring Paused' : 'Monitoring Active'}
          </span>
        </header>

        <section class="summary-grid" aria-label="Session totals">
          <${SummaryCard}
            label="Total Data Usage"
            icon="gauge"
            tint="#a594f9"
            value=${total.value}
            unit=${total.unit}
            caption="Session Total"
          />
          <${SummaryCard}
            label="Download"
            icon="down"
            tint="#7371fc"
            value=${download.value}
            unit=${download.unit}
            caption="Total Received"
          />
          <${SummaryCard}
            label="Upload"
            icon="up"
            tint="#5ce1e6"
            value=${upload.value}
            unit=${upload.unit}
            caption="Total Sent"
          />
        </section>

        <${TrafficChart} history=${telemetry.history} />

        <${ProcessTable} processes=${telemetry.processes} processCount=${telemetry.processCount} />
      </main>
    </div>
  `;
}
