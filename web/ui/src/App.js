import { useEffect, useRef, useState } from 'preact/hooks';
import { html } from 'htm/preact';
import { Sidebar } from './components/Sidebar.js';
import { SummaryCard } from './components/SummaryCard.js';
import { TrafficChart } from './components/TrafficChart.js';
import { ProcessTable } from './components/ProcessTable.js';
import {
  advanceTelemetry,
  applyOverviewPayload,
  collectIconKeys,
  createEmptyTelemetry,
  createInitialTelemetry,
} from './state/overviewStore.js';
import { isAvailable, request } from './bridge/client.js';
import { formatBytes } from './utils/formatters.js';

export function App() {
  const nativeAvailable = isAvailable();
  // Native payloads are the real source; the local generator only runs in a
  // plain browser or if the running desktop build lacks overview.status.
  const [bridgeOk, setBridgeOk] = useState(nativeAvailable);
  const [telemetry, setTelemetry] = useState(
    nativeAvailable ? createEmptyTelemetry : createInitialTelemetry,
  );
  const [paused, setPaused] = useState(false);
  const [icons, setIcons] = useState({});
  const requestedIcons = useRef(new Set());

  useEffect(() => {
    if (paused) return undefined;

    if (bridgeOk) {
      let cancelled = false;
      let inFlight = false;

      // Icons travel outside the one-second status: each executable is asked
      // for once and its data URI is kept for the life of the page.
      const requestIcons = (payload) => {
        for (const key of collectIconKeys(payload?.processes)) {
          if (requestedIcons.current.has(key)) continue;
          requestedIcons.current.add(key);

          request('overview.icon', { name: key }, { timeoutMs: 5000 })
            .then((result) => {
              const icon = result?.icon;
              if (typeof icon !== 'string' || !icon.startsWith('data:image/')) {
                requestedIcons.current.delete(key);
                return;
              }
              setIcons((previous) => (
                previous[key] === icon ? previous : { ...previous, [key]: icon }
              ));
            })
            .catch((error) => {
              requestedIcons.current.delete(key);
              console.warn(`overview.icon unavailable for ${key}.`, error);
            });
        }
      };

      const poll = async () => {
        if (inFlight) return;
        inFlight = true;
        try {
          const payload = await request('overview.status');
          if (!cancelled) {
            setTelemetry((previous) => applyOverviewPayload(previous, payload));
            requestIcons(payload);
          }
        } catch (error) {
          if (!cancelled) {
            console.warn('overview.status unavailable, using preview data.', error);
            setBridgeOk(false);
            setTelemetry((previous) => advanceTelemetry(previous));
          }
        } finally {
          inFlight = false;
        }
      };

      poll();
      const timer = setInterval(poll, 1000);
      return () => {
        cancelled = true;
        clearInterval(timer);
      };
    }

    const timer = setInterval(() => setTelemetry(advanceTelemetry), 1000);
    return () => clearInterval(timer);
  }, [paused, bridgeOk]);

  const total = formatBytes(telemetry.summary.totalBytes);
  const download = formatBytes(telemetry.summary.downloadBytes);
  const upload = formatBytes(telemetry.summary.uploadBytes);

  return html`
    <div class="app-shell">
      <${Sidebar} paused=${paused} onTogglePause=${() => setPaused((value) => !value)} />

      <main class="workspace">
        <header class="workspace-header">
          <h1 class="workspace-title">Overview</h1>
          <span
            class=${`status-pill${paused ? ' is-paused' : ''}${!bridgeOk ? ' is-preview' : ''}`}
            role="status"
            title=${bridgeOk ? 'Reading live data from the native service' : 'The native overview service is unavailable; showing preview data'}
          >
            <span class="status-dot"></span>
            ${paused ? 'Monitoring Paused' : bridgeOk ? 'Monitoring Active' : 'Preview Data'}
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

        <${ProcessTable}
          processes=${telemetry.processes}
          processCount=${telemetry.processCount}
          icons=${icons}
        />
      </main>
    </div>
  `;
}
