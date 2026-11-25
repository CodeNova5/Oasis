/**
 * Overview telemetry source.
 *
 * The native side is expected to push the payload documented in
 * docs/overview-architecture.md (summary / realtime / processes). That bridge
 * method does not exist yet, so this module generates the same shape locally:
 * one tick per second advances a rolling 60-point history, accumulates session
 * totals and drifts the per-process rates. Swapping in real push events later
 * only requires replacing the producer, not the components.
 */

const MB = 1024 * 1024;
const GB = 1024 * MB;
const HISTORY_LENGTH = 60;

const BLUEPRINTS = [
  {
    key: 'chrome',
    name: 'Google Chrome',
    pid: 1024,
    monogram: 'Ch',
    tint: '#5a8dee',
    down: 5.2,
    up: 0.8,
    total: 1.2 * GB,
    children: [
      { key: 'chrome-gpu', name: 'Chrome Helper (GPU)', pid: 2048, down: 1.4, up: 0.1, total: 210 * MB },
      { key: 'chrome-renderer', name: 'Chrome Helper (Renderer)', pid: 3312, down: 0.9, up: 0.05, total: 180 * MB },
    ],
  },
  { key: 'spotify', name: 'Spotify.exe', pid: 2111, monogram: 'Sp', tint: '#3dd598', down: 1.4, up: 0.1, total: 300 * MB },
  { key: 'svchost', name: 'svchost.exe', pid: 890, monogram: 'Sv', tint: '#8e92b2', down: 4.2, up: 0.2, total: 4.5 * GB },
  { key: 'discord', name: 'discord.exe', pid: 3320, monogram: 'Di', tint: '#7371fc', down: 0.9, up: 0.3, total: 150 * MB },
  { key: 'steam', name: 'steam.exe', pid: 4560, monogram: 'St', tint: '#5ce1e6', down: 0.5, up: 0.1, total: 95 * MB },
  { key: 'edge', name: 'msedge.exe', pid: 5120, monogram: 'Ed', tint: '#4cc3e0', down: 2.4, up: 0.2, total: 2.2 * GB },
  { key: 'onedrive', name: 'OneDrive.exe', pid: 1840, monogram: 'Od', tint: '#4a7fdb', down: 1.6, up: 1.6, total: 3.1 * GB },
  { key: 'explorer', name: 'explorer.exe', pid: 6020, monogram: 'Ex', tint: '#ffb547', down: 0.15, up: 0.02, total: 48 * MB },
  { key: 'teams', name: 'Teams.exe', pid: 7100, monogram: 'Te', tint: '#a594f9', down: 0.8, up: 0.4, total: 1.4 * GB },
  { key: 'code', name: 'Code.exe', pid: 8040, monogram: 'Co', tint: '#3ba7e8', down: 0.5, up: 0.1, total: 820 * MB },
  { key: 'slack', name: 'slack.exe', pid: 4290, monogram: 'Sl', tint: '#ff5c75', down: 0.3, up: 0.08, total: 390 * MB },
  { key: 'dropbox', name: 'Dropbox.exe', pid: 2680, monogram: 'Db', tint: '#5a8dee', down: 2.0, up: 0.6, total: 5.4 * GB },
  { key: 'defender', name: 'MsMpEng.exe', pid: 3310, monogram: 'Md', tint: '#3dd598', down: 0.2, up: 0.1, total: 640 * MB },
  { key: 'battlenet', name: 'Battle.net.exe', pid: 9210, monogram: 'Bn', tint: '#6f7cff', down: 0.6, up: 0.02, total: 2.8 * GB },
  { key: 'zoom', name: 'Zoom.exe', pid: 7440, monogram: 'Zo', tint: '#4cc3e0', down: 1.1, up: 0.7, total: 1.1 * GB },
  { key: 'firefox', name: 'firefox.exe', pid: 3660, monogram: 'Ff', tint: '#ff9e64', down: 1.7, up: 0.3, total: 940 * MB },
  {
    key: 'steamwebhelper',
    name: 'steamwebhelper.exe',
    pid: 4572,
    monogram: 'Sw',
    tint: '#5ce1e6',
    down: 0.35,
    up: 0.03,
    total: 260 * MB,
    children: [
      { key: 'steam-cef', name: 'steamwebhelper (CEF)', pid: 4588, down: 0.2, up: 0.02, total: 140 * MB },
    ],
  },
  { key: 'gog', name: 'GalaxyClient.exe', pid: 9480, monogram: 'Gg', tint: '#a594f9', down: 0.25, up: 0.01, total: 420 * MB },
];

// Aggregate base throughput, children included, keeps the chart consistent with
// the process rows visible below it.
const TOTAL_BASE_DOWN = BLUEPRINTS.reduce(
  (sum, process) => sum + process.down + (process.children || []).reduce((childSum, child) => childSum + child.down, 0),
  0,
);
const TOTAL_BASE_UP = BLUEPRINTS.reduce(
  (sum, process) => sum + process.up + (process.children || []).reduce((childSum, child) => childSum + child.up, 0),
  0,
);

/**
 * Gentle traffic envelope: two out-of-phase sine waves give the chart the
 * rolling peak-and-taper shape of real traffic instead of flat noise.
 */
function wave(timestamp, phase = 0) {
  const seconds = timestamp / 1000;
  const value = 0.48 + 0.3 * Math.sin(seconds / 11 + phase) + 0.16 * Math.sin(seconds / 4.3 + phase * 1.7);
  return Math.min(1.15, Math.max(0.08, value));
}

function rate(megabytesPerSecond, timestamp, phase, jitter = 1) {
  return Math.max(0, megabytesPerSecond * MB * wave(timestamp, phase) * jitter);
}

function instantiateProcess(blueprint, timestamp) {
  return {
    id: `${blueprint.key}-${blueprint.pid}`,
    name: blueprint.name,
    pid: blueprint.pid,
    tint: blueprint.tint,
    downBps: rate(blueprint.down, timestamp, 0),
    upBps: rate(blueprint.up, timestamp, 1.4),
    totalBytes: blueprint.total,
    baseDown: blueprint.down,
    baseUp: blueprint.up,
    subprocesses: (blueprint.children || []).map((child, index) => ({
      id: `${child.key}-${child.pid}`,
      name: child.name,
      pid: child.pid,
      tint: blueprint.tint,
      downBps: rate(child.down, timestamp, 0.4 + index * 0.2),
      upBps: rate(child.up, timestamp, 1.8 + index * 0.2),
      totalBytes: child.total,
      baseDown: child.down,
      baseUp: child.up,
    })),
  };
}

export function createInitialTelemetry(now = Date.now()) {
  const processes = BLUEPRINTS.map((blueprint) => instantiateProcess(blueprint, now));

  const history = [];
  for (let index = 0; index < HISTORY_LENGTH; index += 1) {
    const timestamp = now - (HISTORY_LENGTH - 1 - index) * 1000;
    history.push({
      time: timestamp,
      downBps: TOTAL_BASE_DOWN * MB * wave(timestamp, 0),
      upBps: TOTAL_BASE_UP * MB * wave(timestamp, 1.4),
    });
  }

  const summary = {
    totalBytes: 6.2 * GB,
    uploadBytes: 1.2 * GB,
    downloadBytes: 5.0 * GB,
  };

  return {
    summary,
    history,
    processes,
    processCount: countProcesses(processes),
  };
}

export function advanceTelemetry(previous, now = Date.now()) {
  const processes = previous.processes.map((process) => {
    const downBps = rate(process.baseDown, now, 0, 0.94 + Math.random() * 0.12);
    const upBps = rate(process.baseUp, now, 1.4, 0.94 + Math.random() * 0.12);

    return {
      ...process,
      downBps,
      upBps,
      totalBytes: process.totalBytes + downBps + upBps,
      subprocesses: process.subprocesses.map((child) => {
        const childDown = rate(child.baseDown, now, 0.4, 0.94 + Math.random() * 0.12);
        const childUp = rate(child.baseUp, now, 1.8, 0.94 + Math.random() * 0.12);
        return {
          ...child,
          downBps: childDown,
          upBps: childUp,
          totalBytes: child.totalBytes + childDown + childUp,
        };
      }),
    };
  });

  const liveDown = processes.reduce(
    (sum, process) => sum + process.downBps + process.subprocesses.reduce((sub, child) => sub + child.downBps, 0),
    0,
  );
  const liveUp = processes.reduce(
    (sum, process) => sum + process.upBps + process.subprocesses.reduce((sub, child) => sub + child.upBps, 0),
    0,
  );

  const summary = {
    downloadBytes: previous.summary.downloadBytes + liveDown,
    uploadBytes: previous.summary.uploadBytes + liveUp,
    totalBytes: previous.summary.totalBytes + liveDown + liveUp,
  };

  return {
    summary,
    history: [...previous.history.slice(1), { time: now, downBps: liveDown, upBps: liveUp }],
    processes,
    processCount: countProcesses(processes),
  };
}

export function countProcesses(processes) {
  return processes.reduce((sum, process) => sum + 1 + process.subprocesses.length, 0);
}

/* ==========================================================================
   Native bridge payloads
   ==========================================================================
   `overview.status` returns the contract in docs/overview-architecture.md.
   These helpers normalise it for the components: missing values become zeroes,
   and each row gets the icon or fallback tint the table needs. */

const PREVIEW_TINTS = [
  '#5a8dee', '#3dd598', '#8e92b2', '#7371fc', '#5ce1e6',
  '#4cc3e0', '#ffb547', '#a594f9', '#ff5c75', '#ff9e64',
];

function tintFor(name) {
  let hash = 0;
  for (let index = 0; index < name.length; index += 1) {
    hash = (hash * 31 + name.charCodeAt(index)) >>> 0;
  }
  return PREVIEW_TINTS[hash % PREVIEW_TINTS.length];
}

function normalizeProcess(row, tint) {
  const name = String(row?.name || 'Unknown process');
  const subprocesses = Array.isArray(row?.subprocesses) ? row.subprocesses : [];
  const icon = typeof row?.icon === 'string' && /^data:image\/[a-z0-9.+-]+;base64,/i.test(row.icon)
    ? row.icon
    : null;

  return {
    id: String(row?.id || `${name}-${row?.pid || 0}`),
    name,
    pid: Number(row?.pid) || 0,
    downBps: Number(row?.downBps) || 0,
    upBps: Number(row?.upBps) || 0,
    totalBytes: Number(row?.totalBytes) || 0,
    icon,
    tint,
    subprocesses: subprocesses.map((child) => normalizeProcess(child, tint)),
  };
}

function timestampToMs(timestamp, fallback) {
  const match = typeof timestamp === 'string'
    ? /^(\d{1,2}):(\d{2}):(\d{2})$/.exec(timestamp.trim())
    : null;
  if (!match) return fallback;

  const date = new Date(fallback);
  date.setHours(Number(match[1]), Number(match[2]), Number(match[3]), 0);
  return date.getTime();
}

/** Sixty empty points keep the chart's rolling window shape before the first beat. */
export function createEmptyTelemetry(now = Date.now()) {
  const history = [];
  for (let index = 0; index < HISTORY_LENGTH; index += 1) {
    history.push({ time: now - (HISTORY_LENGTH - 1 - index) * 1000, downBps: 0, upBps: 0 });
  }

  return {
    summary: { totalBytes: 0, uploadBytes: 0, downloadBytes: 0 },
    history,
    processes: [],
    processCount: 0,
  };
}

export function applyOverviewPayload(previous, payload, now = Date.now()) {
  const summaryPayload = payload?.summary || {};
  const realtime = payload?.realtime || {};
  const rows = Array.isArray(payload?.processes) ? payload.processes : [];

  const processes = rows.map((row) => normalizeProcess(row, tintFor(String(row?.name || ''))));
  const point = {
    time: timestampToMs(realtime.timestamp, now),
    downBps: Number(realtime.downBps) || 0,
    upBps: Number(realtime.upBps) || 0,
  };

  return {
    summary: {
      totalBytes: Number(summaryPayload.totalBytes) || 0,
      uploadBytes: Number(summaryPayload.uploadBytes) || 0,
      downloadBytes: Number(summaryPayload.downloadBytes) || 0,
    },
    history: previous.history.length
      ? [...previous.history.slice(1), point]
      : [point],
    processes,
    processCount: countProcesses(processes),
  };
}
