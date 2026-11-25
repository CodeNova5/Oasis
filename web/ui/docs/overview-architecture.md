# Overview Page Specification & App Architecture

## 1. Folder & File Structure
To keep the Preact + `htm` application zero-build, modular, and clean inside a desktop WebView, organize the project as follows:

```text
app/
├── docs/
│   └── overview-architecture.md   # Blueprint & data contracts
└── ui/
    ├── index.html                 # Entry point loading fonts, tokens, layout, and app.js
    ├── css/
    │   ├── tokens.css             # Design system variables (colors, typography, spacing)
    │   └── layout.css             # App shell grid, cards, scrollbars, and responsive rules
    └── js/
        ├── vendor/
        │   ├── preact.module.js   # Local Preact bundle
        │   ├── htm.module.js      # Local htm bundle
        │   └── signals.module.js  # Local @preact/signals bundle
        ├── utils/
        │   └── formatters.js      # Auto-scaling formatBytes() & formatRate() helpers
        ├── state/
        │   └── overviewStore.js   # Reactive signals & native WebView bridge listener
        ├── components/
        │   ├── Sidebar.js         # Fixed left icon rail navigation
        │   ├── SummaryCard.js     # Reusable top KPI metric card
        │   ├── TrafficChart.js    # 60s rolling SVG spline chart with auto-scaled Y-axis
        │   └── ProcessTable.js    # Sortable process table with expandable subprocess rows
        └── app.js                 # Root shell assembling Sidebar + Overview workspace
```

---

## 2. App Shell & Layout Architecture
Because the right-side telemetry widgets (speedometer & noise spectrum) are excluded, the layout uses a streamlined **2-zone viewport-locked shell (`100vh`)**:

1. **Left Icon Rail (`72px` fixed width):**
   - Full-height vertical navigation bar (`--bg-surface`).
   - Top: App brand waveform logo.
   - Middle: Navigation icons (`Overview` active inside a `38px` circular `--accent-primary` pill; future tabs like `History`, `Rules`, `Settings`).
   - Bottom: Global monitoring pause/power toggle.
2. **Main Overview Workspace (`1fr` flexible width):**
   - Vertically structured into 4 flex/grid rows inside a padded container (`24px`–`28px`):
     - **Header Bar:** Page title (`Overview`) + live status indicator pill (`Monitoring Active`).
     - **Row 1 — 3 Summary Cards:** Equal 3-column grid (`grid-template-columns: repeat(3, 1fr)`).
     - **Row 2 — Real-Time Traffic Chart:** Full-width fixed-height card (`~250px`–`280px`) displaying the past 60 seconds.
     - **Row 3 — Process Table:** Flexible remaining height (`flex: 1; min-height: 0;`) with an internal scrollable table body (`overflow-y: auto`) so 30+ processes never break viewport height.

---

## 3. Overview Page Sections

### A. Top Summary Cards (3 Cards)
All numbers use `font-variant-numeric: tabular-nums` and auto-scale between `B`, `KB`, `MB`, and `GB`:
1. **Total Data Usage:** Cumulative combined traffic (`downloadBytes + uploadBytes`).
2. **Upload:** Cumulative outbound data (`uploadBytes`).
3. **Download:** Cumulative inbound data (`downloadBytes`).

### B. Real-Time Traffic (Past 1 Minute)
- **Window:** Rolling 60-second buffer (`60` data points at `1s` intervals).
- **Series:**
  - **Download Rate:** Primary periwinkle/indigo curve (`--accent-primary`) with soft vertical linear gradient fill.
  - **Upload Rate:** Secondary lavender/cyan curve (`--accent-secondary`) with subtle gradient fill.
- **Task Manager Auto-Scaling Y-Axis:**
  - Dynamically computes the maximum value across both series in the visible 60s buffer.
  - Rounds up to clean human steps (e.g., `100 KB/s`, `500 KB/s`, `1 MB/s`, `5 MB/s`, `10 MB/s`, `50 MB/s`) with 4 horizontal gridlines (`0`, `33%`, `66%`, `100%`).
- **Interactive Hover Scrubbing:**
  - Hovering over the chart snaps a vertical dashed crosshair to the nearest second and renders a floating glass tooltip showing exact timestamp, Download speed, and Upload speed.

### C. Process / Application Activity Table
- **Columns:**
  1. `Process / App Name` (Expand chevron `>` if `subprocesses.length > 0`, app icon, executable/friendly name)
  2. `PID` (Process ID; parent rows show main PID or subprocess count badge)
  3. `Download` (Live rate, auto-scaled `KB/s` / `MB/s`, highlighted in `--accent-primary`)
  4. `Upload` (Live rate, auto-scaled `KB/s` / `MB/s`, highlighted in `--accent-secondary`)
  5. `Total Data` (Cumulative bytes consumed, auto-scaled `MB` / `GB`)
- **Subprocess Accordion Behavior:**
  - Clicking a parent row's chevron toggles `expandedIds` in state.
  - Child rows render directly beneath the parent with `28px` left indentation, muted tree connector styling, individual PIDs, and per-subprocess throughput.
- **Sorting:** Clicking column headers (`Download`, `Upload`, `Total Data`, `Name`) sorts top-level processes while keeping expanded children attached beneath their parent.

---

## 4. Backend Telemetry Payload Contract
The page calls the native bridge method `overview.status` once per second over the existing WebView2 message bridge. When the bridge is unavailable (a plain browser, or a build without the method), `overviewStore.js` falls back to locally generated preview data. The reply's `result` uses this shape:

```json
{
  "summary": {
    "totalBytes": 6291456000,
    "uploadBytes": 1258291200,
    "downloadBytes": 5033164800
  },
  "realtime": {
    "timestamp": "11:41:05",
    "downBps": 1540000,
    "upBps": 180000
  },
  "processes": [
    {
      "id": "chrome.exe-1024",
      "name": "chrome.exe",
      "pid": 1024,
      "downBps": 1562500,
      "upBps": 100000,
      "totalBytes": 1288490188,
      "subprocesses": [
        {
          "id": "chrome.exe-2048",
          "name": "chrome.exe (GPU Process)",
          "pid": 2048,
          "downBps": 120000,
          "upBps": 25000,
          "totalBytes": 210000000
        }
      ]
    }
  ]
}
```