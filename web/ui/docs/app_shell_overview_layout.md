*,
*::before,
*::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html,
body {
  height: 100%;
  background-color: var(--bg-canvas);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 16px;
  -webkit-font-smoothing: antialiased;
  overflow: hidden; /* Viewport-locked desktop app feel */
}

/* Numeric stability for live updating speeds and byte counters */
.tabular-nums {
  font-variant-numeric: tabular-nums;
}

/* ==========================================================================
   APP SHELL (Left Icon Rail + Overview Workspace)
   ========================================================================== */
.app-shell {
  display: grid;
  grid-template-columns: var(--sidebar-width) 1fr;
  height: 100vh;
  width: 100vw;
  background-color: var(--bg-canvas);
}

.sidebar-rail {
  background-color: var(--bg-surface);
  border-right: 1px solid var(--border-subtle);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: space-between;
  padding: var(--space-6) 0;
  user-select: none;
}

.sidebar-nav {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.nav-btn {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-pill);
  border: none;
  background: transparent;
  color: var(--text-muted);
  display: grid;
  place-items: center;
  cursor: pointer;
  transition: background-color var(--transition-fast), color var(--transition-fast);
}

.nav-btn:hover {
  color: var(--text-primary);
  background-color: var(--bg-surface-hover);
}

.nav-btn.is-active {
  background-color: var(--accent-primary);
  color: var(--text-primary);
  box-shadow: 0 4px 16px var(--accent-primary-glow);
}

/* ==========================================================================
   MAIN OVERVIEW WORKSPACE
   ========================================================================== */
.workspace {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
  padding: var(--space-6) var(--space-7);
  height: 100vh;
  min-width: 0;
  overflow: hidden;
}

.workspace-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}

.workspace-title {
  font-size: var(--text-lg);
  font-weight: var(--weight-semibold);
  letter-spacing: -0.01em;
}

/* Top 3 Summary Cards Grid */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--space-5);
  flex-shrink: 0;
}

.card {
  background-color: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  padding: var(--space-5);
  box-shadow: var(--shadow-card);
}

.kpi-card {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.kpi-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  color: var(--text-secondary);
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
}

.kpi-value {
  font-size: var(--text-kpi);
  font-weight: var(--weight-bold);
  letter-spacing: -0.02em;
  display: flex;
  align-items: baseline;
  gap: var(--space-2);
}

.kpi-unit {
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
  color: var(--text-secondary);
}

/* Middle Real-Time Traffic Chart Card */
.chart-card {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  height: 260px;
  flex-shrink: 0;
}

.chart-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.chart-legend {
  display: flex;
  align-items: center;
  gap: var(--space-5);
  font-size: var(--text-xs);
  color: var(--text-secondary);
}

.legend-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: var(--radius-pill);
  margin-right: var(--space-2);
}

/* Bottom Expandable Process Table Card */
.table-card {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0; /* Allows internal scrolling inside flex column */
  padding: 0;
  overflow: hidden;
}

.table-scroll {
  flex: 1;
  overflow-y: auto;
}

.process-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: var(--text-sm);
}

.process-table thead th {
  position: sticky;
  top: 0;
  z-index: 2;
  background-color: var(--bg-surface);
  color: var(--text-secondary);
  font-size: var(--text-xs);
  font-weight: var(--weight-medium);
  padding: var(--space-4) var(--space-5);
  border-bottom: 1px solid var(--border-subtle);
  cursor: pointer;
  user-select: none;
}

.process-table tbody tr {
  border-bottom: 1px solid var(--border-subtle);
  transition: background-color var(--transition-fast);
}

.process-table tbody tr:hover {
  background-color: var(--bg-surface-hover);
}

.process-table tbody tr.is-subprocess {
  background-color: var(--bg-surface-subtle);
}

.process-table td {
  padding: var(--space-3) var(--space-5);
  white-space: nowrap;
}

/* Custom Slim Scrollbar */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-track {
  background: transparent;
}

::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.12);
  border-radius: var(--radius-pill);
}

::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.22);
}