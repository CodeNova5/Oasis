:root {
  /* ==========================================================================
     1. COLOR PALETTE (Midnight Navy & Periwinkle System)
     ========================================================================== */
  --bg-canvas: #131426;           /* Main application background */
  --bg-surface: #1b1d36;          /* Sidebar rail & elevated cards */
  --bg-surface-hover: #222544;    /* Table row hover & interactive surfaces */
  --bg-surface-subtle: #171930;   /* Expanded subprocess nested row background */
  --bg-tooltip: rgba(23, 25, 48, 0.94);

  /* Borders & Dividers */
  --border-subtle: rgba(255, 255, 255, 0.06);
  --border-strong: rgba(255, 255, 255, 0.12);
  --border-accent: rgba(115, 113, 252, 0.35);

  /* Brand & Telemetry Accents */
  --accent-primary: #7371fc;      /* Active nav pill, Download series, primary focus */
  --accent-primary-glow: rgba(115, 113, 252, 0.25);
  --accent-secondary: #5ce1e6;    /* Upload series (high contrast against periwinkle) */
  --accent-lavender: #a594f9;     /* Secondary highlights & icons */

  /* Semantic Status */
  --status-active: #3dd598;
  --status-warning: #ffb547;
  --status-danger: #ff5c75;

  /* Typography Colors */
  --text-primary: #ffffff;
  --text-secondary: #8e92b2;
  --text-muted: #56597a;

  /* ==========================================================================
     2. TYPOGRAPHY
     ========================================================================== */
  --font-sans: 'Plus Jakarta Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', monospace;

  --text-xs: 0.75rem;     /* 12px - table headers, chart axis ticks */
  --text-sm: 0.8125rem;   /* 13px - table cells, card labels */
  --text-base: 0.9375rem; /* 15px - section headings */
  --text-lg: 1.25rem;     /* 20px - page title */
  --text-kpi: 1.75rem;    /* 28px - summary card numbers */

  --weight-regular: 400;
  --weight-medium: 500;
  --weight-semibold: 600;
  --weight-bold: 700;

  /* ==========================================================================
     3. SPACING & GEOMETRY
     ========================================================================== */
  --sidebar-width: 72px;
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --space-7: 28px;

  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;      /* Standard card corner radius */
  --radius-window: 20px;  /* Outer frameless desktop shell radius */
  --radius-pill: 9999px;

  /* ==========================================================================
     4. ELEVATION & MOTION
     ========================================================================== */
  --shadow-card: 0 8px 24px rgba(8, 9, 20, 0.28);
  --shadow-tooltip: 0 10px 28px rgba(5, 6, 15, 0.55);
  --transition-fast: 150ms cubic-bezier(0.2, 0, 0, 1);
  --transition-smooth: 240ms cubic-bezier(0.2, 0, 0, 1);
}