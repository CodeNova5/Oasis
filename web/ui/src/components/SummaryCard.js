import { html } from 'htm/preact';

const icons = {
  gauge: html`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M4.9 19a9 9 0 1 1 14.2 0" /><path d="M12 13l4-4" />
  </svg>`,
  down: html`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M12 4v16" /><path d="M6 14l6 6 6-6" />
  </svg>`,
  up: html`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M12 20V4" /><path d="M6 10l6-6 6 6" />
  </svg>`,
};

export function SummaryCard({ label, icon, value, unit, caption, tint }) {
  return html`
    <article class="card kpi-card">
      <header class="kpi-header">
        <span class="kpi-label">${label}</span>
        <span class="kpi-icon" style=${{ color: tint, backgroundColor: `${tint}1f` }}>
          ${icons[icon]}
        </span>
      </header>
      <div class="kpi-value tabular-nums">
        <span>${value}</span>
        <span class="kpi-unit">${unit}</span>
      </div>
      <span class="kpi-caption">${caption}</span>
    </article>
  `;
}
