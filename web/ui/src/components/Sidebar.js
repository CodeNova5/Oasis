import { html } from 'htm/preact';

function Icon({ children, size = 20 }) {
  return html`
    <svg
      width=${size}
      height=${size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.7"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      ${children}
    </svg>
  `;
}

const icons = {
  overview: html`<${Icon}>
    <path d="M3 12h3l2.5-6 4 12 3-6H21" />
  <//>`,
  history: html`<${Icon}>
    <path d="M4 20V11" />
    <path d="M10 20V4" />
    <path d="M16 20v-6" />
    <path d="M22 20H2" />
  <//>`,
  rules: html`<${Icon}>
    <path d="M4 7h10" /><circle cx="17" cy="7" r="3" />
    <path d="M20 17H10" /><circle cx="7" cy="17" r="3" />
  <//>`,
  activity: html`<${Icon}>
    <rect x="4" y="3" width="16" height="18" rx="2" />
    <path d="M8 8h8M8 12h8M8 16h5" />
  <//>`,
  settings: html`<${Icon}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
  <//>`,
  plugins: html`<${Icon}>
    <path d="M12 22v-5" />
    <path d="M9 8V2M15 8V2" />
    <path d="M18 8v4a6 6 0 0 1-12 0V8z" />
  <//>`,
  power: html`<${Icon} size=${18}>
    <path d="M18.4 6.6a9 9 0 1 1-12.8 0" />
    <path d="M12 2v10" />
  <//>`,
  gauge: html`<${Icon}>
    <path d="M4.9 19a9 9 0 1 1 14.2 0" />
    <path d="M12 13l4-4" />
  <//>`,
  down: html`<${Icon}>
    <path d="M12 4v16" /><path d="M6 14l6 6 6-6" />
  <//>`,
  up: html`<${Icon}>
    <path d="M12 20V4" /><path d="M6 10l6-6 6 6" />
  <//>`,
};

function NavButton({ icon, label, active = false }) {
  return html`
    <button
      type="button"
      class=${`nav-btn${active ? ' is-active' : ''}`}
      aria-label=${label}
      title=${label}
      aria-current=${active ? 'page' : undefined}
    >
      ${icons[icon]}
    </button>
  `;
}

export function Sidebar({ paused, onTogglePause }) {
  return html`
    <aside class="sidebar-rail">
      <div class="sidebar-brand">
        <span class="brand-logo" aria-label="Oasis">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M3 12h3l2.5-7 4 14 3-7H21"
              stroke="#ffffff"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
        </span>
      </div>

      <nav class="sidebar-nav" aria-label="Primary">
        <${NavButton} icon="overview" label="Overview" active />
        <${NavButton} icon="history" label="Traffic history" />
        <${NavButton} icon="rules" label="Rules" />
        <${NavButton} icon="activity" label="Activity log" />
        <${NavButton} icon="settings" label="Settings" />
        <${NavButton} icon="plugins" label="Plugins" />
      </nav>

      <div class="sidebar-footer">
        <button
          type="button"
          class=${`nav-btn power-btn${paused ? ' is-paused' : ''}`}
          aria-label=${paused ? 'Resume monitoring' : 'Pause monitoring'}
          title=${paused ? 'Resume monitoring' : 'Pause monitoring'}
          aria-pressed=${paused}
          onClick=${onTogglePause}
        >
          ${icons.power}
        </button>
      </div>
    </aside>
  `;
}
