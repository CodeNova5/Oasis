import { useState } from 'preact/hooks';
import { html } from 'htm/preact';
import { performNoticeAction } from '../bridge/client.js';

// Labels mirror `DataSaverNotifications::actionLabel()`; a token this build does
// not know is not rendered, so the page never shows a dead button.
const ACTION_LABELS = {
  allow_once: 'Allow once',
  always_allow: 'Always allow',
  inspect: 'Inspect application',
};

const PRIORITY_LABELS = {
  critical: 'Enforcement problem',
  warning: 'Control applied',
  info: 'Notice',
};

function formatMilestone(notice) {
  if (!notice) return '';
  const mib = typeof notice.milestoneBytes === 'number' ? notice.milestoneBytes / (1024 * 1024) : 0;
  const size = mib >= 10 ? mib.toFixed(0) : mib.toFixed(1);
  return `${size} MiB · index ${notice.milestoneIndex ?? 0}`;
}

function DetailRow({ label, value }) {
  if (!value) return null;
  return html`
    <div class="notice-detail-row">
      <dt>${label}</dt>
      <dd>${value}</dd>
    </div>
  `;
}

function NoticeDetails({ notice }) {
  if (!notice) return null;
  const rate = notice.rateBitsPerSecond
    ? `${notice.rateBitsPerSecond} bits/s`
    : '';
  return html`
    <dl class="notice-details">
      <${DetailRow} label="Application" value=${notice.executable} />
      <${DetailRow} label="Domain" value=${notice.domain} />
      <${DetailRow} label="Milestone" value=${formatMilestone(notice)} />
      <${DetailRow} label="Action" value=${notice.action} />
      <${DetailRow} label="Direction" value=${notice.direction} />
      <${DetailRow} label="Rate" value=${rate} />
      <${DetailRow} label="Enforcement" value=${notice.status} />
      <${DetailRow} label="Channels" value=${notice.enforcementChannels} />
      <${DetailRow}
        label="Enforcement detail"
        value=${notice.enforcementMessage}
      />
      <${DetailRow} label="Reason" value=${notice.reason} />
      <${DetailRow} label="Policy" value=${notice.policyId} />
      <${DetailRow} label="Decision" value=${notice.decisionId} />
      <${DetailRow} label="Observation" value=${notice.observationId} />
    </dl>
  `;
}

function NoticeCard({ notice, onDismiss, onResolved }) {
  const [pendingToken, setPendingToken] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState('');
  const [details, setDetails] = useState(null);

  const tokens = (notice.actions || []).filter((token) => ACTION_LABELS[token]);

  const run = async (token) => {
    // Always Allow is a permanent rule, so the first click only asks; the
    // native pinned store still refuses an unconfirmed write.
    if (token === 'always_allow' && !confirming) {
      setConfirming(true);
      setError('');
      return;
    }

    setPendingToken(token);
    setError('');
    try {
      const result = await performNoticeAction(notice.key, token, {
        confirmed: token === 'always_allow',
      });
      if (token === 'inspect') {
        setDetails(result?.notice ?? null);
      } else {
        onResolved?.(notice.key, token, result);
      }
    } catch (actionError) {
      setError(actionError.message || 'The action could not be applied.');
    } finally {
      setPendingToken('');
      setConfirming(false);
    }
  };

  const priority = PRIORITY_LABELS[notice.priority] ? notice.priority : 'info';
  const folded = notice.suppressedCount > 0
    ? `${notice.suppressedCount} earlier notice${notice.suppressedCount === 1 ? '' : 's'} folded in`
    : '';

  return html`
    <article class=${`notice-card ${priority}`} role="alert">
      <div class="notice-head">
        <span class=${`notice-badge ${priority}`}>${PRIORITY_LABELS[priority]}</span>
        <button
          class="notice-dismiss"
          type="button"
          aria-label="Dismiss notice"
          onClick=${() => onDismiss?.(notice.key)}
        >
          ×
        </button>
      </div>

      <h2 class="notice-title">${notice.title}</h2>
      <p class="notice-message">${notice.message}</p>
      ${folded ? html`<p class="notice-folded">${folded}</p>` : null}

      ${confirming
        ? html`
            <div class="notice-confirm">
              <p>
                Always allow writes a pinned rule that survives Data Saver Off and takes
                precedence over automatic controls.
              </p>
              <div class="notice-actions">
                <button
                  class="notice-button primary"
                  type="button"
                  disabled=${Boolean(pendingToken)}
                  onClick=${() => run('always_allow')}
                >
                  ${pendingToken === 'always_allow' ? 'Saving…' : 'Confirm always allow'}
                </button>
                <button
                  class="notice-button"
                  type="button"
                  disabled=${Boolean(pendingToken)}
                  onClick=${() => setConfirming(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          `
        : null}

      ${tokens.length > 0
        ? html`
            <div class="notice-actions">
              ${tokens.map((token) => html`
                <button
                  key=${token}
                  class=${token === 'allow_once' ? 'notice-button primary' : 'notice-button'}
                  type="button"
                  disabled=${Boolean(pendingToken)}
                  onClick=${() => run(token)}
                >
                  ${pendingToken === token ? 'Working…' : ACTION_LABELS[token]}
                </button>
              `)}
            </div>
          `
        : null}

      ${error ? html`<p class="notice-error">${error}</p>` : null}
      <${NoticeDetails} notice=${details} />
    </article>
  `;
}

export function NoticeStack({ notices, onDismiss, onResolved }) {
  if (!notices || notices.length === 0) return null;
  return html`
    <section class="notice-stack" aria-label="Data Saver notices">
      ${notices.map((notice) => html`
        <${NoticeCard}
          key=${notice.key}
          notice=${notice}
          onDismiss=${onDismiss}
          onResolved=${onResolved}
        />
      `)}
    </section>
  `;
}
