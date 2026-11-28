/**
 * Client for the native JSON message bridge (src/ui/webview2/webuibridge.h).
 *
 * Requests: { id, method, params } -> replies: { id, ok, result | error }.
 * Ids are correlated locally, so several requests can be in flight and a reply
 * that arrives out of order still resolves the right promise.
 *
 * Pushed events arrive on the same transport without an `id`:
 *   { event: "datasaver.notice", payload: { ... } }
 * A surface subscribes with `onEvent()`; nothing is replayed, so an event that
 * arrives while no page is open is simply not shown.
 *
 * Outside the desktop app (a plain browser, the Node test harness) there is no
 * transport; `isAvailable()` reports that and every request rejects instead of
 * hanging.
 */

let nextId = 1;
const pending = new Map();
const eventHandlers = new Set();
let listenerInstalled = false;

function webview() {
  if (typeof window === 'undefined') return null;
  return window.chrome && window.chrome.webview ? window.chrome.webview : null;
}

function ensureListener() {
  if (listenerInstalled) return;
  const transport = webview();
  if (!transport) return;

  transport.addEventListener('message', (event) => {
    const message = event.data;
    if (!message) return;

    // A push has an event name and no id; a reply always has an id.
    if (message.event) {
      for (const handler of Array.from(eventHandlers)) {
        try {
          handler(message.event, message.payload);
        } catch (error) {
          console.error(`Bridge event "${message.event}" handler failed.`, error);
        }
      }
      return;
    }

    if (message.id === undefined || message.id === null) return;

    const entry = pending.get(message.id);
    if (!entry) return;

    pending.delete(message.id);
    clearTimeout(entry.timer);

    if (message.ok) {
      entry.resolve(message.result);
    } else {
      const error = new Error(
        (message.error && message.error.message) || 'The bridge rejected the request.',
      );
      error.code = (message.error && message.error.code) || 'unknown_error';
      entry.reject(error);
    }
  });

  listenerInstalled = true;
}

export function isAvailable() {
  return Boolean(webview());
}

/**
 * Subscribes to pushed events. Returns an unsubscribe function, so a component
 * effect can clean up when it unmounts.
 */
export function onEvent(handler) {
  ensureListener();
  eventHandlers.add(handler);
  return () => {
    eventHandlers.delete(handler);
  };
}

export function request(method, params = {}, options = {}) {
  const transport = webview();
  if (!transport) {
    return Promise.reject(new Error('The Oasis bridge is only available in the desktop app.'));
  }

  ensureListener();

  const id = nextId++;
  const timeoutMs = options.timeoutMs === undefined ? 10000 : options.timeoutMs;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`Bridge request "${method}" timed out after ${timeoutMs} ms.`));
    }, timeoutMs);

    pending.set(id, { resolve, reject, timer });
    transport.postMessage({ id, method, params });
  });
}

export function getAppStatus() {
  return request('app.status');
}

export function getDataSaverStatus() {
  return request('datasaver.status');
}

/**
 * Applies one action of a delivered Data Saver notice. `action` is the token the
 * notice carried (allow_once, always_allow, inspect); Always Allow additionally
 * needs `confirmed: true`, which is the user's explicit confirmation.
 */
export function performNoticeAction(key, action, options = {}) {
  return request('datasaver.notice.action', {
    key,
    action,
    confirmed: Boolean(options.confirmed),
  });
}
