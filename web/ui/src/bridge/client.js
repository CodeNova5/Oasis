/**
 * Client for the native JSON message bridge (src/ui/webview2/webuibridge.h).
 *
 * Requests: { id, method, params } -> replies: { id, ok, result | error }.
 * Ids are correlated locally, so several requests can be in flight and a reply
 * that arrives out of order still resolves the right promise.
 *
 * Outside the desktop app (a plain browser, the Node test harness) there is no
 * transport; `isAvailable()` reports that and every request rejects instead of
 * hanging.
 */

let nextId = 1;
const pending = new Map();
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
    if (!message || message.id === undefined || message.id === null) return;

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
