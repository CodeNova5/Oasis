/**
 * Byte / rate formatting shared by the KPI cards, chart axis and process table.
 *
 * Every helper auto-scales between B, KB, MB, GB and TB (1024-based, matching
 * how the native layer counts bytes) so a value never has to be pre-formatted
 * by the caller.
 */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

export function formatBytes(bytes) {
  const negative = bytes < 0;
  let value = Math.abs(Number(bytes) || 0);
  let unit = 0;

  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }

  const decimals = unit === 0 ? 0 : value >= 100 ? 0 : 1;

  return {
    value: `${negative ? '-' : ''}${value.toFixed(decimals)}`,
    unit: UNITS[unit],
  };
}

export function formatBytesString(bytes) {
  const { value, unit } = formatBytes(bytes);
  return `${value} ${unit}`;
}

/** "12.5 MB/s" for live throughput cells and tooltips. */
export function formatRate(bytesPerSecond) {
  return `${formatBytesString(bytesPerSecond)}/s`;
}

/** Compact axis label; drops a trailing ".0" so ticks stay short. */
export function formatRateAxis(bytesPerSecond) {
  if (!bytesPerSecond) return '0';
  const { value, unit } = formatBytes(bytesPerSecond);
  const trimmed = value.endsWith('.0') ? value.slice(0, -2) : value;
  return `${trimmed} ${unit}/s`;
}

export function formatClock(timestamp) {
  const date = new Date(timestamp);
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
