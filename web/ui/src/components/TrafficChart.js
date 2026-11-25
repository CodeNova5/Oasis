import { useEffect, useRef, useState } from 'preact/hooks';
import { html } from 'htm/preact';
import { formatClock, formatRate, formatRateAxis } from '../utils/formatters.js';

const HEIGHT = 200;
const PAD_LEFT = 66;
const PAD_RIGHT = 16;
const PAD_TOP = 10;
const PAD_BOTTOM = 26;

function smoothPath(points) {
  if (!points.length) return '';
  let path = `M ${points[0].x.toFixed(2)} ${points[0].y.toFixed(2)}`;

  for (let index = 0; index < points.length - 1; index += 1) {
    const previous = points[index - 1] || points[index];
    const current = points[index];
    const next = points[index + 1];
    const after = points[index + 2] || next;
    const tension = 0.17;

    const control1X = current.x + (next.x - previous.x) * tension;
    const control1Y = current.y + (next.y - previous.y) * tension;
    const control2X = next.x - (after.x - current.x) * tension;
    const control2Y = next.y - (after.y - current.y) * tension;

    path += ` C ${control1X.toFixed(2)} ${control1Y.toFixed(2)}, ${control2X.toFixed(2)} ${control2Y.toFixed(2)}, ${next.x.toFixed(2)} ${next.y.toFixed(2)}`;
  }

  return path;
}

/**
 * Rounds up to a clean axis maximum in binary units, so the 1024-based
 * formatter prints whole values (15 MB/s, 22.5 MB/s) instead of 28.6 MB/s.
 */
function niceCeil(value) {
  const MB = 1024 * 1024;
  if (!(value > 0)) return MB;
  const megabytes = value / MB;
  const exponent = Math.floor(Math.log10(megabytes));
  const base = 10 ** exponent;
  const normalized = megabytes / base;
  const steps = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
  const step = steps.find((candidate) => normalized <= candidate + 1e-9) || 10;
  return step * base * MB;
}

export function TrafficChart({ history }) {
  const wrapperRef = useRef(null);
  const [width, setWidth] = useState(560);
  const [hoverIndex, setHoverIndex] = useState(null);

  useEffect(() => {
    const element = wrapperRef.current;
    if (!element || typeof ResizeObserver === 'undefined') return undefined;

    const observer = new ResizeObserver((entries) => {
      const measured = entries[0].contentRect.width;
      if (measured > 0) setWidth(Math.round(measured));
    });
    observer.observe(element);
    setWidth(Math.round(element.clientWidth) || 560);

    return () => observer.disconnect();
  }, []);

  const count = history.length;
  const plotWidth = Math.max(1, width - PAD_LEFT - PAD_RIGHT);
  const plotHeight = HEIGHT - PAD_TOP - PAD_BOTTOM;
  const baselineY = PAD_TOP + plotHeight;

  const peak = history.reduce(
    (max, point) => Math.max(max, point.downBps, point.upBps),
    0,
  );
  const yMax = niceCeil(Math.max(peak, 1024) * 1.05);

  const xFor = (index) => PAD_LEFT + (index / Math.max(1, count - 1)) * plotWidth;
  const yFor = (value) => PAD_TOP + (1 - Math.min(value, yMax) / yMax) * plotHeight;

  const downloadPoints = history.map((point, index) => ({ x: xFor(index), y: yFor(point.downBps) }));
  const uploadPoints = history.map((point, index) => ({ x: xFor(index), y: yFor(point.upBps) }));

  const downloadLine = smoothPath(downloadPoints);
  const uploadLine = smoothPath(uploadPoints);
  const areaSuffix = `L ${xFor(count - 1).toFixed(2)} ${baselineY} L ${xFor(0).toFixed(2)} ${baselineY} Z`;
  const downloadArea = downloadLine ? `${downloadLine} ${areaSuffix}` : '';
  const uploadArea = uploadLine ? `${uploadLine} ${areaSuffix}` : '';

  const gridFractions = [0, 0.25, 0.5, 0.75, 1];
  const tickIndices = count > 1
    ? [0, Math.round((count - 1) * 0.25), Math.round((count - 1) * 0.5), Math.round((count - 1) * 0.75), count - 1]
    : [];

  const activePoint = hoverIndex === null ? null : history[hoverIndex];

  const handlePointerMove = (event) => {
    if (!count) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const relativeX = event.clientX - rect.left - PAD_LEFT;
    const index = Math.round((relativeX / plotWidth) * (count - 1));
    setHoverIndex(Math.max(0, Math.min(count - 1, index)));
  };

  const tooltipLeft = hoverIndex === null
    ? 0
    : Math.max(86, Math.min(width - 86, xFor(hoverIndex)));

  return html`
    <section class="card chart-card">
      <header class="chart-header">
        <h2 class="chart-title">Real-Time Traffic <span class="chart-subtitle">(Past 1 Minute)</span></h2>
        <div class="chart-legend">
          <span class="legend-item"><span class="legend-dot legend-dot-down"></span>Download</span>
          <span class="legend-item"><span class="legend-dot legend-dot-up"></span>Upload</span>
        </div>
      </header>

      <div
        class="chart-plot"
        ref=${wrapperRef}
        onPointerMove=${handlePointerMove}
        onPointerLeave=${() => setHoverIndex(null)}
      >
        <svg
          class="chart-svg"
          width=${width}
          height=${HEIGHT}
          viewBox=${`0 0 ${width} ${HEIGHT}`}
          role="img"
          aria-label="Download and upload throughput over the past minute"
        >
          <defs>
            <linearGradient id="download-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#7371fc" stop-opacity="0.42" />
              <stop offset="100%" stop-color="#7371fc" stop-opacity="0.02" />
            </linearGradient>
            <linearGradient id="upload-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#5ce1e6" stop-opacity="0.3" />
              <stop offset="100%" stop-color="#5ce1e6" stop-opacity="0.02" />
            </linearGradient>
          </defs>

          ${gridFractions.map((fraction) => {
            const y = PAD_TOP + fraction * plotHeight;
            const label = formatRateAxis(yMax * (1 - fraction));
            return html`
              <g key=${`grid-${fraction}`}>
                <line
                  x1=${PAD_LEFT}
                  y1=${y}
                  x2=${width - PAD_RIGHT}
                  y2=${y}
                  stroke="rgba(255, 255, 255, 0.07)"
                  stroke-width="1"
                />
                <text x=${PAD_LEFT - 10} y=${y + 4} text-anchor="end" class="chart-axis-label">
                  ${label}
                </text>
              </g>
            `;
          })}

          ${tickIndices.map((index, position) => html`
            <text
              key=${`tick-${index}`}
              x=${xFor(index)}
              y=${HEIGHT - 6}
              text-anchor=${position === 0 ? 'start' : position === tickIndices.length - 1 ? 'end' : 'middle'}
              class="chart-axis-label"
            >
              ${formatClock(history[index].time)}
            </text>
          `)}

          <path d=${downloadArea} fill="url(#download-fill)" />
          <path d=${uploadArea} fill="url(#upload-fill)" />
          <path d=${downloadLine} fill="none" stroke="#7371fc" stroke-width="2.4" stroke-linecap="round" />
          <path d=${uploadLine} fill="none" stroke="#5ce1e6" stroke-width="2.4" stroke-linecap="round" />

          <circle
            cx=${xFor(count - 1)}
            cy=${yFor(history[count - 1].downBps)}
            r="3.4"
            fill="#7371fc"
            stroke="#1b1d36"
            stroke-width="2"
          />

          ${hoverIndex !== null && activePoint && html`
            <g class="chart-hover">
              <line
                x1=${xFor(hoverIndex)}
                y1=${PAD_TOP}
                x2=${xFor(hoverIndex)}
                y2=${baselineY}
                stroke="rgba(255, 255, 255, 0.32)"
                stroke-width="1"
                stroke-dasharray="4 4"
              />
              <circle
                cx=${xFor(hoverIndex)}
                cy=${yFor(activePoint.downBps)}
                r="4"
                fill="#7371fc"
                stroke="#1b1d36"
                stroke-width="2"
              />
              <circle
                cx=${xFor(hoverIndex)}
                cy=${yFor(activePoint.upBps)}
                r="4"
                fill="#5ce1e6"
                stroke="#1b1d36"
                stroke-width="2"
              />
            </g>
          `}
        </svg>

        ${hoverIndex !== null && activePoint && html`
          <div class="chart-tooltip" style=${{ left: `${tooltipLeft}px` }} role="status">
            <span class="tooltip-time">${formatClock(activePoint.time)}</span>
            <span class="tooltip-sep">|</span>
            <span class="tooltip-down">Dn: ${formatRate(activePoint.downBps)}</span>
            <span class="tooltip-sep">|</span>
            <span class="tooltip-up">Up: ${formatRate(activePoint.upBps)}</span>
          </div>
        `}
      </div>
    </section>
  `;
}
