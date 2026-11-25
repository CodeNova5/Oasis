import { useMemo, useState } from 'preact/hooks';
import { html } from 'htm/preact';
import { formatBytesString, formatRate } from '../utils/formatters.js';

const COLUMNS = [
  { key: 'name', label: 'Process / App Name', numeric: false },
  { key: 'pid', label: 'PID', numeric: true },
  { key: 'downBps', label: 'Download', numeric: true },
  { key: 'upBps', label: 'Upload', numeric: true },
  { key: 'totalBytes', label: 'Total Data', numeric: true },
];

const chevron = html`
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M9 6l6 6-6 6" />
  </svg>
`;

function compareProcesses(left, right, key) {
  if (key === 'name') return left.name.localeCompare(right.name);
  return (left[key] || 0) - (right[key] || 0);
}

export function ProcessTable({ processes, processCount }) {
  const [sort, setSort] = useState({ key: 'downBps', direction: 'desc' });
  const [expanded, setExpanded] = useState(() => new Set());

  const sorted = useMemo(() => {
    const rows = [...processes].sort((left, right) => compareProcesses(left, right, sort.key));
    return sort.direction === 'desc' ? rows.reverse() : rows;
  }, [processes, sort]);

  const toggle = (id) => {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const changeSort = (key) => {
    setSort((previous) => (
      previous.key === key
        ? { key, direction: previous.direction === 'desc' ? 'asc' : 'desc' }
        : { key, direction: key === 'name' ? 'asc' : 'desc' }
    ));
  };

  return html`
    <section class="card table-card">
      <header class="table-card-header">
        <h2 class="table-title">Activity Monitor <span class="table-count">(${processCount} total)</span></h2>
      </header>

      <div class="table-scroll">
        <table class="process-table">
          <thead>
            <tr>
              ${COLUMNS.map((column) => {
                const isSorted = sort.key === column.key;
                return html`
                  <th
                    key=${column.key}
                    scope="col"
                    class=${column.numeric ? 'is-numeric' : ''}
                    aria-sort=${isSorted ? (sort.direction === 'asc' ? 'ascending' : 'descending') : 'none'}
                    onClick=${() => changeSort(column.key)}
                  >
                    <button type="button" class=${`sort-button${column.numeric ? ' is-numeric' : ''}`}>
                      ${column.label}
                      <span class=${`sort-arrow${isSorted ? ' is-active' : ''}`}>
                        ${isSorted ? (sort.direction === 'asc' ? '↑' : '↓') : ''}
                      </span>
                    </button>
                  </th>
                `;
              })}
            </tr>
          </thead>
          <tbody>
            ${sorted.map((process) => html`
              <${ProcessRow} key=${process.id} process=${process} expanded=${expanded.has(process.id)} onToggle=${toggle} />
              ${expanded.has(process.id) && process.subprocesses.map((child) => html`
                <${ProcessRow} key=${child.id} process=${child} subprocess />
              `)}
            `)}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function ProcessRow({ process, subprocess = false, expanded = false, onToggle }) {
  const hasChildren = process.subprocesses && process.subprocesses.length > 0;

  return html`
    <tr class=${subprocess ? 'is-subprocess' : ''}>
      <td>
        <div class=${`proc-cell${subprocess ? ' is-child' : ''}`}>
          ${subprocess
            ? html`<span class="tree-connector" aria-hidden="true"></span>`
            : html`
                <button
                  type="button"
                  class=${`proc-toggle${expanded ? ' is-expanded' : ''}`}
                  onClick=${() => onToggle(process.id)}
                  aria-expanded=${expanded}
                  aria-label=${`${expanded ? 'Collapse' : 'Expand'} ${process.name}`}
                  disabled=${!hasChildren}
                >
                  ${hasChildren ? chevron : html`<span class="toggle-spacer"></span>`}
                </button>
              `}
          <span
            class="proc-monogram"
            style=${{ color: process.tint, backgroundColor: `${process.tint}26` }}
            aria-hidden="true"
          >
            ${process.monogram}
          </span>
          <span class="proc-name">${process.name}</span>
        </div>
      </td>
      <td class="is-numeric tabular-nums">${process.pid}</td>
      <td class="is-numeric tabular-nums">
        <span class="rate-prefix">Dn:</span>
        <span class="rate-down">${formatRate(process.downBps)}</span>
      </td>
      <td class="is-numeric tabular-nums">
        <span class="rate-prefix">Up:</span>
        <span class="rate-up">${formatRate(process.upBps)}</span>
      </td>
      <td class="is-numeric tabular-nums">${formatBytesString(process.totalBytes)}</td>
    </tr>
  `;
}
