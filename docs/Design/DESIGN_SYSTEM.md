# Oasis — Design System Specification

**Target Platform:** Windows 10 / 11  
**UI Framework:** Qt 6 Widgets / C++  
**Visual Direction:** Dark-first Fluent UI (Professional, native, calm, and trustworthy)  

---

## 1. Visual Principles

Every interface decision in Oasis must uphold five core principles:
1. **Clarity:** Users should understand their network usage without needing deep networking knowledge.
2. **Control:** Important actions and restriction tools must be easy to find and predictable.
3. **Trust:** The application must never exaggerate what it knows or what it has actually enforced.
4. **Consistency:** Every page, table, and modal should behave and look like part of a unified product.
5. **Restraint:** Use color, motion, and alerts only when they communicate meaningful state changes.

---

## 2. Color Palette & Design Tokens

These tokens define the Dark-first Fluent UI theme (`colors.h` / `styles.qss`).

### 2.1 Core Surfaces
| Token Name | Hex Value | Usage |
| :--- | :--- | :--- |
| `surface-window` | `#111318` | Base application window background |
| `surface-sidebar` | `#171A21` | Expanded/collapsed navigation sidebar background |
| `surface-primary` | `#1C2029` | Standard card, panel, and container backgrounds |
| `surface-elevated` | `#242A35` | Modals, dialogs, dropdowns, and active table headers |
| `surface-hover` | `#2B3240` | Interactive hover states on rows, cards, and ghost buttons |
| `border-default` | `#343B48` | Subtle 1px structural dividers, card outlines, and inputs |

### 2.2 Accent, Semantic & Text Colors
| Token Name | Hex Value | Usage |
| :--- | :--- | :--- |
| `accent-primary` | `#4C8DFF` | Primary actions, active navigation highlights, links |
| `semantic-success` | `#3FB982` | Confirmed healthy, active, or enforced states |
| `semantic-warning` | `#E6AD4D` | Warnings, partial/degraded states, stored-only policies |
| `semantic-danger` | `#E36B70` | Failed operations, blocked states, destructive actions |
| `semantic-info` | `#62B5E8` | Informational callouts and neutral system notices |
| `text-primary` | `#F3F5F8` | Primary headings, body text, and high-contrast metrics |
| `text-secondary` | `#A1A9B7` | Supporting labels, table headers, and descriptions |
| `text-muted` | `#6C7586` | Disabled states, timestamps, and subtle metadata |

### 2.3 Strict Color Usage Rules
* **Blue (`#4C8DFF`):** Reserved for primary interactive actions, selected navigation items, and links. *A blue button never implies an action has already succeeded.*
* **Green (`#3FB982`):** Reserved strictly for confirmed healthy/active states. *A green badge on one rule does not imply the entire system is protected.*
* **Amber (`#E6AD4D`):** Indicates uncertainty, degraded capability, or policies saved in a **Stored only** state.
* **Red (`#E36B70`):** Reserved for failed enforcement, active block rules, and destructive buttons.
* **Grey (`#A1A9B7` / `#6C7586`):** Indicates disabled controls, unavailable capabilities, or secondary metadata.

---

## 3. Typography (`typography.h`)

* **Primary Font Family:** `Segoe UI Variable`
* **Fallback Font Family:** `Segoe UI`, `sans-serif`

| Text Style | Font Size | Font Weight | Line Height | Typical Usage |
| :--- | :--- | :--- | :--- | :--- |
| **Large Metric** | `28–32 px` | Semibold (600) | `36 px` | Key KPI numbers on Overview and Detail headers |
| **Page Title** | `24 px` | Semibold (600) | `32 px` | Global header screen titles |
| **Section Heading** | `16 px` | Semibold (600) | `24 px` | Major content block titles |
| **Card Heading** | `14 px` | Semibold (600) | `20 px` | Individual card and panel headers |
| **Body** | `13 px` | Normal (400) | `18 px` | Standard UI copy, table cells, and descriptions |
| **Secondary Text** | `12 px` | Normal (400) | `16 px` | Subtitles, helper text, and secondary table details |
| **Metadata** | `11 px` | Normal (400) | `14 px` | Timestamps, badges, and compact status indicators |

> **Hierarchy Rule:** Avoid making every heading bold. Rely on font size, spacing, and text color (`text-primary` vs. `text-secondary`) to create visual hierarchy.

---

## 4. Spacing, Layout & Dimensions (`dimensions.h`)

All layout spacing adheres to a strict **4-point grid system**.

### 4.1 Spacing Tokens
| Token | Value | Typical Usage |
| :--- | :--- | :--- |
| `SPACE_XS` | `4 px` | Icon-to-text gaps, tight badge padding |
| `SPACE_SM` | `8 px` | Compact internal element spacing |
| `SPACE_MD` | `12 px` | Internal card padding, form field spacing |
| `SPACE_LG` | `16 px` | Standard grid gaps between cards and controls |
| `SPACE_XL` | `24 px` | Section separation and standard page margins |
| `SPACE_2XL` | `32 px` | Major layout group separation |
| `SPACE_3XL` | `40 px` | Large structural separation |

### 4.2 Component Dimensions
*Note: Dimensions must be verified across Windows DPI scaling levels (100%, 125%, 150%, 200%).*

| Component | Target Dimension | Notes |
| :--- | :--- | :--- |
| **Expanded Sidebar Width** | `232 px` | Fixed default width |
| **Collapsed Sidebar Width** | `64 px` | Future iteration target |
| **Global Header Height** | `60 px` | Consistent across all primary views |
| **Global Status Bar Height** | `28 px` | Persistent bottom diagnostic strip |
| **Page Padding (H / V)** | `24 px / 24 px` | Standard workspace content inset |
| **Standard Card Radius** | `10 px` | Applied to `QFrame` containers |
| **Modal / Dialog Radius** | `12 px` | Applied to top-level `QDialog` containers |
| **Standard Button Height** | `36 px` | Minimum horizontal padding: `16 px` |
| **Input / Search Height** | `38 px` | Consistent across filters and forms |
| **Standard Table Row** | `48 px` | Primary data views (`Applications`, `Policies`) |
| **Compact Table Row** | `40 px` | Dense secondary logs (`Connections`, `Audit`) |

---

## 5. Iconography

* **Icon Set:** **Lucide Icons** rendered with crisp 1.5px–1.75px strokes to match Windows Fluent aesthetics.
* **Coloring:** Inherit `text-secondary` by default; transition to `text-primary` on hover or `accent-primary` when selected.

| Size Context | Pixel Size | Examples |
| :--- | :--- | :--- |
| **Inline / Table Cells** | `16 px` | Status indicators, sort arrows, row actions |
| **Navigation / Buttons** | `18 px` | Sidebar icons (`layout-dashboard`, `shield`, `network`), button icons |
| **Headers / Empty States** | `20–24 px` | Global header utilities (`bell`, `search`), empty state illustrations |

**Standard Navigation Icon Mapping:**
* Overview: `layout-dashboard` | Activity: `activity` | Applications: `app-window` | Connections: `network`
* Policies: `shield` | Insights: `lightbulb` | Reports: `clipboard-list` | Settings: `settings`

---

## 6. Standardized Status & Attribution System

Oasis strictly separates **Operational/Enforcement Status** from **Attribution Confidence** so users always know what is verified versus inferred.

### 6.1 Operational & Policy Status Labels
| Status Label | Badge Color | Border / Fill Treatment | Meaning |
| :--- | :--- | :--- | :--- |
| **Active** | Green (`#3FB982`) | 12% Green tint + Green text | Confirmed active monitoring or live policy enforcement |
| **Inactive** | Grey (`#A1A9B7`) | 12% Grey tint + Secondary text | Rule or service is intentionally paused/disabled |
| **Pending** | Blue (`#4C8DFF`) | 12% Blue tint + Blue text | Queued or awaiting system confirmation |
| **Degraded** | Amber (`#E6AD4D`) | 12% Amber tint + Amber text | Running with partial capabilities or missing drivers |
| **Stored only** | Amber (`#E6AD4D`) | 12% Amber tint + Amber text | Policy saved to database, **not currently enforced** |
| **Failed** | Red (`#E36B70`) | 12% Red tint + Red text | Enforcement or capture operation failed |
| **Unknown** | Grey (`#A1A9B7`) | 12% Grey tint + Secondary text | Insufficient telemetry to determine state |
| **Expired** | Grey (`#A1A9B7`) | 12% Grey tint + Muted text | Time-bound restriction has completed |

### 6.2 Attribution Confidence Levels
Used in `Applications`, `Connections`, and `Insights` to communicate how reliably traffic is tied to a binary or domain:
* **Confirmed:** Verified via signed binary path, active socket PID mapping, or direct DNS/SNI correlation.
* **Likely:** Strong heuristic or historical correlation, though direct socket ownership has closed.
* **Possible:** Partial metadata match; user verification recommended before creating broad blocks.
* **Unknown:** Raw IP or unassociated system traffic; **never fabricate a domain name when confidence is Unknown.**

---

## 7. Core Atomic Components (`src/ui/components/`)

### 7.1 Buttons (4 Variants)
All buttons use `36 px` height, `6 px` border radius, and `13 px` Semibold text.
1. **Primary (`ButtonPrimary`):** Solid `#4C8DFF` fill, white text. Used for the single primary action on a view (e.g., *Create policy*, *Save*).
2. **Secondary (`ButtonSecondary`):** `#242A35` fill, `1px solid #343B48` border, `#F3F5F8` text. Used for supporting actions (e.g., *View details*, *Export*).
3. **Ghost (`ButtonGhost`):** Transparent background, `#A1A9B7` text, `#2B3240` fill on hover. Used for low-priority actions (e.g., *Cancel*, *Dismiss*).
4. **Danger (`ButtonDanger`):** 15% `#E36B70` tint with `#E36B70` border/text (solid `#E36B70` with dark text on hover). Used for destructive or blocking actions (e.g., *Block application*, *Delete rule*).

### 7.2 Metric Card (`MetricCard`)
* **Container:** `#1C2029` background, `1px solid #343B48` border, `10 px` radius, `16 px` internal padding.
* **Structure:** Top row displays `12 px` Secondary label + optional `16 px` status icon; middle row displays `28 px` Semibold primary value; bottom row displays `11 px` trend or contextual subtitle.

### 7.3 Status Badge (`StatusBadge`)
* **Container:** Pill or `6 px` rounded rectangle, `22 px` height, `8 px` horizontal padding.
* **Structure:** Optional `6 px` circular status dot + `11 px` Semibold label matching Section 6 color rules.

### 7.4 Search & Filter Bars (`SearchBar`, `FilterBar`)
* **SearchBar:** `38 px` height, `#1C2029` background, `1px solid #343B48` border (`#4C8DFF` on focus), leading `16 px` search icon, clear (`x`) button when populated.
* **FilterBar:** Horizontal segmented pill group (`All`, `Active`, `Background`, etc.) using `32 px` height pills. Active pill uses `#242A35` background with `#4C8DFF` bottom/border accent.

### 7.5 Empty & Degraded State Panel (`EmptyStateWidget`)
* **Layout:** Centered vertical stack (`max-width: 420 px`) inside a `#1C2029` container.
* **Elements:** `24 px` muted icon in a `#242A35` circular badge, `16 px` Semibold title, `13 px` Secondary explanation text, and an optional Primary or Secondary recovery button (e.g., *Open diagnostics*).

### 7.6 Notification Toast (`NotificationToast`)
* **Behavior:** Non-blocking floating card (`340 px` width) anchored bottom-right above the status bar.
* **Truthfulness Rule:** Toasts must reflect actual backend outcomes (e.g., *"Policy saved as Stored Only — enforcement driver unavailable"* rather than a generic green *"Success"* message).