# Oasis — Screens & Dialogs Specification

**Target Platform:** Windows 10 / 11  
**UI Framework:** Qt 6 Widgets / C++  
**Scope:** Wireframe layouts, data contracts, interactions, and edge states for all 9 primary destinations and core dialogs.

---

## Global UI State Matrix (Applies to All Screens)

Every screen must explicitly implement these states rather than only designing for ideal populated telemetry:

| State | Visual Treatment | Required Behavior |
| :--- | :--- | :--- |
| **Loading** | Subtle `#242A35` skeleton placeholders | Displayed only during initial database/service warm-up |
| **Empty** | Centered `EmptyStateWidget` (`420 px` max-width) | Explains why no data exists yet + provides concrete next step |
| **Active** | Standard populated card/table layout | Real-time updates preserve user selection and scroll position |
| **Partial / Degraded** | Top amber banner (`#E6AD4D` tint) | Identifies missing capability (e.g., WinDivert/elevation) + link to Diagnostics |
| **Error** | Top red banner (`#E36B70` tint) | Explains failure reason + provides Retry / Diagnostics action |
| **Permission Required** | Inline elevation notice | Explains why Administrator rights are required for the requested view/action |
| **Stale Data** | Header badge displaying `Last updated: HH:MM:SS` | Triggered if monitoring pauses or stops |
| **Unknown Attribution** | Explicit `Unknown` grey badge + raw IP | Never fabricate domain names or publishers when evidence is insufficient |

---

## Screen 01 — Overview (`OverviewPage`) — **P0 (Default Landing)**

**Purpose:** Give users an immediate, trustworthy summary of network activity, active controls, and anomalies.

### Layout Structure
1. **Top KPI Row (4 equal-width `MetricCard` widgets, `16 px` gap):**
   * **Total Usage:** Combined download + upload for active session/window (e.g., `2.4 GB`). *Click → opens Activity.*
   * **Download:** Total downstream volume + current rate (e.g., `1.8 GB`).
   * **Upload:** Total upstream volume + current rate (e.g., `600 MB`).
   * **Active Apps:** Count of processes with observed network activity (e.g., `12`).
2. **Middle Split Row (2-column grid, 65% / 35% split):**
   * **Left — Network Traffic Chart (`TrafficChart`):** Dual-series smooth line/area chart (Download `#4C8DFF`, Upload `#3FB982`) covering the last 60 minutes. *Click → opens Activity with matching range.*
   * **Right — Top Consumers Card:** Ranked list of top 3–5 bandwidth-consuming applications with icon, name, state badge, total volume, and footer link (`View applications →`). *Click row → opens Application Details.*
3. **Bottom Split Row (2-column grid, 50% / 50% split):**
   * **Left — Controls in Force Card:** Summarizes active rules vs. non-enforced rules (e.g., `2 Active policies`, `1 Stored-only policy`), unresolved traffic warning counter, and `Review policies →` link.
   * **Right — Recent Activity & Alerts Card:** Chronological feed of latest policy applications, enforcement failures, and unresolved traffic detections with relative timestamps and quick action links (`Review`, `Inspect`).

### Required Edge States
* Monitoring active, Monitoring stopped, No network adapter available, Elevation/permission unavailable, Partial monitoring, No data collected yet, High unresolved traffic alert.

---

## Screen 02 — Activity (`ActivityPage`) — **P1**

**Purpose:** Show how network consumption changes over time. *(Strictly time-oriented; must not duplicate the identity-oriented Applications table).*

### Layout Structure
1. **Control Toolbar:**
   * Segmented time range selector (`FilterBar`): `Live` | `1 hour` | `24 hours` | `7 days` | `30 days`.
   * Filter dropdowns: `Application`, `Direction (All/Download/Upload)`, `Protocol (TCP/UDP/Other)`.
   * Right-aligned `ButtonSecondary`: `Export` (CSV/JSON).
2. **Bandwidth Timeline Card:**
   * Interactive `TrafficChart` supporting brush/range selection.
   * Summary header displaying total **Downloaded** and **Uploaded** volume for the selected timeframe.
3. **Activity Records Table (`QTableView`, `40 px` compact rows):**
   * Displays time-bucketed traffic entries matching the chart selection.
   * Columns: `Time Window`, `Application`, `Direction`, `Protocol`, `Downloaded`, `Uploaded`, `Total`.

### Interactions
* Dragging/selecting a time slice on the timeline filters the **Activity Records** table below to that exact period.
* Clicking an application name opens **Application Details**.

---

## Screen 03 — Applications (`ApplicationsPage`) — **P0**

**Purpose:** Identify which applications and background services are consuming bandwidth and inspect/control their behavior.

### Layout Structure
1. **Filter & Search Bar:**
   * `SearchBar` (`Search applications or executables...`).
   * `FilterBar` pills: `All` | `Active` | `Background` | `System services` | `Restricted` | `Unresolved`.
   * Right-aligned `Columns...` button allowing users to toggle visible columns (saved in `QSettings`).
2. **Applications Data Table (`QTableView` + `QSortFilterProxyModel`, `48 px` rows):**

| Column | Content & Formatting |
| :--- | :--- |
| **Application** | `20 px` app icon + friendly name (`13 px` Semibold) + executable (`11 px` Muted, e.g., `chrome.exe`) |
| **Publisher** | Verified signer name (`Google LLC`) or `Unknown publisher` (`#A1A9B7`) |
| **Download** | Current download rate (e.g., `1.2 Mbps` or `0 B/s`) |
| **Upload** | Current upload rate (e.g., `140 Kbps` or `0 B/s`) |
| **Total** | Cumulative transferred volume (`840 MB`) |
| **Activity** | Classification badge (`Foreground`, `Background`, `System`) |
| **Policy** | Current rule status (`None`, `Throttle (Active)`, `Block (Stored only)`) |
| **Identity** | Attribution confidence `StatusBadge` (`Confirmed`, `Likely`, `Possible`, `Unknown`) |

### Interactions
* **Clean Row Rule:** Do not crowd rows with inline action buttons.
* **Single Click:** Selects row (selection persists across 1s telemetry updates).
* **Double Click:** Opens **Application Details** (`ApplicationDetailDialog`).
* **Right-Click Context Menu:** `Details`, `Manage traffic`, `Create policy`, `Verify identity`, `Inspect activity`.

---

## Screen 04 — Application Details (`ApplicationDetailDialog` / View) — **P0**

**Purpose:** Provide a unified, deep-dive investigation and control workspace for a single application.

### Header & Action Bar
* **Left:** App icon (`32 px`), Application Name (`20 px` Semibold), Executable path & Publisher (`12 px` Secondary), plus `Identity` and `Operational` status badges.
* **Right Action Buttons:**
  * `ButtonPrimary`: `Manage traffic`
  * `ButtonSecondary`: `Create policy`
  * `ButtonDanger`: `Block network access` *(Requires explicit scope confirmation dialog)*

### Tabbed Navigation (`5 Tabs`)
1. **Overview:**
   * Summary KPI strip (`Total usage`, `Current rate`, `Active connections`).
   * **Application Identity Card:** Executable path, file hash/signer, publisher verification, and attribution confidence.
   * **Related Processes List:** Parent/child PIDs grouped under this application.
   * **Current Policy Summary Card:** Active download/upload limits or block rules with quick `Edit` toggle.
2. **Traffic:**
   * Application-specific download/upload timeline chart with time range filters (`1h`, `24h`, `7d`).
3. **Connections:**
   * Filtered list of endpoints contacted by this app (`Domain/IP`, `Port/Protocol`, `Attribution Source`, `Confidence`, `Bytes`).
4. **Controls:**
   * All policies targeting this application (`Create policy`, `Edit`, `Disable/Enable`, `Delete`).
5. **History:**
   * Chronological audit log of policy changes, recommendations, and enforcement results for this app.

---

## Screen 05 — Connections (`ConnectionsPage`) — **P1**

**Purpose:** Explain where network traffic is going with strict honesty regarding domain vs. IP attribution.

### Layout Structure
1. **Filter & Search Bar:**
   * `SearchBar` (`Search domain, IP address, or application...`).
   * `FilterBar` pills: `All` | `Domains` | `IP addresses` | `Unknown` | `Recent`.
2. **Split View (Main Table + Contextual Side Drawer):**
   * **Connections Table (`40 px` compact rows):**
     * Columns: `Domain / Destination`, `Application`, `Remote IP`, `Port / Protocol`, `Direction`, `Data Transferred`, `Last Observed`, `Confidence`.
   * **Connection Detail Side Panel (opens when a row is selected):**
     * Destination hostname (or raw IP if unresolved).
     * Associated IP addresses & ASN/network info (if locally available).
     * Associated application identities.
     * Port, transport protocol, first/last observed timestamps.
     * **Attribution Source & Evidence:** Explicitly states *how* the domain was linked (e.g., `DNS query observed 4s ago` vs. `TLS SNI` vs. `No domain evidence`).

> **Strict Honesty Rule:** Never perform reverse-DNS guessing to present an unverified hostname as confirmed. If Oasis cannot establish domain association, display the raw IP address and set Confidence to `Unknown`.

---

## Screen 06 — Policies & Policy Editor (`PoliciesPage`) — **P0**

**Purpose:** Central management for all network rules, schedules, and enforcement verification.

### Main Screen Layout
1. **Summary KPI Strip (3 cards):** `Active` (Green), `Stored only` (Amber), `Expired` (Grey).
2. **Filter & Search Bar:**
   * `FilterBar`: `All` | `Active` | `Stored only` | `Scheduled` | `Expired`.
   * Header Primary Action: `+ Create policy`.
3. **Policies Table (`48 px` rows):**
   * Columns: `Name`, `Target` (App/Path/Service), `Action` (`Block`, `Throttle`, `Allow`, `Notify`), `Direction`, `Schedule`, `Enforcement` (`StatusBadge`), `Expiration`, `Actions` (`Edit`, `Toggle`, `Delete`).

### Dedicated Policy Editor Dialog (`PolicyEditorDialog`)
A structured modal (`560 px` width, `12 px` radius) — never a tiny popover:
1. **Choose Target:** Application selector, executable path browser, or system service target.
2. **Select Action:** Segmented selector (`Throttle`, `Block`, `Allow`, `Notify`).
3. **Direction:** `Download` | `Upload` | `Both`.
4. **Rate Limit (when Throttle selected):** Numeric input + unit dropdown (`Kbps` / `Mbps`).
5. **Duration / Schedule:** `Until disabled` | `1 hour` | `Custom duration` | `Recurring schedule`.
6. **Live Impact Preview Box (`#242A35` surface):**
   * Plain-English summary of what the rule will do.
   * **Build Capability Indicator:** Explicitly states whether the current Windows environment can enforce this scope live or will save it as `Stored only`.

### Policy Review & Confirmation Dialog (`PolicyConfirmationDialog`)
Displayed before enabling any rule:
* Summarizes Target, Scope breadth, Direction, Action/Rate, Duration, and whether future child/matching processes are affected.
* **Safety Default:** For broad scopes (e.g., folder paths or system-wide rules), keyboard focus defaults to **Cancel / No**.
* **Post-Save Truthfulness:** Upon confirmation, displays the actual backend enforcement result (`Active`, `Stored only`, or `Failed` with channel error breakdown).

---

## Screen 07 — Insights (`InsightsPage`) — **P1**

**Purpose:** Translate telemetry anomalies into understandable, reversible recommendations.

### Layout Structure
1. **Filter Bar:** `All` | `Recommendations` | `Unusual activity` | `Reviewed`.
2. **Insight Cards Feed:**
   * Each card displays severity/category badge, plain-language title (e.g., *"Background application using significant bandwidth"*), concise summary, and two actions: `Dismiss` (`ButtonGhost`) and `Review →` (`ButtonSecondary`).
3. **Recommendation Detail & Evidence View (`RecommendationDialog`):**
   * Must clearly answer seven questions:
     1. *What was observed?*
     2. *Which application or identity is involved?*
     3. *What evidence supports this?*
     4. *How confident is the attribution?*
     5. *What action is suggested?*
     6. *What happens if applied?*
     7. *How can the user reverse it?*
4. **Optional AI Explanation Layer:**
   * Separated visually from deterministic evidence.
   * **Explicit Privacy Gate:** Clicking `Explain with AI` first displays the exact sanitized metadata payload that would be transmitted and requires explicit user approval.
   * **Unwired/Offline State:** If the remote AI provider is disabled or unavailable in the current build, display the panel clearly as `Unavailable / Disabled in Privacy Settings` rather than hiding or faking functionality. No silent enforcement is ever permitted.

---

## Screen 08 — Audit & Reports (`AuditReportsPage`) — **P1**

**Purpose:** Make every policy change, enforcement outcome, and alert traceable and exportable.

### Layout Structure
1. **Filter & Export Header:**
   * `FilterBar`: `All events` | `Policies` | `Enforcement` | `Recommendations`.
   * Date range picker + `SearchBar`.
   * Redaction indicator pill (`Destination redaction: Enabled/Disabled`).
   * Primary/Secondary action: `Export report` (opens format selector: `CSV` or `JSON` with destination redaction toggle).
2. **Event Log Table (`40 px` compact rows):**
   * Columns: `Timestamp`, `Event Type`, `Target / Rule`, `Outcome` (`Applied`, `Failed`, `Stored only`, `Dismissed`, `Expired`), `Details`.
   * Clicking any row expands or opens an event inspector showing full technical metadata and OS enforcement channel logs.

---

## Screen 09 — Settings (`SettingsPage`) — **P1**

**Purpose:** Organize configuration, privacy disclosures, and system diagnostics into clear categories.

### Layout Structure
* **Left Sub-Navigation (`200 px` width):**
  1. `General` — Startup behavior, language, default landing page.
  2. `Monitoring` — Active network adapters, refresh interval, capture mode.
  3. `Enforcement` — Live capability matrix for **Windows Firewall**, **QoS**, and **WinDivert** (showing `Available`, `Elevation Required`, or `Not Installed`).
  4. `Notifications` — Desktop alert thresholds and toast preferences.
  5. `Privacy` — **Dedicated transparency controls** (see below).
  6. `Appearance` — Dark mode theme settings, table density (`Standard 48px` vs. `Compact 40px`).
  7. `Diagnostics` — Service health checks, log viewer, and support bundle export.
  8. `About` — Version, build info, open-source licenses.

### Special Requirements for `Settings > Privacy`
* Plain-English breakdown of **what metadata is collected locally** vs. what is never collected (**explicitly confirms packet payloads are never stored**).
* Toggles for DNS/TLS SNI metadata correlation.
* Local database retention selector (`7 days`, `30 days`, `90 days`) + `Clear stored telemetry data` (`ButtonDanger` with confirmation).
* Master toggle for **Remote AI Explanations** (`Disabled by default`).
* Default toggle for **Redact destinations in exported reports**.