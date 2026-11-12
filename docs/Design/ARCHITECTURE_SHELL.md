# Ultimate NetGuard AIO — Architecture & Shell Specification

**Target Platform:** Windows 10 / 11  
**UI Framework:** Qt 6 Widgets / C++  
**Scope:** Application window frame, navigation shell, user journeys, and Qt architectural boundaries.

---

## 1. Desktop Window Shell (`MainWindow`)

The application uses a persistent desktop shell composed of four regions:

```text
+-------------------------------------------------------------------+
| AppSidebar (232px) | AppHeader (60px)                             |
|                    +----------------------------------------------+
|  NETGUARD          |                                              |
|  MONITOR           |                                              |
|   - Overview       |               PageStack                      |
|   - Activity       |          (QStackedWidget)                    |
|   - Applications   |                                              |
|   - Connections    |         24px Horizontal/Vertical             |
|  CONTROL           |             Content Padding                  |
|   - Policies       |                                              |
|   - Insights       |                                              |
|  HISTORY           |                                              |
|   - Audit & Reports|                                              |
|                    |                                              |
|  Settings          |                                              |
|  Help & About      |                                              |
+--------------------+----------------------------------------------+
| SystemStatusBar (28px)                                            |
+-------------------------------------------------------------------+
```

### 1.1 Expanded Sidebar (`AppSidebar`)
* **Dimensions:** `232 px` fixed width (default). Designed to support a `64 px` collapsed mode in a future iteration.
* **Header Brand:** Displays **NETGUARD** (`14 px` Semibold) with subtitle *Network intelligence* (`11 px` Muted).
* **Navigation Structure:**
  * **MONITOR** (`11 px` uppercase section header, `#6C7586`)
    * `Overview` (`layout-dashboard`) — *Default landing screen*
    * `Activity` (`activity`)
    * `Applications` (`app-window`)
    * `Connections` (`network`)
  * **CONTROL**
    * `Policies` (`shield`)
    * `Insights` (`lightbulb`)
  * **HISTORY**
    * `Audit & Reports` (`clipboard-list`)
  * **Bottom Pinned Group** (separated by flexible spacer):
    * `Settings` (`settings`)
    * `Help & About` (`help-circle`)
* **Selection & Hover States:**
  * **Default:** Transparent background, `18 px` icon + `13 px` label in `#A1A9B7`.
  * **Hover:** `#2B3240` rounded fill (`6 px` radius), `#F3F5F8` text.
  * **Active:** Muted blue tint (`15% #4C8DFF`), `#4C8DFF` left indicator pill (`3 px` wide), `#F3F5F8` Semibold text, `#4C8DFF` icon.

### 1.2 Global Header (`AppHeader`)
* **Dimensions:** `60 px` fixed height, bottom `1px solid #343B48` border.
* **Left Region:**
  * Optional breadcrumb trail (`11 px` Muted, clickable to return to parent screen).
  * Page Title (`24 px` Semibold) + inline contextual subtitle (`12 px` Secondary).
* **Right Region:**
  * **Global Search (`SearchBar`):** `240 px` width quick-jump search across apps, domains, and policies.
  * **Notification Center (`bell`):** Icon button with unread count dot; opens non-blocking alert popover.
  * **Monitoring Health Pill (`StatusBadge`):** Live state (`Active`, `Degraded`, or `Stopped`). Clicking opens Diagnostics.
  * **Contextual Primary Action:** Optional single `ButtonPrimary` (e.g., `+ Create policy` on the Policies screen).
* **Rule:** Never place page-specific table filters inside `AppHeader`; filters belong inside the page workspace.

### 1.3 Global Status Bar (`SystemStatusBar`)
* **Dimensions:** `28 px` fixed height, `#171A21` background, top `1px solid #343B48` border.
* **Displayed Telemetry:**
  * **Left:** Capture & enforcement engine status (e.g., `Monitoring: Active` · `Adapter: Ethernet (Intel I225-V)`).
  * **Center/Warning Slot:** Interactive amber/red warning link if any driver or permission is degraded (e.g., `WinDivert unavailable — policies will save as Stored Only`). Clicking navigates directly to `Settings > Diagnostics`.
  * **Right:** Architecture mode indicator (`Local-first`) and last telemetry refresh timestamp.

---

## 2. Core Application Flows

### 2.1 First-Time User Onboarding Flow
Designed to be transparent, local-first, and **skippable at any step** so users are never blocked from viewing their traffic.
1. **Welcome:** Explains NetGuard's purpose and local-first architecture (no cloud account required).
2. **System Readiness Check:** Runs automated checks on Administrator/elevation privileges, active network adapters, and enforcement drivers (Windows Firewall, QoS, WinDivert). Reports exact capability status honestly.
3. **Privacy Disclosure:** Explains what metadata is collected locally, retention limits, and confirms that packet payloads are never stored and remote AI is disabled by default.
4. **Preferences:** Quick toggles for launch-at-startup and notification alerts.
5. **Ready:** Transitions directly to `Overview` reflecting true system readiness.

### 2.2 Application Restriction Flow
1. User navigates to **Applications** (or clicks a top consumer on **Overview**).
2. User double-clicks an application row (or right-clicks → *Manage traffic*) to open **Application Details**.
3. User clicks **Manage traffic** (Primary) or **Block network access** (Danger).
4. **Policy Editor Dialog** opens pre-populated with the target application identity/executable path.
5. User configures Action (`Throttle`, `Block`, `Allow`, `Notify`), Direction (`Download`, `Upload`, `Both`), Rate limit, and Duration.
6. **Policy Review & Confirmation Dialog** displays:
   * Exact target scope and breadth (e.g., single executable vs. process tree).
   * Whether future matching processes are affected.
   * Whether the current build/permissions support live enforcement for this scope.
   * *Safety Rule:* For broad scopes, confirmation focus defaults to **No / Cancel**.
7. User confirms → UI invokes backend policy service → UI displays **actual enforcement outcome** (`Active` if enforced, `Stored only` if enforcement channel is unavailable, or `Failed` with error details).

### 2.3 Unexpected Traffic Investigation Flow
1. NetGuard detects anomalous bandwidth consumption or unassociated traffic and surfaces an alert in **Insights** and the **Notification Center**.
2. User clicks the notification or **Review →** on the Insight card.
3. NetGuard opens the contextual evidence view showing:
   * Observed behavior and timeframe.
   * Associated application identity and attribution confidence (`Confirmed`, `Likely`, `Possible`, `Unknown`).
   * Observed destinations (Domain/IP, port, protocol).
4. User chooses one of three explicit actions:
   * **Inspect connections:** Jump to `Connections` pre-filtered to that app/endpoint.
   * **Create policy:** Launch `PolicyEditorDialog` pre-filled with the target.
   * **Dismiss:** Mark insight as reviewed (logged in `Audit & Reports`).

### 2.4 Policy Enforcement Failure & Recovery Flow
When a restriction fails to apply at the OS/driver layer, NetGuard must never show a generic "Policy Saved" toast.
1. Backend enforcement service returns an error state for one or more channels (Firewall / QoS / WinDivert).
2. UI presents an explicit **Policy Enforcement Failed** banner/dialog detailing:
   * **Policy Name & Target**
   * **Requested Action** (e.g., *Download throttle 1.0 Mbps*)
   * **Failed Enforcement Channel** & human-readable error reason
   * **Partial Enforcement Status** (whether any secondary channel succeeded, or if status is `Failed — not enforced`)
3. **Recovery Actions Provided:**
   * `Retry enforcement` (re-attempts OS registration)
   * `Keep as Stored only` (retains rule definition without claiming enforcement)
   * `Open diagnostics` (navigates to `Settings > Diagnostics` to inspect driver/privilege health)

---

## 3. Qt Implementation Architecture (`src/ui/`)

### 3.1 Proposed UI Directory Layout
```text
src/ui/
├── shell/
│   ├── mainwindow.h / .cpp          # Top-level QMainWindow container
│   ├── appsidebar.h / .cpp          # Expanded navigation sidebar
│   ├── appheader.h / .cpp           # Persistent 60px page header
│   └── systemstatusbar.h / .cpp     # Persistent 28px diagnostic status bar
├── pages/
│   ├── overview/                    # OverviewPage
│   ├── activity/                    # ActivityPage
│   ├── applications/                # ApplicationsPage
│   ├── connections/                 # ConnectionsPage
│   ├── policies/                    # PoliciesPage
│   ├── insights/                    # InsightsPage
│   ├── reports/                     # AuditReportsPage
│   └── settings/                    # SettingsPage (categorized sub-views)
├── components/
│   ├── metriccard.h / .cpp
│   ├── statusbadge.h / .cpp
│   ├── trafficchart.h / .cpp
│   ├── searchbar.h / .cpp
│   ├── filterbar.h / .cpp
│   ├── emptystatewidget.h / .cpp
│   └── notificationtoast.h / .cpp
├── dialogs/
│   ├── applicationdetaildialog.h / .cpp
│   ├── policyeditordialog.h / .cpp
│   ├── policyconfirmationdialog.h / .cpp
│   └── recommendationdialog.h / .cpp
└── theme/
    ├── colors.h                     # Hex color constants
    ├── typography.h                 # Font size/weight helpers
    ├── dimensions.h                 # 4px spacing & widget size constants
    ├── thememanager.h / .cpp        # Loads styles.qss & handles DPI scaling
    └── styles.qss                   # Global Fluent dark stylesheet
```

### 3.2 Layered Separation of Concerns
The UI layer is strictly a presentation and interaction layer. It must never duplicate network monitoring or OS enforcement logic.

```text
+-------------------------------------------------------------------+
| Presentation Layer (Qt Widgets)                                   |
| Pages, Dialogs, Custom Components, QTableView                     |
+---------------------------------+---------------------------------+
                                  | Signals / Slots & QAbstractItemModel
+---------------------------------v---------------------------------+
| UI ViewModels / Controllers                                       |
| Formatting (MB/s), Selection preservation, Filter proxy state     |
+---------------------------------+---------------------------------+
                                  | Thread-safe Service Interfaces
+---------------------------------v---------------------------------+
| Core Backend Services (Background Threads)                        |
| NetworkMonitor, PolicyEngine, IdentityResolver, AuditLogger       |
+---------------------------------+---------------------------------+
                                  | OS APIs
+---------------------------------v---------------------------------+
| Windows Integrations                                              |
| Windows Filtering Platform (Firewall), QoS, WinDivert, IP Helper  |
+-------------------------------------------------------------------+
```

### 3.3 Qt-Specific Performance & Reliability Rules
1. **Single Shared Service Instances:** `MainWindow` receives references/pointers to shared backend controllers (`NetworkMonitor`, `PolicyManager`, `AuditService`). Individual pages must never instantiate their own capture or enforcement managers.
2. **Off-Main-Thread Execution:** All packet inspection, DNS/SNI correlation, SQLite audit writes, and Windows firewall/driver calls must run on worker threads (`QThread` / `QtConcurrent`). The UI thread only renders pre-aggregated snapshots.
3. **Model/View & Proxy Filtering:**
   * Back `Applications` and `Connections` tables with custom `QAbstractTableModel` subclasses.
   * Wrap models in `QSortFilterProxyModel` for instant search, status filtering, and column sorting without mutating underlying telemetry arrays.
4. **Selection Preservation Across Refreshes:**
   * Telemetry updates occur at ~1-second intervals. Do **not** call `beginResetModel()` on every tick.
   * Emit `dataChanged(topLeft, bottomRight)` for updated bandwidth cells and use `beginInsertRows` / `beginRemoveRows` only when processes enter or exit. This guarantees the user's selected row and scroll position never jump during live monitoring.
5. **Persistent Preferences:** Store UI-only state (visible table columns, window geometry, active theme settings) in `QSettings`, separate from security policies and audit logs.