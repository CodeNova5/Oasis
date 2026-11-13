# Oasis — Implementation Roadmap & QA Checklist

**Target Platform:** Windows 10 / 11  
**UI Framework:** Qt 6 Widgets / C++  
**Scope:** Implementation priority matrix, 7-phase delivery roadmap, prototype sequence, and Visual QA sign-off criteria.

---

## 1. Screen & Component Priority Matrix

Deliverables are split into **P0 (Core Foundation & Daily Workflows)** and **P1 (Deep Intelligence & Supporting Views)**.

| Priority | Deliverable | Target Files / Modules | Architectural Rationale |
| :--- | :--- | :--- | :--- |
| **P0** | Design Tokens & Theme Manager | `src/ui/theme/*` (`colors.h`, `styles.qss`) | Every widget, card, badge, and dialog depends on the token system. |
| **P0** | Main Window & Navigation Shell | `src/ui/shell/*` (`MainWindow`, `AppSidebar`, `AppHeader`, `SystemStatusBar`) | Establishes the persistent desktop frame, routing, and diagnostic visibility. |
| **P0** | Atomic Components | `src/ui/components/*` (`MetricCard`, `StatusBadge`, `SearchBar`, `FilterBar`) | Reusable building blocks required across all screens. |
| **P0** | Overview (`Screen 01`) | `src/ui/pages/overview/*` | Default landing page; delivers immediate situational awareness. |
| **P0** | Applications (`Screen 03`) | `src/ui/pages/applications/*` | Primary daily workflow for identifying bandwidth consumers. |
| **P0** | Application Details (`Screen 04`) | `src/ui/dialogs/applicationdetaildialog.*` | Core investigation and single-app control workspace. |
| **P0** | Policies & Editor (`Screen 06`) | `src/ui/pages/policies/*`, `policyeditordialog.*`, `policyconfirmationdialog.*` | Core network control workflow and truthful enforcement feedback. |
| **P1** | Activity (`Screen 02`) | `src/ui/pages/activity/*` | Time-oriented historical bandwidth analysis. |
| **P1** | Connections (`Screen 05`) | `src/ui/pages/connections/*` | Endpoint/domain attribution and raw IP inspection. |
| **P1** | Insights (`Screen 07`) | `src/ui/pages/insights/*`, `recommendationdialog.*` | Anomaly recommendations and gated AI explanation layer. |
| **P1** | Audit & Reports (`Screen 08`) | `src/ui/pages/reports/*` | Event traceability and redacted CSV/JSON exports. |
| **P1** | Settings & Diagnostics (`Screen 09`) | `src/ui/pages/settings/*` | Privacy disclosures, driver capability matrix, and support logs. |

---

## 2. First Visual Prototype Strategy

Before building all nine destinations, validate proportions, typography, and component density using a **3-screen vertical slice**:

1. **Overview (`Screen 01`):** Validates KPI card proportions, chart styling, and dark surface hierarchy.
2. **Applications (`Screen 03`):** Validates `48 px` table row density, filter pills, typography hierarchy, and status badges.
3. **Policies (`Screen 06`):** Validates modal form ergonomics, impact previews, and truthful `Active` vs. `Stored only` states.

Once these three screens pass visual inspection across Windows scaling levels, roll out the exact same patterns to the remaining P1 screens.

---

## 3. Phased Delivery Roadmap

### Phase 1 — Design Foundation
* Implement `colors.h`, `typography.h`, `dimensions.h`, and `ThemeManager`.
* Author `styles.qss` covering scrollbars, menus, tooltips, inputs, and buttons (`Primary`, `Secondary`, `Ghost`, `Danger`).
* Build core atomic widgets (`MetricCard`, `StatusBadge`, `SearchBar`, `FilterBar`, `EmptyStateWidget`, `NotificationToast`).

### Phase 2 — Application Shell & State Plumbing
* Map existing repository folders to `src/ui/` without breaking backend service bindings.
* Implement `MainWindow` with `AppSidebar` (`232 px`), `AppHeader` (`60 px`), `QStackedWidget`, and `SystemStatusBar` (`28 px`).
* Wire global monitoring state and diagnostic warning links to `SystemStatusBar`.

### Phase 3 — Core P0 Visibility & Investigation
* Build `OverviewPage` connected to live monitoring and policy summary models.
* Implement `ApplicationsPage` backed by `QAbstractTableModel` + `QSortFilterProxyModel` with selection-preserving 1-second updates.
* Build the 5-tab `ApplicationDetailDialog` (`Overview`, `Traffic`, `Connections`, `Controls`, `History`).

### Phase 4 — Network Control & Policy Enforcement
* Build `PoliciesPage` with KPI summary strip and rule table.
* Implement `PolicyEditorDialog` with live capability detection and impact preview.
* Implement `PolicyConfirmationDialog` (defaulting broad scopes to **No/Cancel**) and the **Policy Enforcement Failure** recovery flow.

### Phase 5 — Network Intelligence (Time & Endpoints)
* Build `ActivityPage` with interactive timeline brush selection and time-bucketed records.
* Build `ConnectionsPage` with split detail drawer and strict `Unknown` attribution enforcement (no reverse-DNS guessing).

### Phase 6 — Insights, Audit & Settings
* Build `InsightsPage` and `RecommendationDialog` answering the 7 core evidence questions, keeping unwired AI capabilities explicitly marked as unavailable.
* Build `AuditReportsPage` with destination redaction indicators and CSV/JSON export dialogs.
* Refactor `SettingsPage` into the 8 categorized sub-views with explicit local-first privacy disclosures and driver capability checks.

### Phase 7 — Visual QA & Release Hardening
* Execute the full Visual QA Checklist (Section 4) across target Windows 10 and Windows 11 configurations.
* Resolve layout clipping, focus ring inconsistencies, and high-DPI scaling defects.

---

## 4. Visual & Functional QA Sign-Off Checklist

Before marking the UI redesign complete, every item below must be verified on a live build:

### 4.1 Layout, Typography & High-DPI Scaling
* [ ] **Windows DPI Scaling:** Verified at **100%**, **125%**, **150%**, and **200%** scaling with zero clipped labels, overlapping controls, or truncated button text.
* [ ] **Window Resizing:** Tables and split cards remain legible and usable down to a `1024 x 720` minimum window size.
* [ ] **Spacing Consistency:** All margins and gaps adhere strictly to the `4 px` grid (`16 px` card gaps, `24 px` page padding).
* [ ] **Visual Restraint:** Zero unnecessary gradients, drop shadows, or decorative animations; `Segoe UI Variable` (with `Segoe UI` fallback) renders consistently.
* [ ] **Dark Theme Completeness:** Native menus, right-click context menus, scrollbars, and dialogs inherit dark surfaces (`#1C2029` / `#242A35`) without white flashes.

### 4.2 Data Integrity & Table Behavior
* [ ] **Selection Preservation:** Selecting a row in `Applications` or `Connections` survives 1-second live telemetry ticks without jumping or resetting scroll position.
* [ ] **Truthful Enforcement States:** Saving a policy when an enforcement driver is unavailable displays `Stored only` (Amber) rather than `Active` (Green).
* [ ] **Truthful Attribution:** Unresolved endpoints display raw IPs and `Unknown` badges rather than fabricated or guessed hostnames.
* [ ] **Unwired Feature Honesty:** Any backend capability not yet live (e.g., remote AI provider) is clearly represented as unavailable/disabled rather than mocked.

### 4.3 Edge States & Accessibility
* [ ] **Complete Edge Coverage:** `Loading`, `Empty`, `Partial/Degraded`, `Error`, `Permission Required`, and `Stale Data` states are implemented and reachable on every major screen.
* [ ] **Keyboard Navigation:** Full `Tab` / `Shift+Tab` traversal works across sidebar items, filter pills, tables, and modal forms.
* [ ] **Visible Focus Rings:** Focused controls display a clear `#4C8DFF` outline for keyboard users.
* [ ] **Safe Defaults:** Broad-scope policy confirmation dialogs default focus to **Cancel / No**.
* [ ] **Contextual Tooltips:** Technical terms (`Stored only`, `Attribution confidence`, `WinDivert`, `SNI`) include plain-English hover tooltips.