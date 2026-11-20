# Policies page — integration plan

Plan for building the redesigned Policies screen from `Policies Page.html` on
top of the existing policy backend. Every capability below was checked against
the source; line numbers are approximate and refer to this revision.

Status: **Phases 1 and 3 are implemented.** Phase 1 is the Policies screen
skeleton; Phase 3 is the configurable throttle rate. Phases 2, 4 and 5 have not
been started.

---

## 1. Decisions already made

| Question | Decision |
| --- | --- |
| Create/edit flow | Reuse `PolicyEditorDialog`. Do not build the mock's 3-step app-first wizard. |
| Throttle rate | Make the stored rate the enforced rate. Remove the fixed 51.2 KB/s behaviour. |
| Service/publisher scopes, Block direction | Leave as-is (stored-only / both directions). Document, do not fake. |
| Verify and Create actions | Page-body toolbar, not the shell header. |
| Phase 1 scope | Skeleton only: page, KPI live counts, empty state. No table. |

---

## 2. What already exists

| Need from the mock | Existing support | Verdict |
| --- | --- | --- |
| Policies screen slot | Sidebar item + placeholder page registered at `m_policiesIndex` (`src/core/mainwindow.cpp`) | Ready — swap the placeholder |
| Policy data model | `NetworkPolicy`, `PolicyStore` (QSettings, v2 JSON) in `src/network/policy.h` | Ready |
| Status: active / in window / expired / disabled | `policyActivationAt()`, `PolicyScheduler` (15 s) in `src/network/policyschedule.h` | Ready |
| Stored-only derivation | `policyEnforcementSummary()`, `policyScopeEnforcedByThisBuild()` in `src/network/policyscope.h` | Ready (definition differs from mock, see §4) |
| Schedule presets and custom windows | `scheduleWindowActive()`, `scheduleIsSupported()` | Ready |
| Expiration and notes | `NetworkPolicy::expiration`, `description` | Ready |
| Throttle / Block / Allow, direction, rate | `NetworkPolicy` + `EnforcementCoordinator` | Ready except fixed rate (§3) |
| Edit policy | `PolicyEditorDialog(const NetworkPolicy &)` | Ready to reuse |
| Delete with confirmation | Implemented inside `PolicyListDialog` | Logic exists, needs a page-callable API |
| Verify rules | `PolicyReconciler` produces `ReconciliationReport` | Needs exposing |
| Per-row enable toggle | No API; only Edit → State | Missing |
| Channel readiness (firewall, QoS, elevated) | `FirewallManager::isInitialized()`, `downloadLimiterStatus()`, no elevation check | Missing accessor |
| App list for "pick an app" | `NetworkWidget::applicationSnapshots()` (name, displayName, icon, path, publisher) | Ready — real data replaces the mock's fake list |
| Toast container | Only `SystemStatusBar::setMessage` | Missing; use the status bar |

The backend is roughly 80% present. The remainder is a thin `NetworkWidget`
policy API (refresh signal, verify, set-enabled, delete, channel readiness),
not new enforcement.

---

## 3. Making the throttle rate real (Phase 3 — implemented)

The stored rate used to be dropped in four places:

| File | What happens |
| --- | --- |
| `src/network/enforcementcoordinator.cpp` — `routeToThrottle()` | `policy.rateBitsPerSecond` is available but `applyForPolicy(path, id, automatic)` is called without it, then a "fixed rate" caveat is appended |
| `src/network/throttlepolicymanager.cpp` — `applyInternal()` | Hardcodes `DefaultLimitBitsPerSecond` for both the QoS request and the download shaper |
| `src/network/throttlepolicymanager.cpp` — `rebuildDownloadLimits()` | Re-applies the default on restore, discarding any stored rate |
| `src/network/throttlepolicymanager.cpp` — `load()` / `save()` | Persist path → policy id only, so per-path rates need an `activeLimits` map with a migration-safe read |

Everything downstream already accepted a rate: `ThrottleWorker::applyRequest(…,
limitBitsPerSecond)`, `ThrottleRequest::limitBitsPerSecond`, and
`DownloadShaper::setPolicies(QHash<QString, quint64>)`. This was plumbing, not a
new backend.

What changed:

- `EnforcementCoordinator::routeToThrottle()` passes `policy.rateBitsPerSecond`.
- `ThrottlePolicyManager::applyForPolicy()` and `applyInternal()` take the rate;
  0 falls back to `DefaultLimitBitsPerSecond`.
- The rate is kept in `m_pathLimits` and persisted as
  `BandwidthGuard/activeLimits`, so a restart, restore or verification
  reproduces the policy's rate. An older store without that key falls back to
  the default instead of failing to load.
- `rebuildDownloadLimits()` uses the stored rate, and a re-apply with a new
  rate updates the WinDivert shaper in place.
- Reconciliation carries the rate on `ReconciliationAction` and treats a limit
  enforced at another rate as needing re-application.

Fixed-rate copy removed in the same change:

- `src/network/policyruleform.cpp` — `"fixed 51.2 KB/s"` notes and the
  configured-vs-enforced comparison
- `src/network/policyscope.cpp` and `policyscope.h` —
  `kEnforcedThrottleBitsPerSecond` and its two caveat branches
- `docs/CREATE_POLICY.md` §10 "Known limitations"

---

## 4. Gaps the mock hides

1. **"Stored only" means unenforceable scope** in this build (`pid`,
   `publisher`, `service`), not "saved without a live rule". A missing firewall
   rule is only detectable via a reconciliation pass. The page derives the badge
   from scope and reports drift in the Verify banner instead.
2. **Block/Allow ignore direction** and always create both rules. The dialog's
   direction field is stored but unused by the firewall channel.
3. **No live refresh signal.** `PolicyScheduler` is private to `NetworkWidget`,
   so a page would go stale. Needs a re-emitted `policiesChanged()`.
4. **No page-callable actions.** `schedulePolicyReconciliation()`,
   `createPolicyForTarget()` and the reconciliation result slot are private.
5. **No elevation status.** The mock's "Elevated" label needs `IsUserAnAdmin()`
   or must be dropped.

---

## 5. Phases

Each phase compiles and runs on its own.

### Phase 1 — Skeleton (no backend change) — DONE

- New `src/ui/pages/policies/policiespage.{h,cpp}`.
- Replace the placeholder at `m_policiesIndex` in `src/core/mainwindow.cpp`.
- Add `setupPolicies()` and `refreshPolicies()` in
  `src/core/mainwindowpages.cpp`, refresh on navigation.
- Body toolbar with Verify / Create (disabled in this phase).
- KPI strip with live counts from `PolicyStore::loadPolicies()` +
  `policyActivationAt()`.
- Empty state via `EmptyStateWidget`.
- Declare the class in `src/core/mainwindow.h` / `mainwindow_p.h`, add sources to
  `Oasis.pro`.

*Done:* the placeholder is replaced by `PoliciesPage`, which shows the KPI
counts, the page-body toolbar (buttons disabled until Phase 4) and the empty
state. Not compiled in this environment at the author's request.

### Phase 2 — Read-only table

- `policiespage_models.{h,cpp}` following the `applicationspage_models` pattern.
- Columns: Application, Action & Limit, Window/Expires, Status & reason,
  Actions (read-only in this phase).
- Filter pills with counts and search over name, target, description, scope.
- Stored-only and unsupported states get their own labels; no silent merging.

*Done when:* every stored policy renders with the correct derived state and
search/filter behave.

### Phase 3 — Real throttle rates (backend, independent of the UI) — DONE

- Thread `rateBitsPerSecond` through `EnforcementCoordinator::routeToThrottle()`
  → `ThrottlePolicyManager::applyForPolicy()` → `applyInternal()`.
- Persist per-path rates and use them in `rebuildDownloadLimits()`.
- Remove the fixed-rate caveat copy (§3).
- Update `docs/CREATE_POLICY.md`.

*Done:* the release build is clean, the harness passes (1299 checks, 0
failures), and new checks cover the rate on the plan and a rate change forcing
re-application. End-to-end enforcement against a live elevated system was not
run from this environment.

### Phase 4 — Actions and Verify

- New `NetworkWidget` API: `policiesChanged()`, `verifyPolicies()`,
  `reconciliationFinished(report)`, `setPolicyEnabled(id, bool)`,
  `deletePolicy(id)`, `enforcementChannels()`.
- Wire the row enable toggle, edit, delete confirmation, Verify banner,
  last-verified timestamp in QSettings, Create via `showPolicyEditorFor()`.
- Sidebar/summary channel readiness uses the new accessor; drop or implement the
  "Elevated" label.

*Done when:* every row action round-trips through the store, audit log,
scheduler and reconciler.

### Phase 5 — Polish

- `src/ui/theme/styles/policies.qss`, registered in
  `ThemeManager::loadTemplate()` and `resources.qrc`.
- "No matching policies" state distinct from the empty state.
- Status-bar feedback instead of the mock's toast container.
- Update `docs/CREATE_POLICY.md`, `docs/Design/SCREENS_SPEC.md`.
- Harness checks for status bucketing, counts and search/filter.

---

## 6. Deliberately out of scope

- Service and publisher scopes stay stored-only.
- Block/Allow keep ignoring direction.
- No import/export UI.
- No 3-step wizard, no per-row rate popover.

---

## 7. Verification

- Build: `qmake Oasis.pro && mingw32-make` (not `run.sh`, which launches the app
  elevated).
- Harness: `tests/oasis_tests.pro`.
- Each phase states its own done-when above; enforcement changes in Phase 3 need
  a manual check against a real elevated system, which this plan cannot cover.
