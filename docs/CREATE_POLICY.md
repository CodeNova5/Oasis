# Create Policy — capabilities and generated rules

Reference for what the **Create policy** flow can do in this build, what it
stores, and which Windows rules it creates. Derived from the source, not the
design mock-ups; where the implementation is narrower than
`docs/Design/SCREENS_SPEC.md`, that is called out under
[Known limitations](#known-limitations).

Primary sources:

- `src/network/policyeditordialog.*` — the dialog
- `src/network/policyscope.*` — scope wording, impact preview, enforcement notes
- `src/network/policyschedule.*` — recurring windows and activation
- `src/network/policy.*` — `NetworkPolicy`, `PolicyStore`
- `src/network/networkwidget.cpp` — save, audit, scheduler wiring
- `src/network/enforcementcoordinator.*`, `enforcementrestore.*` — channel routing
- `src/firewall/firewallmanager.*`, `src/firewall/rulenames.*` — rule mechanics
- `src/network/policyreconcile*` — verification and withdrawal

---

## 1. Where it opens

| Entry point | What it prefills |
| --- | --- |
| Applications page → right-click a row → **Create policy** | PID, process name, executable path, publisher, first service, activity-group name/id |
| Activity page → process action **Create policy** | Same target derived from the activity's process |
| Application detail dialog → **Create policy…** | Same, from the detail's identity |
| Network page process context menu → **🛡 Create policy...** | Same, from the selected process row |
| Policies… dialog → **Edit...** (double-click too) | Reopens the same editor with the stored policy, keeping its id and source |

The target is assembled by `NetworkWidget::policyTargetFor()` from the row, its
path, and its activity group. The editor itself is `PolicyEditorDialog`.

There is also **Review AI explanation & approve policy...**, which creates a
policy through a separate approval dialog; it writes the same `NetworkPolicy`
structure and is listed alongside editor-created policies.

---

## 2. Dialog fields

The dialog is a frameless 520 px rounded card (576 px window including its drop
shadow) with four numbered sections: **Target application**, **Traffic action &
limit**, **Schedule, expiration & note**, and a **Live policy summary**, followed
by a sticky Cancel / Save Policy footer. The form above scrolls within the
card, while the footer stays visible, and the dialog is capped to the screen
height and centred. It is built in C++ and uses the bundled Inter and
JetBrains Mono faces so it matches the design mockup on any machine.

### Scope

Five scopes, matching PRD 9.3. Only one is chosen per policy.

| Scope (stored key) | Breadth | Covers | Future processes | Enforced by this build |
| --- | --- | --- | --- | --- |
| This process only (`pid`) | Narrowest | This process instance while it runs; a restart, respawn, or reused PID is not followed | No | No — stored only |
| This executable path (`path`) | One file | The file at this path, now and on later runs; a copy elsewhere or update to a new path is not covered | Yes | **Yes** |
| This publisher (`publisher`) | Broad | Every process signed by that publisher, including products not seen yet | Yes | No — stored only |
| This Windows service (`service`) | One service | The service and the processes hosting it, including later instances | Yes | No — stored only |
| This application group (`group`) | Broad | Every current and future member of the activity group, including helpers and updaters | Yes | **Yes** (running members) |

Target-field behaviour:

- **PID** and **group** targets are read-only. PID shows `PID <n> (<name>)`;
  group shows `<group name> (<group id>)`.
- **Path**, **publisher**, and **service** are editable text, prefilled when the
  row/group knows the value and left blank for the user to type otherwise.
- Switching scope rewrites the target field, so a path is never carried into a
  publisher policy.
- The stored `targetId` is: the numeric PID as text, the path, the publisher
  string, the service name, or the activity-group **id** (not its name).
- The narrow **executable path** scope is the default selection.

### Effect

| Control | Values | Default | Notes |
| --- | --- | --- | --- |
| **Action** | Throttle, Block, Allow cards; Notify, Ask, No action advisory chips | Throttle | `Schedule` exists in the data model but is not offered here |
| **Direction** | Download, Upload, Both directions | Both | Enabled only for Throttle; stored for every action |
| **Rate limit** | 1–1000000 KB/s, integer, suffix `KB/s`; preset chips 50 / 250 / 500 / 1024 | 400 | Shown only for Throttle; stored as `KB/s × 8000` bits/s |
| **Recurring window** | Combo: Always (24/7), Work hours, Overnight, or Custom; Custom accepts `22:00-06:00`, `Mon-Fri 09:00-17:00`, etc. | Always | Validated with `scheduleIsSupported()`; lives in the collapsible group |
| **Expiration** | Optional checkbox + date/time picker (`yyyy-MM-dd HH:mm`, calendar popup) | off; picker defaults to now + 1 h | Must be in the future |
| **Note** | Single-line text | blank | Saved as `description` |
| **State** | Enabled toggle in the summary card | on | Disabled policies are stored but not enforced |

### Live policy summary

Rebuilt on every control change, in the dialog's own rich-text form rather than
`policyImpactSummary()` (which still supplies the broad-scope confirmation). It
states:

- the resolved target in monospace;
- the chosen effect, e.g. `Throttle traffic for app.exe to 400 KB/s in both
  directions`;
- when it is active (`active immediately`, work hours, overnight, or the custom
  window);
- duration (`with no expiration` or `until <timestamp>`);
- enabled/disabled — a disabled policy reads `Saved inactive — will … once
  enabled.` and the card greys out;
- the enforcement note: `Enforced: …` for path/group, or
  `Stored only: this build cannot resolve <scope> policies …`.

For Throttle the stored rate is the rate both shaping halves request, so the
enforcement note matches the impact summary instead of adding a caveat. The
collapsible group's header shows `(Configured)` once a window or expiration is
set, and the disclosure animates open/closed.

---

## 3. Recurring windows

Evaluated in **local time** by `matchSchedule()`.

| Form | Meaning |
| --- | --- |
| empty, `always`, `*` | always in force |
| `work-hours` | Monday–Friday, 09:00–17:00 |
| `overnight` | every day, 22:00–06:00 (crosses midnight) |
| `HH:MM-HH:MM` | every day; may cross midnight |
| `<days> HH:MM-HH:MM` | day filter plus window |

Days may be a single name, a comma list (`Mon,Wed,Fri`), or a range including a
week wrap (`Fri-Mon`). Names are case-insensitive and may be three-letter or
full (`Monday`). A window crossing midnight belongs to the day it started, so at
01:00 Saturday a `Fri 22:00-06:00` window is still Friday's.

Anything else — including network-profile conditions such as metered
connections — is **Unsupported**, not silently treated as on or off.

### Activation states

Activation is derived at read time and never persisted
(`policyActivationAt()`), so a boundary that passed while the app was closed is
correct on the next evaluation.

| State | Meaning |
| --- | --- |
| `active` | enabled, not expired, and inside its window (or has none) |
| `inactive` | enabled but outside its recurring window |
| `expired` | its expiration has passed |
| `disabled` | the user's switch is off |
| `unsupported` | the window cannot be parsed |

`PolicyScheduler` evaluates immediately on start and every **15 s**, emitting a
change only when a policy's state actually moves.

---

## 4. Validation and confirmation

`PolicyEditorDialog::accept()` refuses to save when:

- scope is PID but no PID was prefilled;
- scope is group but the process has no group id;
- path/publisher/service target is empty;
- the recurring window is not recognised;
- action is Throttle and the rate is not above zero;
- **Expires** is checked with a time at or before now.

Field errors are reported in a transient toast over the bottom of the card and
focus the offending field, rather than opening a warning message box.

Before saving, **publisher** and **application-group** policies that are
**enabled** trigger a confirmation dialog (`policyConfirmationText()`):

- names what will be covered — `every process signed by "<publisher>"` or
  `every member of the group "<group>", including members that join later`;
- embeds the full impact summary;
- warns that broad scopes cover software the user did not select and that the
  policy stays in force until deleted.

**No** is the default button, so an accidental Enter does not widen enforcement.
Disabled broad policies do not prompt, because they have no effect.

---

## 5. What Save does

1. Builds a `NetworkPolicy`:
   - `id` = `policy-<uuid>` for new policies; the existing id is kept when editing;
   - `scope` = `pid` / `path` / `publisher` / `service` / `group`;
   - `targetId` as described above;
   - `direction`, `action`, `rateBitsPerSecond` (0 unless Throttle or the hidden
     Schedule action);
   - `schedule` and `expiration`;
   - `scheduleType` = `None`, `Recurring`, `Expiration`, or `Both` from which
     of window/expiration are set;
   - `source` = `user` (kept on edit, so a user policy cannot quietly become
     removable by emergency restore);
   - `enabled` and `description`.
2. Appends it to `PolicyStore` (QSettings group `Oasis/Policies`, version 2 JSON
   array) and warns if the write fails.
3. Appends an audit event: type `PolicyChange`, scope, reason
   `user created a policy`, result `saved`, related policy id, and the note.
4. Puts `Policy saved.` in the status line.
5. Runs `PolicyScheduler::evaluateNow()` immediately, which is how a policy that
   is already active gets applied without waiting for the 15 s tick.

Editing in the Policies dialog replaces the row in place, keeps the id and
source, saves, and re-evaluates the scheduler. Deleting asks for confirmation,
removes the row, saves, and schedules reconciliation.

> Import/export (`PolicyStore::exportPoliciesJson()` /
> `importPoliciesJson()`) exist in the store but have **no UI caller** in this
> build.

---

## 6. Enforcement: what actually happens

### Channel per action (`plannedChannels()`)

| Action | Channel |
| --- | --- |
| Block | Windows Firewall |
| Allow | Windows Firewall |
| Throttle | Shaping: QoS upload and/or WinDivert download depending on direction |
| Schedule | Shaping (same as Throttle) |
| Notify, Ask, No action | None — advisory only |
| any action, policy disabled | None |

Direction selects shaping halves independently:

- Download → WinDivert download only
- Upload → QoS upload only
- Both → both

### Scope resolution (`NetworkWidget::onPolicyActivationChanged()`)

When a policy becomes **active**:

- **path / executable** → `EnforcementCoordinator::applyPolicy(policy, targetId)`.
- **group** → the policy is re-applied to the executables currently in that
  group (`reapplyGroupPolicies()`). Each `(group id, policy id, lowercased path)`
  triple is applied once, so a replacement at a new path gets its own rule while
  a respawn at the same path does not duplicate it. Future members are covered
  when they join. Hard failures are not remembered, so the next snapshot retries.
- **pid / publisher / service** → nothing is applied; the policy is stored only.

When a policy becomes **inactive, expired, disabled, or unsupported**,
reconciliation is scheduled to withdraw rules attributed to it.

### Results

- Firewall rule created → status `Applied`.
- Shaping request handed to the worker → status `Requested` (the PowerShell /
  WinDivert work happens off the GUI thread; `Partial` is declared but not yet
  produced).
- Disabled policy, advisory action, or throttle without a rate → `NotApplied`
  with the reason.
- Missing manager, failed firewall init, or empty path → `Failed` with the
  channel error.

---

## 7. Firewall rules that are generated

Create Policy does not create arbitrary port/protocol rules. Block and Allow
produce **two per-application rules per executable**.

For a path `C:\Program Files\App\app.exe` and a Block policy:

| Rule | Direction | Action | Protocol | Profiles | Enabled |
| --- | --- | --- | --- | --- | --- |
| `Oasis_app_<sha1-10>_BLOCK_OUT` | Outbound | Block | Any | All | yes |
| `Oasis_app_<sha1-10>_BLOCK_IN` | Inbound | Block | Any | All | yes |

For Allow the suffixes are `ALLOW_OUT` / `ALLOW_IN` with action Allow.

Details:

- **Name**: `firewallRuleName()` = `Oasis_<completeBaseName>_<first 10 hex chars
  of SHA-1 of the normalized lowercase native path>_<SUFFIX>`. The basename is
  shortened to 40 characters for display; the hash is what makes it unique.
- **Description**: `Oasis policy <policy id>` for a policy-created rule, which
  is how reconciliation attributes it. A rule created directly from the
  Firewall tab says `Managed by Oasis`.
- **Grouping**: `Oasis`.
- **ApplicationName**: the expanded, cleaned native executable path.
- **Protocol**: `NET_FW_IP_PROTOCOL_ANY` (any).
- **Profiles**: `NET_FW_PROFILE2_ALL` (domain, private, public).
- **Direction**: Block/Allow always create **both inbound and outbound** rules.
  The dialog's Direction field is disabled except for Throttle and is ignored by
  the firewall channel.
- **Before adding**, the manager removes any rule already using that exact name
  and the legacy base-name-only name (`Oasis_<basename>_<SUFFIX>`) an older
  build may have written, so an upgrade does not leave duplicates.
- **Fallback**: `netsh advfirewall firewall add rule …` helpers exist in
  `FirewallManager`, but `blockApp()`/`allowApp()` do not call them in this
  build; a COM failure is reported as `Failed`, not retried through netsh.
- `FirewallManager::isBlocked(path)` reports "blocked" when an outbound block
  rule exists for the path (current or legacy name); it does not check the
  rule's enabled flag.

Rules the Firewall tab creates on the user's behalf carry no policy id and are
never removed by policy reconciliation or emergency restore.

---

## 8. Lifecycle: verification and withdrawal

`PolicyReconciler` compares stored active policies with what Windows reports,
off GUI thread, and repairs the difference.

- **Startup**: if the firewall is initialized, one pass runs 8 s after launch.
- **On demand**: **Verify...** in the Policies dialog.
- **After changes**: leaving a window, expiring, editing, deleting, or
  emergency restore triggers a pass.

What a pass can do:

| Situation | Action |
| --- | --- |
| Active path policy with no matching attributed firewall rule | Create the block/allow rules |
| Active throttle policy with no limit | Apply throttle |
| Rule/limit attributed to a policy that is no longer active | Remove it |
| Limit with no policy attribution | Report and leave in place |
| Rule with no policy attribution (Firewall tab) | Report and leave in place |
| Unresolvable scope or conflict | Report as unresolved |

Only rules whose description parses as `Oasis policy <id>` are ever removed.
The report distinguishes repaired, removed, failed, unattributed, and unresolved
counts.

**Emergency restore** removes only policies whose `source` is `automatic`,
`system`, or `ai`. Everything created through Create Policy has
`source = user`, so it survives emergency restore. Anything with an unset or
unrecognised source is also preserved.

---

## 9. Policies dialog (companion surface)

Toolbar **Policies…** lists every stored policy with columns: State, Scope,
Target, Action, Direction, Rate, Window, Expires, Enforcement, Source.

- Summary counts stored policies and how many are "stored only".
- **Edit...** / double-click reopens the editor, keeping id and source. Scopes
  the editor cannot represent (`port`, `protocol`, `package`) are refused with
  an explanation rather than rewritten.
- **Delete** confirms ("This cannot be undone"), saves, then reconciliation
  withdraws the attributed rules/limits.
- **Verify...** runs a reconciliation pass and shows the report.
- There is no separate enable/disable toggle; use Edit → State.
- The dialog reloads from `PolicyStore` after every change and sets `changed()`
  so the caller re-evaluates the scheduler and forgets stale re-application
  bookkeeping.

---

## 10. Known limitations

- **Throttle rate**: the stored rate is applied. `ThrottlePolicyManager`
  persists the per-path rate with the active set, so a restart, restore or
  reconciliation pass reproduces the policy's rate instead of a default. A
  rate of 0 falls back to `DefaultLimitBitsPerSecond` (409600 bits/s).
- **PID, publisher, and service scopes are stored only.** No rule or limit is
  created for them. Only `path`/`executable` and `group` are resolved.
- **Package, port, and protocol scopes** exist in `NetworkPolicy` but are not
  offered by the editor and cannot be edited in the Policies dialog.
- **The `Schedule` action** exists in the data model and routes to shaping, but
  is not offered as a card/chip. An existing Schedule policy keeps its action
  when edited through the hidden mapping.
- **Direction is only meaningful for Throttle.** Block/Allow always create both
  inbound and outbound rules. Direction is stored but ignored by the firewall
  channel.
- **Recurring windows are local-time only.** Metered/profile conditions are
  unsupported and report `Unsupported`.
- **Boundary latency**: the 15 s scheduler tick can start or end a window up to
  15 s late.
- **No import/export UI**, and import performs no schema or provenance
  validation (tracked as open finding F-03 in `docs/THREAT_MODEL.md`).
- **Policy storage is per-user QSettings** (`HKCU`). An elevated app applies
  whatever it loads, which is tracked as open finding F-02.
- **No live end-to-end run** of firewall/QoS/WinDivert enforcement is recorded;
  the enforcement matrix is covered by the harness but not against a real
  elevated system.
- The published design spec (`SCREENS_SPEC.md`) promises a segmented action
  selector, a unit dropdown (Kbps/Mbps), duration presets (1 hour / custom), a
  `PolicyConfirmationDialog`, and per-policy toggle in the table. The
  implementation instead uses action cards with a KB/s rate, an optional
  expiration plus recurring window, a `QMessageBox` confirmation for broad
  scopes, and edit-based state changes.
