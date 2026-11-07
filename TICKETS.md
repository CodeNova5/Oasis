# Ultimate NetGuard AIO: Product Tickets

This backlog implements [PRD.md](PRD.md). Tickets are ordered by dependency inside each phase. `P0` means required for the first release of this product direction; `P1` means important follow-up; `P2` means optional or later.

## Ticket conventions

- **Type:** feature, refactor, bug, test, documentation, or security.
- **Status:** `Done`, `Partial`, or `Not started`, summarized in [Current status](#current-status). A ticket with no status line is `Not started`.
- **Dependencies:** tickets that should land first.
- **Acceptance criteria:** observable completion conditions.

## Current status

Last updated: 2026-11-07. Status values: **Done** (acceptance criteria met and verified), **Partial** (code exists but acceptance criteria are unmet or unverified), **Not started** (proposed, no code).

The application builds with Qt 6.11.1 / MinGW 13.1 (`qmake UltimateNetGuard.pro`, then `mingw32-make -j4`). Two warnings remain: unused `buildIpv6TcpPacket()` in `testfixtures.cpp` and unused `EnableDebugPrivilege()` in `networkwidget.cpp`. NG-011, NG-012, NG-013, and NG-014 have been validated at runtime so far (standalone harnesses on Windows 10 19045); no part of the GUI has been exercised.

| Ticket | Status | Implemented | Remaining |
| --- | --- | --- | --- |
| NG-001 | Partial | `src/network/testfixtures.*`: builders for browser download, updater, Windows service, DNS, TLS, VPN, unknown, game launcher, and IDE update, plus `runAllFixtures()` with identity assertions | Respawn-worker fixture added (`createRespawnWorkerFixture()`); `runAllFixtures()` now iterates all fixtures including respawn; identity/category assertions are recorded but not fully validated without `classifyProcess` integration; no Windows 10/11 run |
| NG-002 | Partial | `src/network/policy.*`: identity, observation, policy, throttle-result, and audit-event structs with Qt metatypes and JSON helpers | Contract schema version added; `ThrottleResult` renamed to `NetworkPolicyThrottleResult` to avoid collision with `throttlebackend.h`; no round-trip test; no production consumer yet |
| NG-003 | Partial | `src/network/diagnostics.*`: bounded `DiagnosticsModel` (500 records) with typed reasons, table columns, summary counts, and versioned JSON export; `NetworkMonitor` emits aggregated gap signals (drops, unresolved PIDs, unknown direction, stale mappings, adapter failures); `NetworkWidget` feeds the model; Settings tab has a Diagnostics support view with export and clear | Not exercised at runtime; no automated coverage for the export schema or the gap signals |
| NG-010 | Partial | `src/identity/applicationidentity.*`: canonical-path resolution, version metadata, SHA-1 identity IDs, typed failures, and `QSettings` `IdentityStore` (schema 1); live monitoring now resolves identities for PIDs that own connections (cached per PID, pruned when the PID disappears), attaches them to captured packets, shows the resolver display name in the process tree, and records typed resolution failures as diagnostics. Publisher and signer evidence now come from NG-011 | Path equivalence, typed failures, and restart persistence untested at runtime; PID reuse is now guarded by process start time (NG-013) |
| NG-012 | Partial | `src/identity/serviceresolver.*`: one SCM enumeration per 2 s window (cached) instead of one per svchost PID per loop, PID → service map with service key, display name, `QueryServiceConfig` image path, and runtime state; `NetworkMonitor` names any service host after its service and publishes the per-PID service map only when it changes; `NetworkTreeModel` draws each hosted service as its own row under the host (state, image path in the tooltip) so services sharing one `svchost.exe` stay separable; `DiagnosticsModel::reportServiceLookupFailed` records SCM failures without touching capture | Service rows, snapshot streaming, and the resolver verified on Windows 10 19045 with a standalone harness; GUI rendering not exercised; per-service traffic splitting is intentionally not attempted (packets stay on the host row) |
| NG-013 | Partial | `src/identity/processlineage.*`: per-instance records (PID, parent PID, creation time, executable path, generation, NG-010 identity) with `NewInstance`/`Reused`/`Revived` transitions, `childrenOf()`, depth-bounded `ancestorsOf()`, and age-based expiry (30 s stale → exited, 5 min → forgotten); `NetworkMonitor` feeds it one toolhelp snapshot plus `GetProcessTimes` per refresh, emits `pidReuseDetected`, and drops the cached identity of a recycled PID before resolving it again; rows carry start time and parent in the tooltip; `DiagnosticsModel::reportPidReuse` records the replacement (also in the JSON summary) | Lineage, reuse, revival, expiry, parent chains, cycle safety, and the tooltip verified on Windows 10 19045 with a standalone harness (182 live processes, no false reuse, a spawned helper linked as a child); the running GUI is unverified and PID reuse was exercised with synthetic start times rather than a forced real recycle |
| NG-014 | Partial | `src/identity/processgroupmanager.*`: activity groups built from NG-010 identity, NG-011 publisher, NG-012 services, and NG-013 lineage evidence. Automatic anchors are the hosted service, the shared product metadata, or the install directory plus publisher; a second product co-installed in the same directory joins the group anchored there instead of forming its own, and a helper spawned by a grouped parent joins with weak inference. Every member records its evidence kind, confidence (confirmed / strong / weak), identity id, live PID, and a sentence explaining why it belongs; group confidence is its strongest member. Groups get ids derived from their anchor, so they survive restarts and updates. Manual groups, renames, added members, and removals persist in `QSettings` (schema 1), outrank the automatic derivation, and a removal is remembered as an exclusion. `NetworkMonitor` groups the PIDs that own traffic each refresh and the process tooltip shows `Group: <name> (<confidence>)` | Manager verified on Windows 10 19045 with a standalone harness (91 checks: product/directory/service anchors, OS-wide publisher guard, co-installation, helper inheritance, manual edits and persistence, exclusions, suppression/restore, confidence, live SCM evidence, tooltip); the monitor loop and the running GUI are unverified, and no group detail UI exists yet (NG-016) |
| NG-011 | Partial | `src/identity/publisherresolver.*`: WinVerifyTrust with local-only trust data, catalog fallback (`CryptCATAdmin*`) so inbox binaries resolve, signer CN/organization, SHA-1 certificate thumbprint, countersignature timestamp; `ApplicationIdentityResolver` fills `signerStatus`, `publisher`, and `fingerprints` and never blocks on failure; process rows carry `signed`/`unsigned`/`invalid signature`/`signature unavailable` plus a hover detail | Resolver and identity integration verified on Windows 10 19045 with a standalone harness (embedded, catalog, unsigned, tampered, missing cases); name-column and tooltip rendering not exercised in the running GUI; the per-session cache is not persisted |

NG-015 through NG-016 and all of Phases 2–6 are **not started**. NG-015 can build on the NG-010 resolver, the NG-011 publisher evidence, the NG-012 service map, and the NG-014 groups. NG-016 is the detail UI for those groups.

## Phase 0: Baseline and instrumentation

### NG-001 Establish product-direction test fixtures

- **Status:** Partial — ten scenario builders exist in `src/network/testfixtures.*` (nine original + respawning-worker), `runAllFixtures()` now iterates all fixtures including respawn; identity/category assertions are recorded but not fully validated without `classifyProcess` integration; no Windows 10/11 run has been done.
- **Type:** test
- **Priority:** P0
- **Dependencies:** None
- **Goal:** Create repeatable scenarios for browser traffic, a simulated updater, a respawning worker, a Windows service, DNS traffic, TLS traffic, VPN traffic, and unknown traffic.
- **Acceptance criteria:** Fixtures can generate known traffic and expected identity/category results on Windows 10 and Windows 11; no real third-party updater is required for automated tests.

### NG-002 Define observation and policy telemetry contracts

- **Status:** Partial — structs, metatypes, and JSON helpers exist in `src/network/policy.*` and the app builds; contract versioning, a round-trip test, and a production consumer are still missing, but the `ThrottleResult` collision with `throttlebackend.h` has been resolved by renaming to `NetworkPolicyThrottleResult`;
- **Type:** refactor
- **Priority:** P0
- **Dependencies:** None
- **Goal:** Define Qt metatypes and serialization formats for observations, identities, attribution, policies, enforcement results, and audit events.
- **Acceptance criteria:** Contracts are versioned, documented, and usable across worker threads without exposing UI classes to core logic.

### NG-003 Add diagnostics for capture gaps

- **Status:** Partial — `DiagnosticsModel` is constructed in `NetworkWidget`, bounded at 500 records, and exposed through a Diagnostics group on the Settings tab (table, summary, JSON export, clear). `NetworkMonitor` reports dropped/truncated packets, unresolved owner PIDs, ambiguous direction, stale connection mappings, and adapter setup failures via queued signals; reporting is aggregated per batch so monitoring is not interrupted. Runtime exercise and export-schema tests are still missing.
- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-002
- **Goal:** Report dropped packets, unresolved PIDs, unknown direction, stale connection mappings, and unavailable adapters.
- **Acceptance criteria:** Diagnostics are visible in a support view or export and do not interrupt normal monitoring.

## Phase 1: Durable identity

### NG-010 Implement canonical application identity

- **Status:** Partial — `ApplicationIdentityResolver` and the `QSettings` `IdentityStore` exist in `src/identity/applicationidentity.*`. `NetworkMonitor` resolves identities for PIDs that own live TCP/UDP connections (cached per PID, pruned when the PID disappears, capped per refresh), attaches `identityId`/`identityName` to `CapturedPacketInfo`, and emits `identityResolutionFailed` for typed failures, which the diagnostics model records. `NetworkTreeModel` displays the resolver's display name in the process label and exposes the identity ID via `Qt::UserRole + 6`. Canonical-path equivalence, typed failures, and restart persistence still need runtime verification, and PID reuse is not yet guarded by process start time (NG-013).
- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-002
- **Goal:** Create an identity resolver based on canonical path, process name, version metadata, product name, and original filename.
- **Acceptance criteria:** Equivalent paths normalize to one identity; inaccessible processes produce a typed resolution failure; identities persist across restarts.

### NG-011 Add Authenticode publisher resolution

- **Status:** Partial — `PublisherResolver` in `src/identity/publisherresolver.*` verifies the embedded Authenticode signature through `WinVerifyTrust`, and falls back to the Windows catalog (`CryptCATAdminAcquireContext`/`CalcHashFromFileHandle`/`EnumCatalogFromHash` + `WTD_CHOICE_CATALOG`) because inbox binaries such as `notepad.exe` are catalog-signed only. Evidence covers signer CN, organization, SHA-1 certificate thumbprint, and the countersignature timestamp (`CRYPT_PROVIDER_SGNR::sftVerifyAsOf`). `ApplicationIdentityResolver::resolveExecutablePath` records `signerStatus`, sets `publisher` and `fingerprints` only for verified signatures, and returns a resolved identity even when verification fails. Process rows append `signed: <publisher>`, `unsigned`, `invalid signature`, or `signature unavailable`, with publisher/timestamp detail in the row tooltip. Trust is evaluated from local data only (`WTD_CACHE_ONLY_URL_RETRIEVAL`, no revocation fetch) so a refresh can never block on a certificate server; a chain that only needs remote data is reported as unavailable rather than invalid. Verified against `node.exe` (embedded), `notepad.exe` (catalog), an unsigned build, a byte-flipped copy (invalid), and a missing path (unavailable) on Windows 10 19045. GUI rendering and explicit-distrust/expired-without-timestamp cases are still unverified.
- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-010
- **Goal:** Resolve signer, publisher, signature state, and certificate timestamp using Windows trust APIs.
- **Acceptance criteria:** The UI distinguishes signed, unsigned, invalid, and unavailable states; signature failures do not block observation.
- **Validation:** `Get-AuthenticodeSignature` on the same paths should agree on state and publisher (`node.exe` signed/embedded, `notepad.exe` signed/catalog, a local build unsigned, a modified copy invalid); the app's process row and tooltip must show the matching state.

### NG-012 Add Windows service identity resolution

- **Status:** Partial — `ServiceResolver` in `src/identity/serviceresolver.*` walks the SCM with `EnumServicesStatusExW(SC_ENUM_PROCESS_INFO)` at most once per 2 s window and caches `QueryServiceConfigW` image paths per service name, so every PID lookup is served from one snapshot. It records service key, display name, SCM image path, state (including pending/paused), and whether the service is user-stoppable. `NetworkMonitor` names any service host after its service (not only `svchost.exe`), and publishes the PID → services map only when it changes; `NetworkTreeModel` renders each hosted service as its own row beneath the host, with state and image path in the tooltip, so a `svchost.exe` running five services shows five labelled rows instead of one joined string. SCM failures go to `DiagnosticsModel::reportServiceLookupFailed` while capture continues. The previous implementation enumerated all services once per svchost PID per 200 ms cache loop; the replacement does one enumeration per window (~2.6 ms measured here). Verified on Windows 10 19045 (284 services, 94 hosting PIDs, a host with 5 services, DNS Client mapping, non-svchost hosts such as `lsass.exe` and `MsMpEng.exe`, row insertion/removal); the running GUI is still unverified.
- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-010
- **Goal:** Map service-hosted traffic to service name, display name, executable path, and service status.
- **Acceptance criteria:** Multiple services under one `svchost.exe` remain individually visible; service lookup failures are recorded without dropping traffic.
- **Validation:** compare a host PID's rows against `Get-Service` and `sc qc <name>` (display name, state, image path); stop a non-critical service and confirm its row flips to `Stopped` without losing the host's traffic. Denying admin rights should produce a service-resolution diagnostic and keep packets flowing.

### NG-013 Add process lineage tracking

- **Status:** Partial — `ProcessLineage` in `src/identity/processlineage.*` keeps one record per process instance: PID, parent PID, creation time from `GetProcessTimes`, executable path, NG-010 identity ID, a generation counter, and first/last-seen times. A PID whose creation time changes is reported as `Reused` (the previous record is preserved in the transition) and starts a new generation, so a replacement executable never inherits the old identity. A start time that cannot be read is never treated as a replacement. `NetworkMonitor` feeds the tracker from one toolhelp snapshot for parent PIDs plus the per-process creation time it already opens handles for, publishes the records for PIDs that own traffic to the packet loop, emits `pidReuseDetected`, and drops the recycled PID's cached identity and failure state before the identity pass re-resolves it. Rows carry `Started:` and `Parent:` in the tooltip, and `DiagnosticsModel::reportPidReuse` records the replacement as a `PID reuse` diagnostic (also counted in the JSON summary). Records unseen for 30 s are marked exited (they leave `childrenOf()` and stop counting as live) and are forgotten after 5 minutes; a process observed again within that window is revived rather than duplicated, and `ancestorsOf()` is depth- and cycle-bounded. Verified on Windows 10 19045 with a standalone harness: 46 checks over synthetic reuse/revival/expiry, a live 182-process snapshot with no false reuse, 176 processes resolving a tracked parent, and a spawned helper linked as a child. PID reuse itself was not forced on a real process (Windows no longer recycles PIDs freely); it is exercised with synthetic creation times.
- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-010
- **Goal:** Track parent PID, child processes, start time, and executable identity so replacement and helper processes can be related.
- **Acceptance criteria:** PID reuse is detected using process start time; stale lineage records expire safely.
- **Validation:** restart a self-updating app (e.g. an Electron or `winget`-style updater) and confirm the old row's identity is discarded, a `PID reuse` diagnostic appears, and the new executable is attributed from scratch; leave the app idle and confirm rows do not vanish while their process lives, and that closed processes disappear from the tree and stop being listed as parents.

### NG-014 Create application group manager

- **Status:** Partial — `ProcessGroupManager` in `src/identity/processgroupmanager.*` turns the evidence from NG-010 to NG-013 into durable activity groups. Three automatic anchors exist, in priority order: the Windows service a process hosts (the service itself becomes a confirmed member), the publisher plus product metadata, and the install directory plus a specific publisher. A second product shipped in the same directory by the same publisher joins the group anchored there rather than forming its own, and a child of an already-grouped process joins as a weak inference when it is installed alongside it or shares its publisher. Publishers too broad to mean anything (Microsoft and other OS vendors) and processes without evidence are left ungrouped on purpose, so no OS-wide group is fabricated. Each member stores its type (executable, service, publisher, package), evidence kind, confidence, NG-010 identity id, live PID, and a sentence explaining why it belongs; a group's confidence is that of its strongest member. Group ids are derived from the evidence anchor, so the same group is recognised after a restart or an update even though membership is rebuilt every refresh. Manual groups, renames, added members, and removals are persisted in `QSettings` (schema 1) and outrank the automatic derivation; removing an automatic member records an exclusion so the evidence cannot silently re-add it, removing an automatic group suppresses it until restored, and re-adding a member clears the exclusion. `NetworkMonitor` groups the PIDs that own traffic on each cache refresh, carries the group to the packet loop, and the process tooltip shows `Group: <name> (<confidence>)`. Verified on Windows 10 19045 with a standalone harness: 91 checks covering product, directory, and service anchors, the broad-publisher guard against a real Microsoft service host, co-installation merging, helper inheritance and its rejection of unrelated children, manual add/rename/remove with a reload, exclusions, suppression and restore, confidence aggregation, live SCM evidence, and the tooltip. The monitor's cache loop and the running GUI were not exercised.
- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-010, NG-011, NG-012, NG-013
- **Goal:** Group launchers, updaters, services, and helper processes into durable activity identities.
- **Acceptance criteria:** Groups support manual membership edits, automatic evidence-based membership, confidence, and an explanation of why each member belongs.
- **Validation:** start an app with a separate updater (Chrome, Dropbox, or a winget-style package manager) and confirm the tooltip names one group for the launcher and its helper; rename the group against a live process, remove one automatic member, restart the app, and confirm the edit and the removal survive. Confirm no group appears for `svchost.exe` or other Microsoft binaries, and that manual members disappear when their executable is deleted.

### NG-015 Migrate Data Saver classification to identity groups

- **Type:** refactor
- **Priority:** P0
- **Dependencies:** NG-014
- **Goal:** Preserve existing process categories while evaluating identity, publisher, service, and group evidence.
- **Acceptance criteria:** Existing known candidates still classify correctly; rules can match a replacement executable without relying on the original PID.

### NG-016 Add identity and group detail UI

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-014
- **Goal:** Show identity evidence, related processes, services, publisher, paths, and confidence.
- **Acceptance criteria:** Users can inspect and remove group members without editing configuration files.

## Phase 2: Policy and enforcement coordination

### NG-020 Create versioned policy store

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-002, NG-014
- **Goal:** Persist policies using explicit scope, action, direction, rate, schedule, expiration, source, and enabled state.
- **Acceptance criteria:** Old settings migrate safely; malformed policies are rejected with a recoverable error; policies can be exported and imported.

### NG-021 Implement enforcement coordinator

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-020
- **Goal:** Coordinate Windows Firewall, Windows QoS, and WinDivert without duplicating policy decisions in UI code.
- **Acceptance criteria:** One policy produces a complete per-channel result; partial success is represented explicitly; all requests are auditable.

### NG-022 Add policy scope selection

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-020, NG-021
- **Goal:** Support PID, executable path, publisher, service, package, and application-group scopes.
- **Acceptance criteria:** The UI explains scope breadth and risk before applying a policy; group scope controls future matching processes.

### NG-023 Add temporary and scheduled policies

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-020, NG-021
- **Goal:** Support expiration, recurring schedules, and network-profile conditions.
- **Acceptance criteria:** Policies activate and deactivate at expected boundaries; a missed transition is recovered on startup.

### NG-024 Add startup and periodic policy reconciliation

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-021
- **Goal:** Verify that persisted firewall and QoS policies still exist and that WinDivert shaping matches the active policy set.
- **Acceptance criteria:** Stale records are marked and repaired or removed; the user sees failures; reconciliation does not block the GUI.

### NG-025 Add respawn and replacement enforcement

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-014, NG-021, NG-024
- **Goal:** Re-apply group policies when an updater or worker exits and a related process appears.
- **Acceptance criteria:** A fixture can terminate a worker, start a replacement, and show that the replacement receives the expected control without manual action.

### NG-026 Add policy emergency restore

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-021
- **Goal:** Provide one action to remove automatic controls while preserving explicit user policies.
- **Acceptance criteria:** Automatic and user-created policies are distinguishable; restore results list successes and failures.

### NG-027 Add enforcement integration tests

- **Type:** test
- **Priority:** P0
- **Dependencies:** NG-021, NG-025, NG-026
- **Goal:** Verify upload, download, combined, block, restore, missing-driver, access-denied, and process-respawn behavior.
- **Acceptance criteria:** Tests assert actual policy state and measured behavior where the environment supports elevation and WinDivert.

## Phase 3: DNS, TLS, and endpoint attribution

### NG-030 Implement passive DNS observer

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-002
- **Goal:** Parse visible DNS request and response metadata without retaining payloads.
- **Acceptance criteria:** A DNS event includes name, record type, addresses, timestamp, source process when resolvable, and confidence; malformed packets are ignored safely.

### NG-031 Correlate DNS answers with connections

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-030, NG-010
- **Goal:** Associate destination IPs with recently observed DNS names and application identities.
- **Acceptance criteria:** Correlation has a bounded TTL, supports multiple names per address, and exposes the attribution source.

### NG-032 Parse visible TLS SNI

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-002, NG-010
- **Goal:** Parse TLS ClientHello metadata for visible SNI without decrypting traffic.
- **Acceptance criteria:** SNI is extracted for supported TLS records; fragmented, encrypted, malformed, and ECH-hidden handshakes are marked unavailable rather than misclassified.

### NG-033 Add safe QUIC metadata support

- **Type:** feature
- **Priority:** P1
- **Dependencies:** NG-032
- **Goal:** Extract only safely available hostname metadata from QUIC Initial packets.
- **Acceptance criteria:** Unsupported versions and encrypted fields produce unknown attribution; parser tests cover malformed input.

### NG-034 Build endpoint and publisher catalog

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-010, NG-011, NG-030, NG-032
- **Goal:** Maintain local rules linking publishers, services, executable identities, and known endpoint patterns to activity categories.
- **Acceptance criteria:** Rules are versioned, explainable, updateable, and do not cause a network block by themselves.

### NG-035 Add attribution confidence model

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-031, NG-032, NG-034
- **Goal:** Produce confirmed, strong inference, weak inference, and unknown states from evidence.
- **Acceptance criteria:** Every displayed category and domain has evidence and confidence; UI text never presents weak inference as fact.

### NG-036 Add attribution privacy controls

- **Type:** security
- **Priority:** P0
- **Dependencies:** NG-030, NG-032
- **Goal:** Make DNS and TLS metadata collection configurable and define retention/export behavior.
- **Acceptance criteria:** Payloads are never stored; users can clear attribution history; exported diagnostics redact destinations by default.

## Phase 4: Classification and recommendations

### NG-040 Implement rule-based activity classifier

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-015, NG-034, NG-035
- **Goal:** Classify common update, sync, launcher, developer-tool, and foreground-download scenarios.
- **Acceptance criteria:** Each classification exposes matched rules and evidence; unknown activity remains usable for manual policy creation.

### NG-041 Add foreground/background signal

- **Type:** feature
- **Priority:** P1
- **Dependencies:** NG-014
- **Goal:** Determine whether an identity is associated with the foreground application or active user session.
- **Acceptance criteria:** The signal is advisory, has a freshness timestamp, and never overrides explicit user policy.

### NG-042 Add deterministic recommendation engine

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-040, NG-020
- **Goal:** Suggest throttle, pause, schedule, review-settings, or no-action responses for common activity.
- **Acceptance criteria:** Recommendations include evidence, confidence, expected effect, and reversal action; they never silently enforce.

### NG-043 Add recommendation feedback

- **Type:** feature
- **Priority:** P1
- **Dependencies:** NG-042
- **Goal:** Let users mark recommendations useful, incorrect, or unwanted and persist that preference locally.
- **Acceptance criteria:** Feedback changes future local recommendations without uploading activity data.

### NG-044 Define structured AI context

- **Type:** security
- **Priority:** P0
- **Dependencies:** NG-040, NG-042
- **Goal:** Create a redacted schema for optional AI assistance.
- **Acceptance criteria:** Context contains metadata only, identifies unknown fields, has a size limit, and is inspectable before sending.

### NG-045 Add optional AI provider adapter

- **Type:** feature
- **Priority:** P1
- **Dependencies:** NG-044
- **Goal:** Support an opt-in provider interface for explanations and recommendations.
- **Acceptance criteria:** Provider is disabled by default, failures degrade to local recommendations, and AI output cannot directly apply a policy.

### NG-046 Add AI approval flow

- **Type:** feature
- **Priority:** P1
- **Dependencies:** NG-045, NG-022
- **Goal:** Let users review and approve an AI-suggested policy with explicit scope and duration.
- **Acceptance criteria:** Approval creates a normal auditable policy; rejection does not modify enforcement state.

## Phase 5: Notifications, audit, and UX

### NG-050 Create audit event store

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-002, NG-020, NG-021
- **Goal:** Persist detections, decisions, policy changes, enforcement outcomes, and attribution changes.
- **Acceptance criteria:** Events are timestamped, queryable, bounded by retention settings, and exportable without packet payloads.

### NG-051 Add notification coordinator

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-050
- **Goal:** Deduplicate, prioritize, suppress, and route notifications to the tray and application UI.
- **Acceptance criteria:** Repeated packet activity does not produce notification floods; critical enforcement failures remain visible.

### NG-052 Add application detail view

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-016, NG-035, NG-050
- **Goal:** Provide one view for identity, usage, destinations, related processes, policy, confidence, and audit history.
- **Acceptance criteria:** A user can move from a notification to evidence and then to a reversible action without navigating unrelated tabs.

### NG-053 Add policy editor and scope warnings

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-022, NG-023
- **Goal:** Make policy scope, direction, rate, duration, and expected impact explicit.
- **Acceptance criteria:** Broad publisher/group policies require confirmation; temporary policies show expiration; partial enforcement is visible.

### NG-054 Add top-consumer dashboard

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-040, NG-051, NG-052
- **Goal:** Show current top consumers, active controls, unresolved traffic, and recommended actions at a glance.
- **Acceptance criteria:** The top consumer can be inspected and controlled from the first dashboard view.

### NG-055 Add audit and attribution export

- **Type:** feature
- **Priority:** P1
- **Dependencies:** NG-050, NG-036
- **Goal:** Export filtered JSON/CSV evidence for support and personal analysis.
- **Acceptance criteria:** Export includes schema version and confidence; destination redaction is enabled by default.

## Phase 6: Security, compatibility, and release

### NG-060 Threat-model identity and enforcement boundaries

- **Type:** security
- **Priority:** P0
- **Dependencies:** NG-021, NG-034
- **Goal:** Review path spoofing, signer trust, policy injection, imported JSON, service impersonation, and privilege boundaries.
- **Acceptance criteria:** Threat model documents trust decisions and mitigations; high-risk findings have tickets before release.

### NG-061 Test Windows capability matrix

- **Type:** test
- **Priority:** P0
- **Dependencies:** NG-027, NG-036
- **Goal:** Test Windows 10/11, administrator/non-administrator launch, WinDivert present/missing, VPN, encrypted DNS, IPv4/IPv6, and multiple adapters.
- **Acceptance criteria:** Supported, degraded, and unsupported states are documented and reflected in the UI.

### NG-062 Test performance and retention limits

- **Type:** test
- **Priority:** P0
- **Dependencies:** NG-050
- **Goal:** Measure CPU, memory, capture throughput, storage growth, and UI responsiveness under sustained traffic.
- **Acceptance criteria:** Retention is bounded; the UI remains responsive under the documented traffic target; no unbounded identity or DNS cache exists.

### NG-063 Update user documentation

- **Type:** documentation
- **Priority:** P0
- **Dependencies:** NG-053, NG-061
- **Goal:** Document attribution limitations, partial enforcement, WinDivert requirements, privacy behavior, policy scopes, and recovery actions.
- **Acceptance criteria:** README, feature documentation, security documentation, and release notes agree with actual behavior.

### NG-064 Release readiness review

- **Type:** test
- **Priority:** P0
- **Dependencies:** NG-060, NG-061, NG-062, NG-063
- **Goal:** Verify product acceptance criteria, known limitations, rollback behavior, and installer/runtime packaging.
- **Acceptance criteria:** All P0 tickets meet acceptance criteria; unresolved risks have owner and mitigation; a clean build and smoke test pass.

## Suggested execution order

1. NG-001 through NG-003: establish measurable behavior.
2. NG-010 through NG-016: build durable identity and grouping.
3. NG-020 through NG-027: move enforcement decisions into a policy coordinator.
4. NG-030 through NG-036: improve domain and endpoint attribution.
5. NG-040 through NG-046: add explanations, recommendations, and optional AI.
6. NG-050 through NG-055: make the workflow visible and usable.
7. NG-060 through NG-064: harden, document, and release.

## Definition of done for every ticket

- Code follows the repository's C++14 and Qt conventions.
- Administrator and failure paths are tested where relevant.
- New persisted data has a schema/version and migration behavior.
- User-visible limitations and partial results are documented.
- No raw packet payload is persisted.
- Relevant signals, worker-thread boundaries, and cleanup paths are tested.
- The ticket includes a focused validation command or reproducible manual test.
