# Ultimate NetGuard AIO: Product Tickets

This backlog implements [PRD.md](PRD.md). Tickets are ordered by dependency inside each phase. `P0` means required for the first release of this product direction; `P1` means important follow-up; `P2` means optional or later.

## Ticket conventions

- **Type:** feature, refactor, bug, test, documentation, or security.
- **Status:** `Done`, `Partial`, or `Not started`, summarized in [Current status](#current-status). A ticket with no status line is `Not started`.
- **Dependencies:** tickets that should land first.
- **Acceptance criteria:** observable completion conditions.

## Current status

Last updated: 2026-11-09. Status values: **Done** (acceptance criteria met and verified), **Partial** (code exists but acceptance criteria are unmet or unverified), **Not started** (proposed, no code).

The application builds with Qt 6.11.1 / MinGW 13.1 (`qmake UltimateNetGuard.pro`, then `mingw32-make -j4`). One unused-function warning remains, `EnableDebugPrivilege()` in `networkwidget.cpp`; the unused `buildIpv6TcpPacket()` warning is gone because the IPv6 fixture now uses that builder. Phase 0 checks run as a standalone harness that needs no GUI, elevation, or WinDivert: `qmake tests/netguard_tests.pro && mingw32-make -j4 && ./netguard_tests` (338 checks: five contract round-trips, the schema-version gate, all 22 fixtures, the diagnostics export schema, the emergency-restore/enforcement-channel planning, the policy-reconciliation planner plus its rule and limit attribution, path-unique firewall rule naming, passive DNS metadata parsing, and bounded DNS-to-destination correlation; exits non-zero on failure). NG-011, NG-012, NG-013, NG-014, and NG-015 have been validated at runtime so far (standalone harnesses on Windows 10 19045); NG-016's dialog was driven offscreen by a harness, but no window has been visually reviewed in the running application.

| Ticket | Status | Implemented | Remaining |
| --- | --- | --- | --- |
| NG-001 | Partial | `src/network/testfixtures.*`: ten scenario builders (browser download, updater, respawn worker, Windows service, DNS, TLS, VPN, unknown, game launcher, IDE update) that emit real IPv4/IPv6 TCP, UDP, and ICMP packets, each carrying the typed `ClassificationEvidence` of the process behind that traffic; `runAllFixtures()` parses every packet back and asserts both the intended 5-tuple and the category `BandwidthGuard::classifyProcess()` returns | Verified on Windows 10 19045 through `tests/netguard_tests` (22 fixtures, 0 failures); Windows 11 has not been exercised, and the identities are synthetic names/publishers rather than traffic from real installations |
| NG-002 | Done | `src/network/policy.*`: identity, observation, policy, throttle-result, and audit-event structs with Qt metatypes, `toJson`/`fromJson` helpers, and a documented contract schema (`PolicyContract::kSchemaVersion` = 1, carried in every payload as `schemaVersion`; readers accept pre-versioning payloads and reject a newer one instead of half-parsing). The duplicate declarations and the `fromJsonThrottleResult` / `fromJsonNetworkPolicyThrottleResult` mismatch are fixed | — |
| NG-003 | Partial | `src/network/diagnostics.*`: bounded `DiagnosticsModel` (500 records) with typed reasons, table columns, summary counts, and versioned JSON export; `NetworkMonitor` emits aggregated gap signals (drops, unresolved PIDs, unknown direction, stale mappings, adapter failures); `NetworkWidget` feeds the model; Settings tab has a Diagnostics support view with export and clear | Export schema covered by `tests/netguard_tests` (root, summary, and record keys, string enum names, summary counters, the 500-record bound, and `clear()`) on Windows 10 19045; the monitor's gap signals and the support view are still not exercised |
| NG-010 | Partial | `src/identity/applicationidentity.*`: canonical-path resolution, version metadata, SHA-1 identity IDs, typed failures, and `QSettings` `IdentityStore` (schema 1); live monitoring now resolves identities for PIDs that own connections (cached per PID, pruned when the PID disappears), attaches them to captured packets, shows the resolver display name in the process tree, and records typed resolution failures as diagnostics. Publisher and signer evidence now come from NG-011 | Path equivalence, typed failures, and restart persistence untested at runtime; PID reuse is now guarded by process start time (NG-013) |
| NG-012 | Partial | `src/identity/serviceresolver.*`: one SCM enumeration per 2 s window (cached) instead of one per svchost PID per loop, PID → service map with service key, display name, `QueryServiceConfig` image path, and runtime state; `NetworkMonitor` names any service host after its service and publishes the per-PID service map only when it changes; `NetworkTreeModel` draws each hosted service as its own row under the host (state, image path in the tooltip) so services sharing one `svchost.exe` stay separable; `DiagnosticsModel::reportServiceLookupFailed` records SCM failures without touching capture | Service rows, snapshot streaming, and the resolver verified on Windows 10 19045 with a standalone harness; GUI rendering not exercised; per-service traffic splitting is intentionally not attempted (packets stay on the host row) |
| NG-013 | Partial | `src/identity/processlineage.*`: per-instance records (PID, parent PID, creation time, executable path, generation, NG-010 identity) with `NewInstance`/`Reused`/`Revived` transitions, `childrenOf()`, depth-bounded `ancestorsOf()`, and age-based expiry (30 s stale → exited, 5 min → forgotten); `NetworkMonitor` feeds it one toolhelp snapshot plus `GetProcessTimes` per refresh, emits `pidReuseDetected`, and drops the cached identity of a recycled PID before resolving it again; rows carry start time and parent in the tooltip; `DiagnosticsModel::reportPidReuse` records the replacement (also in the JSON summary) | Lineage, reuse, revival, expiry, parent chains, cycle safety, and the tooltip verified on Windows 10 19045 with a standalone harness (182 live processes, no false reuse, a spawned helper linked as a child); the running GUI is unverified and PID reuse was exercised with synthetic start times rather than a forced real recycle |
| NG-014 | Partial | `src/identity/processgroupmanager.*`: activity groups built from NG-010 identity, NG-011 publisher, NG-012 services, and NG-013 lineage evidence. Automatic anchors are the hosted service, the shared product metadata, or the install directory plus publisher; a second product co-installed in the same directory joins the group anchored there instead of forming its own, and a helper spawned by a grouped parent joins with weak inference. Every member records its evidence kind, confidence (confirmed / strong / weak), identity id, live PID, and a sentence explaining why it belongs; group confidence is its strongest member. Groups get ids derived from their anchor, so they survive restarts and updates. Manual groups, renames, added members, and removals persist in `QSettings` (schema 1), outrank the automatic derivation, and a removal is remembered as an exclusion. `NetworkMonitor` groups the PIDs that own traffic each refresh and the process tooltip shows `Group: <name> (<confidence>)` | Manager verified on Windows 10 19045 with a standalone harness (91 checks: product/directory/service anchors, OS-wide publisher guard, co-installation, helper inheritance, manual edits and persistence, exclusions, suppression/restore, confidence, live SCM evidence, tooltip); the monitor loop and the running GUI are unverified, and no group detail UI exists yet (NG-016) |
| NG-015 | Partial | `src/network/bandwidthguard.*`: `ClassificationEvidence` (PID, name, path, NG-010 identity and display name, NG-011 publisher and signer status, NG-012 service flag, NG-014 group id and name) with a second `classifyProcess()` overload. The twelve shipped executable-name rules run first and unchanged, so every category the product already assigned is kept (and `pid 4` and services stay `Protected`). When a name has no rule, the classifier matches the signed publisher against the product metadata — "Google Chrome" → AskFirst; "Google Update", "Microsoft Edge Update", "Brave Update", "Microsoft OneDrive" → AutoCandidate — so an update that renames its executable keeps its category, while an unsigned or differently signed file matches nothing. `BandwidthGuard::observe()` carries that evidence per PID and, for a member with no rule of its own, falls back to what its activity group has learned, keyed by group id so it outlives a respawn under a new PID; the group keeps its most cautious member, so one AskFirst member stops the group's unnamed helpers from being acted on automatically. `reset()` forgets the learned groups, and both surfaces that act on the decision show it: the bandwidth alert relays the category through the shared `categoryDisplayName()` and says when it was learned from the process's activity group (`BandwidthEvent::groupId`, `groupName`, `categoryFromGroup`), and the activity group dialog shows the group's learned category and, per member, the category it is acted on as (`groupCategory()`, `memberCategory()`) | Learned group categories exist only for groups whose members have already crossed the threshold, the running GUI was not exercised, and a WebView2 host now inherits Edge's AskFirst |
| NG-016 | Partial | `src/network/groupdetaildialog.*`: "Activity group..." in the process context menu opens the group of the selected row. The dialog names the group in an editable field, summarises member count / running members / confidence / manual-or-derived, and lists every executable and service member with type, evidence, confidence and live PID. Selecting a member explains it: full path, NG-010 identity id, NG-011 publisher, evidence kind with confidence, and the sentence saying why it belongs. Members can be removed (automatic removals are remembered as exclusions) and the group renamed from the dialog, both persisted through `ProcessGroupManager`; an executable can be added by browsing. `NetworkMonitor` gained mutex-guarded `processGroups()`, `createProcessGroup()`, `renameProcessGroup()`, `addProcessGroupMember()`, `removeProcessGroupMember()` and a `groupSnapshotReady` signal, and the tree model exposes the group id (`Qt::UserRole + 7`). The summary line and the member pane also show the Data Saver category from NG-015 — the group's learned category, and for the selected member the category it is acted on as, saying so when it came from the group | Dialog built and driven offscreen on Windows 10 19045 with a standalone harness (49 checks: inspection, evidence pane, rename, live refresh, removal, inactive group, model role, reload); not visually reviewed in the running app, and "Add executable" opens a native file dialog that the harness does not exercise |
| NG-011 | Partial | `src/identity/publisherresolver.*`: WinVerifyTrust with local-only trust data, catalog fallback (`CryptCATAdmin*`) so inbox binaries resolve, signer CN/organization, SHA-1 certificate thumbprint, countersignature timestamp; `ApplicationIdentityResolver` fills `signerStatus`, `publisher`, and `fingerprints` and never blocks on failure; process rows carry `signed`/`unsigned`/`invalid signature`/`signature unavailable` plus a hover detail | Resolver and identity integration verified on Windows 10 19045 with a standalone harness (embedded, catalog, unsigned, tampered, missing cases); name-column and tooltip rendering not exercised in the running GUI; the per-session cache is not persisted |
| NG-020 | Partial | `src/network/policy.*`: `PolicyStore` with v1 `QVariantMap` → v2 JSON migration, load/save/export/import, and malformed-entry rejection. `savePolicies()` now writes the v2 JSON array that `loadPolicies()` and `exportPoliciesJson()` read; it had been writing a v1 map, so every saved policy was unreadable and exports were empty | Import, export, and the migration path are unexercised; no live UI writes policies yet |
| NG-021 | Partial | `src/network/enforcementcoordinator.*`: instance coordinator over the existing firewall and throttle managers (no managers means every channel reports why it could not act); channel planning and descriptions live in `enforcementrestore.*`; per-policy result with `NotApplied`/`Requested`/`Applied`/`Failed`; owned by `NetworkWidget` | `Partial` is declared but never produced (the worker's upload/download outcome is not folded back); no live firewall, QoS, or WinDivert application has been run |
| NG-022 | Partial | `src/network/policyeditordialog.*` and `src/network/policylistdialog.*`: "Create policy..." offers the five PRD scopes with breadth/risk/future-process/enforcement notes, prefills targets, validates, and stores a `user` policy; the **Policies…** toolbar button lists stored policies with their derived state and supports edit and confirmed delete | Editing or deleting withdraws the attributed firewall rules and bandwidth limit (NG-024); PID, publisher, and service scopes are stored but not enforced; port/protocol/package scopes cannot be edited; unit tests and visual review not done |
| NG-023 | Partial | `src/network/policyschedule.*`: derived activation from expiration and named/custom local-time windows, `Unsupported` for an unrecognised schedule; `PolicyScheduler` evaluates at startup (recovering a boundary missed while the app was closed) and every 15 s, emitting state changes; `NetworkWidget` applies path/executable and group policies when a window opens | Leaving a window does not withdraw controls (rule ownership belongs to NG-024); metered/profile conditions are unsupported; no tests or live run |
| NG-024 | Partial | `src/network/policyreconcile.*`: pure plan comparing active policies with observed NetGuard rules, throttled paths, and download limits; policy-created firewall rules carry the policy id in their description, so stale rules are removed, missing ones re-created, and unattributed user rules left in place; runs after startup, on activation changes, and from **Verify...** | Rule names now hash the normalized full executable path, so same-named executables cannot share rules; legacy names are cleaned on re-application and removal; bandwidth limits now carry a persisted policy attribution, so the limit of a deleted or inactive policy is withdrawn while a limit applied outside a policy is left in place, and ownership is handed to a different active policy without a new QoS call; **Limits...** lists every enforced limit with its owner and can remove the selected one; unresolved scopes reported; enumeration is synchronous on the GUI thread |
| NG-025 | Partial | `src/network/enforcementcoordinator.*`: `reapplyGroupPolicies()` applies enabled group-scoped policies to a group's running executables on each membership snapshot and remembers each (group, policy, path) triple; `NetworkWidget` feeds it every `groupSnapshotReady` | Replacement fixture and live measurement deferred to NG-027; no UI creates group policies yet |
| NG-026 | Partial | `src/network/enforcementrestore.*` and `EnforcementCoordinator::emergencyRestore()`: user/automatic/unknown origin split, removal of automatic policies only, preserved-set write-back, per-action report, queued throttle restore, and a restore report in `NetworkWidget` | Planning, reporting, and store write-back verified in the harness; the dialog and a live throttle restore are unverified, and no UI creates automatic policies yet |
| NG-027 | Partial | `tests/netguard_tests`: channel routing for block/allow/throttle/schedule/advisory in both directions, the emergency-restore plan and report, failure entries, and the store round-trip | No live enforcement tests: upload, download, combined, block, restore, missing-driver, and access-denied behaviour need elevation and WinDivert and would change real firewall/QoS state; respawn enforcement does not exist |
| NG-030 | Partial | `src/attribution/dnsobserver.*`: parses visible UDP DNS messages into name, record type, A/AAAA addresses, CNAME aliases, TTL, transaction id, timestamp, and confidence; `NetworkMonitor` emits `dnsObservation` and attaches the resolved PID/process/identity; names are lower-cased, compression pointers must point backwards, label and name lengths are bounded, and malformed, overrun, non-standard-opcode, and non-53 messages are ignored | Verified by the harness (29 checks: query, compressed response with A/AAAA/CNAME, IPv4/IPv6 framing, malformed cases) but not against live capture; DNS over TCP, DoH, and DoT are not observed |
| NG-031 | Done | `src/attribution/dnscorrelator.*` indexes DNS answers by destination address; each record carries the name, querying PID/process/identity, confidence, attribution source, first/last seen, and expiry. Several names can share an address (most recent first), the DNS TTL is capped at one hour with a five-minute default, and the store caps names per address and total addresses with least-recently-seen eviction. `NetworkMonitor` observes every parsed answer and exposes `attributionsForAddress()`, which filters expired records | Verified by the harness (33 checks: TTL boundary, multi-name lookup and refresh, identity retention, query rejection, both caps, TTL clamp/default); not yet shown in the UI or used to classify connections, and no live capture run |

Phases 4–6 are **not started**. Phase 2 has only the groundwork described in NG-020 to NG-027, and Phase 3 has the DNS observer and destination correlation (NG-030, NG-031).

## Phase 0: Baseline and instrumentation

### NG-001 Establish product-direction test fixtures

- **Status:** Partial — ten scenario builders exist in `src/network/testfixtures.*` (nine original + respawning-worker) and `runAllFixtures()` iterates all of them. Each fixture builds a well-formed IPv4 or IPv6 TCP/UDP/ICMP packet (the earlier builders wrote the TCP header past a 20-byte buffer, used host-order addresses and ports, and emitted ICMP without an IP header), records the 5-tuple the builder intended, and carries the `ClassificationEvidence` the classifier should see. `runAllFixtures()` re-parses every packet, compares it against that 5-tuple, and compares `BandwidthGuard::classifyProcess()` against the expected category, so the name rules, the publisher/product identity rules, service protection, and the unsigned-copy case are all asserted rather than described. The harness lives in `tests/` (`qmake tests/netguard_tests.pro && mingw32-make -j4 && ./netguard_tests`) and passes 22/22 fixtures on Windows 10 19045. Remaining: Windows 11 has not been exercised, and the process identities are synthetic rather than captured from real updaters.
- **Type:** test
- **Priority:** P0
- **Dependencies:** None
- **Goal:** Create repeatable scenarios for browser traffic, a simulated updater, a respawning worker, a Windows service, DNS traffic, TLS traffic, VPN traffic, and unknown traffic.
- **Acceptance criteria:** Fixtures can generate known traffic and expected identity/category results on Windows 10 and Windows 11; no real third-party updater is required for automated tests.

### NG-002 Define observation and policy telemetry contracts

- **Status:** Done — structs, metatypes, and JSON helpers live in `src/network/policy.*` for identities, observations, policies, throttle results, and audit events. Every payload now carries `schemaVersion` (`PolicyContract::kSchemaVersion` = 1); a reader accepts a payload without the key (data written before versioning) and one carrying the current or an older version, and rejects a payload from a newer build as a whole so new field meanings can never be read as current ones. The versioning rule and the thread-boundary rule are documented at the top of `policy.h`, which includes only QtCore, so no UI class can leak into core logic. The header also lost its duplicated serialization declarations, and the throttle-result reader is now defined under the name it is declared with. `tests/netguard_tests` round-trips all five contracts field by field (including binary fingerprints, 64-bit byte counts, enum values, and UTC timestamps), checks the key is present, and covers both sides of the version gate. The contracts are already consumed outside the UI, by `EnforcementCoordinator` for policy and result JSON and by `IdentityStore` for identity persistence.
- **Type:** refactor
- **Priority:** P0
- **Dependencies:** None
- **Goal:** Define Qt metatypes and serialization formats for observations, identities, attribution, policies, enforcement results, and audit events.
- **Acceptance criteria:** Contracts are versioned, documented, and usable across worker threads without exposing UI classes to core logic.

### NG-003 Add diagnostics for capture gaps

- **Status:** Partial — `DiagnosticsModel` is constructed in `NetworkWidget`, bounded at 500 records, and exposed through a Diagnostics group on the Settings tab (table, summary, JSON export, clear). `NetworkMonitor` reports dropped/truncated packets, unresolved owner PIDs, ambiguous direction, stale connection mappings, and adapter setup failures via queued signals; reporting is aggregated per batch so monitoring is not interrupted. The export schema is now asserted in `tests/netguard_tests`: the root carries `schemaVersion` 1, a parseable `exportedAt`, a summary whose seven counters agree with the records, and a records array whose objects have the ten documented keys with string enum names (`BufferOverflow`, `Unresolved`, `UnknownDirection`, `StaleMapping`, `AdapterUnavailable`, `ServiceHost`, `PidReuse`), numeric PIDs, and ISO-8601 timestamps with milliseconds. The same test drives every reporter, checks that the retained window never exceeds `MaxRecords` (oldest evicted first), and that `clear()` empties both the records and the summary. Remaining: nothing here calls the reporters from a live `NetworkMonitor`, and the support view on the Settings tab has not been exercised in the running application.
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

- **Status:** Partial — `src/network/bandwidthguard.*` now classifies a process from evidence rather than only from its file name. `ClassificationEvidence` carries the PID, executable name and path, the NG-010 identity and display name, the NG-011 publisher and signer status, the NG-012 service flag, and the NG-014 group id and name, and a second `classifyProcess()` overload takes it. The twelve rules that shipped before NG-015 still run first and unchanged, so every category the product already assigned is the category it assigns now, and `pid 4` and services are still `Protected`. Only when a name has no rule does the publisher and product metadata decide: a signed "Google Chrome" is AskFirst and "Google Update", "Microsoft Edge Update", "Brave Update", and "Microsoft OneDrive" are AutoCandidate, with updater fragments ordered before the application they update because "Microsoft Edge Update" also contains "edge". A rule is only borrowed from a verified signer, so an unsigned or tampered copy of a known application matches nothing. `BandwidthGuard::observe()` keeps that evidence on each process window and, for a member with no rule of its own, uses the category its activity group has learned instead — keyed by group id, so a helper or a reloaded executable is classified without a rule naming it and without depending on the PID that was seen first. A group stores its most cautious member's category, so a single AskFirst member keeps the group's unnamed helpers from being blocked automatically, and `reset()` forgets what was learned. Verified on Windows 10 19045 with a standalone harness: 51 checks covering all twelve shipped name rules, case-insensitivity, `pid 4` and service classification, all eleven identity rules including the updater ordering, unsigned and foreign-publisher files matching nothing, a name rule outranking conflicting metadata, inheritance by an unnamed member of a learned group under a new PID, respawn, a service member not softening its group, the most cautious member winning in either order, an explicit override outranking group evidence, exemption, and `reset()`. The decision is now visible where it is acted on: `categoryDisplayName()` is the single wording both surfaces use ("Possible active download", "Background updater candidate", "Protected service", "Background data activity"), the bandwidth alert reports it in a "Classified as: …" line and says when the category was learned from the process's activity group, and the activity group dialog shows the group's learned category in its summary and, per member, the category it is acted on as — read-only, so opening the dialog never changes what was learned. A further offscreen harness (31 checks) covered the display text of every category, the alert event carrying the group id, name, and origin flag, and the dialog's summary and member pane for a learned group, an unclassified group, and no guard. The running GUI was not exercised, and a group's category is only known after one of its members has crossed the bandwidth threshold.
- **Type:** refactor
- **Priority:** P0
- **Dependencies:** NG-014
- **Goal:** Preserve existing process categories while evaluating identity, publisher, service, and group evidence.
- **Acceptance criteria:** Existing known candidates still classify correctly; rules can match a replacement executable without relying on the original PID.

### NG-016 Add identity and group detail UI

- **Type:** feature
- **Priority:** P0
- **Status:** Partial — `GroupDetailDialog` in `src/network/groupdetaildialog.*` is opened from "Activity group..." in the process context menu. Each row names the application and the file behind it (`Google Chrome (chrome.exe)`), the member list is only as tall as its rows (capped, then scrolling) so the evidence pane gets the remaining room, and reading the version resource no longer truncates names — it had been sizing strings from a byte count some resources report in characters, which is why every application name appeared cut in half (Chrome showed up as "Google"). It shows the group name in an editable field with a Rename action, a summary line (member count, how many are running now, group confidence, and whether the group was created by the user or derived from evidence), and one row per executable and service member with its type, evidence kind, confidence, and live PID. Selecting a member fills the detail pane with the full path, the NG-010 identity id, the NG-011 publisher, the evidence and confidence, the PID it is running as, and the sentence explaining why it belongs. Members can be removed from the same window — an automatic member's removal is persisted as an exclusion so the evidence cannot re-add it — and executables can be added by browsing for the file. Everything is persisted by `ProcessGroupManager`, so no configuration file has to be edited by hand. The dialog follows the monitor's published group snapshots, so a membership change made on the cache thread appears while the window is open, and an inactive or unknown group is shown read-only with an explanation instead of an empty table. `NetworkMonitor` now exposes `processGroups()`, `createProcessGroup()`, `renameProcessGroup()`, `addProcessGroupMember()`, `removeProcessGroupMember()`, and `groupSnapshotReady`, all serialized with the cache thread through a group mutex; the tree model exposes the group id as `Qt::UserRole + 7`, and service rows carry their host's group in the tooltip. Its summary line and the member pane show the NG-015 category: the group's learned category (or "not classified yet"), and for the selected member the category it is acted on as, marked "(learned from this group)" when it comes from the group rather than from a rule naming the file — the inspector is read-only, so opening the dialog cannot change a group's category. Verified on Windows 10 19045 with a standalone offscreen harness driving the real dialog: 49 checks covering the monitor API, table contents and labels, the evidence pane, rename and its validation, a live snapshot refresh, member removal and the empty state, an unknown group, the model role, and reload persistence, plus 31 checks over the category display, the alert event's group evidence, and the dialog's summary and member pane for a learned group, an unclassified group, and no guard. The dialog has not been visually reviewed in the running application, and the "Add executable" file dialog is not exercised by the harness.
- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-014
- **Goal:** Show identity evidence, related processes, services, publisher, paths, and confidence.
- **Acceptance criteria:** Users can inspect and remove group members without editing configuration files.
- **Validation:** open a grouped process (for example a browser with its updater running), choose "Activity group...", confirm the members and their explanations match what is running, remove an automatic member and check it does not come back after the next refresh or a restart, and rename the group and confirm the name is still there after restarting the application.

## Phase 2: Policy and enforcement coordination

### NG-020 Create versioned policy store

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-002, NG-014
- **Goal:** Persist policies using explicit scope, action, direction, rate, schedule, expiration, source, and enabled state.
- **Acceptance criteria:** Old settings migrate safely; malformed policies are rejected with a recoverable error; policies can be exported and imported.

- **Status:** Partial — `PolicyStore` implements versioned QSettings persistence (v1 `QVariantMap` legacy, v2 JSON array), `loadPolicies()`/`savePolicies()`/`exportPoliciesJson()`/`importPoliciesJson()`/`migrateOldFormat()`. `savePolicies()` had been writing the v1 map under `formatVersion` 2 while `loadPolicies()` and `exportPoliciesJson()` read the v2 JSON string, so every saved policy was unreadable and an export was empty; it now serialises the array with `toJson(NetworkPolicy)`. `tests/netguard_tests` seeds a four-policy set, reloads it, writes back an emergency-restore result, and checks that exactly the preserved policies survive with their source, action, direction, rate, description, and order. Remaining: import, export, and the v1→v2 migration path are not exercised, and no live UI writes policies yet.

### NG-021 Coordinate firewall, QoS, and WinDivert enforcement

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-020
- **Goal:** Coordinate Windows Firewall, Windows QoS, and WinDivert without duplicating policy decisions in UI code.
- **Acceptance criteria:** One policy produces a complete per-channel result; partial success is represented explicitly; all requests are auditable.

- **Status:** Partial — `EnforcementCoordinator` in `src/network/enforcementcoordinator.*` is now part of the build and is an instance owned by `NetworkWidget`, given the existing `ThrottlePolicyManager` and `FirewallManager` rather than creating its own. `plannedChannels()` decides the channel once: Block and Allow are firewall rules, Throttle and Schedule go to shaping (upload through QoS, download through WinDivert, independently per direction), and Notify/Ask/NoAction need no channel; the same description is carried in every result. Each result names its policy, executable, channels, and a `Status`: a disabled policy, an advisory action, or a missing rate reports `NotApplied` with the reason instead of pretending to enforce; a missing manager or a failed initialization reports `Failed`; a created firewall rule reports `Applied`; a shaping request reports `Requested` because the PowerShell/WinDivert work happens on the throttle worker. `applyPolicy()` emits `policyApplied`, `applyAllPolicies()` emits one `enforcementComplete`, and no channel is guessed in UI code. Remaining: `Partial` is declared but never produced — the worker's upload and download outcome arrives through `ThrottlePolicyManager`'s own signals and is not yet folded back into a result — and no live firewall, QoS, or WinDivert application has been run.

### NG-022 Add policy scope selection

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-020, NG-021
- **Goal:** Support PID, executable path, publisher, service, package, and application-group scopes.
- **Acceptance criteria:** The UI explains scope breadth and risk before applying a policy; group scope controls future matching processes.

- **Status:** Partial — `PolicyEditorDialog` in `src/network/policyeditordialog.*` is opened from "🛡 Create policy..." in the process context menu. It offers the five scopes from PRD 9.3 (this PID, this executable path, this publisher, this Windows service, this application group) and, before Save, states the breadth, explains what the scope covers, says whether processes that appear later inherit it, and says whether this build can enforce that scope. The target is prefilled from the selected row and its activity group (executable path, publisher, first service member, group name and id) and follows the chosen scope, so a path is never carried into a publisher policy. The effect controls cover action (allow, throttle, block, notify, ask, no action), direction, rate, an optional recurring window validated with `scheduleIsSupported()`, an optional expiration, and a note. Validation rejects a missing target, an unsupported window, a throttle without a rate, and a past expiration. Save writes a `source` = `user` policy through `PolicyStore` (so emergency restore preserves it) and runs the scheduler immediately, which applies it through the coordinator when the scope is one this build resolves (path or group) and the policy is in force; a group policy stores the group id in `targetId`, which is how NG-025 applies it to members that appear later. `PolicyListDialog` in `src/network/policylistdialog.*` is opened from the **Policies…** toolbar button and lists every stored policy with its derived activation state, scope, target, action, direction, rate, recurring window, expiration, and source. It reloads from the store after every change, edits through the same editor (keeping the policy id and source), deletes only after confirmation, and refuses to edit scopes the editor cannot represent (`port`, `protocol`, `package`) instead of silently rewriting them. After a change it forgets the coordinator's re-application memory and runs the scheduler once. Remaining: editing or deleting a policy withdraws its attributed firewall rules and bandwidth limit through NG-024; PID, publisher, and service policies are explained and saved but not enforced because no resolver maps them to running processes; and neither dialog has been reviewed in the running application or covered by tests.

### NG-023 Add temporary and scheduled policies

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-020, NG-021
- **Goal:** Support expiration, recurring schedules, and network-profile conditions.
- **Acceptance criteria:** Policies activate and deactivate at expected boundaries; a missed transition is recovered on startup.

- **Status:** Partial — `src/network/policyschedule.*` derives whether a policy is in force. The stored `enabled` flag is the user's switch; a valid `expiration` makes the policy `Expired` once it passes; `Recurring` and `Both` policies are `Active` or `Inactive` according to a local-time window. Supported windows are empty/`always`/`*`, the named `work-hours` (Mon-Fri 09:00-17:00) and `overnight` (22:00-06:00, crossing midnight), `HH:MM-HH:MM` (may cross midnight), and `<days> HH:MM-HH:MM` where days are a single name, a range (including `Fri-Mon`), or a comma list; an unrecognised window is reported `Unsupported` instead of silently enforcing on or off. `PolicyScheduler` evaluates the store immediately when started and every 15 s afterwards, emitting `activationChanged` only when a policy's state actually moves, so the startup evaluation is also the recovery path for a boundary that passed while the application was closed — activation is derived from the wall clock and never persisted, and no transition has to be replayed. `NetworkWidget` starts the scheduler with the application; when a path- or executable-scoped policy becomes active it applies it through the coordinator, and when a group-scoped policy becomes active it re-applies it to that group's running executables from the last group snapshot. Remaining: leaving a window withdraws the attributed firewall rules and bandwidth limit through NG-024; publisher, service, and package scopes are not resolved; network-profile conditions (for example a metered connection) are not modelled, so such schedules report `Unsupported`; and the 15 s poll can apply or end a boundary up to 15 s late.

### NG-024 Verify and reconcile applied policy state

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-021
- **Goal:** Verify that persisted firewall and QoS policies still exist and that WinDivert shaping matches the active policy set.
- **Status:** Partial — `src/network/policyreconcile.*` compares the stored, currently active policies with what the enforcement channels report, then repairs or removes the difference. Firewall rules created by a policy now carry its id in the rule description (`FirewallManager::blockApp()`/`allowApp()` take an optional policy id, and `listRules()` exposes the description), which is what makes safe cleanup possible: attributed rules that no active policy wants are removed, missing or unattributed rules are re-created with the id, and NetGuard rules created from the Firewall tab are counted and left in place. A missing bandwidth limit is requested again, and each limit applied by a policy now records that policy's id (`ThrottlePolicyManager::applyForPolicy()`, persisted with the active set), so reconciliation can withdraw the limit of a policy that was deleted, disabled, expired, or left its window; an automatic limit with no active policy is removed the same way, while a limit applied outside a policy is left in place. When a different active policy takes over a path that is already limited, reconciliation hands ownership over without another QoS call (an automatic user policy also updates the restore flag), so later withdrawal follows the policy that wants the limit now. The **Limits...** toolbar button opens `BandwidthLimitsDialog`, which lists every enforced limit (path, 50 KiB/s, upload or upload+download) and its owner: the owning policy's description and id, or "Manual (applied outside a policy)"; the list refreshes when the worker reports a result. **Remove limit** asks for confirmation showing that owner (the policy itself is not changed), requests removal through the manager, and the row disappears when the worker reports back. The process menu (and the Data Saver detection menu) also names the owner in the throttle action once a limit exists, so "Remove bandwidth limit (policy: <description>)" replaces the anonymous apply label; an unattributed limit reads "Remove bandwidth limit (manual)". Disabled, expired, and out-of-window policies count as not wanted, so leaving a schedule window now withdraws the attributed firewall rules and bandwidth limit. `PolicyReconciler` runs once after startup when the firewall initialized, on every policy activation change (coalesced through a single-shot), and on demand from **Verify...** in the Policies dialog, which shows the report (repaired, removed, failed, left in place, unresolved) and puts the summary in the status bar. `planPolicyReconciliation()` and `reconciledPolicyId()` are pure and live in `policyreconcileplan.cpp`, so the decisions are covered by the harness without COM (71 checks: attribution parsing, missing/disabled/rewritten rules, stale removal, action changes, disabled and expired policies, agreeing and conflicting policies, group expansion, unresolved scopes, and throttle repairs, stale automatic limits, limits attributed to deleted or disabled policies, and unattributed limits). Firewall rule names now include a hash of the normalized full executable path (`src/firewall/rulenames.*`), so two files with the same base name no longer share or overwrite one rule; the harness checks that distinct paths get distinct names and that case, separator, and redundant-segment variations map to one name. Rules written by older builds stay recognised by `isBlocked()`, are removed alongside the new names by `removeAppRules()`, and are replaced the next time a rule is applied, so an upgraded install converges without a migration pass. Remaining: a bandwidth limit is still path-keyed, so policies that target one path share one limit; a limit applied outside a policy is never adopted by a policy; the Limits dialog removes only the limit, not the owning policy; a scope this build cannot resolve (PID, publisher, service, package, port, protocol) is reported as unresolved rather than verified; the NetGuard rule enumeration runs on the GUI thread, although activation changes are coalesced; and no live elevated run was performed, so the executor's COM calls are only compile-checked.
- **Acceptance criteria:** Stale records are marked and repaired or removed; the user sees failures; reconciliation does not block the GUI.

### NG-025 Add respawn and replacement enforcement

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-014, NG-021, NG-024
- **Goal:** Re-apply group policies when an updater or worker exits and a related process appears.
- **Acceptance criteria:** A fixture can terminate a worker, start a replacement, and show that the replacement receives the expected control without manual action.

- **Status:** Partial — `EnforcementCoordinator::reapplyGroupPolicies()` re-applies the enabled group-scoped policies (`scope` = `group`, `targetId` = the group id) to the executables currently running in that group, and `NetworkWidget` calls it for every `groupSnapshotReady` snapshot. Groups are rebuilt from the processes that own traffic, so an updater or worker that exits and is replaced appears as a membership change: a replacement at a new path gets its own firewall rule or shaping request, while a process that returns at the same path is recognised as already covered and is not applied twice. The coordinator remembers each `(group, policy, path)` triple, retries a hard failure on the next snapshot, skips advisory (Notify/Ask/NoAction) policies because they have no enforcement channel, and forgets the triples when emergency restore changes the stored set. Remaining: the terminate-and-replace fixture and the measured re-application are deferred with the rest of the NG-027 work, and no UI creates group-scoped policies yet, so the path is not exercised against live traffic.

### NG-026 Add policy emergency restore

- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-021
- **Goal:** Provide one action to remove automatic controls while preserving explicit user policies.
- **Acceptance criteria:** Automatic and user-created policies are distinguishable; restore results list successes and failures.

- **Status:** Partial — the planning and reporting live in `src/network/enforcementrestore.*`. `policyOrigin()` splits a policy into `User`, `Automatic` (only the product's own sources: `automatic`, `auto`, `system`, `ai`), or `Unknown`; `buildEmergencyRestorePlan()` removes only automatic policies and preserves everything else; `applyEmergencyRestorePlan()` reports each removed, preserved, or failed policy plus the throttle channel, and a failed store write becomes a `failed` entry instead of a claimed removal. `EnforcementCoordinator::emergencyRestore()` loads the store, writes back the preserved set through the now-JSON `savePolicies()`, asks `ThrottlePolicyManager::restoreAutoApplied()` only when a worker is attached, and emits `emergencyRestoreCompleted`; `NetworkWidget` shows the report (one line per action, failures included) in the restore dialog next to the throttle outcome. Firewall rules are deliberately not removed: this build only creates them from the Firewall tab after an explicit user action. `tests/netguard_tests` covers origin classification, the automatic/preserved split, removal/preservation/failure entries, `summary()`/`lines()`, the skipped-throttle case, a failed store write, and a store round-trip proving only the preserved policies survive with their fields. Remaining: the dialog and the automatic throttle restore have not been run against a live system, and no UI creates automatic policies yet, so the path is exercised through the store rather than by real enforcement.

### NG-027 Add enforcement integration tests

- **Type:** test
- **Priority:** P0
- **Dependencies:** NG-021, NG-025, NG-026
- **Goal:** Verify upload, download, combined, block, restore, missing-driver, access-denied, and process-respawn behavior.
- **Acceptance criteria:** Tests assert actual policy state and measured behavior where the environment supports elevation and WinDivert.

- **Status:** Partial — the channel decision and the restore report are covered without elevation: `tests/netguard_tests` asserts `plannedChannels()`/`channelsDescription()` for block, allow, throttle, and schedule in download, upload, and both directions; that advisory actions and disabled policies need no channel; the emergency-restore plan, per-action report, failure entries, and preserved-set write-back. The application-side coordinator is constructed with the real managers in `NetworkWidget` and the application builds with it. Remaining: upload, download, combined, block, restore, missing-driver, access-denied, and respawn behaviour are not measured against a live system — that needs elevation and a WinDivert driver and would modify real firewall/QoS state, so these tests are not run automatically.

## Phase 3: DNS, TLS, and endpoint attribution

### NG-030 Implement passive DNS observer

- **Status:** Partial — `src/attribution/dnsobserver.*` parses a visible UDP DNS message into a `DnsEvent` carrying the timestamp, response/truncated flags, lower-cased question name (no trailing root dot), QTYPE and printable name, A/AAAA addresses, CNAME aliases, the minimum answer TTL, and a hex transaction id; the raw payload is discarded after parsing, so nothing in the event can reconstruct the message. Compression pointers are only followed backwards, labels are capped at 63 bytes and the expanded name at 255, question/answer counts are capped, and a short header, missing question, overrun record, reserved label type, or non-standard opcode yields no event instead of a partial one. `NetworkMonitor` calls the parser only for UDP on port 53 (IPv4 and plain IPv6; extension headers and TCP DNS are not attempted) and emits `dnsObservation` with the resolved socket owner's PID, process name, and identity id when the cache can attribute it; an unresolved socket leaves those fields empty rather than naming a guess. Confidence is `StrongInference` when a response carries addresses, `WeakInference` for a response without them, and `Unknown` for a bare query until NG-035 joins more evidence. The harness covers a query, a compressed response with CNAME/A/AAAA, the smallest-TTL rule, IPv4 and IPv6 datagram framing, non-53 traffic, and six malformed inputs (29 checks). Remaining: it has not run against live capture, and encrypted DNS, DNS over TCP, and IPv6 extension headers are intentionally unattributed.
- **Type:** feature
- **Priority:** P0
- **Dependencies:** NG-002
- **Goal:** Parse visible DNS request and response metadata without retaining payloads.
- **Acceptance criteria:** A DNS event includes name, record type, addresses, timestamp, source process when resolvable, and confidence; malformed packets are ignored safely.

### NG-031 Correlate DNS answers with connections

- **Status:** Done — `src/attribution/dnscorrelator.*` indexes each A/AAAA answer by destination address and keeps the name, querying PID/process/identity, confidence, attribution source, first/last-seen times, and expiry. A destination can carry up to eight names, returned most recently seen first; a repeated name refreshes its TTL and owner without duplicating or losing the first sighting, and an unresolved refresh keeps the previously known identity. Lifetime is the smaller of the DNS TTL and one hour, falling back to five minutes when the answer carries no TTL, so an expired name is never applied to a connection. The store holds at most 4096 addresses and evicts the least recently seen one, and `NetworkMonitor::attributionsForAddress()` returns only still-valid records. Every record exposes `AttributionSource::DnsAnswer` (or `Unknown` for a miss), so a direct-IP connection is not presented as domain-attributed. The harness covers the TTL boundary, multi-name ordering and refresh, identity retention, query rejection, both caps, and the TTL clamp/default (33 checks). Remaining: no UI or classification consumes the lookup yet (NG-035 does the evidence model), and the live capture path has not been exercised.
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
