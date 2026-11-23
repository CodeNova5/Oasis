# Oasis: Data Saver Automation Tickets

This backlog implements [DATA_SAVER_AUTOMATION_PRD.md](DATA_SAVER_AUTOMATION_PRD.md). Tickets are ordered by dependency within each phase.

## Ticket conventions

- **Status:** `Not started`, `In progress`, `Done`, or `Blocked`.
- **Priority:** P0 required for a safe first implementation; P1 important follow-up; P2 later enhancement.
- **Acceptance:** Observable completion conditions, including tests.
- **No ticket may send AI output directly to enforcement.**

## Phase 0: Contracts and foundations

### DSA-001 Add Data Saver automation contracts

- **Status:** Not started
- **Type:** refactor
- **Priority:** P0
- **Dependencies:** None
- **Goal:** Define versioned value types for flow observations, policy decisions, evidence cache keys, and policy resolution reports.
- **Implementation:**
  - Add contracts in `src/network/` or a dedicated `src/datasaver/` module.
  - Keep contracts QtCore-only and cross-thread safe.
  - Use schema version $1$ and reject newer schemas.
  - Reuse existing `NetworkPolicy`, `AuditEvent`, `ApplicationIdentity`, and `Activity::Event` types where possible.
- **Acceptance:**
  - All contracts round-trip through JSON in harness tests.
  - Missing, malformed, unknown, and newer-schema fields are handled safely.
  - Contracts contain no packet payload or API credential fields.
  - Qt metatypes are registered for worker-thread signals.

### DSA-002 Add canonical FlowObservation construction

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-001, existing NG-010 through NG-041
- **Goal:** Build one normalized observation from process, parent, identity, foreground, DNS/SNI, QUIC, and metric evidence.
- **Implementation:**
  - Add stable observation and flow IDs.
  - Attach process role and foreground state.
  - Mark SNI confidence: `verified_sni`, `dns_correlated`, `ech_outer_only`, or `none`.
  - Mark multiplexed CDN connections conservatively.
  - Sanitize paths and destinations before cache and audit storage.
- **Acceptance:**
  - Reused and recycled PIDs cannot inherit stale ownership.
  - Child processes inherit foreground eligibility only through validated lineage.
  - ECH and QUIC without a verified SNI produce `none` or `ech_outer_only`.
  - An observation can be constructed in a harness with no live network.

### DSA-003 Add Data Saver settings and profile state

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-001
- **Goal:** Persist Off, Monitor, and Enforce Data Saver modes plus profile-level foreground/background policy.
- **Implementation:**
  - Persist a versioned settings object in `QSettings`.
  - Support metered hotspot, manual toggle, and battery saver sources.
  - Define foreground and background fallback behavior.
  - Integrate with existing Data Saver mode controls.
- **Acceptance:**
  - Missing or malformed settings fall back safely to Off or Monitor.
  - Settings changes emit one state transition.
  - Disabling Data Saver does not delete user policies.

## Phase 1: Deterministic policy engine

### DSA-010 Implement policy resolver precedence

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-001, DSA-003, existing NG-020 through NG-024
- **Goal:** Resolve a single deterministic decision from all policy tiers.
- **Implementation:**
  - Check user pinned rules first.
  - Check user session overrides second.
  - Check active profile rules third.
  - Check cache fourth.
  - Return safe fallback fifth.
  - Include matched tier, rule ID, cache key, conflict data, and fallback reason in the result.
- **Acceptance:**
  - Resolution order is deterministic for every fixture.
  - Higher tiers win over lower tiers even if lower confidence is higher.
  - Manual allow wins over cached AI throttle/block.
  - Conflicts are represented and auditable.

### DSA-011 Implement profile rules and local signatures

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-010, existing NG-034 and NG-040
- **Goal:** Add signed, updateable local rules for known OS, browser, IDE, package, media, telemetry, and CDN activity.
- **Implementation:**
  - Add a signed local catalog or reuse `EndpointCatalog`.
  - Match executable, publisher, service, identity, group, domain, and process role.
  - Preserve an unknown result for ambiguous evidence.
  - Produce `PolicyDecision`, not a raw category or text response.
- **Acceptance:**
  - VS Code updater, extension host, npm, pip, and an unknown app receive distinct fixtures.
  - Interactive package installs do not receive automatic block decisions.
  - Catalog edits cannot introduce an action outside the decision schema.
  - Unknown local rules do not send a network request by themselves.

### DSA-012 Implement safe fallback decisions

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-010
- **Goal:** Guarantee that unresolved activity receives a conservative immediate result.
- **Implementation:**
  - Foreground unknown: allow or notify.
  - Background unknown: notify or gentle throttle where the active profile permits it.
  - Never cache fallback decisions by default.
  - Cap unknown and low-confidence AI decisions at notify or notify-then-continue.
- **Acceptance:**
  - No unknown foreground flow is hard-blocked in the absence of a pinned/profile rule.
  - No fallback waits for SQLite or cloud AI.
  - Every fallback has a reason and `applied_action` for audit.

### DSA-013 Implement evidence cache store

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-001, DSA-010
- **Goal:** Persist and evict AI and heuristic policy decisions using an evidence fingerprint.
- **Implementation:**
  - Compute SHA-256 or equivalent cache keys from normalized evidence fields.
  - Use byte, duration, foreground, executable-version, source, and destination buckets.
  - Store TTL, expiration, result, schema version, and source tier.
  - Evict entries by expiration and bounded store size.
- **Acceptance:**
  - 12 MB and 450 MB transfers do not share a cache key.
  - `exe_version` changes invalidate app/update decisions.
  - A low-confidence entry expires in 15 to 60 minutes.
  - Malformed or newer cache entries are rejected.

### DSA-014 Implement session and pinned override controls

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-010, existing NG-020 and NG-022
- **Goal:** Create session and persistent allow decisions from notification actions.
- **Implementation:**
  - `Allow Once` creates a Tier 2 session override.
  - `Always Allow` creates a Tier 1 persistent `NetworkPolicy`.
  - Define app restart/session end behavior.
  - Keep scope narrow unless the user explicitly chooses executable or domain scope.
- **Acceptance:**
  - Session override expires on session end or app restart as configured.
  - Always Allow is visible in Policies and can be removed or edited.
  - Session overrides cannot change the base policy store without explicit user intent.

## Phase 2: Flow and milestone observation

### DSA-020 Add per-flow byte and milestone tracking

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-002
- **Goal:** Track cumulative RX/TX, elapsed duration, rate, and milestone crossings for each flow.
- **Implementation:**
  - Maintain in-memory flow records with 5-tuple and process ownership.
  - Aggregate only metadata.
  - Emit milestone jobs for $10$, $25$, $50$, $100$ MB and later doubling.
  - Re-evaluate after bucket boundary changes, foreground transitions, and app restarts.
- **Acceptance:**
  - Duplicate packets do not repeat a milestone.
  - Bursty transfer milestones are deduplicated.
  - Re-evaluation occurs for 10/25/50/100 MB and later required boundaries.
  - Flow expiry is bounded and never retains payload data.

### DSA-021 Add foreground and background state transitions

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-002, existing NG-041
- **Goal:** Classify foreground-active, foreground-idle, and background state with fresh lineage evidence.
- **Implementation:**
  - Inherit foreground eligibility to validated child PIDs.
  - Mark stale snapshots as unknown or background as configured.
  - Emit only meaningful state transitions.
  - Re-run policy resolution after a meaningful transition.
- **Acceptance:**
  - Recycled PIDs do not inherit foreground state.
  - A stale sample cannot produce active UX handling.
  - A foreground app becoming idle can move to profile handling.

### DSA-022 Convert Activity events to policy candidates

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-010, DSA-020, existing activity detector
- **Goal:** Feed qualified background Activity events into the policy engine without making the detector enforce anything.
- **Implementation:**
  - Translate each category to detector tags.
  - Preserve volume, peak, attribution, destination, PID, and app evidence.
  - Apply Tier 1-5 precedence.
  - Apply background fallback as $50$ KiB/s only after candidate qualification.
- **Acceptance:**
  - Detector unit tests remain observation-only.
  - A qualifying background event produces one policy resolution.
  - The existing cross-category cooldown remains separate from enforcement.

### DSA-023 Handle multiplexed and weak-attribution connections

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-002, DSA-010
- **Goal:** Prevent hard block actions from harming shared streams or unidentified connections.
- **Implementation:**
  - Detect and flag HTTP/2/HTTP/3 multiplexing where evidence exists.
  - Downgrade weak SNI and ECH outer-only evidence to throttle/notify.
  - Permit block only for a dedicated executable or pinned rule with confirmed process ownership.
- **Acceptance:**
  - CDN-multiplexed flow cannot receive automatic socket-level block.
  - Weak attribution cannot create a high-confidence block.
  - Throttle behavior is scoped to the process or policy-supported channel.

## Phase 3: Async classifier and Groq

### DSA-030 Add structured classifier adapter contract

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-001
- **Goal:** Support local rules and an optional structured cloud classifier behind one interface.
- **Implementation:**
  - Replace or extend text-only AI path with a `ClassifyFlow` interface.
  - Return raw JSON only to a strict parser.
  - Do not expose policy creation or enforcement methods to providers.
- **Acceptance:**
  - Provider output cannot mutate policy or cache.
  - Unknown or invalid JSON returns a fallback status.
  - Adapter calls are counted and deduplicated.

### DSA-031 Implement Groq OpenAI-compatible provider

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-030, existing NG-045
- **Goal:** Add Groq as an opt-in structured classifier with `GROQ_API_KEY` from the environment.
- **Implementation:**
  - Add HTTPS endpoint and model configuration.
  - Use an OpenAI-compatible chat-completions API.
  - Send only the bounded privacy-redacted classifier payload.
  - Add JSON mode or strict schema mode if supported by the selected model.
  - Cap raw response and timeout.
- **Acceptance:**
  - No API call occurs while AI is disabled or unconfigured.
  - Missing key, unsafe endpoint, timeout, network, HTTP, and malformed response states are covered.
  - Key, executable path, local IP, and payload bytes do not appear in logs or cache.

### DSA-032 Implement strict PolicyDecision validator

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-030, DSA-031
- **Goal:** Accept only schema-valid, locally consistent classifier decisions.
- **Implementation:**
  - Validate classification, action, scope, throttle, TTL, and expiration fields.
  - Reject unknown enum values and contradictory fields.
  - Cap low-confidence decisions at notify or notify-then-continue.
  - Require domain/executable evidence consistent with the request context.
- **Acceptance:**
  - Oversized or malformed JSON is rejected.
  - AI cannot raise a cached block above local confidence limits.
  - AI cannot invent scope or executable evidence absent from the observation.

### DSA-033 Build privacy-redacted classifier payload

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-002, DSA-030, existing NG-044 and NG-036
- **Goal:** Produce a minimal payload suitable for local review and optional cloud classification.
- **Implementation:**
  - Remove executable path and local IP.
  - Retain base executable name only.
  - Redact user-specific subdomains and unknown destination values.
  - Include byte/duration buckets and UX profile, not raw payload.
  - Add exact payload preview and send confirmation.
- **Acceptance:**
  - Payload stays below 4096 bytes.
  - Raw domain/path/IP values are absent when required by privacy settings.
  - The exact payload is shown before opt-in send.
  - Cloud failure cannot alter local classification or policy state.

### DSA-034 Implement classifier job queue and dedupe

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-020, DSA-030
- **Goal:** Run local and optional cloud classification without packet or GUI stalls.
- **Implementation:**
  - Enqueue `ClassifyFlowJob(flow_id, milestone, fingerprint)`.
  - Dedupe matching jobs with a bounded in-memory set.
  - Apply safe fallback immediately before the job runs.
  - Cancel stale jobs when flow/session state changes.
- **Acceptance:**
  - Multiple packets cannot create repeated AI calls for one milestone.
  - AI timeout does not block capture or UI.
  - A stale result cannot commit after flow ownership or foreground state changes.

## Phase 4: Enforcement integration

### DSA-040 Integrate policy decisions with EnforcementCoordinator

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-010, DSA-014, existing NG-021 and NG-024
- **Goal:** Convert validated decisions into existing firewall, throttle, and notification channels.
- **Implementation:**
  - Extend `NetworkPolicy` creation for Data Saver decisions only through the existing store/coordinator.
  - Use scoped executable/group/domain targets supported by this build.
  - Treat `notify` and `notify_then_continue` as non-enforcement actions.
  - Fold channel results into one policy decision report.
- **Acceptance:**
  - Throttle produces download or upload shaping as requested.
  - Hard block uses confirmed/dedicated ownership or a pinned rule.
  - Missing channels produce visible failure, never silent success.
  - Partial channel success is audited.

### DSA-041 Implement $50$ KiB/s background throttle profile

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-022, DSA-040
- **Goal:** Apply the profile's default background throttle after a qualifying event.
- **Implementation:**
  - Convert $50$ KiB/s to the existing policy rate format.
  - Apply by executable, group, or supported identity scope.
  - Record automatic policy origin and policy ID.
  - Respect pinned allow and session override precedence.
- **Acceptance:**
  - A qualifying non-foreground event produces exactly one $50$ KiB/s candidate.
  - A foreground app does not receive this fallback solely for being active.
  - The throttle is reversible and reconciliable.

### DSA-042 Implement milestone re-evaluation and withdrawal

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-020, DSA-040
- **Goal:** Re-evaluate at volume buckets and withdraw temporary automatic controls when warranted.
- **Implementation:**
  - Re-evaluate cache and AI after 10/25/50/100 MB milestones.
  - Withdraw session and temporary AI policy ownership only after a configured transition.
  - Preserve pinned user policies.
  - Add app state, foreground change, and manual override transitions.
- **Acceptance:**
  - A temporary throttle ends at session end or configured milestone.
  - Disabling Data Saver removes automatic policies without deleting user policies.
  - Emergency restore removes AI/automatic controls only.

### DSA-043 Implement conflict and rule ownership reporting

- **Status:** Not started
- **Type:** feature
- **Priority:** P1
- **Dependencies:** DSA-010, DSA-040
- **Goal:** Make every decision explain why it won and which lower-tier rule was suppressed.
- **Implementation:**
  - Store `rule_conflict`, matched tier, policy owner, and cache key.
  - Show conflict in notification, policy details, and audit.
  - Reconcile stale owners after policy edits.
- **Acceptance:**
  - Editing or deleting a pinned rule immediately changes resolution state.
  - Audit lists which tier won and why.

## Phase 5: User interface and notifications

### DSA-050 Add Data Saver decision notification actions

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-040, existing NG-051
- **Goal:** Provide a concise actionable notification for throttle, block, notify, and notify-then-continue transitions.
- **Implementation:**
  - Include executable, domain, milestone, action, reason, and next steps.
  - Add Allow Once and Always Allow actions.
  - Add Inspect Application/Activity action.
  - Route through `NotificationCoordinator` dedupe and priority rules.
- **Acceptance:**
  - Repeated detections use dedupe and fold counts.
  - Allow Once creates a session override.
  - Always Allow creates a persistent pinned policy.
  - Enforcement failure remains visible as critical.

### DSA-051 Add AI payload review and opt-in settings

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-031, DSA-033, existing NG-046
- **Goal:** Let the user enable Groq and review the exact classifier payload before sending.
- **Implementation:**
  - Add enabled toggle, endpoint, model, timeout, and redaction preview.
  - Read Groq key only from `GROQ_API_KEY`.
  - Keep key out of settings and audit.
  - Add test request and failure status.
- **Acceptance:**
  - AI is disabled by default.
  - Sending requires opt-in and a visible exact-payload preview.
  - Unsafe endpoint or missing key cannot make a request.
  - Settings persist without credentials.

### DSA-052 Add Data Saver decisions to Application Detail and Activity

- **Status:** Not started
- **Type:** feature
- **Priority:** P1
- **Dependencies:** DSA-040, existing NG-052
- **Goal:** Surface decision tier, evidence, cache state, action, and reversal from existing views.
- **Implementation:**
  - Add decision summary to application detail.
  - Add policy status to Activity event cards.
  - Link notification into the same evidence view.
- **Acceptance:**
  - User can inspect matched policy/rule, cache, and fallback source.
  - User can remove or change the created policy from existing policy UI.

## Phase 6: Audit and privacy

### DSA-060 Extend audit schema for Data Saver decisions

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-040
- **Goal:** Record all observation-to-policy transitions as payload-free audit events.
- **Implementation:**
  - Reuse `AuditEventStore`.
  - Record observation, flow, milestone, action, tier, cache key, evidence summary, and enforcement result.
  - Keep credential, payload, and raw packet fields prohibited.
- **Acceptance:**
  - Audit export contains no payload or key fields.
  - Query can filter Data Saver event types and policy IDs.
  - Failed and successful enforcement are distinguishable.

### DSA-061 Extend privacy controls and redaction

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DSA-033, existing NG-036
- **Goal:** Ensure flow and AI metadata obey the existing privacy settings.
- **Implementation:**
  - Respect DNS, TLS, and QUIC collection switches.
  - Redact destinations in audit and cache exports.
  - Clear cached AI evidence through privacy history controls.
- **Acceptance:**
  - Disabling attribution collection stops new AI destination metadata.
  - Clearing attribution history clears or redacts relevant cache evidence.
  - Existing settings and export redaction remain compatible.

## Phase 7: Tests and validation

### DSA-070 Add pure policy-engine harness tests

- **Status:** Not started
- **Type:** test
- **Priority:** P0
- **Dependencies:** DSA-010 through DSA-014
- **Goal:** Validate precedence, cache, fallback, and schema behavior without elevation or network access.
- **Acceptance:**
  - At least 100 focused assertions cover tier precedence and conflict behavior.
  - Fixtures cover 10/25/50/100 MB and app-version invalidation.
  - Harness exits nonzero on failure.

### DSA-071 Add local signature and edge-flow fixtures

- **Status:** Not started
- **Type:** test
- **Priority:** P0
- **Dependencies:** DSA-011, DSA-020, DSA-023
- **Goal:** Test package managers, IDE updates, extension updates, AI chats, media, telemetry, CDN multiplexing, and ECH.
- **Acceptance:**
  - Interactive npm/pip/Copilot flows receive no automatic block fixture.
  - VS Code core and extension update fixtures classify locally.
  - Shared CDN and ECH fixtures never recommend hard block.
  - Unknown flows use fallback only.

### DSA-072 Add Groq adapter integration tests

- **Status:** Not started
- **Type:** test
- **Priority:** P0
- **Dependencies:** DSA-031 through DSA-034
- **Goal:** Test Groq success and all safe-degradation states.
- **Acceptance:**
  - Missing key, malformed key state, timeout, HTTP error, malformed JSON, and oversized response are covered.
  - A valid response is parsed and validator-checked.
  - AI output cannot call an enforcement API in tests.

### DSA-073 Add live Windows enforcement tests

- **Status:** Not started
- **Type:** test
- **Priority:** P1
- **Dependencies:** DSA-040 through DSA-043
- **Goal:** Verify firewall, QoS, and WinDivert behavior with elevation.
- **Acceptance:**
  - Live block, allow, download throttle, upload throttle, restore, and missing-driver behavior are recorded.
  - Real enforcement changes are reversible.
  - Tests are clearly gated and not run in the normal harness without elevation.

### DSA-074 Add notification and override tests

- **Status:** Not started
- **Type:** test
- **Priority:** P0
- **Dependencies:** DSA-050, DSA-014
- **Goal:** Verify notification dedupe and session/pinned override behavior.
- **Acceptance:**
  - Same-key repeats fold once.
  - Allow Once expires.
  - Always Allow persists and appears in Policies.
  - Pinned allow wins over cache and profile tier.

### DSA-075 Add privacy and audit tests

- **Status:** Not started
- **Type:** test
- **Priority:** P0
- **Dependencies:** DSA-060, DSA-061
- **Goal:** Verify metadata-only audit and privacy behavior.
- **Acceptance:**
  - No raw destination, payload, key, or full executable path appears in cloud payload or audit export unless explicitly permitted.
  - Redaction mode and clear-history behavior work in harness tests.

## Rollout tickets

### DSA-080 Implement feature flag and diagnostics mode

- **Status:** Not started
- **Type:** feature
- **Priority:** P1
- **Dependencies:** DSA-010, DSA-060
- **Goal:** Introduce a developer/early-user flag for staged rollout.
- **Acceptance:**
  - Flag is disabled by default.
  - Diagnostics expose resolved tier and reason without executing enforcement.
  - Enabling Monitor mode requires no AI and no cloud key.

### DSA-081 Add Monitor-to-Enforce migration

- **Status:** Not started
- **Type:** feature
- **Priority:** P1
- **Dependencies:** DSA-080, DSA-040
- **Goal:** Encourage but never silently switch from Monitor to Enforce.
- **Acceptance:**
  - Mode change requires explicit confirmation.
  - Enforce mode lists automatic actions that may apply.
  - Exit can withdraw automatic controls and retain pinned rules.

### DSA-082 Write user documentation

- **Status:** Not started
- **Type:** documentation
- **Priority:** P1
- **Dependencies:** DSA-050, DSA-051
- **Goal:** Document Data Saver behavior, overrides, privacy, and Groq setup.
- **Acceptance:**
  - VS Code and package-manager examples explain why they are handled conservatively.
  - Groq setup uses `GROQ_API_KEY` and never implies key persistence.
  - Restore, Allow Once, Always Allow, and audit behavior are documented.

## Recommended implementation order

1. DSA-001 through DSA-003: contracts and settings.
2. DSA-010 through DSA-014: precedence, fallback, cache, and overrides.
3. DSA-020 through DSA-023: flow, milestones, foreground state, and multiplexing.
4. DSA-030 through DSA-034: local/AI classification without enforcement coupling.
5. DSA-040 through DSA-043: enforcement and withdrawal.
6. DSA-050 through DSA-052: notifications and UI.
7. DSA-060 through DSA-061: audit and privacy.
8. DSA-070 through DSA-075: test and live validation.
9. DSA-080 through DSA-082: rollout and documentation.
