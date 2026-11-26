# Oasis: Data Saver Automation Tickets

This backlog implements [DATA_SAVER_AUTOMATION_PRD.md](DATA_SAVER_AUTOMATION_PRD.md). Tickets are ordered by dependency within each phase. `P0` is required for the first enforceable release; `P1` is an important follow-up or broader validation. All tickets are **Not started** until their acceptance criteria are implemented and verified.

## Ticket conventions

- **Type:** feature, refactor, bug, test, documentation, or security.
- **Status:** `Done`, `Partial`, or `Not started`.
- **Dependencies:** tickets that should land first.
- **Acceptance criteria:** observable completion conditions.
- Reuse existing identity, attribution, Activity, policy, enforcement, audit, notification, and AI-provider modules. Do not create parallel versions of those systems.

## Phase 0: Contracts and mode safety

### DS-001 Resolve automation contracts and measurement units

- **Status:** Done
- **Type:** documentation
- **Priority:** P0
- **Dependencies:** None
- **Goal:** Resolve contract-level ambiguities before flow accounting or enforcement depends on them.
- **Acceptance criteria:**
  - Define versioned `FlowObservation` and `PolicyDecision` schemas, stable identifier rules, required versus optional fields, and forward-version rejection behavior.
  - Choose canonical units for byte thresholds and rates. In particular, reconcile the 50 KiB/s default with the example `rx_kbps: 64`, and state whether each 10/25/50/100 MB threshold uses decimal MB or MiB.
  - Define how `notify_then_continue` maps to the existing policy/action model and how AI/profile decisions are distinguished from user-pinned policy origins.
  - Document the migration mapping for the existing three-state Data Saver setting to the required `Off` and `Enforce` modes.
- **Validation:** Recorded in [DATA_SAVER_CONTRACT.md](DATA_SAVER_CONTRACT.md); reviewed against `NetworkPolicy`, `ActivityObservation`, `EnforcementResult`, the 409,600 bit/s throttle default, and the stored mode values.

### DS-002 Migrate Data Saver to safe Off/Enforce modes

- **Status:** Done
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-001
- **Goal:** Expose only the two PRD modes while preserving user-created policies.
- **Acceptance criteria:**
  - Persist and report only `Off` or `Enforce` for the automation feature.
  - Existing legacy `Monitor` values migrate conservatively to `Off`; migration is idempotent and does not enable enforcement after restart.
  - `Off` stops Data Saver evaluation and withdraws only Data Saver-owned automatic controls; user-pinned policies remain active.
  - `Enforce` starts evaluation without changing or bypassing higher-priority user policies.
  - Invalid or newer stored values fail closed to `Off` and produce a diagnosable result.
- **Validation:** `tests/main.cpp` `testDataSaverModeContract` covers legacy 0/1/2 values, malformed and newer stored values, idempotent migration, and Off/Enforce persistence across reloads. `Off` withdraws automatic controls through `restoreAllDataSaverPolicies`; user-policy preservation on that path is covered by `testEmergencyRestorePlan`.

## Phase 1: Observation and milestones

### DS-003 Produce canonical, non-blocking flow observations

- **Status:** Done
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-001
- **Goal:** Build bounded flow observations from existing capture, identity, attribution, process-lineage, and foreground evidence.
- **Acceptance criteria:**
  - Observations include stable flow/process identity, timestamp, protocol and endpoints, metadata attribution/confidence, cumulative RX/TX bytes, duration/rate, executable version/role where available, foreground state, and UX/detector signals.
  - Missing, weak, encrypted, shared, or multiplexed evidence is represented explicitly as unknown/weak; it is never promoted to a confident owner or hostname.
  - Packet hooks do not wait on disk, HTTP, AI, policy UI, or other blocking work; aggregation is bounded and thread-safe.
  - Raw payloads and local browsing history are neither persisted nor sent to classification providers.
- **Validation:** `src/network/flowobservation.{h,cpp}` implements the v1 contract and bounded aggregation; `tests/main.cpp` `testFlowObservationContract`/`testFlowObservationBuilder` cover round-trip, forward-version rejection, malformed payloads, IPv4/IPv6, PID reuse, missing process evidence, shared flows, and DNS/SNI confidence. Built and ran `tests/oasis_tests.exe` on Windows with MinGW; the run completed with `checks: 1503 failures: 0` (fixtures: 22 passed, 0 failed).

### DS-004 Track volume milestones and deduplicate evaluations

- **Status:** Done
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-003
- **Goal:** Trigger evaluation at the configured cumulative byte milestones without repeated evaluation storms.
- **Acceptance criteria:**
  - Per-flow, process, and domain accounting triggers the initial 10 MB, 25 MB, 50 MB, 100 MB thresholds and each later doubling according to DS-001's units.
  - A milestone is keyed and deduplicated by flow, process, domain, and milestone bucket for at least one configured evaluation window.
  - Counter rollover, PID reuse, flow replacement, missing domains, and application restart cannot silently reuse stale evidence.
  - Milestones trigger evaluation only; crossing a threshold alone does not imply a block or other enforcement action.
- **Validation:** `src/network/volumemilestone.{h,cpp}` implements MiB thresholds, flow/process/domain aggregation, and windowed dedupe; `tests/main.cpp` `testVolumeMilestones` covers exact boundaries, repeated snapshots, concurrent flows, rollover, PID reuse, missing domains, window expiry, and restart. Verified by the harness (1503 checks, 0 failures).

## Phase 2: Deterministic policy engine

### DS-005 Store pinned rules and session overrides

- **Status:** Done
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-001, DS-002
- **Goal:** Add durable user-pinned precedence and bounded session choices using the existing policy persistence conventions.
- **Acceptance criteria:**
  - Pinned rules support executable plus domain or wildcard and remain the highest-precedence tier.
  - Session overrides support flow or executable/domain scope and expire on session end or app restart as specified.
  - Versioned persistence validates scope, action, target, expiry, and origin; malformed or newer-schema data is rejected safely.
  - Conflicts are reported when lower tiers disagree, without mutating the pinned rule.
  - Always Allow requires explicit confirmation before creating a persistent pinned rule.
- **Validation:** `src/network/datasaverrules.{h,cpp}` implements versioned pins, in-memory session overrides, precedence/conflict resolution, and the Always Allow gate; `tests/main.cpp` `testDataSaverRules` covers round-trip persistence, wildcard/exact precedence, expiry, restart, conflict reporting, schema rejection, and confirmation gating. Verified by the harness (1503 checks, 0 failures).

### DS-006 Add local signatures and profile rules

- **Status:** Partial
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-001, DS-003
- **Goal:** Resolve known traffic locally and distinguish foreground-active, foreground-idle, and background cases.
- **Acceptance criteria:**
  - Local signatures run without network access and return classification, confidence, matched evidence, detector tags, and recommended action/scope.
  - Profile rules can vary behavior by detector tag and foreground state without changing capture or attribution behavior.
  - Protected executables, interactive package installs, latency-sensitive activity, and unknown activity receive conservative outcomes.
  - Foreground-idle is based on fresh process/foreground evidence, not window-title inference; stale evidence becomes unknown.
  - A rule match is explainable and never enforces by itself outside the policy resolver.
- **Validation:** `src/network/datasaverprofiles.{h,cpp}` implements `LocalSignatureEngine`, ordered `ProfileRule` matching by detector tag and foreground state, conservative guards, and explainable recommendations without an enforcement channel; it reuses `EndpointCatalog`, `ActivityClassifier`, and `BandwidthGuard`. `tests/main.cpp` `testLocalSignatures` covers known/unknown signatures, foreground-active/idle/unknown transitions, stale samples, protected services, latency-sensitive activity, interactive/background package installs, profile changes, invalid-profile rejection, and block downgrades. Source review complete; harness/build verification is pending because the user will run it.

### DS-007 Implement evidence fingerprint cache

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-001, DS-003, DS-005
- **Goal:** Reuse decisions only while the evidence that justified them remains valid.
- **Acceptance criteria:**
  - Cache keys include normalized executable/version, domain or fallback identity, process role, foreground state, byte/duration buckets, and Data Saver source.
  - Entries retain schema version, source observation, fingerprint, result, timestamps/expiry, and audit linkage; no payload bytes or credentials are stored.
  - TTL follows the PRD by decision source/confidence, and entries invalidate on version, evidence bucket, source, or catalog changes.
  - Cache failure or invalidation falls back to local resolution and cannot create a hard block.
- **Validation:** Tests cover key stability, each invalidation dimension, TTL boundaries, malformed/newer data, and storage failure.

### DS-008 Resolve decisions with fixed precedence and safe fallback

- **Status:** Partial
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-002, DS-004, DS-005, DS-006, DS-007
- **Goal:** Produce one validated decision from pinned rules, session overrides, profile rules, cache, or fallback.
- **Acceptance criteria:**
  - Resolver applies the PRD tier order deterministically and records the winning tier plus any conflict.
  - Global mode never overrides a pinned user rule; `Off` suppresses automation evaluation without disabling user policy enforcement.
  - Foreground unknown activity immediately receives a safe allow/notify outcome; background fallback uses the approved gentle throttle only when all safety checks pass.
  - Low-confidence decisions cannot exceed notify/notify-then-continue; shared or multiplexed flows and weak/ECH-only attribution cannot produce an automatic hard block.
  - AI or automatic policy origins are validated locally; malformed enums, missing fields, invalid scope/rate, and unknown versions are rejected.
- **Validation:** `src/network/datasaverdecision.{h,cpp}` implements the `PolicyDecision` v1 contract (`toJson`, `fromJson`, local `validate`) and `DecisionResolver`, which applies pinned → session → profile → cache → fallback. The DS-006 `LocalSignatureEngine` is the tier-3 candidate and supplies the lower-tier conflict vote for pinned/session winners; a DS-007 cache candidate is accepted only as a validated tier-4 decision for the same executable and domain; the tier-5 fallback is notify-only unless channel ownership was confirmed and all background safety checks pass. `tests/main.cpp` `testDataSaverDecisionResolver` covers profile-to-decision conversion, contract round-trip, newer-schema/unknown-action/missing-target rejection, pinned and session precedence with conflict reporting, Off suppression while preserving pins, foreground downgrade, cache reuse/mismatch, cache-block rejection, and the notify-only fallback. The real DS-007 cache store and a full build/harness run are still pending; syntax-only compilation of the new module and `tests/main.cpp` passed with Qt 6.11.1/MinGW.

## Phase 3: Enforcement, audit, and user actions

### DS-009 Apply and withdraw automation-owned enforcement

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-002, DS-008
- **Goal:** Route approved decisions through existing policy, scheduler, and enforcement ownership paths.
- **Acceptance criteria:**
  - Throttle decisions request the canonical download rate and direction from DS-001 through existing enforcement managers; all channel outcomes are represented.
  - Automatic controls have explicit ownership and expiry so disable, policy change, app exit, or emergency restore withdraws only the relevant automatic control.
  - Pinned/user policies are never removed by Data Saver disable or emergency restore.
  - Unavailable or failed enforcement produces `NotApplied`/`Failed`, an audit entry, and a user-visible explanation; it never reports success optimistically.
  - Resolver and enforcement work never blocks packet capture; slow reconciliation remains asynchronous.
- **Validation:** Mocked manager tests cover allow, throttle, block, partial/failure, idempotent reapply, expiry, disable, and preserving user-owned controls.

### DS-010 Audit every committed decision

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-001, DS-009
- **Goal:** Make every policy commit traceable and reversible using `AuditEvent`/`AuditEventStore`.
- **Acceptance criteria:**
  - Each committed decision records timestamp, observation/flow IDs, milestone, action/scope, precedence tier, matched rule or cache key, bounded evidence summary, policy ID, and enforcement result.
  - Audit records contain metadata only: no payload bytes, API keys, raw local IPs, or unredacted provider request bodies.
  - Failed and partial outcomes are recorded as such; audit-write failure does not turn a failed enforcement into success.
  - The audit view/export can distinguish Data Saver automatic/AI actions from user-pinned actions and report the reason.
- **Validation:** Tests assert required fields, origin attribution, redaction, failure outcomes, and export schema.

### DS-011 Deliver actionable restriction notifications

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-005, DS-009, DS-010
- **Goal:** Reuse `NotificationCoordinator` for deduplicated notice and provide explicit user reversal actions.
- **Acceptance criteria:**
  - Every successful throttle/block transition produces one deduplicated notice with application, domain when safe, milestone, reason, direction/rate, and enforcement outcome.
  - Allow Once creates the appropriate expiring session override; Always Allow requires confirmation and creates a pinned rule.
  - Notifications link to evidence/details and never claim an action that enforcement did not confirm.
  - Critical enforcement failures bypass ordinary rate limits; repeated notices fold counts according to coordinator policy.
- **Validation:** Tests cover dedupe, cooldown, critical bypass, action routing, allow-once expiry, pinned confirmation, and failed enforcement copy.

## Phase 4: Optional AI classification

### DS-012 Add privacy-safe, opt-in provider settings

- **Status:** Not started
- **Type:** feature
- **Priority:** P1
- **Dependencies:** DS-001
- **Goal:** Configure Groq through the existing OpenAI-compatible provider layer without exposing credentials or sensitive telemetry.
- **Acceptance criteria:**
  - AI is disabled by default; provider, HTTPS endpoint, user-selected model, and 5–60 second timeout are validated.
  - The API key is read only from `GROQ_API_KEY` and is never persisted, logged, cached, or included in errors; reconcile this variable with any existing provider key convention.
  - Users can inspect the exact bounded, redacted request before enabling/sending it.
  - Payload excludes executable paths, local IPs, policy IDs, raw packet data, complete process history, and unredacted user-specific domains.
- **Validation:** Tests cover defaults, endpoint/key validation, timeout bounds, payload redaction/size cap, and proof the key is absent from persisted settings/log output.

### DS-013 Run classification asynchronously and validate decisions locally

- **Status:** Not started
- **Type:** feature
- **Priority:** P1
- **Dependencies:** DS-008, DS-012
- **Goal:** Add optional AI classification without delaying fallback or granting the provider enforcement authority.
- **Acceptance criteria:**
  - Local signatures and the immediate safe fallback run first; cloud work is queued only for unknown activity when explicitly opted in.
  - Worker calls have bounded request/response sizes, timeout, cancellation/stale-result handling, and do not block capture or the UI thread.
  - Only one schema-valid `PolicyDecision` is accepted; every field is normalized and checked against confidence, scope, precedence, shared-flow, and hard-block guards.
  - Provider failure, timeout, malformed JSON, unsafe result, or disabled AI leaves the safe local decision in force and records a bounded reason.
  - Provider output can recommend but cannot directly call enforcement or mutate policy storage.
- **Validation:** Fake-provider tests cover valid/invalid JSON, timeout, HTTP error, cancellation, stale evidence, low confidence, malicious policy-shaped text, and unchanged fallback.

## Phase 5: WebView bridge and Preact experience

### DS-014 Expose a versioned Data Saver bridge contract

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-002, DS-008, DS-009, DS-010
- **Goal:** Give the new frontend a bounded, typed interface to service snapshots and user-approved commands.
- **Acceptance criteria:**
  - Read methods expose mode, capture/service state, active controls, recent decisions, rule conflicts, and audit summaries using a versioned JSON contract.
  - Commands are limited to validated mode changes, session/pinned overrides, restore, and supported rule operations; the page cannot submit arbitrary policy objects or raw enforcement instructions.
  - Invalid, oversized, unknown-version, stale, and unauthorized commands return structured errors without changing backend state.
  - Existing `app.status` and `datasaver.status` reads remain compatible or have an explicit versioned migration.
- **Validation:** Bridge tests cover snapshots, each command, malformed/oversized requests, replay/repeat behavior, unavailable services, and compatibility methods.

### DS-015 Build the Preact Data Saver workflow

- **Status:** Not started
- **Type:** feature
- **Priority:** P0
- **Dependencies:** DS-011, DS-014
- **Goal:** Replace the static preview with a real, accessible Data Saver screen backed by the bridge.
- **Acceptance criteria:**
  - UI offers only Off/Enforce and renders actual backend status rather than mock flow, cache, throttle, or audit values.
  - A flow/decision list and inspector show classification confidence, evidence, milestone, precedence, action, enforcement result, and safe next steps.
  - Allow Once, Always Allow, and Emergency Restore use explicit confirmation/pending/success/failure states and preserve pinned policies.
  - AI opt-in and exact payload preview are visible only when the optional AI path is available; credentials are never displayed.
  - Loading, empty, stale, bridge-error, and unavailable-WebView states are usable at desktop and mobile-like viewport sizes; keyboard navigation and accessible labels are provided.
- **Validation:** Test against mocked bridge responses for all states, then verify the packaged page against live service snapshots and commands.

## Phase 6: Verification and rollout

### DS-016 Add deterministic policy-engine test coverage

- **Status:** Not started
- **Type:** test
- **Priority:** P0
- **Dependencies:** DS-003, DS-004, DS-005, DS-006, DS-007, DS-008, DS-009, DS-010
- **Goal:** Exercise policy behavior without requiring network access, elevation, WebView2, or a live provider.
- **Acceptance criteria:**
  - Harness covers contract parsing/schema rejection, milestone boundaries/dedupe, all scopes, precedence/conflicts, cache keys/expiry, profile and foreground transitions, and pinned/session behavior.
  - Tests cover multiplexed CDN, shared flow, ECH/weak attribution, protected processes, PID reuse, and hard-block prevention.
  - Tests assert audit immutability/required metadata, metadata-only exports, automatic withdrawal, and preservation of user-owned rules.
  - The harness runs deterministically with no network or elevated permissions and returns nonzero on failure.
- **Validation:** Run the documented test target on Windows 10 and Windows 11; record platform coverage and results.

### DS-017 Add provider and asynchronous pipeline tests

- **Status:** Not started
- **Type:** test
- **Priority:** P1
- **Dependencies:** DS-012, DS-013
- **Goal:** Prove optional AI is private, bounded, and unable to delay or override local safety behavior.
- **Acceptance criteria:**
  - Fake-server/provider tests cover success, missing key, malformed/oversized response, timeout, HTTP failure, cancellation, and user opt-out.
  - Exact outbound payload is checked for excluded path/IP/policy/packet fields and configured redaction.
  - Every failure path returns to the already-applied local fallback; provider output cannot bypass resolver validation or precedence.
- **Validation:** Automated tests run offline using a local fake endpoint; no real API key is required.

### DS-018 Validate live Windows enforcement and rollback

- **Status:** Not started
- **Type:** test
- **Priority:** P0
- **Dependencies:** DS-009, DS-010, DS-011, DS-015, DS-016
- **Goal:** Confirm real capture, policy ownership, notification, and rollback behavior on supported Windows versions.
- **Acceptance criteria:**
  - Elevated tests cover background qualifying traffic, foreground interactive traffic, foreground-idle transition, package install protection, a known updater signature, unknown traffic, shared/CDN flows, and unavailable enforcement channels.
  - Measurements confirm the configured throttle rate and direction; every result matches the audit and user-facing notice.
  - Disable, expiry, Allow Once, Always Allow, and Emergency Restore are exercised; no user-pinned rule is removed unexpectedly.
  - Test fixtures and rollback instructions prevent accidental changes to unrelated firewall/QoS state.
- **Validation:** Record Windows 10/11 versions, required elevation/driver availability, observed rates, audit outcomes, and rollback results.

## PRD coverage map

| PRD area | Tickets |
| --- | --- |
| Contracts, modes, and migration | DS-001, DS-002 |
| Flow evidence, privacy, and milestones | DS-003, DS-004 |
| Precedence, profiles, cache, fallback | DS-005 through DS-008 |
| Enforcement, rollback, audit, notifications | DS-009 through DS-011 |
| Groq opt-in and asynchronous validation | DS-012, DS-013, DS-017 |
| Web bridge and Preact screen | DS-014, DS-015 |
| Automated and live verification | DS-016 through DS-018 |
