# Oasis — Data Saver Automation Contract (DS-001)

**Status:** Accepted. This document is the contract for DS-002 through DS-018.
**Implements:** [DATA_SAVER_AUTOMATION_TICKETS.md](DATA_SAVER_AUTOMATION_TICKETS.md) ticket DS-001.
**Source of intent:** [DATA_SAVER_AUTOMATION_PRD.md](DATA_SAVER_AUTOMATION_PRD.md).

Where the PRD's illustrative JSON and the shipped code disagree, the decision recorded here is
normative. The PRD snippets use `snake_case`; that is presentation only. Every contract below is
`camelCase`, matching the shipped `PolicyContract`, `AuditStore`, and WebView bridge payloads.

## 1. Format and versioning

- Wire format is a single JSON object, UTF-8, `camelCase` keys.
- Each contract versions itself. `FlowObservation`, `PolicyDecision`, and `DecisionAudit` each start
  at `schemaVersion: 1`. They do **not** share `PolicyContract::kSchemaVersion`, and they do not
  change the stored policy format version.
- Version rules are the ones `PolicyContract` already implements (`src/network/policy.cpp`,
  `schemaVersionOk`):
  1. A payload with no `schemaVersion` is read as version 1.
  2. Any version from 1 through the current version is accepted.
  3. A payload from a newer build is rejected **as a whole**. It is never half-parsed.
  4. Unknown keys inside a supported version are ignored, so a field can be added without a bump.
  5. Removing, renaming, or changing the meaning of a field bumps the version and adds a migration.
- Enum values are lower-case strings on the wire. Readers accept case-insensitive input and
  normalize to the documented token. Unknown enum values reject the payload.
- Timestamps are ISO-8601 UTC (`2026-11-25T18:00:00Z`). Durations are milliseconds. Sizes are bytes
  and rates are bits per second, as defined in §2.
- Failure is always closed: a rejected observation produces no evaluation; a rejected decision
  leaves the local fallback in force; a rejected stored mode resolves to `off` (§7).

## 2. Canonical units

| Quantity | Unit | Field naming |
| --- | --- | --- |
| Byte counters, thresholds, cache buckets | bytes (8-bit), 1024-based thresholds | `*Bytes`, `milestoneBytes` |
| Rates | **bits per second** | `*BitsPerSecond` |
| Display rates | bytes per second, formatted as KiB/s or MiB/s | `formatRate()` in `connectionsnapshot.h` |
| Durations | milliseconds | `*Ms` |
| Confidence | double, `0.0`–`1.0` | `confidence` |

### 2.1 Thresholds are MiB, not decimal MB

The shipped detector is `BandwidthGuard::DetectionBytes = 10ULL * 1024ULL * 1024ULL`
(`src/network/bandwidthguard.h`), and the PRD says the established 10 MiB detector is retained.
Therefore every `10 / 25 / 50 / 100 MB` threshold in the PRD means **MiB**:

| Milestone index | Bytes | Label |
| --- | --- | --- |
| 1 | 10,485,760 | 10 MiB |
| 2 | 26,214,400 | 25 MiB |
| 3 | 52,428,800 | 50 MiB |
| 4 | 104,857,600 | 100 MiB |
| n ≥ 5 | previous × 2 | 200 MiB, 400 MiB, … |

`milestoneBytes` is the canonical field. The PRD's `milestone_mb` (and any `milestoneMb` spelling of
it) is deprecated; a reader that still receives it treats the number as MiB. User-facing copy must
say `MiB`, not `MB`. Any UI string that currently reads "10 MB" is a defect to fix when that surface
is touched.

### 2.2 The rate is 409,600 bits/s; `rx_kbps: 64` is withdrawn

`ThrottlePolicyManager::DefaultLimitBitsPerSecond = 409600` (`src/network/throttlepolicymanager.h`)
is exactly 50 KiB/s (51,200 bytes/s × 8). That is the canonical Data Saver gentle-throttle rate and
the rate every `throttle` decision must state explicitly.

The PRD's example `"rx_kbps": 64` is inconsistent with its own 50 KiB/s default and is withdrawn:

- 64 **decimal** kbps = 64,000 bit/s = 8,000 B/s ≈ 7.8 KiB/s, about 6.4× stricter than the default.
- 50 KiB/s = 409.6 decimal kbps, so a decimal-kbps field cannot even express it exactly.

Rules:

- Canonical rate fields are `rxBitsPerSecond` and `txBitsPerSecond`. `rx_kbps` / `tx_kbps` are
  rejected in `PolicyDecision` v1.
- Legacy rate fields, where some other component still emits them, are **decimal kilobits per
  second** (`rate_rx_kbps: 19972` in the PRD = 19,972,000 bit/s). They are converted at the edge.
- Enforcement never rounds. `409600` stays `409600`. Display may round to one decimal (`409.6 kbps`).
- `0` means "no limit in that direction", never "unlimited by default".

## 3. `FlowObservation` v1

`FlowObservation` is the evaluation input. It is **not** an enforcement request, it is bounded, and
it is never persisted (§9). It supersedes nothing: `ActivityObservation` remains the per-event
contract for the Activity feed, and an incremental activity event can be derived from a flow delta.

```json
{
  "schemaVersion": 1,
  "observationId": "obs_9f82a1c4",
  "timestamp": "2026-11-25T18:00:00Z",
  "process": {
    "processInstanceId": "pid:14820:1764093600000",
    "pid": 14820,
    "parentPid": 9104,
    "identityId": "app_7f3c11a0",
    "exeName": "Code.exe",
    "exePath": "C:\\Users\\me\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    "exeVersion": "1.95.2",
    "processRole": "main",
    "foregroundState": "foreground_active",
    "foregroundRootPid": 14820,
    "interactionState": "interactive"
  },
  "flow": {
    "flowId": "flow_3ab19d0e",
    "protocol": "TCP",
    "localEndpoint": "192.168.1.100:54312",
    "remoteEndpoint": "13.107.246.40:443",
    "domain": "update.code.visualstudio.com",
    "domainSource": "sni",
    "domainConfidence": "strong_inference",
    "multiplexed": false,
    "shared": false
  },
  "metrics": {
    "rxBytes": 10485760,
    "txBytes": 18432,
    "durationMs": 4200,
    "rateRxBitsPerSecond": 19972876,
    "milestoneBytes": 10485760,
    "milestoneIndex": 1
  },
  "uxSignals": {
    "blockingToUser": false,
    "latencySensitive": false,
    "deferrable": true,
    "avoidable": false,
    "detectorTags": ["ide_core_update_signature"]
  }
}
```

### 3.1 Required and optional fields

| Path | Required | Notes |
| --- | --- | --- |
| `observationId`, `timestamp` | yes | see §3.2 |
| `process.processInstanceId`, `pid`, `exeName` | yes | `exeName` is the normalized base name |
| `process.identityId` | no | absent until NG-010 identity resolution completes |
| `process.exePath` | no | may be withheld for privacy; never sent to a provider |
| `process.exeVersion`, `processRole` | no | `role ∈ {main, child, service, unknown}` |
| `process.foregroundState` | yes | `foreground_active`, `foreground_idle`, `background`, `unknown` |
| `process.foregroundRootPid`, `interactionState` | no | `interactionState ∈ {interactive, idle, unknown}` |
| `flow.flowId`, `protocol`, `localEndpoint`, `remoteEndpoint` | yes | endpoints are `ip:port` |
| `flow.domain` | no | absent when attribution is unknown |
| `flow.domainSource` | no | `dns`, `sni`, `ech_outer`, `none` |
| `flow.domainConfidence` | yes when `domain` present | `confirmed`, `strong_inference`, `weak_inference`, `unknown` |
| `flow.multiplexed`, `flow.shared` | yes | default `false` only when the capture layer positively knows it |
| `metrics.rxBytes`, `txBytes` | yes | cumulative for the flow lifetime |
| `metrics.durationMs` | yes | monotonic flow age |
| `metrics.rateRxBitsPerSecond` | yes | current rate, may be 0 on the first sample |
| `metrics.milestoneBytes`, `milestoneIndex` | yes | §2.1; index 0 when no milestone is set |
| `uxSignals.*` | yes | booleans default `false`, `detectorTags` may be empty |

Missing, weak, encrypted, or shared evidence stays explicitly weak. It is never promoted: an
`unknown` domain confidence must not be serialized as `strong_inference`, and a shared flow must not
be described as a single owner.

### 3.2 Stable identifier rules

| Identifier | Rule |
| --- | --- |
| `observationId` | `obs_` + 8–32 lower-case hex. Identifies one evaluation input. A new one is minted per milestone crossing, never reused. |
| `flowId` | `flow_` + 8–32 lower-case hex, hashed from (protocol, local endpoint, remote endpoint, connection start time). A flow that is torn down and re-established gets a new id. Never recycled from a previous boot. |
| `processInstanceId` | `pid:<pid>:<processStartMs>` from the kernel process start time, so a reused PID cannot inherit the earlier process's evidence. |
| `identityId` | The existing `ApplicationIdentity::id`. Stable across updates where the publisher and product identity agree. |
| `domainKey` | Normalized domain: lower-case, IDNA ASCII, no trailing dot, no port, no wildcard. Wildcards exist only in pinned rules. |
| `executableKey` | Lower-case base name plus version when known: `code.exe@1.95.2`. Paths are not keys. |
| `decisionId` | `dec_` + 8–32 lower-case hex, unique per committed decision. |
| `fingerprint` | `fp_` + SHA-256 hex over the canonical cache-key field list (§8). |

Domain presence is never proof of process behavior. A CDN-multiplexed connection with `weak_inference`
or `ech_outer` cannot justify an automatic hard block (§4.4).

## 4. `PolicyDecision` v1

One decision shape is produced by pinned rules, session overrides, profile rules, the cache, the
fallback, and (when enabled) AI. Only a locally validated decision may commit.

```json
{
  "schemaVersion": 1,
  "decisionId": "dec_51c0a9e2",
  "observationId": "obs_9f82a1c4",
  "createdAt": "2026-11-25T18:00:00Z",
  "origin": "profile",
  "tier": 3,
  "action": "throttle",
  "scope": "executable",
  "target": {
    "executable": "code.exe",
    "identityId": "app_7f3c11a0",
    "domain": "update.code.visualstudio.com",
    "flowId": "flow_3ab19d0e"
  },
  "direction": "download",
  "throttle": {
    "rxBitsPerSecond": 409600,
    "txBitsPerSecond": 0,
    "until": "foreground_change"
  },
  "confidence": 0.94,
  "classification": "app_update",
  "cacheTtlSeconds": 2592000,
  "expiresAt": "2026-12-25T18:00:00Z",
  "conflict": {
    "hasConflict": false,
    "conflictingTier": null,
    "resolution": "applied"
  },
  "evidenceSummary": {
    "exe": "Code.exe",
    "domain": "update.code.visualstudio.com",
    "milestoneBytes": 10485760,
    "milestoneIndex": 1,
    "foregroundState": "foreground_active",
    "uxProfile": "deferrable_non_blocking",
    "domainConfidence": "strong_inference",
    "multiplexed": false
  },
  "reasonShort": "VS Code core update download crossing the 10 MiB milestone.",
  "nextSteps": [
    "Set Update: Mode to manual or none in VS Code settings",
    "Run updates on an unmetered network"
  ]
}
```

### 4.1 Required and optional fields

| Field | Required | Notes |
| --- | --- | --- |
| `schemaVersion`, `decisionId`, `observationId`, `createdAt` | yes | IDs follow §3.2 |
| `origin` | yes | `pinned`, `session`, `profile`, `cache`, `fallback`, `ai` |
| `tier` | yes | `1`–`5`, must match `origin` (§5) |
| `action` | yes | `allow`, `notify`, `notify_then_continue`, `throttle`, `block` |
| `scope` | yes | `flow`, `domain`, `executable`, `group` |
| `target` | yes | at least one of `executable`, `identityId`, `flowId`; `domain` required for `domain` scope |
| `direction` | yes | `download`, `upload`, `both` |
| `throttle` | when `action = throttle` | §4.2 |
| `continueAfterNotify` | when `action ∈ {notify, notify_then_continue}` | must be `false` / `true` respectively |
| `confidence` | yes | `0.0`–`1.0`; pinned and session decisions are `1.0` |
| `classification` | yes | `app_update`, `extension_update`, `package_install`, `ai_inference`, `media_stream`, `telemetry`, `policy_action`, `unknown` |
| `cacheTtlSeconds`, `expiresAt` | no | required for cacheable origins (§8) |
| `conflict` | no | defaults to no conflict with `resolution = "applied"` |
| `evidenceSummary`, `reasonShort`, `nextSteps` | yes | bounded; `reasonShort` ≤ 200 chars, `nextSteps` ≤ 5 entries of ≤ 160 chars |

### 4.2 Throttle block

```json
{
  "rxBitsPerSecond": 409600,
  "txBitsPerSecond": 0,
  "until": "foreground_change"
}
```

- At least one direction must be non-zero.
- Automatic origins (`profile`, `cache`, `fallback`, `ai`) must use exactly `409600` bits/s for the
  direction they throttle. A lower value is a de facto block and is rejected. Higher values are
  capped to `409600` and flagged in the audit.
- `until` is one of `foreground_change`, `milestone_next`, `session_end`, `manual_override`; default
  `milestone_next`.
- `NetworkPolicy` stores a single `rateBitsPerSecond` and one `direction`. A decision that asks for
  different RX and TX rates on `both` is rejected until the policy type gains per-direction rates.

### 4.3 What `notify_then_continue` means

It is not a new persisted action and it is not a block:

| Decision | Persisted form | Enforcement channel | User impact |
| --- | --- | --- | --- |
| `allow` | `NetworkPolicy::Action::Allow` | firewall (only when a user pin or explicit rule requires it) | traffic continues |
| `notify` | `Action::Notify` + `continueAfterNotify: false` | none (advisory) | notice asks the user |
| `notify_then_continue` | `Action::Notify` + `continueAfterNotify: true` | none (advisory) | notice only; traffic never waits |
| `throttle` | `Action::Throttle` | QoS upload and/or WinDivert download | rate capped |
| `block` | `Action::Block` | firewall | traffic stopped |

`Action::Ask` and `Action::NoAction` are legacy and are never produced by Data Saver; a decision that
names them is rejected. `continueAfterNotify` is persisted in the decision record and audit details,
not in the policy enum, so the stored policy format version does not change.

### 4.4 Validation guards (fail closed)

1. **Enums and required fields.** Unknown action, scope, origin, classification, or `until`, and any
   missing required field, reject the decision.
2. **Tier consistency.** `tier` must match `origin` (§5). AI output may not set `origin`, `tier`,
   `decisionId`, `observationId`, `policyId`, or `enforcement`; those are assigned locally. A provider
   payload containing them is rejected whole, not sanitized.
3. **Confidence caps.** `confidence < 0.70` permits only `allow` / `notify` / `notify_then_continue`.
   `0.70 ≤ confidence < 0.85` may throttle but not block.
4. **Block guards.** `block` requires `origin ∈ {pinned, profile}`; a profile block additionally needs
   `confidence ≥ 0.85`, `scope = executable`, `domainConfidence` not `weak_inference`/`unknown`,
   `multiplexed = false`, `shared = false`, and `foregroundState ≠ foreground_active`.
5. **Scope guard.** Firewall, QoS, and WinDivert are keyed by executable path, so a `flow`- or
   `domain`-scoped throttle/block cannot be enforced without widening to the executable. A
   domain-scoped automatic block is rejected; the resolver must return `notify_then_continue`
   instead. A flow-scoped throttle is applied at executable scope and the audit records
   `"enforcedAt": "executable"` with the reason.
6. **Foreground protection.** Foreground-active traffic is never throttled or blocked by an automatic
   origin. Package installs (`classification = package_install`), protected executables, and
   latency-sensitive UX signals are advisory-only.

## 5. Origins, precedence, and the user boundary

| Tier | `origin` | Persisted `NetworkPolicy.source` | Survives Off / Emergency Restore |
| --- | --- | --- | --- |
| 1 | `pinned` | `user` (explicitly pinned flag in `description`/UI) | yes |
| 2 | `session` | not persisted (in-memory override with expiry) | yes, until session end |
| 3 | `profile` | `system` | no |
| 4 | `cache` | `ai` for AI-derived, `system` for local signature | no |
| 5 | `fallback` | not persisted (ephemeral decision) | no |

- `PolicyOrigin` in `policy.h` remains the restore boundary: only `source = "user"` is preserved.
  `"ai"`, `"system"`, `"automatic"`, and `"auto"` are automatic and are withdrawn. Anything else,
  including an unset source, is preserved.
- `PolicyDecision.origin` is the runtime discriminator the UI and audit display. It must agree with
  the stored source: a `pinned` decision with `source != "user"` is rejected; a `profile` or `ai`
  decision with `source = "user"` is rejected.
- Conflict reporting: a lower tier that disagrees does not overwrite the winner. The committed
  decision records `conflict.hasConflict = true`, `conflictingTier`, and
  `resolution = "higher_tier_won"`. A pinned rule can never be mutated by a conflict.
- The global mode never overrides a pinned rule. `off` suppresses automation evaluation only (§7).

## 6. Committed decision, audit, and notification

Enforcement outcomes reuse the shipped vocabulary `EnforcementResult::Status`
(`src/network/enforcementcoordinator.h`): `not_applied`, `requested`, `applied`, `partial`, `failed`.
`requested` is not `applied`: QoS installation runs on the throttle worker.

`DecisionAudit` v1 is the JSON placed in `AuditEvent.details`:

```json
{
  "schemaVersion": 1,
  "decisionId": "dec_51c0a9e2",
  "observationId": "obs_9f82a1c4",
  "flowId": "flow_3ab19d0e",
  "milestone": { "bytes": 10485760, "index": 1 },
  "action": "throttle",
  "scope": "executable",
  "target": "code.exe|update.code.visualstudio.com",
  "tier": 3,
  "origin": "profile",
  "matchedKey": "profile:app_update+deferrable",
  "evidence": {
    "classification": "app_update",
    "confidence": 0.94,
    "domainConfidence": "strong_inference",
    "multiplexed": false,
    "foregroundState": "foreground_active"
  },
  "policyId": "pol_9c31",
  "enforcement": {
    "status": "applied",
    "channels": ["windivert_download"],
    "message": "WinDivert rate cap active on the receive direction"
  }
}
```

- `AuditEvent` mapping: `type = AutomaticDecision` for automatic/AI commits, `UserDecision` for
  pinned/session actions, `PolicyChange` for rule edits and mode changes, `EnforcementResult` for a
  channel outcome that arrives after the decision. `scope` is the normalized target, `reason` is
  `reasonShort`, `result` is the action token plus enforcement status, `relatedPolicyId` and
  `relatedIdentityId` are filled when known. `errorInfo` carries the failure reason.
- Audit data is metadata only. No payload bytes, credentials, API keys, provider request bodies, or
  raw local addresses. Destination redaction on export remains `AuditEventStore` behavior.
- Failure to write audit never turns a failed enforcement into success; the in-memory decision
  remains authoritative for the current session.
- Notification mapping: `AppNotification.key = datasaver:<action>:<executableKey>:<domainKey or flowId>:<milestoneIndex>`.
  `critical` for `failed` enforcement or failed withdrawal (bypasses cooldown and caps), `warning`
  for throttle/block transitions, `info` for notify. `route = TrayAndApp`. Every delivered notice
  carries the application, domain when the confidence allows naming it, milestone, direction/rate,
  reason, and the enforcement status. A notice never claims an action the channel did not confirm.

## 7. Mode contract and Monitor → Off migration

### 7.1 Stored form

| Key | Type | Values |
| --- | --- | --- |
| `Oasis/DataSaver/modeVersion` | int | `2` |
| `Oasis/DataSaver/mode` | string | `off`, `enforce` |
| `Oasis/DataSaver/legacyValue` | int, optional | the raw numeric pre-migration value, retained for diagnostics |

Reading order, all fail-closed:

1. `modeVersion` present but not `2` (newer, older, or malformed) → `off`, log a diagnostic. Never
   fall back to the legacy key, never enable enforcement.
2. `modeVersion == 2` → read `mode`; `off`/`enforce` accepted (case-insensitive). Any other token
   resolves to `off` and is repaired to the `off` token, so the rejection is audited once instead
   of on every start.
3. No `modeVersion` → legacy migration (§7.2), then write `modeVersion = 2` and the resulting `mode`.

### 7.2 Legacy three-state mapping

The legacy control was an in-memory `int` (`0 = off`, `1 = monitor`, `2 = enforce`, compiled default
`1`). `NetworkWidget` now stores `DataSaverMode::Mode` and loads it once at construction through
`DataSaverMode::load`, so there is no compiled Monitor default and missing state means `off`.
`DataSaverMode::{load,save}` own the format for both the widget and the headless host; the migration
must handle a missing value as well as one written by an intermediate build.

| Legacy value | Legacy meaning | Migrated mode | Why |
| --- | --- | --- | --- |
| `0` | off | `off` | same meaning |
| `1` | monitor (evaluate, never enforce) | `off` | monitoring is not an enforceable mode; conservative |
| `2` | enforce | `enforce` | same meaning |
| missing | compiled default `1` | `off` | never enable automation without a user choice |
| `< 0`, `> 2`, non-numeric | invalid | `off` + diagnostic | fail closed |
| string, object, newer token | unsupported | `off` + diagnostic | fail closed |

Rules:

- The migration is idempotent: once `modeVersion = 2` exists, the legacy key is never read again.
  Re-running it does not change the stored mode.
- `legacyValue` records what was seen, so support can explain why an upgrade landed in `off`.
- A mode write is a `PolicyChange` audit event (`reason`: "mode changed", `result`: the new token).
  An invalid stored mode is a `PolicyChange` with `result = "rejected"` and the raw value in
  `errorInfo`. A legacy migration records `reason`: "legacy Data Saver mode migrated" and the raw
  value in `details`.
- `off` withdraws only automatic controls: stop evaluation, call the existing
  `restoreAllDataSaverPolicies()` path, and leave `source = "user"` policies and live session
  overrides alone. `enforce` re-evaluates; it never changes or bypasses a pinned rule.
- Every automatic control carries its owning policy id so withdrawal is targeted
  (`relatedPolicyId` in audit, `applyForPolicy()` on the throttle channel). Emergency Restore keeps
  its current contract: automatic controls are removed, user and unknown-origin policies survive.

### 7.3 Bridge exposure

`datasaver.status` keeps `schemaVersion: 1` and gains fields without a bump:

- `mode.token`: `"off"` or `"enforce"` (new, canonical).
- `mode.label`: `"off"` / `"enforce"` / `"unknown"`. `"monitor"` is never emitted again.
- `mode.value`: retained for compatibility, `0` or `2` only. It is deprecated; new consumers read
  `mode.token`.
- `enforcing` remains `mode.token == "enforce"` and is `false` for any unknown value.

Command methods are out of scope here and are defined by DS-014.

## 8. Cache contract (consumed by DS-007)

The cache key is a fingerprint over these inputs, in this order, none of which is a payload:

1. `executableKey` (name + version)
2. `domainKey`, or the ASN/address fallback token
3. `processRole`
4. `foregroundState`
5. receive bucket: `10_25MB`, `25_50MB`, `50_100MB`, `100MB_plus`
6. duration bucket: `burst_<10s`, `sustained_10_60s`, `long_>60s`
7. Data Saver source: `metered_hotspot`, `manual_toggle`, `battery_saver`

An entry stores `schemaVersion`, `fingerprint`, `observationId`, `decisionId`, the full decision,
`schemaVersion` of the decision, `createdAt`, `expiresAt`, and the audit link. TTL:

| Decision source | TTL |
| --- | --- |
| `ai`, confidence ≥ 0.85 | 7 days |
| `ai`, domain-only with no process/SNI corroboration | 24 hours |
| `ai`, confidence < 0.70 | 15–60 minutes |
| `profile` (local signature) | 30 days or catalog version lifetime |
| `session` | session end / app restart |
| `pinned` | persistent |

Invalidation: executable version change; any bucket change; Data Saver source change; local catalog
version change. A malformed or newer-version entry is discarded without affecting the decision path;
cache failure falls back to local resolution and can never produce a hard block.

## 9. Privacy boundary

Never persisted, never audited, never sent to a classification provider:

- packet payloads, file bodies, TLS plaintext, credentials, API keys;
- complete process histories, browsing history, DNS query logs;
- raw local addresses, policy IDs, executable paths.

The AI request is built from an allow-list, exactly:
`exeName`, `exeVersion`, `domainToken` (registrable domain or redacted token), `foregroundState`,
`processRole`, `receiveBucket`, `durationBucket`, `uxSignals`, plus `schemaVersion` and a request
kind. The user can inspect the exact bounded payload before the first send (DS-012). Provider output
is a proposal only: it is validated (§4.4), assigned `origin = ai` and `tier = 4` locally, and can
never call enforcement or touch the policy store.

## 10. Deferred to later tickets

- Cache entry storage schema and eviction: DS-007.
- Local signature catalog format and profile rule schema: DS-006.
- Bridge read/command contract and error envelope: DS-014.
- Domain-scoped enforcement channel (today's channels are path-keyed): not planned in P0.

## Appendix A — Shipped code this contract is reviewed against

| Contract element | Shipped reference |
| --- | --- |
| Schema versioning rules | `src/network/policy.h` (`PolicyContract`), `src/network/policy.cpp` (`schemaVersionOk`) |
| Observation fields | `src/network/flowobservation.{h,cpp}` (`FlowObservation` v1, `FlowObservationBuilder`), `src/network/policy.h` (`ActivityObservation`), `src/network/connectionsnapshot.h` (rates) |
| Policy action/scope/source | `src/network/policy.h` (`NetworkPolicy`), `src/network/policy.cpp` (`policyOrigin`) |
| Rate unit | `NetworkPolicy::rateBitsPerSecond`; `ThrottlePolicyManager::DefaultLimitBitsPerSecond = 409600` |
| 10 MiB milestone | `BandwidthGuard::DetectionBytes = 10 * 1024 * 1024` |
| Enforcement outcome vocabulary | `EnforcementResult::Status` (`src/network/enforcementcoordinator.h`) |
| Channel routing | `plannedChannels()` (`src/network/enforcementrestore.cpp`) |
| Milestone accounting/dedupe | `src/network/volumemilestone.{h,cpp}` (`thresholdBytes`, `VolumeMilestoneEvaluator`) |
| Audit records | `AuditEvent` (`src/network/policy.h`), `AuditEventStore` (`src/network/auditeventstore.h`) |
| Notification dedupe/priority | `src/network/notificationcoordinator.h` |
| Mode values | `src/network/datasavermode.{h,cpp}` (`load`/`save`, legacy migration), `NetworkWidget::setDataSaverMode()` |
| Bridge status shape | `dataSaverStatus()` (`src/ui/webview2/webuibridge.cpp`) |
| Policy persistence | `PolicyStore` group `Oasis/Policies`, format version 2 |
