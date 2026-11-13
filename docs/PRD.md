# Oasis: Data Control Plane

**Document type:** Product Requirements Document  
**Status:** Proposed  
**Target platform:** Windows 10 and Windows 11  
**Current implementation baseline:** v1.2.0  
**Last updated:** 2026-11-04

## 1. Product Summary

Oasis will help Windows users understand, control, and reduce laptop data consumption. It will identify which applications, services, and application groups are consuming bandwidth; explain the likely reason for that consumption; and apply durable controls that remain effective when a process is restarted, respawned, or replaced by an updater service.

The product combines four capabilities:

1. **Observe:** measure traffic by application, process, service, direction, connection, and time period.
2. **Explain:** associate traffic with domains, publishers, Windows services, update systems, synchronization jobs, and foreground activity.
3. **Control:** block, throttle, schedule, exempt, or temporarily pause network activity.
4. **Recommend:** provide transparent, actionable suggestions, with optional AI assistance for unfamiliar activity.

The central product principle is:

> Control the durable activity identity, not only the current PID.

A PID is temporary. An executable, signed publisher, Windows service, package identity, and related process group are more useful policy targets.

## 2. Problem Statement

Users often see their connection become slow or their data allowance disappear without knowing why. Common causes include:

- Windows Update, Delivery Optimization, or BITS downloads.
- Browser and browser-component updates.
- OneDrive and other cloud synchronization clients.
- Game launchers and game updates.
- IDE, extension, package-manager, and developer-tool updates.
- A foreground application downloading content without an obvious indication.
- A process that is terminated but immediately relaunched by a service, task, launcher, or updater.

Existing tools frequently expose a process list or offer a firewall rule, but users still have to interpret the activity, identify the responsible service, and repeatedly react to replacement processes. Blocking everything is too disruptive; killing a PID is too temporary; and a raw IP address is not an explanation.

## 3. Goals

### 3.1 Primary goals

- Show which applications and services consume bandwidth in near real time.
- Track upload and download consumption accurately enough for user decisions and historical reporting.
- Identify common update, synchronization, launcher, and system-service activity.
- Apply upload and download limits that survive process restarts and connection churn.
- Apply controls to a durable application identity or activity group where possible.
- Give users a clear reason for each alert and recommendation.
- Allow users to choose notification-only, ask-first, or automatic enforcement behavior.
- Preserve user control: every automatic action must be visible, reversible, and logged.
- Operate locally by default and avoid collecting packet payloads.

### 3.2 Secondary goals

- Attribute destinations using passive DNS and TLS SNI metadata when available.
- Explain uncertainty when attribution is inferred rather than confirmed.
- Offer optional AI-generated explanations and recommendations from structured metadata.
- Support schedules such as metered hours, work hours, gaming sessions, or overnight windows.
- Provide an auditable history of detections, recommendations, actions, and outcomes.

## 4. Non-goals

The following are explicitly outside the first product release of this direction:

- Deep packet inspection of application payloads.
- Decrypting HTTPS, QUIC, VPN, or TLS traffic.
- Guaranteeing attribution for every kernel-owned, encrypted, tunneled, or off-device flow.
- Automatically changing application settings without user approval.
- Automatically terminating processes as the default response.
- Replacing Windows Defender Firewall, Windows Update, or the Windows Task Scheduler.
- Acting as a general antivirus, intrusion-prevention system, or content filter.
- Sending raw packet payloads, browsing content, or complete local histories to a remote AI service.

## 5. Existing Capability Baseline

The current application already provides a substantial foundation:

| Area | Current capability |
| --- | --- |
| Observation | Raw-socket IPv4/IPv6 capture, packet parsing, PID resolution, upload/download direction, per-process tree view |
| Usage | Per-application daily history, JSON persistence, CSV export, session totals |
| Firewall | Windows Firewall COM integration, allow/block rules, lockdown mode, import/export |
| Upload shaping | Windows QoS policy through a worker thread |
| Download shaping | WinDivert-based inbound pacing with per-executable policies |
| Data Saver | Detection threshold, exemptions, process categories, automatic throttling for known candidates |
| Process context | Executable path resolution and multi-service `svchost.exe` display |
| Notifications | Tray notifications, status messages, detection table, action results |
| Runtime | Administrator manifest, persistent settings, Windows-native Qt application |

The current baseline should be preserved while the new identity, attribution, policy, and recommendation layers are introduced.

## 6. Users and Use Cases

### 6.1 Metered-connection user

The user wants to know what consumed a large portion of a monthly data allowance and temporarily limit background updates without disabling important applications permanently.

### 6.2 Laptop power user

The user wants a quick explanation when the network becomes busy and wants one-click controls for a browser, sync client, launcher, or updater.

### 6.3 Developer

The user wants to distinguish an IDE update, extension download, package manager, Docker image pull, and source-control operation, then set different limits for work and non-work hours.

### 6.4 Gamer or media user

The user wants to prevent launchers and background updates from consuming bandwidth during a game or video call, without permanently blocking the launcher.

### 6.5 Privacy-conscious user

The user wants local visibility and control without payload inspection or mandatory cloud analytics.

## 7. Product Principles

- **Local first:** observation, policy evaluation, and enforcement work without an internet AI service.
- **Explain before acting:** an automatic action must have a reason, confidence, and reversal path.
- **Durable policy over PID reaction:** prefer path, publisher, service, package, and process-group controls.
- **Least disruption:** throttle before blocking; ask before affecting foreground applications.
- **Honest attribution:** distinguish confirmed, inferred, and unknown information.
- **Fail visible:** partial enforcement, missing WinDivert, permission failures, and stale rules must be surfaced.
- **No silent policy drift:** policies must show their scope, rate, schedule, and current enforcement state.
- **Privacy by default:** retain metadata needed for decisions, not payload content.

## 8. Functional Requirements

### FR-1: Traffic observation

The system shall:

- Capture and aggregate traffic by direction, process, executable path, PID, connection, protocol, and time window.
- Continue supporting IPv4 and IPv6.
- Preserve current upload/download shaping and measurement behavior.
- Mark observations that cannot be confidently assigned to a process.
- Avoid treating a missing process mapping as zero traffic.
- Expose sampling intervals, capture limitations, and dropped/unknown traffic to diagnostics.

### FR-2: Durable application identity

The system shall derive a stable identity from available evidence:

- Canonical executable path.
- File version metadata, product name, and original filename.
- Authenticode signer and publisher where available.
- Windows service name and display name.
- Package or AppX identity where available.
- Process parent and child relationships.
- Hash or version fingerprint when path alone is insufficient.

The identity resolver shall record confidence and resolution failures. Policy matching shall support exact path, publisher, service, package, and application-group scopes.

### FR-3: Process and activity groups

The system shall support an activity group containing multiple executable paths and services. A group may include:

- A launcher and its updater.
- A Windows service and its worker processes.
- A cloud-sync client and its updater.
- A browser and browser update components.
- A package manager and its helper processes.

New instances shall inherit the group policy when identity evidence matches. Group membership must be inspectable and editable by the user.

### FR-4: Domain attribution

The system shall optionally collect metadata from:

- DNS request and response observations.
- TLS ClientHello SNI when visible.
- QUIC Initial metadata when safely parseable.
- Reverse lookup only when explicitly enabled, because reverse DNS is not authoritative attribution.

Each destination record shall include:

- Domain or IP.
- Source of attribution.
- First and last seen times.
- Associated process or group.
- Confidence: confirmed, strong inference, weak inference, or unknown.

The system shall handle encrypted DNS, TLS ECH, direct-IP connections, VPNs, and missing metadata without claiming certainty.

### FR-5: Activity classification

The system shall classify activity using local rules and metadata, including:

- Windows Update and Delivery Optimization.
- BITS and related services.
- Browser updates.
- Cloud synchronization.
- Game launchers and game updates.
- IDE and developer-tool updates.
- Package managers and container image downloads.
- Foreground application downloads.
- Unknown or unclassified activity.

Every classification shall include evidence and confidence. Rules shall be versioned and updateable without changing enforcement code.

### FR-6: Policy evaluation

The policy engine shall evaluate:

- Application and group identity.
- Current rate and cumulative usage.
- Foreground/background state when available.
- Activity classification and confidence.
- Current network profile and adapter.
- Schedule and metered-connection settings.
- User exemptions and manual overrides.
- Existing firewall and throttle state.

Policy outcomes shall include allow, notify, ask, throttle, temporary block, persistent block, schedule, or no action.

### FR-7: Throttling and blocking

The system shall support:

- Upload limits.
- Download limits.
- Combined application rate budgets.
- Temporary limits with expiration.
- Scheduled limits.
- Persistent limits.
- Firewall block and restore.
- Path-wide application enforcement for current and future instances.

The UI shall distinguish upload enforcement, download enforcement, and partial enforcement. If one channel fails, the user must see which channel remains active.

### FR-8: Respawn and replacement handling

The system shall detect when a process is replaced or respawned and re-evaluate identity-group policy. It shall not rely on killing a PID as the primary control mechanism.

When a policy cannot safely match a replacement process, the UI shall explain the limitation and offer a narrower or broader scope.

### FR-9: Notifications

Notifications shall support:

- Sustained usage alerts.
- New high-consumption application alerts.
- Automatic throttle or block results.
- Partial or failed enforcement.
- Policy expiration.
- Newly discovered related processes.
- Attribution changes or low-confidence classification.

Notifications shall be deduplicated and rate-limited. Each notification must provide an action path to inspect, throttle, block, exempt, schedule, or dismiss.

### FR-10: Recommendations and AI assistance

The system shall provide deterministic local recommendations for common cases before optional AI assistance is used.

Recommendations shall include:

- What was observed.
- Why the activity is likely occurring.
- What action is suggested.
- Expected effect.
- Confidence and evidence.
- Reversal instructions.

Optional AI assistance may summarize structured metadata and propose actions, but it shall not silently apply policies. The user must approve an AI-proposed enforcement action.

### FR-11: Audit and history

The system shall persist an audit event for:

- Detection.
- Classification.
- Recommendation.
- User decision.
- Automatic decision.
- Enforcement request.
- Enforcement result.
- Policy change.
- Process-group membership change.

Audit records shall include timestamps, scope, reason, result, and relevant error information. Payload content shall not be stored.

### FR-12: Import, export, and recovery

Users shall be able to export and import application groups and policies as versioned JSON. Import shall validate schema, normalize paths, report conflicts, and never silently overwrite existing policies.

At startup, the application shall verify persisted Windows QoS and firewall state and reconcile stale or missing enforcement records.

## 9. User Experience Requirements

### 9.1 Dashboard

The main dashboard shall show:

- Current download and upload rates.
- Top consumers by current rate and session bytes.
- Active automatic controls.
- Unknown or unresolved traffic.
- A compact notification/action queue.

### 9.2 Application detail

An application detail view shall show:

- Identity and publisher evidence.
- Current and historical usage.
- Related processes and services.
- Domains and destinations.
- Current policy and enforcement channels.
- Recent audit events.
- Recommended actions.

### 9.3 Policy editor

The policy editor shall make scope explicit:

- This PID only.
- This executable path.
- This publisher.
- This Windows service.
- This application group.

It shall show the risk of each scope, expiration, schedule, rate, and direction.

### 9.4 Confidence and limitations

The interface shall use plain labels such as `Confirmed`, `Likely`, `Possible`, and `Unknown`. It shall not present a domain or activity classification as fact when only an IP or partial handshake was observed.

## 10. Technical Architecture

The proposed architecture adds layers around the existing implementation:

```text
Capture sources
  raw sockets | connection tables | DNS metadata | TLS/QUIC metadata | Windows APIs
        |
Observation normalizer
        |
Identity resolver
  path | signer | service | package | process lineage | activity group
        |
Attribution and classification
  domains | endpoints | local rules | confidence | evidence
        |
Policy engine
  schedules | thresholds | user overrides | foreground state | metered state
        |
Enforcement coordinator
  Windows Firewall | Windows QoS | WinDivert | reconciliation/watchdog
        |
UI, notifications, history, audit, optional AI assistant
```

### 10.1 Suggested new modules

- `src/identity/applicationidentity.*`
- `src/identity/processgroupmanager.*`
- `src/identity/publisherresolver.*`
- `src/attribution/dnsobserver.*`
- `src/attribution/tlsobserver.*`
- `src/attribution/endpointcatalog.*`
- `src/policy/policyengine.*`
- `src/policy/policystore.*`
- `src/policy/enforcementcoordinator.*`
- `src/audit/auditeventstore.*`
- `src/recommendation/recommendationengine.*`
- `src/ai/assistantprovider.*`

Existing modules such as `BandwidthGuard`, `ThrottlePolicyManager`, `FirewallManager`, and `NetworkMonitor` should remain reusable enforcement and observation components rather than being replaced wholesale.

## 11. Data Model

### Application identity

```text
ApplicationIdentity
  id
  displayName
  executablePaths[]
  publisher
  signerStatus
  productName
  packageFamilyName
  services[]
  processNames[]
  fingerprints[]
  confidence
```

### Activity observation

```text
ActivityObservation
  timestamp
  identityId
  pid
  direction
  bytes
  protocol
  localEndpoint
  remoteEndpoint
  domain
  attributionSource
  classification
  confidence
```

### Policy

```text
NetworkPolicy
  id
  scope
  targetId
  direction
  action
  rateBitsPerSecond
  schedule
  expiration
  source
  enabled
```

## 12. Privacy and Security Requirements

- Do not capture or persist packet payloads.
- Store only metadata required for attribution, policy, history, and diagnostics.
- Make DNS and TLS metadata collection visible and configurable.
- Make remote AI opt-in and disabled by default.
- Redact or hash sensitive destination data in exported diagnostics unless the user chooses otherwise.
- Validate all imported policies and endpoint catalogs.
- Restrict enforcement operations to the elevated process and validate paths before applying rules.
- Clearly show when the app lacks WinDivert, administrator access, or a required Windows capability.
- Do not weaken Windows Firewall protections outside explicitly requested policies.

## 13. Success Metrics

The first release of this product direction is successful when:

- At least 95% of common test scenarios identify the correct executable path.
- At least 90% of known updater/sync scenarios receive the correct category or a clearly marked likely category.
- A path-wide throttle remains effective after the original PID exits and a replacement instance starts.
- Users can determine the top consumer and take an action in under 30 seconds.
- Automatic actions have a visible explanation and reversible policy record in 100% of tested cases.
- No raw payload data is stored by default.
- Missing attribution never causes the UI to claim certainty.
- Enforcement failures are visible and actionable.

## 14. Rollout Plan

### Phase 1: Durable identity and policy foundation

Add identity records, process groups, policy scopes, audit events, and reconciliation while preserving current Data Saver behavior.

### Phase 2: Better attribution

Add DNS, TLS SNI, endpoint catalogs, confidence scoring, and activity explanations.

### Phase 3: Schedules and resilient enforcement

Add temporary and scheduled controls, watchdog verification, replacement-process handling, and policy health status.

### Phase 4: Recommendations and optional AI

Add deterministic recommendations, structured AI context, user approval, provider settings, and feedback capture.

### Phase 5: Hardening and release

Run Windows 10/11 compatibility testing, VPN and DNS-encryption testing, bandwidth accuracy tests, recovery tests, security review, and documentation updates.

## 15. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Raw sockets cannot observe every flow | Combine capture with Windows connection tables and label unknown traffic honestly |
| TLS SNI or DNS is hidden | Use confidence levels and retain IP/protocol evidence without false attribution |
| VPN or proxy hides the final destination | Attribute to the tunnel process and show the limitation |
| WinDivert is missing or unavailable | Keep upload and firewall controls independent; show partial enforcement |
| Updaters change executable paths | Use publisher, service, package, lineage, and group identities |
| Broad policies disrupt important work | Require scope confirmation, prefer throttle, support expiration and emergency restore |
| Remote AI leaks sensitive metadata | Local recommendations first; explicit opt-in, redaction, and provider controls |
| Policy state diverges from Windows | Startup verification, periodic reconciliation, and audit events |

## 16. Acceptance Criteria for the Product Direction

The product direction is ready for general release when a test machine can demonstrate all of the following:

1. A known updater is detected, identified, and explained.
2. The updater is throttled without terminating it.
3. The updater spawns a replacement process and remains controlled.
4. A foreground application is detected but is not automatically throttled under Ask First mode.
5. A user can apply a temporary download-only, upload-only, or combined limit.
6. A user can restore all automatic controls from one place.
7. DNS and visible TLS metadata improve attribution without payload capture.
8. Hidden or unavailable metadata is shown as unknown or inferred.
9. A notification links to the relevant application detail and policy action.
10. Every automatic action and enforcement result is present in the audit history.
