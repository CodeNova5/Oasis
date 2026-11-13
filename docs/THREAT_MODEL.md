# Threat Model — Identity and Enforcement Boundaries (NG-060)

Status: **review complete**, release decision pending the open findings below.
Scope: the trust decisions this product makes about *which executable is which*, *who is allowed to change policy*, and *what the elevated process will do on their behalf*.
Out of scope: Windows kernel, WinDivert driver internals, Qt/OpenSSL vulnerabilities, and physical access.

This document records the model as it exists in the code, not the model the product would like to have. Where the two differ, that is a finding and has a ticket.

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| Firewall rules (`Oasis_*` in `INetFwRules`) | Blocking or allowing outbound traffic is the product's whole effect. Unauthorized writes are a firewall bypass or a denial of service. |
| Throttle limits (QoS policies) | Same authority, lower blast radius. |
| Policy store (`HKCU\Software\…\Oasis/Policies`) | The authority the elevated app acts on. |
| Audit trail (`AuditEventStore`, same QSettings) | The record of what was enforced. Forgeable evidence undermines every other control. |
| Installed executable (`C:\Program Files\Oasis\Oasis.exe`) | Runs elevated; whoever can replace it owns the machine. |
| Destination/attribution metadata (DNS, TLS SNI, QUIC, endpoint catalog) | User browsing interests. Must never leave the machine except through the opt-in AI path. |
| AI provider credential | Read from `OASIS_AI_API_KEY`; never persisted by this product. |

## 2. Adversary model

1. **Local non-admin user, same session or another session** — can write their own `HKCU`, start their own processes, name a process anything, and read the audit trail. Cannot write `Program Files` *by default*.
2. **Malicious policy/rule file author** — distributes a "recommended rules" JSON file. Needs the user to import it. This is the realistic policy-injection vector.
3. **Malicious local process with admin rights** — already owns the machine; not defended against.
4. **Network attacker on the path** — can influence destination names, not the policy store.
5. **Third-party services** — the AI provider (only when the user opts in) and the update-check host.

## 3. Trust boundaries and the decisions taken at each

### TB1 — Process → policy target (path and identity)

| Decision | Where | Assessment |
| --- | --- | --- |
| Identity is keyed by canonical path, not process name or PID | `ApplicationIdentityResolver::canonicalPath` → `GetFinalPathNameByHandleW`, then `identityIdForCanonicalPath` (SHA-1 of the normalized path) | Sound: the same file reached by a different spelling (case, separators, `/`, trailing slash) maps to one identity; symlinks/junctions are resolved to the final path by the handle call. |
| PID reuse must not inherit attribution | `NetworkMonitor` lineage pass: cached identity dropped on `LineageChange::Reused`, using process creation time | Sound; covered by harness checks. |
| Enforcement targets are resolved per policy scope at reconcile time | `policyreconcileplan.cpp`, `path`/`executable` use `targetId` verbatim; `group` uses the live group membership snapshot | **Gap:** `publisher`, `service`, `package`, `pid`, `port`, `protocol` scopes never resolve to paths in this build and land in the report as "cannot be resolved". They are stored and displayed, but they do not enforce. This is honest in the reconcile report, but the policy editor's effect text should keep saying "stored only" for them. |
| Display path for unqueryable processes may fall back to `%SystemRoot%\System32\<name>` | `NetworkWidget::getExactProcessPath`, `FirewallManager` callers | **Low risk:** this can only mislabel a row the product cannot open. It never becomes a firewall path, because enforcement uses the stored policy target, not the display path. Worth keeping the fallback marked as display-only. |

### TB2 — Signer → publisher trust

| Decision | Where | Assessment |
| --- | --- | --- |
| A file is "signed" only if `WinVerifyTrust` returns success for the embedded signature or a catalog signature | `publisherresolver.cpp::runTrustCheck` | Sound. Unsigned and invalid states are distinct from "unverified with local trust data". |
| Publisher, organization, subject, thumbprint are cleared unless the status is `Signed` | `publisherresolver.cpp` end of `resolve` | Sound: an untrusted chain can never supply a publisher string that later drives a policy. |
| Trust is evaluated with `WTD_CACHE_ONLY_URL_RETRIEVAL \| WTD_REVOCATION_CHECK_NONE` | `makeVerifyData` | **Accepted:** a refresh must not block on the network, so revocation is not consulted. A revoked-but-still-cached certificate reads as `Signed`. Publisher is display/policy-matching evidence only, never an enforcement authority in this build. |
| Publisher is a certificate CN string | `readSignerEvidence`, `certificateName(cert, "2.5.4.3")` | **Accepted for now:** CNs are not unique across CAs. This is acceptable while publisher-scope policies are stored-only; it becomes a real weakness the moment publisher scope enforces (see TB1). |

### TB3 — Policy store → elevated enforcement

| Decision | Where | Assessment |
| --- | --- | --- |
| Policies live in per-user QSettings; the elevated app applies every `Active` policy it loads, including the startup reconcile (8 s after launch) and the scheduler tick | `PolicyStore::loadPolicies`, `EnforcementCoordinator`, `PolicyReconciler`, `PolicyScheduler` | **Open finding F-02.** A medium-integrity process running as the same user can write `HKCU` and have the elevated app apply an allow or block rule for an arbitrary executable at the next launch — a firewall change performed by a process that was never granted admin, with no user action in the loop. |
| Emergency restore only removes policies whose source is `automatic`/`system`/`ai`; user policies survive | `policyOrigin` | Sound. The split is conservative: unrecognized sources are preserved rather than removed. |
| Conflicting active policies for one path are not auto-resolved | `planPolicyReconciliation` (`firewallConflicts`) | Sound: fails safe, reports unresolved rather than silently choosing a winner. |
| Firewall rule writes are remove-then-create | `FirewallManager::addRuleInternal` → `removeRuleByName` then `put_*` | **Accepted (low):** a brief window exists where the old rule is gone and the new one is not yet set. Recovery is the next reconciliation; a deliberate attacker able to race this window already has admin. |

### TB4 — Imported JSON

| Decision | Where | Assessment |
| --- | --- | --- |
| Policy import merges by `id`, replaces an existing policy with the same id, keeps any `scope`/`action`/`source`/`targetId` the file supplies, and saves immediately | `PolicyStore::importPoliciesJson` | **Open finding F-03 (latent).** No schema validation, no "this will replace your existing policy" confirmation, no preview of what will be enforced, and no restriction on claiming `source: system`. No UI calls the function today, so the reachable injection route is F-02; the import must be hardened before any import/restore feature ships. |
| Firewall rule import reads `appPath`/`action` and calls `blockApp`/`allowApp` with no validation and no confirmation | `FirewallWidget::onImportRules` → `FirewallManager::addRuleInternal` | **Open finding F-04.** An empty `appPath` produces a rule with **no application name**, which applies to every program on the profile: two "Oasis" block rules become a machine-wide outbound block. The UI reports "Rules imported successfully." |
| Exported evidence files are the only other files this product writes; none are importable | `evidenceexport`, `MainWindow` export actions | Sound: no import path exists for evidence, so export content can never re-enter enforcement. |

### TB5 — Privilege boundaries

| Decision | Where | Assessment |
| --- | --- | --- |
| The app requires administrator (`requireAdministrator`), and self-elevates with `runas` when launched unelevated | `app.manifest`, `main.cpp::elevate` | Expected for a firewall manager. The consequence is that every trust decision above is made *inside* an elevated process, so the inputs to those decisions must be treated as attacker-controlled. |
| The installed executable is granted `WriteOther` ("Everyone: write") after install and after update | `AppInstaller::setFullPermissions`, applied to `installedExePath()` | **Open finding F-01, highest severity.** Any local user can overwrite the binary that the product then launches elevated. This is a direct local privilege escalation and it defeats every other control in this document. |
| Install/update runs kill every process named `Oasis.exe` | `AppInstaller::killOtherInstances` | **Accepted (low):** name-based termination lets a user kill another user's instance or a lookalike process. Annoyance, not escalation; the product is single-instance per machine by design. |
| Update check fetches a version document from a third-party pastebin and only shows a dialog with a link; it downloads and executes nothing | `updatechecker.cpp::UPDATE_URL` | **Accepted, with a recommendation:** no code execution risk beyond a misleading dialog, but the channel should be hosted on the project's own domain so a pastebin compromise cannot announce a fake release. |

### TB6 — AI assistance egress (opt-in)

| Decision | Where | Assessment |
| --- | --- | --- |
| Disabled until the user configures an endpoint and model | `AiProviderSettings::isConfigured` | Sound. |
| HTTPS required; plain HTTP only for loopback | `AiProviderSettings::endpointProblem` | Sound; prevents accidental cleartext of local metadata. |
| Credential comes from `OASIS_AI_API_KEY`, never from settings | `OpenAiCompatibleProvider::explain` | Sound. |
| The request body is the redacted AI context document only; no payloads, no full paths | `aicontext`, `openaiadapter` | Sound by construction; destination names are already masked by NG-036 before the payload is built. |
| The response is never parsed into a policy; it is shown as explanation text and approval still goes through the local dialog | `AiAssistant`, `AiApprovalDialog` | Sound: the model has no path to enforcement. |

## 4. Findings

| ID | Severity | Finding | Ticket |
| --- | --- | --- | --- |
| F-01 | **High** | Installed executable in `Program Files` is writable by `Everyone`; the product relaunches it elevated. Local privilege escalation. | NG-065 |
| F-02 | **High** | Policy store (and audit trail) in per-user settings is trusted by the elevated app, which applies it at startup; a same-user medium-integrity process can inject allow/block policies and erase evidence. | NG-066 |
| F-03 | Medium (latent) | Policy JSON import accepts arbitrary scope/action/source/target and silently replaces existing policies by id, with no validation, preview, or confirmation. Not exposed in the UI today; harden before exposing it. | NG-067 |
| F-04 | **High** | Firewall rule JSON import accepts an empty or arbitrary `appPath`; an empty path creates a profile-wide block. No validation or confirmation. | NG-068 |
| F-05 | Medium | Enforcement is path-keyed, so a copy/hardlink of a blocked image at a different path is not blocked; reconcile keys and firewall normalization also differ (env vars, 8.3 names, links). | NG-069 |
| F-06 | Low | Display path fallback to `%SystemRoot%\System32\<name>` can mislabel an unqueryable process. | Documented above (TB1) |
| F-07 | Low | Publisher identity is a certificate CN; fine while publisher policies are stored-only. | Tracked with NG-067 / revisit when publisher scope enforces |
| F-08 | Low | Rule replacement is remove-then-create. | Accepted (TB3) |
| F-09 | Info | Revocation is not checked (offline trust only). | Accepted (TB2) |
| F-10 | Info | Update manifest is hosted on a third-party pastebin. | Accepted (TB5) |

**Release gate:** F-01, F-02, and F-04 must be closed before a 1.0 release. F-03 must be closed before any policy import/restore UI ships. F-05 may ship with documented limits, because path-keyed firewall rules are an OS-level constraint rather than a bug to fix in this process.

## 5. Mitigations already in place that should not regress

- Publisher strings are erased unless the chain verifies (TB2).
- `PolicyOrigin` preserves unrecognized sources, so imported or hand-edited policies can never be silently deleted by emergency restore.
- Conflicting policies fail closed into "unresolved" and change no rule (TB3).
- The AI context is redacted before it is built and the model output cannot reach enforcement (TB6).
- Destination redaction is on by default for both evidence exports (NG-055) and audit cannot contain payload content by contract.
- Evidence exports are write-only from the product's perspective; there is no import path back into enforcement.

## 6. Re-checking this model

- Firewall path handling: `FirewallManager::expandAndCleanPath`, `addRuleInternal`, `removeAppRules`.
- Policy authority: `PolicyStore::loadPolicies` / `savePolicies` / `importPoliciesJson`, `policyOrigin`, `planPolicyReconciliation`.
- Identity and signer evidence: `identity/applicationidentity.cpp`, `identity/publisherresolver.cpp`, `NetworkMonitor` lineage pass.
- Install/update: `AppInstaller::setFullPermissions`, `run`, `syncStaleInstall`.
- Egress: `AiProviderSettings::endpointProblem`, `OpenAiCompatibleProvider::explain`, `aicontext`.

Update the findings table in the same commit as any fix, and keep the acceptance criteria in `TICKETS.md` linked to these IDs.
