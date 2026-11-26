# Threat Model — Identity and Enforcement Boundaries (NG-060)

Status: **review complete**. The model below describes the code as it exists today, not as it is intended to be; where the two differ, that is a finding with a ticket.
Scope: the trust decisions the product makes about *which executable is which*, *who may change policy*, and *what the elevated process will do on their behalf*.
Out of scope: Windows kernel, WinDivert driver internals, Qt/OpenSSL vulnerabilities, and physical access.

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| Firewall rules named `Oasis_*` in `INetFwRules` | Blocking or allowing outbound traffic is the product's whole effect. Unauthorized writes are a firewall bypass or a denial of service. |
| Throttle limits (QoS policies) | Same authority, smaller blast radius. |
| Policy store (`HKCU\Software\…\Oasis/Policies`, QSettings) | The authority the elevated app acts on. |
| Audit trail (`Oasis/Audit`, same QSettings) | The record of what was enforced. Forgeable evidence undermines every other control. |
| Installed executable (`%ProgramFiles%\Oasis\Oasis.exe`) | Runs elevated; whoever can replace it owns the machine. |
| Attribution metadata (DNS, TLS SNI, QUIC, endpoint catalog) | The user's browsing interests. Must not leave the machine except through the opt-in AI path. |
| AI provider credential | Read from `OASIS_AI_API_KEY`; never persisted by this product. |

## 2. Adversary model

1. **Local non-admin user** — can write their own `HKCU`, start processes, name them anything, and read the audit trail. Cannot write `Program Files` *by default*.
2. **Malicious policy-file author** — distributes a "recommended policies" JSON file and relies on the user importing it.
3. **Malicious local process with admin rights** — already owns the machine; not defended against.
4. **Network attacker on the path** — can influence destination names, not the policy store.
5. **Third-party services** — the AI provider (only when the user opts in) and the update-check host.

## 3. Trust boundaries and the decisions taken at each

### TB1 — Process identity and policy targets

| Decision | Where | Assessment |
| --- | --- | --- |
| Identity is keyed by canonical path, not by process name or PID | `ApplicationIdentityResolver::canonicalPath` → `GetFinalPathNameByHandleW`; `identityIdForCanonicalPath` hashes the normalized path | Sound: the same file reached by a different spelling (case, separators, `/`, trailing slash) maps to one identity, and junctions/symlinks resolve to the final path via the handle. |
| PID reuse must not inherit attribution | `processlineage` reports `LineageChange::Reused` when a PID's creation time changes, and `networkmonitor_caches` drops the cached identity | Sound: a new process at an old PID starts with no attribution. |
| Enforcement targets are resolved per scope at reconcile time | `planPolicyReconciliation`: `path`/`executable` use `targetId` verbatim, `group` uses the live membership snapshot | **Gap:** `publisher`, `service`, `package`, `pid`, `port`, and `protocol` scopes never resolve to paths and are reported as unresolved. They are stored and explained but do not enforce; the editor's stored-only wording (NG-053) keeps that honest. |
| Reconcile compares paths with `QDir::cleanPath` + case folding, without environment expansion or final-path resolution | `policyreconcileplan.cpp::normalizedPath` vs `FirewallManager::expandAndCleanPath` | **Open finding F-05.** A target stored as `%ProgramFiles%\App\app.exe` produces the key `%programfiles%\app\app.exe`, while the rule Windows holds is `C:\Program Files\App\app.exe`; they never match, so the policy is re-applied every cycle and reported as missing. |
| A display path may fall back to `%SystemRoot%\System32\<name>` for a process that cannot be opened | `NetworkWidget::getExactProcessPath` | **Open finding F-06 (low).** The fallback feeds `showApplicationDetails` and policy creation, so a process that hides its image path but presents a System32 file's name can produce an action against `System32\<name>` instead of the process the user is looking at. It cannot affect a policy that already has a stored target. |

### TB2 — Signer → publisher trust

| Decision | Where | Assessment |
| --- | --- | --- |
| "Signed" requires a successful `WinVerifyTrust` for the embedded or catalog signature | `PublisherResolver::runTrustCheck` | Sound; unsigned, invalid, and unverified states are distinct. |
| Publisher, organization, subject, thumbprint, and timestamp are cleared unless the status is `Signed` | end of `PublisherResolver::resolve` | Sound: an untrusted chain can never supply a publisher string that later drives a policy. |
| Trust uses `WTD_CACHE_ONLY_URL_RETRIEVAL \| WTD_REVOCATION_CHECK_NONE` | `makeVerifyData` | **Accepted:** a refresh must not block on the network, so revocation is not consulted; a revoked but cached certificate reads as `Signed`. Publisher is evidence only in this build, never an enforcement authority. |
| Publisher is a certificate CN string | `readSignerEvidence` (`2.5.4.3`) | **Accepted for now:** CNs are not unique across CAs. Acceptable while publisher-scope policies do not enforce; it must change before they do. |

### TB3 — Policy store → elevated enforcement

| Decision | Where | Assessment |
| --- | --- | --- |
| Policies and audit events live in per-user QSettings; the elevated app applies every active policy it loads at the 8-second startup reconcile and on each scheduler tick | `PolicyStore::loadPolicies`, `AuditEventStore`, `PolicyScheduler`, `PolicyReconciler` in `NetworkWidget`'s constructor | **Open finding F-02.** A medium-integrity process running as the same user can write `HKCU` and have the elevated app apply an allow or block rule for an arbitrary executable at the next launch, with no user action in the loop; the same write access can erase or forge audit entries. |
| Emergency restore only removes policies whose origin is `automatic`/`system`/`ai` | `policyOrigin` | Sound. Unknown sources are preserved rather than removed. |
| Conflicting active policies for one path are not auto-resolved | `planPolicyReconciliation` (`firewallConflicts` → report action) | Sound: fails safe and changes no rule. |
| Rule writes are remove-then-create | `FirewallManager::addRuleInternal` after `removeRuleByName` | **Accepted (low):** a brief window exists where neither rule is set. An attacker able to race it already has admin. |
| `removeAppRules` always reports success | `FirewallManager::removeAppRules` (HRESULT ignored, `success` never set false) | **Accepted (informational):** affects reporting only; reconciliation re-creates rules on the next pass. |
| Kill by image name during install/update | `AppInstaller::killOtherInstances` | **Accepted (low):** another user's instance, or a look-alike process, can be terminated. Annoyance, not escalation. |

### TB4 — Imported JSON

| Decision | Where | Assessment |
| --- | --- | --- |
| No rule or policy import UI exists in this build | `src/ui`, `src/network` (no `QFileDialog` import path) | Sound today. Both hazards below are reachable only through the store APIs or a future UI. |
| Policy import merges by `id`, replaces an existing policy with the same id, keeps any `scope`/`action`/`source`/`targetId`, and saves immediately; no schema validation, preview, or confirmation | `PolicyStore::importPoliciesJson` | **Open finding F-03 (latent, medium).** Nothing calls it yet. Before any import/restore feature ships, an imported policy must not be able to claim `system`/`automatic`, silently replace an allow with a block, or skip a diff and confirmation. |
| An empty application path produces a rule with no `ApplicationName`, which applies to every program on the profile | `FirewallManager::addRuleInternal` (`bA == nullptr` when `nativePath` is empty) | **Open finding F-04 (latent, low).** No current caller passes an empty path: reconcile skips empty targets and policy paths come from the process list. It is a one-line guard and a harness check away from being a non-issue, and it matters the moment an import or bulk-edit path is added. |
| Evidence files are the only files the product writes that can be re-read; none is importable | `EvidenceExport`, audit export | Sound: exported evidence cannot re-enter enforcement. |

### TB5 — Privilege boundaries

| Decision | Where | Assessment |
| --- | --- | --- |
| The app requires administrator and self-elevates with `runas` when launched unelevated | `app.manifest` (`requireAdministrator`), `main.cpp::elevate` | Expected for a firewall manager. The consequence is that every decision above happens inside an elevated process, so its inputs must be treated as attacker-controlled. |
| The installed executable and `version.dat` are granted `WriteOther` / `WriteGroup` after install, after update, and on the copy path | `AppInstaller::setFullPermissions`, applied to `installedExePath()` | **Open finding F-01, highest severity.** Any local user can overwrite the binary the product then launches elevated: direct local privilege escalation, and it defeats every other control here. |
| Update check fetches a version document from a third-party pastebin and only opens a download page; it downloads and executes nothing | `updatechecker.cpp` (`UPDATE_URL`, `DOWNLOAD_PAGE` via `QDesktopServices::openUrl`) | **Accepted, with a recommendation:** no code-execution path, but the channel should be hosted on the project's own domain so a pastebin compromise cannot announce a fake release. |

### TB6 — AI assistance egress (opt-in)

| Decision | Where | Assessment |
| --- | --- | --- |
| Disabled until the user configures an endpoint and model | `AiProviderSettings::isConfigured` | Sound. |
| HTTPS required; plain HTTP allowed only for loopback | `AiProviderSettings::endpointProblem` | Sound; prevents accidental cleartext of local metadata. |
| Credential comes from `OASIS_AI_API_KEY`, never from settings | `OpenAiCompatibleProvider::explain` | Sound. |
| The request body is the redacted AI context document only: no payloads, no full paths | `AiContext`, `OpenAiCompatibleProvider` | Sound by construction; destination masking (NG-036) runs before the payload is built. |
| A response can never become a policy; it is explanation text and approval still goes through the local dialog | `AiAssistant`, `AiApprovalDialog` | Sound: the model has no path to enforcement. |

## 4. Findings

| ID | Severity | Finding | Ticket |
| --- | --- | --- | --- |
| F-01 | **High** | Installed executable in `Program Files` is writable by `Everyone`; the product relaunches it elevated. Local privilege escalation. | NG-065 (P0) |
| F-02 | **High** | Policy store and audit trail live in per-user settings that the elevated app trusts and applies at startup; a same-user medium-integrity process can inject allow/block rules and erase evidence. | NG-066 (P0) |
| F-03 | Medium (latent) | `PolicyStore::importPoliciesJson` accepts any scope/action/source/target and silently replaces policies by id; no validation, preview, or confirmation. Not exposed in the UI today. | NG-067 (P1) |
| F-04 | Low (latent) | An empty `appPath` becomes a firewall rule with no application name, i.e. a profile-wide block; no current caller passes one. | NG-068 (P2) |
| F-05 | Medium | Enforcement is path-keyed: a copy or hardlink of a blocked image is not blocked, and reconcile path keys omit the expansion/canonicalization the firewall applies, so `%VAR%` targets never match and are re-applied forever. | NG-069 (P2) |
| F-06 | Low | The display-path fallback to `System32\<name>` is also used to build enforcement actions for unopenable processes. | NG-069 (P2) |
| F-07 | Low | Publisher identity is a certificate CN, which is not unique; harmless only while publisher scope does not enforce. | Tracked with NG-067; revisit when publisher scope enforces |
| F-08 | Low | Rule replacement is remove-then-create. | Accepted (TB3) |
| F-09 | Info | Revocation is not checked (offline-only trust). | Accepted (TB2) |
| F-10 | Info | The update manifest is hosted on a third-party pastebin. | Accepted (TB5) |

**Release gate:** F-01 and F-02 must be closed before a 1.0 release. F-03 must be closed before any policy import/restore UI ships. F-05 and F-06 are documented limits with a P2 hardening ticket, because path-keyed firewall rules are an OS constraint and the fallback only reaches a user-initiated action.

## 5. Mitigations that must not regress

- Publisher strings are erased unless the chain verifies (TB2).
- Unknown policy sources are preserved, so emergency restore cannot silently delete imported or hand-edited policies (TB3).
- Conflicting policies fail closed into a report and change no rule (TB3).
- The AI context is redacted before it is built, and model output cannot reach enforcement (TB6).
- Destination redaction is on by default for evidence exports (NG-055), and audit events cannot contain payload content by contract.
- Exported evidence cannot be imported back into enforcement.

## 6. Re-checking this model

- Firewall path handling: `FirewallManager::expandAndCleanPath`, `addRuleInternal`, `removeAppRules`.
- Policy authority: `PolicyStore::loadPolicies` / `savePolicies` / `importPoliciesJson`, `policyOrigin`, `planPolicyReconciliation`, `normalizedPath`.
- Identity and signer evidence: `identity/applicationidentity.cpp`, `identity/publisherresolver.cpp`, the `NetworkMonitor` lineage pass, `NetworkWidget::getExactProcessPath`.
- Install/update: `AppInstaller::setFullPermissions`, `run`, `syncStaleInstall`, `killOtherInstances`.
- Egress: `AiProviderSettings::endpointProblem`, `OpenAiCompatibleProvider::explain`, `AiContext`, `updatechecker.cpp`.

When fixing a finding, update its row in this document in the same commit so the severity, evidence, and ticket stay together.
