/**
 * @file   policyscope.h
 * @brief  What a policy covers, what it will do, and whether this build does it (NG-053).
 *
 * The editor and the policy list both have to answer the same three questions
 * before a policy is saved and again while it is listed: how broad is the
 * scope, what exactly happens while it is in force, and will this build
 * actually enforce it. Keeping the answers here, free of widgets, means the
 * wording is checked by the harness and cannot drift between the two dialogs.
 *
 * Scope keys match `NetworkPolicy::scope`: "pid", "path", "publisher",
 * "service", and "group". A group policy stores the activity-group id in
 * `targetId`, which is what NG-025 re-applies to future members.
 *
 * @author Codebuff
 */

#pragma once

#include <QDateTime>
#include <QString>

#include "network/policy.h"

// ─── Scopes the editor offers (PRD 9.3) ─────────────────────────────────────
enum class PolicyScopeKind {
    Pid,              // this process instance only
    ExecutablePath,   // this file at this path
    Publisher,        // every process signed by this publisher
    Service,          // this Windows service and its hosts
    ApplicationGroup  // every current and future member of the group
};

QString policyScopeDisplayName(PolicyScopeKind scope);
QString policyScopeKey(PolicyScopeKind scope);
// Parses a stored scope key; false leaves `scope` untouched.
bool policyScopeKindFromKey(const QString &key, PolicyScopeKind *scope);

QString policyScopeBreadth(PolicyScopeKind scope);
QString policyScopeExplanation(PolicyScopeKind scope);
bool policyScopeAffectsFutureProcesses(PolicyScopeKind scope);
// False for scopes this build stores but cannot resolve to running processes
// yet; the dialog says so instead of implying the policy is in force.
bool policyScopeEnforcedByThisBuild(PolicyScopeKind scope);

// Publisher and group scopes cover software the user has not chosen directly,
// so they are the two that ask for confirmation before saving.
bool policyScopeIsBroad(PolicyScopeKind scope);
// Only an enabled broad policy is worth interrupting for: a disabled one is
// stored but has no effect.
bool policyScopeRequiresConfirmation(PolicyScopeKind scope, bool enabled);

// Breadth, explanation, future-process note, and enforcement note, as shown in
// the dialog.
QString policyScopeRiskSummary(PolicyScopeKind scope);
// One short sentence: what this build does with the scope, or that it only
// stores it.
QString policyScopeEnforcementNote(PolicyScopeKind scope);

// ─── Effect and impact ──────────────────────────────────────────────────────
// The rate the throttle channel actually requests in this build (NG-021): a
// stored rate is recorded but the manager is asked for this default. Keep in
// sync with ThrottlePolicyManager::DefaultLimitBitsPerSecond.
constexpr quint64 kEnforcedThrottleBitsPerSecond = 409600;

QString policyActionDisplayName(NetworkPolicy::Action action);
QString policyDirectionDisplayName(NetworkDirection direction);
// "0.40 Mbit/s"
QString policyRateText(quint64 bitsPerSecond);

QString policyEffectSummary(NetworkPolicy::Action action, NetworkDirection direction,
                            quint64 rateBitsPerSecond);

// Everything the editor has chosen, before it becomes a NetworkPolicy.
struct PolicyImpact
{
    PolicyScopeKind scope = PolicyScopeKind::ExecutablePath;
    QString target;
    NetworkPolicy::Action action = NetworkPolicy::Action::Allow;
    NetworkDirection direction = NetworkDirection::Download;
    quint64 rateBitsPerSecond = 0;
    QDateTime expiration;
    QString schedule;
    bool enabled = true;
};

// Multi-line preview: scope and breadth, target, effect, duration, recurring
// window, state, and enforcement. Deterministic for a given `now`.
QString policyImpactSummary(const PolicyImpact &impact, const QDateTime &now);

// The question asked before a broad policy is saved, with the impact summary
// underneath it.
QString policyConfirmationText(const PolicyImpact &impact, const QDateTime &now);

// One line for the policy list: "Enforced", "Stored only — ...", or the
// fixed-rate caveat. The scope key is read from the policy, so a stored policy
// with a scope the editor does not know is reported rather than assumed.
QString policyEnforcementSummary(const NetworkPolicy &policy);
