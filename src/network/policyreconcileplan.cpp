/**
 * @file   policyreconcileplan.cpp
 * @brief  Pure reconciliation planning (NG-024): no COM, no managers.
 *
 * Kept apart from the executor so the decisions can be exercised by the test
 * harness on any machine, without elevation or a Windows Firewall API.
 *
 * @author Codebuff
 */

#include "policyreconcile.h"

#include "enforcementrestore.h"
#include "policyschedule.h"

#include <QDir>
#include <QStringList>

namespace {

// Plain aggregates: the project builds as C++14, where default member
// initializers would stop brace initialization from compiling.
struct DesiredFirewall
{
    QString path;      // original form
    bool block;
    QString policyId;
};

struct DesiredThrottle
{
    QString path;      // original form
    NetworkPolicy policy;
};

QString normalizedPath(const QString &path)
{
    const QString trimmed = path.trimmed();
    if (trimmed.isEmpty()) return QString();
    return QDir::cleanPath(QDir::toNativeSeparators(trimmed)).toLower();
}

ReconciliationAction reportAction(const QString &message, const QString &policyId = QString())
{
    ReconciliationAction action;
    action.kind = ReconciliationAction::Kind::Report;
    action.policyId = policyId;
    action.message = message;
    return action;
}

bool wantsDownload(const NetworkPolicy &policy)
{
    return policy.direction == NetworkDirection::Download ||
           policy.direction == NetworkDirection::Both;
}

} // namespace

// ─── Report ─────────────────────────────────────────────────────────────────

QString ReconciliationReport::summary() const
{
    if (repaired == 0 && removed == 0 && failed == 0 && unattributed == 0 &&
        unresolved == 0) {
        return QStringLiteral("All stored policies match the enforced state.");
    }

    QStringList parts;
    parts << QStringLiteral("%1 repaired").arg(repaired);
    parts << QStringLiteral("%1 removed").arg(removed);
    if (failed > 0) parts << QStringLiteral("%1 failed").arg(failed);
    if (unattributed > 0) parts << QStringLiteral("%1 left in place").arg(unattributed);
    if (unresolved > 0) parts << QStringLiteral("%1 unresolved").arg(unresolved);
    return parts.join(QStringLiteral(", "));
}

QStringList ReconciliationReport::lines() const
{
    QStringList result;
    for (const ReconciliationAction &action : actions) {
        const QString subject = action.path.isEmpty() ? action.ruleName : action.path;
        switch (action.kind) {
        case ReconciliationAction::Kind::CreateFirewallRule:
            result << QStringLiteral("%1 firewall rule for %2 — %3")
                          .arg(action.block ? QStringLiteral("created block")
                                            : QStringLiteral("created allow"),
                               subject, action.message);
            break;
        case ReconciliationAction::Kind::RemoveFirewallRule:
            result << QStringLiteral("removed firewall rule %1 for %2 — %3")
                          .arg(action.ruleName, subject, action.message);
            break;
        case ReconciliationAction::Kind::ApplyThrottle:
            result << QStringLiteral("requested a limit for %1 — %2")
                          .arg(subject, action.message);
            break;
        case ReconciliationAction::Kind::ReassignThrottle:
            result << QStringLiteral("updated the limit owner for %1 — %2")
                          .arg(subject, action.message);
            break;
        case ReconciliationAction::Kind::RemoveThrottle:
            result << QStringLiteral("removed the limit for %1 — %2")
                          .arg(subject, action.message);
            break;
        case ReconciliationAction::Kind::Report:
            result << action.message;
            break;
        }
    }
    return result;
}

QString reconciledPolicyId(const QString &ruleDescription)
{
    const QString prefix = QStringLiteral("NetGuard policy ");
    const QString description = ruleDescription.trimmed();
    if (!description.startsWith(prefix, Qt::CaseInsensitive)) return QString();
    return description.mid(prefix.size()).trimmed();
}

// ─── Plan ───────────────────────────────────────────────────────────────────

ReconciliationReport planPolicyReconciliation(
    const QList<NetworkPolicy> &policies,
    const QHash<QString, QStringList> &groupPaths,
    const PolicyObservation &observed,
    const QDateTime &now)
{
    ReconciliationReport report;

    QHash<QString, DesiredFirewall> desiredFirewall;
    QHash<QString, DesiredThrottle> desiredThrottle;
    QSet<QString> firewallConflicts;

    // ── What the active policies want ──
    for (const NetworkPolicy &policy : policies) {
        if (policy.id.isEmpty()) continue;
        if (policyActivationAt(policy, now) != PolicyActivationState::Active) continue;

        const PolicyChannels channels = plannedChannels(policy);
        if (!channels.any()) continue;

        const QString scope = policy.scope.trimmed().toLower();
        QStringList paths;
        if (scope == QLatin1String("path") || scope == QLatin1String("executable")) {
            if (!policy.targetId.trimmed().isEmpty()) paths << policy.targetId;
        } else if (scope == QLatin1String("group")) {
            paths = groupPaths.value(policy.targetId);
            if (paths.isEmpty()) {
                report.actions << reportAction(
                    QStringLiteral("Group \"%1\" has no running members; nothing to verify")
                        .arg(policy.targetId), policy.id);
                continue;
            }
        } else {
            ++report.unresolved;
            report.actions << reportAction(
                QStringLiteral("Policy scope \"%1\" cannot be resolved to running processes in this build")
                    .arg(policy.scope), policy.id);
            continue;
        }

        if (paths.isEmpty()) {
            ++report.unresolved;
            report.actions << reportAction(
                QStringLiteral("Policy has no target to verify"), policy.id);
            continue;
        }

        for (const QString &path : paths) {
            const QString key = normalizedPath(path);
            if (key.isEmpty()) continue;

            if (channels.firewall) {
                if (firewallConflicts.contains(key)) continue;
                const bool block = policy.action == NetworkPolicy::Action::Block;
                const auto existing = desiredFirewall.constFind(key);
                if (existing != desiredFirewall.constEnd() && existing->block != block) {
                    firewallConflicts.insert(key);
                    desiredFirewall.remove(key);
                    ++report.unresolved;
                    report.actions << reportAction(
                        QStringLiteral("Two active policies target %1 with different firewall "
                                       "actions; no rule was changed automatically").arg(path),
                        policy.id);
                } else if (existing == desiredFirewall.constEnd()) {
                    // Two policies wanting the same action agree; the first one
                    // keeps ownership of the rule.
                    desiredFirewall.insert(key, DesiredFirewall{path, block, policy.id});
                }
            }

            if (channels.throttle && !desiredThrottle.contains(key)) {
                // Path-keyed limits have no per-policy identity, so the first
                // policy owns the limit for this path.
                desiredThrottle.insert(key, DesiredThrottle{path, policy});
            }
        }
    }

    // ── Firewall: what exists ──
    QHash<QString, QList<FirewallObservation>> rulesByPath;
    for (const FirewallObservation &rule : observed.firewallRules) {
        const QString key = normalizedPath(rule.path);
        if (key.isEmpty()) continue;
        rulesByPath[key].append(rule);
    }

    // Missing rules for a wanted path.
    for (auto it = desiredFirewall.constBegin(); it != desiredFirewall.constEnd(); ++it) {
        if (firewallConflicts.contains(it.key())) continue;

        bool outbound = false;
        bool inbound = false;
        bool attributed = false;
        for (const FirewallObservation &rule : rulesByPath.value(it.key())) {
            if (!rule.enabled || rule.block != it->block) continue;
            if (rule.inbound) inbound = true; else outbound = true;
            if (rule.policyId == it->policyId) attributed = true;
        }

        if (outbound && inbound && attributed) continue;

        ReconciliationAction action;
        action.kind = ReconciliationAction::Kind::CreateFirewallRule;
        action.policyId = it->policyId;
        action.path = it->path;
        action.block = it->block;
        action.message = attributed
            ? QStringLiteral("the inbound or outbound rule is missing")
            : QStringLiteral("the rule is missing or was not created by this policy");
        report.actions << action;
    }

    // Attributed rules that no active policy wants any more.
    for (const FirewallObservation &rule : observed.firewallRules) {
        if (rule.policyId.isEmpty()) continue;
        const QString key = normalizedPath(rule.path);
        if (firewallConflicts.contains(key)) continue;

        const auto desired = desiredFirewall.constFind(key);
        if (desired != desiredFirewall.constEnd() && desired->block == rule.block) continue;

        ReconciliationAction action;
        action.kind = ReconciliationAction::Kind::RemoveFirewallRule;
        action.policyId = rule.policyId;
        action.path = rule.path;
        action.ruleName = rule.name;
        action.block = rule.block;
        action.message = QStringLiteral("no active policy wants this rule any more");
        report.actions << action;
    }

    // Rules the user (or an older build) made outside a policy: never removed.
    for (const FirewallObservation &rule : observed.firewallRules) {
        if (!rule.policyId.isEmpty()) continue;
        const QString key = normalizedPath(rule.path);
        const auto desired = desiredFirewall.constFind(key);
        if (desired != desiredFirewall.constEnd() && desired->block == rule.block)
            continue;  // the create action above rewrites it with the policy id
        ++report.unattributed;
    }

    // ── Throttle/shaping: what exists ──
    for (auto it = desiredThrottle.constBegin(); it != desiredThrottle.constEnd(); ++it) {
        const bool throttled = observed.throttledPaths.contains(it.key());
        const bool downloadLimited = observed.downloadLimits.contains(it.key());

        if (throttled && (!wantsDownload(it->policy) || downloadLimited)) {
            // The enforced limit is right, but a different policy may have
            // asked for it originally. Hand ownership over without touching
            // QoS, so a later withdrawal follows the policy that wants it now.
            // A limit applied outside a policy has no owner and is not adopted.
            const QString currentOwner = observed.throttlePolicyIds.value(it.key());
            const bool automatic = policyOrigin(it->policy) == PolicyOrigin::Automatic;
            const bool autoMatches =
                observed.autoAppliedPaths.contains(it.key()) == automatic;
            if (!currentOwner.isEmpty() &&
                (currentOwner != it->policy.id || !autoMatches)) {
                ReconciliationAction reassign;
                reassign.kind = ReconciliationAction::Kind::ReassignThrottle;
                reassign.policyId = it->policy.id;
                reassign.path = it->path;
                reassign.automatic = automatic;
                reassign.message = currentOwner == it->policy.id
                    ? QStringLiteral("the limit's automatic status changed")
                    : QStringLiteral("the limit is now owned by the active policy");
                report.actions << reassign;
            }
            continue;
        }

        ReconciliationAction action;
        action.kind = ReconciliationAction::Kind::ApplyThrottle;
        action.policyId = it->policy.id;
        action.path = it->path;
        action.automatic = policyOrigin(it->policy) == PolicyOrigin::Automatic;
        action.message = throttled
            ? QStringLiteral("the download shaping limit is missing")
            : QStringLiteral("no limit is applied");
        report.actions << action;
    }

    for (const QString &path : observed.throttledPaths) {
        if (desiredThrottle.contains(path)) continue;

        // A limit is safe to withdraw when the product applied it automatically,
        // or when it names the policy that asked for it; only a limit with no
        // attribution at all is left in place.
        const QString attributed = observed.throttlePolicyIds.value(path);
        if (observed.autoAppliedPaths.contains(path) || !attributed.isEmpty()) {
            ReconciliationAction action;
            action.kind = ReconciliationAction::Kind::RemoveThrottle;
            action.policyId = attributed;
            action.path = path;
            action.message = attributed.isEmpty()
                ? QStringLiteral("no active policy wants this automatic limit any more")
                : QStringLiteral("the policy that asked for this limit is no longer active");
            report.actions << action;
        } else {
            ++report.unattributed;
        }
    }

    if (report.unattributed > 0) {
        report.actions << reportAction(
            QStringLiteral("%1 control(s) were not created by a policy and were left in place; "
                           "attribution is missing")
                .arg(report.unattributed));
    }

    return report;
}
