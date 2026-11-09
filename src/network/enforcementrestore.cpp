/**
 * @file   enforcementrestore.cpp
 * @brief  Enforcement channel routing and emergency-restore planning (NG-026).
 * @author Codebuff
 */

#include "enforcementrestore.h"

namespace {

QString originNote(const NetworkPolicy &policy)
{
    switch (policyOrigin(policy)) {
    case PolicyOrigin::User:
        return QStringLiteral("Kept: created by the user");
    case PolicyOrigin::Automatic:
        return QStringLiteral("Removed: created by automatic enforcement");
    case PolicyOrigin::Unknown:
        break;
    }
    return QStringLiteral("Kept: origin not recorded, so it was not removed");
}

} // namespace

// ─── Enforcement channels ───────────────────────────────────────────────────

PolicyChannels plannedChannels(const NetworkPolicy &policy)
{
    PolicyChannels channels;

    if (!policy.enabled) return channels;

    switch (policy.action) {
    case NetworkPolicy::Action::Block:
    case NetworkPolicy::Action::Allow:
        // Both are firewall rules; a block stops traffic instead of shaping it.
        channels.firewall = true;
        break;
    case NetworkPolicy::Action::Throttle:
    case NetworkPolicy::Action::Schedule:
        channels.throttle = true;
        break;
    case NetworkPolicy::Action::Notify:
    case NetworkPolicy::Action::Ask:
    case NetworkPolicy::Action::NoAction:
        // Advisory: the user or a later policy makes the decision. A port or
        // protocol scope does not change that; mapping it to the firewall would
        // create an allow rule nobody asked for.
        break;
    }

    if (channels.throttle) {
        channels.uploadShaping =
            policy.direction == NetworkDirection::Upload ||
            policy.direction == NetworkDirection::Both;
        channels.downloadShaping =
            policy.direction == NetworkDirection::Download ||
            policy.direction == NetworkDirection::Both;
    }

    return channels;
}

QString channelsDescription(const PolicyChannels &channels)
{
    if (!channels.any()) return QStringLiteral("none");

    QStringList parts;
    if (channels.firewall) parts << QStringLiteral("firewall");

    if (channels.throttle) {
        QStringList shaping;
        if (channels.uploadShaping) shaping << QStringLiteral("QoS upload");
        if (channels.downloadShaping) shaping << QStringLiteral("WinDivert download");
        if (shaping.isEmpty()) shaping << QStringLiteral("throttle (no direction)");
        parts << shaping.join(QStringLiteral(" + "));
    }

    return parts.join(QStringLiteral(", "));
}

// ─── Emergency restore ──────────────────────────────────────────────────────

EmergencyRestorePlan buildEmergencyRestorePlan(const QList<NetworkPolicy> &policies)
{
    EmergencyRestorePlan plan;
    for (const NetworkPolicy &policy : policies) {
        if (policyOrigin(policy) == PolicyOrigin::Automatic)
            plan.automatic.append(policy);
        else
            plan.preserved.append(policy);
    }
    return plan;
}

EmergencyRestoreReport applyEmergencyRestorePlan(const EmergencyRestorePlan &plan,
                                                 bool throttleRestoreRequested,
                                                 const QString &throttleMessage,
                                                 bool storeWriteSucceeded)
{
    EmergencyRestoreReport report;

    for (const NetworkPolicy &policy : plan.automatic) {
        EmergencyRestoreEntry entry;
        entry.policyId = policy.id;
        entry.target = policy.targetId;
        entry.channel = QStringLiteral("policy store");
        if (storeWriteSucceeded) {
            entry.outcome = QStringLiteral("removed");
            entry.message = originNote(policy);
            ++report.removed;
            report.removedIds << policy.id;
        } else {
            entry.outcome = QStringLiteral("failed");
            entry.message = QStringLiteral("Could not remove the policy: the store write failed");
            ++report.failed;
        }
        report.entries.append(entry);
    }

    for (const NetworkPolicy &policy : plan.preserved) {
        EmergencyRestoreEntry entry;
        entry.policyId = policy.id;
        entry.target = policy.targetId;
        entry.channel = QStringLiteral("policy store");
        entry.outcome = QStringLiteral("preserved");
        entry.message = originNote(policy);
        ++report.preserved;
        report.preservedIds << policy.id;
        report.entries.append(entry);
    }

    EmergencyRestoreEntry throttle;
    throttle.channel = QStringLiteral("throttle");
    throttle.outcome = throttleRestoreRequested
        ? QStringLiteral("requested")
        : QStringLiteral("skipped");
    throttle.message = throttleMessage;
    report.throttleRestoreRequested = throttleRestoreRequested;
    report.throttleMessage = throttleMessage;
    report.entries.append(throttle);

    return report;
}

QString EmergencyRestoreReport::summary() const
{
    QStringList parts;
    if (removed > 0)
        parts << QStringLiteral("Removed %1 automatic %2")
                     .arg(removed)
                     .arg(removed == 1 ? QStringLiteral("policy") : QStringLiteral("policies"));
    else
        parts << QStringLiteral("No automatic policies to remove");

    if (preserved > 0)
        parts << QStringLiteral("kept %1 %2")
                     .arg(preserved)
                     .arg(preserved == 1 ? QStringLiteral("policy") : QStringLiteral("policies"));

    if (failed > 0)
        parts << QStringLiteral("%1 failed").arg(failed);

    parts << (throttleRestoreRequested ? QStringLiteral("bandwidth limits being restored")
                                       : QStringLiteral("no bandwidth limits to restore"));
    return parts.join(QStringLiteral("; "));
}

QStringList EmergencyRestoreReport::lines() const
{
    QStringList result;
    for (const EmergencyRestoreEntry &entry : entries) {
        QString subject = entry.target.isEmpty() ? entry.policyId : entry.target;
        if (subject.isEmpty()) subject = entry.channel;
        result << QStringLiteral("%1 [%2] %3 — %4")
                      .arg(entry.outcome, entry.channel, subject, entry.message);
    }
    return result;
}
