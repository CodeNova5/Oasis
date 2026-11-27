/**
 * @file    datasaverenforcementbackend.cpp
 * @brief   Shipped enforcement adapter for Data Saver controls (DS-009).
 * @author  Oasis
 */
#include "datasaverenforcementbackend.h"

#include "firewall/firewallmanager.h"
#include "throttlepolicymanager.h"

namespace {

EnforcementResult makeResult(EnforcementResult::Status status, const QString &policyId,
                             const QString &executablePath, const QString &message)
{
    EnforcementResult value;
    value.status = status;
    value.policyId = policyId;
    value.executablePath = executablePath;
    value.message = message;
    return value;
}

QString directionChannels(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("WinDivert download");
    case NetworkDirection::Upload:   return QStringLiteral("QoS upload");
    case NetworkDirection::Both:     break;
    }
    return QStringLiteral("QoS upload + WinDivert download");
}

} // namespace

ManagerEnforcementBackend::ManagerEnforcementBackend(ThrottlePolicyManager *throttle,
                                                     FirewallManager *firewall)
    : m_throttle(throttle)
    , m_firewall(firewall)
{
}

bool ManagerEnforcementBackend::isAvailable() const
{
    return m_throttle != nullptr || m_firewall != nullptr;
}

EnforcementResult ManagerEnforcementBackend::applyThrottle(const QString &executablePath,
                                                            const QString &policyId,
                                                            quint64 rateBitsPerSecond,
                                                            NetworkDirection direction)
{
    if (!m_throttle) {
        return makeResult(EnforcementResult::Status::Failed, policyId, executablePath,
                      QStringLiteral("No throttle worker is attached, so no limit was requested"));
    }
    if (executablePath.trimmed().isEmpty()) {
        return makeResult(EnforcementResult::Status::Failed, policyId, executablePath,
                      QStringLiteral("No executable path was resolved, so no limit was requested"));
    }

    // One limit per path: never take over a policy limit or a manual limit the
    // user applied from the Limits dialog.
    const QString normalized = ThrottlePolicyManager::normalizePath(executablePath);
    const QString owner = m_throttle->policyAttribution().value(normalized);
    if (m_throttle->isThrottled(executablePath)
        && !DataSaverEnforcement::throttleBelongsTo(owner, policyId)) {
        return makeResult(EnforcementResult::Status::NotApplied, policyId, executablePath,
                      QStringLiteral("Another control already owns this executable's limit"));
    }

    // `automatic = true` is the Data Saver ownership mark: emergency restore may
    // take the limit back, and no user-requested limit is touched.
    m_throttle->applyForPolicy(executablePath, policyId, rateBitsPerSecond, true);

    EnforcementResult value = makeResult(
        EnforcementResult::Status::Requested, policyId, executablePath,
        QStringLiteral("Queued a %1 bits/s limit on the throttle worker").arg(rateBitsPerSecond));
    value.channels = directionChannels(direction);
    value.uploadLimited = direction == NetworkDirection::Upload
                          || direction == NetworkDirection::Both;
    value.downloadLimited = direction == NetworkDirection::Download
                           || direction == NetworkDirection::Both;
    if (value.uploadLimited) value.uploadReason = QStringLiteral("QoS request queued");
    if (value.downloadLimited) value.downloadReason = QStringLiteral("WinDivert shaping request queued");

    // The QoS channel shapes upload only; the download direction needs the
    // WinDivert shaper. When that is not running, report the partial outcome
    // instead of claiming the whole request was accepted.
    const QString downloadStatus = m_throttle->downloadLimiterStatus();
    if (value.downloadLimited && !downloadStatus.isEmpty()) {
        value.status = EnforcementResult::Status::Partial;
        value.downloadReason = downloadStatus;
        value.message = QStringLiteral(
                            "Upload shaping was queued, but download shaping is unavailable: %1")
                            .arg(downloadStatus);
    }
    return value;
}

EnforcementResult ManagerEnforcementBackend::withdrawThrottle(const QString &executablePath,
                                                               const QString &policyId)
{
    if (!m_throttle) {
        return makeResult(EnforcementResult::Status::Failed, policyId, executablePath,
                      QStringLiteral("No throttle worker is attached, so no limit was removed"));
    }

    const QString normalized = ThrottlePolicyManager::normalizePath(executablePath);
    const QString owner = m_throttle->policyAttribution().value(normalized);
    if (!DataSaverEnforcement::throttleBelongsTo(owner, policyId)) {
        // A different policy, or a limit the user applied by hand, owns this
        // path. Data Saver must not take it back.
        return makeResult(EnforcementResult::Status::NotApplied, policyId, executablePath,
                      QStringLiteral("The executable is not attributed to this Data Saver control"));
    }

    m_throttle->remove(executablePath);
    return makeResult(EnforcementResult::Status::Requested, policyId, executablePath,
                  QStringLiteral("Queued removal on the throttle worker"));
}

EnforcementResult ManagerEnforcementBackend::applyBlock(const QString &executablePath,
                                                         const QString &policyId)
{
    if (!m_firewall || !m_firewall->isInitialized()) {
        return makeResult(EnforcementResult::Status::Failed, policyId, executablePath,
                      QStringLiteral("The firewall channel is not available, so no block was applied"));
    }
    if (executablePath.trimmed().isEmpty()) {
        return makeResult(EnforcementResult::Status::Failed, policyId, executablePath,
                      QStringLiteral("No executable path was resolved, so no block was applied"));
    }

    // Rule names are path-keyed, so applying over a block rule that is not ours
    // would rewrite its attribution and make a later withdrawal remove a rule
    // the user created from the Firewall tab. Refuse instead.
    const QString target = DataSaverEnforcement::normalizedPath(executablePath);
    for (const FirewallRule &rule : m_firewall->listRules(true)) {
        if (rule.action != NET_FW_ACTION_BLOCK) continue;
        if (DataSaverEnforcement::normalizedPath(rule.appPath) != target) continue;
        if (DataSaverEnforcement::firewallRuleBelongsTo(rule.description, policyId)) continue;
        return makeResult(EnforcementResult::Status::NotApplied, policyId, executablePath,
                      QStringLiteral("A firewall block outside this control already covers the executable"));
    }

    if (!m_firewall->blockApp(executablePath, policyId)) {
        return makeResult(EnforcementResult::Status::Failed, policyId, executablePath,
                      QStringLiteral("The firewall rejected the block rule"));
    }

    EnforcementResult value = makeResult(EnforcementResult::Status::Applied, policyId,
                                     executablePath,
                                     QStringLiteral("Firewall block rules applied"));
    value.channels = QStringLiteral("firewall");
    return value;
}

EnforcementResult ManagerEnforcementBackend::withdrawBlock(const QString &executablePath,
                                                            const QString &policyId)
{
    if (!m_firewall || !m_firewall->isInitialized()) {
        return makeResult(EnforcementResult::Status::Failed, policyId, executablePath,
                      QStringLiteral("The firewall channel is not available, so no block was removed"));
    }

    const QString target = DataSaverEnforcement::normalizedPath(executablePath);
    QStringList ruleNames;
    for (const FirewallRule &rule : m_firewall->listRules(true)) {
        if (!DataSaverEnforcement::firewallRuleBelongsTo(rule.description, policyId)) continue;
        if (DataSaverEnforcement::normalizedPath(rule.appPath) != target) continue;
        ruleNames.append(rule.name);
    }

    if (ruleNames.isEmpty()) {
        return makeResult(EnforcementResult::Status::NotApplied, policyId, executablePath,
                      QStringLiteral("No firewall rule is attributed to this Data Saver control"));
    }

    bool removed = true;
    for (const QString &name : ruleNames)
        removed = m_firewall->removeRuleByName(name) && removed;

    return makeResult(removed ? EnforcementResult::Status::Applied
                          : EnforcementResult::Status::Failed,
                  policyId, executablePath,
                  removed ? QStringLiteral("Firewall block rules removed")
                          : QStringLiteral("A firewall block rule could not be removed"));
}
