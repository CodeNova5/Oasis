/**
 * @file   enforcementcoordinator.cpp
 * @brief  EnforcementCoordinator (NG-021) and emergency restore (NG-026).
 * @author Codebuff
 */

#include "enforcementcoordinator.h"

#include "policy.h"
#include "firewallmanager.h"
#include "throttlepolicymanager.h"

#include <QDebug>
#include <QStringList>

EnforcementCoordinator::EnforcementCoordinator(QObject *parent)
    : QObject(parent)
{
}

EnforcementCoordinator::EnforcementCoordinator(ThrottlePolicyManager *throttle,
                                               FirewallManager *firewall,
                                               QObject *parent)
    : QObject(parent)
    , m_throttle(throttle)
    , m_firewall(firewall)
{
}

EnforcementCoordinator::~EnforcementCoordinator() = default;

EnforcementResult EnforcementCoordinator::unenforcedResult(const NetworkPolicy &policy,
                                                           const QString &executablePath,
                                                           const QString &reason)
{
    EnforcementResult result;
    result.policyId = policy.id;
    result.executablePath = executablePath;
    result.channels = channelsDescription(plannedChannels(policy));
    result.status = EnforcementResult::Status::NotApplied;
    result.message = reason;
    return result;
}

// ──────────────────────────────────────────────────────────────────────
//  Public: apply one policy
// ──────────────────────────────────────────────────────────────────────
EnforcementResult EnforcementCoordinator::applyPolicy(const NetworkPolicy &policy,
                                                      const QString &executablePath)
{
    const PolicyChannels channels = plannedChannels(policy);

    EnforcementResult result;
    if (!policy.enabled) {
        result = unenforcedResult(policy, executablePath, QStringLiteral("Policy is disabled"));
    } else if (channels.firewall) {
        result = routeToFirewall(policy, executablePath);
    } else if (channels.throttle) {
        result = routeToThrottle(policy, executablePath);
    } else {
        result = unenforcedResult(policy, executablePath,
                                  QStringLiteral("This action needs no enforcement channel"));
    }

    emit policyApplied(result.policyId, result.executablePath, result);
    return result;
}

QList<EnforcementResult> EnforcementCoordinator::applyAllPolicies(
    const QList<NetworkPolicy> &policies, const QString &executablePath)
{
    QList<EnforcementResult> results;
    results.reserve(policies.size());

    for (const NetworkPolicy &policy : policies)
        results.append(applyPolicy(policy, executablePath));

    emit enforcementComplete(executablePath, results);
    return results;
}

// ──────────────────────────────────────────────────────────────────────
//  Group re-application (NG-025)
//
//  Groups are rebuilt from the processes that own traffic, so a member that
//  exits and is replaced shows up as a membership change: the old PID is no
//  longer running and a new executable path may appear. This is the only place
//  that decides whether a control must be applied again, so a replacement is
//  handled the same way whether the group was automatic or created by the user.
// ──────────────────────────────────────────────────────────────────────
QList<EnforcementResult> EnforcementCoordinator::reapplyGroupPolicies(
    const QString &groupId, const QStringList &executablePaths,
    const QList<NetworkPolicy> &policies)
{
    QList<EnforcementResult> results;
    if (groupId.isEmpty() || executablePaths.isEmpty()) return results;

    for (const NetworkPolicy &policy : policies) {
        if (!policy.enabled || policy.id.isEmpty()) continue;
        if (policy.scope.trimmed().compare(QStringLiteral("group"), Qt::CaseInsensitive) != 0)
            continue;
        if (policy.targetId != groupId) continue;

        const PolicyChannels channels = plannedChannels(policy);
        if (!channels.any()) continue;  // advisory policy: nothing to re-apply

        for (const QString &path : executablePaths) {
            const QString executable = path.trimmed();
            if (executable.isEmpty()) continue;

            const QString pairKey = groupId + QLatin1Char('\n') + policy.id +
                                    QLatin1Char('\n') + executable.toLower();
            if (m_reappliedPairs.contains(pairKey)) continue;

            const EnforcementResult result = applyPolicy(policy, executable);
            if (result.status == EnforcementResult::Status::Failed) {
                // Do not remember a hard failure: the next snapshot retries it,
                // which is how a transient firewall initialization failure heals.
                continue;
            }

            m_reappliedPairs.insert(pairKey);
            results.append(result);
        }
    }

    return results;
}

void EnforcementCoordinator::forgetReappliedPolicies()
{
    m_reappliedPairs.clear();
}

// ──────────────────────────────────────────────────────────────────────
//  Emergency restore (NG-026)
//
//  Only policies whose source marks them as the product's own are removed. A
//  user policy, or one whose origin is not recorded, is preserved: deletion is
//  not something to guess at. The throttle channel is asked to take back the
//  limits it applied automatically; the manager reports that outcome through
//  its own signal, because the QoS call runs on the worker thread.
// ──────────────────────────────────────────────────────────────────────
EmergencyRestoreReport EnforcementCoordinator::emergencyRestore()
{
    const QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    const EmergencyRestorePlan plan = buildEmergencyRestorePlan(policies);

    bool storeWritten = true;
    if (!plan.automatic.isEmpty())
        storeWritten = PolicyStore::savePolicies(plan.preserved);

    // The stored policy set changed, so a later group refresh must not assume
    // the previous re-applications are still in place.
    m_reappliedPairs.clear();

    const bool throttleAttached = m_throttle != nullptr;
    const QString throttleNote = throttleAttached
        ? QStringLiteral("Automatic QoS and download limits are being removed by the throttle worker")
        : QStringLiteral("No throttle channel is attached, so no bandwidth limit was touched");

    EmergencyRestoreReport report =
        applyEmergencyRestorePlan(plan, throttleAttached, throttleNote, storeWritten);

    // Ask the throttle worker only after the report is built, so the report says
    // what was requested rather than what is merely intended.
    if (throttleAttached)
        m_throttle->restoreAutoApplied();

    if (report.failed > 0) {
        qWarning().noquote() << "EnforcementCoordinator: emergency restore finished with"
                             << report.failed << "failure(s)";
    }

    emit emergencyRestoreCompleted(report);
    return report;
}

// ──────────────────────────────────────────────────────────────────────
//  Firewall channel
// ──────────────────────────────────────────────────────────────────────
EnforcementResult EnforcementCoordinator::routeToFirewall(const NetworkPolicy &policy,
                                                          const QString &executablePath)
{
    EnforcementResult result;
    result.policyId = policy.id;
    result.executablePath = executablePath;
    result.channels = channelsDescription(plannedChannels(policy));

    if (!m_firewall) {
        result.status = EnforcementResult::Status::Failed;
        result.message = QStringLiteral("No firewall manager is attached, so no rule was created");
        return result;
    }

    if (!m_firewallInitialized) {
        // NetworkWidget initializes its firewall manager in the constructor;
        // reuse that instead of initializing the COM objects a second time.
        m_firewallInitialized = m_firewall->isInitialized() || m_firewall->initialize();
        if (!m_firewallInitialized) {
            result.status = EnforcementResult::Status::Failed;
            result.message = QStringLiteral("Firewall initialization failed: %1")
                                 .arg(m_firewall->lastError());
            result.firewallMessage = result.message;
            return result;
        }
    }

    if (executablePath.isEmpty()) {
        result.status = EnforcementResult::Status::Failed;
        result.message = QStringLiteral(
            "No executable path was resolved, so a path-scoped rule was not created");
        result.firewallMessage = result.message;
        return result;
    }

    const bool wantsBlock = policy.action == NetworkPolicy::Action::Block;
    // The policy id goes into the rule description so reconciliation can tell
    // this rule from one the user created from the Firewall tab.
    const bool ruleCreated = wantsBlock ? m_firewall->blockApp(executablePath, policy.id)
                                        : m_firewall->allowApp(executablePath, policy.id);

    if (ruleCreated) {
        result.status = EnforcementResult::Status::Applied;
        result.message = wantsBlock
            ? QStringLiteral("Blocking rules created for outbound and inbound traffic")
            : QStringLiteral("Allow rules created for outbound and inbound traffic");
    } else {
        result.status = EnforcementResult::Status::Failed;
        result.message = QStringLiteral("The firewall rejected the rule: %1")
                             .arg(m_firewall->lastError());
    }

    result.firewallMessage = result.message;
    return result;
}

// ──────────────────────────────────────────────────────────────────────
//  Throttle channel (QoS upload + WinDivert download)
// ──────────────────────────────────────────────────────────────────────
EnforcementResult EnforcementCoordinator::routeToThrottle(const NetworkPolicy &policy,
                                                          const QString &executablePath)
{
    EnforcementResult result;
    result.policyId = policy.id;
    result.executablePath = executablePath;

    const PolicyChannels channels = plannedChannels(policy);
    result.channels = channelsDescription(channels);

    if (!m_throttle) {
        result.status = EnforcementResult::Status::Failed;
        result.message = QStringLiteral("No throttle worker is attached, so no limit was requested");
        return result;
    }

    if (executablePath.isEmpty()) {
        result.status = EnforcementResult::Status::Failed;
        result.message = QStringLiteral(
            "No executable path was resolved, so no limit was requested");
        return result;
    }

    if (policy.rateBitsPerSecond == 0 && policy.action != NetworkPolicy::Action::Schedule) {
        result.status = EnforcementResult::Status::NotApplied;
        result.message = QStringLiteral("Policy has no rate limit, so there was nothing to throttle");
        return result;
    }

    // Marked automatic only when the product created the policy, so a limit the
    // user asked for is never taken back by emergency restore. The policy id
    // travels with the request so reconciliation can withdraw the limit later.
    m_throttle->applyForPolicy(executablePath, policy.id,
                               policyOrigin(policy) == PolicyOrigin::Automatic);

    result.status = EnforcementResult::Status::Requested;
    if (policy.rateBitsPerSecond > 0 &&
        policy.rateBitsPerSecond != ThrottlePolicyManager::DefaultLimitBitsPerSecond) {
        result.message = QStringLiteral(
            "Requested the default %1 bits/s limit; the policy asks for %2 bits/s, "
            "which this build cannot set")
            .arg(ThrottlePolicyManager::DefaultLimitBitsPerSecond)
            .arg(policy.rateBitsPerSecond);
    } else {
        result.message = QStringLiteral("Limit request queued on the throttle worker");
    }

    if (channels.uploadShaping) result.uploadReason = QStringLiteral("QoS request queued");
    if (channels.downloadShaping)
        result.downloadReason = QStringLiteral("WinDivert shaping request queued");

    return result;
}
