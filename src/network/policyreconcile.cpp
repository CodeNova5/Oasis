/**
 * @file   policyreconcile.cpp
 * @brief  Apply a reconciliation plan to the enforcement channels (NG-024).
 *
 * The planning decisions live in policyreconcileplan.cpp so they can be tested
 * without COM; this file only observes and executes.
 *
 * @author Codebuff
 */

#include "policyreconcile.h"

#include "firewallmanager.h"
#include "throttlepolicymanager.h"

#include <QDateTime>
#include <QDir>
#include <QStringList>

namespace {

QString normalizedPath(const QString &path)
{
    const QString trimmed = path.trimmed();
    if (trimmed.isEmpty()) return QString();
    return QDir::cleanPath(QDir::toNativeSeparators(trimmed)).toLower();
}

ReconciliationAction failureAction(const QString &message)
{
    ReconciliationAction action;
    action.kind = ReconciliationAction::Kind::Report;
    action.message = message;
    return action;
}

} // namespace

PolicyReconciler::PolicyReconciler(ThrottlePolicyManager *throttle,
                                   FirewallManager *firewall, QObject *parent)
    : QObject(parent)
    , m_throttle(throttle)
    , m_firewall(firewall)
{
}

ReconciliationReport PolicyReconciler::reconcileNow(
    const QHash<QString, QStringList> &groupPaths)
{
    ReconciliationReport report;

    if (!m_firewall || !m_throttle) {
        ++report.failed;
        report.actions << failureAction(
            QStringLiteral("No enforcement channel is attached; policy state was not verified."));
        emit reconciliationFinished(report);
        return report;
    }

    if (!m_firewall->isInitialized() && !m_firewall->initialize()) {
        ++report.failed;
        report.actions << failureAction(
            QStringLiteral("Firewall initialization failed, so policy state was not verified: %1")
                .arg(m_firewall->lastError()));
        emit reconciliationFinished(report);
        return report;
    }

    PolicyObservation observed;
    for (const FirewallRule &rule : m_firewall->listRules(true)) {
        const QString path = rule.realAppPath.isEmpty() ? rule.appPath : rule.realAppPath;
        if (path.trimmed().isEmpty()) continue;  // not an application rule

        FirewallObservation observation;
        observation.name = rule.name;
        observation.path = path;
        observation.block = rule.action == NET_FW_ACTION_BLOCK;
        observation.inbound = rule.direction == NET_FW_RULE_DIR_IN;
        observation.enabled = rule.enabled;
        observation.policyId = reconciledPolicyId(rule.description);
        observed.firewallRules << observation;
    }

    for (const QString &path : m_throttle->activePaths())
        observed.throttledPaths.insert(normalizedPath(path));
    for (const QString &path : m_throttle->autoAppliedPaths())
        observed.autoAppliedPaths.insert(normalizedPath(path));
    observed.downloadLimits = m_throttle->downloadLimits();

    report = planPolicyReconciliation(PolicyStore::loadPolicies(), groupPaths, observed,
                                      QDateTime::currentDateTime());

    for (const ReconciliationAction &action : report.actions) {
        switch (action.kind) {
        case ReconciliationAction::Kind::CreateFirewallRule: {
            const bool created = action.block
                ? m_firewall->blockApp(action.path, action.policyId)
                : m_firewall->allowApp(action.path, action.policyId);
            if (created) ++report.repaired; else ++report.failed;
            break;
        }
        case ReconciliationAction::Kind::RemoveFirewallRule:
            if (m_firewall->removeRuleByName(action.ruleName)) ++report.removed;
            else ++report.failed;
            break;
        case ReconciliationAction::Kind::ApplyThrottle:
            // The worker performs the QoS call; this is a request, not a result.
            m_throttle->apply(action.path, action.automatic);
            ++report.repaired;
            break;
        case ReconciliationAction::Kind::RemoveThrottle:
            m_throttle->remove(action.path);
            ++report.removed;
            break;
        case ReconciliationAction::Kind::Report:
            break;
        }
    }

    emit reconciliationFinished(report);
    return report;
}
