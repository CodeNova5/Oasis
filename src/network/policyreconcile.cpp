/**
 * @file   policyreconcile.cpp
 * @brief  Apply a reconciliation plan to the enforcement channels (NG-024).
 *
 * The planning decisions live in policyreconcileplan.cpp so they can be tested
 * without COM; this file only observes and executes. Execution runs on the
 * thread owned by PolicyReconciler, never on the GUI thread.
 *
 * @author Codebuff
 */

#include "policyreconcileservice.h"

#include "firewallmanager.h"
#include "throttlepolicymanager.h"

#include <QDateTime>
#include <QDir>
#include <QMetaObject>
#include <QStringList>
#include <QThread>

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

// ─── Worker ─────────────────────────────────────────────────────────────────

PolicyReconcileWorker::PolicyReconcileWorker(QObject *parent)
    : QObject(parent)
{
}

PolicyReconcileWorker::~PolicyReconcileWorker()
{
    // Runs on the worker thread (the reconciler deletes this object through
    // deleteLater on QThread::finished), so COM is released by the apartment
    // that created it.
    if (m_firewall) {
        m_firewall->shutdown();
        delete m_firewall;
        m_firewall = nullptr;
    }
}

void PolicyReconcileWorker::runAndReport(const QList<NetworkPolicy> &policies,
                                         const QHash<QString, QStringList> &groupPaths,
                                         const PolicyObservation &observed,
                                         const QDateTime &now)
{
    emit finished(runReconciliation(policies, groupPaths, observed, now));
}

ReconciliationReport PolicyReconcileWorker::runReconciliation(
    const QList<NetworkPolicy> &policies,
    const QHash<QString, QStringList> &groupPaths,
    const PolicyObservation &observed,
    const QDateTime &now)
{
    ReconciliationReport report;

    if (!m_firewall) {
        // Constructed here rather than in the reconciler, so the COM apartment
        // belongs to this thread.
        m_firewall = new FirewallManager;
    }

    if (!m_firewall->isInitialized() && !m_firewall->initialize()) {
        ++report.failed;
        report.actions << failureAction(
            QStringLiteral("Firewall initialization failed, so policy state was not verified: %1")
                .arg(m_firewall->lastError()));
        return report;
    }

    PolicyObservation snapshot = observed;
    snapshot.firewallRules.clear();
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
        snapshot.firewallRules << observation;
    }

    report = planPolicyReconciliation(policies, groupPaths, snapshot, now);

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
        case ReconciliationAction::Kind::ReassignThrottle:
        case ReconciliationAction::Kind::RemoveThrottle:
            // Throttle requests belong to the thread that owns the manager.
            // They are executed in deliverReport() and counted there.
            break;
        case ReconciliationAction::Kind::Report:
            break;
        }
    }

    return report;
}

// ─── Executor ───────────────────────────────────────────────────────────────

PolicyReconciler::PolicyReconciler(ThrottlePolicyManager *throttle, QObject *parent)
    : QObject(parent)
    , m_throttle(throttle)
{
    qRegisterMetaType<ReconciliationReport>("ReconciliationReport");

    m_thread = new QThread(this);
    m_thread->setObjectName(QStringLiteral("policy-reconcile"));
    m_worker = new PolicyReconcileWorker;
    m_worker->moveToThread(m_thread);
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_worker, &PolicyReconcileWorker::finished,
            this, &PolicyReconciler::deliverReport, Qt::QueuedConnection);
    m_thread->start();
}

PolicyReconciler::~PolicyReconciler()
{
    if (!m_thread) return;
    // A pass in progress must finish: its COM apartment has to shut down on
    // the thread that opened it. quit() stops any further queued pass.
    m_thread->quit();
    m_thread->wait(15000);
}

void PolicyReconciler::requestReconciliation(
    const QHash<QString, QStringList> &groupPaths)
{
    m_pendingGroupPaths = groupPaths;

    if (m_busy) {
        // One pass is already checking the channels; run once more afterwards
        // so a change made during it is not missed.
        m_rerun = true;
        return;
    }

    if (!m_throttle) {
        ReconciliationReport report;
        ++report.failed;
        report.actions << failureAction(
            QStringLiteral("No enforcement channel is attached; policy state was not verified."));
        emit reconciliationFinished(report);
        return;
    }

    startPass(groupPaths);
}

void PolicyReconciler::startPass(const QHash<QString, QStringList> &groupPaths)
{
    m_busy = true;
    m_rerun = false;

    // The throttle manager's caches are plain members, so they are read on the
    // thread that owns the manager. The firewall half is enumerated on the
    // worker thread.
    PolicyObservation observed;
    for (const QString &path : m_throttle->activePaths())
        observed.throttledPaths.insert(normalizedPath(path));
    for (const QString &path : m_throttle->autoAppliedPaths())
        observed.autoAppliedPaths.insert(normalizedPath(path));
    observed.throttlePolicyIds = m_throttle->policyAttribution();
    observed.downloadLimits = m_throttle->downloadLimits();

    const QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    const QDateTime now = QDateTime::currentDateTime();

    QMetaObject::invokeMethod(m_worker,
        [worker = m_worker, policies, groupPaths, observed, now]() {
            worker->runAndReport(policies, groupPaths, observed, now);
        },
        Qt::QueuedConnection);
}

void PolicyReconciler::deliverReport(const ReconciliationReport &report)
{
    ReconciliationReport finalReport = report;

    // Issue the shaping requests from the thread that owns the throttle
    // manager, then count them like the firewall actions already were.
    if (m_throttle) {
        for (const ReconciliationAction &action : finalReport.actions) {
            switch (action.kind) {
            case ReconciliationAction::Kind::ApplyThrottle:
                // The throttle worker performs the QoS call; this is a request,
                // not a result. The policy id is attached so the limit can be
                // withdrawn later.
                m_throttle->applyForPolicy(action.path, action.policyId, action.automatic);
                ++finalReport.repaired;
                break;
            case ReconciliationAction::Kind::ReassignThrottle:
                if (m_throttle->reassign(action.path, action.policyId, action.automatic))
                    ++finalReport.repaired;
                else
                    ++finalReport.failed;
                break;
            case ReconciliationAction::Kind::RemoveThrottle:
                m_throttle->remove(action.path);
                ++finalReport.removed;
                break;
            default:
                break;
            }
        }
    }

    m_busy = false;
    emit reconciliationFinished(finalReport);

    if (m_rerun) {
        const QHash<QString, QStringList> pending = m_pendingGroupPaths;
        m_rerun = false;
        startPass(pending);
    }
}
