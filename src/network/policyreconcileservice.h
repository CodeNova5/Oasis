/**
 * @file   policyreconcileservice.h
 * @brief  Run policy reconciliation off the GUI thread (NG-024).
 *
 * Enumerating and repairing Windows Firewall rules blocks for seconds: the COM
 * rule collection is walked in full, and the netsh fallbacks wait on a child
 * process. This service moves that work to its own thread so activating,
 * expiring, or verifying a policy never freezes the window.
 *
 * The planning and report types stay in policyreconcile.h, which has no COM or
 * threading dependency and can be linked by the test harness on its own.
 *
 * @author Codebuff
 */

#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QObject>
#include <QStringList>

#include "network/policy.h"
#include "network/policyreconcile.h"

class FirewallManager;
class QThread;
class ThrottlePolicyManager;

// ─── Worker ─────────────────────────────────────────────────────────────────
// Creates its own FirewallManager on the worker thread: a COM object belongs to
// the apartment that created it and must not be called from another thread.
class PolicyReconcileWorker : public QObject
{
    Q_OBJECT
public:
    explicit PolicyReconcileWorker(QObject *parent = nullptr);
    ~PolicyReconcileWorker() override;

    // Runs on the worker thread. `observed` carries the throttle state gathered
    // by the owner of ThrottlePolicyManager; the worker only fills in the
    // firewall half and executes the firewall actions.
    void runAndReport(const QList<NetworkPolicy> &policies,
                      const QHash<QString, QStringList> &groupPaths,
                      const PolicyObservation &observed,
                      const QDateTime &now);

signals:
    void finished(const ReconciliationReport &report);

private:
    ReconciliationReport runReconciliation(const QList<NetworkPolicy> &policies,
                                           const QHash<QString, QStringList> &groupPaths,
                                           const PolicyObservation &observed,
                                           const QDateTime &now);

    FirewallManager *m_firewall = nullptr;
};

// ─── Executor ───────────────────────────────────────────────────────────────
class PolicyReconciler : public QObject
{
    Q_OBJECT
public:
    explicit PolicyReconciler(ThrottlePolicyManager *throttle, QObject *parent = nullptr);
    ~PolicyReconciler() override;

    // Queues one reconciliation and returns immediately. The report arrives
    // through reconciliationFinished(). A request made while a pass is running
    // is remembered and run once afterwards, so a burst of state changes still
    // ends by verifying the latest state.
    void requestReconciliation(const QHash<QString, QStringList> &groupPaths);
    bool isBusy() const { return m_busy; }

signals:
    void reconciliationFinished(const ReconciliationReport &report);

private:
    void startPass(const QHash<QString, QStringList> &groupPaths);
    void deliverReport(const ReconciliationReport &report);

    ThrottlePolicyManager *m_throttle = nullptr;
    PolicyReconcileWorker *m_worker = nullptr;
    QThread *m_thread = nullptr;
    bool m_busy = false;
    bool m_rerun = false;
    QHash<QString, QStringList> m_pendingGroupPaths;
};
