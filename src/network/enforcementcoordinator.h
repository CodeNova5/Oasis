/**
 * @file   enforcementcoordinator.h
 * @brief  EnforcementCoordinator (NG-021): routes a policy to the channel that
 *         can enforce it (Windows Firewall, Windows QoS, WinDivert) and reports
 *         per-channel what actually happened. Emergency restore (NG-026) lives
 *         here too, so the UI has one entry point for taking back the product's
 *         own controls.
 *
 * The coordinator does not create managers. It is given the ones the
 * application already owns, so a result posted by the throttle worker reaches
 * the widget that asked for it, and so a test can run it with no managers at
 * all — no COM, no elevation, no worker thread.
 *
 * @author Codebuff
 */

#pragma once

#include <QObject>
#include <QList>
#include <QSet>
#include <QString>
#include <QStringList>

#include "network/enforcementrestore.h"

struct NetworkPolicy;
class ThrottlePolicyManager;
class FirewallManager;

// ──────────────────────────────────────────────────────────────────────
//  Enforcement result — what one policy's channel reported.
//
//  `Requested` is not `Applied`: QoS policy installation happens on the
//  throttle worker (it shells out to PowerShell), so the coordinator can only
//  report that the request was accepted. The manager's own signal carries the
//  final outcome.
// ──────────────────────────────────────────────────────────────────────
struct EnforcementResult
{
    enum class Status { NotApplied, Requested, Applied, Partial, Failed };

    Status status = Status::NotApplied;
    QString message;          // Human-readable result description
    QString policyId;         // The policy ID this result refers to
    QString executablePath;   // Path the policy was applied to
    QString channels;         // Channels this result covers, e.g. "QoS upload"
    bool    uploadLimited = false;
    bool    downloadLimited = false;
    QString uploadReason;     // Why upload shaping succeeded/fails
    QString downloadReason;   // Why download shaping succeeds/fails
    QString firewallMessage;  // Firewall-specific result detail
};

Q_DECLARE_METATYPE(EnforcementResult)

// ──────────────────────────────────────────────────────────────────────
//  The coordinator.
// ──────────────────────────────────────────────────────────────────────
class EnforcementCoordinator : public QObject
{
    Q_OBJECT
public:
    // No managers: every channel reports `NotApplied` with the reason. This is
    // what the tests use, and it keeps the failure visible instead of pretending
    // a policy was enforced.
    explicit EnforcementCoordinator(QObject *parent = nullptr);

    // The managers the application owns. Either may be null.
    EnforcementCoordinator(ThrottlePolicyManager *throttle, FirewallManager *firewall,
                           QObject *parent = nullptr);
    ~EnforcementCoordinator() override;

    // Apply one policy to one executable path.
    EnforcementResult applyPolicy(const NetworkPolicy &policy, const QString &executablePath);

    // Apply the policies that are enabled, returning one result per policy.
    QList<EnforcementResult> applyAllPolicies(const QList<NetworkPolicy> &policies,
                                              const QString &executablePath);

    // NG-025: a group's live membership changed, which is what a respawned
    // updater or worker looks like once it owns traffic. Re-applies the enabled
    // group-scoped policies (scope "group", targetId == groupId) to the
    // executables running now. A (group, policy, executable) triple is applied
    // once: firewall and shaping controls are keyed by executable path, so a
    // process that exits and comes back at the same path is already covered,
    // while a replacement at a new path is not and gets its own rule. Returns
    // only the results produced for newly applied pairs.
    QList<EnforcementResult> reapplyGroupPolicies(const QString &groupId,
                                                  const QStringList &executablePaths,
                                                  const QList<NetworkPolicy> &policies);

    // Forgets what reapplyGroupPolicies() remembers, so the next snapshot
    // re-applies every pair (used when the policy store was changed wholesale).
    void forgetReappliedPolicies();

    // NG-026: remove the controls the product applied on its own, keep every
    // user-created policy, and report each action with its outcome. Firewall
    // rules are not touched: this build only creates them from the Firewall tab
    // after an explicit user action, so none of them is automatic.
    EmergencyRestoreReport emergencyRestore();

signals:
    void policyApplied(const QString &policyId, const QString &executablePath,
                       const EnforcementResult &result);
    void enforcementComplete(const QString &executablePath,
                             const QList<EnforcementResult> &results);
    void emergencyRestoreCompleted(const EmergencyRestoreReport &report);

private:
    EnforcementResult routeToFirewall(const NetworkPolicy &policy,
                                      const QString &executablePath);
    EnforcementResult routeToThrottle(const NetworkPolicy &policy,
                                      const QString &executablePath);
    static EnforcementResult unenforcedResult(const NetworkPolicy &policy,
                                              const QString &executablePath,
                                              const QString &reason);

    ThrottlePolicyManager *m_throttle = nullptr;
    FirewallManager *m_firewall = nullptr;
    bool m_firewallInitialized = false;
    // "group-id\npolicy-id\nlowercased-path" for every pair already applied.
    QSet<QString> m_reappliedPairs;
};
