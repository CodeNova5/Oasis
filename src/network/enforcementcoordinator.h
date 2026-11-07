/**

  * @file   enforcementcoordinator.h
  * @brief  EnforcementCoordinator (NG-021): coordinates Windows Firewall,
  *         Windows QoS, and WinDivert without duplicating policy decisions
  *         in UI code.  One policy produces a complete per-channel result;
  *         partial success is represented explicitly; all requests are auditable.
  * @author Codebuff
  */

#pragma once

#include <QObject>
#include <QList>
#include <QSettings>

struct NetworkPolicy;
class PolicyStore;
class ThrottlePolicyManager;
class FirewallManager;

// ──────────────────────────────────────────────────────────────────────
//  Enforcement result — what happened when we tried to apply a policy.
// ──────────────────────────────────────────────────────────────────────
struct EnforcementResult
{
    enum class Status { NotApplied, Applied, Partial, Failed }::Status;
    Status status = Status::NotApplied;
    QString message;          // Human-readable result description
    QString policyId;         // The policy ID this result refers to
    QString executablePath;   // Path the policy was applied to
    bool   uploadLimited = false;
    bool   downloadLimited = false;
    QString uploadReason;     // Why upload shaping succeeded/fails
    QString downloadReason;   // Why download shaping succeeds/fails
    QString firewallMessage;  // Firewall-specific result detail
};

Q_DECLARE_METATYPE(EnforcementResult)

// ──────────────────────────────────────────────────────────────────────
//  The coordinator itself.  All methods are static so the UI can call
//  it without owning a long-lived instance; it delegates to the concrete
//  managers (ThrottlePolicyManager, FirewallManager) and logs every
//  action as an AuditEvent.
// ──────────────────────────────────────────────────────────────────────
class EnforcementCoordinator : public QObject
{
    Q_OBJECT
public:
    explicit EnforcementCoordinator(QObject *parent = nullptr);
    ~EnforcementCoordinator() override;

    // Apply a single policy to the given executable path.
    // Tries Firewall first, then QoS/WinDivert, recording partial results.
    static void applyPolicy(const NetworkPolicy &policy, const QString &executablePath);

    // Remove a previously applied policy from the given executable path.
    static void removePolicy(const NetworkPolicy &policy, const QString &executablePath);

    // Apply all active policies for the given executable.
    // Returns a list of per-channel EnforcementResult one per active policy.
    static QList<EnforcementResult> applyAllPolicies(const QList<NetworkPolicy> &policies,
                                                     const QString &executablePath);

    // Load policies from PolicyStore and apply them for the given executable.
    static void enforceForExecutable(const QString &executablePath);

signals:
    // One policy was applied/removed; result is auditable.
    void policyApplied(const QString &policyId, const QString &executablePath,
                       const EnforcementResult &result);
    void policyRemoved(const QString &policyId, const QString &executablePath,
                       const EnforcementResult &result);
    // Batch completion — useful for UI refresh.
    void enforcementComplete(const QString &executablePath,
                             const QList<EnforcementResult> &results);

private:
    // Helper: apply via Windows Firewall (delegates to FirewallManager)
    static EnforcementResult applyFirewall(const NetworkPolicy &policy,
                                           const QString &executablePath);

    // Helper: apply via Windows QoS / WinDivert (delegates to ThrottlePolicyManager)
    static EnforcementResult applyThrottle(const NetworkPolicy &policy,
                                           const QString &executablePath);

    // Log the enforcement action as an AuditEvent (never throws).
    static void logEnforcement(const NetworkPolicy &policy, const EnforcementResult &result,
                               const QString &action);

    // Shared instances — created lazily
    static ThrottlePolicyManager *m_throttleManager;
    static FirewallManager *m_firewallManager;
};