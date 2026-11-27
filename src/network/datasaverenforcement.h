/**
 * @file    datasaverenforcement.h
 * @brief   Apply and withdraw automation-owned enforcement for Data Saver
 *          decisions (DS-009).
 *
 * The enforcer is the ownership layer between DS-008's validated decision and
 * the shipped enforcement channels. It never invents a channel: throttle
 * requests go to the throttle manager and block requests to the firewall
 * manager, using `EnforcementResult` so outcomes read the same as the policy
 * path. The enforcer only records and withdraws the controls it created, and
 * every control is keyed by its own `dsauto_` policy id and by the executable
 * path the channel is keyed by.
 *
 * Ownership rules:
 *  - only automatic origins (profile, cache, fallback) create controls; a
 *    pinned or session decision wins, so any automatic control for the path is
 *    withdrawn instead;
 *  - a throttle is requested at the canonical 50 KiB/s rate (higher automatic
 *    rates are capped and reported, lower ones are refused);
 *  - each control carries its `ThrottleUntil` basis and an optional absolute
 *    lease, and `withdrawAll` / `withdrawUntil` / `expire` remove exactly the
 *    matching controls;
 *  - a channel that cannot act reports `Failed`, and a failed apply does not
 *    leave a control that claims to be enforced.
 *
 * `DataSaverEnforcementBackend` is the seam that keeps the enforcer testable
 * with no COM, elevation, worker thread, or WinDivert. The shipped adapter
 * (`datasaverenforcementbackend.h`) wraps the real managers.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>

#include "datasaverdecision.h"
#include "enforcementcoordinator.h"

namespace DataSaverEnforcement {

/// Normalized path used as the ownership key, matching how the channels key
/// their own state.
QString normalizedPath(const QString &executablePath);

/// Stable Data Saver policy id for one executable path. Deterministic so a
/// re-apply attributes to the same control instead of stacking a second one.
QString automaticPolicyId(const QString &executablePath);

/// True only when the throttle manager attributes the path to this exact
/// automatic policy. A limit the user applied by hand has no attribution, so
/// it is never Data Saver's to withdraw.
bool throttleBelongsTo(const QString &attributedPolicyId, const QString &policyId);

/// True only when a firewall rule description names this automatic policy.
/// Rules created from the Firewall tab keep the generic description and are
/// therefore preserved.
bool firewallRuleBelongsTo(const QString &ruleDescription, const QString &policyId);
} // namespace DataSaverEnforcement

/// One request to enforce a decision for one executable.
struct ControlLease
{
    QString executablePath;      // resolved path; enforcement channels are path-keyed
    QDateTime expiresAt;         // invalid = withdrawn by until/withdrawAll instead
    QString reason;              // bounded explanation carried into the control
};

/// One automatic control the enforcer owns. It is not a stored policy; it is
/// the in-memory record of what Data Saver asked a channel to do.
struct DataSaverControl
{
    QString policyId;            // dsauto_ + 12 lower-case hex
    QString executablePath;      // normalized
    QString observationId;
    QString decisionId;
    NetworkPolicy::Action action = NetworkPolicy::Action::NoAction;
    DecisionOrigin origin = DecisionOrigin::Fallback;
    int tier = 0;
    quint64 rateBitsPerSecond = 0;
    NetworkDirection direction = NetworkDirection::Download;
    ThrottleUntil until = ThrottleUntil::MilestoneNext;
    QDateTime requestedAt;
    QDateTime expiresAt;
    EnforcementResult::Status status = EnforcementResult::Status::NotApplied;
    QString channels;
    QString reason;
};

struct EnforcementOutcome
{
    bool evaluated = false;      // a decision was routed
    bool changed = false;        // a control was added, replaced, or removed
    QString policyId;
    QString executablePath;
    NetworkPolicy::Action action = NetworkPolicy::Action::NoAction;
    EnforcementResult::Status status = EnforcementResult::Status::NotApplied;
    QString message;
    QString channels;
    quint64 rateBitsPerSecond = 0;
    NetworkDirection direction = NetworkDirection::Download;

    bool ok() const
    {
        return status == EnforcementResult::Status::Applied
               || status == EnforcementResult::Status::Requested
               || status == EnforcementResult::Status::Partial;
    }
    bool failed() const { return status == EnforcementResult::Status::Failed; }
};

/// The channel seam. The shipped adapter wraps the throttle and firewall
/// managers; tests supply a mock. Every method reports what the channel
/// actually did, never what it was asked to do.
class DataSaverEnforcementBackend
{
public:
    virtual ~DataSaverEnforcementBackend() = default;

    /// True when at least one channel can accept a request.
    virtual bool isAvailable() const = 0;

    virtual EnforcementResult applyThrottle(const QString &executablePath,
                                            const QString &policyId,
                                            quint64 rateBitsPerSecond,
                                            NetworkDirection direction) = 0;
    virtual EnforcementResult withdrawThrottle(const QString &executablePath,
                                               const QString &policyId) = 0;
    virtual EnforcementResult applyBlock(const QString &executablePath,
                                         const QString &policyId) = 0;
    virtual EnforcementResult withdrawBlock(const QString &executablePath,
                                            const QString &policyId) = 0;
};

class DataSaverEnforcer
{
public:
    DataSaverEnforcer() = default;
    explicit DataSaverEnforcer(DataSaverEnforcementBackend *backend);

    void setBackend(DataSaverEnforcementBackend *backend) { m_backend = backend; }
    DataSaverEnforcementBackend *backend() const { return m_backend; }

    /// True when a throttle could be requested. The resolver uses this for
    /// `gentleThrottleAvailable`.
    bool canThrottle() const;

    /// Routes one committed decision. A throttle/block becomes a control; an
    /// allow/notice withdraws the control for that path; a user-owned decision
    /// withdraws the automatic control so it cannot mask the user's rule.
    EnforcementOutcome apply(const PolicyDecision &decision, const ControlLease &lease,
                             const QDateTime &now = QDateTime());

    /// Withdraws the control for one path. Only a control this enforcer owns is
    /// touched. A failed withdrawal keeps the record so it can be retried.
    EnforcementOutcome withdraw(const QString &executablePath, const QString &reason);

    /// Withdraws every Data Saver-owned control (Off, emergency restore, exit).
    QList<EnforcementOutcome> withdrawAll(const QString &reason);

    /// Withdraws the controls whose lease basis is `until` (for example a
    /// foreground change or a new milestone for the same path).
    QList<EnforcementOutcome> withdrawUntil(ThrottleUntil until, const QString &reason);

    /// Withdraws controls whose absolute lease has elapsed.
    QList<EnforcementOutcome> expire(const QDateTime &now = QDateTime());

    QList<DataSaverControl> controls() const;
    DataSaverControl controlFor(const QString &executablePath) const;
    bool owns(const QString &executablePath) const;
    int count() const { return static_cast<int>(m_controls.size()); }

private:
    EnforcementOutcome applyThrottleControl(const PolicyDecision &decision,
                                            const ControlLease &lease,
                                            const QDateTime &now);
    EnforcementOutcome applyBlockControl(const PolicyDecision &decision,
                                         const ControlLease &lease,
                                         const QDateTime &now);
    EnforcementOutcome backendUnavailable(const PolicyDecision &decision,
                                          const ControlLease &lease);
    EnforcementOutcome outcomeForControl(const DataSaverControl &control,
                                         const EnforcementResult &result);
    static EnforcementResult failedResult(const QString &message);

    DataSaverEnforcementBackend *m_backend = nullptr;
    QHash<QString, DataSaverControl> m_controls; // normalized path -> control
};
