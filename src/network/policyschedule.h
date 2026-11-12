/**
 * @file   policyschedule.h
 * @brief  When a stored policy is currently in force (NG-023).
 *
 * Activation is derived, never persisted: a policy's stored `enabled` flag is
 * the user's switch, while its expiration and recurring window decide whether
 * the policy is in force right now. That means a boundary that passed while the
 * application was closed needs no special recovery path — evaluating once at
 * startup produces the correct state instead of waiting for the next boundary.
 *
 * Recurring windows are evaluated in local time. The supported forms are:
 *
 *   "" or "always" or "*"        always in force
 *   "work-hours"                 Monday-Friday, 09:00-17:00
 *   "overnight"                  22:00-06:00 every day (crosses midnight)
 *   "HH:MM-HH:MM"                every day, may cross midnight
 *   "<days> HH:MM-HH:MM"         a single day, a list ("Mon,Wed,Fri"), or a
 *                                range ("Mon-Fri", including a wrap such as
 *                                "Fri-Mon"); day names are case-insensitive and
 *                                may be three-letter or full
 *
 * An unrecognised window is reported as `Unsupported` rather than silently
 * treated as always-on or always-off, so a typo cannot change enforcement
 * without the caller seeing why. Network-profile conditions (for example a
 * metered connection) are not modelled yet; a schedule that asks for them is
 * `Unsupported`.
 *
 * @author Codebuff
 */

#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QMetaType>
#include <QObject>
#include <QSet>
#include <QString>

#include "network/policy.h"

class QTimer;

// ─── Activation ─────────────────────────────────────────────────────────────
enum class PolicyActivationState {
    Active,       // in force now
    Inactive,     // enabled, but outside its recurring window
    Expired,      // its expiration has passed
    Disabled,     // the user's switch is off
    Unsupported   // the schedule cannot be understood
};

QString policyActivationName(PolicyActivationState state);

// True only when `schedule` is understood and `now` is inside its window.
bool scheduleWindowActive(const QString &schedule, const QDateTime &now);

// True when the window can be parsed. Empty means "no recurring window" and
// is supported, so an editor can validate optional input without evaluating it.
bool scheduleIsSupported(const QString &schedule);

PolicyActivationState policyActivationAt(const NetworkPolicy &policy, const QDateTime &now);

// "45 s", "5 min", "2 h 10 min", "1 d 3 h" — coarse on purpose: a policy's
// remaining lifetime does not need to read like a stopwatch.
QString humanizedPolicyDuration(qint64 seconds);

// How long a temporary policy has left, with the absolute time so the reader
// can check it against a calendar: "Expires in 3 h 12 min (2026-11-12 18:00)",
// "Expired 5 min ago (...)", or "No expiration" when the policy is persistent.
QString policyExpirationSummary(const QDateTime &expiration, const QDateTime &now);

struct PolicyActivation
{
    NetworkPolicy policy;
    PolicyActivationState state = PolicyActivationState::Active;
    QString reason;             // human-readable reason for the state
};

Q_DECLARE_METATYPE(PolicyActivationState)
Q_DECLARE_METATYPE(PolicyActivation)

// ─── Scheduler ──────────────────────────────────────────────────────────────
// Re-evaluates the stored policies on a timer. The first evaluation happens
// when start() is called, so a policy that expired or left its window while the
// application was not running is reported straight away. `activationChanged` is
// emitted only when a policy's state actually moved (and for every policy on
// the first evaluation, because nothing was known before it).
class PolicyScheduler : public QObject
{
    Q_OBJECT
public:
    static constexpr int kDefaultIntervalMs = 15000;

    explicit PolicyScheduler(QObject *parent = nullptr);
    ~PolicyScheduler() override;

    void setIntervalMs(int intervalMs);
    int intervalMs() const;

    // Evaluates once, then keeps evaluating every interval.
    void start();
    void stop();
    bool isRunning() const;

    // Evaluates the stored policies at the current time, emits the changes, and
    // returns the new snapshot. Safe to call while the timer is running.
    QList<PolicyActivation> evaluateNow();

    // The most recent evaluation, in store order.
    const QList<PolicyActivation> &snapshot() const { return m_snapshot; }

signals:
    void activationChanged(const NetworkPolicy &policy, PolicyActivationState state,
                           const QString &reason);
    void evaluationFinished(int active, int inactive, int expired, int disabled,
                            int unsupported);

private:
    QTimer *m_timer = nullptr;
    QHash<QString, PolicyActivation> m_states;
    QList<PolicyActivation> m_snapshot;
};
