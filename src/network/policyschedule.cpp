/**
 * @file   policyschedule.cpp
 * @brief  Schedule evaluation and activation tracking (NG-023).
 * @author Codebuff
 */

#include "policyschedule.h"

#include <QTime>
#include <QTimer>

namespace {

// 1 = Monday ... 7 = Sunday, matching QDate::dayOfWeek().
int dayIndex(const QString &token)
{
    QString t = token.trimmed().toLower();
    if (t.size() < 3) return -1;
    t = t.left(3);

    static const char *names[] = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"};
    for (int i = 0; i < 7; ++i) {
        if (t == QLatin1String(names[i])) return i + 1;
    }
    return -1;
}

bool dayMatches(int firstDay, int lastDay, int isoDay)
{
    if (firstDay <= lastDay) return isoDay >= firstDay && isoDay <= lastDay;
    return isoDay >= firstDay || isoDay <= lastDay;  // "Fri-Mon" wraps the week
}

// "Mon", "Mon-Fri", "Fri-Mon", or a comma-separated list of those.
bool daySpecMatches(const QString &text, int isoDay)
{
    const QStringList parts = text.split(QLatin1Char(','), Qt::SkipEmptyParts);
    if (parts.isEmpty()) return false;

    for (const QString &part : parts) {
        const QString spec = part.trimmed();
        const int dash = spec.indexOf(QLatin1Char('-'));
        if (dash > 0) {
            const int first = dayIndex(spec.left(dash));
            const int last = dayIndex(spec.mid(dash + 1));
            if (first < 0 || last < 0) return false;
            if (dayMatches(first, last, isoDay)) return true;
        } else {
            const int single = dayIndex(spec);
            if (single < 0) return false;
            if (single == isoDay) return true;
        }
    }
    return false;
}

QTime parseClockTime(const QString &text)
{
    const QString value = text.trimmed();
    QTime time = QTime::fromString(value, QStringLiteral("H:mm"));
    if (!time.isValid()) time = QTime::fromString(value, QStringLiteral("hh:mm"));
    return time;
}

bool parseWindow(const QString &text, int *startMs, int *endMs)
{
    const int dash = text.indexOf(QLatin1Char('-'));
    if (dash <= 0) return false;

    const QTime start = parseClockTime(text.left(dash));
    const QTime end = parseClockTime(text.mid(dash + 1));
    if (!start.isValid() || !end.isValid() || start == end) return false;

    *startMs = start.msecsSinceStartOfDay();
    *endMs = end.msecsSinceStartOfDay();
    return true;
}

enum class ScheduleMatch { Active, Inactive, Unsupported };

ScheduleMatch matchSchedule(const QString &schedule, const QDateTime &now)
{
    const QString spec = schedule.trimmed().toLower();
    if (spec.isEmpty() || spec == QLatin1String("always") || spec == QLatin1String("*"))
        return ScheduleMatch::Active;

    QString daySpec;
    QString window;
    if (spec == QLatin1String("work-hours")) {
        daySpec = QStringLiteral("mon-fri");
        window = QStringLiteral("09:00-17:00");
    } else if (spec == QLatin1String("overnight")) {
        daySpec = QStringLiteral("*");
        window = QStringLiteral("22:00-06:00");
    } else {
        const QStringList parts = spec.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (parts.size() == 1) {
            window = parts.at(0);
        } else if (parts.size() == 2) {
            daySpec = parts.at(0);
            window = parts.at(1);
        } else {
            return ScheduleMatch::Unsupported;
        }
    }

    int startMs = 0;
    int endMs = 0;
    if (!parseWindow(window, &startMs, &endMs)) return ScheduleMatch::Unsupported;

    const QDateTime local = now.toLocalTime();
    const int nowMs = local.time().msecsSinceStartOfDay();
    const bool wraps = endMs <= startMs;

    if (!daySpec.isEmpty() && daySpec != QLatin1String("*")) {
        // A window that crosses midnight belongs to the day it started: at
        // 01:00 on Saturday, an "Fri 22:00-06:00" window is still Friday's.
        const int effectiveDay = (wraps && nowMs < endMs)
            ? local.date().addDays(-1).dayOfWeek()
            : local.date().dayOfWeek();
        if (!daySpecMatches(daySpec, effectiveDay)) return ScheduleMatch::Inactive;
    }

    if (!wraps) {
        return (nowMs >= startMs && nowMs < endMs) ? ScheduleMatch::Active
                                                   : ScheduleMatch::Inactive;
    }
    return (nowMs >= startMs || nowMs < endMs) ? ScheduleMatch::Active
                                               : ScheduleMatch::Inactive;
}

QString activationReason(const NetworkPolicy &policy, PolicyActivationState state)
{
    switch (state) {
    case PolicyActivationState::Active:
        if (policy.expiration.isValid()) {
            return QStringLiteral("In force until %1")
                .arg(policy.expiration.toString(Qt::ISODate));
        }
        return QStringLiteral("In force");
    case PolicyActivationState::Inactive:
        return QStringLiteral("Outside the scheduled window \"%1\"").arg(policy.schedule);
    case PolicyActivationState::Expired:
        return QStringLiteral("Expired at %1").arg(policy.expiration.toString(Qt::ISODate));
    case PolicyActivationState::Disabled:
        return QStringLiteral("Policy is disabled");
    case PolicyActivationState::Unsupported:
        return QStringLiteral("Schedule \"%1\" is not supported").arg(policy.schedule);
    }
    return QString();
}

} // namespace

// ─── Activation ─────────────────────────────────────────────────────────────

QString policyActivationName(PolicyActivationState state)
{
    switch (state) {
    case PolicyActivationState::Active: return QStringLiteral("active");
    case PolicyActivationState::Inactive: return QStringLiteral("inactive");
    case PolicyActivationState::Expired: return QStringLiteral("expired");
    case PolicyActivationState::Disabled: return QStringLiteral("disabled");
    case PolicyActivationState::Unsupported: return QStringLiteral("unsupported");
    }
    return QStringLiteral("unknown");
}

bool scheduleWindowActive(const QString &schedule, const QDateTime &now)
{
    return matchSchedule(schedule, now) == ScheduleMatch::Active;
}

bool scheduleIsSupported(const QString &schedule)
{
    return matchSchedule(schedule, QDateTime::currentDateTime()) != ScheduleMatch::Unsupported;
}

PolicyActivationState policyActivationAt(const NetworkPolicy &policy, const QDateTime &now)
{
    if (!policy.enabled) return PolicyActivationState::Disabled;

    if (policy.expiration.isValid() && now >= policy.expiration)
        return PolicyActivationState::Expired;

    if (policy.scheduleType == NetworkPolicy::ScheduleType::Recurring ||
        policy.scheduleType == NetworkPolicy::ScheduleType::Both) {
        switch (matchSchedule(policy.schedule, now)) {
        case ScheduleMatch::Active: return PolicyActivationState::Active;
        case ScheduleMatch::Inactive: return PolicyActivationState::Inactive;
        case ScheduleMatch::Unsupported: return PolicyActivationState::Unsupported;
        }
    }

    return PolicyActivationState::Active;
}

QString humanizedPolicyDuration(qint64 seconds)
{
    const qint64 secs = seconds < 0 ? -seconds : seconds;
    if (secs >= 86400) {
        const qint64 days = secs / 86400;
        const qint64 hours = (secs % 86400) / 3600;
        return hours > 0
            ? QStringLiteral("%1 d %2 h").arg(days).arg(hours)
            : QStringLiteral("%1 d").arg(days);
    }
    if (secs >= 3600) {
        const qint64 hours = secs / 3600;
        const qint64 minutes = (secs % 3600) / 60;
        return minutes > 0
            ? QStringLiteral("%1 h %2 min").arg(hours).arg(minutes)
            : QStringLiteral("%1 h").arg(hours);
    }
    if (secs >= 60)
        return QStringLiteral("%1 min").arg(secs / 60);
    return QStringLiteral("%1 s").arg(secs);
}

QString policyExpirationSummary(const QDateTime &expiration, const QDateTime &now)
{
    if (!expiration.isValid()) return QStringLiteral("No expiration");

    const QString stamp = expiration.toString(QStringLiteral("yyyy-MM-dd HH:mm"));
    const qint64 secs = now.secsTo(expiration);
    if (secs <= 0) {
        return QStringLiteral("Expired %1 ago (%2)")
            .arg(humanizedPolicyDuration(-secs), stamp);
    }
    return QStringLiteral("Expires in %1 (%2)")
        .arg(humanizedPolicyDuration(secs), stamp);
}

// ─── Scheduler ──────────────────────────────────────────────────────────────

PolicyScheduler::PolicyScheduler(QObject *parent)
    : QObject(parent)
    , m_timer(new QTimer(this))
{
    m_timer->setInterval(kDefaultIntervalMs);
    connect(m_timer, &QTimer::timeout, this, &PolicyScheduler::evaluateNow);
}

PolicyScheduler::~PolicyScheduler() = default;

void PolicyScheduler::setIntervalMs(int intervalMs)
{
    if (intervalMs <= 0 || intervalMs == m_timer->interval()) return;
    m_timer->setInterval(intervalMs);
    if (m_timer->isActive()) m_timer->start();
}

int PolicyScheduler::intervalMs() const
{
    return m_timer->interval();
}

void PolicyScheduler::start()
{
    if (m_timer->isActive()) return;
    evaluateNow();
    m_timer->start();
}

void PolicyScheduler::stop()
{
    m_timer->stop();
}

bool PolicyScheduler::isRunning() const
{
    return m_timer->isActive();
}

QList<PolicyActivation> PolicyScheduler::evaluateNow()
{
    const QDateTime now = QDateTime::currentDateTime();
    const QList<NetworkPolicy> policies = PolicyStore::loadPolicies();

    QList<PolicyActivation> current;
    current.reserve(policies.size());
    QSet<QString> seen;

    int active = 0;
    int inactive = 0;
    int expired = 0;
    int disabled = 0;
    int unsupported = 0;

    for (const NetworkPolicy &policy : policies) {
        PolicyActivation activation;
        activation.policy = policy;
        activation.state = policyActivationAt(policy, now);
        activation.reason = activationReason(policy, activation.state);
        current.append(activation);

        switch (activation.state) {
        case PolicyActivationState::Active: ++active; break;
        case PolicyActivationState::Inactive: ++inactive; break;
        case PolicyActivationState::Expired: ++expired; break;
        case PolicyActivationState::Disabled: ++disabled; break;
        case PolicyActivationState::Unsupported: ++unsupported; break;
        }

        if (policy.id.isEmpty()) continue;
        seen.insert(policy.id);

        const auto known = m_states.constFind(policy.id);
        if (known != m_states.constEnd() && known->state == activation.state) continue;

        m_states.insert(policy.id, activation);
        emit activationChanged(activation.policy, activation.state, activation.reason);
    }

    // A policy removed from the store stops being tracked, so re-adding it
    // later is treated as a fresh decision rather than a no-op.
    for (auto it = m_states.begin(); it != m_states.end();) {
        if (seen.contains(it.key())) {
            ++it;
        } else {
            it = m_states.erase(it);
        }
    }

    m_snapshot = current;
    emit evaluationFinished(active, inactive, expired, disabled, unsupported);
    return current;
}
