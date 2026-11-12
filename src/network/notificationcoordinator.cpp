/**
 * @file   notificationcoordinator.cpp
 * @brief  Notification deduplication, priorities, suppression, and routing
 *         decisions (NG-051).
 * @author Codebuff
 */

#include "notificationcoordinator.h"

#include <QDateTime>

namespace {
constexpr int kDefaultWindowMs = 60 * 1000;
} // namespace

QString AppNotification::fallbackKey(const QString &title, const QString &message)
{
    const QString composed = title.trimmed() + QLatin1Char('\n') + message.trimmed();
    return composed.trimmed().isEmpty() ? QStringLiteral("notification") : composed;
}

QString AppNotification::effectiveKey() const
{
    const QString trimmed = key.trimmed();
    return trimmed.isEmpty() ? fallbackKey(title, message) : trimmed;
}

NotificationCoordinator::NotificationCoordinator(const NotificationSettings &settings)
{
    setSettings(settings);
}

NotificationSettings NotificationCoordinator::settings() const
{
    return m_settings;
}

NotificationSettings NotificationCoordinator::sanitized(const NotificationSettings &settings)
{
    NotificationSettings clean = settings;
    clean.cooldownMs = qMax(0, clean.cooldownMs);
    if (clean.windowMs <= 0) clean.windowMs = kDefaultWindowMs;
    clean.maxDeliveriesPerWindow = qMax(1, clean.maxDeliveriesPerWindow);
    return clean;
}

void NotificationCoordinator::setSettings(const NotificationSettings &settings)
{
    m_settings = sanitized(settings);
    // Existing timestamps were measured against the old window, so keeping
    // them after a change would let a stale delivery block a new one.
    m_deliveryTimes.clear();
    for (auto it = m_keys.begin(); it != m_keys.end(); ++it) {
        it->lastDeliveredMs = -1;
        it->suppressed = 0;
    }
}

NotificationDecision NotificationCoordinator::submit(const AppNotification &notification,
                                                      qint64 nowMs)
{
    NotificationDecision decision;
    const QString key = notification.effectiveKey();
    KeyState &state = m_keys[key];

    if (notification.priority == NotificationPriority::Critical) {
        // Critical failures are the one thing a rate limit must never hide.
        // Any folded repeats of the same key are still mentioned, so a burst
        // of failures becomes "failed again (N earlier)" rather than silence.
        decision.deliver = true;
        decision.suppressedCount = state.suppressed;
        decision.reason = QStringLiteral("delivered");
        state.lastDeliveredMs = nowMs;
        state.suppressed = 0;
        return decision;
    }

    pruneDeliveryTimes(nowMs);

    const qint64 elapsed = nowMs - state.lastDeliveredMs;
    if (state.lastDeliveredMs >= 0 && elapsed < m_settings.cooldownMs) {
        ++state.suppressed;
        decision.reason = QStringLiteral("duplicate");
        return decision;
    }

    if (m_deliveryTimes.size() >= m_settings.maxDeliveriesPerWindow) {
        ++state.suppressed;
        decision.rateLimited = true;
        decision.reason = QStringLiteral("rate-limited");
        return decision;
    }

    decision.deliver = true;
    decision.suppressedCount = state.suppressed;
    decision.reason = QStringLiteral("delivered");
    state.lastDeliveredMs = nowMs;
    state.suppressed = 0;
    m_deliveryTimes.append(nowMs);
    return decision;
}

int NotificationCoordinator::suppressedCount(const QString &key) const
{
    const auto it = m_keys.constFind(key);
    return it == m_keys.constEnd() ? 0 : it->suppressed;
}

void NotificationCoordinator::reset()
{
    m_keys.clear();
    m_deliveryTimes.clear();
}

void NotificationCoordinator::pruneDeliveryTimes(qint64 nowMs)
{
    const qint64 cutoff = nowMs - m_settings.windowMs;
    while (!m_deliveryTimes.isEmpty() && m_deliveryTimes.first() <= cutoff)
        m_deliveryTimes.removeFirst();
}
