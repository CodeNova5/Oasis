/**
 * @file   notificationcoordinator.h
 * @brief  Deduplicates, prioritizes, suppresses, and routes user notifications
 *         to the tray and the application UI (NG-051).
 * @author Codebuff
 *
 * Packet activity is bursty: the same executable can cross the Data Saver
 * threshold, fail an enforcement channel, and produce several alerts within
 * seconds. `NotificationCoordinator` decides which of those alerts actually
 * reach the user instead of letting every producer call `showMessage()`.
 *
 * The rules are deliberately small and deterministic:
 *  - A notification belongs to a caller-supplied key. A repeated key inside
 *    its cooldown is folded into a count instead of shown again.
 *  - When the cooldown ends, the next notification is shown with the number of
 *    folded repeats, so information is delayed, never silently lost.
 *  - Info and warning notifications also share a rolling-window delivery cap,
 *    so a burst of *different* processes cannot flood the tray either.
 *  - Critical notifications (failed enforcement, restore failure, capture
 *    loss) bypass both limits. That is the acceptance criterion: repeated
 *    packet activity cannot hide a critical failure.
 *
 * The coordinator holds no UI and no clock. The caller passes `nowMs`, which
 * keeps the policy testable without waiting for timers.
 */

#pragma once

#include <QHash>
#include <QList>
#include <QString>

enum class NotificationPriority
{
    Info,
    Warning,
    Critical
};

enum class NotificationRoute
{
    TrayAndApp,
    TrayOnly,
    AppOnly
};

struct AppNotification
{
    // Stable identity for deduplication, for example "bandwidth:<path>:<kind>".
    // An empty key falls back to the title and message, so producers that do
    // not care still get exact-repeat suppression.
    QString key;
    QString title;
    QString message;
    NotificationPriority priority = NotificationPriority::Info;
    NotificationRoute route = NotificationRoute::TrayAndApp;
    // Optional audit correlation; carried through untouched so a future view
    // can link a notification to its evidence.
    QString identityId;
    QString policyId;

    QString effectiveKey() const;
    static QString fallbackKey(const QString &title, const QString &message);
};

struct NotificationDecision
{
    bool deliver = false;
    // Repeats folded into this delivery. Zero when nothing was suppressed.
    int suppressedCount = 0;
    // True when the rolling-window cap (not the per-key cooldown) suppressed it.
    bool rateLimited = false;
    // Short machine-readable reason for logging: "delivered", "duplicate",
    // "rate-limited".
    QString reason;
};

struct NotificationSettings
{
    // Repeats of one key inside this window are folded together.
    int cooldownMs = 60 * 1000;
    // Rolling window for the cross-key delivery cap.
    int windowMs = 60 * 1000;
    // Info/warning deliveries allowed per window. Critical is exempt.
    int maxDeliveriesPerWindow = 6;
};

class NotificationCoordinator
{
public:
    explicit NotificationCoordinator(const NotificationSettings &settings = NotificationSettings());

    NotificationSettings settings() const;
    // Clamped when applied: a negative cooldown becomes 0, a non-positive
    // window falls back to 60 s, and the cap is at least 1.
    void setSettings(const NotificationSettings &settings);
    static NotificationSettings sanitized(const NotificationSettings &settings);

    // Considers one notification at the caller's clock reading. A delivered
    // decision means the caller should show it; `suppressedCount` is the
    // number of earlier repeats that should be mentioned with it.
    NotificationDecision submit(const AppNotification &notification, qint64 nowMs);

    // Repeats currently folded for a key (0 when nothing is pending).
    int suppressedCount(const QString &key) const;
    // Forgets every delivery and folded repeat. Used when a session ends.
    void reset();

private:
    struct KeyState
    {
        qint64 lastDeliveredMs = -1;
        int suppressed = 0;
    };

    void pruneDeliveryTimes(qint64 nowMs);

    NotificationSettings m_settings;
    QHash<QString, KeyState> m_keys;
    QList<qint64> m_deliveryTimes; // oldest first, info/warning only
};
