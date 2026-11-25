/**
 * @file    servicehost.h
 * @author  Oasis
 * @brief   Owns the long-lived backend services, independent of any window.
 *
 * Before the web UI, MainWindow was both the shell and the owner of the
 * capture, policy, enforcement and notification services. The window is no
 * longer the application, so those services need an owner that exists whether
 * or not a particular screen is shown. ServiceHost is that owner: main()
 * starts it before the window and stops it on exit.
 *
 * It intentionally forwards to the existing implementations instead of
 * reimplementing them. NetworkWidget already acts as the hidden host of the
 * capture, policy store, enforcement coordinator and audit store (see
 * docs/POLICIES_PAGE_PLAN.md); this class gives that role an explicit name and
 * a lifecycle that does not depend on a tab being constructed.
 */
#pragma once

#include <QObject>
#include <QString>

#include "network/datasavermode.h"
#include "network/notificationcoordinator.h"

class NetworkWidget;
class NetworkMonitor;
class AuditEventStore;
class ActivityService;

class ServiceHost final : public QObject
{
    Q_OBJECT
public:
    explicit ServiceHost(QObject *parent = nullptr);
    ~ServiceHost() override;

    // Creates the backend services and starts capture. Safe to call twice;
    // the second call is a no-op.
    void start();
    // Stops capture and waits briefly for the capture thread. Called from
    // main() before the process exits and from the destructor.
    void stop();

    bool isStarted() const { return m_started; }

    // The capture and policy services. Never null after start(); exposed so
    // later layers (the WebView2 bridge) can read state without ServiceHost
    // growing one accessor per field. Ownership stays here.
    NetworkWidget *network() const { return m_network; }
    // Activity collection remains available independently of frontend lifetime.
    ActivityService *activity() const { return m_activity; }
    NetworkMonitor *monitor() const;
    AuditEventStore *auditStore() const;

    // Data Saver controls. The mode is persisted and applied by the existing
    // NetworkWidget policy path; this is only the headless entry point.
    void setDataSaverMode(DataSaverMode::Mode mode);
    void restoreDataSaverPolicies();

    // Notifications: one dedupe/priority coordinator for the whole process.
    NotificationCoordinator *notifications() { return &m_notifications; }
    NotificationSettings notificationSettings() const;
    void setNotificationSettings(const NotificationSettings &settings);
    // Submits a notification through the coordinator. Returns the decision so
    // a caller can tell a delivery from a deduplicated repeat. Emits
    // notificationPosted() only when the coordinator delivers it.
    NotificationDecision post(const AppNotification &notification);

    QString activeAdapterDescription() const;
    bool isCapturing() const;

signals:
    // The notification that survived dedupe and rate limiting, with the number
    // of repeats folded into it.
    void notificationPosted(const AppNotification &notification, int suppressedCount);
    void started();
    void stopped();

private:
    // Routes a failed enforcement channel to a critical notification. Critical
    // priority bypasses the coordinator's cooldown, matching NG-051.
    void onEnforcementFailed(const QString &policyId, const QString &executablePath,
                             const QString &message);

    NetworkWidget *m_network = nullptr;
    ActivityService *m_activity = nullptr;
    NotificationCoordinator m_notifications;
    bool m_started = false;
};
