/**
 * @file    servicehost.cpp
 * @author  Oasis
 */

#include "servicehost.h"

#include "network/auditeventstore.h"

#include <QDateTime>
#include "network/networkmonitor.h"
#include "network/networkwidget.h"

ServiceHost::ServiceHost(QObject *parent)
    : QObject(parent)
{
}

ServiceHost::~ServiceHost()
{
    stop();
    delete m_network;
    m_network = nullptr;
}

void ServiceHost::start()
{
    if (m_started)
        return;

    // NetworkWidget owns the capture thread, the policy store path, the
    // enforcement coordinator, the throttle manager and the audit store. It is
    // constructed but never shown: nothing here needs a visible widget.
    m_network = new NetworkWidget;
    connect(m_network, &NetworkWidget::enforcementFailed,
            this, &ServiceHost::onEnforcementFailed);

    m_network->autoStart();
    m_started = true;
    emit started();
}

void ServiceHost::stop()
{
    if (!m_started || !m_network)
        return;

    // The capture thread writes into the monitor's tables, so it is stopped and
    // joined before anything it feeds is torn down. The widget destructor does
    // this too; doing it here keeps the shutdown explicit in main().
    if (NetworkMonitor *monitor = m_network->networkMonitor()) {
        monitor->stopCapture();
        monitor->wait(1500);
    }

    m_started = false;
    emit stopped();
}

NetworkMonitor *ServiceHost::monitor() const
{
    return m_network ? m_network->networkMonitor() : nullptr;
}

AuditEventStore *ServiceHost::auditStore() const
{
    return m_network ? m_network->auditStore() : nullptr;
}

void ServiceHost::setDataSaverMode(int mode)
{
    if (m_network)
        m_network->setDataSaverMode(mode);
}

void ServiceHost::restoreDataSaverPolicies()
{
    if (m_network)
        m_network->restoreAllDataSaverPolicies();
}

NotificationSettings ServiceHost::notificationSettings() const
{
    return m_notifications.settings();
}

void ServiceHost::setNotificationSettings(const NotificationSettings &settings)
{
    m_notifications.setSettings(settings);
}

NotificationDecision ServiceHost::post(const AppNotification &notification)
{
    const NotificationDecision decision = m_notifications.submit(
        notification, QDateTime::currentMSecsSinceEpoch());
    if (decision.deliver) {
        emit notificationPosted(notification, decision.suppressedCount);
    }
    return decision;
}

QString ServiceHost::activeAdapterDescription() const
{
    return m_network ? m_network->activeAdapterDescription() : QString();
}

bool ServiceHost::isCapturing() const
{
    return m_network && m_network->isCapturing();
}

void ServiceHost::onEnforcementFailed(const QString &policyId,
                                      const QString &executablePath,
                                      const QString &message)
{
    AppNotification notification;
    notification.key = QStringLiteral("enforcement:%1:%2").arg(policyId, executablePath);
    notification.title = QStringLiteral("Enforcement failed");
    notification.message = QStringLiteral("Policy %1 could not be applied to %2.\n%3")
                               .arg(policyId.isEmpty() ? QStringLiteral("(unknown)") : policyId,
                                    executablePath.isEmpty()
                                        ? QStringLiteral("(unknown executable)")
                                        : executablePath,
                                    message);
    // A failed enforcement is never rate-limited away (NG-051).
    notification.priority = NotificationPriority::Critical;
    notification.policyId = policyId;
    post(notification);
}
