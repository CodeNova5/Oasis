/*
 =============================================================================
    Copyright (c) 2026  Oasis  |  All Rights Reserved
 =============================================================================
*/
/**
 * @file    mainwindowtray.cpp
 * @author  Oasis
 *
 * MainWindow tray, notifications and live status: tray menu and activation,
 * theme toggle, the network alert feed, data-saver actions, hardware status
 * and the silent background update check.
 */
#include "mainwindow_p.h"

void MainWindow::setupTray()
{
    m_trayMenu = new QMenu(this);

    QAction *actShow  = m_trayMenu->addAction("Show / Hide");
    QAction *actTheme = m_trayMenu->addAction("Toggle Theme");
    m_trayMenu->addSeparator();
    QAction *actQuit  = m_trayMenu->addAction("Exit");

    connect(actShow,  &QAction::triggered, this, [this](){
        isVisible() ? hide() : (showNormal(), activateWindow());
    });
    connect(actTheme, &QAction::triggered, this, &MainWindow::onToggleTheme);
    connect(actQuit,  &QAction::triggered, qApp, &QApplication::quit);

    QIcon trayIcon(":/icons/Oasis.png");
    if (trayIcon.isNull()) trayIcon = QIcon(":/icons/app.ico");

    m_tray = new QSystemTrayIcon(trayIcon, this);
    m_tray->setContextMenu(m_trayMenu);
    m_tray->setToolTip("Oasis");
    m_tray->show();

    connect(m_tray, &QSystemTrayIcon::activated, this, &MainWindow::onTrayActivated);
    // NG-052: clicking a balloon follows it to the same evidence.
    connect(m_tray, &QSystemTrayIcon::messageClicked,
            this, &MainWindow::openLastNotificationSubject);
}

void MainWindow::onToggleTheme()
{
    ThemeManager::instance().toggleTheme();
    m_theme = ThemeManager::instance().mode();
    saveSettings();
}

void MainWindow::rememberNotificationSubject(quint32 pid, const QString &path,
                                             const QString &name)
{
    m_notificationPid = pid;
    m_notificationPath = path.trimmed();
    m_notificationName = name.trimmed();
}

// NG-052: "move from a notification to evidence and then to a reversible
// action". The detail view is the evidence, and its action bar is the reversible
// control, so a warning is one click away from the thing it is warning about.
void MainWindow::openLastNotificationSubject()
{
    if (!m_netWidget) return;
    if (m_notificationPid == 0 && m_notificationPath.isEmpty()) return;

    showNormal();
    activateWindow();
    raise();
    navigateTo(m_overviewIndex);

    m_netWidget->showApplicationDetails(m_notificationPid, m_notificationPath,
                                        m_notificationName);
}

void MainWindow::postNotification(const AppNotification &notification)
{
    const NotificationDecision decision = m_notifications.submit(
        notification, QDateTime::currentMSecsSinceEpoch());
    if (!decision.deliver) {
        qDebug().noquote() << "Notification suppressed (" + decision.reason + "):"
                           << notification.title;
        return;
    }

    // Fold repeats into the delivered text. The count goes first because a
    // tray balloon truncates from the end of a long message.
    QString message = notification.message;
    if (decision.suppressedCount > 0) {
        message = QStringLiteral("%1 earlier similar notification%2 were suppressed.\n\n%3")
                      .arg(decision.suppressedCount)
                      .arg(decision.suppressedCount == 1 ? QString() : QStringLiteral("s"))
                      .arg(notification.message);
    }

    const bool trayRoute = notification.route == NotificationRoute::TrayAndApp ||
                           notification.route == NotificationRoute::TrayOnly;
    const bool appRoute = notification.route == NotificationRoute::TrayAndApp ||
                          notification.route == NotificationRoute::AppOnly;

    if (trayRoute && m_tray) {
        QSystemTrayIcon::MessageIcon icon = QSystemTrayIcon::Information;
        int timeoutMs = 6000;
        switch (notification.priority) {
        case NotificationPriority::Warning:
            icon = QSystemTrayIcon::Warning;
            timeoutMs = 8000;
            break;
        case NotificationPriority::Critical:
            icon = QSystemTrayIcon::Critical;
            timeoutMs = 10000;
            break;
        case NotificationPriority::Info:
            break;
        }
        m_tray->showMessage(notification.title, message, icon, timeoutMs);
    }

    if (appRoute && m_statusBar) {
        QString status = notification.title;
        if (decision.suppressedCount > 0)
            status += QStringLiteral(" (+%1 earlier)").arg(decision.suppressedCount);
        m_statusBar->setMessage(status, message);
    }
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick)
        isVisible() ? hide() : (showNormal(), activateWindow(), raise());
}

void MainWindow::onNetworkSpeed(quint64 rxBps, quint64 txBps)
{
    if (m_statusBar) {
        m_statusBar->setSpeedText(fmtSpeed(rxBps), fmtSpeed(txBps));
        m_statusBar->setLastUpdated(QDateTime::currentDateTime());
    }
    m_tray->setToolTip(QString("Oasis\n↓ %1  ↑ %2").arg(fmtSpeed(rxBps), fmtSpeed(txBps)));
}

void MainWindow::onBandwidthAlert(const BandwidthEvent &event)
{
    // NG-052: the alert and the detail view must describe the same application.
    rememberNotificationSubject(event.pid, event.executablePath, event.processName);
    const QString category = BandwidthGuard::categoryDisplayName(event.category);
    const QString categoryWithConfidence = AttributionConfidenceModel::qualifiedText(
        category, event.categoryConfidence);
    const QString confidenceText = QStringLiteral("%1 (%2)")
        .arg(AttributionConfidenceModel::displayName(event.categoryConfidence),
             AttributionConfidenceModel::technicalName(event.categoryConfidence));
    const QString evidenceText = event.categoryEvidence.isEmpty()
        ? QStringLiteral("No category evidence was recorded.")
        : event.categoryEvidence.join(QStringLiteral("; "));

    // NG-015: the category may be the one the process's activity group learned
    // rather than one a rule names, and the alert says so. NG-035: the label is
    // qualified when it is only Likely or Possible, and the evidence is shown.
    const QString origin = event.categoryFromGroup
        ? (event.groupName.isEmpty()
               ? QStringLiteral(" (learned from its activity group)")
               : QStringLiteral(" (learned from activity group \"%1\")").arg(event.groupName))
        : QString();
    const QString classifiedAs = QStringLiteral("Category: %1; confidence: %2%3.\nEvidence: %4")
        .arg(categoryWithConfidence, confidenceText, origin, evidenceText);

    QString title = categoryWithConfidence;
    QString action;
    if (event.throttleAttempted) {
        if (event.throttled) {
            title = "Bandwidth limited";
            action = event.throttleMessage.isEmpty()
                ? QStringLiteral("A 50 KiB/s limit was applied to this executable.")
                : event.throttleMessage;
        } else {
            title = "Bandwidth limit not applied";
            action = event.throttleMessage.isEmpty()
                ? QStringLiteral("The QoS policy could not be applied.")
                : event.throttleMessage;
        }
    } else if (event.firewallAttempted) {
        if (event.firewallBlocked) {
            title = "Internet access blocked";
            action = QStringLiteral("Internet access was blocked for every instance of this executable.\n"
                                    "Right-click the process in Oasis to restore access.");
        } else {
            title = "Internet block failed";
            action = event.firewallMessage.isEmpty()
                ? QStringLiteral("The firewall rule could not be applied.")
                : event.firewallMessage;
        }
    } else if (event.firewallBlocked) {
        title = "Internet access already blocked";
        action = QStringLiteral("This executable is already blocked by a Oasis firewall rule.");
    } else if (!event.firewallMessage.isEmpty()) {
        action = event.firewallMessage;
    } else {
        action = QStringLiteral("No bandwidth limit or block was applied.");
    }

    const QString pathText = event.executablePath.isEmpty()
        ? QString()
        : QString("\nPath: %1").arg(event.executablePath);
    const QString message = QString("%1 used %2 in this capture session (PID %3).%4\n%5\n%6")
        .arg(event.processName)
        .arg(fmtBytes(event.totalBytes))
        .arg(event.pid)
        .arg(pathText)
        .arg(classifiedAs)
        .arg(action);

    if (ui->tableDataSaverDetections) {
        const int row = ui->tableDataSaverDetections->rowCount();
        ui->tableDataSaverDetections->insertRow(row);
        ui->tableDataSaverDetections->setItem(row, 0, new QTableWidgetItem(event.processName));
        ui->tableDataSaverDetections->setItem(row, 1, new QTableWidgetItem(event.executablePath));
        ui->tableDataSaverDetections->setItem(row, 2, new QTableWidgetItem(fmtBytes(event.totalBytes)));
        auto *categoryItem = new QTableWidgetItem(categoryWithConfidence);
        categoryItem->setToolTip(classifiedAs);
        ui->tableDataSaverDetections->setItem(row, 3, categoryItem);
        ui->tableDataSaverDetections->setItem(row, 4, new QTableWidgetItem(action));
        ui->tableDataSaverDetections->item(row, 0)->setData(Qt::UserRole, event.processName);
        ui->tableDataSaverDetections->item(row, 0)->setData(Qt::UserRole + 1, event.executablePath);
        ui->tableDataSaverDetections->item(row, 0)->setData(Qt::UserRole + 2, event.pid);
        ui->tableDataSaverDetections->resizeColumnsToContents();
    }

    // NG-051: one key per executable and outcome, so repeated packet activity
    // for the same process folds into a count instead of a balloon flood.
    const bool failed = (event.throttleAttempted && !event.throttled) ||
                        (event.firewallAttempted && !event.firewallBlocked);
    AppNotification notification;
    notification.key = QStringLiteral("bandwidth:%1:%2")
                           .arg(event.executablePath.isEmpty() ? event.processName
                                                               : event.executablePath,
                                title);
    notification.title = title;
    notification.message = message;
    notification.priority = failed
        ? NotificationPriority::Critical
        : ((event.throttled || event.firewallBlocked) ? NotificationPriority::Warning
                                                      : NotificationPriority::Info);
    qWarning().noquote() << title << "-" << message;
    postNotification(notification);
}

void MainWindow::onDataSaverModeChanged(int mode)
{
    if (m_netWidget) m_netWidget->setDataSaverMode(mode);
    if (ui->cmbDataSaverPageMode->currentIndex() != mode)
        ui->cmbDataSaverPageMode->setCurrentIndex(mode);
    saveSettings();
}

void MainWindow::onRestoreDataSaverPolicies()
{
    if (m_netWidget) m_netWidget->restoreAllDataSaverPolicies();
}

void MainWindow::onDataSaverDetectionMenu(const QPoint &pos)
{
    if (!m_netWidget) return;

    QTableWidgetItem *item = ui->tableDataSaverDetections->itemAt(pos);
    if (!item) return;

    QTableWidgetItem *processItem = ui->tableDataSaverDetections->item(item->row(), 0);
    if (!processItem) return;

    const QString processName = processItem->data(Qt::UserRole).toString();
    const QString executablePath = processItem->data(Qt::UserRole + 1).toString();
    if (processName.isEmpty()) return;

    QMenu menu(this);
    QAction *keepFullSpeed = menu.addAction("Keep full speed for 2 hours");
    QAction *throttle = menu.addAction(m_netWidget->throttleActionText(executablePath));
    QAction *block = menu.addAction("Block internet access as fallback...");

    connect(keepFullSpeed, &QAction::triggered, this, [this, processName]() {
        m_netWidget->exemptProcess(processName, 2 * 60 * 60);
    });
    connect(throttle, &QAction::triggered, this, [this, executablePath]() {
        m_netWidget->requestThrottlePath(executablePath);
    });
    connect(block, &QAction::triggered, this, [this, processName, executablePath]() {
        m_netWidget->toggleInternetAccess(processName, executablePath);
    });

    menu.exec(ui->tableDataSaverDetections->viewport()->mapToGlobal(pos));
}

void MainWindow::onHardwareSnapshot(const HardwareSnapshot &snap)
{
    if (m_statusBar)
        m_statusBar->setHardware(static_cast<int>(snap.cpuLoadPct),
                                 static_cast<int>(snap.ramLoadPct));
}

