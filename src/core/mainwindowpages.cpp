/*
 =============================================================================
    Copyright (c) 2026  Oasis  |  All Rights Reserved
 =============================================================================
*/
/**
 * @file    mainwindowpages.cpp
 * @author  Oasis
 *
 * MainWindow page wiring: per-screen setup and the one-second refreshes for
 * Overview, Activity, Applications and Connections.
 */
#include "mainwindow_p.h"

void MainWindow::setupWidgets()
{
    m_netWidget = new NetworkWidget(this);
    ui->tabNetwork->layout()->addWidget(m_netWidget);

    // Hardware sampling outlives its screen: the status bar and the taskbar
    // overlay still show CPU, memory and temperatures.
    m_hwMonitor = new HardwareMonitor(this);

    m_overlay = new TaskbarOverlay;
    m_overlay->setAdapterList(m_netWidget->getAdapterList());
    m_overlay->show();

    connect(m_overlay, &TaskbarOverlay::adapterChangeRequested, m_netWidget, &NetworkWidget::selectAdapterByIPOrAuto);

    connect(m_netWidget, &NetworkWidget::speedUpdated, this, &MainWindow::onNetworkSpeed, Qt::QueuedConnection);
    connect(m_netWidget, &NetworkWidget::speedUpdated, m_overlay, &TaskbarOverlay::updateSpeed, Qt::QueuedConnection);
    connect(m_netWidget, &NetworkWidget::bandwidthAlert, this, &MainWindow::onBandwidthAlert, Qt::QueuedConnection);
    connect(m_netWidget, &NetworkWidget::enforcementFailed, this,
            [this](const QString &policyId, const QString &executablePath, const QString &message) {
        AppNotification notification;
        notification.key = QStringLiteral("enforcement:%1:%2").arg(policyId, executablePath);
        notification.title = QStringLiteral("Enforcement failed");
        notification.message = QStringLiteral("Policy %1 could not be applied to %2.\n%3")
                                   .arg(policyId.isEmpty() ? QStringLiteral("(unknown)") : policyId,
                                        executablePath.isEmpty() ? QStringLiteral("(unknown executable)")
                                                                 : executablePath,
                                        message);
        notification.priority = NotificationPriority::Critical;
        notification.policyId = policyId;
        // NG-052: a failed enforcement is about one executable; carry it so the
        // balloon click opens that application's evidence.
        rememberNotificationSubject(0, executablePath, QFileInfo(executablePath).fileName());
        postNotification(notification);
    }, Qt::QueuedConnection);

    connect(m_hwMonitor, &HardwareMonitor::snapshotReady, this, [this](const HardwareSnapshot &snap){
        onHardwareSnapshot(snap);
        if (m_overlay) {
            m_overlay->updateHardware(static_cast<int>(snap.cpuLoadPct), static_cast<int>(snap.ramLoadPct));
            m_overlay->updateFullHardware(snap.cpuLoadPct, snap.ramLoadPct, snap.ramUsedMB, snap.ramTotalMB,
                                          snap.gpuLoadPct, snap.cpuTempC, snap.gpuTempC, 0.0);
        }
    }, Qt::QueuedConnection);
    m_hwMonitor->startMonitor();

    connect(m_overlay, &TaskbarOverlay::showMainWindowRequested, this, [this](){
        showNormal();
        activateWindow();
        raise();
    });

    connect(m_overlay, &TaskbarOverlay::minimizeRequested, this, [this](){
        hide();
    });

    connect(m_overlay, &TaskbarOverlay::exitRequested, qApp, &QApplication::quit);

    // ── Global monitoring state → header pill and status bar ───────────────
    NetworkMonitor *monitor = m_netWidget->networkMonitor();
    connect(monitor, &NetworkMonitor::captureStarted, this, [this]() {
        if (m_header)
            m_header->setMonitoringState(AppHeader::MonitorState::Active);
        if (m_statusBar) {
            m_statusBar->setWarning(QString());
            m_statusBar->setMonitoringState(true, m_netWidget->activeAdapterDescription());
        }
    });
    connect(monitor, &NetworkMonitor::captureStopped, this, [this]() {
        if (m_header)
            m_header->setMonitoringState(AppHeader::MonitorState::Stopped);
        if (m_statusBar)
            m_statusBar->setMonitoringState(false);
    });
    connect(monitor, &NetworkMonitor::captureError, this, [this](const QString &msg) {
        if (m_header)
            m_header->setMonitoringState(AppHeader::MonitorState::Degraded);
        if (m_statusBar)
            m_statusBar->setWarning(
                QStringLiteral("⚠ Capture error — open diagnostics"), true);
        qWarning() << "Capture error:" << msg;
    });
    connect(monitor, &NetworkMonitor::adapterDiagnostic, this,
            [this](const QString &adapter, const QString &reason) {
        if (m_statusBar)
            m_statusBar->setWarning(
                QStringLiteral("⚠ Adapter unavailable — open diagnostics"), false);
        qWarning() << "Adapter issue:" << adapter << reason;
    });
}

// ============================================================================
// Overview (Screen 01)
// ============================================================================

void MainWindow::setupOverview()
{
    if (!m_overview || !m_netWidget)
        return;

    // The beat fires once a second for every screen, but only the screen that is
    // on top needs to rebuild. Hidden pages are refreshed on navigation instead,
    // so four screens no longer do their full work every second.
    connect(m_netWidget, &NetworkWidget::dashboardUpdated, this,
            [this](const TopConsumers::Summary &summary) {
        if (isCurrentPage(m_overview))
            refreshOverview(summary);
    });
    connect(m_netWidget, &NetworkWidget::speedUpdated,
            this, &MainWindow::onOverviewSpeed);
    if (AuditEventStore *audit = m_netWidget->auditStore())
        connect(audit, &AuditEventStore::changed,
                this, &MainWindow::refreshOverviewAlerts);

    m_overview->setCollecting(true);
    refreshOverviewState();
    refreshOverviewAlerts();
    refreshOverview(m_netWidget->dashboardSummary());
}

// ============================================================================
// Activity (Screen 02)
// ============================================================================

void MainWindow::setupActivity()
{
    if (!m_activity || !m_netWidget)
        return;

    QDir dir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation));
    if (!dir.exists())
        dir.mkpath(QStringLiteral("."));
    m_activitySeriesFilePath = dir.absoluteFilePath(QStringLiteral("Oasis_ActivitySeries.json"));

    QFile file(m_activitySeriesFilePath);
    if (file.open(QIODevice::ReadOnly)) {
        m_activitySeries.fromJsonString(QString::fromUtf8(file.readAll()));
        file.close();
    }

    QSettings settings;
    m_activity->setDismissedIds(settings.value(
        QStringLiteral("Oasis/Activity/DismissedIds")).toStringList());
    m_activity->setSimulationVisible(qEnvironmentVariableIsSet("OASIS_DEBUG_ACTIVITY"));
    m_activity->setMonitoringActive(m_netWidget->isCapturing());
    m_activity->setSeries(m_activitySeries.series(m_activity->range()));

    const TopConsumers::Summary summary = m_netWidget->dashboardSummary();
    m_activityApplications.clear();
    for (const TopConsumers::Consumer &consumer : summary.consumers) {
        if (!consumer.name.isEmpty())
            m_activityApplications.append(consumer.name);
    }
    m_activityApplications.removeDuplicates();
    m_activity->setApplications(m_activityApplications, QString());

    // Collection (the bounded series and the detector) runs on every beat so the
    // timeline has no gaps while the user is on another screen; the panel itself
    // is only redrawn when it is visible.
    connect(m_netWidget, &NetworkWidget::dashboardUpdated,
            this, &MainWindow::onActivityTelemetry);
    if (AuditEventStore *audit = m_netWidget->auditStore()) {
        connect(audit, &AuditEventStore::changed,
                this, &MainWindow::refreshActivityAuditEvents);
    }

    // Stored audits from previous sessions become policy/respawn cards. They
    // are already in the local audit log; nothing is inferred here.
    refreshActivityAuditEvents();
    m_activity->setEvents(m_activityEvents);
    m_activity->setUpdated(QDateTime::currentDateTime());

    m_activitySaveTimer = new QTimer(this);
    m_activitySaveTimer->setInterval(30 * 1000);
    connect(m_activitySaveTimer, &QTimer::timeout, this, &MainWindow::saveActivitySeries);
    m_activitySaveTimer->start();
}

// ============================================================================
// Applications (Screen 03)
// ============================================================================

void MainWindow::setupApplications()
{
    if (!m_applications || !m_netWidget)
        return;

    connect(m_netWidget, &NetworkWidget::dashboardUpdated, this,
            [this](const TopConsumers::Summary &) {
        if (isCurrentPage(m_applications))
            refreshApplications();
    });

    connect(m_applications, &ApplicationsPage::detailsRequested,
            this, [this](quint32 pid, const QString &path, const QString &name) {
        if (!m_netWidget)
            return;
        Applications::Details details =
            m_netWidget->applicationDetails(pid, path, name);
        if (details.name.trimmed().isEmpty())
            details.name = name;

        // Seven-day totals come from the daily store this screen already
        // maintains; the drawer's session figures come from the process model.
        const QDate today = QDate::currentDate();
        for (int offset = 0; offset < 7; ++offset) {
            const auto day = m_historyData.constFind(
                today.addDays(-offset).toString(QStringLiteral("yyyy-MM-dd")));
            if (day == m_historyData.constEnd())
                continue;
            const auto app = day.value().constFind(details.name);
            if (app == day.value().constEnd())
                continue;
            details.weeklyUploadedBytes += app.value().txBytes;
            details.weeklyDownloadedBytes += app.value().rxBytes;
        }
        m_applications->showDetails(details);
    });
    connect(m_applications, &ApplicationsPage::trafficRequested,
            this, [this](quint32 pid, const QString &path, const QString &name) {
        if (m_netWidget)
            m_netWidget->showTrafficControlsFor(pid, path, name);
    });
    connect(m_applications, &ApplicationsPage::policyRequested,
            this, [this](quint32 pid, const QString &path, const QString &name) {
        if (m_netWidget)
            m_netWidget->showPolicyEditorFor(pid, path, name);
    });
    connect(m_applications, &ApplicationsPage::activityRequested,
            this, [this](quint32, const QString &, const QString &name) {
        if (!m_activity || m_activityIndex < 0)
            return;
        navigateTo(m_activityIndex);
        m_activity->setApplications(m_activityApplications, name);
    });
    connect(m_applications, &ApplicationsPage::ruleChangeRequested,
            this, [this](quint32 pid, const QString &path, const QString &name,
                         const QString &rule) {
        if (m_netWidget)
            m_netWidget->applyApplicationRule(pid, path, name, rule);
    });
    connect(m_applications, &ApplicationsPage::policiesRequested,
            this, [this]() {
        if (m_netWidget)
            m_netWidget->showPolicies();
    });

    refreshApplications();
}

void MainWindow::setupConnections()
{
    if (!m_connections || !m_netWidget)
        return;

    connect(m_netWidget, &NetworkWidget::dashboardUpdated, this,
            [this](const TopConsumers::Summary &) {
        if (isCurrentPage(m_connections))
            refreshConnections();
    });
    connect(m_connections, &ConnectionsPage::refreshRequested, this, [this]() {
        if (!m_netWidget)
            return;
        m_netWidget->refreshConnectionEvidence();
        refreshConnections();
    });
    connect(m_connections, &ConnectionsPage::detailsRequested, this,
            [this](quint32 pid, const QString &path, const QString &name) {
        if (m_netWidget)
            m_netWidget->showApplicationDetails(pid, path, name);
    });
    connect(m_connections, &ConnectionsPage::trafficRequested, this,
            [this](quint32 pid, const QString &path, const QString &name) {
        if (m_netWidget)
            m_netWidget->showTrafficControlsFor(pid, path, name);
    });
    m_connections->setMonitoringActive(m_netWidget->isCapturing());
    refreshConnections();
}

void MainWindow::refreshConnections()
{
    if (!m_connections || !m_netWidget)
        return;
    // State first: the snapshot handler treats rows as live only while capture
    // is running, so a stopped capture cannot refresh a row's last-seen time.
    m_connections->setMonitoringActive(m_netWidget->isCapturing());
    m_connections->setGroups(m_netWidget->connectionGroups());
}

void MainWindow::refreshApplications()
{
    if (!m_applications || !m_netWidget)
        return;

    const QList<Applications::Snapshot> snapshots =
        m_netWidget->applicationSnapshots();
    QList<Applications::Row> rows;
    rows.reserve(snapshots.size());

    for (const Applications::Snapshot &snapshot : snapshots) {
        Applications::Row row;
        row.pid = snapshot.pid;
        row.icon = snapshot.icon;
        row.name = snapshot.name;
        row.displayName = snapshot.displayName;
        row.publisher = snapshot.publisher;
        row.path = snapshot.path;
        row.rxBytesPerSecond = snapshot.rxBytesPerSecond;
        row.txBytesPerSecond = snapshot.txBytesPerSecond;
        row.totalBytes = snapshot.totalBytes;
        row.activity = snapshot.activity;
        row.policy = snapshot.policy;
        row.policyToken = snapshot.policyToken;
        row.identity = snapshot.identity;
        row.rule = snapshot.rule;
        rows.append(row);
    }

    m_applications->setRows(rows);
}

void MainWindow::onActivityTelemetry(const TopConsumers::Summary &summary)
{
    if (!m_activity || !m_netWidget)
        return;

    const QDateTime now = QDateTime::currentDateTime();
    int elapsed = 1;
    if (m_activityLastBeat.isValid())
        elapsed = qBound(1, int(m_activityLastBeat.secsTo(now)), 5);
    m_activityLastBeat = now;

    QList<Activity::AppRate> apps;
    QList<Activity::ProcessRate> rates;
    QStringList names;
    apps.reserve(summary.consumers.size());
    rates.reserve(summary.consumers.size());

    for (const TopConsumers::Consumer &consumer : summary.consumers) {
        if (consumer.name.isEmpty())
            continue;
        names.append(consumer.name);

        Activity::AppRate app;
        app.name = consumer.name;
        app.rxBytesPerSecond = consumer.rxBytesPerSecond;
        app.txBytesPerSecond = consumer.txBytesPerSecond;
        apps.append(app);

        Activity::ProcessRate rate;
        rate.name = consumer.name;
        rate.path = consumer.path;
        rate.pid = consumer.pid;
        rate.rxBytesPerSecond = consumer.rxBytesPerSecond;
        rate.txBytesPerSecond = consumer.txBytesPerSecond;
        rate.foreground = consumer.foreground;
        rate.attribution = consumer.activity;
        if (consumer.pid != 0) {
            QString confidence;
            rate.destination = m_netWidget->primaryDestinationForPid(consumer.pid,
                                                                     &confidence);
            if (rate.attribution.isEmpty() && !confidence.isEmpty())
                rate.attribution = confidence;
        }
        rates.append(rate);
    }

    m_activitySeries.addSample(now, summary.totalRxBytesPerSecond,
                               summary.totalTxBytesPerSecond, apps, elapsed);

    const QList<Activity::Event> detected =
        m_activityDetector.observe(now, rates, summary.unresolvedBytes);
    for (const Activity::Event &event : detected)
        appendActivityEvent(event);

    names.removeDuplicates();
    names.sort(Qt::CaseInsensitive);
    if (names != m_activityApplications) {
        m_activityApplications = names;
        m_activity->setApplications(names, m_activity->application());
    }

    if (!detected.isEmpty())
        m_activity->setEvents(m_activityEvents);

    // Everything above is collected state and must be complete whether or not
    // the screen is on show (the timeline would otherwise have gaps). The panel
    // updates below are only worth the work while it is visible.
    if (!isCurrentPage(m_activity))
        return;

    renderActivityPanel();
}

bool MainWindow::isCurrentPage(QWidget *page) const
{
    return page != nullptr && m_pages && m_pages->currentWidget() == page;
}

void MainWindow::refreshVisiblePage()
{
    if (!m_netWidget || !m_pages)
        return;

    QWidget *current = m_pages->currentWidget();
    if (current == m_overview) {
        refreshOverview(m_netWidget->dashboardSummary());
    } else if (current == m_applications) {
        refreshApplications();
    } else if (current == m_connections) {
        refreshConnections();
    } else if (current == m_activity) {
        renderActivityPanel();
    }
}

void MainWindow::renderActivityPanel()
{
    if (!m_activity || !m_netWidget)
        return;

    // The panel reflects the last collected sample, which may have arrived while
    // another screen was open.
    const QDateTime now = m_activityLastBeat.isValid()
        ? m_activityLastBeat
        : QDateTime::currentDateTime();

    m_activity->setSeries(m_activitySeries.series(m_activity->range()));
    m_activity->setUpdated(now);
    m_activity->setMonitoringActive(m_netWidget->isCapturing());

    if (m_netWidget->getAdapterList().isEmpty()) {
        m_activity->setBanner(QStringLiteral(
            "No network adapter is available, so no traffic can be recorded. "
            "Connect an adapter and reopen Oasis."), QStringLiteral("warning"));
    } else if (!m_netWidget->isCapturing()) {
        m_activity->setBanner(QStringLiteral(
            "Monitoring is stopped. The feed below shows events already stored "
            "in this range."), QStringLiteral("warning"));
    } else {
        m_activity->clearBanner();
    }
}

void MainWindow::appendActivityEvent(const Activity::Event &event)
{
    if (!event.isValid() || m_activityEventIds.contains(event.id))
        return;
    m_activityEventIds.insert(event.id);
    m_activityEvents.append(event);

    constexpr int kMaxEvents = 800;
    while (m_activityEvents.size() > kMaxEvents) {
        const Activity::Event removed = m_activityEvents.takeFirst();
        m_activityEventIds.remove(removed.id);
    }
}

void MainWindow::refreshActivityAuditEvents()
{
    if (!m_netWidget)
        return;
    AuditEventStore *store = m_netWidget->auditStore();
    if (!store)
        return;

    bool added = false;
    for (const AuditEvent &audit : store->events()) {
        const QString result = audit.result.trimmed();
        const QString lowered = result.toLower();

        Activity::Category category;
        QString badge;
        QString titlePrefix;
        bool include = false;

        switch (audit.type) {
        case AuditEvent::EventType::PolicyChange:
            category = Activity::Category::Policy;
            badge = QStringLiteral("Policy Changed");
            titlePrefix = QStringLiteral("Policy changed for %1");
            include = true;
            break;
        case AuditEvent::EventType::AutomaticDecision:
            category = Activity::Category::Policy;
            badge = QStringLiteral("Auto-Throttled");
            titlePrefix = QStringLiteral("Data Saver limited %1");
            include = true;
            break;
        case AuditEvent::EventType::EnforcementResult:
            if (!lowered.contains(QLatin1String("fail"))
                && !lowered.contains(QLatin1String("partial"))
                && !lowered.contains(QLatin1String("stored")))
                continue;
            category = Activity::Category::Policy;
            badge = lowered.contains(QLatin1String("fail"))
                ? QStringLiteral("Enforcement Failed")
                : QStringLiteral("Enforcement Partial");
            titlePrefix = QStringLiteral("Enforcement outcome for %1");
            include = true;
            break;
        case AuditEvent::EventType::ProcessGroupMembershipChange:
            category = Activity::Category::Respawn;
            badge = QStringLiteral("Respawn Handled");
            titlePrefix = QStringLiteral("%1 inherited a policy after respawn");
            include = true;
            break;
        default:
            continue;
        }

        if (!include || !audit.timestamp.isValid())
            continue;

        QString target = audit.scope.trimmed();
        const bool looksLikePath = target.contains(QLatin1Char('\\'))
            || target.contains(QLatin1Char('/'));
        if (looksLikePath)
            target = QFileInfo(target).fileName();
        if (target.isEmpty())
            target = QStringLiteral("an unrecognized target");

        Activity::Event event;
        event.at = audit.timestamp;
        event.category = category;
        event.badge = badge;
        event.title = titlePrefix.arg(target);
        event.appName = target;
        event.appPath = looksLikePath ? audit.scope.trimmed() : QString();
        event.description = !audit.reason.trimmed().isEmpty()
            ? audit.reason.trimmed()
            : (!audit.details.trimmed().isEmpty()
                   ? audit.details.trimmed()
                   : QStringLiteral("Recorded in the local audit log."));
        if (!result.isEmpty())
            event.extra.append({ QStringLiteral("Outcome"), result });
        if (!audit.relatedPolicyId.isEmpty())
            event.extra.append({ QStringLiteral("Policy"), audit.relatedPolicyId });
        if (!audit.details.trimmed().isEmpty()
            && audit.details.trimmed() != event.description)
            event.extra.append({ QStringLiteral("Details"), audit.details.trimmed() });
        if (!audit.errorInfo.trimmed().isEmpty())
            event.extra.append({ QStringLiteral("Error"), audit.errorInfo.trimmed() });

        event.id = Activity::makeEventId(
            category, event.at, audit.scope,
            QStringLiteral("audit-%1-%2")
                .arg(static_cast<int>(audit.type))
                .arg(result));
        const int before = m_activityEvents.size();
        appendActivityEvent(event);
        added = added || m_activityEvents.size() != before;
    }

    if (added && m_activity)
        m_activity->setEvents(m_activityEvents);
}

void MainWindow::exportActivityFeed(const QString &format)
{
    if (!m_activity)
        return;
    const bool csv = format.compare(QLatin1String("csv"), Qt::CaseInsensitive) == 0;
    const QString filter = csv ? QStringLiteral("CSV files (*.csv)")
                               : QStringLiteral("JSON files (*.json)");
    const QString suggested = QStringLiteral("Oasis_Activity_%1.%2")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")),
             csv ? QStringLiteral("csv") : QStringLiteral("json"));
    QString fileName = QFileDialog::getSaveFileName(
        this, QStringLiteral("Export activity feed"), suggested, filter);
    if (fileName.isEmpty())
        return;
    if (csv && !fileName.endsWith(QLatin1String(".csv"), Qt::CaseInsensitive))
        fileName += QStringLiteral(".csv");
    if (!csv && !fileName.endsWith(QLatin1String(".json"), Qt::CaseInsensitive))
        fileName += QStringLiteral(".json");

    // Destinations are redacted by default, matching every other export.
    const QList<Activity::Event> events = m_activity->visibleEvents();
    const QString contents = csv ? Activity::exportCsv(events, true)
                                 : Activity::exportJson(events, true);
    if (writeExportFile(fileName, contents)) {
        if (m_statusBar)
            m_statusBar->setMessage(
                QStringLiteral("Exported %1 activity events%2")
                    .arg(events.size())
                    .arg(exportRedactionNote(true)));
    }
}

void MainWindow::saveActivitySeries()
{
    if (m_activitySeriesFilePath.isEmpty())
        return;
    QSaveFile file(m_activitySeriesFilePath);
    if (!file.open(QIODevice::WriteOnly))
        return;
    file.write(m_activitySeries.toJsonString().toUtf8());
    file.commit();
}

void MainWindow::refreshOverview(const TopConsumers::Summary &summary)
{
    if (!m_overview)
        return;

    const quint64 total = summary.totalRxBytes + summary.totalTxBytes;
    if (total > 0 || summary.consumerCount > 0)
        m_overviewHasData = true;

    m_overview->setUsageTotals(total, summary.totalRxBytes, summary.totalTxBytes,
                               m_overviewRxRate, m_overviewTxRate);
    m_overview->setActiveAppCount(summary.consumerCount);

    QVector<Overview::Consumer> consumers;
    consumers.reserve(summary.rows.size());
    for (const TopConsumers::Row &row : summary.rows) {
        Overview::Consumer consumer;
        consumer.pid = row.pid;
        consumer.name = row.name;
        consumer.path = row.path;
        consumer.usage = row.usage;
        consumer.bytesPerSecond = row.bytesPerSecond;
        consumer.totalBytes = row.totalBytes;

        // DESIGN_SYSTEM.md §2.3: red only for an enforced block, green only for
        // a confirmed limit, grey when the attribution could not be pinned down.
        if (row.control == QLatin1String("Blocked")) {
            consumer.stateLabel = QStringLiteral("Blocked");
            consumer.stateToken = QStringLiteral("failed");
        } else if (row.control == QLatin1String("Limited")) {
            consumer.stateLabel = QStringLiteral("Limited");
            consumer.stateToken = QStringLiteral("active");
        } else if (row.unresolved) {
            consumer.stateLabel = QStringLiteral("Unknown");
            consumer.stateToken = QStringLiteral("unknown");
        }

        consumer.subtitle = row.activity.isEmpty() ? row.identity : row.activity;
        consumers.append(consumer);
    }
    m_overview->setTopConsumers(consumers);

    // Controls. "Active" means the same thing it means to the scheduler: in
    // force now. A policy this build cannot enforce is reported as stored only
    // rather than counted as active.
    Overview::ControlCounts counts;
    counts.unresolvedConsumers = summary.unresolvedConsumers;
    counts.unresolvedBytes = summary.unresolvedBytes;
    counts.totalBytes = total;

    const QDateTime now = QDateTime::currentDateTime();
    const QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    for (const NetworkPolicy &policy : policies) {
        const PolicyActivationState state = policyActivationAt(policy, now);
        if (state == PolicyActivationState::Expired) {
            ++counts.expired;
            continue;
        }
        if (state != PolicyActivationState::Active)
            continue;
        if (policyEnforcementSummary(policy).startsWith(QStringLiteral("Stored only"),
                                                       Qt::CaseInsensitive))
            ++counts.storedOnly;
        else
            ++counts.active;
    }
    m_overview->setControls(counts);
    m_overview->setUpdated(now);

    refreshOverviewState();
}

void MainWindow::onOverviewSpeed(quint64 rxBps, quint64 txBps)
{
    m_overviewRxRate = rxBps;
    m_overviewTxRate = txBps;
    if (!m_overview)
        return;

    Overview::TrafficPoint point;
    point.timestamp = QDateTime::currentDateTime();
    point.rxBytesPerSecond = rxBps;
    point.txBytesPerSecond = txBps;
    m_overview->appendTrafficPoint(point);

    refreshOverviewState();
}

void MainWindow::refreshOverviewState()
{
    if (!m_overview || !m_netWidget)
        return;

    const bool capturing = m_netWidget->isCapturing();
    m_overview->setMonitoringActive(capturing);
    m_overview->setCollecting(!m_overviewHasData);

    if (m_netWidget->getAdapterList().isEmpty()) {
        m_overview->setBanner(Overview::BannerSeverity::Warning,
            QStringLiteral("No network adapter is available, so no traffic can be "
                           "recorded. Connect an adapter and reopen Oasis."));
    } else if (!capturing) {
        m_overview->setBanner(Overview::BannerSeverity::Warning,
            QStringLiteral("Monitoring is stopped. Figures below are from the last "
                           "session and are no longer updating."));
    } else {
        m_overview->clearBanner();
    }
}

void MainWindow::refreshOverviewAlerts()
{
    if (!m_overview || !m_netWidget)
        return;

    AuditEventStore *store = m_netWidget->auditStore();
    if (!store)
        return;

    const QList<AuditEvent> events = store->events();
    QVector<Overview::Alert> alerts;
    for (int i = events.size() - 1; i >= 0 && alerts.size() < 5; --i) {
        const AuditEvent &event = events.at(i);

        Overview::Alert alert;
        alert.at = event.timestamp;
        alert.title = overviewAlertTitle(event);
        alert.tone = overviewAlertTone(event);

        QString detail = auditEventTypeName(event.type);
        const QString outcome = event.result.trimmed();
        if (!outcome.isEmpty())
            detail += QStringLiteral(" · ") + outcome;
        else if (!event.reason.trimmed().isEmpty())
            detail += QStringLiteral(" · ") + event.reason.trimmed();
        alert.detail = detail;

        if (event.type == AuditEvent::EventType::PolicyChange
            || event.type == AuditEvent::EventType::EnforcementRequest
            || event.type == AuditEvent::EventType::EnforcementResult)
            alert.actionLabel = QStringLiteral("Review");

        alerts.append(alert);
    }
    m_overview->setAlerts(alerts);
}

