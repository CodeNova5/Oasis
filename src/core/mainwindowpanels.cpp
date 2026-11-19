/*
 =============================================================================
    Copyright (c) 2026  Oasis  |  All Rights Reserved
 =============================================================================
*/
/**
 * @file    mainwindowpanels.cpp
 * @author  Oasis
 *
 * Settings-screen panels owned by MainWindow: the traffic history engine,
 * diagnostics, the audit log, attribution privacy, and the AI provider form.
 */
#include "mainwindow_p.h"

// ============================================================================
// History Engine (Smart Data Extraction & Persistence with Tree Logic)
// ============================================================================

void MainWindow::initHistoryManager()
{
    QString appDataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(appDataPath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    m_historyFilePath = dir.absoluteFilePath("Oasis_History.json");

    loadHistoryFromJson();

    // Setup History Tree UI
    ui->treeHistory->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui->treeHistory->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->treeHistory->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->treeHistory->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);

    connect(ui->btnExportHistory, &QPushButton::clicked, this, &MainWindow::onExportHistory);
    connect(ui->btnClearHistory, &QPushButton::clicked, this, &MainWindow::onClearHistory);
    connect(ui->cmbHistoryRange, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::onHistoryFilterChanged);

    // Set Default Filter to "All Time" (Index 3)
    ui->cmbHistoryRange->setCurrentIndex(3);

    m_trafficMonitorTimer = new QTimer(this);
    m_trafficMonitorTimer->setInterval(1000);
    connect(m_trafficMonitorTimer, &QTimer::timeout, this, &MainWindow::recordLiveTraffic);
    m_trafficMonitorTimer->start();

    m_historyUiTimer = new QTimer(this);
    m_historyUiTimer->setInterval(2000);
    connect(m_historyUiTimer, &QTimer::timeout, this, [this](){
        if (m_pages && m_pages->currentWidget() == ui->tabHistory) {
            refreshHistoryUI();
        }
    });
    m_historyUiTimer->start();

    refreshHistoryUI();
}

void MainWindow::recordLiveTraffic()
{
    QTreeView *tree = m_netWidget->findChild<QTreeView*>("treeView");
    if (!tree) return;

    QAbstractItemModel *model = tree->model();
    if (!model) return;

    QString today = QDate::currentDate().toString("yyyy-MM-dd");
    bool dataChanged = false;

    for (int r = 0; r < model->rowCount(); ++r) {
        QModelIndex idxName = model->index(r, 0);
        QModelIndex idxRx   = model->index(r, 4);
        QModelIndex idxTx   = model->index(r, 5);

        QString appName = model->data(idxName, Qt::UserRole + 1).toString();
        quint32 pid = model->data(idxName, Qt::UserRole).toUInt();
        if (appName.isEmpty()) continue;

        quint64 rxSpeed = model->data(idxRx, Qt::UserRole + 5).toULongLong();
        quint64 txSpeed = model->data(idxTx, Qt::UserRole + 5).toULongLong();

        if (rxSpeed > 0 || txSpeed > 0) {
            m_historyData[today][appName].rxBytes += rxSpeed;
            m_historyData[today][appName].txBytes += txSpeed;
            if (m_historyData[today][appName].exePath.isEmpty()) {
                m_historyData[today][appName].exePath = m_netWidget->getExactProcessPath(pid, appName);
            }
            dataChanged = true;
        }

        if (!m_iconCache.contains(appName)) {
            QVariant iconVar = model->data(idxName, Qt::DecorationRole);
            if (!iconVar.isNull() && iconVar.canConvert<QPixmap>()) {
                m_iconCache.insert(appName, QIcon(iconVar.value<QPixmap>()));
            } else if (!iconVar.isNull() && iconVar.canConvert<QIcon>()) {
                m_iconCache.insert(appName, iconVar.value<QIcon>());
            }
        }
    }

    if (dataChanged) {
        m_saveCounter++;
        if (m_saveCounter >= 60) {
            saveHistoryToJson();
            m_saveCounter = 0;
        }
    }
}

void MainWindow::refreshHistoryUI()
{
    int filterIdx = ui->cmbHistoryRange->currentIndex();
    QDate today = QDate::currentDate();

    quint64 globalRx = 0, globalTx = 0;
    QString topApp = "No Data";
    quint64 topAppTotal = 0;

    // FIX: Save the expanded state of the tree before clearing it
    QSet<QString> expandedDates;
    for (int i = 0; i < ui->treeHistory->topLevelItemCount(); ++i) {
        QTreeWidgetItem *item = ui->treeHistory->topLevelItem(i);
        if (item->isExpanded()) {
            expandedDates.insert(item->text(0));
        }
    }

    ui->treeHistory->clear();

    QIcon defaultAppIcon = qApp->style()->standardIcon(QStyle::SP_ComputerIcon);

    auto getOrResolveIcon = [&](const QString &appName, const QString &exePath) -> QIcon {
        if (m_iconCache.contains(appName) && !m_iconCache.value(appName).isNull()) {
            return m_iconCache.value(appName);
        }

        QString targetPath = exePath;
        if (targetPath.isEmpty()) {
            wchar_t sysDir[MAX_PATH] = {};
            GetSystemDirectoryW(sysDir, MAX_PATH);
            QString fallback = QString::fromWCharArray(sysDir) + "\\" + appName;
            if (QFileInfo::exists(fallback)) targetPath = fallback;
        }

        QIcon ico;
        if (!targetPath.isEmpty() && QFileInfo::exists(targetPath)) {
            SHFILEINFOW sfi = {};
            if (SHGetFileInfoW(targetPath.toStdWString().c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON)) {
                if (sfi.hIcon) {
                    ico = iconFromHICON(sfi.hIcon);
                    DestroyIcon(sfi.hIcon);
                }
            }
        }

        if (ico.isNull()) {
            SHFILEINFOW sfi = {};
            if (SHGetFileInfoW(appName.toStdWString().c_str(), FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES)) {
                if (sfi.hIcon) {
                    ico = iconFromHICON(sfi.hIcon);
                    DestroyIcon(sfi.hIcon);
                }
            }
        }

        if (ico.isNull()) ico = defaultAppIcon;
        m_iconCache.insert(appName, ico);
        return ico;
    };

    if (filterIdx == 0) {
        // Mode: TODAY -> Flat list of applications
        QMap<QString, DailyAppStat> todayStats;
        QString todayStr = today.toString("yyyy-MM-dd");

        if (m_historyData.contains(todayStr)) {
            todayStats = m_historyData[todayStr];
        }

        QList<QPair<QString, DailyAppStat>> sortedList;
        for (auto it = todayStats.constBegin(); it != todayStats.constEnd(); ++it) {
            sortedList.append(qMakePair(it.key(), it.value()));
            globalRx += it.value().rxBytes;
            globalTx += it.value().txBytes;

            quint64 appTotal = it.value().rxBytes + it.value().txBytes;
            if (appTotal > topAppTotal) {
                topAppTotal = appTotal;
                topApp = it.key();
            }
        }

        std::sort(sortedList.begin(), sortedList.end(), [](const QPair<QString, DailyAppStat>& a, const QPair<QString, DailyAppStat>& b) {
            return (a.second.rxBytes + a.second.txBytes) > (b.second.rxBytes + b.second.txBytes);
        });

        for (const auto &pair : sortedList) {
            QTreeWidgetItem *appItem = new QTreeWidgetItem(ui->treeHistory);
            appItem->setText(0, pair.first);
            appItem->setIcon(0, getOrResolveIcon(pair.first, pair.second.exePath));
            appItem->setText(1, fmtBytes(pair.second.rxBytes));
            appItem->setText(2, fmtBytes(pair.second.txBytes));
            appItem->setText(3, fmtBytes(pair.second.rxBytes + pair.second.txBytes));
        }

    } else {
        // Mode: MULTI-DAY -> Tree grouped by Date
        QMap<QString, quint64> overallAppTotals;

        auto dateIt = m_historyData.constEnd();
        while (dateIt != m_historyData.constBegin()) {
            --dateIt;
            QDate nodeDate = QDate::fromString(dateIt.key(), "yyyy-MM-dd");
            bool includeDate = false;

            if (filterIdx == 1 && nodeDate.daysTo(today) <= 7 && nodeDate.daysTo(today) >= 0) includeDate = true;
            else if (filterIdx == 2 && nodeDate.year() == today.year() && nodeDate.month() == today.month()) includeDate = true;
            else if (filterIdx == 3) includeDate = true;

            if (!includeDate) continue;

            quint64 dateRx = 0, dateTx = 0;
            QTreeWidgetItem *dateItem = new QTreeWidgetItem(ui->treeHistory);
            dateItem->setText(0, dateIt.key());

            QList<QPair<QString, DailyAppStat>> sortedDailyList;
            for (auto appIt = dateIt.value().constBegin(); appIt != dateIt.value().constEnd(); ++appIt) {
                sortedDailyList.append(qMakePair(appIt.key(), appIt.value()));
                dateRx += appIt.value().rxBytes;
                dateTx += appIt.value().txBytes;

                globalRx += appIt.value().rxBytes;
                globalTx += appIt.value().txBytes;

                overallAppTotals[appIt.key()] += (appIt.value().rxBytes + appIt.value().txBytes);
            }

            dateItem->setText(1, fmtBytes(dateRx));
            dateItem->setText(2, fmtBytes(dateTx));
            dateItem->setText(3, fmtBytes(dateRx + dateTx));

            dateItem->setIcon(0, qApp->style()->standardIcon(QStyle::SP_FileDialogDetailedView));

            std::sort(sortedDailyList.begin(), sortedDailyList.end(), [](const QPair<QString, DailyAppStat>& a, const QPair<QString, DailyAppStat>& b) {
                return (a.second.rxBytes + a.second.txBytes) > (b.second.rxBytes + b.second.txBytes);
            });

            for (const auto &pair : sortedDailyList) {
                QTreeWidgetItem *appItem = new QTreeWidgetItem(dateItem);
                appItem->setText(0, pair.first);
                appItem->setIcon(0, getOrResolveIcon(pair.first, pair.second.exePath));
                appItem->setText(1, fmtBytes(pair.second.rxBytes));
                appItem->setText(2, fmtBytes(pair.second.txBytes));
                appItem->setText(3, fmtBytes(pair.second.rxBytes + pair.second.txBytes));
            }

            // FIX: Restore the expanded state for this specific date node
            if (expandedDates.contains(dateItem->text(0))) {
                dateItem->setExpanded(true);
            }
        }

        for (auto it = overallAppTotals.constBegin(); it != overallAppTotals.constEnd(); ++it) {
            if (it.value() > topAppTotal) {
                topAppTotal = it.value();
                topApp = it.key();
            }
        }
    }

    // Update Summary Cards
    ui->lblHistRx->setText(fmtBytes(globalRx));
    ui->lblHistTx->setText(fmtBytes(globalTx));

    if (topApp != "No Data") {
        QString iconAppName = topApp;
        topApp[0] = topApp[0].toUpper();
        topApp = topApp.remove(".exe");
        ui->lblHistTopApp->setText(QString("%1\n%2").arg(topApp, fmtBytes(topAppTotal)));
        ui->lblHistTopIcon->setPixmap(getOrResolveIcon(iconAppName, "").pixmap(35, 35));
    } else {
        ui->lblHistTopApp->setText("No Data");
        ui->lblHistTopIcon->clear();
    }
}

void MainWindow::onHistoryFilterChanged(int)
{
    refreshHistoryUI();
}

void MainWindow::onClearHistory()
{
    if (QMessageBox::question(this, "Clear History", "Are you sure you want to permanently delete all network history data?", QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
        m_historyData.clear();
        saveHistoryToJson();
        refreshHistoryUI();
    }
}

void MainWindow::setupDiagnosticsView()
{
    DiagnosticsModel *diag = m_netWidget ? m_netWidget->diagnosticsModel() : nullptr;
    if (!diag)
        return;

    ui->tableDiagnostics->setModel(diag);
    QHeaderView *header = ui->tableDiagnostics->horizontalHeader();
    header->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(2, QHeaderView::Stretch);
    header->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ui->tableDiagnostics->verticalHeader()->setVisible(false);

    connect(diag, &QAbstractItemModel::rowsInserted, this, &MainWindow::refreshDiagnosticsSummary);
    connect(diag, &QAbstractItemModel::rowsRemoved, this, &MainWindow::refreshDiagnosticsSummary);
    connect(diag, &QAbstractItemModel::modelReset, this, &MainWindow::refreshDiagnosticsSummary);
    connect(ui->btnExportDiagnostics, &QPushButton::clicked, this, &MainWindow::onExportDiagnostics);
    connect(ui->btnClearDiagnostics, &QPushButton::clicked, this, &MainWindow::onClearDiagnostics);

    refreshDiagnosticsSummary();
}

void MainWindow::refreshDiagnosticsSummary()
{
    DiagnosticsModel *diag = m_netWidget ? m_netWidget->diagnosticsModel() : nullptr;
    if (!diag)
        return;

    if (diag->rowCount() == 0) {
        ui->lblDiagnosticsSummary->setText("No capture gaps recorded.");
        return;
    }

    ui->lblDiagnosticsSummary->setText(
        QString("%1 records · %2 dropped · %3 unresolved PID · %4 unknown direction · %5 stale mapping · %6 adapter")
            .arg(diag->rowCount())
            .arg(diag->droppedPacketsCount())
            .arg(diag->unresolvedPidsCount())
            .arg(diag->unknownDirectionCount())
            .arg(diag->staleMappingsCount())
            .arg(diag->adapterUnavailableCount()));
}

void MainWindow::onExportDiagnostics()
{
    DiagnosticsModel *diag = m_netWidget ? m_netWidget->diagnosticsModel() : nullptr;
    if (!diag)
        return;

    const QString fileName = QFileDialog::getSaveFileName(this, "Export Diagnostics",
        QDir::homePath() + "/Oasis_Diagnostics.json", "JSON Files (*.json)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not create the file.");
        return;
    }

    // NG-036: destinations are redacted unless the user turned that off.
    file.write(diag->toJson(ui->chkRedactDestinations->isChecked()).toUtf8());
    file.close();
    QMessageBox::information(this, "Export Successful", "Diagnostics exported successfully!");
}

void MainWindow::setupAuditLogView()
{
    AuditEventStore *audit = m_netWidget ? m_netWidget->auditStore() : nullptr;
    if (!audit)
        return;

    m_auditModel = new AuditLogModel(this);
    m_auditModel->setStore(audit);
    ui->tableAuditLog->setModel(m_auditModel);

    QHeaderView *header = ui->tableAuditLog->horizontalHeader();
    header->setSectionResizeMode(AuditLogModel::TimeColumn, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(AuditLogModel::TypeColumn, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(AuditLogModel::ScopeColumn, QHeaderView::Stretch);
    header->setSectionResizeMode(AuditLogModel::ReasonColumn, QHeaderView::Stretch);
    header->setSectionResizeMode(AuditLogModel::ResultColumn, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(AuditLogModel::PolicyColumn, QHeaderView::ResizeToContents);
    ui->tableAuditLog->verticalHeader()->setVisible(false);

    ui->cmbAuditType->addItem(QStringLiteral("All types"), -1);
    const QStringList types = auditEventTypeNames();
    for (int i = 0; i < types.size(); ++i)
        ui->cmbAuditType->addItem(types.at(i), i);

    ui->cmbAuditWindow->addItem(QStringLiteral("Last hour"), 1);
    ui->cmbAuditWindow->addItem(QStringLiteral("Last 24 hours"), 24);
    ui->cmbAuditWindow->addItem(QStringLiteral("Last 7 days"), 24 * 7);
    ui->cmbAuditWindow->addItem(QStringLiteral("Last 30 days"), 24 * 30);
    ui->cmbAuditWindow->addItem(QStringLiteral("All retained"), 0);
    ui->cmbAuditWindow->setCurrentIndex(ui->cmbAuditWindow->count() - 1);

    // One place applies every control, so the model is re-queried once per
    // change instead of three times while the filters are being set up.
    const auto applyFilters = [this]() {
        m_auditModel->setFilters(ui->cmbAuditType->currentData().toInt(),
                                 ui->edtAuditFilter->text(),
                                 ui->cmbAuditWindow->currentData().toInt());
        refreshAuditSummary();
    };

    connect(ui->cmbAuditType, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, applyFilters);
    connect(ui->cmbAuditWindow, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, applyFilters);
    connect(ui->edtAuditFilter, &QLineEdit::textChanged, this, applyFilters);
    connect(m_auditModel, &QAbstractItemModel::modelReset,
            this, &MainWindow::refreshAuditSummary);
    connect(ui->btnExportAuditLog, &QPushButton::clicked, this, &MainWindow::onExportAuditLog);
    connect(ui->btnExportAuditLogCsv, &QPushButton::clicked,
            this, &MainWindow::onExportAuditLogCsv);
    connect(ui->btnClearAuditLog, &QPushButton::clicked, this, &MainWindow::onClearAuditLog);

    applyFilters();
}

void MainWindow::refreshAuditSummary()
{
    if (!m_auditModel)
        return;

    AuditEventStore *audit = m_auditModel->store();
    const int shown = m_auditModel->rowCount();
    const int retained = audit ? audit->count() : 0;

    if (shown == 0) {
        ui->lblAuditSummary->setText(
            retained == 0
                ? QStringLiteral("No audit events recorded.")
                : QStringLiteral("No audit events match the current filter (%1 retained).")
                      .arg(retained));
        return;
    }

    const AuditRetentionSettings retention = audit->retention();
    ui->lblAuditSummary->setText(
        QStringLiteral("%1 of %2 retained events shown · keeping %3 day(s) / up to %4 events")
            .arg(shown)
            .arg(retained)
            .arg(retention.retentionDays)
            .arg(retention.maxEvents));
}

void MainWindow::onExportAuditLog()
{
    AuditEventStore *audit = m_netWidget ? m_netWidget->auditStore() : nullptr;
    if (!audit || !m_auditModel)
        return;

    const QList<AuditEvent> events = m_auditModel->visibleEvents();
    if (events.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Export audit log"),
                                 QStringLiteral("No audit events match the current filter."));
        return;
    }

    const QString fileName = QFileDialog::getSaveFileName(
        this, QStringLiteral("Export audit log"),
        QDir::homePath() + "/Oasis_AuditLog.json",
        QStringLiteral("JSON Files (*.json)"));
    if (fileName.isEmpty())
        return;

    // The export mirrors the visible (filtered) rows with the same versioned
    // envelope as the whole log, so support can receive exactly what is shown.
    // NG-055: destinations are redacted unless the user turns that off.
    const bool redact = ui->chkRedactDestinations->isChecked();
    if (!writeExportFile(fileName, audit->exportJson(events, redact)))
        return;

    QMessageBox::information(
        this, QStringLiteral("Export successful"),
        QStringLiteral("Exported %1 audit events%2.")
            .arg(events.size())
            .arg(exportRedactionNote(redact)));
}

void MainWindow::onExportAuditLogCsv()
{
    AuditEventStore *audit = m_netWidget ? m_netWidget->auditStore() : nullptr;
    if (!audit || !m_auditModel)
        return;

    const QList<AuditEvent> events = m_auditModel->visibleEvents();
    if (events.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Export audit log"),
                                 QStringLiteral("No audit events match the current filter."));
        return;
    }

    const QString fileName = QFileDialog::getSaveFileName(
        this, QStringLiteral("Export audit log"),
        QDir::homePath() + "/Oasis_AuditLog.csv",
        QStringLiteral("CSV Files (*.csv)"));
    if (fileName.isEmpty())
        return;

    const bool redact = ui->chkRedactDestinations->isChecked();
    if (!writeExportFile(fileName, audit->exportCsv(events, redact)))
        return;

    QMessageBox::information(
        this, QStringLiteral("Export successful"),
        QStringLiteral("Exported %1 audit events%2.")
            .arg(events.size())
            .arg(exportRedactionNote(redact)));
}

void MainWindow::onExportAttribution()
{
    NetworkMonitor *monitor = m_netWidget ? m_netWidget->networkMonitor() : nullptr;
    if (!monitor)
        return;

    const QList<DestinationNameSummary> destinations = monitor->attributionSummaries();
    if (destinations.isEmpty()) {
        QMessageBox::information(
            this, QStringLiteral("Export attribution data"),
            QStringLiteral("No destination attributions are retained. "
                           "DNS or TLS metadata has to be observed first."));
        return;
    }

    QFileDialog dialog(this, QStringLiteral("Export attribution data"),
                       QDir::homePath() + "/Oasis_Attribution.json");
    dialog.setAcceptMode(QFileDialog::AcceptSave);
    dialog.setNameFilters({QStringLiteral("JSON Files (*.json)"),
                           QStringLiteral("CSV Files (*.csv)")});
    if (dialog.exec() != QDialog::Accepted)
        return;

    QString fileName = dialog.selectedFiles().value(0);
    if (fileName.isEmpty())
        return;

    const bool csv = dialog.selectedNameFilter().contains(QStringLiteral("*.csv"));
    if (!fileName.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive) &&
        !fileName.endsWith(QStringLiteral(".csv"), Qt::CaseInsensitive)) {
        fileName += csv ? QStringLiteral(".csv") : QStringLiteral(".json");
    }

    const bool redact = ui->chkRedactDestinations->isChecked();
    const QString contents = csv ? EvidenceExport::attributionCsv(destinations, redact)
                                 : EvidenceExport::attributionJson(destinations, redact);
    if (!writeExportFile(fileName, contents))
        return;

    QMessageBox::information(
        this, QStringLiteral("Export successful"),
        QStringLiteral("Exported %1 destinations%2.")
            .arg(destinations.size())
            .arg(exportRedactionNote(redact)));
}

bool MainWindow::writeExportFile(const QString &fileName, const QString &contents)
{
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, QStringLiteral("Export error"),
                              QStringLiteral("Could not create the file."));
        return false;
    }

    file.write(contents.toUtf8());
    file.close();
    return true;
}

void MainWindow::onClearAuditLog()
{
    AuditEventStore *audit = m_netWidget ? m_netWidget->auditStore() : nullptr;
    if (!audit)
        return;

    if (QMessageBox::question(
            this, QStringLiteral("Clear audit log"),
            QStringLiteral("Permanently delete every stored audit event? "
                           "The retention settings are kept."),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    audit->clear();
    refreshAuditSummary();
}

void MainWindow::setupAttributionPrivacyView()
{
    const AttributionPrivacy::Store store;
    const AttributionPrivacySettings settings = store.load();

    // Set the stored values without treating them as user edits.
    {
        QSignalBlocker dns(ui->chkCollectDns);
        QSignalBlocker tls(ui->chkCollectTlsSni);
        QSignalBlocker quic(ui->chkCollectQuic);
        QSignalBlocker redact(ui->chkRedactDestinations);
        QSignalBlocker retention(ui->spinAttributionRetention);

        ui->chkCollectDns->setChecked(settings.collectDns);
        ui->chkCollectTlsSni->setChecked(settings.collectTlsSni);
        ui->chkCollectQuic->setChecked(settings.collectQuic);
        ui->chkRedactDestinations->setChecked(settings.redactDestinationsInExport);
        ui->spinAttributionRetention->setValue(
            qBound(1, settings.retentionSeconds / 60, 1440));
    }

    for (QCheckBox *box : {ui->chkCollectDns, ui->chkCollectTlsSni,
                           ui->chkCollectQuic, ui->chkRedactDestinations}) {
        connect(box, &QCheckBox::toggled, this, &MainWindow::applyAttributionPrivacy);
    }
    connect(ui->spinAttributionRetention, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &MainWindow::applyAttributionPrivacy);
    connect(ui->btnClearAttribution, &QPushButton::clicked,
            this, &MainWindow::onClearAttributionHistory);
    connect(ui->btnExportAttribution, &QPushButton::clicked,
            this, &MainWindow::onExportAttribution);

    applyAttributionPrivacy();
}

void MainWindow::setupAiProviderView()
{
    refreshAiProviderUi();

    connect(ui->chkAiProviderEnabled, &QCheckBox::toggled,
            this, &MainWindow::saveAiProviderSettings);
    connect(ui->btnSaveAiProviderSettings, &QPushButton::clicked,
            this, &MainWindow::saveAiProviderSettings);
    connect(ui->lineAiProviderEndpoint, &QLineEdit::returnPressed,
            this, &MainWindow::saveAiProviderSettings);
    connect(ui->lineAiProviderModel, &QLineEdit::returnPressed,
            this, &MainWindow::saveAiProviderSettings);

    // The approval dialog can also change these settings, so re-read them when
    // the Settings tab is shown.
    connect(m_pages, &QStackedWidget::currentChanged, this, [this](int) {
        if (m_pages->currentWidget() == ui->tabSettings)
            refreshAiProviderUi();
    });
}

void MainWindow::refreshAiProviderUi()
{
    const AiProviderSettings settings = AiProviderSettingsStore().load();

    {
        QSignalBlocker enabled(ui->chkAiProviderEnabled);
        QSignalBlocker endpoint(ui->lineAiProviderEndpoint);
        QSignalBlocker model(ui->lineAiProviderModel);

        ui->chkAiProviderEnabled->setChecked(settings.enabled);
        ui->lineAiProviderEndpoint->setText(settings.endpoint);
        ui->lineAiProviderModel->setText(settings.model);
    }

    ui->lineAiProviderEndpoint->setEnabled(settings.enabled);
    ui->lineAiProviderModel->setEnabled(settings.enabled);

    if (!settings.enabled) {
        ui->lblAiProviderStatus->setText(
            QStringLiteral("AI is off. Local recommendations work without it."));
    } else if (settings.isUsable()) {
        ui->lblAiProviderStatus->setText(
            QStringLiteral("AI is configured. Nothing is sent until you press the "
                           "button in the approval dialog."));
    } else {
        ui->lblAiProviderStatus->setText(
            QStringLiteral("AI is enabled but not usable: %1")
                .arg(settings.endpointProblem().isEmpty()
                         ? QStringLiteral("set an endpoint and a model")
                         : settings.endpointProblem()));
    }
}

void MainWindow::saveAiProviderSettings()
{
    AiProviderSettingsStore store;
    AiProviderSettings settings = store.load();
    settings.enabled = ui->chkAiProviderEnabled->isChecked();
    settings.endpoint = ui->lineAiProviderEndpoint->text().trimmed();
    settings.model = ui->lineAiProviderModel->text().trimmed();

    const bool saved = store.save(settings);
    if (m_netWidget)
        m_netWidget->reloadAiProviderSettings();

    refreshAiProviderUi();

    if (!saved) {
        ui->lblAiProviderStatus->setText(
            QStringLiteral("The AI provider settings could not be saved."));
    } else if (settings.enabled && !settings.isUsable()) {
        ui->lblAiProviderStatus->setText(
            QStringLiteral("Settings saved, but AI is not usable yet: %1")
                .arg(settings.endpointProblem().isEmpty()
                         ? QStringLiteral("set an endpoint and a model")
                         : settings.endpointProblem()));
    } else {
        ui->lblAiProviderStatus->setText(
            QStringLiteral("Settings saved. The API key still comes from "
                           "OASIS_AI_API_KEY."));
    }
}

void MainWindow::applyAttributionPrivacy()
{
    AttributionPrivacySettings settings;
    settings.collectDns = ui->chkCollectDns->isChecked();
    settings.collectTlsSni = ui->chkCollectTlsSni->isChecked();
    settings.collectQuic = ui->chkCollectQuic->isChecked();
    settings.retentionSeconds = ui->spinAttributionRetention->value() * 60;
    settings.redactDestinationsInExport = ui->chkRedactDestinations->isChecked();

    const AttributionPrivacy::Store store;
    store.save(settings);

    if (m_netWidget) {
        if (NetworkMonitor *monitor = m_netWidget->networkMonitor())
            monitor->setAttributionPrivacy(settings);
    }

    refreshAttributionHistory();
}

void MainWindow::refreshAttributionHistory()
{
    NetworkMonitor *monitor = m_netWidget ? m_netWidget->networkMonitor() : nullptr;
    const int records = monitor ? monitor->attributionRecordCount() : 0;

    if (records == 0) {
        ui->lblAttributionHistory->setText(
            QStringLiteral("No attribution history is retained."));
        return;
    }

    ui->lblAttributionHistory->setText(
        QStringLiteral("%1 destination name record%2 retained (kept for %3).")
            .arg(records)
            .arg(records == 1 ? QString() : QStringLiteral("s"))
            .arg(AttributionPrivacy::retentionDescription(
                ui->spinAttributionRetention->value() * 60)));
}

void MainWindow::onClearAttributionHistory()
{
    const auto answer = QMessageBox::question(
        this, "Clear attribution history",
        "Delete the domain names observed for connections? Passive DNS and TLS "
        "metadata will start collecting again immediately if it is enabled.");
    if (answer != QMessageBox::Yes)
        return;

    if (m_netWidget) {
        if (NetworkMonitor *monitor = m_netWidget->networkMonitor())
            monitor->clearAttributionHistory();
    }
    refreshAttributionHistory();
}

void MainWindow::onClearDiagnostics()
{
    if (DiagnosticsModel *diag = m_netWidget ? m_netWidget->diagnosticsModel() : nullptr)
        diag->clear();
}

void MainWindow::onExportHistory()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Export History", QDir::homePath() + "/Oasis_History.csv", "CSV Files (*.csv)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not create the file.");
        return;
    }

    QTextStream out(&file);
    out << "Category,Download,Upload,Total Traffic\n";

    for (int i = 0; i < ui->treeHistory->topLevelItemCount(); ++i) {
        QTreeWidgetItem *top = ui->treeHistory->topLevelItem(i);
        out << QString("\"%1\",\"%2\",\"%3\",\"%4\"\n")
                   .arg(top->text(0), top->text(1), top->text(2), top->text(3));

        for (int j = 0; j < top->childCount(); ++j) {
            QTreeWidgetItem *child = top->child(j);
            out << QString("\" - %1\",\"%2\",\"%3\",\"%4\"\n")
                       .arg(child->text(0), child->text(1), child->text(2), child->text(3));
        }
    }

    file.close();
    QMessageBox::information(this, "Export Successful", "Network history exported successfully!");
}

void MainWindow::loadHistoryFromJson()
{
    QFile file(m_historyFilePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    QByteArray data = file.readAll();
    file.close();

    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) return;

    QJsonObject rootObj = doc.object();
    for (const QString &dateKey : rootObj.keys()) {
        QJsonObject appsObj = rootObj.value(dateKey).toObject();
        for (const QString &appName : appsObj.keys()) {
            QJsonObject statsObj = appsObj.value(appName).toObject();
            DailyAppStat stat;
            stat.rxBytes = static_cast<quint64>(statsObj.value("rx").toDouble());
            stat.txBytes = static_cast<quint64>(statsObj.value("tx").toDouble());
            stat.exePath = statsObj.value("path").toString();
            m_historyData[dateKey][appName] = stat;
        }
    }
}

void MainWindow::saveHistoryToJson()
{
    if (m_historyFilePath.isEmpty()) return;

    QJsonObject rootObj;
    for (auto dateIt = m_historyData.constBegin(); dateIt != m_historyData.constEnd(); ++dateIt) {
        QJsonObject appsObj;
        for (auto appIt = dateIt.value().constBegin(); appIt != dateIt.value().constEnd(); ++appIt) {
            QJsonObject statObj;
            statObj["rx"] = static_cast<double>(appIt.value().rxBytes);
            statObj["tx"] = static_cast<double>(appIt.value().txBytes);
            if (!appIt.value().exePath.isEmpty()) {
                statObj["path"] = appIt.value().exePath;
            }
            appsObj[appIt.key()] = statObj;
        }
        rootObj[dateIt.key()] = appsObj;
    }

    QJsonDocument doc(rootObj);
    QFile file(m_historyFilePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        file.write(doc.toJson(QJsonDocument::Compact));
        file.close();
    }
}

// ============================================================================
// Settings Management
// ============================================================================

