/*
 =============================================================================
    Copyright (c) 2026  AliSakkaf  |  All Rights Reserved
 =============================================================================
*/
#include "mainwindow.h"
#include "version.h"
#include "qdebug.h"
#include "ui_mainwindow.h"
#include "ui/theme/thememanager.h"
#include "updatechecker.h"
#include "appinstaller.h"
#include "windowsicon.h"
#include "network/networkwidget.h"
#include "network/bandwidthguard.h"
#include "attribution/attributionconfidence.h"
#include "attribution/attributionprivacy.h"
#include "attribution/aiprovider.h"
#include "network/diagnostics.h"
#include "network/auditlogmodel.h"
#include "network/evidenceexport.h"
#include "network/notificationcoordinator.h"
#include "network/networkmonitor.h"
#include "firewall/firewallwidget.h"
#include "hardware/hardwarewidget.h"
#include "taskbar/taskbaroverlay.h"

#include <QCloseEvent>
#include <QMouseEvent>
#include <windows.h>
#include <shellapi.h>
#include <QTimer>
#include <QStyle>
#include <QScreen>
#include <QGuiApplication>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QApplication>
#include <QDir>
#include <QTreeView>
#include <QTableView>
#include <QHeaderView>
#include <QAbstractItemModel>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QDateTime>
#include <QFileDialog>
#include <QTextStream>
#include <QMessageBox>
#include <QTableWidgetItem>

// How an export says whether destinations were redacted, appended to every
// success message so the file's contents are never a surprise.
static QString exportRedactionNote(bool redacted)
{
    return redacted ? QStringLiteral(" (destinations redacted)")
                    : QStringLiteral(" (verbatim destinations)");
}

// ============================================================================
// Initialization & Core Setup
// ============================================================================

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    QString Title = APP_NAME;
    Title.append(" Version ");
    Title.append(APP_VERSION_STR);
    setWindowTitle(Title);
    ui->versionLabel->setText(APP_VERSION_DISPLAY);

    if (QScreen *scr = QGuiApplication::primaryScreen())
        move(scr->availableGeometry().center() - rect().center());

    setupWidgets();
    setupDiagnosticsView();
    setupAuditLogView();
    setupAttributionPrivacyView();
    setupAiProviderView();
    setupTray();

    // NG-052: the status line shows the latest notification. Make it clickable
    // so the user can go from the alert to the evidence behind it.
    if (ui->statusMsg) {
        ui->statusMsg->installEventFilter(this);
        ui->statusMsg->setCursor(Qt::PointingHandCursor);
        ui->statusMsg->setToolTip(QStringLiteral("Click for the details of the last notification."));
    }

    loadSettings();
    initHistoryManager();

    ui->mainTabs->setCurrentIndex(0);
    ui->cmbOverlayRamFormat->setCurrentIndex(0);


    m_badgeTimer = new QTimer(this);
    m_badgeTimer->setInterval(900);
    connect(m_badgeTimer, &QTimer::timeout, this, &MainWindow::animateLiveBadge);
    m_badgeTimer->start();

    connect(ui->btnThemeToggle, &QPushButton::clicked, this, &MainWindow::onToggleTheme);
    connect(ui->btnMinimizeToTray, &QPushButton::clicked, this, &MainWindow::onMinimizeToTray);

    connect(ui->chkRunAtStartup, &QCheckBox::toggled, this, [this](bool checked){
        applyRunAtStartup(checked);
        saveSettings();
    });
    connect(ui->chkStartMinimized, &QCheckBox::toggled, this, &MainWindow::saveSettings);
        connect(ui->cmbDataSaverMode, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onDataSaverModeChanged);
            connect(ui->btnRestoreDataSaver, &QPushButton::clicked,
                this, &MainWindow::onRestoreDataSaverPolicies);
                connect(ui->cmbDataSaverPageMode, QOverload<int>::of(&QComboBox::currentIndexChanged),
                    this, [this](int mode) {
                    if (ui->cmbDataSaverMode->currentIndex() != mode)
                        ui->cmbDataSaverMode->setCurrentIndex(mode);
                    });
                connect(ui->btnRestoreDataSaverPage, &QPushButton::clicked,
                    this, &MainWindow::onRestoreDataSaverPolicies);
                    ui->tableDataSaverDetections->setContextMenuPolicy(Qt::CustomContextMenu);
                    connect(ui->tableDataSaverDetections, &QTableWidget::customContextMenuRequested,
                        this, &MainWindow::onDataSaverDetectionMenu);

    connect(ui->chkEnableOverlay, &QCheckBox::toggled, this, &MainWindow::applySettingsToOverlay);
    connect(ui->spinOverlayFontSize, QOverload<int>::of(&QSpinBox::valueChanged), this, &MainWindow::applySettingsToOverlay);
    connect(ui->spinOverlayOpacity, QOverload<int>::of(&QSpinBox::valueChanged), this, &MainWindow::applySettingsToOverlay);
    connect(ui->cmbOverlayTextColor, &QComboBox::currentTextChanged, this, &MainWindow::applySettingsToOverlay);
    connect(ui->cmbOverlayBgColor, &QComboBox::currentTextChanged, this, &MainWindow::applySettingsToOverlay);

    connect(ui->chkOverlayCpu,   &QCheckBox::toggled, this, &MainWindow::applySettingsToOverlay);
    connect(ui->chkOverlayRam,   &QCheckBox::toggled, this, &MainWindow::applySettingsToOverlay);
    connect(ui->chkOverlayGpu,   &QCheckBox::toggled, this, &MainWindow::applySettingsToOverlay);
    connect(ui->chkOverlayTemps, &QCheckBox::toggled, this, &MainWindow::applySettingsToOverlay);

    connect(ui->cmbOverlayRamFormat, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::applySettingsToOverlay);
    connect(ui->cmbOverlayGpuSelect, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::applySettingsToOverlay);

    // ── Populate GPU combo with detected GPU names ──
    {
        QStringList gpuNames = m_hwWidget->monitor()->enumerateGpuNames();
        for (const QString &name : gpuNames) {
            ui->cmbOverlayGpuSelect->addItem(name);
        }
    }

    m_netWidget->autoStart();

    // ── Silent background update check (2 seconds after launch) ──
    QTimer::singleShot(2000, this, [this](){
        auto *updater = new UpdateChecker(this, this);
        updater->checkNow();
    });

}

MainWindow::~MainWindow()
{
    saveHistoryToJson(); // Ensure data is saved before exiting
    delete m_overlay;
    delete ui;
}

// ============================================================================
// History Engine (Smart Data Extraction & Persistence)
// ============================================================================

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
    m_historyFilePath = dir.absoluteFilePath("NetGuard_History.json");

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
        if (ui->mainTabs->currentWidget() == ui->tabHistory) {
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
        QDir::homePath() + "/NetGuard_Diagnostics.json", "JSON Files (*.json)");
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
        QDir::homePath() + "/NetGuard_AuditLog.json",
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
        QDir::homePath() + "/NetGuard_AuditLog.csv",
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
                       QDir::homePath() + "/NetGuard_Attribution.json");
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
    connect(ui->mainTabs, &QTabWidget::currentChanged, this, [this](int) {
        if (ui->mainTabs->currentWidget() == ui->tabSettings)
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
                           "NETGUARD_AI_API_KEY."));
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
    QString fileName = QFileDialog::getSaveFileName(this, "Export History", QDir::homePath() + "/NetGuard_History.csv", "CSV Files (*.csv)");
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

void MainWindow::loadSettings()
{
    QSettings settings("AliSakkaf", "NetGuardAIO");

    ui->chkRunAtStartup->setChecked(settings.value("General/RunAtStartup", true).toBool());
    ui->chkStartMinimized->setChecked(settings.value("General/StartMinimized", false).toBool());
    ui->cmbDataSaverMode->setCurrentIndex(settings.value("DataSaver/Mode", 1).toInt());

    bool isDark = settings.value("General/DarkTheme", true).toBool();
    if (!isDark && ThemeManager::instance().isDark()) {
        onToggleTheme();
    }

    ui->chkEnableOverlay->setChecked(settings.value("Overlay/Enabled", true).toBool());
    ui->spinOverlayFontSize->setValue(settings.value("Overlay/FontSize", 8).toInt());
    ui->spinOverlayOpacity->setValue(settings.value("Overlay/Opacity", 0).toInt());
    ui->cmbOverlayTextColor->setCurrentText(settings.value("Overlay/TextColor", "White").toString());
    ui->cmbOverlayBgColor->setCurrentText(settings.value("Overlay/BgColor", "Transparent").toString());

    ui->chkOverlayCpu->setChecked(settings.value("Overlay/ShowCpu", false).toBool());
    ui->chkOverlayRam->setChecked(settings.value("Overlay/ShowRam", false).toBool());
    ui->chkOverlayGpu->setChecked(settings.value("Overlay/ShowGpu", false).toBool());
    ui->chkOverlayTemps->setChecked(settings.value("Overlay/ShowTemps", false).toBool());

    ui->cmbOverlayRamFormat->setCurrentIndex(settings.value("Overlay/RamDisplayMode", 2).toInt());  // Default: GB
    ui->cmbOverlayGpuSelect->setCurrentIndex(settings.value("Overlay/GpuIndex", 0).toInt());        // Default: Auto

    applySettingsToOverlay();

    if (ui->chkStartMinimized->isChecked()) {
        QTimer::singleShot(100, this, &MainWindow::hide);
    }
}

void MainWindow::saveSettings()
{
    QSettings settings("AliSakkaf", "NetGuardAIO");

    settings.setValue("General/RunAtStartup", ui->chkRunAtStartup->isChecked());
    settings.setValue("General/StartMinimized", ui->chkStartMinimized->isChecked());
    settings.setValue("DataSaver/Mode", ui->cmbDataSaverMode->currentIndex());
    settings.setValue("General/DarkTheme", ThemeManager::instance().isDark());

    settings.setValue("Overlay/Enabled", ui->chkEnableOverlay->isChecked());
    settings.setValue("Overlay/FontSize", ui->spinOverlayFontSize->value());
    settings.setValue("Overlay/Opacity", ui->spinOverlayOpacity->value());
    settings.setValue("Overlay/TextColor", ui->cmbOverlayTextColor->currentText());
    settings.setValue("Overlay/BgColor", ui->cmbOverlayBgColor->currentText());

    settings.setValue("Overlay/ShowCpu", ui->chkOverlayCpu->isChecked());
    settings.setValue("Overlay/ShowRam", ui->chkOverlayRam->isChecked());
    settings.setValue("Overlay/ShowGpu", ui->chkOverlayGpu->isChecked());
    settings.setValue("Overlay/ShowTemps", ui->chkOverlayTemps->isChecked());

    settings.setValue("Overlay/RamDisplayMode", ui->cmbOverlayRamFormat->currentIndex());
    settings.setValue("Overlay/GpuIndex", ui->cmbOverlayGpuSelect->currentIndex());
}

void MainWindow::applySettingsToOverlay()
{
    if (!m_overlay) return;

    m_overlay->setOverlayVisible(ui->chkEnableOverlay->isChecked());

    int fontSize = ui->spinOverlayFontSize->value();
    int opacity = ui->spinOverlayOpacity->value();

    QString txtColorHex = "white";
    QString selTxt = ui->cmbOverlayTextColor->currentText();
    if (selTxt == "Black") txtColorHex = "black";
    else if (selTxt == "Green") txtColorHex = "#34D399";
    else if (selTxt == "Blue") txtColorHex = "#60A5FA";
    else if (selTxt == "Yellow") txtColorHex = "#FBBF24";

    QColor bgColor(28, 33, 40);
    QString selBg = ui->cmbOverlayBgColor->currentText();
    if (selBg == "Solid Black") bgColor = Qt::black;
    else if (selBg == "Solid Blue") bgColor = QColor("#1D4ED8");
    else if (selBg == "Transparent") bgColor = Qt::transparent;

    m_overlay->setCustomStyle(fontSize, txtColorHex, opacity, bgColor);

    m_overlay->setShowCpu(ui->chkOverlayCpu->isChecked());
    m_overlay->setShowRam(ui->chkOverlayRam->isChecked());
    m_overlay->setShowGpu(ui->chkOverlayGpu->isChecked());
    m_overlay->setShowTemps(ui->chkOverlayTemps->isChecked());

    // ── RAM display format ──
    int ramFmtIdx = ui->cmbOverlayRamFormat->currentIndex();
    m_overlay->setRamDisplayMode(static_cast<RamDisplayMode>(ramFmtIdx));

    // ── GPU selection (index 0 = Auto = -1, index 1+ = specific GPU) ──
    int gpuSelIdx = ui->cmbOverlayGpuSelect->currentIndex();
    int gpuMonitorIdx = gpuSelIdx - 1;  // -1 means auto/all
    m_overlay->setGpuIndex(gpuMonitorIdx);
    if (m_hwWidget && m_hwWidget->monitor()) {
        m_hwWidget->monitor()->setGpuIndex(gpuMonitorIdx);
    }

    saveSettings();
}

void MainWindow::applyRunAtStartup(bool enable)
{
    QSettings boot("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
    if (enable) {
        // Always use the canonical installed path (Program Files\NetGuard)
        QString appPath = QDir::toNativeSeparators(AppInstaller::installedExePath());
        boot.setValue("NetGuardAIO", "\"" + appPath + "\"");
    } else {
        boot.remove("NetGuardAIO");
    }
}

// ============================================================================
// Core Window Methods
// ============================================================================

void MainWindow::setupWidgets()
{
    m_netWidget = new NetworkWidget(this);
    m_fwWidget  = new FirewallWidget(this);
    m_hwWidget  = new HardwareWidget(this);

    ui->tabNetwork ->layout()->addWidget(m_netWidget);
    ui->tabFirewall->layout()->addWidget(m_fwWidget);
    ui->tabHardware->layout()->addWidget(m_hwWidget);

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

    connect(m_hwWidget->monitor(), &HardwareMonitor::snapshotReady, this, [this](const HardwareSnapshot &snap){
        onHardwareSnapshot(snap);
        if (m_overlay) {
            m_overlay->updateHardware(static_cast<int>(snap.cpuLoadPct), static_cast<int>(snap.ramLoadPct));
            m_overlay->updateFullHardware(snap.cpuLoadPct, snap.ramLoadPct, snap.ramUsedMB, snap.ramTotalMB,
                                          snap.gpuLoadPct, snap.cpuTempC, snap.gpuTempC, 0.0);
        }
    }, Qt::QueuedConnection);

    connect(m_overlay, &TaskbarOverlay::showMainWindowRequested, this, [this](){
        showNormal();
        activateWindow();
        raise();
    });

    connect(m_overlay, &TaskbarOverlay::minimizeRequested, this, [this](){
        hide();
    });

    connect(m_overlay, &TaskbarOverlay::exitRequested, qApp, &QApplication::quit);
}

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

    QIcon trayIcon(":/icons/Ultimate_NetGuard_AIO.png");
    if (trayIcon.isNull()) trayIcon = QIcon(":/icons/app.ico");

    m_tray = new QSystemTrayIcon(trayIcon, this);
    m_tray->setContextMenu(m_trayMenu);
    m_tray->setToolTip("Ultimate NetGuard AIO");
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
    ui->btnThemeToggle->setChecked(m_theme == ThemeManager::Light);
    ui->btnThemeToggle->setText(m_theme == ThemeManager::Dark ? "☀" : "🌙");
    saveSettings();
}

void MainWindow::onMinimizeToTray()
{
    hide();
    // A tray notice is not about an application, so following it would be wrong.
    rememberNotificationSubject(0, QString(), QString());
    AppNotification notification;
    notification.key = QStringLiteral("tray-background");
    notification.title = QStringLiteral("NetGuard AIO");
    notification.message = QStringLiteral("Running in the background. Click the tray icon to restore.");
    postNotification(notification);
}

void MainWindow::rememberNotificationSubject(quint32 pid, const QString &path,
                                             const QString &name)
{
    m_notificationPid = pid;
    m_notificationPath = path.trimmed();
    m_notificationName = name.trimmed();
}

bool MainWindow::eventFilter(QObject *watched, QEvent *event)
{
    if (ui && watched == ui->statusMsg && event->type() == QEvent::MouseButtonRelease) {
        const auto *mouse = static_cast<QMouseEvent *>(event);
        if (mouse->button() == Qt::LeftButton) {
            openLastNotificationSubject();
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
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
    if (ui->mainTabs && ui->tabNetwork)
        ui->mainTabs->setCurrentWidget(ui->tabNetwork);

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

    if (appRoute && ui->statusMsg) {
        QString status = notification.title;
        if (decision.suppressedCount > 0)
            status += QStringLiteral(" (+%1 earlier)").arg(decision.suppressedCount);
        ui->statusMsg->setText(status);
        ui->statusMsg->setToolTip(message);
    }
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick)
        isVisible() ? hide() : (showNormal(), activateWindow(), raise());
}

void MainWindow::onNetworkSpeed(quint64 rxBps, quint64 txBps)
{
    ui->rxLabel->setText("↓ " + fmtSpeed(rxBps));
    ui->txLabel->setText("↑ " + fmtSpeed(txBps));
    m_tray->setToolTip(QString("NetGuard AIO\n↓ %1  ↑ %2").arg(fmtSpeed(rxBps), fmtSpeed(txBps)));
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
                                    "Right-click the process in NetGuard to restore access.");
        } else {
            title = "Internet block failed";
            action = event.firewallMessage.isEmpty()
                ? QStringLiteral("The firewall rule could not be applied.")
                : event.firewallMessage;
        }
    } else if (event.firewallBlocked) {
        title = "Internet access already blocked";
        action = QStringLiteral("This executable is already blocked by a NetGuard firewall rule.");
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
    ui->cpuLabel->setText(QString("CPU %1%").arg(static_cast<int>(snap.cpuLoadPct)));
    ui->ramLabel->setText(QString("RAM %1%").arg(static_cast<int>(snap.ramLoadPct)));
}

void MainWindow::animateLiveBadge()
{
    m_badgeLit = !m_badgeLit;
    ui->liveBadge->setStyleSheet(m_badgeLit ? "color:#2EA043; font-weight:700; font-size:8pt;" : "color:#1A3A22; font-weight:700; font-size:8pt;");
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    hide();
    rememberNotificationSubject(0, QString(), QString());
    AppNotification notification;
    notification.key = QStringLiteral("tray-background");
    notification.title = QStringLiteral("NetGuard AIO");
    notification.message = QStringLiteral("Running in the background.\nDouble-click the tray icon to restore.");
    postNotification(notification);
    event->ignore();
}

void MainWindow::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::WindowStateChange && isMinimized()) {
        hide();
        event->ignore();
        return;
    }
    QMainWindow::changeEvent(event);
}

QString MainWindow::fmtSpeed(quint64 bps)
{
    if (bps < 1024)      return QString("%1 B/s").arg(bps);
    if (bps < 1024*1024) return QString("%1 KB/s").arg(bps/1024.0,0,'f',1);
    return                     QString("%1 MB/s").arg(bps/(1024.0*1024),0,'f',2);
}

QString MainWindow::fmtBytes(quint64 bytes)
{
    if (bytes < 1024)             return QString("%1 B").arg(bytes);
    if (bytes < 1024*1024)        return QString("%1 KB").arg(bytes/1024.0, 0, 'f', 1);
    if (bytes < 1024*1024*1024ULL)return QString("%1 MB").arg(bytes/(1024.0*1024), 0, 'f', 2);
    return                               QString("%1 GB").arg(bytes/(1024.0*1024*1024), 0, 'f', 2);
}
