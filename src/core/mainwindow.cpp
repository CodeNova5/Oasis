/*
 =============================================================================
    Copyright (c) 2026  Oasis  |  All Rights Reserved
 =============================================================================
*/
/**
 * @file    mainwindow.cpp
 * @author  Oasis
 * @brief   Main window shell: construction, navigation, settings and shutdown.
 *
 * Page wiring lives in mainwindowpages.cpp and the tray/notification/update
 * handling in mainwindowtray.cpp.
 */
#include "mainwindow_p.h"

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

    if (QScreen *scr = QGuiApplication::primaryScreen())
        move(scr->availableGeometry().center() - rect().center());

    buildShell();
    setupWidgets();
    setupOverview();
    setupDiagnosticsView();
    setupAuditLogView();
    setupAttributionPrivacyView();
    setupAiProviderView();
    setupTray();

    loadSettings();
    initHistoryManager();
    setupActivity();
    setupApplications();
    setupConnections();
    setupPolicies();

    ui->cmbOverlayRamFormat->setCurrentIndex(0);

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
        QStringList gpuNames = m_hwMonitor ? m_hwMonitor->enumerateGpuNames()
                                          : QStringList();
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
    saveActivitySeries();
    if (m_hwMonitor) {
        // The sampling thread is owned by this window, so it is stopped here
        // rather than left to outlive the widgets it reports to.
        m_hwMonitor->stopMonitor();
        m_hwMonitor->wait(3000);
    }
    delete m_overlay;
    delete ui;
}

// ============================================================================
// History Engine (Smart Data Extraction & Persistence)
// ============================================================================

// ============================================================================
// History Engine (Smart Data Extraction & Persistence with Tree Logic)
// ============================================================================


void MainWindow::loadSettings()
{
    QSettings settings("Oasis", "Oasis");

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
    QSettings settings("Oasis", "Oasis");

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
    if (m_hwMonitor)
        m_hwMonitor->setGpuIndex(gpuMonitorIdx);

    saveSettings();
}

void MainWindow::applyRunAtStartup(bool enable)
{
    QSettings boot("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
    if (enable) {
        // Always use the canonical installed path (Program Files\Oasis)
        QString appPath = QDir::toNativeSeparators(AppInstaller::installedExePath());
        boot.setValue("Oasis", "\"" + appPath + "\"");
    } else {
        boot.remove("Oasis");
    }
}


// ============================================================================
// Core Window Methods
// ============================================================================

// ============================================================================
// Application shell (sidebar + header + page stack + status bar)
// ============================================================================

void MainWindow::buildShell()
{
    // Detach the existing screens from the legacy tab widget. Their internal
    // UI is intentionally untouched: the redesigned Overview/Activity/...
    // pages are added here in later phases, one destination at a time.
    QWidget *oldRoot = takeCentralWidget();
    QTabWidget *tabs = ui->mainTabs;

    // Policies and Hardware owned their screens in separate widget classes;
    // those are retired to legacy/ and are no longer part of mainwindow.ui.
    const QList<QWidget *> existingPages = {
        ui->tabNetwork, ui->tabDataSaver, ui->tabHistory, ui->tabSettings
    };
    for (QWidget *page : existingPages) {
        if (!page)
            continue;
        const int index = tabs->indexOf(page);
        if (index >= 0)
            tabs->removeTab(index);
        // Kept parented but hidden. The legacy screens still own the services
        // the redesigned pages read from (capture, policies, audit, hardware),
        // so nothing is destroyed while the product is replaced screen by
        // screen. None of them is reachable from the new shell.
        page->setParent(this);
        page->hide();
    }
    delete oldRoot;

    auto *root = new QWidget(this);
    auto *rootLayout = new QVBoxLayout(root);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    auto *workspace = new QWidget(root);
    auto *workspaceLayout = new QHBoxLayout(workspace);
    workspaceLayout->setContentsMargins(0, 0, 0, 0);
    workspaceLayout->setSpacing(0);

    m_sidebar = new AppSidebar(workspace);

    auto *mainColumn = new QWidget(workspace);
    auto *columnLayout = new QVBoxLayout(mainColumn);
    columnLayout->setContentsMargins(0, 0, 0, 0);
    columnLayout->setSpacing(0);

    m_header = new AppHeader(mainColumn);
    m_pages = new QStackedWidget(mainColumn);
    m_pages->setObjectName(QStringLiteral("PageSurface"));
    columnLayout->addWidget(m_header);
    columnLayout->addWidget(m_pages, 1);

    workspaceLayout->addWidget(m_sidebar);
    workspaceLayout->addWidget(mainColumn, 1);

    m_statusBar = new SystemStatusBar(root);
    rootLayout->addWidget(workspace, 1);
    rootLayout->addWidget(m_statusBar);

    setCentralWidget(root);

    // Sidebar item index and stack index are kept identical so navigation is
    // a single number rather than a lookup table.
    auto addScreen = [this](const QString &label, QWidget *page,
                            const QString &title, const QString &subtitle) {
        m_sidebar->addItem(label);
        m_pages->addWidget(page);
        m_screenTitles << title;
        m_screenSubtitles << subtitle;
    };

    // NG-054 → Screen 01: the redesigned Overview owns the landing screen.
    // The legacy network tab is never added to the stack; it stays alive only
    // as the hidden host of NetworkWidget's capture and policy services.
    m_overview = new OverviewPage;
    addScreen(QStringLiteral("Overview"), m_overview,
              QStringLiteral("Overview"),
              QStringLiteral("Activity, controls and anomalies at a glance"));
    m_overviewIndex = m_screenTitles.size() - 1;
    m_activity = new ActivityPage;
    addScreen(QStringLiteral("Activity"), m_activity,
              QStringLiteral("Activity"),
              QStringLiteral("Bandwidth spikes, unrecognized traffic and policy actions"));
    m_activityIndex = m_screenTitles.size() - 1;
    m_applications = new ApplicationsPage;
    addScreen(QStringLiteral("Applications"), m_applications,
              QStringLiteral("Applications"),
              QStringLiteral("Manage network access for each application."));
    m_applicationsIndex = m_screenTitles.size() - 1;
    // Applications is the first screen whose controls belong in the page header.
    m_header->setPageActions(m_applications->actionsWidget());
    m_connections = new ConnectionsPage;
    addScreen(QStringLiteral("Connections"), m_connections,
              QStringLiteral("Connections"),
              QStringLiteral("Domains, IPs and evidence"));
    m_connectionsIndex = m_screenTitles.size() - 1;

    // The legacy tabs behind these destinations (Data Saver, History, Hardware,
    // Settings) are detached and excluded from the build. Their services keep
    // running; only the screens are gone until each is rebuilt.
    m_policies = new PoliciesPage;
    addScreen(QStringLiteral("Policies"), m_policies,
              QStringLiteral("Policies"),
              QStringLiteral("Rules and enforcement status"));
    m_policiesIndex = m_screenTitles.size() - 1;
    addScreen(QStringLiteral("Insights"),
              makePlaceholderPage(QStringLiteral("Insights"),
                  QStringLiteral("Recommendations are being rebuilt as a dedicated "
                                 "screen. Local recommendations remain available on Overview.")),
              QStringLiteral("Insights"),
              QStringLiteral("Anomalies and recommendations"));

    addScreen(QStringLiteral("Reports"),
              makePlaceholderPage(QStringLiteral("Reports"),
                  QStringLiteral("The audit log and its exports are being rebuilt as a "
                                 "dedicated screen. Events are still recorded locally.")),
              QStringLiteral("Reports"),
              QStringLiteral("Event traceability and exports"));

    // Settings is now a real screen: its first section is the detection
    // profile, which the host applies to the live detector below.
    const Activity::DetectionProfile storedProfile =
        Activity::DetectionProfileStore().load();
    m_activityDetector.setSettings(Activity::detectionSettings(storedProfile));
    m_settingsPage = new SettingsPage;
    m_settingsPage->setDetectionProfile(storedProfile);
    addScreen(QStringLiteral("Settings"), m_settingsPage,
              QStringLiteral("Settings"),
              QStringLiteral("Detection, privacy, diagnostics and preferences"));
    m_settingsIndex = m_screenTitles.size() - 1;

    connect(m_settingsPage, &SettingsPage::detectionProfileChanged, this,
            [this](Activity::DetectionProfile profile) {
        Activity::DetectionProfileStore().save(profile);
        // Apply immediately. Evidence gathered under the previous profile is
        // dropped so a half-finished window cannot fire under new numbers;
        // events already in the feed keep their original classification.
        m_activityDetector.setSettings(Activity::detectionSettings(profile));
        m_activityDetector.clear();
    });

    connect(m_sidebar, &AppSidebar::itemActivated, this, &MainWindow::navigateTo);
    connect(m_statusBar, &SystemStatusBar::warningActivated, this, [this]() {
        navigateTo(m_settingsIndex);
    });
    connect(m_statusBar, &SystemStatusBar::messageActivated,
            this, &MainWindow::openLastNotificationSubject);

    // The Overview page navigates; it never performs an action itself.
    connect(m_overview, &OverviewPage::activityRequested, this, [this]() {
        // Overview shows the last 30 seconds, so the matching Activity range is
        // Live rather than the screen's default hour.
        if (m_activity)
            m_activity->setRange(Activity::Range::Live);
        navigateTo(m_activityIndex);
    });
    connect(m_overview, &OverviewPage::applicationsRequested, this, [this]() {
        navigateTo(m_applicationsIndex);
    });
    connect(m_overview, &OverviewPage::policiesRequested, this, [this]() {
        navigateTo(m_policiesIndex);
    });
    connect(m_overview, &OverviewPage::diagnosticsRequested, this, [this]() {
        navigateTo(m_settingsIndex);
    });
    connect(m_overview, &OverviewPage::monitoringRequested, this, [this]() {
        if (m_netWidget)
            m_netWidget->startMonitoring();
    });
    // A consumer row opens the existing application evidence view, so the
    // redesigned screen reuses one investigation path instead of a second one.
    connect(m_overview, &OverviewPage::applicationActivated, this,
            [this](quint32 pid, const QString &path, const QString &name) {
        if (m_netWidget)
            m_netWidget->showApplicationDetails(pid, path, name);
    });
    // An alert is followed to the audit log, which is where its evidence lives.
    connect(m_overview, &OverviewPage::alertActivated, this, [this](int) {
        navigateTo(m_settingsIndex);
    });

    // Activity actions route to the existing policy editor, policy list and
    // application evidence view. The page itself owns no enforcement path.
    if (m_activity) {
        connect(m_activity, &ActivityPage::policyRequested, this,
                [this](quint32 pid, const QString &path, const QString &name) {
            if (m_netWidget)
                m_netWidget->showPolicyEditorFor(pid, path, name);
        });
        connect(m_activity, &ActivityPage::policiesRequested, this, [this]() {
            if (m_netWidget)
                m_netWidget->showPolicies();
        });
        connect(m_activity, &ActivityPage::applicationRequested, this,
                [this](quint32 pid, const QString &path, const QString &name) {
            if (m_netWidget)
                m_netWidget->showApplicationDetails(pid, path, name);
        });
        connect(m_activity, &ActivityPage::dismissRequested, this,
                [this](const QString &id) {
            QSettings settings;
            QStringList dismissed = settings.value(
                QStringLiteral("Oasis/Activity/DismissedIds")).toStringList();
            if (!dismissed.contains(id)) {
                dismissed.append(id);
                settings.setValue(QStringLiteral("Oasis/Activity/DismissedIds"),
                                  dismissed);
                if (m_statusBar)
                    m_statusBar->setMessage(QStringLiteral(
                        "Activity event dismissed. It stays hidden on this device."));
            }
        });
        connect(m_activity, &ActivityPage::exportRequested,
                this, &MainWindow::exportActivityFeed);
        connect(m_activity, &ActivityPage::simulateRequested, this, [this]() {
            Activity::Event event;
            event.at = QDateTime::currentDateTime();
            event.category = Activity::Category::Spike;
            event.badge = QStringLiteral("Simulated Spike");
            event.title = QStringLiteral("Download spike on sample-download.exe");
            event.description = QStringLiteral(
                "Example event from the debug control. This was not observed and "
                "is never counted as telemetry.");
            event.appName = QStringLiteral("sample-download.exe");
            event.destination = QStringLiteral("cdn.example.net");
            event.attribution = QStringLiteral("Simulated");
            event.volumeBytes = 48ull * 1024 * 1024;
            event.peakBytesPerSecond = 12ull * 1024 * 1024;
            event.simulated = true;
            event.id = Activity::makeEventId(event.category, event.at,
                                            event.appName,
                                            QStringLiteral("simulated"));
            appendActivityEvent(event);
            if (m_activity)
                m_activity->setEvents(m_activityEvents);
        });
    }

    navigateTo(m_overviewIndex);
}

QWidget *MainWindow::makePlaceholderPage(const QString &title, const QString &detail)
{
    auto *page = new QWidget;
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(Theme::Dim::SpaceXl, Theme::Dim::SpaceXl,
                              Theme::Dim::SpaceXl, Theme::Dim::SpaceXl);
    outer->setSpacing(0);

    auto *card = new QFrame(page);
    card->setProperty("uiRole", QStringLiteral("emptyState"));
    card->setMaximumWidth(420);

    auto *cardLayout = new QVBoxLayout(card);
    cardLayout->setContentsMargins(Theme::Dim::Space2Xl, Theme::Dim::Space2Xl,
                                   Theme::Dim::Space2Xl, Theme::Dim::Space2Xl);
    cardLayout->setSpacing(Theme::Dim::SpaceSm);

    auto *heading = new QLabel(title, card);
    heading->setProperty("uiRole", QStringLiteral("emptyTitle"));
    heading->setAlignment(Qt::AlignCenter);

    auto *body = new QLabel(detail, card);
    body->setProperty("uiRole", QStringLiteral("emptyText"));
    body->setWordWrap(true);
    body->setAlignment(Qt::AlignCenter);

    cardLayout->addWidget(heading);
    cardLayout->addWidget(body);

    auto *row = new QHBoxLayout;
    row->addStretch(1);
    row->addWidget(card);
    row->addStretch(1);

    outer->addStretch(1);
    outer->addLayout(row);
    outer->addStretch(1);
    return page;
}

void MainWindow::navigateTo(int index)
{
    if (!m_pages || index < 0 || index >= m_pages->count())
        return;
    m_pages->setCurrentIndex(index);
    if (m_sidebar)
        m_sidebar->setCurrentIndex(index);
    // This screen has not been rebuilt since it was last visible, so refresh it
    // from the latest beat now instead of leaving stale figures on show for up
    // to a second.
    refreshVisiblePage();
    if (m_header && index < m_screenTitles.size()) {
        m_header->setPage(m_screenTitles.at(index),
                          m_screenSubtitles.value(index));
        // Each rebuilt screen owns the header controls its mock puts there.
        if (index == m_applicationsIndex && m_applications)
            m_header->setPageActions(m_applications->actionsWidget());
        else if (index == m_connectionsIndex && m_connections)
            m_header->setPageActions(m_connections->actionsWidget());
        m_header->setPageActionsVisible(index == m_applicationsIndex
                                       || index == m_connectionsIndex);
    }
}


void MainWindow::closeEvent(QCloseEvent *event)
{
    hide();
    rememberNotificationSubject(0, QString(), QString());
    AppNotification notification;
    notification.key = QStringLiteral("tray-background");
    notification.title = QStringLiteral("Oasis");
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
