/**
 * @file    mainwindow.h
 * @author  Oasis
 * @brief   Main Window definition with intelligent History Management and JSON persistence.
 */
#pragma once

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QLabel>
#include <QSettings>
#include <QMap>
#include <QHash>
#include <QIcon>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QStringList>

#include "ui/theme/thememanager.h"
#include "hardware/hardwaremonitor.h"
#include "network/notificationcoordinator.h"

namespace Ui { class MainWindow; }

class NetworkWidget;
class FirewallWidget;
class HardwareWidget;
class TaskbarOverlay;
class DiagnosticsModel;
class AuditLogModel;
class AppSidebar;
class AppHeader;
class SystemStatusBar;
class QStackedWidget;
struct BandwidthEvent;

// Data structure to hold daily traffic per application
struct DailyAppStat {
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    QString exePath;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent  (QCloseEvent *event) override;
    void changeEvent (QEvent *event)      override;

private slots:
    void onToggleTheme();
    void onMinimizeToTray();
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void onNetworkSpeed(quint64 rxBps, quint64 txBps);
    void onBandwidthAlert(const BandwidthEvent &event);
    void onDataSaverDetectionMenu(const QPoint &pos);
    void onDataSaverModeChanged(int mode);
    void onRestoreDataSaverPolicies();
    void onHardwareSnapshot(const HardwareSnapshot &snap);

    void saveSettings();
    void applySettingsToOverlay();
    void applyRunAtStartup(bool enable);

    // Shell navigation: switching pages also updates the header title and the
    // sidebar selection, so the three never disagree.
    void navigateTo(int index);

    // NG-052: follow a notification to its evidence. A no-op until a
    // notification has named an application.
    void openLastNotificationSubject();

    void onExportHistory();
    void onClearHistory();
    void onHistoryFilterChanged(int index);

    void refreshDiagnosticsSummary();
    void onExportDiagnostics();
    void onClearDiagnostics();

    // NG-050: the audit view's summary, filtered JSON export, and clear action.
    void refreshAuditSummary();
    void onExportAuditLog();
    void onExportAuditLogCsv();
    void onExportAttribution();
    void onClearAuditLog();

    // NG-036: attribution collection, retention, redaction, and history clearing.
    void applyAttributionPrivacy();
    void onClearAttributionHistory();

    // NG-045: the optional AI provider is configured here as well as in the
    // approval dialog; both views persist through the same store.
    void saveAiProviderSettings();

    void recordLiveTraffic();
    void refreshHistoryUI();
    void saveHistoryToJson();

private:
    void buildShell();
    QWidget *makePlaceholderPage(const QString &title, const QString &detail);
    void setupWidgets();
    void setupDiagnosticsView();
    void setupAuditLogView();
    void setupAttributionPrivacyView();
    void setupAiProviderView();
    void refreshAiProviderUi();
    void refreshAttributionHistory();
    // NG-055: writes an export payload, reporting a failure once so the three
    // export actions behave the same way.
    bool writeExportFile(const QString &fileName, const QString &contents);
    void setupTray();
    // NG-051: one place decides whether a notification reaches the tray, the
    // in-app status line, both, or neither.
    void postNotification(const AppNotification &notification);
    // NG-052: which application the latest notification was about, so a tray
    // click or the status line can open its detail view.
    void rememberNotificationSubject(quint32 pid, const QString &path,
                                     const QString &name);
    void loadSettings();
    void initHistoryManager();
    void loadHistoryFromJson();

    static QString fmtSpeed(quint64 bps);
    static QString fmtBytes(quint64 bytes);

    Ui::MainWindow    *ui          = nullptr;

    AppSidebar        *m_sidebar   = nullptr;
    AppHeader         *m_header    = nullptr;
    SystemStatusBar   *m_statusBar = nullptr;
    QStackedWidget    *m_pages     = nullptr;
    QStringList        m_screenTitles;
    QStringList        m_screenSubtitles;
    int                m_overviewIndex = 0;
    int                m_settingsIndex = 0;

    NetworkWidget     *m_netWidget = nullptr;
    AuditLogModel     *m_auditModel = nullptr;
    FirewallWidget    *m_fwWidget  = nullptr;
    HardwareWidget    *m_hwWidget  = nullptr;
    TaskbarOverlay    *m_overlay   = nullptr;

    QSystemTrayIcon   *m_tray      = nullptr;
    QMenu             *m_trayMenu  = nullptr;
    NotificationCoordinator m_notifications;
    quint32            m_notificationPid  = 0;
    QString            m_notificationPath;
    QString            m_notificationName;

    ThemeManager::Mode m_theme     = ThemeManager::Dark;

    QTimer            *m_trafficMonitorTimer = nullptr;
    QTimer            *m_historyUiTimer      = nullptr;
    QString            m_historyFilePath;
    int                m_saveCounter         = 0;

    QMap<QString, QMap<QString, DailyAppStat>> m_historyData;
    QHash<QString, QIcon> m_iconCache;
};
