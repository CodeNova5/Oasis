/**
 =============================================================================
    Oasis
    Copyright © 2026  Oasis  |  All Rights Reserved
 -----------------------------------------------------------------------------
    GitHub   : https://github.com/CodeNova5/Oasis
 =============================================================================
*/

// -- Windows first ------------------------------------------------------------
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <shellapi.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <tchar.h>

// -- Qt -----------------------------------------------------------------------
#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QIcon>
#include <QPixmap>
#include <QByteArray>
#include <QStyle>
#include <QDebug>
#include <QTcpSocket>
#include <QCryptographicHash>
#include <QList>
#include <QMessageBox>
#include <QPair>
#include <QSharedMemory>
#include <QFile>
#include <QSettings>
#include <QDir>
#include <QStorageInfo>
#include <QScreen>

// -- Project ------------------------------------------------------------------
#include "core/version.h"
#include "ui/webview2/webuiwindow.h"
#include "ui/theme/thememanager.h"
#include "core/appinstaller.h"
#include "core/servicehost.h"
#include "network/datasavernotification.h"
#include "network/networkwidget.h"
#include "taskbar/systemtrayicon.h"
#include "hardware/hardwaremonitor.h"    // Q_DECLARE_METATYPE(HardwareSnapshot)
#include "network/packetparser.h"        // Q_DECLARE_METATYPE(ParsedPacket)

// -----------------------------------------------------------------------------
// Admin check / elevation
// -----------------------------------------------------------------------------
static bool isAdmin()
{
    BOOL   admin = FALSE;
    PSID   sid   = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0,0,0,0,0,0, &sid))
    {
        CheckTokenMembership(nullptr, sid, &admin);
        FreeSid(sid);
    }
    return admin == TRUE;
}

static void elevate(const QString &exe)
{
    const std::wstring path = exe.toStdWString();
    SHELLEXECUTEINFOW sei   = {};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = path.c_str();
    sei.nShow  = SW_SHOWNORMAL;
    ShellExecuteExW(&sei);
}

// -----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    // -- DPI awareness --------------------------------------------------------
    // Per-monitor (V2) awareness is declared in app.manifest and embedded into
    // the executable via appicon.rc, so Windows applies it before main() runs:
    // the window receives WM_DPICHANGED and each screen reports its own scale
    // factor. Qt 6 turns high-DPI scaling on by itself; pinning the rounding
    // policy to PassThrough keeps fractional factors (125%, 150%) at their true
    // ratio so the window and the policy dialog scale with the monitor instead
    // of snapping between 100% and 200%.
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);

    // -- App Initialization ---------------------------------------------------
    QApplication app(argc, argv);
    app.setApplicationName(APP_NAME);
    app.setApplicationVersion(APP_VERSION_STR);
    app.setOrganizationName(APP_COMPANY);

    // -- Admin elevation ------------------------------------------------------
    if (!isAdmin())
    {
        elevate(QCoreApplication::applicationFilePath());
        return 0;
    }

    // -- Self-install / auto-update check -------------------------------------
    // Must run BEFORE the single-instance guard: the installed copy holds the
    // shared memory lock, and this instance may need to replace it.
    // Copies exe to Program Files\Oasis on first run, or replaces an older
    // build on update. Returns false when it relaunched the installed copy
    // (this instance must exit).
    if (!AppInstaller::run())
        return 0;

    // -- Single-instance lock (QSharedMemory) ---------------------------------
    QSharedMemory sharedMemory("Oasis_SharedMemory");
    if (!sharedMemory.create(1))
    {
        // Another instance is already running
        QString winTitle = QString("%1 Version %2").arg(APP_NAME, APP_VERSION_STR);
        std::wstring wTitle = winTitle.toStdWString();
        HWND hw = FindWindowW(nullptr, wTitle.c_str());
        if (hw) { ShowWindow(hw, SW_RESTORE); SetForegroundWindow(hw); }
        return 0;
    }

    // -- CRITICAL: Register custom types BEFORE any thread connections --------
    qRegisterMetaType<HardwareSnapshot>("HardwareSnapshot");
    qRegisterMetaType<ParsedPacket>("ParsedPacket");

    // -- Runtime icon ---------------------------------------------------------
    // Load PNG from Qt Resources (.qrc)
    QIcon appIcon(":/icons/Oasis.png");

    // Fallback if PNG is missing from resources
    if (appIcon.isNull()) {
        qWarning() << "PNG Icon not found in resources! Trying ICO...";
        appIcon = QIcon(":/icons/app.ico");
    }

    // Set the global window icon for the entire application
    QApplication::setWindowIcon(appIcon);

    // -- Apply theme ----------------------------------------------------------
    // Resolves design tokens (src/ui/theme) into the styles/ partials and installs the
    // matching QPalette + Segoe UI Variable font.
    ThemeManager::instance().apply(&app);

    // -- Start the backend services -------------------------------------------
    // Capture, policy, enforcement, notifications, and Activity collection
    // run independently of the web window for the whole process lifetime.
    ServiceHost services;
    services.start();

    // -- Show the web UI ------------------------------------------------------
    // The window hosts the single Preact + HTM bundle edge to edge; all visible
    // application UI comes from web/ui.
    WebUiWindow w(QStringLiteral("web/ui/dist"), QStringLiteral("index.html"),
                  QStringLiteral("Oasis"), &services);
    // The single-instance guard above finds the running window by this exact
    // title, so it has to keep the "App Version x.y.z" form.
    w.setWindowTitle(QStringLiteral("%1 Version %2").arg(APP_NAME, APP_VERSION_STR));
    w.setWindowIcon(appIcon);
    w.showMaximized();

    // -- Tray alert and Data Saver notice actions ------------------------------
    // The tray carries the passive alert (a Windows tray balloon has no
    // buttons) plus the actions of the latest notice in its menu; the page in
    // the window carries the actionable card. Both address the notice by the
    // key the coordinator delivered it under.
    SystemTrayIcon tray;
    tray.show();

    auto bringWindowForward = [&w] {
        w.showMaximized();
        w.raise();
        w.activateWindow();
    };
    QObject::connect(&tray, &SystemTrayIcon::showRequested, &w, bringWindowForward);
    QObject::connect(&tray, &SystemTrayIcon::quitRequested, &app, [&app] { app.quit(); });

    QObject::connect(&services, &ServiceHost::notificationPosted, &tray,
                     [&tray](const AppNotification &notification, int suppressedCount) {
        QString message = notification.message;
        if (suppressedCount > 0) {
            message += QStringLiteral("\n(+%1 similar notices folded)").arg(suppressedCount);
        }
        tray.showNotice(notification.title, message,
                        notification.priority == NotificationPriority::Critical);

        QList<QPair<QString, QString>> actions;
        for (const QString &token : notification.actions) {
            const QString label = DataSaverNotifications::actionLabel(token);
            if (!label.isEmpty())
                actions.append(qMakePair(token, label));
        }
        tray.setNoticeActions(notification.key, actions);
    });

    QObject::connect(&tray, &SystemTrayIcon::noticeActionRequested, &tray,
                     [&services, &tray, &w, bringWindowForward](
                         const QString &noticeKey, const QString &token) {
        NetworkWidget *network = services.network();
        if (!network)
            return;

        // Inspect renders the retained evidence in the page, so the tray action
        // only brings the window forward.
        if (token == DataSaverNotifications::inspectActionToken()) {
            bringWindowForward();
            return;
        }

        QString error;
        if (token == DataSaverNotifications::allowOnceActionToken()) {
            if (network->allowOnceForNotice(noticeKey, &error)) {
                // The notice is resolved now; do not offer the same reversal
                // again from a stale menu.
                tray.setNoticeActions(noticeKey, QList<QPair<QString, QString>>());
                tray.showNotice(QStringLiteral("Allowed once"),
                                QStringLiteral("The control is paused for this flow for one hour."),
                                false);
            } else {
                tray.showNotice(QStringLiteral("Could not allow the flow"),
                                error.isEmpty()
                                    ? QStringLiteral("The session override was refused.")
                                    : error,
                                true);
            }
            return;
        }

        if (token != DataSaverNotifications::alwaysAllowActionToken())
            return;

        // Always Allow is tier 1, so it needs the explicit confirmation the
        // pinned store enforces (DS-005).
        DataSaverNotifications::DecisionNotice evidence;
        QString application;
        if (network->noticeEvidence(noticeKey, &evidence)) {
            application = DataSaverNotifications::evidenceSummary(evidence)
                              .value(QStringLiteral("executable"))
                              .toString();
        }
        const QString question =
            (application.isEmpty()
                 ? QStringLiteral("Create a permanent allow rule for this application?")
                 : QStringLiteral("Create a permanent allow rule for %1?").arg(application))
            + QStringLiteral("\n\nA pinned rule survives Data Saver Off and takes "
                             "precedence over automatic controls.");
        if (QMessageBox::question(nullptr, QStringLiteral("Always allow"), question,
                                  QMessageBox::Yes | QMessageBox::No, QMessageBox::No)
            != QMessageBox::Yes) {
            return;
        }

        if (network->alwaysAllowForNotice(noticeKey, true, &error)) {
            tray.setNoticeActions(noticeKey, QList<QPair<QString, QString>>());
            tray.showNotice(
                QStringLiteral("Always allowed"),
                application.isEmpty()
                    ? QStringLiteral("A pinned allow rule was saved.")
                    : QStringLiteral("%1 is now allowed by a pinned rule.").arg(application),
                false);
        } else {
            tray.showNotice(QStringLiteral("Could not save the rule"),
                            error.isEmpty() ? QStringLiteral("The pinned rule was refused.")
                                            : error,
                            true);
        }
    });

    const int exitCode = app.exec();

    // The window is gone but the capture thread is still running; stop it while
    // the application object is alive so its workers shut down in order.
    services.stop();

    return exitCode;
}
