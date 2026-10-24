/**
 =============================================================================
    UltimateNetGuard
    Copyright © 2026  AliSakkaf  |  All Rights Reserved
 -----------------------------------------------------------------------------
    Website  : https://mysterious-dev.com/
    GitHub   : https://github.com/alisakkaf
    Facebook : https://www.facebook.com/AliSakkaf.Dev/
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
#include <QMessageBox>
#include <QSharedMemory>
#include <QFile>
#include <QSettings>
#include <QDir>
#include <QStorageInfo>
#include <QScreen>

// -- Project ------------------------------------------------------------------
#include "core/version.h"
#include "core/mainwindow.h"
#include "core/apptheme.h"
#include "core/appinstaller.h"
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
    // -- CRITICAL DPI AWARENESS SETTINGS --------------------------------------
    // MUST be set before QApplication initialization to guarantee compatibility
    // across all Windows versions and scaling factors.

    // Disable High DPI Scaling globally
    qputenv("QT_ENABLE_HIGHDPI_SCALING", "0");
    qputenv("QT_AUTO_SCREEN_SCALE_FACTOR", "0");

    // Force Windows to treat the application as DPI Unaware
    qputenv("QT_QPA_PLATFORM", "windows:dpiawareness=0");

#if QT_VERSION < QT_VERSION_CHECK(6,0,0)
    QApplication::setAttribute(Qt::AA_DisableHighDpiScaling);
#endif

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
    // Copies exe to Program Files\NetGuard on first run, or replaces an older
    // build on update. Returns false when it relaunched the installed copy
    // (this instance must exit).
    if (!AppInstaller::run())
        return 0;

    // -- Single-instance lock (QSharedMemory) ---------------------------------
    QSharedMemory sharedMemory("UltimateNetGuardAIO_SharedMemory");
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
    QIcon appIcon(":/icons/Ultimate_NetGuard_AIO.png");

    // Fallback if PNG is missing from resources
    if (appIcon.isNull()) {
        qWarning() << "PNG Icon not found in resources! Trying ICO...";
        appIcon = QIcon(":/icons/app.ico");
    }

    // Set the global window icon for the entire application
    QApplication::setWindowIcon(appIcon);

    // -- Apply dark theme -----------------------------------------------------
    AppTheme::apply(&app, AppTheme::Dark);

    // -- Font Setup -----------------------------------------------------------
    // Removed dynamic scaling logic since the app is now completely DPI Unaware.
    // Windows Desktop Window Manager (DWM) will handle bitmap scaling automatically.
    QFont f("Segoe UI", 9);
    f.setHintingPreference(QFont::PreferFullHinting);
    app.setFont(f);

    // -- Show main window -----------------------------------------------------
    MainWindow w;
    w.setWindowIcon(appIcon);
    w.show();

    return app.exec();
}
