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
#include "ui/theme/thememanager.h"
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
    // Resolves design tokens (src/ui/theme) into styles.qss and installs the
    // matching QPalette + Segoe UI Variable font.
    ThemeManager::instance().apply(&app);

    // -- Show main window -----------------------------------------------------
    MainWindow w;
    w.setWindowIcon(appIcon);
    w.showMaximized();

    return app.exec();
}
