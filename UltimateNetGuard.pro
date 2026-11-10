##############################################################################
#   UltimateNetGuard
#   Copyright © 2026  AliSakkaf  |  All Rights Reserved
#-----------------------------------------------------------------------------
#   Website  : https://mysterious-dev.com/
#   GitHub   : https://github.com/alisakkaf
#   Facebook : https://www.facebook.com/AliSakkaf.Dev/
##############################################################################


QT += core gui widgets network

greaterThan(QT_MAJOR_VERSION, 4): lessThan(QT_MAJOR_VERSION, 6) {
    QT += winextras
}

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG   += c++14
CONFIG   -= app_bundle

TARGET   = UltimateNetGuard
TEMPLATE = app

VERSION  = 1.0.0
RC_FILE  = appicon.rc

# ─── Source files ───────────────────────────────────────────────────────────
SOURCES += \
    src/main.cpp \
    src/core/mainwindow.cpp \
    src/core/apptheme.cpp \
    src/core/stylemanager.cpp \
    src/core/updatechecker.cpp \
    src/core/appinstaller.cpp \
    src/core/windowsicon.cpp \
    src/network/networkmonitor.cpp \
    src/network/bandwidthguard.cpp \
    src/network/windowsqosbackend.cpp \
    src/network/windivertapi.cpp \
    src/network/downloadthrottle.cpp \
    src/network/throttlepolicymanager.cpp \
    src/network/networkmodel.cpp \
    src/network/networkwidget.cpp \
    src/network/packetparser.cpp \
    src/network/testfixtures.cpp \
    src/network/policy.cpp \
    src/network/diagnostics.cpp \
    src/network/enforcementrestore.cpp \
    src/network/enforcementcoordinator.cpp \
    src/network/policyschedule.cpp \
    src/network/policyeditordialog.cpp \
    src/network/policylistdialog.cpp \
    src/network/policyreconcile.cpp \
    src/network/bandwidthlimitsdialog.cpp \
    src/network/policyreconcileplan.cpp \
    src/attribution/dnsobserver.cpp \
    src/attribution/dnscorrelator.cpp \
    src/identity/applicationidentity.cpp \
    src/identity/publisherresolver.cpp \
    src/identity/serviceresolver.cpp \
    src/identity/processlineage.cpp \
    src/identity/processgroupmanager.cpp \
    src/network/groupdetaildialog.cpp \
    src/firewall/firewallmanager.cpp \
    src/firewall/rulenames.cpp \
    src/firewall/firewallmodel.cpp \
    src/firewall/firewallwidget.cpp \
    src/hardware/hardwaremonitor.cpp \
    src/hardware/hardwarewidget.cpp \
    src/taskbar/taskbaroverlay.cpp \
    src/taskbar/systemtrayicon.cpp

# ─── Headers ────────────────────────────────────────────────────────────────
HEADERS += \
    src/core/version.h \
    src/core/mainwindow.h \
    src/core/apptheme.h \
    src/core/stylemanager.h \
    src/core/updatechecker.h \
    src/core/appinstaller.h \
    src/core/windowsicon.h \
    src/network/networkmonitor.h \
    src/network/bandwidthguard.h \
    src/network/throttlebackend.h \
    src/network/windowsqosbackend.h \
    src/network/windivertapi.h \
    src/network/downloadthrottle.h \
    src/network/throttlepolicymanager.h \
    src/network/networkmodel.h \
    src/network/networkwidget.h \
    src/network/packetparser.h \
    src/network/testfixtures.h \
    src/network/policy.h \
    src/network/diagnostics.h \
    src/network/enforcementrestore.h \
    src/network/enforcementcoordinator.h \
    src/network/policyschedule.h \
    src/network/policyeditordialog.h \
    src/network/policylistdialog.h \
    src/network/policyreconcile.h \
    src/network/bandwidthlimitsdialog.h \
    src/attribution/dnsobserver.h \
    src/attribution/dnscorrelator.h \
    src/identity/applicationidentity.h \
    src/identity/publisherresolver.h \
    src/identity/serviceresolver.h \
    src/identity/processlineage.h \
    src/identity/processgroupmanager.h \
    src/network/groupdetaildialog.h \
    src/firewall/firewallmanager.h \
    src/firewall/rulenames.h \
    src/firewall/firewallmodel.h \
    src/firewall/firewallwidget.h \
    src/hardware/hardwaremonitor.h \
    src/hardware/hardwarewidget.h \
    src/taskbar/taskbaroverlay.h \
    src/taskbar/systemtrayicon.h

# ─── Qt Designer UI forms ────────────────────────────────────────────────────
FORMS += \
    src/ui/mainwindow.ui \
    src/ui/networkwidget.ui \
    src/ui/firewallwidget.ui \
    src/ui/hardwarewidget.ui

# ─── Resources ──────────────────────────────────────────────────────────────
RESOURCES += resources.qrc

# ─── Include paths ──────────────────────────────────────────────────────────
INCLUDEPATH += \
    src \
    src/core \
    src/network \
    src/firewall \
    src/hardware \
    src/taskbar

# ─── WinDivert (download shaping) ────────────────────────────────────────────
# Resolved at runtime, so nothing links against it at build time. Put
# WinDivert.dll + WinDivert64.sys in third_party/windivert/ and the bundling
# rule at the end of this file copies them next to the executable; without them
# only uploads are throttled (Windows QoS).

# ─── Windows system libraries ────────────────────────────────────────────────
win32: LIBS += \
    -lws2_32 \
    -liphlpapi \
    -lole32 \
    -loleaut32 \
    -lwbemuuid \
    -lpdh \
    -ladvapi32 \
    -lshell32 \
    -luser32 \
    -lgdi32 \
    -luuid \
    -lshlwapi \
    -ldxgi \
    -lversion \
    -lwintrust \
    -lcrypt32

# ─── Compiler / preprocessor flags ──────────────────────────────────────────
mingw {
    QMAKE_CXXFLAGS += -O2 -Wno-unknown-pragmas -Wno-unused-parameter
    DEFINES += UNICODE _UNICODE \
               WIN32_LEAN_AND_MEAN \
               NOMINMAX \
               _WIN32_WINNT=0x0601 \
               WINVER=0x0601
}

# ─── Output dirs ────────────────────────────────────────────────────────────
DESTDIR     = $$OUT_PWD/bin
OBJECTS_DIR = $$OUT_PWD/.obj
MOC_DIR     = $$OUT_PWD/.moc
RCC_DIR     = $$OUT_PWD/.rcc
UI_DIR      = $$OUT_PWD/.ui

# ─── WinDivert runtime bundling ──────────────────────────────────────────────
# Copies the WinDivert runtime from third_party/windivert/ next to the
# executable after linking. The leading "-" makes make ignore a copy that has
# become stale (files removed after qmake ran) instead of failing the build.
win32 {
    WINDIVERT_BUNDLE = $$files($$PWD/third_party/windivert/WinDivert.dll)
    WINDIVERT_BUNDLE += $$files($$PWD/third_party/windivert/WinDivert64.sys)
    WINDIVERT_BUNDLE += $$files($$PWD/third_party/windivert/WinDivert32.sys)
    for(windivert_file, WINDIVERT_BUNDLE) {
        QMAKE_POST_LINK += - $$QMAKE_COPY \"$$shell_path($$windivert_file)\" \"$$shell_path($$DESTDIR)\" $$escape_expand(\\n\\t)
    }
}
