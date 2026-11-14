##############################################################################
#   Oasis
#   Copyright © 2026  Oasis  |  All Rights Reserved
#-----------------------------------------------------------------------------
#   GitHub   : https://github.com/CodeNova5/Oasis
##############################################################################


QT += core gui widgets network concurrent

greaterThan(QT_MAJOR_VERSION, 4): lessThan(QT_MAJOR_VERSION, 6) {
    QT += winextras
}

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG   += c++14
CONFIG   -= app_bundle

TARGET   = Oasis
TEMPLATE = app

VERSION  = 1.0.0
RC_FILE  = appicon.rc

# ─── Source files ───────────────────────────────────────────────────────────
SOURCES += \
    src/main.cpp \
    src/core/mainwindow.cpp \
    src/ui/theme/thememanager.cpp \
    src/ui/shell/appsidebar.cpp \
    src/ui/shell/appheader.cpp \
    src/ui/shell/systemstatusbar.cpp \
    src/ui/components/statusbadge.cpp \
    src/ui/components/metriccard.cpp \
    src/ui/components/emptystatewidget.cpp \
    src/ui/components/trafficchart.cpp \
    src/ui/pages/overview/overviewpage.cpp \
    src/ui/pages/activity/activitypage.cpp \
    src/ui/pages/activity/activitytimeline.cpp \
    src/activity/activityevent.cpp \
    src/activity/activityseries.cpp \
    src/activity/activitydetector.cpp \
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
    src/network/auditeventstore.cpp \
    src/network/evidenceexport.cpp \
    src/network/auditlogmodel.cpp \
    src/network/notificationcoordinator.cpp \
    src/network/applicationdetail.cpp \
    src/network/applicationdetaildialog.cpp \
    src/network/diagnostics.cpp \
    src/network/enforcementrestore.cpp \
    src/network/enforcementcoordinator.cpp \
    src/network/policyschedule.cpp \
    src/network/policyeditordialog.cpp \
    src/network/policyscope.cpp \
    src/network/topconsumers.cpp \
    src/network/dashboardpanel.cpp \
    src/network/policylistdialog.cpp \
    src/network/policyreconcile.cpp \
    src/network/bandwidthlimitsdialog.cpp \
    src/network/recommendationdialog.cpp \
    src/network/aiapprovaldialog.cpp \
    src/network/policyreconcileplan.cpp \
    src/attribution/dnsobserver.cpp \
    src/attribution/attributionprivacy.cpp \
    src/attribution/activityclassifier.cpp \
    src/attribution/recommendationengine.cpp \
    src/attribution/recommendationfeedback.cpp \
    src/attribution/aicontext.cpp \
    src/attribution/aiprovider.cpp \
    src/attribution/aiapproval.cpp \
    src/attribution/openaiadapter.cpp \
    src/attribution/dnscorrelator.cpp \
    src/attribution/tlsobserver.cpp \
    src/attribution/quicobserver.cpp \
    src/attribution/endpointcatalog.cpp \
    src/attribution/attributionconfidence.cpp \
    src/identity/applicationidentity.cpp \
    src/identity/publisherresolver.cpp \
    src/identity/serviceresolver.cpp \
    src/identity/processlineage.cpp \
    src/identity/processgroupmanager.cpp \
    src/identity/foregroundsignal.cpp \
    src/network/groupdetaildialog.cpp \
    src/firewall/firewallmanager.cpp \
    src/firewall/rulenames.cpp \
    src/firewall/firewallmodel.cpp \
    src/hardware/hardwaremonitor.cpp \
    src/taskbar/taskbaroverlay.cpp \
    src/taskbar/systemtrayicon.cpp

# ─── Headers ────────────────────────────────────────────────────────────────
HEADERS += \
    src/core/version.h \
    src/core/mainwindow.h \
    src/ui/theme/colors.h \
    src/ui/theme/typography.h \
    src/ui/theme/dimensions.h \
    src/ui/theme/thememanager.h \
    src/ui/shell/appsidebar.h \
    src/ui/shell/appheader.h \
    src/ui/shell/systemstatusbar.h \
    src/ui/components/statusbadge.h \
    src/ui/components/metriccard.h \
    src/ui/components/emptystatewidget.h \
    src/ui/components/trafficchart.h \
    src/ui/pages/overview/overviewpage.h \
    src/ui/pages/activity/activitypage.h \
    src/ui/pages/activity/activitytimeline.h \
    src/activity/activityevent.h \
    src/activity/activityseries.h \
    src/activity/activitydetector.h \
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
    src/network/auditeventstore.h \
    src/network/evidenceexport.h \
    src/network/auditlogmodel.h \
    src/network/notificationcoordinator.h \
    src/network/applicationdetail.h \
    src/network/applicationdetaildialog.h \
    src/network/diagnostics.h \
    src/network/enforcementrestore.h \
    src/network/enforcementcoordinator.h \
    src/network/policyschedule.h \
    src/network/policyeditordialog.h \
    src/network/policyscope.h \
    src/network/topconsumers.h \
    src/network/dashboardpanel.h \
    src/network/policylistdialog.h \
    src/network/policyreconcile.h \
    src/network/policyreconcileservice.h \
    src/network/bandwidthlimitsdialog.h \
    src/network/recommendationdialog.h \
    src/network/aiapprovaldialog.h \
    src/attribution/dnsobserver.h \
    src/attribution/attributionprivacy.h \
    src/attribution/activityclassifier.h \
    src/attribution/recommendationengine.h \
    src/attribution/recommendationfeedback.h \
    src/attribution/aicontext.h \
    src/attribution/aiprovider.h \
    src/attribution/aiapproval.h \
    src/attribution/openaiadapter.h \
    src/attribution/dnscorrelator.h \
    src/attribution/tlsobserver.h \
    src/attribution/quicobserver.h \
    src/attribution/endpointcatalog.h \
    src/attribution/attributionconfidence.h \
    src/identity/applicationidentity.h \
    src/identity/publisherresolver.h \
    src/identity/serviceresolver.h \
    src/identity/processlineage.h \
    src/identity/processgroupmanager.h \
    src/identity/foregroundsignal.h \
    src/network/groupdetaildialog.h \
    src/firewall/firewallmanager.h \
    src/firewall/rulenames.h \
    src/firewall/firewallmodel.h \
    src/hardware/hardwaremonitor.h \
    src/taskbar/taskbaroverlay.h \
    src/taskbar/systemtrayicon.h

# ─── Qt Designer UI forms ────────────────────────────────────────────────────
FORMS += \
    src/ui/mainwindow.ui \
    src/ui/networkwidget.ui

# ─── Resources ──────────────────────────────────────────────────────────────
RESOURCES += resources.qrc

# ─── Include paths ──────────────────────────────────────────────────────────
INCLUDEPATH += \
    src \
    src/core \
    src/ui/theme \
    src/ui/shell \
    src/ui/components \
    src/ui/pages/overview \
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
