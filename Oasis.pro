##############################################################################
#   Oasis
#   Copyright © 2026  Oasis  |  All Rights Reserved
#-----------------------------------------------------------------------------
#   GitHub   : https://github.com/CodeNova5/Oasis
##############################################################################


QT += core gui widgets network concurrent svg

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
    src/ui/theme/thememanager.cpp \
    src/activity/activityevent.cpp \
    src/activity/activityseries.cpp \
    src/activity/activitydetector.cpp \
    src/activity/activityservice.cpp \
    src/activity/detectionprofile.cpp \
    src/core/updatechecker.cpp \
    src/core/appinstaller.cpp \
    src/core/servicehost.cpp \
    src/core/windowsicon.cpp \
    src/network/networkmonitor.cpp \
    src/network/networkmonitor_adapters.cpp \
    src/network/networkmonitor_caches.cpp \
    src/network/bandwidthguard.cpp \
    src/network/windowsqosbackend.cpp \
    src/network/windivertapi.cpp \
    src/network/downloadthrottle.cpp \
    src/network/throttlepolicymanager.cpp \
    src/network/throttlepolicyid.cpp \
    src/network/networkmodel.cpp \
    src/network/networkwidget.cpp \
    src/network/networkwidgettable.cpp \
    src/network/networkwidgetpolicies.cpp \
    src/network/networkwidgetinsights.cpp \
    src/network/connectionview.cpp \
    src/network/packetparser.cpp \
    src/network/testfixtures.cpp \
    src/network/policy.cpp \
    src/network/datasavermode.cpp \
    src/network/flowobservation.cpp \
    src/network/volumemilestone.cpp \
    src/network/datasaverrules.cpp \
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
    src/network/policyruleform.cpp \
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
    src/identity/processgroupmanager_assign.cpp \
    src/identity/foregroundsignal.cpp \
    src/network/groupdetaildialog.cpp \
    src/firewall/firewallmanager.cpp \
    src/firewall/rulenames.cpp \
    src/firewall/firewallmodel.cpp \
    src/hardware/hardwaremonitor.cpp \
    src/taskbar/taskbaroverlay.cpp \
    src/taskbar/systemtrayicon.cpp \
    src/ui/webview2/webuipage.cpp \
    src/ui/webview2/webuibridge.cpp \
    src/ui/webview2/webuiwindow.cpp

# ─── Headers ────────────────────────────────────────────────────────────────
HEADERS += \
    src/core/version.h \
    src/core/guitiming.h \
    src/ui/theme/colors.h \
    src/ui/theme/typography.h \
    src/ui/theme/dimensions.h \
    src/ui/theme/thememanager.h \
    src/activity/activityevent.h \
    src/activity/activityseries.h \
    src/activity/activitydetector.h \
    src/activity/activityservice.h \
    src/activity/detectionprofile.h \
    src/core/updatechecker.h \
    src/core/appinstaller.h \
    src/core/servicehost.h \
    src/core/windowsicon.h \
    src/network/networkmonitor.h \
    src/network/bandwidthguard.h \
    src/network/throttlebackend.h \
    src/network/throttlepolicyid.h \
    src/network/windowsqosbackend.h \
    src/network/windivertapi.h \
    src/network/downloadthrottle.h \
    src/network/throttlepolicymanager.h \
    src/network/networkmodel.h \
    src/network/networkwidget.h \
    src/network/applicationsnapshot.h \
    src/network/connectionsnapshot.h \
    src/network/packetparser.h \
    src/network/testfixtures.h \
    src/network/policy.h \
    src/network/datasavermode.h \
    src/network/flowobservation.h \
    src/network/volumemilestone.h \
    src/network/datasaverrules.h \
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
    src/network/policyruleform.h \
    src/network/policyeditorstyle.h \
    src/network/policyeditorcontrols.h \
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
    src/identity/processgroupmanager_p.h \
    src/identity/foregroundsignal.h \
    src/network/groupdetaildialog.h \
    src/firewall/firewallmanager.h \
    src/firewall/rulenames.h \
    src/firewall/firewallmodel.h \
    src/hardware/hardwaremonitor.h \
    src/taskbar/taskbaroverlay.h \
    src/taskbar/systemtrayicon.h \
    src/ui/webview2/webuipage.h \
    src/ui/webview2/webuibridge.h \
    src/ui/webview2/webuiwindow.h

# ─── Qt Designer UI forms ────────────────────────────────────────────────────
FORMS += \
    src/ui/networkwidget.ui

# ─── Resources ──────────────────────────────────────────────────────────────
RESOURCES += resources.qrc

# ─── Include paths ──────────────────────────────────────────────────────────
INCLUDEPATH += \
    src \
    src/core \
    src/ui/theme \
    src/network \
    src/firewall \
    src/hardware \
    src/taskbar \
    third_party/webview2/include

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

# ─── Runtime bundling (WebView2 assets + WinDivert) ──────────────────────────
# Copies each Preact bundle (one web/ project per page) and the WinDivert
# runtime next to the executable
# after linking. The leading "-" on the WinDivert copies makes make ignore a
# copy that has become stale (files removed after qmake ran) instead of failing
# the build.
#
# Every path is wrapped in $$shell_quote(): the project root can contain spaces
# (e.g. ".../Documents/Next Js/...") and make would otherwise split the path
# into separate arguments. Escaped \" quotes do not survive into the Makefile.
win32 {
    for(web_page, ui) {
        WEB_ASSET_DIR = $$shell_quote($$shell_path($$DESTDIR/web/$$web_page/dist))
        QMAKE_POST_LINK += $$QMAKE_MKDIR $$WEB_ASSET_DIR $$escape_expand(\\n\\t)
        WEB_ASSET_BUNDLE = $$files($$PWD/web/$$web_page/dist/*)
        for(web_asset, WEB_ASSET_BUNDLE) {
            QMAKE_POST_LINK += $$QMAKE_COPY $$shell_quote($$shell_path($$web_asset)) $$WEB_ASSET_DIR $$escape_expand(\\n\\t)
        }
    }
    TARGET_DIR = $$shell_quote($$shell_path($$DESTDIR))
    WINDIVERT_BUNDLE = $$files($$PWD/third_party/windivert/WinDivert.dll)
    WINDIVERT_BUNDLE += $$files($$PWD/third_party/windivert/WinDivert64.sys)
    WINDIVERT_BUNDLE += $$files($$PWD/third_party/windivert/WinDivert32.sys)
    for(windivert_file, WINDIVERT_BUNDLE) {
        QMAKE_POST_LINK += - $$QMAKE_COPY $$shell_quote($$shell_path($$windivert_file)) $$TARGET_DIR $$escape_expand(\\n\\t)
    }
}
