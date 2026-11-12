##############################################################################
#   UltimateNetGuard — Phase 0 test harness
#
#   Focused harness for NG-001 (product-direction fixtures), NG-002
#   (observation and policy telemetry contracts), NG-003 (diagnostics export
#   schema), NG-026 (emergency-restore planning), NG-027 (enforcement-channel
#   routing), NG-024 (policy attribution and reconciliation planning), and
#   NG-030 (passive DNS metadata). It links only the pure-logic sources it needs, so it runs without
#   a GUI, without administrator rights, and without WinDivert.
#
#   Build and run from the repository root:
#       qmake tests/netguard_tests.pro && mingw32-make -j4
#       ./netguard_tests
##############################################################################

QT += core network
CONFIG += console c++14
CONFIG -= app_bundle

TEMPLATE = app
TARGET   = netguard_tests

DESTDIR     = $$OUT_PWD
OBJECTS_DIR = $$OUT_PWD/.obj
MOC_DIR     = $$OUT_PWD/.moc

INCLUDEPATH += $$PWD/../src

SOURCES += \
    main.cpp \
    ../src/network/policy.cpp \
    ../src/network/auditeventstore.cpp \
    ../src/network/evidenceexport.cpp \
    ../src/network/auditlogmodel.cpp \
    ../src/network/notificationcoordinator.cpp \
    ../src/network/applicationdetail.cpp \
    ../src/network/packetparser.cpp \
    ../src/network/bandwidthguard.cpp \
    ../src/network/testfixtures.cpp \
    ../src/network/diagnostics.cpp \
    ../src/network/enforcementrestore.cpp \
    ../src/network/policyschedule.cpp \
    ../src/network/policyscope.cpp \
    ../src/network/topconsumers.cpp \
    ../src/network/policyreconcileplan.cpp \
    ../src/attribution/dnsobserver.cpp \
    ../src/attribution/attributionprivacy.cpp \
    ../src/attribution/activityclassifier.cpp \
    ../src/attribution/recommendationengine.cpp \
    ../src/attribution/recommendationfeedback.cpp \
    ../src/attribution/aicontext.cpp \
    ../src/attribution/aiprovider.cpp \
    ../src/attribution/aiapproval.cpp \
    ../src/attribution/openaiadapter.cpp \
    ../src/attribution/dnscorrelator.cpp \
    ../src/attribution/tlsobserver.cpp \
    ../src/attribution/quicobserver.cpp \
    ../src/attribution/endpointcatalog.cpp \
    ../src/attribution/attributionconfidence.cpp \
    ../src/identity/processlineage.cpp \
    ../src/identity/foregroundsignal.cpp \
    ../src/firewall/rulenames.cpp

HEADERS += \
    ../src/network/policy.h \
    ../src/network/auditeventstore.h \
    ../src/network/evidenceexport.h \
    ../src/network/auditlogmodel.h \
    ../src/network/notificationcoordinator.h \
    ../src/network/applicationdetail.h \
    ../src/network/packetparser.h \
    ../src/network/bandwidthguard.h \
    ../src/network/testfixtures.h \
    ../src/network/diagnostics.h \
    ../src/network/enforcementrestore.h \
    ../src/network/policyschedule.h \
    ../src/network/policyscope.h \
    ../src/network/topconsumers.h \
    ../src/network/policyreconcile.h \
    ../src/attribution/dnsobserver.h \
    ../src/attribution/attributionprivacy.h \
    ../src/attribution/activityclassifier.h \
    ../src/attribution/recommendationengine.h \
    ../src/attribution/recommendationfeedback.h \
    ../src/attribution/aicontext.h \
    ../src/attribution/aiprovider.h \
    ../src/attribution/aiapproval.h \
    ../src/attribution/openaiadapter.h \
    ../src/attribution/dnscorrelator.h \
    ../src/attribution/tlsobserver.h \
    ../src/attribution/quicobserver.h \
    ../src/attribution/endpointcatalog.h \
    ../src/attribution/attributionconfidence.h \
    ../src/identity/processlineage.h \
    ../src/identity/foregroundsignal.h \
    ../src/firewall/rulenames.h

win32: LIBS += -lws2_32 -luser32
