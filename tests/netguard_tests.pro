##############################################################################
#   UltimateNetGuard — Phase 0 test harness
#
#   Focused harness for NG-001 (product-direction fixtures), NG-002
#   (observation and policy telemetry contracts), NG-003 (diagnostics export
#   schema), NG-026 (emergency-restore planning), NG-027 (enforcement-channel
#   routing) and NG-024 (policy attribution and reconciliation planning). It links only the pure-logic sources it needs, so it runs without
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
    ../src/network/packetparser.cpp \
    ../src/network/bandwidthguard.cpp \
    ../src/network/testfixtures.cpp \
    ../src/network/diagnostics.cpp \
    ../src/network/enforcementrestore.cpp \
    ../src/network/policyschedule.cpp \
    ../src/network/policyreconcileplan.cpp \
    ../src/firewall/rulenames.cpp

HEADERS += \
    ../src/network/policy.h \
    ../src/network/packetparser.h \
    ../src/network/bandwidthguard.h \
    ../src/network/testfixtures.h \
    ../src/network/diagnostics.h \
    ../src/network/enforcementrestore.h \
    ../src/network/policyschedule.h \
    ../src/network/policyreconcile.h \
    ../src/firewall/rulenames.h

win32: LIBS += -lws2_32
