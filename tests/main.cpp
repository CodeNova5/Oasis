/**
 * @file   main.cpp
 * @brief  Entry point for the Oasis test suite. The tests themselves live in
 *         contract_tests.cpp, policy_tests.cpp, attribution_tests.cpp,
 *         ai_tests.cpp, ui_tests.cpp, and datasaver_tests.cpp.
 *
 * Build and run from the repository root:
 *   qmake tests/oasis_tests.pro && mingw32-make -j4
 *   ./oasis_tests
 *
 * Exit code 0 means every check passed; failures are printed with the value
 * that was observed so a broken rule does not need a debugger to explain.
 */

#include "testharness.h"
#include "testdeclarations.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    // Policy-store tests write real settings, so keep them in a scope of their
    // own and start from a clean slate.
    QCoreApplication::setOrganizationName(QStringLiteral("OasisTests"));
    QCoreApplication::setApplicationName(QStringLiteral("oasis_tests"));
    QSettings().clear();

    runDataSaverTests();
    runContractTests();
    runPolicyTests();
    runAttributionTests();
    runAiTests();
    runUiTests();

    QSettings().clear();

    qInfo() << "checks:" << g_checks << "failures:" << g_failures;
    return g_failures == 0 ? 0 : 1;
}
