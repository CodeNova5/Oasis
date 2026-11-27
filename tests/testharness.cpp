/**
 * @file   testharness.cpp
 * @brief  Shared assertion state and failure reporting for the Oasis suite.
 */

#include "testharness.h"

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const QString &what)
{
    ++g_checks;
    if (condition) return;
    ++g_failures;
    qWarning().noquote() << "FAIL" << what;
}
