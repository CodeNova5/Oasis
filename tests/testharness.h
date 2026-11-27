/**
 * @file   testharness.h
 * @brief  Shared assertion helpers and contract/domain headers for the Oasis
 *         test suite. Split out of the former single-file tests/main.cpp.
 */

#pragma once

#include <QCoreApplication>
#include <QDate>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QStringList>
#include <QTimeZone>

#include "attribution/activityclassifier.h"
#include "attribution/aicontext.h"
#include "attribution/aiapproval.h"
#include "attribution/aiprovider.h"
#include "attribution/openaiadapter.h"
#include "attribution/recommendationengine.h"
#include "attribution/recommendationfeedback.h"
#include "attribution/attributionprivacy.h"
#include "attribution/dnsobserver.h"
#include "attribution/dnscorrelator.h"
#include "attribution/tlsobserver.h"
#include "attribution/quicobserver.h"
#include "attribution/endpointcatalog.h"
#include "attribution/attributionconfidence.h"
#include "identity/foregroundsignal.h"
#include "identity/processlineage.h"
#include "firewall/rulenames.h"
#include "network/auditeventstore.h"
#include "network/auditlogmodel.h"
#include "network/notificationcoordinator.h"
#include "network/applicationdetail.h"
#include "network/evidenceexport.h"
#include "network/diagnostics.h"
#include "network/enforcementrestore.h"
#include "network/datasavermode.h"
#include "network/flowobservation.h"
#include "network/volumemilestone.h"
#include "network/datasaverrules.h"
#include "network/datasaverprofiles.h"
#include "network/datasaverdecision.h"
#include "network/datasavercache.h"
#include "network/datasaverenforcement.h"
#include "network/datasaveraudit.h"
#include "network/policy.h"
#include "network/policyschedule.h"
#include "network/policyscope.h"
#include "network/topconsumers.h"
#include "network/policyreconcile.h"
#include "network/testfixtures.h"
#include "activity/activitydetector.h"
#include "activity/activityevent.h"
#include "activity/activityseries.h"

extern int g_checks;
extern int g_failures;

void check(bool condition, const QString &what);

template <typename T>
void checkEqual(const T &actual, const T &expected, const QString &what)
{
    ++g_checks;
    if (actual == expected) return;
    ++g_failures;
    QString detail;
    QDebug(&detail) << actual << "!=" << expected;
    qWarning().noquote() << "FAIL" << what << "--" << detail;
}

inline QJsonObject objectOf(const QString &json)
{
    return QJsonDocument::fromJson(json.toUtf8()).object();
}
