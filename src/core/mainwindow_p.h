/**
 * @file    mainwindow_p.h
 * @author  Oasis
 *
 * Private prelude for the MainWindow implementation units. It is not
 * installed and must not be included from a public header.
 */
#pragma once

#include "mainwindow.h"
#include "version.h"
#include "qdebug.h"
#include "ui_mainwindow.h"
#include "ui/theme/thememanager.h"
#include "ui/theme/dimensions.h"
#include "ui/shell/appsidebar.h"
#include "ui/shell/appheader.h"
#include "ui/shell/systemstatusbar.h"
#include "ui/pages/overview/overviewpage.h"
#include "ui/pages/activity/activitypage.h"
#include "ui/pages/applications/applicationspage.h"
#include "ui/pages/connections/connectionspage.h"
#include "ui/pages/policies/policiespage.h"
#include "ui/pages/settings/settingspage.h"
#include "activity/detectionprofile.h"
#include "ui/components/trafficchart.h"
#include "updatechecker.h"
#include "appinstaller.h"
#include "windowsicon.h"
#include "network/networkwidget.h"
#include "network/bandwidthguard.h"
#include "attribution/attributionconfidence.h"
#include "attribution/attributionprivacy.h"
#include "attribution/aiprovider.h"
#include "network/diagnostics.h"
#include "network/auditlogmodel.h"
#include "network/evidenceexport.h"
#include "network/notificationcoordinator.h"
#include "network/networkmonitor.h"
#include "network/topconsumers.h"
#include "network/policyschedule.h"
#include "network/policyscope.h"
#include "hardware/hardwaremonitor.h"
#include "taskbar/taskbaroverlay.h"

#include <QCloseEvent>
#include <QMouseEvent>
#include <windows.h>
#include <shellapi.h>
#include <QTimer>
#include <QStyle>
#include <QScreen>
#include <QGuiApplication>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QApplication>
#include <QDir>
#include <QFileInfo>
#include <QTreeView>
#include <QTableView>
#include <QHeaderView>
#include <QAbstractItemModel>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QDateTime>
#include <QFileDialog>
#include <QSaveFile>
#include <QTextStream>
#include <QMessageBox>
#include <QTableWidgetItem>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>

// ── Shared implementation helpers ─────────────────────────────────────────
// How an export says whether destinations were redacted, appended to every
// success message so the file's contents are never a surprise.
inline QString exportRedactionNote(bool redacted)
{
    return redacted ? QStringLiteral(" (destinations redacted)")
                    : QStringLiteral(" (verbatim destinations)");
}

// ── Overview feed ──────────────────────────────────────────────────────────
// A short human phrase for a stored audit event. The target is whatever the
// event actually recorded; when none was recorded the copy says so instead of
// naming an application.
inline QString overviewAlertTitle(const AuditEvent &event)
{
    QString target = event.scope.trimmed();
    if (target.contains(QLatin1Char('\\')) || target.contains(QLatin1Char('/')))
        target = QFileInfo(target).fileName();
    if (target.isEmpty())
        target = QStringLiteral("an application");

    switch (event.type) {
    case AuditEvent::EventType::EnforcementResult:
        return QStringLiteral("Enforcement result for %1").arg(target);
    case AuditEvent::EventType::EnforcementRequest:
        return QStringLiteral("Enforcement requested for %1").arg(target);
    case AuditEvent::EventType::PolicyChange:
        return QStringLiteral("Policy changed for %1").arg(target);
    case AuditEvent::EventType::Detection:
        return QStringLiteral("Traffic detected from %1").arg(target);
    case AuditEvent::EventType::Classification:
        return QStringLiteral("Application classified: %1").arg(target);
    case AuditEvent::EventType::Recommendation:
        return QStringLiteral("Recommendation for %1").arg(target);
    case AuditEvent::EventType::UserDecision:
    case AuditEvent::EventType::AutomaticDecision:
        return QStringLiteral("Decision recorded for %1").arg(target);
    case AuditEvent::EventType::ProcessGroupMembershipChange:
        return QStringLiteral("Activity group changed: %1").arg(target);
    }
    return auditEventTypeName(event.type);
}

// Red only for a recorded failure or block, green only for a confirmed
// outcome. Anything else stays informational.
inline QString overviewAlertTone(const AuditEvent &event)
{
    const QString outcome = (event.result + QLatin1Char(' ') + event.errorInfo).toLower();
    if (outcome.contains(QStringLiteral("fail")) || outcome.contains(QStringLiteral("error"))
        || outcome.contains(QStringLiteral("blocked")))
        return QStringLiteral("danger");
    if (outcome.contains(QStringLiteral("applied")) || outcome.contains(QStringLiteral("saved"))
        || outcome.contains(QStringLiteral("allowed"))
        || outcome.contains(QStringLiteral("throttled")))
        return QStringLiteral("success");
    return QStringLiteral("info");
}
