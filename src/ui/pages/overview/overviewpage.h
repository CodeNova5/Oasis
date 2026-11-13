/**
 * @file    overviewpage.h
 * @brief   Screen 01 — Overview (SCREENS_SPEC.md).
 *
 * The default landing view: KPI row, 60-minute traffic chart, top consumers,
 * controls in force, and recent activity. The page is a pure presentation
 * layer: it owns no monitor, no timer and no enforcement call. A host (see
 * docs/Design/ARCHITECTURE_SHELL.md §3.2) pushes formatted snapshots in through
 * the setters below and reacts to the navigation signals, so this screen can be
 * built, opened and reviewed without touching the existing screens.
 *
 * @author  Oasis
 */
#pragma once
#include <QDateTime>
#include <QIcon>
#include <QVector>
#include <QWidget>

#include "ui/components/trafficchart.h"

class QFrame;
class QLabel;
class QPushButton;
class QVBoxLayout;
class QScrollArea;
class EmptyStateWidget;
class MetricCard;
class TrafficChart;
class StatusBadge;

namespace Overview {

/// What a top-consumer row says about the process's operational state.
struct Consumer
{
    quint32 pid = 0;
    QString name;
    QString subtitle;     // executable or identity, e.g. "chrome.exe"
    QString usage;        // "1.2 Mbps · 840 MB"
    // The numbers behind `usage`; the row's bar is proportional to the busiest
    // consumer on screen.
    quint64 bytesPerSecond = 0;
    quint64 totalBytes = 0;
    QString stateLabel;   // empty hides the badge
    QString stateToken;   // QSS badge token: active, degraded, unknown, ...
    QString path;         // executable path, empty when unresolved
    QIcon   icon;
};

/// One entry in Recent Activity & Alerts.
struct Alert
{
    QDateTime at;
    QString   title;
    QString   detail;
    QString   actionLabel; // "Review", "Inspect", empty for none
    QString   tone;        // icon tint: success, warning, danger, info
};

/// KPI counts for the Controls in Force card.
struct ControlCounts
{
    int     active = 0;
    int     storedOnly = 0;
    int     expired = 0;
    int     unresolvedConsumers = 0;
    quint64 unresolvedBytes = 0;
    // All captured traffic, so the unresolved row can state its share.
    quint64 totalBytes = 0;
};

enum class BannerSeverity { Info, Warning, Danger };

} // namespace Overview

class OverviewPage : public QWidget
{
    Q_OBJECT
public:
    explicit OverviewPage(QWidget *parent = nullptr);

    // ── Content ────────────────────────────────────────────────────────────
    /// Totals and current rates; the page formats them (bytes, per second).
    void setUsageTotals(quint64 totalBytes, quint64 rxBytes, quint64 txBytes,
                        quint64 rxBytesPerSecond, quint64 txBytesPerSecond);
    void setActiveAppCount(int count);

    /// The last 30 seconds. Older samples are dropped when this is called.
    void setTrafficSeries(const QVector<Overview::TrafficPoint> &points);
    void appendTrafficPoint(const Overview::TrafficPoint &point);

    void setTopConsumers(const QVector<Overview::Consumer> &consumers);
    void setControls(const Overview::ControlCounts &counts);
    void setAlerts(const QVector<Overview::Alert> &alerts);

    // ── Page state ─────────────────────────────────────────────────────────
    /// A top banner for partial/degraded, error or permission states.
    void setBanner(Overview::BannerSeverity severity, const QString &text);
    void clearBanner();

    /// True while the host is still warming up: shows skeletons instead of
    /// zeroed cards, so "0 B" never pretends to be measured traffic.
    void setCollecting(bool collecting);

    /// Stopped monitoring changes the chart and empty-state copy rather than
    /// leaving a stale-looking line on screen.
    void setMonitoringActive(bool active);

    void setUpdated(const QDateTime &when);

signals:
    void activityRequested();
    void applicationsRequested();
    void monitoringRequested();
    void policiesRequested();
    void diagnosticsRequested();
    void applicationActivated(quint32 pid, const QString &path, const QString &name);
    void alertActivated(int index);

private:
    QFrame *createCard(const QString &title, const QString &subtitle = QString());
    QPushButton *createLink(const QString &text);
    void rebuildConsumers();
    void rebuildAlerts();
    void refreshControls();
    void refreshChartState();

    static QString formatBytes(quint64 bytes);
    static QString formatRate(quint64 bytesPerSecond);
    static QString relativeTime(const QDateTime &when);

    QScrollArea  *m_scroll = nullptr;
    QWidget      *m_body = nullptr;
    QFrame       *m_banner = nullptr;
    QLabel       *m_bannerText = nullptr;
    QPushButton  *m_bannerAction = nullptr;
    EmptyStateWidget *m_loading = nullptr;

    MetricCard   *m_totalCard = nullptr;
    MetricCard   *m_downloadCard = nullptr;
    MetricCard   *m_uploadCard = nullptr;
    MetricCard   *m_appsCard = nullptr;

    TrafficChart *m_chart = nullptr;

    QVBoxLayout  *m_consumerRows = nullptr;
    EmptyStateWidget *m_consumerEmpty = nullptr;
    QLabel       *m_consumerFootnote = nullptr;

    QLabel       *m_activeCount = nullptr;
    QLabel       *m_activeDetail = nullptr;
    QLabel       *m_storedCount = nullptr;
    QLabel       *m_storedDetail = nullptr;
    QLabel       *m_unresolvedCount = nullptr;
    QLabel       *m_unresolvedDetail = nullptr;
    QLabel       *m_controlSummary = nullptr;

    QVBoxLayout  *m_alertRows = nullptr;
    QLabel       *m_alertEmpty = nullptr;

    QLabel       *m_updated = nullptr;

    QVector<Overview::Consumer>     m_consumers;
    QVector<Overview::TrafficPoint> m_series;
    QVector<Overview::Alert>        m_alerts;
    Overview::ControlCounts     m_controlCounts;

    bool m_collecting = false;
    bool m_monitoringActive = true;
};
