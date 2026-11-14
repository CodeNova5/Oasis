/**
 * @file    activitypage.h
 * @brief   Screen 02 — Activity (SCREENS_SPEC.md).
 *
 * A pure presentation layer for the event stream. The host owns capture,
 * detection, persistence and enforcement; it pushes completed events and
 * bucketed series in here and reacts to the action signals. The page never
 * creates a policy itself and never guesses an owner for unresolved traffic.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

#include "activity/activityevent.h"
#include "activity/activityseries.h"

class QComboBox;
class QFrame;
class QLabel;
class QPushButton;
class QScrollArea;
class QToolButton;
class QVBoxLayout;
class ActivityTimeline;
class EmptyStateWidget;

class ActivityPage : public QWidget
{
    Q_OBJECT
public:
    explicit ActivityPage(QWidget *parent = nullptr);

    // ── Content ────────────────────────────────────────────────────────────
    void setSeries(const QVector<Activity::SeriesPoint> &points);
    void setEvents(const QList<Activity::Event> &events);
    void setApplications(const QStringList &applications, const QString &current);
    void setDismissedIds(const QStringList &ids);
    void setSimulationVisible(bool visible);
    void setMonitoringActive(bool active);
    void setUpdated(const QDateTime &when);

    // ── Page state ─────────────────────────────────────────────────────────
    void setBanner(const QString &text, const QString &severity = QStringLiteral("warning"));
    void clearBanner();

    void setRange(Activity::Range range);
    Activity::Range range() const { return m_range; }
    QString application() const { return m_appFilter; }
    /// The cards currently shown, in feed order. Exports use exactly this list.
    QList<Activity::Event> visibleEvents() const;

signals:
    void rangeChanged(Activity::Range range);
    void applicationChanged(const QString &application);
    void policyRequested(quint32 pid, const QString &path, const QString &name);
    void policiesRequested();
    void applicationRequested(quint32 pid, const QString &path, const QString &name);
    void dismissRequested(const QString &id);
    void exportRequested(const QString &format);
    void simulateRequested();

private:
    QFrame *createCard(const QString &title, const QString &subtitle = QString());
    void buildToolbar();
    void buildTimelineCard();
    void buildFeed();
    void refreshTimeline();
    void refreshMarkers();
    void refreshKpis();
    void rebuildFeed();
    void refreshCategoryCounts();
    void applyTimelineSelection(int first, int last);
    void clearSelection();

    Activity::EventFilter currentFilter() const;
    bool isDismissed(const QString &id) const;

    static QString formatBytes(quint64 bytes);
    static QString formatRate(quint64 bytesPerSecond);
    static QString formatSpan(const QDateTime &from, const QDateTime &to);

    // ── Toolbar ────────────────────────────────────────────────────────────
    QFrame      *m_toolbar = nullptr;
    QComboBox   *m_appCombo = nullptr;
    QToolButton *m_exportButton = nullptr;
    QPushButton *m_simulateButton = nullptr;
    QList<QToolButton *> m_rangeButtons;

    // ── Banner / timeline ──────────────────────────────────────────────────
    QFrame      *m_banner = nullptr;
    QLabel      *m_bannerText = nullptr;
    QLabel      *m_updatedLabel = nullptr;
    QFrame      *m_timelineCard = nullptr;
    QLabel      *m_timelineSubtitle = nullptr;
    QLabel      *m_collectingBadge = nullptr;
    ActivityTimeline *m_timeline = nullptr;
    QLabel      *m_downloadedValue = nullptr;
    QLabel      *m_uploadedValue = nullptr;
    QLabel      *m_peakValue = nullptr;
    QLabel      *m_selectionLabel = nullptr;
    QPushButton *m_clearSelection = nullptr;

    // ── Feed ───────────────────────────────────────────────────────────────
    QLabel      *m_feedCount = nullptr;
    QList<QToolButton *> m_categoryButtons;
    QVBoxLayout *m_feedLayout = nullptr;
    QWidget     *m_feedHost = nullptr;

    // ── State ──────────────────────────────────────────────────────────────
    QVector<Activity::SeriesPoint> m_points;
    QList<Activity::Event> m_events;
    QStringList m_dismissed;
    QStringList m_applications;
    QString     m_appFilter;
    Activity::Range m_range = Activity::Range::Hour;
    int         m_category = -1; // -1 = all events
    QDateTime   m_selectionFrom;
    QDateTime   m_selectionTo;
    bool        m_monitoringActive = true;
    QDateTime   m_updated; // timestamp of the latest telemetry beat
};
