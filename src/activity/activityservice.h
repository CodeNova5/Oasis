/**
 * @file    activityservice.h
 * @brief   Collects and retains Activity data independently of any UI.
 */
#pragma once

#include <QDateTime>
#include <QList>
#include <QObject>
#include <QSet>
#include <QStringList>
#include <QTimer>
#include <QVector>

#include "activity/activitydetector.h"
#include "activity/activityevent.h"
#include "activity/activityseries.h"
#include "activity/detectionprofile.h"

class NetworkWidget;

namespace TopConsumers {
struct Summary;
}

class ActivityService final : public QObject
{
    Q_OBJECT
public:
    explicit ActivityService(NetworkWidget *network, QObject *parent = nullptr);
    ~ActivityService() override;

    QVector<Activity::SeriesPoint> series(Activity::Range range,
                                           const QString &application = QString()) const;
    Activity::SeriesTotals totals(Activity::Range range,
                                  const QString &application = QString()) const;
    QList<Activity::Event> events() const { return m_events; }
    QStringList applications() const { return m_applications; }
    QDateTime lastUpdated() const { return m_lastBeat; }
    Activity::DetectionProfile profile() const { return m_profile; }

    void setProfile(Activity::DetectionProfile profile);
    void save();

signals:
    void updated();
    void eventsChanged();

private slots:
    void onDashboardUpdated(const TopConsumers::Summary &summary);
    void refreshAuditEvents();

private:
    void appendEvent(const Activity::Event &event);

    NetworkWidget *m_network = nullptr;
    Activity::SeriesStore m_series;
    Activity::Detector m_detector;
    QList<Activity::Event> m_events;
    QSet<QString> m_eventIds;
    QString m_seriesFilePath;
    QDateTime m_lastBeat;
    QStringList m_applications;
    Activity::DetectionProfile m_profile = Activity::DetectionProfile::Balanced;
    QTimer m_saveTimer;
};