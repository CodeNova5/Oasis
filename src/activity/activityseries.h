/**
 * @file    activityseries.h
 * @brief   Bounded bandwidth history for the Activity timeline.
 *
 * Four rolling levels are kept, one per range the screen offers:
 *
 *   Live   5 s buckets, 60 of them  (last 5 minutes)
 *   1 hour 1 min buckets, 60 of them
 *   24 h   1 h buckets, 24 of them
 *   7 d    1 day buckets, 7 of them
 *
 * Bytes are accumulated from one-second telemetry, both for the whole capture
 * and for each named application, so selecting an application can redraw the
 * chart for that application. Every level is bounded and small enough to
 * persist, so a restart keeps the pre-restart tail of each range.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVector>

namespace Activity {

enum class Range {
    Live,
    Hour,
    Day,
    Week
};

QString rangeKey(Range range);
QString rangeLabel(Range range);
QString rangeLongLabel(Range range);
int rangeBucketSeconds(Range range);
int rangeBucketCount(Range range);
/// Range used to filter the feed as well as the chart.
QDateTime rangeStart(Range range, const QDateTime &now);
bool rangeFromKey(const QString &key, Range *range);
QList<Range> allRanges();

struct SeriesPoint
{
    QDateTime start;
    quint64   rxBytes = 0;
    quint64   txBytes = 0;

    quint64 totalBytes() const { return rxBytes + txBytes; }
};

struct SeriesTotals
{
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 peakBucketBytes = 0;
    int     bucketSeconds = 0;
    QDateTime from;
    QDateTime to;
};

/// One application's rate in a telemetry beat.
struct AppRate
{
    QString name;
    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
};

class SeriesStore
{
public:
    SeriesStore();

    /// Adds one telemetry beat. `elapsedSeconds` is the time since the previous
    /// beat, so a delayed beat does not under-count the transferred bytes.
    void addSample(const QDateTime &at, quint64 rxBytesPerSecond,
                   quint64 txBytesPerSecond, const QList<AppRate> &apps,
                   int elapsedSeconds = 1);

    void clear();
    bool isEmpty(Range range) const;

    /// Buckets for the requested range, ending at the current bucket. Empty
    /// slots are returned as zero so the x-axis is continuous. When `app` is
    /// not empty only that application's bytes are returned.
    QVector<SeriesPoint> series(Range range, const QString &app = QString()) const;
    SeriesTotals totals(Range range, const QString &app = QString()) const;

    /// Applications that moved bytes in the requested range.
    QStringList appNames(Range range) const;

    /// Persistence for every bounded level, including the live window. A reopened
    /// screen shows the stored tail and then continues from the new beat.
    QJsonObject toJson() const;
    bool fromJson(const QJsonObject &object);
    QString toJsonString() const;
    bool fromJsonString(const QString &json);

private:
    struct Bucket
    {
        quint64 rxBytes = 0;
        quint64 txBytes = 0;
        QHash<QString, QPair<quint64, quint64>> apps; // name -> (rx, tx)
    };

    static int levelFor(Range range);
    static qint64 bucketStartSecs(const QDateTime &at, int stepSeconds);
    static void prune(QMap<qint64, Bucket> *level, int capacity);
    QMap<qint64, Bucket> *levelMap(Range range);
    const QMap<qint64, Bucket> *levelMap(Range range) const;

    QMap<qint64, Bucket> m_live;
    QMap<qint64, Bucket> m_minute;
    QMap<qint64, Bucket> m_hour;
    QMap<qint64, Bucket> m_day;
};

} // namespace Activity
