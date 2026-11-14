/**
 * @file    activityseries.cpp
 * @author  Oasis
 */
#include "activityseries.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QPair>
#include <QTime>
#include <QTimeZone>
#include <QtMath>

#include <algorithm>

namespace Activity {

namespace {

constexpr int kLiveSeconds = 5;
constexpr int kLiveCount = 60;
constexpr int kMinuteSeconds = 60;
constexpr int kMinuteCount = 60;
constexpr int kHourSeconds = 3600;
constexpr int kHourCount = 24;
constexpr int kDaySeconds = 86400;
constexpr int kDayCount = 7;

} // namespace

QString rangeKey(Range range)
{
    switch (range) {
    case Range::Live: return QStringLiteral("live");
    case Range::Hour: return QStringLiteral("hour");
    case Range::Day:  return QStringLiteral("day");
    case Range::Week: return QStringLiteral("week");
    }
    return QStringLiteral("hour");
}

QString rangeLabel(Range range)
{
    switch (range) {
    case Range::Live: return QStringLiteral("Live");
    case Range::Hour: return QStringLiteral("1 hour");
    case Range::Day:  return QStringLiteral("24 hours");
    case Range::Week: return QStringLiteral("7 days");
    }
    return QStringLiteral("1 hour");
}

QString rangeLongLabel(Range range)
{
    switch (range) {
    case Range::Live: return QStringLiteral("Bandwidth · live stream");
    case Range::Hour: return QStringLiteral("Bandwidth · last 1 hour");
    case Range::Day:  return QStringLiteral("Bandwidth · last 24 hours");
    case Range::Week: return QStringLiteral("Bandwidth · last 7 days");
    }
    return QStringLiteral("Bandwidth");
}

int rangeBucketSeconds(Range range)
{
    switch (range) {
    case Range::Live: return kLiveSeconds;
    case Range::Hour: return kMinuteSeconds;
    case Range::Day:  return kHourSeconds;
    case Range::Week: return kDaySeconds;
    }
    return kMinuteSeconds;
}

int rangeBucketCount(Range range)
{
    switch (range) {
    case Range::Live: return kLiveCount;
    case Range::Hour: return kMinuteCount;
    case Range::Day:  return kHourCount;
    case Range::Week: return kDayCount;
    }
    return kMinuteCount;
}

QDateTime rangeStart(Range range, const QDateTime &now)
{
    const QDateTime end = now.isValid() ? now : QDateTime::currentDateTime();
    return end.addSecs(-rangeBucketSeconds(range) * rangeBucketCount(range));
}

bool rangeFromKey(const QString &key, Range *range)
{
    if (!range)
        return false;
    const QString normalized = key.trimmed().toLower();
    if (normalized == QLatin1String("live")) {
        *range = Range::Live;
        return true;
    }
    if (normalized == QLatin1String("hour") || normalized == QLatin1String("1 hour")) {
        *range = Range::Hour;
        return true;
    }
    if (normalized == QLatin1String("day") || normalized == QLatin1String("24 hours")) {
        *range = Range::Day;
        return true;
    }
    if (normalized == QLatin1String("week") || normalized == QLatin1String("7 days")) {
        *range = Range::Week;
        return true;
    }
    return false;
}

QList<Range> allRanges()
{
    return { Range::Live, Range::Hour, Range::Day, Range::Week };
}

SeriesStore::SeriesStore() = default;

int SeriesStore::levelFor(Range range)
{
    switch (range) {
    case Range::Live: return 0;
    case Range::Hour: return 1;
    case Range::Day:  return 2;
    case Range::Week: return 3;
    }
    return 1;
}

QMap<qint64, SeriesStore::Bucket> *SeriesStore::levelMap(Range range)
{
    switch (levelFor(range)) {
    case 0:  return &m_live;
    case 1:  return &m_minute;
    case 2:  return &m_hour;
    default: return &m_day;
    }
}

const QMap<qint64, SeriesStore::Bucket> *SeriesStore::levelMap(Range range) const
{
    return const_cast<SeriesStore *>(this)->levelMap(range);
}

qint64 SeriesStore::bucketStartSecs(const QDateTime &at, int stepSeconds)
{
    // Align to the local day/hour/minute so labels match the clock a user sees,
    // including time zones whose offset is not a whole hour.
    const QDateTime dayStart(at.date(), QTime(0, 0), at.timeZone());
    const qint64 day = dayStart.toSecsSinceEpoch();
    if (stepSeconds >= kDaySeconds)
        return day;
    if (stepSeconds >= kHourSeconds)
        return day + at.time().hour() * 3600;
    if (stepSeconds >= kMinuteSeconds)
        return day + at.time().hour() * 3600 + at.time().minute() * 60;

    const qint64 secs = at.toSecsSinceEpoch();
    return secs - (secs % stepSeconds);
}

void SeriesStore::prune(QMap<qint64, Bucket> *level, int capacity)
{
    if (!level)
        return;
    while (level->size() > capacity)
        level->erase(level->begin());
}

void SeriesStore::addSample(const QDateTime &at, quint64 rxBytesPerSecond,
                            quint64 txBytesPerSecond, const QList<AppRate> &apps,
                            int elapsedSeconds)
{
    if (!at.isValid())
        return;

    // A stalled GUI or a paused capture must not invent a huge transfer on the
    // next beat; only the first few seconds of a gap are attributed.
    const quint64 seconds = static_cast<quint64>(qBound(1, elapsedSeconds, 10));
    const quint64 rx = rxBytesPerSecond * seconds;
    const quint64 tx = txBytesPerSecond * seconds;

    struct Level
    {
        QMap<qint64, Bucket> *map;
        int step;
        int capacity;
    };
    const Level levels[] = {
        { &m_live,   kLiveSeconds,   kLiveCount },
        { &m_minute, kMinuteSeconds, kMinuteCount },
        { &m_hour,   kHourSeconds,   kHourCount },
        { &m_day,    kDaySeconds,    kDayCount }
    };

    for (const Level &level : levels) {
        const qint64 start = bucketStartSecs(at, level.step);
        auto it = level.map->find(start);
        if (it == level.map->end())
            it = level.map->insert(start, Bucket());
        it->rxBytes += rx;
        it->txBytes += tx;
        for (const AppRate &app : apps) {
            if (app.name.trimmed().isEmpty())
                continue;
            QPair<quint64, quint64> &bytes = it->apps[app.name];
            bytes.first += app.rxBytesPerSecond * seconds;
            bytes.second += app.txBytesPerSecond * seconds;
        }
        prune(level.map, level.capacity);
    }
}

void SeriesStore::clear()
{
    m_live.clear();
    m_minute.clear();
    m_hour.clear();
    m_day.clear();
}

bool SeriesStore::isEmpty(Range range) const
{
    return levelMap(range)->isEmpty();
}

QVector<SeriesPoint> SeriesStore::series(Range range, const QString &app) const
{
    const QMap<qint64, Bucket> *level = levelMap(range);
    const int step = rangeBucketSeconds(range);
    const int count = rangeBucketCount(range);
    const QString appKey = app.trimmed();

    QVector<SeriesPoint> points;
    points.reserve(count);
    if (level->isEmpty())
        return points;

    qint64 latest = bucketStartSecs(QDateTime::currentDateTime(), step);
    const qint64 storedLatest = level->lastKey();
    if (storedLatest > latest)
        latest = storedLatest;

    for (int i = count - 1; i >= 0; --i) {
        const qint64 start = latest - static_cast<qint64>(i) * step;
        SeriesPoint point;
        point.start = QDateTime::fromSecsSinceEpoch(start);
        const auto it = level->constFind(start);
        if (it != level->constEnd()) {
            if (appKey.isEmpty()) {
                point.rxBytes = it->rxBytes;
                point.txBytes = it->txBytes;
            } else {
                const auto appIt = it->apps.constFind(appKey);
                if (appIt != it->apps.constEnd()) {
                    point.rxBytes = appIt->first;
                    point.txBytes = appIt->second;
                }
            }
        }
        points.append(point);
    }
    return points;
}

SeriesTotals SeriesStore::totals(Range range, const QString &app) const
{
    const QVector<SeriesPoint> points = series(range, app);
    SeriesTotals totals;
    totals.bucketSeconds = rangeBucketSeconds(range);
    if (points.isEmpty())
        return totals;

    totals.from = points.first().start;
    totals.to = points.last().start.addSecs(totals.bucketSeconds);
    for (const SeriesPoint &point : points) {
        totals.rxBytes += point.rxBytes;
        totals.txBytes += point.txBytes;
        totals.peakBucketBytes = std::max(totals.peakBucketBytes, point.totalBytes());
    }
    return totals;
}

QStringList SeriesStore::appNames(Range range) const
{
    const QMap<qint64, Bucket> *level = levelMap(range);
    QHash<QString, bool> seen;
    for (auto it = level->constBegin(); it != level->constEnd(); ++it) {
        for (auto app = it->apps.constBegin(); app != it->apps.constEnd(); ++app) {
            if (app->first > 0 || app->second > 0)
                seen.insert(app.key(), true);
        }
    }
    QStringList names = seen.keys();
    std::sort(names.begin(), names.end(), [](const QString &a, const QString &b) {
        return QString::compare(a, b, Qt::CaseInsensitive) < 0;
    });
    return names;
}

QJsonObject SeriesStore::toJson() const
{
    const auto levelArray = [](const QMap<qint64, Bucket> &level) {
        QJsonArray array;
        for (auto it = level.constBegin(); it != level.constEnd(); ++it) {
            QJsonObject bucket;
            bucket.insert(QStringLiteral("t"), static_cast<double>(it.key()));
            bucket.insert(QStringLiteral("rx"), static_cast<double>(it->rxBytes));
            bucket.insert(QStringLiteral("tx"), static_cast<double>(it->txBytes));
            if (!it->apps.isEmpty()) {
                QJsonObject apps;
                for (auto app = it->apps.constBegin(); app != it->apps.constEnd(); ++app) {
                    QJsonArray bytes;
                    bytes.append(static_cast<double>(app->first));
                    bytes.append(static_cast<double>(app->second));
                    apps.insert(app.key(), bytes);
                }
                bucket.insert(QStringLiteral("apps"), apps);
            }
            array.append(bucket);
        }
        return array;
    };

    QJsonObject root;
    root.insert(QStringLiteral("format"), QStringLiteral("oasis.activity-series"));
    root.insert(QStringLiteral("version"), 1);
    root.insert(QStringLiteral("savedAt"),
                QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
    root.insert(QStringLiteral("live"), levelArray(m_live));
    root.insert(QStringLiteral("minute"), levelArray(m_minute));
    root.insert(QStringLiteral("hour"), levelArray(m_hour));
    root.insert(QStringLiteral("day"), levelArray(m_day));
    return root;
}

bool SeriesStore::fromJson(const QJsonObject &object)
{
    if (object.value(QStringLiteral("format")).toString()
        != QLatin1String("oasis.activity-series"))
        return false;
    if (object.value(QStringLiteral("version")).toInt(1) > 1)
        return false;

    clear();

    const struct
    {
        const char *key;
        QMap<qint64, Bucket> *map;
        int capacity;
    } levels[] = {
        { "live",   &m_live,   kLiveCount },
        { "minute", &m_minute, kMinuteCount },
        { "hour",   &m_hour,   kHourCount },
        { "day",    &m_day,    kDayCount }
    };

    for (const auto &level : levels) {
        const QJsonArray array = object.value(QLatin1String(level.key)).toArray();
        for (const QJsonValue &value : array) {
            if (!value.isObject())
                continue;
            const QJsonObject bucket = value.toObject();
            const qint64 start = static_cast<qint64>(bucket.value(QStringLiteral("t")).toDouble());
            if (start <= 0)
                continue;
            Bucket entry;
            entry.rxBytes = static_cast<quint64>(bucket.value(QStringLiteral("rx")).toDouble());
            entry.txBytes = static_cast<quint64>(bucket.value(QStringLiteral("tx")).toDouble());
            const QJsonObject apps = bucket.value(QStringLiteral("apps")).toObject();
            for (auto app = apps.constBegin(); app != apps.constEnd(); ++app) {
                const QJsonArray bytes = app.value().toArray();
                if (bytes.size() < 2)
                    continue;
                entry.apps.insert(
                    app.key(),
                    qMakePair(static_cast<quint64>(bytes.at(0).toDouble()),
                              static_cast<quint64>(bytes.at(1).toDouble())));
            }
            level.map->insert(start, entry);
        }
        prune(level.map, level.capacity);
    }
    return true;
}

QString SeriesStore::toJsonString() const
{
    return QString::fromUtf8(QJsonDocument(toJson()).toJson(QJsonDocument::Compact));
}

bool SeriesStore::fromJsonString(const QString &json)
{
    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8());
    return document.isObject() && fromJson(document.object());
}

} // namespace Activity
