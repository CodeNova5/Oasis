/**
 * @file    activitydetector.cpp
 * @author  Oasis
 */
#include "activitydetector.h"

#include <QMutableHashIterator>

#include <algorithm>

namespace Activity {

namespace {

/// Median rather than mean: a spike must not raise the baseline it is being
/// compared with. Five high seconds inside a sixty-second window cannot move
/// the median, so a sustained transfer keeps qualifying through its run.
quint64 typicalRate(const QVector<quint64> &history)
{
    if (history.isEmpty())
        return 0;
    QVector<quint64> sorted = history;
    std::sort(sorted.begin(), sorted.end());
    const int middle = sorted.size() / 2;
    if (sorted.size() % 2 == 1)
        return sorted.at(middle);
    return (sorted.at(middle - 1) + sorted.at(middle)) / 2;
}

} // namespace

Detector::Detector(const DetectorSettings &settings)
{
    setSettings(settings);
}

void Detector::setSettings(const DetectorSettings &settings)
{
    m_settings = settings;
    m_settings.sustainSeconds = std::max(1, m_settings.sustainSeconds);
    m_settings.baselineSeconds = std::max(3, m_settings.baselineSeconds);
    m_settings.cooldownSeconds = std::max(0, m_settings.cooldownSeconds);
    m_settings.unresolvedWindowSeconds = std::max(1, m_settings.unresolvedWindowSeconds);
    m_settings.unresolvedCooldownSeconds = std::max(0, m_settings.unresolvedCooldownSeconds);
    if (m_settings.absoluteFloorBytesPerSecond == 0)
        m_settings.absoluteFloorBytesPerSecond = 1;
    if (m_settings.unresolvedBytesThreshold == 0)
        m_settings.unresolvedBytesThreshold = 1;
}

void Detector::clear()
{
    m_tracks.clear();
    m_unresolvedLastBytes = 0;
    m_unresolvedWindowBytes = 0;
    m_unresolvedWindowStart = QDateTime();
    m_unresolvedLastEventMs = 0;
}

QList<Event> Detector::observe(const QDateTime &at, const QList<ProcessRate> &rates,
                               quint64 unresolvedBytes)
{
    QList<Event> events;
    if (!at.isValid())
        return events;

    const qint64 nowMs = at.toMSecsSinceEpoch();
    const quint64 floor = m_settings.absoluteFloorBytesPerSecond;
    const double multiplier = m_settings.baselineMultiplier > 0.0
                                  ? m_settings.baselineMultiplier : 3.0;

    for (const ProcessRate &rate : rates) {
        if (rate.name.trimmed().isEmpty())
            continue;

        Track &track = m_tracks[rate.name];
        track.lastSeenMs = nowMs;

        const quint64 current = rate.rxBytesPerSecond + rate.txBytesPerSecond;
        const quint64 baseline = typicalRate(track.history);
        const quint64 threshold = std::max(
            floor, static_cast<quint64>(double(baseline) * multiplier));

        const bool qualifies = current > 0 && current >= threshold;
        if (qualifies) {
            if (track.aboveSeconds == 0) {
                track.spikeBytes = 0;
                track.peakBytesPerSecond = 0;
            }
            ++track.aboveSeconds;
            track.spikeBytes += current;
            track.peakBytesPerSecond = std::max(track.peakBytesPerSecond, current);

            const bool cooledDown = track.lastEventMs == 0
                || nowMs - track.lastEventMs
                       >= static_cast<qint64>(m_settings.cooldownSeconds) * 1000;
            if (track.aboveSeconds >= m_settings.sustainSeconds && cooledDown) {
                events.append(makeSpikeEvent(at, rate, track));
                track.lastEventMs = nowMs;
                track.aboveSeconds = 0;
                track.spikeBytes = 0;
                track.peakBytesPerSecond = 0;
            }
        } else {
            track.aboveSeconds = 0;
            track.spikeBytes = 0;
            track.peakBytesPerSecond = 0;
        }

        track.history.append(current);
        while (track.history.size() > m_settings.baselineSeconds)
            track.history.removeFirst();
    }

    // Forget applications that sent nothing for ten minutes: memory stays
    // bounded even on a machine that starts hundreds of short-lived helpers.
    QMutableHashIterator<QString, Track> it(m_tracks);
    while (it.hasNext()) {
        it.next();
        if (nowMs - it.value().lastSeenMs > 10 * 60 * 1000)
            it.remove();
    }

    // ── Unresolved traffic ────────────────────────────────────────────────
    if (unresolvedBytes < m_unresolvedLastBytes) {
        // The unresolved set shrank (a process exited or was identified), so a
        // negative delta is not traffic; start a fresh window.
        m_unresolvedLastBytes = unresolvedBytes;
        m_unresolvedWindowBytes = 0;
        m_unresolvedWindowStart = at;
    } else {
        const quint64 delta = unresolvedBytes - m_unresolvedLastBytes;
        m_unresolvedLastBytes = unresolvedBytes;
        if (!m_unresolvedWindowStart.isValid()
            || m_unresolvedWindowStart.secsTo(at) > m_settings.unresolvedWindowSeconds) {
            m_unresolvedWindowStart = at;
            m_unresolvedWindowBytes = 0;
        }
        m_unresolvedWindowBytes += delta;
    }

    const bool unresolvedCooledDown = m_unresolvedLastEventMs == 0
        || nowMs - m_unresolvedLastEventMs
               >= static_cast<qint64>(m_settings.unresolvedCooldownSeconds) * 1000;
    if (m_unresolvedWindowBytes >= m_settings.unresolvedBytesThreshold
        && unresolvedCooledDown) {
        events.append(makeUnresolvedEvent(at, m_unresolvedWindowBytes,
                                          m_unresolvedWindowStart));
        m_unresolvedLastEventMs = nowMs;
        m_unresolvedWindowBytes = 0;
        m_unresolvedWindowStart = at;
    }

    return events;
}

Event Detector::makeSpikeEvent(const QDateTime &at, const ProcessRate &rate,
                               const Track &track) const
{
    Event event;
    event.at = at;
    event.category = Category::Spike;
    event.badge = rate.foreground ? QStringLiteral("Foreground Surge")
                                  : QStringLiteral("Bandwidth Spike");
    event.title = QStringLiteral("%1 sustained a bandwidth spike").arg(rate.name);
    event.description = QStringLiteral(
        "Traffic stayed well above this application's recent average for several "
        "seconds. No policy was changed.");
    event.appName = rate.name;
    event.appPath = rate.path;
    event.pid = rate.pid;
    event.destination = rate.destination;
    event.attribution = rate.attribution;
    event.volumeBytes = track.spikeBytes;
    event.peakBytesPerSecond = track.peakBytesPerSecond;
    if (rate.foreground)
        event.extra.append({ QStringLiteral("Foreground"), QStringLiteral("Yes") });
    event.id = makeEventId(event.category, at, rate.name,
                           QString::number(rate.pid));
    return event;
}

Event Detector::makeUnresolvedEvent(const QDateTime &at, quint64 bytes,
                                    const QDateTime &windowStart) const
{
    Event event;
    event.at = at;
    event.category = Category::Unresolved;
    event.badge = QStringLiteral("Unrecognized Traffic");
    event.title = QStringLiteral("Unattributed external data transfer detected");
    event.description = QStringLiteral(
        "Data moved without a confirmed owning process or destination name. "
        "Oasis did not guess an owner.");
    event.appName = QStringLiteral("Unrecognized traffic");
    event.attribution = QStringLiteral("Unknown");
    event.volumeBytes = bytes;
    event.extra.append({ QStringLiteral("Local match"), QStringLiteral("None") });
    if (windowStart.isValid()) {
        event.extra.append({
            QStringLiteral("Window"),
            QStringLiteral("%1–%2").arg(
                windowStart.toString(QStringLiteral("HH:mm:ss")),
                at.toString(QStringLiteral("HH:mm:ss")))
        });
    }
    event.id = makeEventId(event.category, at, QStringLiteral("unresolved"));
    return event;
}

} // namespace Activity
