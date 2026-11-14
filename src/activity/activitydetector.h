/**
 * @file    activitydetector.h
 * @brief   Turns one-second telemetry into Spike and Unresolved events.
 *
 * The detector is deliberately conservative:
 *
 *   Spike      an application stays above both an absolute floor and several
 *              times its own recent average for a few seconds. A one-second
 *              burst is not an event.
 *   Unresolved traffic accumulates in a bounded window and only becomes an
 *              event once a meaningful amount moved with no resolvable owner.
 *
 * One event per application per cooldown, so a sustained transfer does not
 * produce a card every second. Nothing here enforces anything; the page turns
 * an event into a user action.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>
#include <QVector>

#include "activity/activityevent.h"

namespace Activity {

struct DetectorSettings
{
    quint64 absoluteFloorBytesPerSecond = 2 * 1024 * 1024; // ~16 Mbit/s
    double  baselineMultiplier = 3.0;
    int     sustainSeconds = 5;
    int     baselineSeconds = 60;
    int     cooldownSeconds = 180;
    quint64 unresolvedBytesThreshold = 8 * 1024 * 1024;
    int     unresolvedWindowSeconds = 300;
    int     unresolvedCooldownSeconds = 180;
};

struct ProcessRate
{
    QString name;
    QString path;
    quint32 pid = 0;
    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
    QString destination;
    QString attribution;
    bool    foreground = false;
};

class Detector
{
public:
    explicit Detector(const DetectorSettings &settings = DetectorSettings());

    /// Feeds one telemetry beat. `unresolvedBytes` is the cumulative bytes this
    /// build cannot attribute to a process; the detector uses its growth.
    QList<Event> observe(const QDateTime &at, const QList<ProcessRate> &rates,
                         quint64 unresolvedBytes);

    void clear();
    void setSettings(const DetectorSettings &settings);
    DetectorSettings settings() const { return m_settings; }

private:
    struct Track
    {
        QVector<quint64> history;
        int     aboveSeconds = 0;
        quint64 spikeBytes = 0;
        quint64 peakBytesPerSecond = 0;
        qint64  lastEventMs = 0;
        qint64  lastSeenMs = 0;
    };

    Event makeSpikeEvent(const QDateTime &at, const ProcessRate &rate,
                         const Track &track) const;
    Event makeUnresolvedEvent(const QDateTime &at, quint64 bytes,
                              const QDateTime &windowStart) const;

    DetectorSettings m_settings;
    QHash<QString, Track> m_tracks; // application name -> rolling evidence
    quint64 m_unresolvedLastBytes = 0;
    quint64 m_unresolvedWindowBytes = 0;
    QDateTime m_unresolvedWindowStart;
    qint64  m_unresolvedLastEventMs = 0;
};

} // namespace Activity
