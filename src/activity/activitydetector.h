/**
 * @file    activitydetector.h
 * @brief   Turns one-second telemetry into Spike and Unresolved events.
 *
 * The detector is deliberately conservative:
 *
 *   Spike      an application stays above both an absolute floor and several
 *              times its own recent average for a few seconds. A single
 *              low sample inside an otherwise sustained run is tolerated, and
 *              a single one-second burst is not an event.
 *   High bandwidth
 *              an application stays above a high absolute rate for long enough
 *              that the consumption itself is the story, even though the rate
 *              is normal for that application. Kept separate from Spike so
 *              steady heavy use is never presented as suspicious behavior.
 *   Background
 *              an application moves a meaningful volume while it is not the
 *              foreground application. Volume, not rate: a slow sync and a
 *              fast one both cost the same data allowance. A transfer that was
 *              mostly in the foreground is not reported here.
 *   Unresolved traffic accumulates in a bounded window and only becomes an
 *              event once a meaningful amount moved with no resolvable owner,
 *              and only when that traffic stood clear of its own recent
 *              baseline. Constant unattributable background traffic (kernel
 *              counters, System) therefore stays quiet. This gate has its own
 *              sustain so tuning the spike detector cannot loosen it.
 *
 * One event per application per episode, so a sustained transfer does not
 * produce a card every few seconds while it is still running; a later, separate
 * episode can report again. Nothing here enforces anything; the page turns an
 * event into a user action.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVector>

#include "activity/activityevent.h"

namespace Activity {

struct DetectorSettings
{
    /// A spike is relative first, absolute second: turning this too far down
    /// would flag every ordinary page load on a metered connection.
    quint64 absoluteFloorBytesPerSecond = 1 * 1024 * 1024; // ~8 Mbit/s
    double  baselineMultiplier = 3.0;
    /// Qualifying one-second samples required inside the sampling window.
    int     sustainSeconds = 3;
    /// Rolling window of recent samples: the difference between this and
    /// sustainSeconds is how many brief dips a spike may absorb, so one noisy
    /// beat does not restart the whole detection.
    int     samplingWindow = 5;
    int     baselineSeconds = 60;
    int     cooldownSeconds = 90;
    /// A card about traffic nobody can name is only worth showing when enough
    /// data moved to act on. 8 MiB used to qualify, which is ordinary Windows
    /// background chatter; 16 MiB is a transfer the user would notice on a
    /// metered connection.
    quint64 unresolvedBytesThreshold = 16 * 1024 * 1024;
    int     unresolvedWindowSeconds = 300;
    int     unresolvedCooldownSeconds = 300;
    /// How far unresolved traffic has to rise above its own recent median rate
    /// before it can count as an anomaly rather than background noise. Lower
    /// than the per-application floor because unresolved traffic has no owner
    /// to compare itself against; the volume threshold above does the heavy
    /// lifting against false positives.
    quint64 unresolvedFloorBytesPerSecond = 256 * 1024;
    /// Notable beats required inside the sampling window. Separate from
    /// sustainSeconds on purpose: this evidence is weaker (no owner, no
    /// baseline of its own beyond a few beats), so it must not get quieter just
    /// because the spike detector is tuned.
    int     unresolvedSustainSeconds = 3;

    // ── High bandwidth usage ─────────────────────────────────────────────
    /// Steady, substantial consumption. Not relative to the app's own history:
    /// a launcher that always downloads at 15 MiB/s never spikes, and the user
    /// still needs to know where the data went.
    quint64 highBandwidthFloorBytesPerSecond = 5 * 1024 * 1024; // ~40 Mbit/s
    int     highBandwidthSustainSeconds = 10;
    int     highBandwidthCooldownSeconds = 15 * 60;

    // ── Unusual background consumption ──────────────────────────────────
    /// Bytes moved while the application was not in front of the user, inside
    /// one rolling window. Volume rather than rate: what matters for a data
    /// allowance is how much moved, not how quickly it moved.
    quint64 backgroundVolumeThreshold = 32 * 1024 * 1024; // 32 MiB
    int     backgroundWindowSeconds = 300;
    int     backgroundCooldownSeconds = 10 * 60;

    /// One continuous transfer should tell one story: once an application has
    /// produced a spike, high-bandwidth or background card, the other two stay
    /// quiet for this long so the feed does not stack three cards about the
    /// same bytes.
    int     crossCategoryCooldownSeconds = 15 * 60;
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
        /// Qualification of the most recent samples, newest last.
        QVector<bool> evidence;
        quint64 spikeBytes = 0;
        quint64 peakBytesPerSecond = 0;
        /// Samples below the threshold since the last qualifying one.
        int     quietSamples = 0;
        /// True while an emitted spike is still running: suppresses duplicates.
        bool    ongoing = false;
        qint64  lastEventMs = 0;
        qint64  lastSeenMs = 0;
        // Steady-high-bandwidth evidence, kept apart from the spike run above so
        // one can never shorten or reset the other.
        int     highSeconds = 0;
        quint64 highBytes = 0;
        quint64 highPeakBytesPerSecond = 0;
        bool    highOngoing = false;
        qint64  lastHighEventMs = 0;
        // Background traffic is accumulated per window and only counted when
        // the application is not the foreground one; foreground bytes are kept
        // so a mostly-foreground transfer cannot be reported as background use.
        quint64 backgroundBytes = 0;
        quint64 backgroundForegroundBytes = 0;
        quint64 backgroundPeakBytesPerSecond = 0;
        qint64  backgroundWindowStartMs = 0;
        qint64  lastBackgroundEventMs = 0;
        /// Last event of any category for this application (see
        /// crossCategoryCooldownSeconds).
        qint64  lastAnyEventMs = 0;
    };

    Event makeSpikeEvent(const QDateTime &at, const ProcessRate &rate,
                         const Track &track) const;
    Event makeHighBandwidthEvent(const QDateTime &at, const ProcessRate &rate,
                                 const Track &track) const;
    Event makeBackgroundEvent(const QDateTime &at, const ProcessRate &rate,
                              const Track &track) const;
    Event makeUnresolvedEvent(const QDateTime &at, quint64 bytes,
                              const QDateTime &windowStart,
                              const QStringList &contributors) const;

    DetectorSettings m_settings;
    QHash<QString, Track> m_tracks; // application name -> rolling evidence
    quint64 m_unresolvedLastBytes = 0;
    quint64 m_unresolvedWindowBytes = 0;
    QDateTime m_unresolvedWindowStart;
    qint64  m_unresolvedLastEventMs = 0;
    // Recent unresolved rate per beat, used as the traffic's own baseline so a
    // steady trickle cannot keep crossing the volume threshold.
    QVector<quint64> m_unresolvedRates;
    /// Qualification of the most recent beats, newest last, so one flat beat
    /// does not throw away an otherwise standing-out transfer.
    QVector<bool> m_unresolvedEvidence;
    bool    m_unresolvedWindowQualified = false;
    qint64  m_unresolvedLastBeatMs = 0;
};

} // namespace Activity
