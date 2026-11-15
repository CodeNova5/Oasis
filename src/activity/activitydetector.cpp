/**
 * @file    activitydetector.cpp
 * @author  Oasis
 */
#include "activitydetector.h"

#include <QMutableHashIterator>

#include <algorithm>

namespace Activity {

namespace {

QString rateLabel(quint64 bytesPerSecond)
{
    const double mib = static_cast<double>(bytesPerSecond) / (1024.0 * 1024.0);
    if (mib >= 1.0)
        return QStringLiteral("%1 MiB/s").arg(mib, 0, 'f', 1);
    return QStringLiteral("%1 KiB/s")
        .arg(static_cast<double>(bytesPerSecond) / 1024.0, 0, 'f', 0);
}

QString volumeLabel(quint64 bytes)
{
    const double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
    if (mib >= 1.0)
        return QStringLiteral("%1 MiB").arg(mib, 0, 'f', 1);
    return QStringLiteral("%1 KiB").arg(static_cast<double>(bytes) / 1024.0, 0, 'f', 0);
}

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
    m_settings.samplingWindow = std::max(1, m_settings.samplingWindow);
    m_settings.sustainSeconds = std::max(1, m_settings.sustainSeconds);
    // A sustain longer than the window can never be satisfied; clamp instead of
    // silently never firing.
    m_settings.sustainSeconds = std::min(m_settings.sustainSeconds,
                                         m_settings.samplingWindow);
    m_settings.baselineSeconds = std::max(3, m_settings.baselineSeconds);
    m_settings.cooldownSeconds = std::max(0, m_settings.cooldownSeconds);
    m_settings.unresolvedWindowSeconds = std::max(1, m_settings.unresolvedWindowSeconds);
    m_settings.unresolvedCooldownSeconds = std::max(0, m_settings.unresolvedCooldownSeconds);
    m_settings.unresolvedSustainSeconds =
        std::max(1, std::min(m_settings.unresolvedSustainSeconds,
                             m_settings.samplingWindow));
    if (m_settings.absoluteFloorBytesPerSecond == 0)
        m_settings.absoluteFloorBytesPerSecond = 1;
    if (m_settings.unresolvedBytesThreshold == 0)
        m_settings.unresolvedBytesThreshold = 1;
    m_settings.highBandwidthSustainSeconds =
        std::max(1, m_settings.highBandwidthSustainSeconds);
    m_settings.highBandwidthCooldownSeconds =
        std::max(0, m_settings.highBandwidthCooldownSeconds);
    if (m_settings.highBandwidthFloorBytesPerSecond == 0)
        m_settings.highBandwidthFloorBytesPerSecond = 1;
    m_settings.backgroundWindowSeconds = std::max(1, m_settings.backgroundWindowSeconds);
    m_settings.backgroundCooldownSeconds =
        std::max(0, m_settings.backgroundCooldownSeconds);
    m_settings.crossCategoryCooldownSeconds =
        std::max(0, m_settings.crossCategoryCooldownSeconds);
    if (m_settings.backgroundVolumeThreshold == 0)
        m_settings.backgroundVolumeThreshold = 1;
    m_settings.consumptionWindowSeconds =
        std::max(1, m_settings.consumptionWindowSeconds);
    m_settings.consumptionSuppressionSeconds =
        std::max(0, m_settings.consumptionSuppressionSeconds);
    if (m_settings.consumptionWarningBytes == 0)
        m_settings.consumptionWarningBytes = 1;
    // A critical level below the warning would make the ladder meaningless.
    m_settings.consumptionCriticalBytes = std::max(
        m_settings.consumptionWarningBytes, m_settings.consumptionCriticalBytes);
}

void Detector::clear()
{
    m_tracks.clear();
    m_unresolvedLastBytes = 0;
    m_unresolvedWindowBytes = 0;
    m_unresolvedWindowStart = QDateTime();
    m_unresolvedLastEventMs = 0;
    m_unresolvedRates.clear();
    m_unresolvedEvidence.clear();
    m_unresolvedWindowQualified = false;
    m_unresolvedLastBeatMs = 0;
    m_consumptionSystemWindow.clear();
    m_consumptionSystemLevel = 0;
    m_consumptionSystemLastEventMs = 0;
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
    const qint64 consumptionWindowMs =
        static_cast<qint64>(m_settings.consumptionWindowSeconds) * 1000;

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

        // Evidence is a rolling window rather than a consecutive-run counter: a
        // sustained transfer keeps its credit through a single dip, so sampling
        // jitter cannot restart detection. Volume and peak are accumulated over
        // the same window for the event card.
        track.evidence.append(qualifies);
        while (track.evidence.size() > m_settings.samplingWindow)
            track.evidence.removeFirst();

        if (qualifies) {
            track.quietSamples = 0;
            track.spikeBytes += current;
            track.peakBytesPerSecond = std::max(track.peakBytesPerSecond, current);
        } else {
            ++track.quietSamples;
            // Enough quiet samples that the window cannot reach the required
            // count again: the spike has ended. Any cooldown left over from it
            // is dropped so the next, genuinely separate episode can report at
            // once instead of waiting out a timer from the previous one.
            if (track.quietSamples >= m_settings.samplingWindow) {
                track.evidence.clear();
                track.ongoing = false;
                track.lastEventMs = 0;
                track.spikeBytes = 0;
                track.peakBytesPerSecond = 0;
            }
        }

        const int qualifying = int(std::count(track.evidence.cbegin(),
                                              track.evidence.cend(), true));
        const bool cooledDown = track.lastEventMs == 0
            || nowMs - track.lastEventMs
                   >= static_cast<qint64>(m_settings.cooldownSeconds) * 1000;
        if (!track.ongoing
            && qualifying >= m_settings.sustainSeconds
            && cooledDown) {
            events.append(makeSpikeEvent(at, rate, track));
            track.lastEventMs = nowMs;
            track.lastAnyEventMs = nowMs;
            track.ongoing = true;
            track.evidence.clear();
            track.spikeBytes = 0;
            track.peakBytesPerSecond = 0;
        }

        // ── High bandwidth usage ──────────────────────────────────────────
        // The same measurement answers a different question: not "is this
        // surprising?" but "what is steadily eating the allowance?". Kept
        // independent of the spike state so heavy-but-normal transfers are
        // visible, and suppressed only while a spike for the same application
        // is already on screen, so one run never produces two cards.
        if (current >= m_settings.highBandwidthFloorBytesPerSecond) {
            ++track.highSeconds;
            track.highBytes += current;
            track.highPeakBytesPerSecond =
                std::max(track.highPeakBytesPerSecond, current);
        } else {
            track.highSeconds = 0;
            track.highBytes = 0;
            track.highPeakBytesPerSecond = 0;
            track.highOngoing = false;
        }

        const bool highCooledDown = track.lastHighEventMs == 0
            || nowMs - track.lastHighEventMs
                   >= static_cast<qint64>(m_settings.highBandwidthCooldownSeconds)
                          * 1000;
        const bool crossCooledDown = track.lastAnyEventMs == 0
            || nowMs - track.lastAnyEventMs
                   >= static_cast<qint64>(m_settings.crossCategoryCooldownSeconds)
                          * 1000;
        if (!track.ongoing
            && !track.highOngoing
            && crossCooledDown
            && track.highSeconds >= m_settings.highBandwidthSustainSeconds
            && highCooledDown) {
            events.append(makeHighBandwidthEvent(at, rate, track));
            track.lastHighEventMs = nowMs;
            track.lastAnyEventMs = nowMs;
            track.highOngoing = true;
            track.highBytes = 0;
            track.highPeakBytesPerSecond = 0;
        }

        // ── Unusual background consumption ────────────────────────────────
        // Accumulated per rolling window instead of per beat: the question is
        // how much data left or arrived while the user was doing something
        // else, which is a volume question. Foreground bytes are accumulated
        // too, so an application the user was actively using is never reported
        // as background usage.
        if (track.backgroundWindowStartMs == 0
            || nowMs - track.backgroundWindowStartMs
                   > static_cast<qint64>(m_settings.backgroundWindowSeconds) * 1000) {
            track.backgroundBytes = 0;
            track.backgroundForegroundBytes = 0;
            track.backgroundPeakBytesPerSecond = 0;
            track.backgroundWindowStartMs = nowMs;
        }

        if (rate.foreground) {
            track.backgroundForegroundBytes += current;
        } else {
            track.backgroundBytes += current;
            track.backgroundPeakBytesPerSecond =
                std::max(track.backgroundPeakBytesPerSecond, current);
        }

        const bool backgroundCooledDown = track.lastBackgroundEventMs == 0
            || nowMs - track.lastBackgroundEventMs
                   >= static_cast<qint64>(m_settings.backgroundCooldownSeconds) * 1000;
        if (crossCooledDown
            && track.lastAnyEventMs != nowMs // a high-bandwidth card already claimed this beat
            && backgroundCooledDown
            && !track.ongoing
            && track.backgroundBytes >= m_settings.backgroundVolumeThreshold
            && track.backgroundBytes > track.backgroundForegroundBytes) {
            events.append(makeBackgroundEvent(at, rate, track));
            track.lastBackgroundEventMs = nowMs;
            track.lastAnyEventMs = nowMs;
            track.backgroundBytes = 0;
            track.backgroundForegroundBytes = 0;
            track.backgroundPeakBytesPerSecond = 0;
            track.backgroundWindowStartMs = nowMs;
        }

        // ── Data consumption surge ────────────────────────────────────────
        // Volume inside a rolling window, independent of every rate detector:
        // an application can stay under all of them and still use up a
        // noticeable share of an allowance. Unlike the rate categories this one
        // deliberately ignores the cross-category cooldown, because the bytes
        // are the story even when a spike or high-bandwidth card also fired.
        track.consumptionWindow.append({ nowMs, current });
        while (!track.consumptionWindow.isEmpty()
               && nowMs - track.consumptionWindow.first().first > consumptionWindowMs)
            track.consumptionWindow.removeFirst();

        quint64 consumed = 0;
        quint64 consumptionPeak = 0;
        for (const QPair<qint64, quint64> &sample : track.consumptionWindow) {
            consumed += sample.second;
            consumptionPeak = std::max(consumptionPeak, sample.second);
        }

        // The window drained below the warning level: whatever was running has
        // stopped, so the next transfer is a new episode with its own levels.
        if (consumed < m_settings.consumptionWarningBytes)
            track.consumptionLevel = 0;

        const bool consumptionSuppressed = track.lastConsumptionEventMs != 0
            && nowMs - track.lastConsumptionEventMs
                   < static_cast<qint64>(m_settings.consumptionSuppressionSeconds)
                          * 1000;
        if (consumed >= m_settings.consumptionCriticalBytes
            && track.consumptionLevel < 2) {
            // Escalation is not a repeat: the higher level is never held back
            // by the suppression window that a warning just opened.
            events.append(makeConsumptionEvent(at, rate, consumed,
                                               consumptionPeak, 2));
            track.consumptionLevel = 2;
            track.lastConsumptionEventMs = nowMs;
        } else if (consumed >= m_settings.consumptionWarningBytes
                   && track.consumptionLevel < 1
                   && !consumptionSuppressed) {
            events.append(makeConsumptionEvent(at, rate, consumed,
                                               consumptionPeak, 1));
            track.consumptionLevel = 1;
            track.lastConsumptionEventMs = nowMs;
        }

        track.history.append(current);
        while (track.history.size() > m_settings.baselineSeconds)
            track.history.removeFirst();
    }

    // Applications that stopped sending still have bytes inside the rolling
    // window. Prune them here so an idle application cannot keep its level (and
    // keep the machine-wide card suppressed) after its transfer ended.
    for (auto trackIt = m_tracks.begin(); trackIt != m_tracks.end(); ++trackIt) {
        Track &track = trackIt.value();
        if (track.lastSeenMs == nowMs)
            continue;
        while (!track.consumptionWindow.isEmpty()
               && nowMs - track.consumptionWindow.first().first > consumptionWindowMs)
            track.consumptionWindow.removeFirst();
        quint64 remaining = 0;
        for (const QPair<qint64, quint64> &sample : track.consumptionWindow)
            remaining += sample.second;
        if (remaining < m_settings.consumptionWarningBytes)
            track.consumptionLevel = 0;
    }

    // Forget applications that sent nothing for ten minutes: memory stays
    // bounded even on a machine that starts hundreds of short-lived helpers.
    QMutableHashIterator<QString, Track> it(m_tracks);
    while (it.hasNext()) {
        it.next();
        if (nowMs - it.value().lastSeenMs > 10 * 60 * 1000)
            it.remove();
    }

    // ── Machine-wide data consumption ─────────────────────────────────────
    // Two or three applications can each stay under every per-application
    // threshold and still add up to a transfer worth reporting. The counter is
    // only reported when no single application already frames those bytes, so
    // one busy download does not produce an application card and a system card
    // for the same transfer.
    quint64 attributed = 0;
    quint64 busiestBytes = 0;
    QString busiestName;
    int activeApplications = 0;
    for (const ProcessRate &rate : rates) {
        const quint64 current = rate.rxBytesPerSecond + rate.txBytesPerSecond;
        if (current == 0)
            continue;
        attributed += current;
        ++activeApplications;
        if (current > busiestBytes) {
            busiestBytes = current;
            busiestName = rate.name;
        }
    }

    m_consumptionSystemWindow.append({ nowMs, attributed });
    const qint64 systemWindowMs =
        static_cast<qint64>(m_settings.consumptionWindowSeconds) * 1000;
    while (!m_consumptionSystemWindow.isEmpty()
           && nowMs - m_consumptionSystemWindow.first().first > systemWindowMs)
        m_consumptionSystemWindow.removeFirst();
    quint64 systemConsumed = 0;
    for (const QPair<qint64, quint64> &sample : m_consumptionSystemWindow)
        systemConsumed += sample.second;

    if (systemConsumed < m_settings.consumptionWarningBytes)
        m_consumptionSystemLevel = 0;

    bool applicationExplains = false;
    for (auto trackIt = m_tracks.constBegin(); trackIt != m_tracks.constEnd();
         ++trackIt) {
        if (trackIt.value().consumptionLevel >= 1) {
            applicationExplains = true;
            break;
        }
    }

    const bool systemSuppressed = m_consumptionSystemLastEventMs != 0
        && nowMs - m_consumptionSystemLastEventMs
               < static_cast<qint64>(m_settings.consumptionSuppressionSeconds) * 1000;
    if (!applicationExplains
        && systemConsumed >= m_settings.consumptionCriticalBytes
        && m_consumptionSystemLevel < 2) {
        events.append(makeSystemConsumptionEvent(at, systemConsumed, busiestName,
                                                 busiestBytes, activeApplications, 2));
        m_consumptionSystemLevel = 2;
        m_consumptionSystemLastEventMs = nowMs;
    } else if (!applicationExplains
               && systemConsumed >= m_settings.consumptionWarningBytes
               && m_consumptionSystemLevel < 1
               && !systemSuppressed) {
        events.append(makeSystemConsumptionEvent(at, systemConsumed, busiestName,
                                                 busiestBytes, activeApplications, 1));
        m_consumptionSystemLevel = 1;
        m_consumptionSystemLastEventMs = nowMs;
    }

    // ── Unresolved traffic ────────────────────────────────────────────────
    // Some traffic is unattributable by nature: kernel counters, System, a
    // service running without an image path. Steady background bytes like that
    // used to cross the volume threshold every cooldown and produce a card with
    // no possible action. So a window only becomes reportable once the unresolved
    // rate has risen clear of its own recent baseline for several beats; a
    // constant trickle never does, and a transfer that stands out still does.
    // Clamped to [1, 60] so a paused or resumed tick cannot skew the rate.
    // Every argument is qint64: mixing int literals with a qint64 value makes
    // qBound's mixed-type overloads ambiguous.
    int elapsedSeconds = 1;
    if (m_unresolvedLastBeatMs > 0)
        elapsedSeconds = int(qBound<qint64>(
            qint64(1), (nowMs - m_unresolvedLastBeatMs) / 1000, qint64(60)));
    m_unresolvedLastBeatMs = nowMs;

    if (unresolvedBytes < m_unresolvedLastBytes) {
        // The unresolved set shrank (a process exited or was identified), so a
        // negative delta is not traffic; start a fresh window.
        m_unresolvedLastBytes = unresolvedBytes;
        m_unresolvedWindowBytes = 0;
        m_unresolvedWindowStart = at;
        m_unresolvedWindowQualified = false;
        m_unresolvedEvidence.clear();
    } else {
        const quint64 delta = unresolvedBytes - m_unresolvedLastBytes;
        m_unresolvedLastBytes = unresolvedBytes;
        const quint64 rate = delta / quint64(elapsedSeconds);

        if (!m_unresolvedWindowStart.isValid()
            || m_unresolvedWindowStart.secsTo(at) > m_settings.unresolvedWindowSeconds) {
            m_unresolvedWindowStart = at;
            m_unresolvedWindowBytes = 0;
            m_unresolvedWindowQualified = false;
            m_unresolvedEvidence.clear();
        }

        // The measure is how far this beat rises above the median of the recent
        // beats, not the rate itself: a stream that simply continues what was
        // already there contributes nothing, while a new or growing one clears
        // the floor immediately. That is what keeps steady background traffic
        // from producing a card every cooldown period.
        const quint64 beatBaseline = typicalRate(m_unresolvedRates);
        const quint64 excess = rate > beatBaseline ? rate - beatBaseline : 0;
        const bool notable =
            excess > 0 && excess >= m_settings.unresolvedFloorBytesPerSecond;

        // Same rolling-window idea as the spike detector: a single flat beat in
        // the middle of a rising transfer should not discard the evidence.
        m_unresolvedEvidence.append(notable);
        while (m_unresolvedEvidence.size() > m_settings.samplingWindow)
            m_unresolvedEvidence.removeFirst();
        const int notableBeats = int(std::count(m_unresolvedEvidence.cbegin(),
                                                m_unresolvedEvidence.cend(), true));
        if (notableBeats >= m_settings.unresolvedSustainSeconds)
            m_unresolvedWindowQualified = true;

        m_unresolvedRates.append(rate);
        while (m_unresolvedRates.size() > m_settings.baselineSeconds)
            m_unresolvedRates.removeFirst();

        m_unresolvedWindowBytes += delta;
    }

    const bool unresolvedCooledDown = m_unresolvedLastEventMs == 0
        || nowMs - m_unresolvedLastEventMs
               >= static_cast<qint64>(m_settings.unresolvedCooldownSeconds) * 1000;
    if (m_unresolvedWindowQualified
        && m_unresolvedWindowBytes >= m_settings.unresolvedBytesThreshold
        && unresolvedCooledDown) {
        // Name the busiest rows that landed in the unresolved bucket instead of
        // reporting a bare "Unknown": the same condition that makes a row
        // unattributed (no executable path or no activity match) is checked
        // here, and the largest rates are the most likely cause.
        QList<ProcessRate> unmatched;
        for (const ProcessRate &rate : rates) {
            if (rate.path.trimmed().isEmpty() || rate.attribution.trimmed().isEmpty())
                unmatched.append(rate);
        }
        std::stable_sort(unmatched.begin(), unmatched.end(),
                         [](const ProcessRate &a, const ProcessRate &b) {
            return a.rxBytesPerSecond + a.txBytesPerSecond
                 > b.rxBytesPerSecond + b.txBytesPerSecond;
        });

        QStringList contributors;
        QStringList contributorNames;
        for (const ProcessRate &rate : unmatched) {
            if (contributors.size() >= 3) break;
            const quint64 current = rate.rxBytesPerSecond + rate.txBytesPerSecond;
            if (current == 0 || contributorNames.contains(rate.name)) continue;
            contributorNames.append(rate.name);
            contributors.append(QStringLiteral("%1 (%2)")
                                    .arg(rate.name, rateLabel(current)));
        }

        events.append(makeUnresolvedEvent(at, m_unresolvedWindowBytes,
                                          m_unresolvedWindowStart, contributors));
        m_unresolvedLastEventMs = nowMs;
        m_unresolvedWindowBytes = 0;
        m_unresolvedWindowStart = at;
        m_unresolvedWindowQualified = false;
        m_unresolvedEvidence.clear();
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
        "Traffic stayed well above this application's recent average for a few "
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

Event Detector::makeHighBandwidthEvent(const QDateTime &at, const ProcessRate &rate,
                                       const Track &track) const
{
    Event event;
    event.at = at;
    event.category = Category::HighBandwidth;
    event.badge = QStringLiteral("High Bandwidth");
    event.title = QStringLiteral("%1 is sustaining high bandwidth").arg(rate.name);
    event.description = QStringLiteral(
        "This application has stayed above the high-bandwidth floor while the "
        "rate is normal for it. That is usage worth knowing about, not a spike; "
        "no policy was changed.");
    event.appName = rate.name;
    event.appPath = rate.path;
    event.pid = rate.pid;
    event.destination = rate.destination;
    event.attribution = rate.attribution;
    event.volumeBytes = track.highBytes;
    event.peakBytesPerSecond = track.highPeakBytesPerSecond;
    event.extra.append({ QStringLiteral("Above floor"),
                         rateLabel(m_settings.highBandwidthFloorBytesPerSecond) });
    event.extra.append({ QStringLiteral("Sustained"),
                         QStringLiteral("%1 s").arg(track.highSeconds) });
    if (rate.foreground)
        event.extra.append({ QStringLiteral("Foreground"), QStringLiteral("Yes") });
    event.id = makeEventId(event.category, at, rate.name,
                           QString::number(rate.pid));
    return event;
}

Event Detector::makeBackgroundEvent(const QDateTime &at, const ProcessRate &rate,
                                   const Track &track) const
{
    Event event;
    event.at = at;
    event.category = Category::Background;
    event.badge = QStringLiteral("Background Usage");
    event.title = QStringLiteral("%1 moved data while in the background").arg(rate.name);
    event.description = QStringLiteral(
        "Most of this transfer happened while the application was not in the "
        "foreground. Updates and sync can do this legitimately; it is reported "
        "so data used without the user watching is not invisible.");
    event.appName = rate.name;
    event.appPath = rate.path;
    event.pid = rate.pid;
    event.destination = rate.destination;
    event.attribution = rate.attribution;
    event.volumeBytes = track.backgroundBytes;
    event.peakBytesPerSecond = track.backgroundPeakBytesPerSecond;

    const quint64 total = track.backgroundBytes + track.backgroundForegroundBytes;
    if (total > 0) {
        const int share = int((track.backgroundBytes * 100) / total);
        event.extra.append({ QStringLiteral("Background share"),
                             QStringLiteral("%1%").arg(share) });
    }
    if (track.backgroundWindowStartMs > 0) {
        const QDateTime windowStart =
            QDateTime::fromMSecsSinceEpoch(track.backgroundWindowStartMs);
        event.extra.append({
            QStringLiteral("Window"),
            QStringLiteral("%1–%2").arg(
                windowStart.toString(QStringLiteral("HH:mm:ss")),
                at.toString(QStringLiteral("HH:mm:ss")))
        });
    }
    event.id = makeEventId(event.category, at, rate.name,
                           QString::number(rate.pid));
    return event;
}

Event Detector::makeConsumptionEvent(const QDateTime &at, const ProcessRate &rate,
                                     quint64 consumed, quint64 peak, int level) const
{
    const bool critical = level >= 2;
    Event event;
    event.at = at;
    event.category = Category::Consumption;
    event.severity = critical ? QStringLiteral("critical")
                              : QStringLiteral("warning");
    event.badge = QStringLiteral("Data Consumption");
    event.title = critical
        ? QStringLiteral("%1 consumed %2 in a short window")
              .arg(rate.name, volumeLabel(consumed))
        : QStringLiteral("%1 is using up data steadily").arg(rate.name);
    event.description = QStringLiteral(
        "This is volume, not speed: the application stayed under the rate "
        "thresholds and still used %1 within %2 seconds. Worth knowing on a "
        "limited connection; no policy was changed.")
        .arg(volumeLabel(consumed))
        .arg(m_settings.consumptionWindowSeconds);
    event.appName = rate.name;
    event.appPath = rate.path;
    event.pid = rate.pid;
    event.destination = rate.destination;
    event.attribution = rate.attribution;
    event.volumeBytes = consumed;
    event.peakBytesPerSecond = peak;
    event.extra.append({ QStringLiteral("Level"),
                         critical ? QStringLiteral("Critical")
                                  : QStringLiteral("Warning") });
    event.extra.append({ QStringLiteral("Consumed"), volumeLabel(consumed) });
    event.extra.append({ QStringLiteral("Window"),
                         QStringLiteral("%1 s").arg(m_settings.consumptionWindowSeconds) });
    event.extra.append({ QStringLiteral("Peak rate"), rateLabel(peak) });
    if (rate.foreground)
        event.extra.append({ QStringLiteral("Foreground"), QStringLiteral("Yes") });
    event.id = makeEventId(event.category, at, rate.name,
                           QStringLiteral("%1-%2").arg(rate.pid).arg(level));
    return event;
}

Event Detector::makeSystemConsumptionEvent(const QDateTime &at, quint64 consumed,
                                           const QString &busiest, quint64 busiestBytes,
                                           int activeApplications, int level) const
{
    const bool critical = level >= 2;
    Event event;
    event.at = at;
    event.category = Category::Consumption;
    event.severity = critical ? QStringLiteral("critical")
                              : QStringLiteral("warning");
    event.badge = QStringLiteral("Data Consumption");
    event.title = critical
        ? QStringLiteral("All applications consumed %1 in a short window")
              .arg(volumeLabel(consumed))
        : QStringLiteral("Machine-wide data use is adding up");
    event.description = QStringLiteral(
        "No single application crossed its own consumption level, but together "
        "they used %1 within %2 seconds across %3 active applications. "
        "Reported once per episode; no policy was changed.")
        .arg(volumeLabel(consumed))
        .arg(m_settings.consumptionWindowSeconds)
        .arg(activeApplications);
    event.appName = QStringLiteral("All applications");
    event.attribution = QStringLiteral("System-wide");
    event.volumeBytes = consumed;
    event.peakBytesPerSecond = busiestBytes;
    event.extra.append({ QStringLiteral("Level"),
                         critical ? QStringLiteral("Critical")
                                  : QStringLiteral("Warning") });
    event.extra.append({ QStringLiteral("Consumed"), volumeLabel(consumed) });
    event.extra.append({ QStringLiteral("Window"),
                         QStringLiteral("%1 s").arg(m_settings.consumptionWindowSeconds) });
    if (!busiest.isEmpty()) {
        event.extra.append({ QStringLiteral("Busiest application"),
                             QStringLiteral("%1 (%2)")
                                 .arg(busiest, rateLabel(busiestBytes)) });
    }
    event.extra.append({ QStringLiteral("Active applications"),
                         QString::number(activeApplications) });
    event.id = makeEventId(event.category, at, QStringLiteral("all-applications"),
                           QString::number(level));
    return event;
}

Event Detector::makeUnresolvedEvent(const QDateTime &at, quint64 bytes,
                                    const QDateTime &windowStart,
                                    const QStringList &contributors) const
{
    Event event;
    event.at = at;
    event.category = Category::Unresolved;
    event.badge = QStringLiteral("Unrecognized Traffic");
    event.title = QStringLiteral("Unattributed external data transfer detected");
    event.description = QStringLiteral(
        "Data moved without a confirmed owning process or destination name. "
        "Oasis lists the busiest applications it could not match rather than "
        "guessing an owner.");
    event.appName = QStringLiteral("Unrecognized traffic");
    event.attribution = QStringLiteral("Unknown");
    event.volumeBytes = bytes;
    event.extra.append({ QStringLiteral("Local match"), QStringLiteral("None") });
    if (!contributors.isEmpty()) {
        event.extra.append({ QStringLiteral("Most active without a match"),
                             contributors.join(QStringLiteral(", ")) });
    }
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
