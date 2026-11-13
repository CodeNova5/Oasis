/**
 * @file    foregroundsignal.h
 * @brief   Foreground application and active-session signal (NG-041).
 * @author  Oasis
 *
 * The signal answers one question: is this PID part of the application the user
 * is currently looking at? It is sampled from the foreground window and the
 * active console session, expanded to the live child processes that carry a
 * browser's or launcher's traffic, and stamped with the sample time so a stale
 * answer is never presented as current.
 *
 * The signal is advisory. It is an input to classification (NG-040) and
 * recommendations (NG-042); it never applies, withdraws, or overrides a policy.
 * An explicit user policy always wins.
 */
#pragma once

#include <QMetaType>
#include <QSet>
#include <QString>

#include "processlineage.h"

namespace Oasis {

/// How a PID relates to the application the user is looking at.
enum class ForegroundAssociation : int {
    None = 0,        // not the foreground app and not one of its live children
    ForegroundApp,   // owns the foreground window
    ForegroundChild  // live child of the foreground application
};

QString foregroundAssociationName(ForegroundAssociation association);

/**
 * One raw sample from the Windows APIs. Kept separate from the validated
 * snapshot so the association logic can be exercised without a real window.
 */
struct ForegroundObservation
{
    bool    hasWindow             = false;
    quint32 pid                   = 0;
    quint32 sessionId             = 0;
    bool    sessionKnown          = false;
    quint32 activeConsoleSessionId = 0;
    qint64  startTimeMs           = 0; // process creation time, 0 when unreadable
    qint64  sampledAtMs           = 0;
    QString processName;
    QString executablePath;
};

/**
 * The validated foreground state for one sample. `sampledAtMs` is the freshness
 * timestamp: callers pass it to `isFresh()`/`associationFor()` and a stale
 * sample never reports an association.
 */
struct ForegroundSnapshot
{
    /// A sample older than this is not presented as the current foreground app.
    static constexpr int kFreshnessMs          = 5000;
    /// Descendant expansion stops at this depth so a corrupt tree cannot run away.
    static constexpr int kMaxDescendantDepth   = 4;
    /// Hard bound on the PIDs associated with one foreground application.
    static constexpr int kMaxAssociatedPids    = 128;

    bool    hasForegroundWindow   = false;
    /// The foreground PID was replaced (creation time changed) since the sample;
    /// the association is discarded instead of inherited by the new process.
    bool    staleObservation      = false;
    quint32 foregroundPid         = 0;
    quint32 sessionId             = 0;
    bool    sessionKnown          = false;
    quint32 activeConsoleSessionId = 0;
    qint64  sampledAtMs           = 0;
    QString processName;
    QString executablePath;
    QString identityId;
    QString groupId;
    QString groupName;
    QSet<quint32> associatedPids;

    bool isValid() const
    {
        return hasForegroundWindow && foregroundPid != 0 && !staleObservation;
    }
    /// True when the foreground window is in the active console session.
    bool activeSessionMatches() const;
    /// True while the sample is no older than `maxAgeMs`.
    bool isFresh(qint64 nowMs, int maxAgeMs = kFreshnessMs) const;
    /// None for an unknown, stale, or unrelated PID. Freshness is enforced here,
    /// so a caller cannot accidentally act on an old sample.
    ForegroundAssociation associationFor(quint32 pid, qint64 nowMs,
                                         int maxAgeMs = kFreshnessMs) const;
    bool isAssociated(quint32 pid, qint64 nowMs,
                      int maxAgeMs = kFreshnessMs) const
    {
        return associationFor(pid, nowMs, maxAgeMs) != ForegroundAssociation::None;
    }

    /// One sentence for a tooltip or an audit line.
    QString evidenceText() const;

    /// The signal is advisory by construction. These helpers exist so a caller
    /// cannot mistake it for an enforcement source.
    static bool isAdvisory() { return true; }
    static bool canChangePolicy() { return false; }
};

/**
 * Samples the foreground window and resolves it against the tracked process
 * lineage. `observeNow()` is the only Windows-specific part; `buildSnapshot()`
 * is pure and is what the harness exercises.
 */
class ForegroundSampler
{
public:
    static ForegroundObservation observeNow();

    /// Validate the observation against the lineage, discard a recycled PID, and
    /// expand the foreground process to its live descendants.
    static ForegroundSnapshot buildSnapshot(const ForegroundObservation &observation,
                                            const ProcessLineage &lineage,
                                            qint64 nowMs);

    /// Observe the live desktop and build the snapshot in one call.
    static ForegroundSnapshot sample(const ProcessLineage &lineage, qint64 nowMs);
};

} // namespace Oasis

Q_DECLARE_METATYPE(Oasis::ForegroundSnapshot)
