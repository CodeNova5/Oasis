/**
 * @file    volumemilestone.h
 * @brief   Data Saver volume milestones and evaluation dedupe (DS-004).
 *
 * Thresholds follow docs/DATA_SAVER_CONTRACT.md §2.1: 10/25/50/100 MiB and each
 * later doubling (200, 400, 800 MiB, ...). The evaluator consumes the canonical
 * `FlowObservation`s from DS-003 and reports crossings only; it never applies a
 * policy, blocks, or throttles.
 *
 * Accounting runs per flow, per process instance, and per domain. A crossing is
 * keyed by scope identity plus bucket (flow id, process instance id, or
 * normalized domain), so a PID reuse, a re-established flow, or an application
 * restart cannot inherit a prior crossing. Counter rollover resets the scope,
 * and a re-cross inside the configured evaluation window is suppressed rather
 * than treated as new evidence.
 *
 * The evaluator is mutex-guarded and bounded: at most 4096 scopes and 4096
 * remembered emissions, with the oldest scope evicted under pressure.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QElapsedTimer>
#include <QHash>
#include <QList>
#include <QMetaType>
#include <QMutex>
#include <QString>

#include "flowobservation.h"

namespace VolumeMilestone {

constexpr quint64 kMiB = 1024ULL * 1024ULL;

/// Threshold for a 1-based milestone index. 0 means "no milestone"; indexes
/// beyond the representable range return `std::numeric_limits<quint64>::max()`.
quint64 thresholdBytes(int index);

/// Highest milestone index whose threshold `bytes` has reached (0 when none).
int highestCrossedIndex(quint64 bytes);

} // namespace VolumeMilestone

enum class MilestoneScope {
    Flow,
    Process,
    Domain
};

QString milestoneScopeToken(MilestoneScope scope);

/// One accepted milestone crossing. This is an evaluation trigger, not an
/// enforcement action. `observationId` is minted per crossing and never reused.
struct MilestoneCrossing
{
    QString observationId;          // obs_ + 16 lower-case hex
    QDateTime timestamp;
    MilestoneScope scope = MilestoneScope::Flow;
    QString scopeId;                // flow id, process instance id, or domain
    int milestoneIndex = 0;         // 1-based
    quint64 milestoneBytes = 0;     // threshold reached
    quint64 cumulativeBytes = 0;    // scope total when it was reached
    QString flowId;
    QString processInstanceId;
    QString domain;
};
Q_DECLARE_METATYPE(MilestoneCrossing)

class VolumeMilestoneEvaluator
{
public:
    /// `dedupeWindowMs` is the minimum time a crossing for the same scope and
    /// bucket stays deduplicated (the contract's evaluation window). The window
    /// matters when a counter resets and climbs through the same bucket again.
    explicit VolumeMilestoneEvaluator(qint64 dedupeWindowMs = 10 * 60 * 1000,
                                      int maxScopes = 4096);

    /// Returns the crossings accepted for this snapshot. `nowMs` is monotonic
    /// milliseconds; a negative value uses the evaluator's own clock, so tests
    /// can supply deterministic times.
    QList<MilestoneCrossing> evaluate(const QList<FlowObservation> &observations,
                                      qint64 nowMs = -1);

    int acceptedCount() const;
    int suppressedCount() const;
    void reset();

private:
    struct ScopeState
    {
        quint64 total = 0;
        int highestAccepted = 0;
        qint64 lastSeenMs = 0;
    };

    QString mintObservationId(const QString &scopeKey, int index);
    void pruneLocked(qint64 nowMs);
    void evictOldestScopeLocked();

    mutable QMutex m_mutex;
    QHash<QString, ScopeState> m_scopes;   // scope token + id -> accounting state
    QHash<QString, qint64> m_emittedAt;    // scope key + '#' + index -> accepted ms
    QElapsedTimer m_clock;
    qint64 m_windowMs = 10 * 60 * 1000;
    int m_maxScopes = 4096;
    quint64 m_nonce = 0;
    quint64 m_sequence = 0;
    int m_accepted = 0;
    int m_suppressed = 0;
};
