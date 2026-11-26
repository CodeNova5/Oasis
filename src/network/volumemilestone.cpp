/**
 * @file    volumemilestone.cpp
 * @brief   Data Saver volume milestone accounting and dedupe (DS-004).
 * @author  Oasis
 */
#include "volumemilestone.h"

#include <QCryptographicHash>

#include <limits>

namespace {

quint64 saturatingAdd(quint64 left, quint64 right)
{
    const quint64 maximum = std::numeric_limits<quint64>::max();
    return left > maximum - right ? maximum : left + right;
}

QString eventKey(const QString &scopeKey, int index)
{
    return scopeKey + QLatin1Char('#') + QString::number(index);
}

struct Aggregate
{
    MilestoneScope scope = MilestoneScope::Flow;
    QString scopeId;
    QString scopeKey;
    quint64 total = 0;
    QDateTime timestamp;
    QString flowId;
    QString processInstanceId;
    QString domain;
};

} // namespace

namespace VolumeMilestone {

quint64 thresholdBytes(int index)
{
    if (index <= 0) return 0;
    switch (index) {
    case 1: return 10 * kMiB;
    case 2: return 25 * kMiB;
    case 3: return 50 * kMiB;
    case 4: return 100 * kMiB;
    default: break;
    }

    const int shift = index - 4;
    const quint64 maximum = std::numeric_limits<quint64>::max();
    if (shift >= 64 || (100 * kMiB) > (maximum >> shift))
        return maximum;
    return (100 * kMiB) << shift;
}

int highestCrossedIndex(quint64 bytes)
{
    int highest = 0;
    // The threshold saturates at quint64::max, so cap the walk instead of
    // looping forever when the counter itself is saturated.
    for (int index = 1; index < 64; ++index) {
        const quint64 threshold = thresholdBytes(index);
        if (threshold == 0 || bytes < threshold) break;
        highest = index;
    }
    return highest;
}

} // namespace VolumeMilestone

QString milestoneScopeToken(MilestoneScope scope)
{
    switch (scope) {
    case MilestoneScope::Flow: return QStringLiteral("flow");
    case MilestoneScope::Process: return QStringLiteral("process");
    case MilestoneScope::Domain: return QStringLiteral("domain");
    }
    return QStringLiteral("unknown");
}

VolumeMilestoneEvaluator::VolumeMilestoneEvaluator(qint64 dedupeWindowMs, int maxScopes)
    : m_windowMs(qMax<qint64>(0, dedupeWindowMs))
    , m_maxScopes(qMax(1, maxScopes))
    , m_nonce((static_cast<quint64>(QDateTime::currentMSecsSinceEpoch()) << 17)
              ^ static_cast<quint64>(quintptr(this)))
{
    m_clock.start();
}

QList<MilestoneCrossing> VolumeMilestoneEvaluator::evaluate(
    const QList<FlowObservation> &observations, qint64 nowMs)
{
    QMutexLocker locker(&m_mutex);
    const qint64 now = nowMs >= 0 ? nowMs : m_clock.elapsed();
    pruneLocked(now);

    QHash<QString, Aggregate> aggregates;

    for (const FlowObservation &observation : observations) {
        const quint64 total = saturatingAdd(observation.metrics.rxBytes,
                                            observation.metrics.txBytes);

        if (!observation.flow.flowId.isEmpty()) {
            Aggregate &flow = aggregates[QStringLiteral("flow|") + observation.flow.flowId];
            flow.scope = MilestoneScope::Flow;
            flow.scopeId = observation.flow.flowId;
            flow.scopeKey = QStringLiteral("flow|") + observation.flow.flowId;
            flow.total = saturatingAdd(flow.total, total);
            flow.flowId = observation.flow.flowId;
            flow.processInstanceId = observation.process.processInstanceId;
            flow.domain = observation.flow.domain;
            if (!flow.timestamp.isValid() || observation.timestamp > flow.timestamp)
                flow.timestamp = observation.timestamp;
        }

        if (!observation.process.processInstanceId.isEmpty()) {
            Aggregate &process = aggregates[QStringLiteral("process|")
                                            + observation.process.processInstanceId];
            process.scope = MilestoneScope::Process;
            process.scopeId = observation.process.processInstanceId;
            process.scopeKey = QStringLiteral("process|")
                               + observation.process.processInstanceId;
            process.total = saturatingAdd(process.total, total);
            process.processInstanceId = observation.process.processInstanceId;
            if (!process.timestamp.isValid() || observation.timestamp > process.timestamp)
                process.timestamp = observation.timestamp;
        }

        // A missing domain is not a domain scope: it must not silently aggregate
        // unrelated destinations under an empty key.
        if (!observation.flow.domain.isEmpty()) {
            Aggregate &domain = aggregates[QStringLiteral("domain|") + observation.flow.domain];
            domain.scope = MilestoneScope::Domain;
            domain.scopeId = observation.flow.domain;
            domain.scopeKey = QStringLiteral("domain|") + observation.flow.domain;
            domain.total = saturatingAdd(domain.total, total);
            domain.domain = observation.flow.domain;
            if (!domain.timestamp.isValid() || observation.timestamp > domain.timestamp)
                domain.timestamp = observation.timestamp;
        }
    }

    QList<MilestoneCrossing> crossings;
    for (const Aggregate &aggregate : aggregates) {
        auto scope = m_scopes.find(aggregate.scopeKey);
        if (scope == m_scopes.end()) {
            while (m_scopes.size() >= m_maxScopes)
                evictOldestScopeLocked();
            scope = m_scopes.insert(aggregate.scopeKey, ScopeState());
            scope->lastSeenMs = now;
        }

        ScopeState &state = scope.value();
        if (aggregate.total < state.total) {
            // Counter rollover or a shorter replacement flow. The evidence is
            // new, but the same scope and bucket must not be re-evaluated inside
            // the window.
            state.highestAccepted = 0;
            state.total = 0;
        }

        const int highest = VolumeMilestone::highestCrossedIndex(aggregate.total);
        for (int index = state.highestAccepted + 1; index <= highest; ++index) {
            const QString key = eventKey(aggregate.scopeKey, index);
            const auto emitted = m_emittedAt.constFind(key);
            const bool withinWindow =
                emitted != m_emittedAt.constEnd() && now >= emitted.value()
                && now - emitted.value() < m_windowMs;
            if (withinWindow) {
                ++m_suppressed;
                continue;
            }

            MilestoneCrossing crossing;
            crossing.observationId = mintObservationId(aggregate.scopeKey, index);
            crossing.timestamp = aggregate.timestamp.isValid()
                                     ? aggregate.timestamp
                                     : QDateTime::currentDateTimeUtc();
            crossing.scope = aggregate.scope;
            crossing.scopeId = aggregate.scopeId;
            crossing.milestoneIndex = index;
            crossing.milestoneBytes = VolumeMilestone::thresholdBytes(index);
            crossing.cumulativeBytes = aggregate.total;
            crossing.flowId = aggregate.flowId;
            crossing.processInstanceId = aggregate.processInstanceId;
            crossing.domain = aggregate.domain;
            crossings.append(crossing);

            m_emittedAt.insert(key, now);
            ++m_accepted;
        }

        state.highestAccepted = qMax(state.highestAccepted, highest);
        state.total = aggregate.total;
        state.lastSeenMs = now;
    }
    return crossings;
}

int VolumeMilestoneEvaluator::acceptedCount() const
{
    QMutexLocker locker(&m_mutex);
    return m_accepted;
}

int VolumeMilestoneEvaluator::suppressedCount() const
{
    QMutexLocker locker(&m_mutex);
    return m_suppressed;
}

void VolumeMilestoneEvaluator::reset()
{
    QMutexLocker locker(&m_mutex);
    m_scopes.clear();
    m_emittedAt.clear();
    m_accepted = 0;
    m_suppressed = 0;
}

QString VolumeMilestoneEvaluator::mintObservationId(const QString &scopeKey, int index)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(QByteArray::number(m_nonce));
    hash.addData("|milestone|");
    hash.addData(QByteArray::number(m_sequence++));
    hash.addData(scopeKey.toUtf8());
    hash.addData("|");
    hash.addData(QByteArray::number(index));
    return QStringLiteral("obs_") + QString::fromLatin1(hash.result().toHex().left(16));
}

void VolumeMilestoneEvaluator::pruneLocked(qint64 nowMs)
{
    if (m_emittedAt.size() <= m_maxScopes)
        return;

    for (auto it = m_emittedAt.begin(); it != m_emittedAt.end();) {
        if (it.value() > nowMs || nowMs - it.value() >= m_windowMs)
            it = m_emittedAt.erase(it);
        else
            ++it;
    }
    // If nothing has aged out yet, keep the store bounded by dropping entries.
    // A dropped entry can only cause a later re-evaluation, never a missed one.
    while (m_emittedAt.size() > m_maxScopes)
        m_emittedAt.erase(m_emittedAt.begin());
}

void VolumeMilestoneEvaluator::evictOldestScopeLocked()
{
    QString oldestKey;
    qint64 oldest = std::numeric_limits<qint64>::max();
    for (auto it = m_scopes.constBegin(); it != m_scopes.constEnd(); ++it) {
        if (it->lastSeenMs < oldest) {
            oldest = it->lastSeenMs;
            oldestKey = it.key();
        }
    }
    if (oldestKey.isEmpty())
        return;

    const auto oldestScope = m_scopes.find(oldestKey);
    if (oldestScope == m_scopes.end())
        return;
    m_scopes.erase(oldestScope);
    const QString prefix = oldestKey + QLatin1Char('#');
    for (auto it = m_emittedAt.begin(); it != m_emittedAt.end();) {
        if (it.key().startsWith(prefix))
            it = m_emittedAt.erase(it);
        else
            ++it;
    }
}
