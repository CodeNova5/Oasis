/**
 * @file    processlineage.cpp
 * @brief   Process lineage and PID-reuse tracking (NG-013).
 */
#include "processlineage.h"

#include <QDateTime>
#include <QSet>
#include <QTimeZone>

namespace Oasis {

QString lineageChangeName(LineageChange change)
{
    switch (change) {
    case LineageChange::NewInstance: return QStringLiteral("new");
    case LineageChange::Reused:      return QStringLiteral("reused");
    case LineageChange::Revived:     return QStringLiteral("revived");
    case LineageChange::Exited:      return QStringLiteral("exited");
    case LineageChange::Expired:     return QStringLiteral("expired");
    }
    return QStringLiteral("unknown");
}

QVector<LineageTransition> ProcessLineage::observe(const LineageObservation &observation)
{
    QVector<LineageTransition> transitions;
    if (observation.pid == 0)
        return transitions;

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const auto existing = m_byPid.constFind(observation.pid);

    if (existing == m_byPid.constEnd()) {
        ProcessLineageRecord fresh;
        fresh.pid            = observation.pid;
        fresh.parentPid      = observation.parentPid;
        fresh.generation     = 1;
        fresh.processName    = observation.processName;
        fresh.executablePath = observation.executablePath;
        fresh.identityId     = observation.identityId;
        fresh.startTimeMs    = observation.startTimeMs;
        fresh.firstSeenMs    = now;
        fresh.lastSeenMs     = now;
        fresh.alive          = true;
        m_byPid.insert(fresh.pid, fresh);

        LineageTransition transition;
        transition.change = LineageChange::NewInstance;
        transition.record = fresh;
        transitions.append(transition);
        return transitions;
    }

    const ProcessLineageRecord previous = existing.value();

    // PID reuse: only decidable when both creation times are known. A process
    // whose start time could not be read keeps the recorded instance instead of
    // being mistaken for a replacement.
    if (previous.startTimeMs > 0 && observation.startTimeMs > 0
        && previous.startTimeMs != observation.startTimeMs) {
        ProcessLineageRecord fresh;
        fresh.pid            = observation.pid;
        fresh.parentPid      = observation.parentPid;
        fresh.generation     = previous.generation + 1;
        fresh.processName    = observation.processName;
        fresh.executablePath = observation.executablePath;
        fresh.identityId     = observation.identityId;
        fresh.startTimeMs    = observation.startTimeMs;
        fresh.firstSeenMs    = now;
        fresh.lastSeenMs     = now;
        fresh.alive          = true;

        m_byPid.insert(fresh.pid, fresh);
        ++m_reuseCount;

        LineageTransition transition;
        transition.change   = LineageChange::Reused;
        transition.record   = fresh;
        transition.previous = previous; // keeps the old executable and identity
        transitions.append(transition);
        return transitions;
    }

    // Same instance: refresh what is known. Missing values never overwrite
    // information we already have.
    ProcessLineageRecord &current = m_byPid[observation.pid];
    current.lastSeenMs = now;
    if (current.startTimeMs == 0 && observation.startTimeMs > 0)
        current.startTimeMs = observation.startTimeMs;
    if (observation.parentPid != 0)
        current.parentPid = observation.parentPid;
    if (!observation.processName.isEmpty())
        current.processName = observation.processName;
    if (!observation.executablePath.isEmpty())
        current.executablePath = observation.executablePath;
    if (!observation.identityId.isEmpty())
        current.identityId = observation.identityId;

    if (!current.alive) {
        current.alive = true;
        current.exitedAtMs = 0;
        LineageTransition transition;
        transition.change   = LineageChange::Revived;
        transition.record   = current;
        transition.previous = previous;
        transitions.append(transition);
    }

    return transitions;
}

QVector<LineageTransition> ProcessLineage::expire(qint64 nowMs, int staleAfterMs,
                                                  int retainAfterExitMs)
{
    QVector<LineageTransition> transitions;

    for (auto it = m_byPid.begin(); it != m_byPid.end(); ) {
        ProcessLineageRecord &record = it.value();

        if (record.alive && nowMs - record.lastSeenMs > staleAfterMs) {
            record.alive      = false;
            record.exitedAtMs = nowMs;

            LineageTransition transition;
            transition.change = LineageChange::Exited;
            transition.record = record;
            transitions.append(transition);
            ++it;
            continue;
        }

        if (!record.alive && nowMs - record.exitedAtMs > retainAfterExitMs) {
            LineageTransition transition;
            transition.change = LineageChange::Expired;
            transition.record = record;
            transitions.append(transition);
            it = m_byPid.erase(it);
            continue;
        }

        ++it;
    }

    return transitions;
}

ProcessLineageRecord ProcessLineage::record(quint32 pid) const
{
    return m_byPid.value(pid);
}

QVector<ProcessLineageRecord> ProcessLineage::liveRecords() const
{
    QVector<ProcessLineageRecord> result;
    for (const auto &record : m_byPid)
        if (record.alive) result.append(record);
    return result;
}

QVector<ProcessLineageRecord> ProcessLineage::childrenOf(quint32 pid) const
{
    QVector<ProcessLineageRecord> result;
    if (pid == 0) return result;
    for (const auto &record : m_byPid)
        if (record.parentPid == pid && record.alive) result.append(record);
    return result;
}

QList<ProcessLineageRecord> ProcessLineage::ancestorsOf(quint32 pid, int maxDepth) const
{
    QList<ProcessLineageRecord> chain;
    QSet<quint32> visited;
    visited.insert(pid);

    quint32 currentPid = pid;
    for (int depth = 0; depth < maxDepth; ++depth) {
        const auto current = m_byPid.constFind(currentPid);
        if (current == m_byPid.constEnd()) break;

        const quint32 parentPid = current->parentPid;
        if (parentPid == 0 || parentPid == currentPid || visited.contains(parentPid))
            break;

        const auto parent = m_byPid.constFind(parentPid);
        if (parent == m_byPid.constEnd()) break;

        visited.insert(parentPid);
        chain.append(parent.value());
        currentPid = parentPid;
    }

    return chain;
}

int ProcessLineage::liveCount() const
{
    int count = 0;
    for (const auto &record : m_byPid)
        if (record.alive) ++count;
    return count;
}

void ProcessLineage::clear()
{
    m_byPid.clear();
    m_reuseCount = 0;
}

QString ProcessLineage::formatStartTime(qint64 startTimeMs)
{
    if (startTimeMs <= 0) return QString();
    return QDateTime::fromMSecsSinceEpoch(startTimeMs, QTimeZone::UTC).toString(Qt::ISODate);
}

} // namespace Oasis
