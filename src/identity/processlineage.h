/**
 * @file    processlineage.h
 * @brief   Process lineage and PID-reuse tracking (NG-013).
 *
 * Records the parent PID, children, start time, and executable identity of
 * every process the monitor observes. A PID is only treated as the same
 * process while its creation time matches, so a recycled PID can never inherit
 * the previous process's identity. Records that stop being observed age out:
 * they are marked exited first and dropped after a retention window.
 *
 * The tracker is used from the monitor's cache thread only; it does not lock.
 */
#pragma once

#include <QHash>
#include <QList>
#include <QString>
#include <QVector>

namespace Oasis {

// ─── One tracked process instance ───────────────────────────────────────────
struct ProcessLineageRecord
{
    quint32 pid        = 0;
    quint32 parentPid  = 0;
    quint32 generation = 0;       // 1 for the first instance of a PID, +1 per reuse
    QString processName;
    QString executablePath;
    QString identityId;           // NG-010 identity, once resolved
    qint64  startTimeMs = 0;      // process creation time (UTC ms); 0 = unknown
    qint64  firstSeenMs = 0;
    qint64  lastSeenMs  = 0;
    qint64  exitedAtMs  = 0;      // set when the instance is marked exited
    bool    alive       = false;

    bool isValid() const { return pid != 0; }
};

// ─── Observation fed to the tracker ────────────────────────────────────────
struct LineageObservation
{
    quint32 pid         = 0;
    quint32 parentPid   = 0;
    qint64  startTimeMs = 0;      // 0 when the caller could not read it
    QString processName;
    QString executablePath;
    QString identityId;
};

enum class LineageChange : int {
    NewInstance = 0, // first sighting of this PID
    Reused,          // same PID, different creation time: a new process
    Revived,         // an instance previously marked exited is observed again
    Exited,          // not observed for longer than the stale window
    Expired          // exited long enough ago to be forgotten
};

QString lineageChangeName(LineageChange change);

struct LineageTransition
{
    LineageChange         change = LineageChange::NewInstance;
    ProcessLineageRecord  record;    // state after the change
    ProcessLineageRecord  previous;  // state before it (empty for NewInstance)
};

// ─── Tracker ────────────────────────────────────────────────────────────────
class ProcessLineage
{
public:
    // Feed one observation. Returns the transitions it caused: NewInstance,
    // Reused, or Revived. An unchanged observation returns nothing.
    QVector<LineageTransition> observe(const LineageObservation &observation);

    // Age the map: instances unseen for staleAfterMs become Exited, and records
    // exited for longer than retainAfterExitMs are dropped. Both are reported so
    // callers can prune anything keyed by PID.
    QVector<LineageTransition> expire(qint64 nowMs,
                                      int staleAfterMs = 30000,
                                      int retainAfterExitMs = 300000);

    ProcessLineageRecord record(quint32 pid) const;
    bool contains(quint32 pid) const { return m_byPid.contains(pid); }

    QVector<ProcessLineageRecord> liveRecords() const;
    QVector<ProcessLineageRecord> childrenOf(quint32 pid) const;
    // Nearest parent first, bounded by maxDepth so a corrupt cycle cannot hang.
    QList<ProcessLineageRecord> ancestorsOf(quint32 pid, int maxDepth = 16) const;

    int     trackedCount() const { return m_byPid.size(); }
    int     liveCount()    const;
    quint64 reuseCount()   const { return m_reuseCount; }

    void clear();

    // "2026-11-06T21:14:03Z" for display, empty when the start time is unknown.
    static QString formatStartTime(qint64 startTimeMs);

private:
    QHash<quint32, ProcessLineageRecord> m_byPid;
    quint64 m_reuseCount = 0;
};

} // namespace Oasis
