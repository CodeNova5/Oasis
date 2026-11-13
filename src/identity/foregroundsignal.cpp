/**
 * @file    foregroundsignal.cpp
 * @brief   Foreground application and active-session signal (NG-041).
 * @author  Oasis
 */
#include "foregroundsignal.h"

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <QDateTime>
#include <QList>

namespace {

// Process creation time as UTC milliseconds since the epoch (0 when unknown).
qint64 fileTimeToMs(const FILETIME &fileTime)
{
    ULARGE_INTEGER value;
    value.LowPart  = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    if (value.QuadPart == 0) return 0;
    return static_cast<qint64>(value.QuadPart / 10000ULL) - 11644473600000LL;
}

QString processNameFromPath(const QString &path)
{
    const int slash = path.lastIndexOf(QLatin1Char('\\'));
    return slash >= 0 ? path.mid(slash + 1) : path;
}

} // namespace

namespace Oasis {

QString foregroundAssociationName(ForegroundAssociation association)
{
    switch (association) {
    case ForegroundAssociation::ForegroundApp:   return QStringLiteral("foreground application");
    case ForegroundAssociation::ForegroundChild: return QStringLiteral("foreground helper");
    case ForegroundAssociation::None:            break;
    }
    return QStringLiteral("background");
}

bool ForegroundSnapshot::activeSessionMatches() const
{
    // WTSGetActiveConsoleSessionId() returns 0xFFFFFFFF when no console session
    // exists, for example on a locked or headless machine.
    return sessionKnown
        && sessionId != 0xFFFFFFFFu
        && activeConsoleSessionId != 0xFFFFFFFFu
        && sessionId == activeConsoleSessionId;
}

bool ForegroundSnapshot::isFresh(qint64 nowMs, int maxAgeMs) const
{
    if (sampledAtMs <= 0 || maxAgeMs < 0) return false;
    const qint64 age = nowMs >= sampledAtMs ? nowMs - sampledAtMs
                                            : sampledAtMs - nowMs;
    return age <= maxAgeMs;
}

ForegroundAssociation ForegroundSnapshot::associationFor(quint32 pid, qint64 nowMs,
                                                         int maxAgeMs) const
{
    if (!isValid() || pid == 0 || !isFresh(nowMs, maxAgeMs))
        return ForegroundAssociation::None;
    if (pid == foregroundPid)
        return ForegroundAssociation::ForegroundApp;
    if (associatedPids.contains(pid))
        return ForegroundAssociation::ForegroundChild;
    return ForegroundAssociation::None;
}

QString ForegroundSnapshot::evidenceText() const
{
    if (staleObservation) {
        return QStringLiteral("The foreground window belonged to a process that "
                              "has since been replaced; the association was "
                              "discarded.");
    }
    if (!isValid())
        return QStringLiteral("No foreground application was observed.");

    const QString name = processName.trimmed().isEmpty()
        ? QStringLiteral("PID %1").arg(foregroundPid)
        : processName.trimmed();

    QString text = QStringLiteral("Foreground application: %1 (PID %2)")
                       .arg(name)
                       .arg(foregroundPid);
    if (activeSessionMatches())
        text += QStringLiteral(", active session");
    const int helpers = associatedPids.size() - 1;
    if (helpers > 0)
        text += QStringLiteral(", plus %1 live helper(s)").arg(helpers);
    text += QStringLiteral("; sampled at %1.")
                .arg(QDateTime::fromMSecsSinceEpoch(sampledAtMs)
                         .toString(QStringLiteral("HH:mm:ss")));
    return text;
}

ForegroundObservation ForegroundSampler::observeNow()
{
    ForegroundObservation observation;
    observation.sampledAtMs = QDateTime::currentMSecsSinceEpoch();
    observation.activeConsoleSessionId = WTSGetActiveConsoleSessionId();

    const HWND window = GetForegroundWindow();
    if (!window) return observation;

    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid == 0) return observation;

    observation.hasWindow = true;
    observation.pid = static_cast<quint32>(pid);

    DWORD session = 0;
    if (ProcessIdToSessionId(pid, &session)) {
        observation.sessionId = static_cast<quint32>(session);
        observation.sessionKnown = true;
    }

    // PROCESS_QUERY_LIMITED_INFORMATION is enough for the path and creation time
    // and works for most elevated processes from a normal user session.
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process) {
        wchar_t path[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(process, 0, path, &size)) {
            observation.executablePath =
                QString::fromWCharArray(path, static_cast<int>(size));
            observation.processName = processNameFromPath(observation.executablePath);
        }

        FILETIME created{}, exited{}, kernel{}, user{};
        if (GetProcessTimes(process, &created, &exited, &kernel, &user))
            observation.startTimeMs = fileTimeToMs(created);
        CloseHandle(process);
    }

    return observation;
}

ForegroundSnapshot ForegroundSampler::buildSnapshot(const ForegroundObservation &observation,
                                                    const ProcessLineage &lineage,
                                                    qint64 nowMs)
{
    ForegroundSnapshot snapshot;
    snapshot.sampledAtMs = observation.sampledAtMs > 0 ? observation.sampledAtMs
                                                       : nowMs;
    snapshot.sessionId = observation.sessionId;
    snapshot.sessionKnown = observation.sessionKnown;
    snapshot.activeConsoleSessionId = observation.activeConsoleSessionId;

    if (!observation.hasWindow || observation.pid == 0)
        return snapshot;

    const ProcessLineageRecord record = lineage.record(observation.pid);

    // A recycled PID must not inherit the previous process's foreground state.
    // Only a known, differing creation time proves replacement; a process whose
    // start time could not be read keeps the tracked instance.
    if (record.isValid() && record.startTimeMs > 0 && observation.startTimeMs > 0
        && record.startTimeMs != observation.startTimeMs) {
        snapshot.staleObservation = true;
        snapshot.foregroundPid = observation.pid;
        return snapshot;
    }

    snapshot.hasForegroundWindow = true;
    snapshot.foregroundPid = observation.pid;
    snapshot.processName = !observation.processName.isEmpty()
        ? observation.processName
        : record.processName;
    snapshot.executablePath = !observation.executablePath.isEmpty()
        ? observation.executablePath
        : record.executablePath;
    snapshot.identityId = record.identityId;
    snapshot.associatedPids.insert(observation.pid);

    // A browser's or launcher's traffic usually belongs to a renderer, GPU, or
    // utility child rather than the process that owns the window, so the live
    // descendants are part of the foreground application too. The walk is
    // depth- and size-bounded and never leaves the tracked process tree.
    QSet<quint32> visited;
    visited.insert(observation.pid);
    QList<quint32> frontier;
    frontier.append(observation.pid);

    bool full = false;
    for (int depth = 0; depth < ForegroundSnapshot::kMaxDescendantDepth && !full; ++depth) {
        QList<quint32> next;
        for (quint32 parent : frontier) {
            const QVector<ProcessLineageRecord> children = lineage.childrenOf(parent);
            for (const ProcessLineageRecord &child : children) {
                if (child.pid == 0 || visited.contains(child.pid))
                    continue;
                if (snapshot.associatedPids.size() >= ForegroundSnapshot::kMaxAssociatedPids) {
                    full = true;
                    break;
                }
                visited.insert(child.pid);
                snapshot.associatedPids.insert(child.pid);
                next.append(child.pid);
            }
            if (full) break;
        }
        frontier = next;
        if (frontier.isEmpty()) break;
    }

    return snapshot;
}

ForegroundSnapshot ForegroundSampler::sample(const ProcessLineage &lineage, qint64 nowMs)
{
    return buildSnapshot(observeNow(), lineage, nowMs);
}

} // namespace Oasis
