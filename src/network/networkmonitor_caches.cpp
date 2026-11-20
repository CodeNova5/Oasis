/**
 * @file    networkmonitor_caches.cpp
 * @brief   Connection, identity, service, lineage and group cache refresh,
 *          split out of networkmonitor.cpp. Definitions only; the
 *          NetworkMonitor interface is unchanged.
 * @author  Oasis
 */
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif

#include "networkmonitor.h"

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QString>
#include <QStringList>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <netioapi.h>
#include <psapi.h>
#include <tlhelp32.h>

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

} // namespace

void NetworkMonitor::updateCaches()
{
    QHash<QString, quint32> tCache, uCache;
    QHash<quint16, quint32> tListenCache, uAnyCache;
    QHash<quint32, QString> pCache;

    // ── 1. Extract IPv4 Table ──
    DWORD szTcp = 0;
    GetExtendedTcpTable(nullptr, &szTcp, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    QByteArray bufTcp(szTcp += 1024*20, '\0');
    if (GetExtendedTcpTable(bufTcp.data(), &szTcp, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto *t = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(bufTcp.constData());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto &row = t->table[i];
            quint16 lport = ntohs(static_cast<uint16_t>(row.dwLocalPort));
            quint32 pid = static_cast<quint32>(row.dwOwningPid);
            if (row.dwState == MIB_TCP_STATE_LISTEN) tListenCache.insert(lport, pid);
            IN_ADDR la, ra; la.S_un.S_addr = row.dwLocalAddr; ra.S_un.S_addr = row.dwRemoteAddr;
            char ls[INET_ADDRSTRLEN]={}, rs[INET_ADDRSTRLEN]={};
            inet_ntop(AF_INET, &la, ls, sizeof(ls)); inet_ntop(AF_INET, &ra, rs, sizeof(rs));
            tCache.insert(QString::fromLatin1(ls) + ":" + QString::number(lport) + "-" + QString::fromLatin1(rs) + ":" + QString::number(ntohs(static_cast<uint16_t>(row.dwRemotePort))), pid);
        }
    }

    DWORD szUdp = 0;
    GetExtendedUdpTable(nullptr, &szUdp, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    QByteArray bufUdp(szUdp += 1024*20, '\0');
    if (GetExtendedUdpTable(bufUdp.data(), &szUdp, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        auto *u = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(bufUdp.constData());
        for (DWORD i = 0; i < u->dwNumEntries; ++i) {
            const auto &row = u->table[i];
            quint16 lport = ntohs(static_cast<uint16_t>(row.dwLocalPort));
            quint32 pid = static_cast<quint32>(row.dwOwningPid);
            if (row.dwLocalAddr == 0) uAnyCache.insert(lport, pid);
            IN_ADDR la; la.S_un.S_addr = row.dwLocalAddr;
            char ls[INET_ADDRSTRLEN]={}; inet_ntop(AF_INET, &la, ls, sizeof(ls));
            uCache.insert(QString::fromLatin1(ls) + ":" + QString::number(lport), pid);
        }
    }

    // ── 2. Extract IPv6 Table ──
    DWORD szTcp6 = 0;
    GetExtendedTcpTable(nullptr, &szTcp6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    QByteArray bufTcp6(szTcp6 += 1024*20, '\0');
    if (GetExtendedTcpTable(bufTcp6.data(), &szTcp6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto *t6 = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(bufTcp6.constData());
        for (DWORD i = 0; i < t6->dwNumEntries; ++i) {
            const auto &row = t6->table[i];
            quint16 lport = ntohs(static_cast<uint16_t>(row.dwLocalPort));
            quint32 pid = static_cast<quint32>(row.dwOwningPid);
            if (row.dwState == MIB_TCP_STATE_LISTEN) tListenCache.insert(lport, pid);

            char ls[INET6_ADDRSTRLEN]={}, rs[INET6_ADDRSTRLEN]={};
            // const_cast for MinGW compatibility
            inet_ntop(AF_INET6, const_cast<UCHAR*>(row.ucLocalAddr), ls, sizeof(ls));
            inet_ntop(AF_INET6, const_cast<UCHAR*>(row.ucRemoteAddr), rs, sizeof(rs));

            tCache.insert(QString::fromLatin1(ls) + ":" + QString::number(lport) + "-" + QString::fromLatin1(rs) + ":" + QString::number(ntohs(static_cast<uint16_t>(row.dwRemotePort))), pid);
        }
    }

    DWORD szUdp6 = 0;
    GetExtendedUdpTable(nullptr, &szUdp6, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    QByteArray bufUdp6(szUdp6 += 1024*20, '\0');
    if (GetExtendedUdpTable(bufUdp6.data(), &szUdp6, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        auto *u6 = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(bufUdp6.constData());
        for (DWORD i = 0; i < u6->dwNumEntries; ++i) {
            const auto &row = u6->table[i];
            quint16 lport = ntohs(static_cast<uint16_t>(row.dwLocalPort));
            quint32 pid = static_cast<quint32>(row.dwOwningPid);
            bool isAny = true;
            for(int j=0; j<16; ++j) if(row.ucLocalAddr[j] != 0) { isAny = false; break; }
            if (isAny) uAnyCache.insert(lport, pid);

            char ls[INET6_ADDRSTRLEN]={};
            inet_ntop(AF_INET6, const_cast<UCHAR*>(row.ucLocalAddr), ls, sizeof(ls));

            uCache.insert(QString::fromLatin1(ls) + ":" + QString::number(lport), pid);
        }
    }

    // ── 3. Resolve Service Hosting (NG-012) ──
    // One SCM snapshot per refresh window, shared by every PID below. The old
    // path enumerated all services once per svchost PID per loop.
    m_serviceResolver.refresh(2000);
    const Oasis::ServicePidMap servicesByPid = m_serviceResolver.servicesByPid();
    const QString serviceError = m_serviceResolver.lastError();
    if (serviceError != m_lastServiceError) {
        m_lastServiceError = serviceError;
        // A failure is recorded once per distinct reason; packets keep flowing.
        if (!serviceError.isEmpty()) emit serviceLookupFailed(serviceError);
    }

    // ── 3. Resolve Process Names and Lineage (NG-013) ──
    // Parent PIDs come from a single toolhelp snapshot; creation times are what
    // tell a recycled PID apart from the process it replaced.
    QHash<quint32, quint32> parentByPid;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W entry;
            entry.dwSize = sizeof(entry);
            if (Process32FirstW(snap, &entry)) {
                do {
                    parentByPid.insert(entry.th32ProcessID, entry.th32ParentProcessID);
                } while (Process32NextW(snap, &entry));
            }
            CloseHandle(snap);
        }
    }

    // Identities already resolved, attached so lineage records can be related
    // to a durable identity instead of a bare PID.
    QHash<quint32, QString> knownIdentities;
    {
        QMutexLocker lk(&m_cacheMutex);
        for (auto it = m_identityCache.constBegin(); it != m_identityCache.constEnd(); ++it)
            knownIdentities.insert(it.key(), it->id);
    }

    // Processes are observed every 200 ms, so anything unseen for 30 s is gone;
    // its record is kept for 5 minutes so helpers can still be related by PID.
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    m_lineage.expire(nowMs);
    QVector<Oasis::LineageTransition> reusedPids;

    DWORD aProcs[1024], cbNeeded, cProcs;
    if (EnumProcesses(aProcs, sizeof(aProcs), &cbNeeded)) {
        cProcs = cbNeeded / sizeof(DWORD);
        for (unsigned i = 0; i < cProcs; i++) {
            if (aProcs[i] != 0) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, aProcs[i]);
                if (hProc) {
                    wchar_t path[MAX_PATH] = {};
                    DWORD size = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
                        QString fullPath = QString::fromWCharArray(path, static_cast<int>(size));
                        int idx = fullPath.lastIndexOf(QLatin1Char('\\'));
                        QString procName = (idx >= 0) ? fullPath.mid(idx + 1) : fullPath;

                        // Any service host (not just svchost.exe) is named after
                        // the service it runs; the full list travels in the
                        // service snapshot so shared hosts stay separable.
                        const auto hosted = servicesByPid.constFind(aProcs[i]);
                        if (hosted != servicesByPid.constEnd() && !hosted->isEmpty()) {
                            QString primary = hosted->first().displayName;
                            for (const auto &svc : hosted.value()) {
                                if (svc.state == Oasis::ServiceState::Running) {
                                    primary = svc.displayName;
                                    break;
                                }
                            }
                            if (!primary.isEmpty()) procName = "Service: " + primary;
                        }
                        pCache.insert(aProcs[i], procName);

                        Oasis::LineageObservation observation;
                        observation.pid            = aProcs[i];
                        observation.parentPid      = parentByPid.value(aProcs[i], 0);
                        observation.processName    = procName;
                        observation.executablePath = fullPath;
                        observation.identityId     = knownIdentities.value(aProcs[i]);
                        FILETIME created{}, exitedTime{}, kernelTime{}, userTime{};
                        if (GetProcessTimes(hProc, &created, &exitedTime, &kernelTime, &userTime))
                            observation.startTimeMs = fileTimeToMs(created);

                        for (const auto &transition : m_lineage.observe(observation))
                            if (transition.change == Oasis::LineageChange::Reused)
                                reusedPids.append(transition);
                    }
                    CloseHandle(hProc);
                }
            }
        }
    }

    // A recycled PID must never inherit the previous process's attribution:
    // drop the cached identity before the identity pass below runs.
    if (!reusedPids.isEmpty()) {
        {
            QMutexLocker lk(&m_cacheMutex);
            for (const auto &transition : reusedPids) {
                m_identityCache.remove(transition.record.pid);
                m_identityFailurePids.remove(transition.record.pid);
            }
        }
        for (const auto &transition : reusedPids)
            emit pidReuseDetected(transition.record.pid,
                                  transition.previous.executablePath,
                                  transition.record.executablePath,
                                  transition.previous.startTimeMs,
                                  transition.record.startTimeMs);
    }

    // ── 3b. Resolve durable identities for PIDs that own live connections ──
    // Only processes with traffic are resolved, cached across refreshes, and
    // capped per refresh so version-resource reads never stall the cache loop.
    QSet<quint32> activePids;
    for (quint32 pid : tCache)     if (pid) activePids.insert(pid);
    for (quint32 pid : uCache)     if (pid) activePids.insert(pid);
    for (quint32 pid : tListenCache) if (pid) activePids.insert(pid);
    for (quint32 pid : uAnyCache)  if (pid) activePids.insert(pid);

    QHash<quint32, ApplicationIdentity> idCache;
    QHash<quint32, quint32> failureCache;
    {
        QMutexLocker lk(&m_cacheMutex);
        for (auto it = m_identityCache.constBegin(); it != m_identityCache.constEnd(); ++it)
            if (activePids.contains(it.key())) idCache.insert(it.key(), it.value());
        for (auto it = m_identityFailurePids.constBegin(); it != m_identityFailurePids.constEnd(); ++it)
            if (activePids.contains(it.key())) failureCache.insert(it.key(), it.value());
    }

    int resolvedThisRefresh = 0;
    for (quint32 pid : activePids) {
        if (idCache.contains(pid) || failureCache.contains(pid)) continue;
        if (resolvedThisRefresh >= 64) break;
        ++resolvedThisRefresh;

        const Oasis::IdentityResolution resolution = m_identityResolver.resolvePid(pid);
        if (resolution.ok()) {
            idCache.insert(pid, resolution.identity);
            continue;
        }

        failureCache.insert(pid, static_cast<quint32>(resolution.status));
        // Exiting processes are expected; only report failures that hide an
        // executable we can still attribute.
        if (resolution.status != Oasis::IdentityResolutionStatus::ProcessNotFound)
            emit identityResolutionFailed(pid,
                Oasis::identityResolutionStatusName(resolution.status),
                resolution.message);
    }

    // ── 3c. Publish the service mapping for PIDs that own traffic ──
    // Only changed snapshots are sent, so a state poll does not repaint the
    // tree; the GUI keeps per-service rows for shared hosts.
    Oasis::ServicePidMap servicesForActive;
    for (quint32 pid : activePids) {
        const auto hosted = servicesByPid.constFind(pid);
        if (hosted != servicesByPid.constEnd() && !hosted->isEmpty())
            servicesForActive.insert(pid, hosted.value());
    }
    bool servicesChanged = false;
    {
        QMutexLocker lk(&m_cacheMutex);
        servicesChanged = (servicesForActive != m_serviceCache);
    }
    if (servicesChanged)
        emit serviceSnapshotReady(servicesForActive);

    // ── 3d. Publish lineage for PIDs that own traffic ──
    // Records are copied under the cache lock in step 4 below; the packet loop
    // only reads this snapshot.
    QHash<quint32, Oasis::ProcessLineageRecord> lineageForActive;
    for (quint32 pid : activePids) {
        const Oasis::ProcessLineageRecord record = m_lineage.record(pid);
        if (record.isValid()) lineageForActive.insert(pid, record);
    }

    // ── 3e. Group the PIDs that own traffic (NG-014) ──
    // Each observation carries the identity, publisher, service, and lineage
    // evidence gathered above, so one pass decides the membership of every
    // active process and records why. Groups are rebuilt each refresh; only
    // user edits are persisted.
    QList<Oasis::GroupEvidence> groupEvidence;
    groupEvidence.reserve(activePids.size());
    for (quint32 pid : activePids) {
        const Oasis::ProcessLineageRecord record = m_lineage.record(pid);
        if (!record.isValid() || record.executablePath.isEmpty()) continue;

        Oasis::GroupEvidence evidence;
        evidence.pid            = pid;
        evidence.parentPid      = record.parentPid;
        evidence.generation     = record.generation;
        evidence.executablePath = record.executablePath;
        evidence.processName    = record.processName;
        evidence.displayName    = record.processName;

        const auto identity = idCache.constFind(pid);
        if (identity != idCache.constEnd()) {
            evidence.identityId        = identity->id;
            evidence.productName       = identity->productName;
            evidence.companyName       = identity->companyName;
            evidence.publisher         = identity->publisher;
            evidence.packageFamilyName = identity->packageFamilyName;
            evidence.signerStatus      = identity->signerStatus;
            if (!identity->displayName.isEmpty()) evidence.displayName = identity->displayName;
        }

        const auto hosted = servicesByPid.constFind(pid);
        if (hosted != servicesByPid.constEnd()) {
            for (const Oasis::ServiceEntry &service : hosted.value()) {
                evidence.serviceNames.append(service.serviceName);
                evidence.serviceDisplayNames.append(service.displayName);
            }
        }

        groupEvidence.append(evidence);
    }
    QHash<quint32, Oasis::GroupBinding> groupBindings;
    {
        // Serialized with GUI edits (rename, add/remove member).
        QMutexLocker lk(&m_groupMutex);
        groupBindings = m_groupManager.assign(groupEvidence);
    }
    syncGroupSnapshot();

    // ── 3f. Sample the foreground application (NG-041) ──
    // The sample is validated against the lineage just refreshed above, so a
    // recycled PID is discarded and the live helper processes that carry a
    // browser's traffic are included. The result is advisory and stamped with
    // the sample time; nothing here changes a policy.
    Oasis::ForegroundSnapshot foreground =
        Oasis::ForegroundSampler::sample(m_lineage, nowMs);
    if (foreground.isValid()) {
        const auto group = groupBindings.constFind(foreground.foregroundPid);
        if (group != groupBindings.constEnd() && group->isValid()) {
            foreground.groupId = group->groupId;
            foreground.groupName = group->groupName;
        }
    }

    const bool foregroundChanged =
        m_lastForeground.hasForegroundWindow != foreground.hasForegroundWindow
        || m_lastForeground.staleObservation != foreground.staleObservation
        || m_lastForeground.foregroundPid != foreground.foregroundPid
        || m_lastForeground.sessionId != foreground.sessionId
        || m_lastForeground.associatedPids != foreground.associatedPids
        || m_lastForeground.processName != foreground.processName
        || m_lastForeground.groupId != foreground.groupId;
    if (foregroundChanged) {
        m_lastForeground = foreground;
        emit foregroundSnapshotReady(foreground);
    }

    // ── 4. Detect stale mappings: a connection key changed owner ──
    // Rate-limited to once per 5 seconds so a churning table cannot flood
    // the diagnostics model.
    if (nowMs - m_lastStaleReportMs >= 5000) {
        QList<QPair<quint32, quint32>> changes; // old pid -> new pid
        {
            QMutexLocker lk(&m_cacheMutex);
            const auto scan = [&changes](const QHash<QString, quint32> &oldMap,
                                         const QHash<QString, quint32> &newMap) {
                for (auto it = newMap.constBegin(); it != newMap.constEnd() && changes.size() < 3; ++it) {
                    const quint32 oldPid = oldMap.value(it.key(), 0);
                    if (oldPid != 0 && it.value() != 0 && oldPid != it.value())
                        changes.append(qMakePair(oldPid, it.value()));
                }
            };
            scan(m_tcpCache, tCache);
            if (changes.size() < 3)
                scan(m_udpCache, uCache);
        }
        if (!changes.isEmpty()) {
            m_lastStaleReportMs = nowMs;
            for (const auto &change : changes)
                emit staleMappingDetected(change.first,
                                          QStringLiteral("PID %1").arg(change.first),
                                          QStringLiteral("PID %1").arg(change.second));
        }
    }

    QMutexLocker lk(&m_cacheMutex);
    m_tcpCache = tCache;
    m_udpCache = uCache;
    m_tcpListenCache = tListenCache;
    m_udpAnyCache = uAnyCache;
    m_procCache = pCache;
    m_identityCache = idCache;
    m_identityFailurePids = failureCache;
    m_serviceCache = servicesForActive;
    m_lineageCache = lineageForActive;
    m_groupCache = groupBindings;
    m_foregroundCache = foreground;
}
