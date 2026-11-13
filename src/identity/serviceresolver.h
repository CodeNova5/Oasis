/**
 * @file    serviceresolver.h
 * @brief   Windows service identity resolution for service-hosted traffic (NG-012).
 * @author  Oasis
 */
#pragma once

#include <QHash>
#include <QMetaType>
#include <QString>
#include <QVector>

namespace Oasis {

// ─── Service runtime state ──────────────────────────────────────────────────
// Mirrors SERVICE_STATUS_PROCESS::dwCurrentState with a neutral Unknown value
// for services the SCM could not describe.
enum class ServiceState : int {
    Running = 0,
    Stopped,
    StartPending,
    StopPending,
    Paused,
    PausePending,
    ContinuePending,
    Unknown
};

QString serviceStateName(ServiceState state);

// ─── One service ────────────────────────────────────────────────────────────
struct ServiceEntry
{
    QString      serviceName;    // SCM key, e.g. "wuauserv"
    QString      displayName;    // e.g. "Windows Update"
    QString      executablePath; // lpBinaryPathName, includes arguments when set
    ServiceState state      = ServiceState::Unknown;
    quint32      processId  = 0;
    bool         acceptsStop = false; // SERVICE_ACCEPT_STOP, i.e. user-stoppable
};

inline bool operator==(const ServiceEntry &a, const ServiceEntry &b)
{
    return a.serviceName == b.serviceName
        && a.displayName == b.displayName
        && a.executablePath == b.executablePath
        && a.state == b.state
        && a.processId == b.processId
        && a.acceptsStop == b.acceptsStop;
}
inline bool operator!=(const ServiceEntry &a, const ServiceEntry &b) { return !(a == b); }

// ─── Resolver ───────────────────────────────────────────────────────────────
// Enumerates Win32 services once per refresh window (never per PID) and maps
// hosting PIDs to the services they run, so several services sharing one
// svchost.exe stay individually addressable. Image paths are queried once per
// service name and cached for the session because they only change on install.
class ServiceResolver
{
public:
    // Refresh when the cached snapshot is older than refreshIntervalMs.
    // Returns true when a fresh snapshot is available (even if not re-queried).
    bool refresh(int refreshIntervalMs = 2000);
    // Force a new SCM enumeration; used on start and by tests.
    bool refreshNow();

    QVector<ServiceEntry> servicesForPid(quint32 pid) const;
    // Every service hosted by a live PID, keyed by PID.
    QHash<quint32, QVector<ServiceEntry>> servicesByPid() const { return m_byPid; }

    int     serviceCount()     const { return m_serviceCount; }
    quint64 revision()         const { return m_revision; }
    QString lastError()        const { return m_lastError; }
    int     failedPathLookups() const { return m_failedPathLookups; }
    bool    hasSnapshot()      const { return m_haveSnapshot; }

    void clear();

private:
    QHash<quint32, QVector<ServiceEntry>> m_byPid;
    QHash<QString, QString> m_pathCache; // service name -> image path
    qint64  m_lastRefreshMs = 0;
    bool    m_haveSnapshot  = false;
    quint64 m_revision      = 0;
    int     m_serviceCount  = 0;
    int     m_failedPathLookups = 0;
    QString m_lastError;
};

// Alias exists so the map can be declared as a Qt metatype; the comma inside
// QHash<quint32, QVector<...>> would otherwise split the macro arguments.
using ServicePidMap = QHash<quint32, QVector<ServiceEntry>>;

} // namespace Oasis

Q_DECLARE_METATYPE(Oasis::ServiceEntry)
Q_DECLARE_METATYPE(Oasis::ServicePidMap)
