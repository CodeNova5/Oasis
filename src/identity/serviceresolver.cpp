/**
 * @file    serviceresolver.cpp
 * @brief   SCM enumeration and PID -> service mapping (NG-012).
 * @author  Ali Sakkaf
 */
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif

#include "serviceresolver.h"

#include <QDateTime>

#include <algorithm>

#include <windows.h>
#include <winsvc.h>

namespace NetGuard {

namespace {

ServiceState toServiceState(DWORD state)
{
    switch (state) {
    case SERVICE_RUNNING:          return ServiceState::Running;
    case SERVICE_STOPPED:          return ServiceState::Stopped;
    case SERVICE_START_PENDING:    return ServiceState::StartPending;
    case SERVICE_STOP_PENDING:     return ServiceState::StopPending;
    case SERVICE_PAUSED:           return ServiceState::Paused;
    case SERVICE_PAUSE_PENDING:    return ServiceState::PausePending;
    case SERVICE_CONTINUE_PENDING: return ServiceState::ContinuePending;
    default:                       return ServiceState::Unknown;
    }
}

// QueryServiceConfig reports the SCM image path, which may contain arguments
// (svchost services look like "C:\Windows\system32\svchost.exe -k netsvcs -p").
QString queryImagePath(SC_HANDLE scm, const QString &serviceName, int *failureCount)
{
    SC_HANDLE svc = OpenServiceW(scm, reinterpret_cast<LPCWSTR>(serviceName.utf16()),
                                 SERVICE_QUERY_CONFIG);
    if (!svc) {
        if (failureCount) ++*failureCount;
        return QString();
    }

    DWORD needed = 0;
    QueryServiceConfigW(svc, nullptr, 0, &needed);
    QString path;
    if (needed > 0) {
        QByteArray buffer(static_cast<int>(needed), 0);
        auto *config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
        if (QueryServiceConfigW(svc, config, needed, &needed) && config->lpBinaryPathName)
            path = QString::fromWCharArray(config->lpBinaryPathName);
        else if (failureCount)
            ++*failureCount;
    } else if (failureCount) {
        ++*failureCount;
    }

    CloseServiceHandle(svc);
    return path;
}

} // namespace

QString serviceStateName(ServiceState state)
{
    switch (state) {
    case ServiceState::Running:         return QStringLiteral("Running");
    case ServiceState::Stopped:         return QStringLiteral("Stopped");
    case ServiceState::StartPending:    return QStringLiteral("Starting");
    case ServiceState::StopPending:     return QStringLiteral("Stopping");
    case ServiceState::Paused:          return QStringLiteral("Paused");
    case ServiceState::PausePending:    return QStringLiteral("Pausing");
    case ServiceState::ContinuePending: return QStringLiteral("Resuming");
    case ServiceState::Unknown:         break;
    }
    return QStringLiteral("Unknown");
}

bool ServiceResolver::refresh(int refreshIntervalMs)
{
    if (m_haveSnapshot) {
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (now - m_lastRefreshMs < refreshIntervalMs)
            return true;
    }
    return refreshNow();
}

bool ServiceResolver::refreshNow()
{
    m_lastRefreshMs = QDateTime::currentMSecsSinceEpoch();

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,
                                   SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        const DWORD err = GetLastError();
        m_lastError = QStringLiteral("Could not open the service manager (Win32 error %1). "
                                     "Service names need administrator rights.")
                          .arg(err);
        // Keep whatever we already had: a transient failure must not erase the
        // mapping the process tree is currently showing.
        return m_haveSnapshot;
    }

    QHash<quint32, QVector<ServiceEntry>> byPid;
    int serviceCount = 0;
    int pathFailures = 0;
    bool enumerated = false;

    // EnumServicesStatusEx reports ERROR_MORE_DATA when the buffer filled up;
    // the entries in the buffer are still valid and the resume handle continues
    // the walk, so loop until a call succeeds.
    QByteArray buffer(128 * 1024, 0);
    DWORD resumeHandle = 0;
    for (;;) {
        DWORD needed = 0, returned = 0;
        const BOOL ok = EnumServicesStatusExW(
            scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            reinterpret_cast<LPBYTE>(buffer.data()), static_cast<DWORD>(buffer.size()),
            &needed, &returned, &resumeHandle, nullptr);

        const DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && err != ERROR_MORE_DATA) {
            m_lastError = QStringLiteral("Service enumeration failed (Win32 error %1).").arg(err);
            break;
        }

        auto *services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
        for (DWORD i = 0; i < returned; ++i) {
            ServiceEntry entry;
            entry.serviceName = QString::fromWCharArray(services[i].lpServiceName);
            entry.displayName = QString::fromWCharArray(services[i].lpDisplayName);
            entry.processId   = static_cast<quint32>(services[i].ServiceStatusProcess.dwProcessId);
            entry.state       = toServiceState(services[i].ServiceStatusProcess.dwCurrentState);
            entry.acceptsStop =
                (services[i].ServiceStatusProcess.dwControlsAccepted & SERVICE_ACCEPT_STOP) != 0;

            const auto cachedPath = m_pathCache.constFind(entry.serviceName);
            if (cachedPath != m_pathCache.constEnd()) {
                entry.executablePath = cachedPath.value();
            } else {
                const int before = pathFailures;
                entry.executablePath = queryImagePath(scm, entry.serviceName, &pathFailures);
                if (pathFailures == before && !entry.executablePath.isEmpty())
                    m_pathCache.insert(entry.serviceName, entry.executablePath);
            }

            ++serviceCount;
            if (entry.processId != 0)
                byPid[entry.processId].append(entry);
        }

        enumerated = true;
        if (ok || returned == 0)
            break;
    }

    CloseServiceHandle(scm);

    if (!enumerated) {
        // Enumeration failed before producing anything usable.
        if (m_lastError.isEmpty())
            m_lastError = QStringLiteral("Service enumeration returned no data.");
        return m_haveSnapshot;
    }

    // A stable order keeps the tree from reshuffling every refresh.
    for (auto it = byPid.begin(); it != byPid.end(); ++it) {
        std::sort(it.value().begin(), it.value().end(),
                  [](const ServiceEntry &a, const ServiceEntry &b) {
                      return a.displayName.compare(b.displayName, Qt::CaseInsensitive) < 0;
                  });
    }

    m_byPid         = byPid;
    m_serviceCount  = serviceCount;
    m_failedPathLookups = pathFailures;
    m_haveSnapshot  = true;
    m_lastError.clear();
    ++m_revision;
    return true;
}

QVector<ServiceEntry> ServiceResolver::servicesForPid(quint32 pid) const
{
    return m_byPid.value(pid);
}

void ServiceResolver::clear()
{
    m_byPid.clear();
    m_haveSnapshot = false;
    m_lastRefreshMs = 0;
    m_serviceCount = 0;
    m_failedPathLookups = 0;
    m_lastError.clear();
}

} // namespace NetGuard
