/**
 * @file    downloadthrottle.cpp
 * @author  Ali Sakkaf
 */
#include "downloadthrottle.h"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "windivertapi.h"

#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QPair>
#include <QQueue>

namespace {

// Every inbound TCP/UDP packet except loopback is diverted while at least one
// limit is active. Matching on a stable filter instead of on the throttled
// ports keeps the handle open across connection churn: reopening it would drop
// whatever the driver still has queued and stall those connections.
constexpr const char *FilterExpression = "inbound and (tcp or udp) and not loopback";

constexpr int PortRefreshIntervalMs = 1000;
constexpr int RetryAfterErrorMs = 5000;
constexpr int PathCacheTtlMs = 10000;
// Stop receiving diverted packets while a flow is this far ahead. This lets
// WinDivert's queue and TCP flow control apply backpressure instead of flushing
// a burst that bypasses the configured rate.
constexpr qint64 MaxQueuedBytesPerFlow = 256 * 1024;

struct QueuedPacket
{
    QByteArray data;
    windivert::Address address{};
    qint64 dueMs = 0;
    QString key;
    qint64 bytes = 0;
};

struct PacketShape
{
    quint8 protocol = 0;
    quint16 localPort = 0;
    qint64 wireBytes = 0;
    qint64 payloadBytes = 0;
};

QString endpointKey(quint8 protocol, quint16 localPort)
{
    return QStringLiteral("%1:%2").arg(protocol).arg(localPort);
}

QString normalizePath(const QString &path)
{
    return QDir::cleanPath(QDir::toNativeSeparators(path.trimmed())).toLower();
}

// Reads the inbound direction only: the local port of a download is the
// destination port, because WinDivert delivers the packet before the stack
// touches it.
bool describeInboundPacket(const char *data, UINT length, PacketShape *shape)
{
    const auto *bytes = reinterpret_cast<const unsigned char *>(data);
    if (length < 20)
        return false;

    qint64 ipHeader = 0;
    qint64 totalLength = 0;
    int protocol = 0;

    const int version = bytes[0] >> 4;
    if (version == 4) {
        ipHeader = (bytes[0] & 0x0f) * 4;
        totalLength = (qint64(bytes[2]) << 8) | bytes[3];
        protocol = bytes[9];
    } else if (version == 6) {
        ipHeader = 40;
        totalLength = ipHeader + ((qint64(bytes[4]) << 8) | bytes[5]);
        protocol = bytes[6];
    } else {
        return false;
    }

    shape->protocol = static_cast<quint8>(protocol);

    if (ipHeader < 20 || totalLength > qint64(length) || qint64(length) < ipHeader + 4)
        return false;

    qint64 transportHeader = 0;
    if (protocol == 6) {
        if (qint64(length) < ipHeader + 20)
            return false;
        transportHeader = (bytes[ipHeader + 12] >> 4) * 4;
        if (transportHeader < 20)
            return false;
    } else if (protocol == 17) {
        if (qint64(length) < ipHeader + 8)
            return false;
        transportHeader = 8;
    } else {
        return false;
    }

    shape->localPort = quint16((bytes[ipHeader + 2] << 8) | bytes[ipHeader + 3]);
    shape->wireBytes = totalLength;
    shape->payloadBytes = totalLength - ipHeader - transportHeader;
    return true;
}

QString resolveExecutablePath(quint32 pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return QString();

    wchar_t buffer[32768] = {};
    DWORD length = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    const BOOL resolved = QueryFullProcessImageNameW(process, 0, buffer, &length);
    CloseHandle(process);
    return resolved ? QString::fromWCharArray(buffer, static_cast<int>(length)) : QString();
}

// Protocol/port -> owning PID for both TCP and UDP, IPv4 and IPv6.
QHash<QString, quint32> localPortOwners()
{
    QHash<QString, quint32> owners;

    for (const ULONG family : {ULONG(AF_INET), ULONG(AF_INET6)}) {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size > 0) {
            QByteArray buffer(static_cast<int>(size), '\0');
            if (GetExtendedTcpTable(buffer.data(), &size, FALSE, family,
                                    TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                if (family == AF_INET) {
                    const auto *table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(buffer.constData());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const quint16 port = ntohs(static_cast<quint16>(table->table[i].dwLocalPort));
                        const quint32 pid = static_cast<quint32>(table->table[i].dwOwningPid);
                        if (pid > 4)
                            owners.insert(endpointKey(IPPROTO_TCP, port), pid);
                    }
                } else {
                    const auto *table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID *>(buffer.constData());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const quint16 port = ntohs(static_cast<quint16>(table->table[i].dwLocalPort));
                        const quint32 pid = static_cast<quint32>(table->table[i].dwOwningPid);
                        if (pid > 4)
                            owners.insert(endpointKey(IPPROTO_TCP, port), pid);
                    }
                }
            }
        }

        size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
        if (size > 0) {
            QByteArray buffer(static_cast<int>(size), '\0');
            if (GetExtendedUdpTable(buffer.data(), &size, FALSE, family,
                                    UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                if (family == AF_INET) {
                    const auto *table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID *>(buffer.constData());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const quint16 port = ntohs(static_cast<quint16>(table->table[i].dwLocalPort));
                        const quint32 pid = static_cast<quint32>(table->table[i].dwOwningPid);
                        if (pid > 4)
                            owners.insert(endpointKey(IPPROTO_UDP, port), pid);
                    }
                } else {
                    const auto *table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID *>(buffer.constData());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const quint16 port = ntohs(static_cast<quint16>(table->table[i].dwLocalPort));
                        const quint32 pid = static_cast<quint32>(table->table[i].dwOwningPid);
                        if (pid > 4)
                            owners.insert(endpointKey(IPPROTO_UDP, port), pid);
                    }
                }
            }
        }
    }

    return owners;
}

// Ports that belong to an executable with an active limit. Only those packets
// are paced; everything else is re-injected immediately.
QHash<QString, QString> buildPortKeyMap(const QHash<QString, quint64> &policies,
                                         QHash<quint32, QPair<QString, qint64>> &pathCache)
{
    QHash<QString, QString> portKeys;
    const QHash<QString, quint32> owners = localPortOwners();
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();

    for (auto it = owners.constBegin(); it != owners.constEnd(); ++it) {
        const quint32 pid = it.value();
        auto cached = pathCache.find(pid);
        if (cached == pathCache.end() || nowMs - cached.value().second > PathCacheTtlMs) {
            pathCache.insert(pid, qMakePair(normalizePath(resolveExecutablePath(pid)), nowMs));
            cached = pathCache.find(pid);
        }

        const QString path = cached.value().first;
        if (path.isEmpty() || !policies.contains(path))
            continue;
        portKeys.insert(it.key(), path);
    }

    return portKeys;
}

} // namespace

DownloadShaper::DownloadShaper(QObject *parent)
    : QThread(parent)
{
    m_wakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

DownloadShaper::~DownloadShaper()
{
    stop();
    if (wait(3000)) {
        if (m_wakeEvent) {
            CloseHandle(static_cast<HANDLE>(m_wakeEvent));
            m_wakeEvent = nullptr;
        }
    }
    // A thread still parked inside a WinDivert call keeps its event; the OS
    // reclaims both when the process exits.
}

QString DownloadShaper::unavailableReason()
{
    windivert::Api &api = windivert::Api::instance();
    return api.loaded() ? QString() : api.unavailableReason();
}

void DownloadShaper::setPolicies(const QHash<QString, quint64> &policies)
{
    {
        QMutexLocker lock(&m_mutex);
        m_policies = policies;
    }
    if (m_wakeEvent)
        SetEvent(static_cast<HANDLE>(m_wakeEvent));
}

void DownloadShaper::stop()
{
    {
        QMutexLocker lock(&m_mutex);
        m_stopRequested = true;
    }
    if (m_wakeEvent)
        SetEvent(static_cast<HANDLE>(m_wakeEvent));
}

bool DownloadShaper::stopRequested() const
{
    QMutexLocker lock(&m_mutex);
    return m_stopRequested;
}

void DownloadShaper::run()
{
    windivert::Api &api = windivert::Api::instance();
    if (!api.loaded()) {
        emit availabilityChecked(false, api.unavailableReason());
        while (!stopRequested())
            WaitForSingleObject(static_cast<HANDLE>(m_wakeEvent), 500);
        return;
    }

    // Startup capability check. Opening a handle proves the driver is installed
    // and that this process is elevated; the filter cannot match a packet, so
    // the probe diverts no traffic. Failures are still reported per policy.
    {
        HANDLE probe = api.open("inbound and tcp.DstPort == 0 and tcp.DstPort == 1",
                                windivert::LayerNetwork, 0, 0);
        if (probe == INVALID_HANDLE_VALUE) {
            emit availabilityChecked(false,
                QStringLiteral("WinDivert could not start (error %1). WinDivert.dll and "
                               "WinDivert64.sys must sit next to the application, and "
                               "NetGuard must run as administrator.").arg(GetLastError()));
        } else {
            api.close(probe);
            emit availabilityChecked(true, QString());
        }
    }

    QElapsedTimer clock;
    clock.start();
    auto elapsed = [&clock]() { return static_cast<qint64>(clock.elapsed()); };

    HANDLE handle = INVALID_HANDLE_VALUE;
    HANDLE recvEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    QByteArray buffer(windivert::MtuMax, '\0');
    windivert::Address address{};
    UINT addressLength = sizeof(address);
    UINT received = 0;
    OVERLAPPED overlapped{};
    overlapped.hEvent = recvEvent;
    bool pendingReceive = false;

    QQueue<QueuedPacket> queue;
    QHash<QString, qint64> nextDeparture;
    QHash<QString, qint64> queuedBytes;
    QHash<QString, QString> portKeys;
    QHash<quint32, QPair<QString, qint64>> pathCache;
    bool receivePaused = false;
    qint64 nextPortRefresh = 0;
    qint64 retryAt = 0;
    QString lastError;

    auto reportError = [this, &lastError](const QString &message) {
        if (message.isEmpty()) {
            lastError.clear();
            return;
        }
        if (message == lastError)
            return;
        lastError = message;
        emit shaperError(message);
    };

    auto sendPacket = [&api, &handle](const char *data, UINT length,
                                      const windivert::Address &packetAddress) {
        if (handle == INVALID_HANDLE_VALUE || length == 0)
            return;
        UINT sent = 0;
        api.send(handle, data, length, &sent, &packetAddress);
    };

    auto closeHandle = [&]() {
        if (handle == INVALID_HANDLE_VALUE)
            return;

        // A closed handle can no longer inject, so whatever is still held back
        // goes out first rather than being dropped.
        while (!queue.isEmpty()) {
            const QueuedPacket packet = queue.dequeue();
            sendPacket(packet.data.constData(), UINT(packet.data.size()), packet.address);
        }
        queuedBytes.clear();
        nextDeparture.clear();

        if (pendingReceive) {
            api.shutdown(handle, windivert::ShutdownRecv);
            DWORD done = 0;
            GetOverlappedResult(handle, &overlapped, &done, TRUE);
            pendingReceive = false;
        }
        api.close(handle);
        handle = INVALID_HANDLE_VALUE;
        ResetEvent(recvEvent);
    };

    for (;;) {
        if (stopRequested())
            break;

        QHash<QString, quint64> policies;
        {
            QMutexLocker lock(&m_mutex);
            policies = m_policies;
        }

        if (policies.isEmpty()) {
            if (handle != INVALID_HANDLE_VALUE) {
                closeHandle();
                emit limitingActiveChanged(false);
            }
            WaitForSingleObject(static_cast<HANDLE>(m_wakeEvent), 250);
            continue;
        }

        // Release everything whose slot has arrived.
        {
            const qint64 nowMs = elapsed();
            QQueue<QueuedPacket> remaining;
            while (!queue.isEmpty()) {
                QueuedPacket packet = queue.dequeue();
                if (packet.dueMs <= nowMs) {
                    sendPacket(packet.data.constData(), UINT(packet.data.size()), packet.address);
                    queuedBytes[packet.key] = qMax<qint64>(0, queuedBytes.value(packet.key) - packet.bytes);
                } else {
                    remaining.enqueue(packet);
                }
            }
            queue = remaining;

            if (receivePaused) {
                receivePaused = false;
                for (auto it = queuedBytes.constBegin(); it != queuedBytes.constEnd(); ++it) {
                    if (it.value() > MaxQueuedBytesPerFlow / 2) {
                        receivePaused = true;
                        break;
                    }
                }
            }
        }

        const qint64 nowMs = elapsed();
        if (nowMs >= nextPortRefresh) {
            portKeys = buildPortKeyMap(policies, pathCache);
            nextPortRefresh = nowMs + PortRefreshIntervalMs;
        }

        if (handle == INVALID_HANDLE_VALUE) {
            if (nowMs < retryAt) {
                WaitForSingleObject(static_cast<HANDLE>(m_wakeEvent), 200);
                continue;
            }

            handle = api.open(FilterExpression, windivert::LayerNetwork, 0, 0);
            if (handle == INVALID_HANDLE_VALUE) {
                const DWORD error = GetLastError();
                reportError(QStringLiteral("WinDivert could not start the download shaper "
                                           "(error %1). WinDivert.dll and WinDivert64.sys must "
                                           "sit next to the application, and NetGuard must run "
                                           "as administrator.").arg(error));
                retryAt = elapsed() + RetryAfterErrorMs;
                WaitForSingleObject(static_cast<HANDLE>(m_wakeEvent), 200);
                continue;
            }

            api.setParam(handle, windivert::ParamQueueLength, 8192);
            api.setParam(handle, windivert::ParamQueueTime, 2000);
            reportError(QString());
            emit limitingActiveChanged(true);
        }

        auto acceptPacket = [&](const QByteArray &data, UINT length,
                                const windivert::Address &packetAddress) {
            PacketShape shape;
            if (!describeInboundPacket(data.constData(), length, &shape) ||
                shape.payloadBytes <= 0) {
                // Handshakes, ACKs and anything unparsable are never delayed.
                sendPacket(data.constData(), length, packetAddress);
                return;
            }

            const QString key = portKeys.value(endpointKey(shape.protocol, shape.localPort));
            const quint64 bits = key.isEmpty() ? 0 : policies.value(key, 0);
            if (bits == 0) {
                sendPacket(data.constData(), length, packetAddress);
                return;
            }

            const qint64 at = elapsed();
            qint64 &next = nextDeparture[key];
            const qint64 due = qMax(at, next);
            // Time this packet needs on the wire at the configured rate.
            next = due + qMax<qint64>(1, shape.wireBytes * 8000 / qint64(bits));
            if (due <= at) {
                sendPacket(data.constData(), length, packetAddress);
                return;
            }

            QueuedPacket packet;
            packet.data = QByteArray(data.constData(), int(length));
            packet.address = packetAddress;
            packet.dueMs = due;
            packet.key = key;
            packet.bytes = shape.wireBytes;
            queue.enqueue(packet);
            queuedBytes[key] = queuedBytes.value(key) + shape.wireBytes;
            if (queuedBytes.value(key) >= MaxQueuedBytesPerFlow)
                receivePaused = true;
        };

        if (!pendingReceive && !receivePaused) {
            ZeroMemory(&overlapped, sizeof(overlapped));
            overlapped.hEvent = recvEvent;
            ResetEvent(recvEvent);
            addressLength = sizeof(address);
            received = 0;

            if (api.recvEx(handle, buffer.data(), UINT(buffer.size()), &received, 0,
                           &address, &addressLength, &overlapped)) {
                acceptPacket(buffer, received, address);
            } else if (GetLastError() == ERROR_IO_PENDING) {
                pendingReceive = true;
            } else {
                reportError(QStringLiteral("WinDivert receive failed (error %1).")
                                .arg(GetLastError()));
                closeHandle();
                retryAt = elapsed() + RetryAfterErrorMs;
                continue;
            }
        }

        qint64 earliestDue = -1;
        for (const QueuedPacket &packet : queue) {
            if (earliestDue < 0 || packet.dueMs < earliestDue)
                earliestDue = packet.dueMs;
        }
        const qint64 timeout = earliestDue < 0
            ? qint64(200)
            : qBound<qint64>(qint64(0), earliestDue - elapsed(), qint64(200));

        HANDLE events[2] = {recvEvent, static_cast<HANDLE>(m_wakeEvent)};
        const DWORD signalled = WaitForMultipleObjects(2, events, FALSE, DWORD(timeout));

        if (signalled == WAIT_OBJECT_0 && pendingReceive) {
            DWORD done = 0;
            if (GetOverlappedResult(handle, &overlapped, &done, FALSE) && done > 0) {
                pendingReceive = false;
                acceptPacket(buffer, done, address);
            } else {
                pendingReceive = false;
                const DWORD error = GetLastError();
                if (handle != INVALID_HANDLE_VALUE) {
                    reportError(QStringLiteral("WinDivert stopped delivering packets "
                                               "(error %1).").arg(error));
                    closeHandle();
                    retryAt = elapsed() + RetryAfterErrorMs;
                }
            }
        }
    }

    closeHandle();
    if (recvEvent)
        CloseHandle(recvEvent);
}
