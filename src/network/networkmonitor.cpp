/**
 * @file    networkmonitor.cpp
 * @brief   Thread-safe capture with dedicated caching thread and exact process/service mapping.
 * Includes Smart Auto-Detect & Dual-Socket IPv4/IPv6 Capture Engine!
 * @author  Ali Sakkaf
 */
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif

#include "networkmonitor.h"
#include <QMutexLocker>
#include <QDateTime>
#include <QSet>
#include <thread>

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

QList<AdapterInfo> NetworkMonitor::enumerateAdapters()
{
    QList<AdapterInfo> result;
    ULONG sz = 20000;
    QByteArray buf(static_cast<int>(sz), '\0');
    auto *addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &sz) != NO_ERROR)
        return result;

    for (auto *a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        bool gw = (a->FirstGatewayAddress != nullptr);

        QString ipv4, ipv6;
        for (auto *ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            SOCKADDR *sa = ua->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                char ipBuf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(sa)->sin_addr, ipBuf, sizeof(ipBuf));
                ipv4 = QString::fromLatin1(ipBuf);
            } else if (sa->sa_family == AF_INET6) {
                char ipBuf[INET6_ADDRSTRLEN] = {};
                inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr, ipBuf, sizeof(ipBuf));
                ipv6 = QString::fromLatin1(ipBuf);
            }
        }

        if (!ipv4.isEmpty()) {
            AdapterInfo ai;
            ai.ip = ipv4;
            ai.ipv6 = ipv6; // IPv6 address
            ai.hasGateway = gw;
            ai.index = a->IfIndex;
            QString fn = a->FriendlyName ? QString::fromWCharArray(a->FriendlyName) : ai.ip;
            ai.description = fn + "  [" + ai.ip + "]" + (gw ? "  ★" : "");
            result.append(ai);
        }
    }
    return result;
}

// Smart Auto-Detect Adapter Index
int NetworkMonitor::recommendedAdapterIndex(const QList<AdapterInfo> &list)
{
    if (list.isEmpty()) return 0;

    auto isVirtual = [](const QString &description) {
        QString desc = description.toLower();
        return desc.contains("vmware") || desc.contains("virtual") || desc.contains("vbox") ||
               desc.contains("radmin") || desc.contains("pseudo") || desc.contains("zerotier") ||
               desc.contains("hamachi") || desc.contains("tap-") || desc.contains("tun-") ||
               desc.contains("wsl") || desc.contains("vethernet");
    };

    // 1. Check active IPv4 interface
    DWORD bestIfIndex = 0;
    if (GetBestInterface(inet_addr("8.8.8.8"), &bestIfIndex) == NO_ERROR) {
        for (int i = 0; i < list.size(); ++i) {
            if (list[i].index == bestIfIndex && !isVirtual(list[i].description)) {
                return i;
            }
        }
    }

    // 2. Check active IPv6 interface
    SOCKADDR_IN6 sa6 = {};
    sa6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:4860:4860::8888", &sa6.sin6_addr);
    MIB_IPFORWARD_ROW2 routeRow = {};
    SOCKADDR_INET bestDest = {};
    bestDest.Ipv6 = sa6;
    if (GetBestRoute2(nullptr, 0, nullptr, &bestDest, 0, &routeRow, nullptr) == NO_ERROR) {
        for (int i = 0; i < list.size(); ++i) {
            if (list[i].index == routeRow.InterfaceIndex && !isVirtual(list[i].description)) {
                return i;
            }
        }
    }

    // 3. Find physical adapter with highest active traffic (InOctets + OutOctets)
    int bestTrafficIdx = -1;
    quint64 maxBytes = 0;

    for (int i = 0; i < list.size(); ++i) {
        if (!isVirtual(list[i].description) && list[i].hasGateway) {
            MIB_IF_ROW2 row;
            ZeroMemory(&row, sizeof(row));
            row.InterfaceIndex = list[i].index;
            if (GetIfEntry2(&row) == NO_ERROR) {
                quint64 totalBytes = row.InOctets + row.OutOctets;
                if (totalBytes > maxBytes) {
                    maxBytes = totalBytes;
                    bestTrafficIdx = i;
                }
            }
        }
    }

    if (bestTrafficIdx != -1) return bestTrafficIdx;

    // 4. Fallback: First physical adapter with a Gateway
    for (int i = 0; i < list.size(); ++i) {
        if (list[i].hasGateway && !isVirtual(list[i].description)) {
            return i;
        }
    }

    // 5. Ultimate Fallback
    for (int i = 0; i < list.size(); ++i) {
        if (list[i].hasGateway) return i;
    }

    return 0;
}

NetworkMonitor::NetworkMonitor(QObject *parent) : QThread(parent)
{
    qRegisterMetaType<DnsEvent>("DnsEvent");
    qRegisterMetaType<TlsObservation>("TlsObservation");
    qRegisterMetaType<QuicObservation>("QuicObservation");

    // NG-036: honour the persisted attribution privacy choices before the first
    // packet is parsed, so a user who turned collection off never gets a brief
    // enabled window at startup.
    const AttributionPrivacy::Store privacyStore;
    setAttributionPrivacy(privacyStore.load());

    m_speedTimer = new QTimer(this);
    m_speedTimer->setInterval(1000);
    connect(m_speedTimer, &QTimer::timeout, this, [this]() {
        quint64 sysRx = 0, sysTx = 0;

        if (m_adapterIndex != 0) {
            MIB_IF_ROW2 row;
            ZeroMemory(&row, sizeof(row));
            row.InterfaceIndex = m_adapterIndex;
            if (GetIfEntry2(&row) == NO_ERROR) {
                sysRx = row.InOctets;
                sysTx = row.OutOctets;
            }
        }

        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - m_lastTick).count();
        if (dt < 0.001) dt = 1.0;
        m_lastTick = now;

        quint64 rxD = (sysRx >= m_sysRxLast) ? (sysRx - m_sysRxLast) : 0;
        quint64 txD = (sysTx >= m_sysTxLast) ? (sysTx - m_sysTxLast) : 0;

        m_sysRxLast = sysRx;
        m_sysTxLast = sysTx;

        if (m_firstTick) { rxD = 0; txD = 0; m_firstTick = false; }
        emit speedUpdated(static_cast<quint64>(rxD / dt), static_cast<quint64>(txD / dt));
    });
}

NetworkMonitor::~NetworkMonitor()
{
    m_stopFlag.store(true);
    if (!wait(2000)) terminate();
}

QList<DomainAttribution> NetworkMonitor::attributionsForAddress(const QString &address) const
{
    return m_dnsCorrelator.lookup(address);
}

void NetworkMonitor::setAttributionPrivacy(const AttributionPrivacySettings &settings)
{
    m_collectDns.store(settings.collectDns);
    m_collectTlsSni.store(settings.collectTlsSni);
    m_collectQuic.store(settings.collectQuic);
    m_redactDestinationsInExport.store(settings.redactDestinationsInExport);
    m_dnsCorrelator.setRetentionSeconds(
        AttributionPrivacy::clampedRetentionSeconds(settings.retentionSeconds));
}

AttributionPrivacySettings NetworkMonitor::attributionPrivacy() const
{
    AttributionPrivacySettings settings;
    settings.collectDns = m_collectDns.load();
    settings.collectTlsSni = m_collectTlsSni.load();
    settings.collectQuic = m_collectQuic.load();
    settings.retentionSeconds = m_dnsCorrelator.retentionSeconds();
    settings.redactDestinationsInExport = m_redactDestinationsInExport.load();
    return settings;
}

void NetworkMonitor::clearAttributionHistory()
{
    m_dnsCorrelator.clear();
}

int NetworkMonitor::attributionRecordCount() const
{
    return m_dnsCorrelator.recordCount();
}

void NetworkMonitor::setAdapterIP(const QString &ip)
{
    m_adapterIP = ip;
    m_adapterIPv6.clear();
    refreshLocalIPs();
    m_adapterIndex = 0;
    QList<AdapterInfo> adps = enumerateAdapters();
    for (const auto &ai : adps) {
        if (ai.ip == ip) {
            m_adapterIndex = ai.index;
            m_adapterIPv6 = ai.ipv6;
            break;
        }
    }
}

// ─── NG-016 group inspection and editing ───────────────────────────────────
QList<NetGuard::ProcessGroup> NetworkMonitor::processGroups() const
{
    QMutexLocker lk(&m_groupMutex);
    return m_publishedGroups;
}

void NetworkMonitor::syncGroupSnapshot()
{
    QList<NetGuard::ProcessGroup> groups;
    bool changed = false;
    {
        QMutexLocker lk(&m_groupMutex);
        groups = m_groupManager.groups();
        changed = (groups != m_publishedGroups);
        if (changed) m_publishedGroups = groups;
    }
    // Emitted outside the lock: receivers live on the GUI thread.
    if (changed) emit groupSnapshotReady(groups);
}

QString NetworkMonitor::createProcessGroup(const QString &name)
{
    QString id;
    {
        QMutexLocker lk(&m_groupMutex);
        id = m_groupManager.createGroup(name).id;
    }
    if (!id.isEmpty()) syncGroupSnapshot();
    return id;
}

bool NetworkMonitor::renameProcessGroup(const QString &groupId, const QString &name)
{
    bool renamed = false;
    {
        QMutexLocker lk(&m_groupMutex);
        renamed = m_groupManager.renameGroup(groupId, name);
    }
    if (renamed) syncGroupSnapshot();
    return renamed;
}

bool NetworkMonitor::addProcessGroupMember(const QString &groupId,
                                           NetGuard::GroupMemberType type,
                                           const QString &value, QString *error)
{
    bool added = false;
    {
        QMutexLocker lk(&m_groupMutex);
        added = m_groupManager.addMember(groupId, type, value, error);
    }
    if (added) syncGroupSnapshot();
    return added;
}

bool NetworkMonitor::removeProcessGroupMember(const QString &groupId,
                                              NetGuard::GroupMemberType type,
                                              const QString &value)
{
    bool removed = false;
    {
        QMutexLocker lk(&m_groupMutex);
        removed = m_groupManager.removeMember(groupId, type, value);
    }
    if (removed) syncGroupSnapshot();
    return removed;
}

void NetworkMonitor::startCapture()
{
    if (isRunning()) return;
    m_stopFlag.store(false);
    m_firstTick = true;
    m_lastTick = std::chrono::steady_clock::now();
    m_speedTimer->start();
    start(QThread::HighPriority);
}

void NetworkMonitor::stopCapture()
{
    m_stopFlag.store(true);
    m_speedTimer->stop();
}

void NetworkMonitor::run()
{
    m_captureRunning.store(true);
    emit captureStarted();

    if (m_adapterIP.isEmpty()) {
        emit adapterDiagnostic(QString(), QStringLiteral("No adapter IP set."));
        emit captureError("No adapter IP set.");
        m_captureRunning.store(false); emit captureStopped(); return;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa)) {
        emit adapterDiagnostic(m_adapterIP, QStringLiteral("WSAStartup failed."));
        emit captureError("WSAStartup failed.");
        m_captureRunning.store(false); emit captureStopped(); return;
    }

    // ── Open Dual Sockets for IPv4 and IPv6 Packet Capture ──
    SOCKET sock4 = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    SOCKET sock6 = INVALID_SOCKET;

    if (sock4 == INVALID_SOCKET) {
        emit adapterDiagnostic(m_adapterIP, QStringLiteral("Raw socket unavailable — run as Administrator."));
        emit captureError("WSASocket failed — run as Administrator.");
        WSACleanup(); m_captureRunning.store(false); emit captureStopped(); return;
    }

    int rcvBufSize = 32 * 1024 * 1024;
    setsockopt(sock4, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvBufSize), sizeof(rcvBufSize));
    sockaddr_in sa4 = {}; sa4.sin_family = AF_INET; sa4.sin_addr.s_addr = inet_addr(m_adapterIP.toLatin1().constData());

    if (bind(sock4, reinterpret_cast<sockaddr*>(&sa4), sizeof(sa4)) == SOCKET_ERROR) {
        emit adapterDiagnostic(m_adapterIP, QStringLiteral("bind() IPv4 failed."));
        emit captureError("bind() IPv4 failed.");
        closesocket(sock4); WSACleanup(); m_captureRunning.store(false); emit captureStopped(); return;
    }

    DWORD dw = 0, on = RCVALL_ON;
    WSAIoctl(sock4, SIO_RCVALL, &on, sizeof(on), nullptr, 0, &dw, nullptr, nullptr);

    // ── Configure IPv6 Socket ──
    if (!m_adapterIPv6.isEmpty()) {
        sock6 = WSASocket(AF_INET6, SOCK_RAW, IPPROTO_IPV6, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (sock6 != INVALID_SOCKET) {
            setsockopt(sock6, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvBufSize), sizeof(rcvBufSize));
            sockaddr_in6 sa6 = {};
            sa6.sin6_family = AF_INET6;
            inet_pton(AF_INET6, m_adapterIPv6.toLatin1().constData(), &sa6.sin6_addr);
            if (bind(sock6, reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6)) != SOCKET_ERROR) {
                WSAIoctl(sock6, SIO_RCVALL, &on, sizeof(on), nullptr, 0, &dw, nullptr, nullptr);
            } else {
                closesocket(sock6); sock6 = INVALID_SOCKET;
            }
        }
    }

    QByteArray buf(1024 * 1024, '\0');
    QList<CapturedPacketInfo> batch;
    batch.reserve(5000);
    qint64 lastBatchTime = QDateTime::currentMSecsSinceEpoch();

    // NG-003: aggregate capture gaps per report interval so diagnostics stay
    // cheap and never interrupt the capture loop.
    int droppedSinceReport = 0;
    int unresolvedSinceReport = 0;
    int unknownDirectionSinceReport = 0;

    auto flushGaps = [&]() {
        if (droppedSinceReport > 0 || unresolvedSinceReport > 0 || unknownDirectionSinceReport > 0) {
            emit captureGapDetected(droppedSinceReport, unresolvedSinceReport,
                                    unknownDirectionSinceReport, m_adapterIP);
            droppedSinceReport = 0;
            unresolvedSinceReport = 0;
            unknownDirectionSinceReport = 0;
        }
    };

    std::atomic<bool> cacheStop{false};
    std::thread cacheThread([this, &cacheStop]() {
        int loopCount = 0;
        while (!cacheStop.load()) {
            updateCaches();
            loopCount++;
            if (loopCount >= 25) { // Refresh local IPs every 5s
                refreshLocalIPs();
                loopCount = 0;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });

    while (!m_stopFlag.load())
    {
        // ── Listen on both IPv4 and IPv6 ──
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(sock4, &readSet);
        if (sock6 != INVALID_SOCKET) FD_SET(sock6, &readSet);

        timeval tv = {0, 100000}; // 100ms timeout
        int res = select(0, &readSet, nullptr, nullptr, &tv);

        if (res > 0) {
            SOCKET activeSock = FD_ISSET(sock4, &readSet) ? sock4 : (sock6 != INVALID_SOCKET && FD_ISSET(sock6, &readSet) ? sock6 : INVALID_SOCKET);
            if (activeSock == INVALID_SOCKET) continue;

            int len = recv(activeSock, buf.data(), buf.size(), 0);
            if (len == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAEMSGSIZE) {
                    len = buf.size();          // truncated packet: capture gap
                    ++droppedSinceReport;
                } else {
                    ++droppedSinceReport;      // socket error: capture gap
                    continue;
                }
            }
            else if (len <= 0) continue;

            ParsedPacket pkt = PacketParser::parseIP(reinterpret_cast<const uint8_t*>(buf.constData()), static_cast<uint32_t>(len));
            if (!pkt.valid) continue;

            const bool srcIsLocal = m_localIPs.contains(pkt.srcIP) || pkt.srcIP == m_adapterIP || pkt.srcIP == m_adapterIPv6 || pkt.srcIP.startsWith("127.") || pkt.srcIP == "::1";
            const bool dstIsLocal = m_localIPs.contains(pkt.dstIP) || pkt.dstIP == m_adapterIP || pkt.dstIP == m_adapterIPv6 || pkt.dstIP.startsWith("127.") || pkt.dstIP == "::1";

            bool directionKnown = true;
            if (dstIsLocal && !srcIsLocal) {
                pkt.isDownload = true;
            } else if (srcIsLocal && !dstIsLocal) {
                pkt.isDownload = false;
            } else if (dstIsLocal && srcIsLocal) {
                pkt.isDownload = (pkt.dstIP == m_adapterIP || pkt.dstIP == m_adapterIPv6);
                // Both endpoints are local: direction is only known when one of
                // them is this adapter (otherwise it is loopback/another adapter).
                directionKnown = (pkt.dstIP == m_adapterIP || pkt.dstIP == m_adapterIPv6 ||
                                  pkt.srcIP == m_adapterIP || pkt.srcIP == m_adapterIPv6);
            } else {
                // Neither endpoint is local: the packet belongs to another adapter
                // (promiscuous capture) and its direction cannot be attributed.
                pkt.isDownload = (pkt.dstIP == m_adapterIP || pkt.dstIP == m_adapterIPv6);
                directionKnown = false;
            }
            if (!directionKnown)
                ++unknownDirectionSinceReport;

            quint32 pid  = 0;
            QString proc = "Unknown";
            bool isSvc = false;
            QString identityId, identityName, identityPublisher;
            ApplicationIdentity::SignerStatus signerStatus = ApplicationIdentity::SignerStatus::Unknown;
            qint64 processStartMs = 0;
            quint32 parentPid = 0;
            QString parentName;
            QString groupId, groupName;
            ApplicationIdentity::Confidence groupConfidence =
                ApplicationIdentity::Confidence::Unknown;

            if (pkt.protocol.startsWith("TCP") || pkt.protocol.startsWith("UDP")) {
                QString sPortStr = QString::number(pkt.srcPort);
                QString dPortStr = QString::number(pkt.dstPort);
                QString tcpF = pkt.srcIP + ":" + sPortStr + "-" + pkt.dstIP + ":" + dPortStr;
                QString tcpR = pkt.dstIP + ":" + dPortStr + "-" + pkt.srcIP + ":" + sPortStr;
                QString udpS = pkt.srcIP + ":" + sPortStr;
                QString udpD = pkt.dstIP + ":" + dPortStr;

                QMutexLocker lk(&m_cacheMutex);
                if (pkt.protocol.startsWith("TCP")) {
                    if (m_tcpCache.contains(tcpF)) pid = m_tcpCache.value(tcpF);
                    else if (m_tcpCache.contains(tcpR)) pid = m_tcpCache.value(tcpR);

                    if (pid == 0) {
                        quint16 localPort = pkt.isDownload ? pkt.dstPort : pkt.srcPort;
                        if (m_tcpListenCache.contains(localPort)) pid = m_tcpListenCache.value(localPort);
                        else if (m_tcpListenCache.contains(pkt.dstPort)) pid = m_tcpListenCache.value(pkt.dstPort);
                        else if (m_tcpListenCache.contains(pkt.srcPort)) pid = m_tcpListenCache.value(pkt.srcPort);
                    }
                } else {
                    if (m_udpCache.contains(udpS)) pid = m_udpCache.value(udpS);
                    else if (m_udpCache.contains(udpD)) pid = m_udpCache.value(udpD);

                    if (pid == 0) {
                        quint16 localPort = pkt.isDownload ? pkt.dstPort : pkt.srcPort;
                        if (m_udpAnyCache.contains(localPort)) pid = m_udpAnyCache.value(localPort);
                        else if (m_udpAnyCache.contains(pkt.dstPort)) pid = m_udpAnyCache.value(pkt.dstPort);
                        else if (m_udpAnyCache.contains(pkt.srcPort)) pid = m_udpAnyCache.value(pkt.srcPort);
                    }
                }

                if (pid == 0) {
                    proc = "System Services / Network Overhead";
                    isSvc = true;
                    ++unresolvedSinceReport;   // NG-003: owner PID not resolvable
                } else if (pid == 4) {
                    proc = "System Kernel (ntoskrnl)";
                    isSvc = true;
                } else {
                    proc = m_procCache.value(pid, "Unknown");
                    if (proc.startsWith("Service:")) isSvc = true;
                }

                // NG-010: attach the durable identity resolved by the cache
                // thread. Read under the same lock as the tables above.
                const auto identityIt = m_identityCache.constFind(pid);
                if (identityIt != m_identityCache.constEnd()) {
                    identityId = identityIt->id;
                    identityName = identityIt->displayName;
                    identityPublisher = identityIt->publisher;
                    signerStatus = identityIt->signerStatus;
                }

                // NG-013: start time and parent of the owning instance.
                const auto lineageIt = m_lineageCache.constFind(pid);
                if (lineageIt != m_lineageCache.constEnd()) {
                    processStartMs = lineageIt->startTimeMs;
                    parentPid = lineageIt->parentPid;
                    if (parentPid != 0) parentName = m_procCache.value(parentPid);
                }

                // NG-014: durable activity group of the owning process.
                const auto groupIt = m_groupCache.constFind(pid);
                if (groupIt != m_groupCache.constEnd() && groupIt->isValid()) {
                    groupId = groupIt->groupId;
                    groupName = groupIt->groupName;
                    groupConfidence = groupIt->confidence;
                }
            }

            // NG-030: passive DNS. The raw datagram is still available here, so
            // a visible UDP/53 message is parsed and the payload discarded; the
            // resolved socket owner travels with the event.
            if (m_collectDns.load() && pkt.protocol.startsWith(QStringLiteral("UDP")) &&
                (pkt.srcPort == 53 || pkt.dstPort == 53)) {
                const QList<DnsEvent> events = DnsObserver::parseDatagram(
                    reinterpret_cast<const uint8_t *>(buf.constData()),
                    static_cast<quint32>(len));
                for (DnsEvent event : events) {
                    if (pid != 0) {
                        event.pid = pid;
                        event.processName = proc;
                    }
                    event.identityId = identityId;
                    // NG-031: only answers with addresses create a mapping; the
                    // store bounds lifetime by the DNS TTL and keeps the owner.
                    m_dnsCorrelator.observe(event);
                    emit dnsObservation(event);
                }
            }

            // NG-033: safe QUIC metadata. Only clear long-header facts are
            // parsed: the Initial payload holds an encrypted ClientHello, so
            // this reports unknown attribution rather than decrypting traffic.
            if (m_collectQuic.load() && pkt.protocol.startsWith(QStringLiteral("UDP"))) {
                QuicObservation observation = QuicObserver::parseDatagram(
                    reinterpret_cast<const uint8_t *>(buf.constData()),
                    static_cast<quint32>(len));
                if (observation.status != QuicMetadataStatus::NotQuic &&
                    observation.status != QuicMetadataStatus::NotInitial) {
                    if (pid != 0) {
                        observation.pid = pid;
                        observation.processName = proc;
                    }
                    observation.identityId = identityId;
                    emit quicObservation(observation);
                }
            }

            // NG-032: visible TLS. Only a ClientHello can name a destination;
            // non-TLS traffic and server handshakes are ignored here, while a
            // split, encrypted, ECH, or malformed handshake is reported as
            // unavailable instead of being given a guessed name.
            if (m_collectTlsSni.load() && pkt.protocol.startsWith(QStringLiteral("TCP"))) {
                TlsObservation observation = TlsObserver::parseDatagram(
                    reinterpret_cast<const uint8_t *>(buf.constData()),
                    static_cast<quint32>(len));
                if (observation.status != TlsSniStatus::NotTls &&
                    observation.status != TlsSniStatus::NotClientHello) {
                    if (pid != 0) {
                        observation.pid = pid;
                        observation.processName = proc;
                    }
                    observation.identityId = identityId;
                    // NG-032/NG-035: associate a visible SNI with the remote
                    // endpoint so the connection tree can combine it with a
                    // DNS answer. Capture sees both directions; the remote side
                    // is the source of received traffic and the destination of
                    // sent traffic.
                    observation.remoteAddress =
                        pkt.isDownload ? pkt.srcIP : pkt.dstIP;
                    m_dnsCorrelator.observeTls(observation);
                    emit tlsObservation(observation);
                }
            }

            batch.append({pkt, pid, proc, isSvc, identityId, identityName,
                          identityPublisher, signerStatus, processStartMs,
                          parentPid, parentName, groupId, groupName, groupConfidence});

            qint64 now = QDateTime::currentMSecsSinceEpoch();
            if (now - lastBatchTime >= 250 || batch.size() >= 3000) {
                emit packetsCapturedBatch(batch);
                batch.clear();
                flushGaps();
                lastBatchTime = now;
            }
        }
    }

    if (!batch.isEmpty()) emit packetsCapturedBatch(batch);
    flushGaps();

    cacheStop.store(true);
    cacheThread.join();

    DWORD off = RCVALL_OFF;
    WSAIoctl(sock4, SIO_RCVALL, &off, sizeof(off), nullptr, 0, &dw, nullptr, nullptr);
    closesocket(sock4);
    if (sock6 != INVALID_SOCKET) {
        WSAIoctl(sock6, SIO_RCVALL, &off, sizeof(off), nullptr, 0, &dw, nullptr, nullptr);
        closesocket(sock6);
    }
    WSACleanup();

    m_captureRunning.store(false); emit captureStopped();
}

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
    const NetGuard::ServicePidMap servicesByPid = m_serviceResolver.servicesByPid();
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
    m_lineage.expire(QDateTime::currentMSecsSinceEpoch());
    QVector<NetGuard::LineageTransition> reusedPids;

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
                                if (svc.state == NetGuard::ServiceState::Running) {
                                    primary = svc.displayName;
                                    break;
                                }
                            }
                            if (!primary.isEmpty()) procName = "Service: " + primary;
                        }
                        pCache.insert(aProcs[i], procName);

                        NetGuard::LineageObservation observation;
                        observation.pid            = aProcs[i];
                        observation.parentPid      = parentByPid.value(aProcs[i], 0);
                        observation.processName    = procName;
                        observation.executablePath = fullPath;
                        observation.identityId     = knownIdentities.value(aProcs[i]);
                        FILETIME created{}, exitedTime{}, kernelTime{}, userTime{};
                        if (GetProcessTimes(hProc, &created, &exitedTime, &kernelTime, &userTime))
                            observation.startTimeMs = fileTimeToMs(created);

                        for (const auto &transition : m_lineage.observe(observation))
                            if (transition.change == NetGuard::LineageChange::Reused)
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

        const NetGuard::IdentityResolution resolution = m_identityResolver.resolvePid(pid);
        if (resolution.ok()) {
            idCache.insert(pid, resolution.identity);
            continue;
        }

        failureCache.insert(pid, static_cast<quint32>(resolution.status));
        // Exiting processes are expected; only report failures that hide an
        // executable we can still attribute.
        if (resolution.status != NetGuard::IdentityResolutionStatus::ProcessNotFound)
            emit identityResolutionFailed(pid,
                NetGuard::identityResolutionStatusName(resolution.status),
                resolution.message);
    }

    // ── 3c. Publish the service mapping for PIDs that own traffic ──
    // Only changed snapshots are sent, so a state poll does not repaint the
    // tree; the GUI keeps per-service rows for shared hosts.
    NetGuard::ServicePidMap servicesForActive;
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
    QHash<quint32, NetGuard::ProcessLineageRecord> lineageForActive;
    for (quint32 pid : activePids) {
        const NetGuard::ProcessLineageRecord record = m_lineage.record(pid);
        if (record.isValid()) lineageForActive.insert(pid, record);
    }

    // ── 3e. Group the PIDs that own traffic (NG-014) ──
    // Each observation carries the identity, publisher, service, and lineage
    // evidence gathered above, so one pass decides the membership of every
    // active process and records why. Groups are rebuilt each refresh; only
    // user edits are persisted.
    QList<NetGuard::GroupEvidence> groupEvidence;
    groupEvidence.reserve(activePids.size());
    for (quint32 pid : activePids) {
        const NetGuard::ProcessLineageRecord record = m_lineage.record(pid);
        if (!record.isValid() || record.executablePath.isEmpty()) continue;

        NetGuard::GroupEvidence evidence;
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
            for (const NetGuard::ServiceEntry &service : hosted.value()) {
                evidence.serviceNames.append(service.serviceName);
                evidence.serviceDisplayNames.append(service.displayName);
            }
        }

        groupEvidence.append(evidence);
    }
    QHash<quint32, NetGuard::GroupBinding> groupBindings;
    {
        // Serialized with GUI edits (rename, add/remove member).
        QMutexLocker lk(&m_groupMutex);
        groupBindings = m_groupManager.assign(groupEvidence);
    }
    syncGroupSnapshot();

    // ── 4. Detect stale mappings: a connection key changed owner ──
    // Rate-limited to once per 5 seconds so a churning table cannot flood
    // the diagnostics model.
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
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
}

void NetworkMonitor::refreshLocalIPs()
{
    m_localIPs.clear();
    ULONG sz = 15000;
    QByteArray buf(static_cast<int>(sz), '\0');
    auto *a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST, nullptr, a, &sz) != NO_ERROR) return;
    for (; a; a = a->Next)
        for (auto *ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            SOCKADDR *s = ua->Address.lpSockaddr;
            char ip[INET6_ADDRSTRLEN] = {};
            if      (s->sa_family==AF_INET)  inet_ntop(AF_INET,  &reinterpret_cast<sockaddr_in *>(s)->sin_addr,  ip, sizeof(ip));
            else if (s->sa_family==AF_INET6) inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(s)->sin6_addr, ip, sizeof(ip));
            if (ip[0]) m_localIPs << QString::fromLatin1(ip);
        }
}
