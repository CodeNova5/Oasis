/**
 * @file    networkmonitor.cpp
 * @brief   Thread-safe capture with dedicated caching thread and exact process/service mapping.
 * Includes Smart Auto-Detect & Dual-Socket IPv4/IPv6 Capture Engine!
 * @author  Oasis
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



NetworkMonitor::NetworkMonitor(QObject *parent) : QThread(parent)
{
    qRegisterMetaType<DnsEvent>("DnsEvent");
    qRegisterMetaType<TlsObservation>("TlsObservation");
    qRegisterMetaType<QuicObservation>("QuicObservation");
    qRegisterMetaType<Oasis::ForegroundSnapshot>("Oasis::ForegroundSnapshot");

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

QList<DestinationNameSummary> NetworkMonitor::attributionSummaries() const
{
    return m_dnsCorrelator.summaries();
}

QList<DomainAttribution> NetworkMonitor::attributionRecords() const
{
    return m_dnsCorrelator.records();
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

Oasis::ForegroundSnapshot NetworkMonitor::foregroundSnapshot() const
{
    QMutexLocker lk(&m_cacheMutex);
    return m_foregroundCache;
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
QList<Oasis::ProcessGroup> NetworkMonitor::processGroups() const
{
    QMutexLocker lk(&m_groupMutex);
    return m_publishedGroups;
}

void NetworkMonitor::syncGroupSnapshot()
{
    QList<Oasis::ProcessGroup> groups;
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
                                           Oasis::GroupMemberType type,
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
                                              Oasis::GroupMemberType type,
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
            Oasis::ForegroundAssociation foregroundAssociation =
                Oasis::ForegroundAssociation::None;

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

                // NG-041: the foreground snapshot is read under the same lock as
                // the caches above. Freshness is checked here, so an old sample
                // never marks a packet as foreground.
                foregroundAssociation = m_foregroundCache.associationFor(
                    pid, QDateTime::currentMSecsSinceEpoch());
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
                          parentPid, parentName, groupId, groupName, groupConfidence,
                          foregroundAssociation});

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


