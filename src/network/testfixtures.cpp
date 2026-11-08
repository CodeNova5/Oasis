/**
 * @file   testfixtures.cpp
 * @brief  Test fixtures implementation for product-direction automated tests (Phase 0).
 *         Provides known-traffic scenarios and expected identity/category results.
 * @author Codebuff
 */

#include "testfixtures.h"

#include <QHostAddress>
#include <QStringList>

// ─── Packet builders ────────────────────────────────────────────────────────
// The capture path hands parseIP() a bare IP packet (no Ethernet header), so the
// builders below produce exactly that: a 20-byte IPv4 header or a 40-byte IPv6
// header, followed by the transport header the scenario needs. All multi-byte
// fields are written in network byte order because parseIP() reads them with
// ntohs()/ntohl().
namespace {

void writeBe16(uint8_t *p, quint16 value)
{
    p[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    p[1] = static_cast<uint8_t>(value & 0xFF);
}

void writeBe32(uint8_t *p, quint32 value)
{
    p[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(value & 0xFF);
}

// IPv4 address bytes in network order. An address that does not parse falls back
// to loopback, so a typo in a fixture cannot silently produce a random address.
void writeIpv4(uint8_t *p, const QString &address)
{
    QHostAddress host(address);
    quint32 value = 0x7F000001u; // 127.0.0.1
    if (host.protocol() == QAbstractSocket::IPv4Protocol)
        value = host.toIPv4Address();
    writeBe32(p, value);
}

void writeIpv6(uint8_t *p, const QString &address)
{
    QHostAddress host(address);
    if (host.protocol() == QAbstractSocket::IPv6Protocol) {
        const Q_IPV6ADDR v6 = host.toIPv6Address();
        memcpy(p, &v6, 16);
        return;
    }
    // ::1 fallback for a fixture typo.
    memset(p, 0, 16);
    p[15] = 1;
}

void fillTcpHeader(uint8_t *tcp, quint16 srcPort, quint16 dstPort)
{
    writeBe16(tcp + 0, srcPort);
    writeBe16(tcp + 2, dstPort);
    writeBe32(tcp + 4, 0);            // sequence number
    writeBe32(tcp + 8, 0);            // acknowledgment number
    tcp[12] = 0x50;                   // data offset 5 * 4 = 20 bytes
    tcp[13] = 0x10;                   // ACK
    writeBe16(tcp + 14, 0xFFFF);      // window
    writeBe16(tcp + 16, 0);           // checksum (not validated by the parser)
    writeBe16(tcp + 18, 0);           // urgent pointer
}

QByteArray buildIpv4TcpPacket(const QString &srcAddr, const QString &dstAddr,
                              quint16 srcPort, quint16 dstPort)
{
    const int ipHeaderLen = 20;
    const int tcpHeaderLen = 20;
    QByteArray pkt(ipHeaderLen + tcpHeaderLen, Qt::Uninitialized);
    uint8_t *h = reinterpret_cast<uint8_t *>(pkt.data());

    h[0] = 0x45;                        // version 4, header length 5 * 4 bytes
    h[1] = 0;                           // DSCP / ECN
    writeBe16(h + 2, static_cast<quint16>(pkt.size())); // total length
    writeBe16(h + 4, 0);                // identification
    writeBe16(h + 6, 0);                // flags / fragment offset
    h[8] = 64;                          // TTL
    h[9] = IPPROTO_TCP_;                // protocol
    writeBe16(h + 10, 0);               // header checksum (not validated)
    writeIpv4(h + 12, srcAddr);
    writeIpv4(h + 16, dstAddr);

    fillTcpHeader(h + ipHeaderLen, srcPort, dstPort);
    return pkt;
}

QByteArray buildIpv4UdpPacket(const QString &srcAddr, const QString &dstAddr,
                              quint16 srcPort, quint16 dstPort)
{
    const int ipHeaderLen = 20;
    QByteArray pkt(ipHeaderLen + 8, Qt::Uninitialized);
    uint8_t *h = reinterpret_cast<uint8_t *>(pkt.data());

    h[0] = 0x45;
    h[1] = 0;
    writeBe16(h + 2, static_cast<quint16>(pkt.size()));
    writeBe16(h + 4, 0);
    writeBe16(h + 6, 0);
    h[8] = 64;
    h[9] = IPPROTO_UDP_;
    writeBe16(h + 10, 0);
    writeIpv4(h + 12, srcAddr);
    writeIpv4(h + 16, dstAddr);

    writeBe16(h + ipHeaderLen + 0, srcPort);
    writeBe16(h + ipHeaderLen + 2, dstPort);
    writeBe16(h + ipHeaderLen + 4, 8);  // UDP length: header only
    writeBe16(h + ipHeaderLen + 6, 0);  // checksum (not validated)
    return pkt;
}

QByteArray buildIpv4IcmpPacket(const QString &srcAddr, const QString &dstAddr)
{
    const int ipHeaderLen = 20;
    QByteArray pkt(ipHeaderLen + 8, Qt::Uninitialized);
    uint8_t *h = reinterpret_cast<uint8_t *>(pkt.data());

    h[0] = 0x45;
    h[1] = 0;
    writeBe16(h + 2, static_cast<quint16>(pkt.size()));
    writeBe16(h + 4, 0);
    writeBe16(h + 6, 0);
    h[8] = 64;
    h[9] = IPPROTO_ICMP_;
    writeBe16(h + 10, 0);
    writeIpv4(h + 12, srcAddr);
    writeIpv4(h + 16, dstAddr);

    h[ipHeaderLen + 0] = 8;             // echo request
    h[ipHeaderLen + 1] = 0;             // code
    writeBe16(h + ipHeaderLen + 4, 0);  // identifier
    writeBe16(h + ipHeaderLen + 6, 1);  // sequence number
    return pkt;
}

QByteArray buildIpv6TcpPacket(const QString &srcAddr, const QString &dstAddr,
                              quint16 srcPort, quint16 dstPort)
{
    const int ipHeaderLen = 40;
    const int tcpHeaderLen = 20;
    QByteArray pkt(ipHeaderLen + tcpHeaderLen, Qt::Uninitialized);
    uint8_t *h = reinterpret_cast<uint8_t *>(pkt.data());

    h[0] = 0x60;                        // version 6
    writeBe16(h + 4, static_cast<quint16>(tcpHeaderLen)); // payload length
    h[6] = IPPROTO_TCP_;                // next header
    h[7] = 64;                          // hop limit
    writeIpv6(h + 8, srcAddr);
    writeIpv6(h + 24, dstAddr);

    fillTcpHeader(h + ipHeaderLen, srcPort, dstPort);
    return pkt;
}

QByteArray buildIpv6Icmpv6Packet(const QString &srcAddr, const QString &dstAddr)
{
    QByteArray pkt(40, Qt::Uninitialized);
    uint8_t *h = reinterpret_cast<uint8_t *>(pkt.data());

    h[0] = 0x60;
    writeBe16(h + 4, 0);                // no payload
    h[6] = IPPROTO_ICMPv6_;             // next header
    h[7] = 255;                         // hop limit
    writeIpv6(h + 8, srcAddr);
    writeIpv6(h + 24, dstAddr);
    return pkt;
}

// Builds a fixture around a raw packet: parses it once, records the 5-tuple the
// builder intended, and attaches the evidence the classifier should receive.
TestPacketFixture makeFixture(TrafficScenario scenario,
                              const QByteArray &rawPacket,
                              const QString &expectedSrcIP,
                              const QString &expectedDstIP,
                              quint16 expectedSrcPort,
                              quint16 expectedDstPort,
                              const QString &expectedIdentity,
                              const ClassificationEvidence &evidence,
                              ProcessCategory expectedCategory)
{
    TestPacketFixture fixture;
    fixture.rawPacket = rawPacket;
    fixture.parsed = PacketParser::parseIP(
        reinterpret_cast<const uint8_t *>(fixture.rawPacket.constData()),
        static_cast<uint32_t>(fixture.rawPacket.size()));
    fixture.scenario = scenario;
    fixture.expectedSrcIP = expectedSrcIP;
    fixture.expectedDstIP = expectedDstIP;
    fixture.expectedSrcPort = expectedSrcPort;
    fixture.expectedDstPort = expectedDstPort;
    fixture.expectedIdentity = expectedIdentity;
    fixture.evidence = evidence;
    fixture.expectedCategory = expectedCategory;
    return fixture;
}

QString scenarioName(TrafficScenario scenario)
{
    switch (scenario) {
    case TrafficScenario::BrowserDownload: return QStringLiteral("browser-download");
    case TrafficScenario::BrowserUpload:   return QStringLiteral("browser-upload");
    case TrafficScenario::Updater:         return QStringLiteral("updater");
    case TrafficScenario::RespawnWorker:   return QStringLiteral("respawn-worker");
    case TrafficScenario::WindowsService:  return QStringLiteral("windows-service");
    case TrafficScenario::DnsQuery:        return QStringLiteral("dns-query");
    case TrafficScenario::TlsHandshake:    return QStringLiteral("tls-handshake");
    case TrafficScenario::VpnEncrypted:    return QStringLiteral("vpn-encrypted");
    case TrafficScenario::Unknown:         return QStringLiteral("unknown");
    case TrafficScenario::GameLauncher:    return QStringLiteral("game-launcher");
    case TrafficScenario::IdeUpdate:       return QStringLiteral("ide-update");
    case TrafficScenario::Count:           break;
    }
    return QStringLiteral("scenario-%1").arg(static_cast<int>(scenario));
}

} // namespace

// ─── Browser Download: HTTPS request from local to external ──────────────────
QList<TestPacketFixture> createBrowserDownloadFixture()
{
    QList<TestPacketFixture> fixtures;

    // chrome.exe and msedge.exe are both name rules, so a browser download is
    // AskFirst no matter which browser produced it.
    fixtures.append(makeFixture(
        TrafficScenario::BrowserDownload,
        buildIpv4TcpPacket("192.168.1.100", "93.184.216.34", 50000, 443),
        "192.168.1.100", "93.184.216.34", 50000, 443,
        "Google Chrome (chrome.exe)",
        fixtureEvidence("chrome.exe"), ProcessCategory::AskFirst));

    fixtures.append(makeFixture(
        TrafficScenario::BrowserDownload,
        buildIpv4TcpPacket("192.168.1.100", "93.184.216.34", 50001, 443),
        "192.168.1.100", "93.184.216.34", 50001, 443,
        "Microsoft Edge (msedge.exe)",
        fixtureEvidence("msedge.exe"), ProcessCategory::AskFirst));

    return fixtures;
}

// ─── Updater: Simulated updater traffic ─────────────────────────────────────
QList<TestPacketFixture> createUpdaterFixture()
{
    QList<TestPacketFixture> fixtures;

    // 1. Name rule: chromeupdate.exe is AutoCandidate even with no publisher.
    fixtures.append(makeFixture(
        TrafficScenario::Updater,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50000, 443),
        "192.168.1.100", "192.0.0.1", 50000, 443,
        "Chrome Update (chromeupdate.exe)",
        fixtureEvidence("chromeupdate.exe"), ProcessCategory::AutoCandidate));

    // 2. Name rule: Edge's updater.
    fixtures.append(makeFixture(
        TrafficScenario::Updater,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50001, 443),
        "192.168.1.100", "192.0.0.1", 50001, 443,
        "Microsoft Edge Update (microsoftedgeupdate.exe)",
        fixtureEvidence("microsoftedgeupdate.exe"), ProcessCategory::AutoCandidate));

    // 3. No name rule: googleupdater.exe would be Unknown, but a verified
    //    Google publisher plus product metadata is an identity rule.
    fixtures.append(makeFixture(
        TrafficScenario::Updater,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50002, 443),
        "192.168.1.100", "192.0.0.1", 50002, 443,
        "Google Updater (renamed executable, verified publisher)",
        fixtureEvidence("googleupdater.exe", false, "Google LLC", "Google Update"),
        ProcessCategory::AutoCandidate));

    // 4. The same name with no verified signer must not borrow Google's rule.
    fixtures.append(makeFixture(
        TrafficScenario::Updater,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50003, 443),
        "192.168.1.100", "192.0.0.1", 50003, 443,
        "Unsigned copy of GoogleUpdater.exe",
        fixtureEvidence("googleupdater.exe"), ProcessCategory::Unknown));

    return fixtures;
}

// ─── Windows Service: svchost.exe traffic ──────────────────────────────────
QList<TestPacketFixture> createWindowsServiceFixture()
{
    QList<TestPacketFixture> fixtures;

    // svchost.exe has no name rule; the service flag is what protects it.
    fixtures.append(makeFixture(
        TrafficScenario::WindowsService,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50000, 80),
        "192.168.1.100", "192.0.0.1", 50000, 80,
        "Service host (svchost.exe)",
        fixtureEvidence("svchost.exe", true), ProcessCategory::Protected));

    // The same host running Windows Update traffic stays Protected.
    fixtures.append(makeFixture(
        TrafficScenario::WindowsService,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50001, 80),
        "192.168.1.100", "192.0.0.1", 50001, 80,
        "Windows Update host (svchost.exe)",
        fixtureEvidence("svchost.exe", true, "Microsoft Windows", "Windows Update"),
        ProcessCategory::Protected));

    return fixtures;
}

// ─── DNS Query: DNS resolution traffic ─────────────────────────────────────
QList<TestPacketFixture> createDnsFixture()
{
    QList<TestPacketFixture> fixtures;

    // A resolver has no name rule and is not an updater, so DNS traffic stays
    // Unknown until the activity classifier (NG-040) describes the destination.
    fixtures.append(makeFixture(
        TrafficScenario::DnsQuery,
        buildIpv4UdpPacket("192.168.1.100", "8.8.8.8", 53000, 53),
        "192.168.1.100", "8.8.8.8", 53000, 53,
        "DNS query (nslookup.exe)",
        fixtureEvidence("nslookup.exe"), ProcessCategory::Unknown));

    fixtures.append(makeFixture(
        TrafficScenario::DnsQuery,
        buildIpv4UdpPacket("8.8.8.8", "192.168.1.100", 53, 53000),
        "8.8.8.8", "192.168.1.100", 53, 53000,
        "DNS response (nslookup.exe)",
        fixtureEvidence("nslookup.exe"), ProcessCategory::Unknown));

    return fixtures;
}

// ─── TLS SNI Handshake ─────────────────────────────────────────────────────
QList<TestPacketFixture> createTlsSniFixture()
{
    QList<TestPacketFixture> fixtures;

    // A TLS handshake carries no name the classifier knows yet: SNI belongs to
    // the attribution layer (NG-032), so the category stays Unknown.
    fixtures.append(makeFixture(
        TrafficScenario::TlsHandshake,
        buildIpv4TcpPacket("192.168.1.100", "1.1.1.1", 50000, 443),
        "192.168.1.100", "1.1.1.1", 50000, 443,
        "TLS client hello over IPv4 (curl.exe)",
        fixtureEvidence("curl.exe"), ProcessCategory::Unknown));

    // Same handshake over IPv6, to keep the IPv6 builder exercised.
    fixtures.append(makeFixture(
        TrafficScenario::TlsHandshake,
        buildIpv6TcpPacket("2606:4700:4700::1111", "2606:4700:4700::1001", 50001, 443),
        QString(), QString(), 50001, 443,
        "TLS client hello over IPv6 (curl.exe)",
        fixtureEvidence("curl.exe"), ProcessCategory::Unknown));

    return fixtures;
}

// ─── VPN Encrypted traffic ──────────────────────────────────────────────────
QList<TestPacketFixture> createVpnFixture()
{
    QList<TestPacketFixture> fixtures;

    // Traffic on a tunnel address is not attributable from the packet alone.
    fixtures.append(makeFixture(
        TrafficScenario::VpnEncrypted,
        buildIpv4TcpPacket("10.0.0.2", "10.0.0.1", 50000, 443),
        "10.0.0.2", "10.0.0.1", 50000, 443,
        "OpenVPN tunnel traffic",
        fixtureEvidence("openvpn.exe"), ProcessCategory::Unknown));

    fixtures.append(makeFixture(
        TrafficScenario::VpnEncrypted,
        buildIpv4TcpPacket("10.8.0.2", "10.8.0.1", 50001, 443),
        "10.8.0.2", "10.8.0.1", 50001, 443,
        "WireGuard tunnel traffic",
        fixtureEvidence("wireguard.exe"), ProcessCategory::Unknown));

    return fixtures;
}

// ─── Unknown traffic ────────────────────────────────────────────────────────
QList<TestPacketFixture> createUnknownFixture()
{
    QList<TestPacketFixture> fixtures;

    // TEST-NET-1 / TEST-NET-2: unroutable addresses, no name rule, no evidence.
    fixtures.append(makeFixture(
        TrafficScenario::Unknown,
        buildIpv4IcmpPacket("192.0.2.1", "198.51.100.1"),
        "192.0.2.1", "198.51.100.1", 0, 0,
        "IPv4 ICMP from an unrecognised process",
        fixtureEvidence("mysteryapp.exe"), ProcessCategory::Unknown));

    fixtures.append(makeFixture(
        TrafficScenario::Unknown,
        buildIpv6Icmpv6Packet("2001:db8::1", "2001:db8::2"),
        QString(), QString(), 0, 0,
        "IPv6 ICMPv6 from an unrecognised process",
        fixtureEvidence("mysteryapp.exe"), ProcessCategory::Unknown));

    return fixtures;
}

// ─── Game Launcher ──────────────────────────────────────────────────────────
QList<TestPacketFixture> createGameLauncherFixture()
{
    QList<TestPacketFixture> fixtures;

    fixtures.append(makeFixture(
        TrafficScenario::GameLauncher,
        buildIpv4TcpPacket("192.168.1.100", "104.160.141.0", 50000, 443),
        "192.168.1.100", "104.160.141.0", 50000, 443,
        "Steam launcher",
        fixtureEvidence("steam.exe"), ProcessCategory::AskFirst));

    fixtures.append(makeFixture(
        TrafficScenario::GameLauncher,
        buildIpv4TcpPacket("192.168.1.100", "104.160.141.0", 50001, 443),
        "192.168.1.100", "104.160.141.0", 50001, 443,
        "Epic Games Launcher",
        fixtureEvidence("epicgameslauncher.exe"), ProcessCategory::AskFirst));

    return fixtures;
}

// ─── IDE Update ─────────────────────────────────────────────────────────────
QList<TestPacketFixture> createIdeUpdateFixture()
{
    QList<TestPacketFixture> fixtures;

    // No IDE executable has a name or identity rule yet. That is honest and
    // intentional: describing an IDE update is the activity classifier's job
    // (NG-040), not a Data Saver category guess.
    fixtures.append(makeFixture(
        TrafficScenario::IdeUpdate,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50000, 443),
        "192.168.1.100", "192.0.0.1", 50000, 443,
        "Visual Studio Code update check (code.exe)",
        fixtureEvidence("code.exe", false, "Microsoft Corporation", "Visual Studio Code"),
        ProcessCategory::Unknown));

    fixtures.append(makeFixture(
        TrafficScenario::IdeUpdate,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50001, 443),
        "192.168.1.100", "192.0.0.1", 50001, 443,
        "JetBrains IDE update check (idea64.exe)",
        fixtureEvidence("idea64.exe", false, "JetBrains s.r.o.", "IntelliJ IDEA"),
        ProcessCategory::Unknown));

    return fixtures;
}

// ─── Respawn worker: traffic from a worker that respawns after termination ─────
QList<TestPacketFixture> createRespawnWorkerFixture()
{
    QList<TestPacketFixture> fixtures;

    // A sync worker that a watchdog restarts: the first instance and the
    // replacement must land in the same category, although the PID changes.
    fixtures.append(makeFixture(
        TrafficScenario::RespawnWorker,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50000, 443),
        "192.168.1.100", "192.0.0.1", 50000, 443,
        "OneDrive sync worker, first instance",
        fixtureEvidence("onedrive.exe"), ProcessCategory::AutoCandidate));

    fixtures.append(makeFixture(
        TrafficScenario::RespawnWorker,
        buildIpv4TcpPacket("192.168.1.100", "192.0.0.1", 50001, 443),
        "192.168.1.100", "192.0.0.1", 50001, 443,
        "OneDrive sync worker, respawned",
        fixtureEvidence("onedrive.exe"), ProcessCategory::AutoCandidate));

    return fixtures;
}

// ─── Run all fixtures ───────────────────────────────────────────────────────
FixtureResult runAllFixtures()
{
    FixtureResult result;
    const QList<QList<TestPacketFixture>> allFixtures = {
        createBrowserDownloadFixture(),
        createUpdaterFixture(),
        createWindowsServiceFixture(),
        createDnsFixture(),
        createTlsSniFixture(),
        createVpnFixture(),
        createUnknownFixture(),
        createGameLauncherFixture(),
        createIdeUpdateFixture(),
        createRespawnWorkerFixture()
    };

    for (const QList<TestPacketFixture> &batch : allFixtures) {
        for (const TestPacketFixture &fixture : batch) {
            QStringList problems;

            // The packet half: a fixture is only meaningful if the bytes the
            // builder produced parse back into the 5-tuple it claims.
            if (!fixture.parsed.valid) {
                problems << QStringLiteral("packet did not parse");
            } else {
                if (!fixture.expectedSrcIP.isEmpty() && fixture.parsed.srcIP != fixture.expectedSrcIP) {
                    problems << QStringLiteral("src %1 != %2")
                                    .arg(fixture.parsed.srcIP, fixture.expectedSrcIP);
                }
                if (!fixture.expectedDstIP.isEmpty() && fixture.parsed.dstIP != fixture.expectedDstIP) {
                    problems << QStringLiteral("dst %1 != %2")
                                    .arg(fixture.parsed.dstIP, fixture.expectedDstIP);
                }
                if (fixture.parsed.srcPort != fixture.expectedSrcPort) {
                    problems << QStringLiteral("src port %1 != %2")
                                    .arg(fixture.parsed.srcPort)
                                    .arg(fixture.expectedSrcPort);
                }
                if (fixture.parsed.dstPort != fixture.expectedDstPort) {
                    problems << QStringLiteral("dst port %1 != %2")
                                    .arg(fixture.parsed.dstPort)
                                    .arg(fixture.expectedDstPort);
                }
            }

            // The identity half: the process behind that traffic must land in
            // the category the fixture claims, through the real classifier.
            const ProcessCategory actual = BandwidthGuard::classifyProcess(fixture.evidence);
            if (actual != fixture.expectedCategory) {
                problems << QStringLiteral("%1 classified as %2 (%3), expected %4")
                                .arg(fixture.evidence.processName,
                                     BandwidthGuard::categoryDisplayName(actual))
                                .arg(static_cast<int>(actual))
                                .arg(static_cast<int>(fixture.expectedCategory));
            }

            const QString label = QStringLiteral("%1: %2")
                                      .arg(scenarioName(fixture.scenario),
                                           fixture.expectedIdentity);
            if (problems.isEmpty()) {
                ++result.passed;
                result.details += QStringLiteral("PASS %1\n").arg(label);
            } else {
                ++result.failed;
                result.details += QStringLiteral("FAIL %1 -- %2\n")
                                      .arg(label, problems.join(QStringLiteral("; ")));
            }
        }
    }

    return result;
}
