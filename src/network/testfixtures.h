/**
 * @file   testfixtures.h
 * @brief  Test fixtures for product-direction automated tests (Phase 0).
 *         Provides known-traffic scenarios and expected identity/category results.
 * @author Codebuff
 */

#pragma once

#include <QString>
#include <QList>
#include <QByteArray>

#include "packetparser.h"
#include "bandwidthguard.h"

// ─── Traffic scenario types ────────────────────────────────────────────────
enum class TrafficScenario : int {
    BrowserDownload,      // Standard browser download (HTTPS)
    BrowserUpload,        // Browser upload (HTTPS)
    Updater,              // Simulated updater (e.g., chromeupdate.exe)
    RespawnWorker,        // Worker that respawns after termination
    WindowsService,       // Traffic from a Windows service
    DnsQuery,             // DNS query traffic
    TlsHandshake,         // TLS handshake with visible SNI
    VpnEncrypted,         // VPN-encrypted traffic (unknown destination)
    Unknown,              // Unclassified/unknown traffic
    GameLauncher,         // Game launcher initial connection
    IdeUpdate,            // IDE extension/update download
    Count                // Must remain last
};

// ─── Test packet data ──────────────────────────────────────────────────────
// Each entry provides a raw packet buffer (as it would come from the capture
// thread), what that buffer must parse to, and the evidence the classifier
// should see for the process that owns such a connection. The expected identity
// and category therefore describe the same process, and runAllFixtures() checks
// both halves: the packet parses to the intended 5-tuple, and classifyProcess()
// puts that process in the intended category.
struct TestPacketFixture
{
    QByteArray rawPacket;   // Raw packet bytes (IP layer onward, no Ethernet header)
    ParsedPacket parsed;    // Result of PacketParser::parseIP on rawPacket
    TrafficScenario scenario;

    // Parsed 5-tuple the builder intends. Empty address strings are not
    // asserted (IPv6 fixtures check validity, ports, and category instead).
    QString expectedSrcIP;
    QString expectedDstIP;
    quint16 expectedSrcPort = 0;
    quint16 expectedDstPort = 0;

    QString expectedIdentity;        // Human description of the process behind the traffic
    ClassificationEvidence evidence; // Evidence handed to BandwidthGuard::classifyProcess
    ProcessCategory expectedCategory = ProcessCategory::Unknown;
};

// Convenience: evidence for a fixture whose decision comes from its executable
// name, or from a verified publisher when no name rule matches. `pid` is not 4
// and `isService` is false unless the scenario is a service, so the fixture
// exercises the name/identity rules rather than the protected-process shortcut.
inline ClassificationEvidence fixtureEvidence(const QString &processName,
                                              bool isService = false,
                                              const QString &publisher = QString(),
                                              const QString &displayName = QString())
{
    ClassificationEvidence evidence;
    evidence.pid = 1234;
    evidence.processName = processName;
    evidence.isService = isService;
    evidence.publisher = publisher;
    evidence.displayName = displayName;
    evidence.signerStatus = publisher.isEmpty()
        ? ApplicationIdentity::SignerStatus::Unsigned
        : ApplicationIdentity::SignerStatus::Signed;
    return evidence;
}

// ─── Fixture collections ────────────────────────────────────────────────────
QList<TestPacketFixture> createBrowserDownloadFixture();
QList<TestPacketFixture> createUpdaterFixture();
QList<TestPacketFixture> createWindowsServiceFixture();
QList<TestPacketFixture> createDnsFixture();
QList<TestPacketFixture> createTlsSniFixture();
QList<TestPacketFixture> createVpnFixture();
QList<TestPacketFixture> createUnknownFixture();
QList<TestPacketFixture> createGameLauncherFixture();
QList<TestPacketFixture> createIdeUpdateFixture();

// ─── Respawn worker: traffic from a worker that respawns after termination ─────
QList<TestPacketFixture> createRespawnWorkerFixture();

// ─── Convenience: run all fixtures ──────────────────────────────────────────
// Returns pass/fail counts plus one line per fixture, and does not abort on the
// first failure so one broken rule does not hide the rest.
struct FixtureResult
{
    int passed = 0;
    int failed = 0;
    QString details;
};
FixtureResult runAllFixtures();
