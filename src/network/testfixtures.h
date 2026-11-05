/**
 * @file   testfixtures.h
 * @brief  Test fixtures for product-direction automated tests (Phase 0).
 *         Provides known-traffic scenarios and expected identity/category results.
 * @author Codebuff
 */

#pragma once

#include <QString>
#include <QList>
#include <QPair>
#include "packetparser.h"

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
// Each entry provides a raw packet buffer (as it would come from the capture thread)
// and the expected parsed result identity/category.
struct TestPacketFixture
{
    QByteArray rawPacket;   // Raw packet bytes (IP layer onward, no Ethernet header)
    ParsedPacket parsed;    // Expected result from PacketParser::parseIP
    TrafficScenario scenario;
    QString expectedCategory;  // Expected BandwidthGuard::ProcessCategory
    QString expectedIdentity;  // Expected identity descriptor
};

// ─── Fixture collections ────────────────────────────────────────────────────
// Generates one fixture per TrafficScenario. Fill in the rawPacket with minimal
// valid IP packets; the parser will populate parsed.srcIP, parsed.dstIP, etc.
// expectedCategory and expectedIdentity should match what BandwidthGuard::classifyProcess
// would return given the parsed information.
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
// Returns a map of scenario -> (pass/fail count, details).
struct FixtureResult
{
    int passed = 0;
    int failed = 0;
    QString details;
};
FixtureResult runAllFixtures();
