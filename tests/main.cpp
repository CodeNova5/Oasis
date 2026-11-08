/**
 * @file   main.cpp
 * @brief  Focused harness for the Phase 0 tickets: NG-002 contract round-trips
 *         and NG-001 product-direction fixtures.
 *
 * Run it after a build:
 *   qmake tests/netguard_tests.pro && mingw32-make
 *   ./netguard_tests
 *
 * Exit code 0 means every check passed; failures are printed with the value
 * that was observed so a broken rule does not need a debugger to explain.
 */

#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStringList>
#include <QTimeZone>

#include "network/policy.h"
#include "network/testfixtures.h"

namespace {

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const QString &what)
{
    ++g_checks;
    if (condition) return;
    ++g_failures;
    qWarning().noquote() << "FAIL" << what;
}

template <typename T>
void checkEqual(const T &actual, const T &expected, const QString &what)
{
    ++g_checks;
    if (actual == expected) return;
    ++g_failures;
    QString detail;
    QDebug(&detail) << actual << "!=" << expected;
    qWarning().noquote() << "FAIL" << what << "--" << detail;
}

QJsonObject objectOf(const QString &json)
{
    return QJsonDocument::fromJson(json.toUtf8()).object();
}

// ─── NG-002: contract round-trips ───────────────────────────────────────────
// Every contract is written with all fields set, read back, and compared field
// by field. Each payload must also carry the schema version it was written with.

void testApplicationIdentityRoundTrip()
{
    ApplicationIdentity in;
    in.id = QStringLiteral("sha1:0123456789abcdef");
    in.displayName = QStringLiteral("Google Chrome");
    in.executablePaths << QStringLiteral("C:/Program Files/Google/Chrome/chrome.exe")
                       << QStringLiteral("C:/Program Files (x86)/Google/Chrome/chrome.exe");
    in.publisher = QStringLiteral("Google LLC");
    in.signerStatus = ApplicationIdentity::SignerStatus::Signed;
    in.productName = QStringLiteral("Google Chrome");
    in.originalFileName = QStringLiteral("chrome.exe");
    in.fileVersion = QStringLiteral("131.0.6778.86");
    in.companyName = QStringLiteral("Google LLC");
    in.packageFamilyName = QStringLiteral("Google.Chrome_1234");
    in.services << QStringLiteral("ChromeElevationService");
    in.processNames << QStringLiteral("chrome.exe");
    in.fingerprints = QByteArray("\x00\x01\xFE\x7F", 4);
    in.confidence = ApplicationIdentity::Confidence::Confirmed;

    const QString json = toJson(in);
    checkEqual(objectOf(json).value(QLatin1String(PolicyContract::kSchemaVersionKey)).toInt(),
               PolicyContract::kSchemaVersion,
               QStringLiteral("ApplicationIdentity payload carries the schema version"));

    const ApplicationIdentity out = fromJsonApplicationIdentity(json);
    checkEqual(out.id, in.id, QStringLiteral("ApplicationIdentity.id"));
    checkEqual(out.displayName, in.displayName, QStringLiteral("ApplicationIdentity.displayName"));
    checkEqual(out.executablePaths, in.executablePaths,
               QStringLiteral("ApplicationIdentity.executablePaths"));
    checkEqual(out.publisher, in.publisher, QStringLiteral("ApplicationIdentity.publisher"));
    checkEqual(static_cast<int>(out.signerStatus), static_cast<int>(in.signerStatus),
               QStringLiteral("ApplicationIdentity.signerStatus"));
    checkEqual(out.productName, in.productName, QStringLiteral("ApplicationIdentity.productName"));
    checkEqual(out.originalFileName, in.originalFileName,
               QStringLiteral("ApplicationIdentity.originalFileName"));
    checkEqual(out.fileVersion, in.fileVersion, QStringLiteral("ApplicationIdentity.fileVersion"));
    checkEqual(out.companyName, in.companyName, QStringLiteral("ApplicationIdentity.companyName"));
    checkEqual(out.packageFamilyName, in.packageFamilyName,
               QStringLiteral("ApplicationIdentity.packageFamilyName"));
    checkEqual(out.services, in.services, QStringLiteral("ApplicationIdentity.services"));
    checkEqual(out.processNames, in.processNames,
               QStringLiteral("ApplicationIdentity.processNames"));
    checkEqual(out.fingerprints, in.fingerprints,
               QStringLiteral("ApplicationIdentity.fingerprints (binary bytes)"));
    checkEqual(static_cast<int>(out.confidence), static_cast<int>(in.confidence),
               QStringLiteral("ApplicationIdentity.confidence"));
}

void testActivityObservationRoundTrip()
{
    ActivityObservation in;
    in.timestamp = QDateTime(QDate(2026, 11, 8), QTime(12, 34, 56), QTimeZone::UTC);
    in.identityId = QStringLiteral("sha1:0123456789abcdef");
    in.pid = 4242;
    in.direction = NetworkDirection::Upload;
    in.bytes = 123456789012ULL;
    in.protocol = QStringLiteral("TCP");
    in.localEndpoint = QStringLiteral("192.168.1.100:50000");
    in.remoteEndpoint = QStringLiteral("93.184.216.34:443");
    in.domain = QStringLiteral("example.com");
    in.attributionSource = ActivityObservation::AttributionSource::StrongInference;
    in.classification = ActivityObservation::Classification::Likely;
    in.details = QStringLiteral("observed during a browser download");

    const QString json = toJson(in);
    checkEqual(objectOf(json).value(QLatin1String(PolicyContract::kSchemaVersionKey)).toInt(),
               PolicyContract::kSchemaVersion,
               QStringLiteral("ActivityObservation payload carries the schema version"));

    const ActivityObservation out = fromJsonActivityObservation(json);
    checkEqual(out.timestamp, in.timestamp, QStringLiteral("ActivityObservation.timestamp"));
    checkEqual(out.identityId, in.identityId, QStringLiteral("ActivityObservation.identityId"));
    checkEqual(out.pid, in.pid, QStringLiteral("ActivityObservation.pid"));
    checkEqual(static_cast<int>(out.direction), static_cast<int>(in.direction),
               QStringLiteral("ActivityObservation.direction"));
    checkEqual(out.bytes, in.bytes, QStringLiteral("ActivityObservation.bytes (64-bit)"));
    checkEqual(out.protocol, in.protocol, QStringLiteral("ActivityObservation.protocol"));
    checkEqual(out.localEndpoint, in.localEndpoint,
               QStringLiteral("ActivityObservation.localEndpoint"));
    checkEqual(out.remoteEndpoint, in.remoteEndpoint,
               QStringLiteral("ActivityObservation.remoteEndpoint"));
    checkEqual(out.domain, in.domain, QStringLiteral("ActivityObservation.domain"));
    checkEqual(static_cast<int>(out.attributionSource), static_cast<int>(in.attributionSource),
               QStringLiteral("ActivityObservation.attributionSource"));
    checkEqual(static_cast<int>(out.classification), static_cast<int>(in.classification),
               QStringLiteral("ActivityObservation.classification"));
    checkEqual(out.details, in.details, QStringLiteral("ActivityObservation.details"));
}

void testNetworkPolicyRoundTrip()
{
    NetworkPolicy in;
    in.id = QStringLiteral("policy-chrome-temporary");
    in.scope = QStringLiteral("path");
    in.targetId = QStringLiteral("C:/Program Files/Google/Chrome/chrome.exe");
    in.direction = NetworkDirection::Both;
    in.action = NetworkPolicy::Action::Throttle;
    in.scheduleType = NetworkPolicy::ScheduleType::Expiration;
    in.rateBitsPerSecond = 8000000ULL;
    in.schedule = QStringLiteral("work-hours");
    in.expiration = QDateTime(QDate(2026, 12, 1), QTime(0, 0), QTimeZone::UTC);
    in.source = QStringLiteral("user");
    in.enabled = false;
    in.description = QStringLiteral("limit Chrome during work hours");

    const QString json = toJson(in);
    checkEqual(objectOf(json).value(QLatin1String(PolicyContract::kSchemaVersionKey)).toInt(),
               PolicyContract::kSchemaVersion,
               QStringLiteral("NetworkPolicy payload carries the schema version"));

    const NetworkPolicy out = fromJsonNetworkPolicy(json);
    checkEqual(out.id, in.id, QStringLiteral("NetworkPolicy.id"));
    checkEqual(out.scope, in.scope, QStringLiteral("NetworkPolicy.scope"));
    checkEqual(out.targetId, in.targetId, QStringLiteral("NetworkPolicy.targetId"));
    checkEqual(static_cast<int>(out.direction), static_cast<int>(in.direction),
               QStringLiteral("NetworkPolicy.direction"));
    checkEqual(static_cast<int>(out.action), static_cast<int>(in.action),
               QStringLiteral("NetworkPolicy.action"));
    checkEqual(static_cast<int>(out.scheduleType), static_cast<int>(in.scheduleType),
               QStringLiteral("NetworkPolicy.scheduleType"));
    checkEqual(out.rateBitsPerSecond, in.rateBitsPerSecond,
               QStringLiteral("NetworkPolicy.rateBitsPerSecond"));
    checkEqual(out.schedule, in.schedule, QStringLiteral("NetworkPolicy.schedule"));
    checkEqual(out.expiration, in.expiration, QStringLiteral("NetworkPolicy.expiration"));
    checkEqual(out.source, in.source, QStringLiteral("NetworkPolicy.source"));
    checkEqual(out.enabled, in.enabled, QStringLiteral("NetworkPolicy.enabled"));
    checkEqual(out.description, in.description, QStringLiteral("NetworkPolicy.description"));
}

void testThrottleResultRoundTrip()
{
    NetworkPolicyThrottleResult in;
    in.status = NetworkPolicyThrottleResult::Status::Applied;
    in.message = QStringLiteral("upload limited, download unavailable");
    in.policyId = QStringLiteral("policy-chrome-temporary");
    in.executablePath = QStringLiteral("C:/Program Files/Google/Chrome/chrome.exe");
    in.uploadLimited = true;
    in.downloadLimited = false;
    in.uploadReason = QStringLiteral("QoS policy applied");
    in.downloadReason = QStringLiteral("WinDivert driver not found");

    const QString json = toJson(in);
    checkEqual(objectOf(json).value(QLatin1String(PolicyContract::kSchemaVersionKey)).toInt(),
               PolicyContract::kSchemaVersion,
               QStringLiteral("NetworkPolicyThrottleResult payload carries the schema version"));

    const NetworkPolicyThrottleResult out = fromJsonNetworkPolicyThrottleResult(json);
    checkEqual(static_cast<int>(out.status), static_cast<int>(in.status),
               QStringLiteral("NetworkPolicyThrottleResult.status"));
    checkEqual(out.message, in.message, QStringLiteral("NetworkPolicyThrottleResult.message"));
    checkEqual(out.policyId, in.policyId, QStringLiteral("NetworkPolicyThrottleResult.policyId"));
    checkEqual(out.executablePath, in.executablePath,
               QStringLiteral("NetworkPolicyThrottleResult.executablePath"));
    checkEqual(out.uploadLimited, in.uploadLimited,
               QStringLiteral("NetworkPolicyThrottleResult.uploadLimited"));
    checkEqual(out.downloadLimited, in.downloadLimited,
               QStringLiteral("NetworkPolicyThrottleResult.downloadLimited"));
    checkEqual(out.uploadReason, in.uploadReason,
               QStringLiteral("NetworkPolicyThrottleResult.uploadReason"));
    checkEqual(out.downloadReason, in.downloadReason,
               QStringLiteral("NetworkPolicyThrottleResult.downloadReason"));
}

void testAuditEventRoundTrip()
{
    AuditEvent in;
    in.timestamp = QDateTime(QDate(2026, 11, 8), QTime(9, 15, 0), QTimeZone::UTC);
    in.type = AuditEvent::EventType::EnforcementResult;
    in.scope = QStringLiteral("group:chrome");
    in.reason = QStringLiteral("sustained background download");
    in.result = QStringLiteral("throttled");
    in.errorInfo = QStringLiteral("download channel unavailable");
    in.relatedIdentityId = QStringLiteral("sha1:0123456789abcdef");
    in.relatedPolicyId = QStringLiteral("policy-chrome-temporary");
    in.details = QStringLiteral("{\"bytes\":10485760}");

    const QString json = toJson(in);
    checkEqual(objectOf(json).value(QLatin1String(PolicyContract::kSchemaVersionKey)).toInt(),
               PolicyContract::kSchemaVersion,
               QStringLiteral("AuditEvent payload carries the schema version"));

    const AuditEvent out = fromJsonAuditEvent(json);
    checkEqual(out.timestamp, in.timestamp, QStringLiteral("AuditEvent.timestamp"));
    checkEqual(static_cast<int>(out.type), static_cast<int>(in.type),
               QStringLiteral("AuditEvent.type"));
    checkEqual(out.scope, in.scope, QStringLiteral("AuditEvent.scope"));
    checkEqual(out.reason, in.reason, QStringLiteral("AuditEvent.reason"));
    checkEqual(out.result, in.result, QStringLiteral("AuditEvent.result"));
    checkEqual(out.errorInfo, in.errorInfo, QStringLiteral("AuditEvent.errorInfo"));
    checkEqual(out.relatedIdentityId, in.relatedIdentityId,
               QStringLiteral("AuditEvent.relatedIdentityId"));
    checkEqual(out.relatedPolicyId, in.relatedPolicyId,
               QStringLiteral("AuditEvent.relatedPolicyId"));
    checkEqual(out.details, in.details, QStringLiteral("AuditEvent.details"));
}

void testSchemaVersionGate()
{
    // Pre-versioning data (written before NG-002 added the key) must still load.
    NetworkPolicy legacy;
    legacy.id = QStringLiteral("legacy-policy");
    legacy.scope = QStringLiteral("publisher");
    legacy.targetId = QStringLiteral("Google LLC");

    QJsonObject legacyObject = objectOf(toJson(legacy));
    legacyObject.remove(QLatin1String(PolicyContract::kSchemaVersionKey));
    const NetworkPolicy legacyOut = fromJsonNetworkPolicy(
        QString::fromUtf8(QJsonDocument(legacyObject).toJson(QJsonDocument::Compact)));
    checkEqual(legacyOut.id, legacy.id,
               QStringLiteral("a payload without a schema version is read as version 1"));

    // A payload from a newer build is rejected instead of half-parsed.
    QJsonObject futureObject = objectOf(toJson(legacy));
    futureObject[QLatin1String(PolicyContract::kSchemaVersionKey)] =
        PolicyContract::kSchemaVersion + 1;
    const NetworkPolicy futureOut = fromJsonNetworkPolicy(
        QString::fromUtf8(QJsonDocument(futureObject).toJson(QJsonDocument::Compact)));
    check(futureOut.id.isEmpty(),
          QStringLiteral("a payload from a newer schema version is rejected"));

    const ApplicationIdentity futureIdentity = fromJsonApplicationIdentity(
        QString::fromUtf8(QJsonDocument(futureObject).toJson(QJsonDocument::Compact)));
    check(futureIdentity.id.isEmpty(),
          QStringLiteral("the version gate applies to every contract reader"));
}

// ─── NG-001: product-direction fixtures ─────────────────────────────────────

void testFixtures()
{
    const FixtureResult result = runAllFixtures();

    qInfo().noquote() << result.details.trimmed();
    qInfo() << "fixtures:" << result.passed << "passed," << result.failed << "failed";

    checkEqual(result.failed, 0, QStringLiteral("NG-001 fixtures: no failing fixture"));
    // Ten scenario builders with two fixtures each, plus two extra updater
    // variants (identity rule and its unsigned counterpart).
    checkEqual(result.passed + result.failed, 22,
               QStringLiteral("NG-001 fixtures: every fixture ran"));
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    testApplicationIdentityRoundTrip();
    testActivityObservationRoundTrip();
    testNetworkPolicyRoundTrip();
    testThrottleResultRoundTrip();
    testAuditEventRoundTrip();
    testSchemaVersionGate();

    testFixtures();

    qInfo() << "checks:" << g_checks << "failures:" << g_failures;
    return g_failures == 0 ? 0 : 1;
}
