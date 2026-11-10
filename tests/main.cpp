/**
 * @file   main.cpp
 * @brief  Focused harness for the Phase 0 tickets: NG-002 contract round-trips,
 *         NG-001 product-direction fixtures, and the NG-003 diagnostics export.
 *
 * Run it after a build:
 *   qmake tests/netguard_tests.pro && mingw32-make
 *   ./netguard_tests
 *
 * Exit code 0 means every check passed; failures are printed with the value
 * that was observed so a broken rule does not need a debugger to explain.
 */

#include <QCoreApplication>
#include <QDate>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QStringList>
#include <QTimeZone>

#include "attribution/dnsobserver.h"
#include "attribution/dnscorrelator.h"
#include "attribution/tlsobserver.h"
#include "attribution/quicobserver.h"
#include "attribution/endpointcatalog.h"
#include "attribution/attributionconfidence.h"
#include "firewall/rulenames.h"
#include "network/diagnostics.h"
#include "network/enforcementrestore.h"
#include "network/policy.h"
#include "network/policyreconcile.h"
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

// ─── NG-003: diagnostics export schema ─────────────────────────────────────
// toJson() is what a user attaches to a support report, so its shape is a
// contract: fixed key names, string enum values, and a summary that agrees with
// the records it describes. The version is asserted as a literal on purpose:
// changing the export should require a deliberate change to this test.
void testDiagnosticsExportSchema()
{
    DiagnosticsModel model;

    const QJsonObject empty = objectOf(model.toJson());
    checkEqual(empty.value(QStringLiteral("schemaVersion")).toInt(), 1,
               QStringLiteral("diagnostics export carries schemaVersion 1"));
    check(QDateTime::fromString(empty.value(QStringLiteral("exportedAt")).toString(),
                                Qt::ISODateWithMs).isValid(),
          QStringLiteral("diagnostics export carries a parseable exportedAt"));

    QStringList rootKeys = empty.keys();
    rootKeys.sort();
    QStringList expectedRootKeys{QStringLiteral("exportedAt"), QStringLiteral("records"),
                                 QStringLiteral("schemaVersion"), QStringLiteral("summary")};
    expectedRootKeys.sort();
    checkEqual(rootKeys, expectedRootKeys, QStringLiteral("diagnostics export root keys"));

    const QJsonObject emptySummary = empty.value(QStringLiteral("summary")).toObject();
    QStringList summaryKeys = emptySummary.keys();
    summaryKeys.sort();
    QStringList expectedSummaryKeys{QStringLiteral("records"), QStringLiteral("droppedPackets"),
                                    QStringLiteral("unresolvedPids"),
                                    QStringLiteral("unknownDirections"),
                                    QStringLiteral("staleMappings"),
                                    QStringLiteral("pidReuses"),
                                    QStringLiteral("adapterUnavailable")};
    expectedSummaryKeys.sort();
    checkEqual(summaryKeys, expectedSummaryKeys, QStringLiteral("diagnostics summary keys"));
    check(empty.value(QStringLiteral("records")).toArray().isEmpty(),
          QStringLiteral("an empty model exports an empty records array"));
    for (const QString &key : summaryKeys) {
        checkEqual(emptySummary.value(key).toInt(), 0,
                   QStringLiteral("empty diagnostics summary counter %1 is zero").arg(key));
    }

    // One record per gap reporter the capture loop uses.
    model.reportDroppedPackets(3, QStringLiteral("Ethernet"), QStringLiteral("capture loop"));
    model.reportUnresolvedPid(4321, QStringLiteral("unknown.exe"), QStringLiteral("cache refresh"));
    model.reportUnknownDirection(QStringLiteral("192.0.2.1 -> 198.51.100.1"),
                                 QStringLiteral("capture loop"));
    model.reportStaleMapping(77, QStringLiteral("chrome.exe"), QStringLiteral("svchost.exe"),
                             QStringLiteral("cache refresh"));
    model.reportAdapterUnavailable(QStringLiteral("Wi-Fi"),
                                   QStringLiteral("No suitable adapter"));
    model.reportServiceLookupFailed(88, QStringLiteral("Dnscache"),
                                    QStringLiteral("SCM enumeration failed"));
    model.reportPidReuse(99, QStringLiteral("old.exe"), QStringLiteral("new.exe"), 1000, 2000);

    checkEqual(model.rowCount(), 7, QStringLiteral("one diagnostic record per reporter"));

    const QJsonObject populated = objectOf(model.toJson());
    const QJsonObject summary = populated.value(QStringLiteral("summary")).toObject();
    checkEqual(summary.value(QStringLiteral("records")).toInt(), 7,
               QStringLiteral("summary counts every record"));
    for (const QString &key : {QStringLiteral("droppedPackets"), QStringLiteral("unresolvedPids"),
                               QStringLiteral("unknownDirections"), QStringLiteral("staleMappings"),
                               QStringLiteral("pidReuses"), QStringLiteral("adapterUnavailable")}) {
        checkEqual(summary.value(key).toInt(), 1,
                   QStringLiteral("summary counter %1 counts its gap").arg(key));
    }

    const QJsonArray records = populated.value(QStringLiteral("records")).toArray();
    checkEqual(static_cast<int>(records.size()), 7,
               QStringLiteral("export carries one object per record"));

    QStringList recordKeys = records.at(0).toObject().keys();
    recordKeys.sort();
    QStringList expectedRecordKeys{QStringLiteral("timestamp"), QStringLiteral("dropReason"),
                                   QStringLiteral("pidStatus"), QStringLiteral("directionStatus"),
                                   QStringLiteral("adapterStatus"), QStringLiteral("mappingStatus"),
                                   QStringLiteral("details"), QStringLiteral("context"),
                                   QStringLiteral("affectedPid"),
                                   QStringLiteral("affectedProcess")};
    expectedRecordKeys.sort();
    checkEqual(recordKeys, expectedRecordKeys, QStringLiteral("diagnostic record keys"));

    for (const QJsonValue &value : records) {
        const QJsonObject record = value.toObject();
        check(QDateTime::fromString(record.value(QStringLiteral("timestamp")).toString(),
                                    Qt::ISODateWithMs).isValid(),
              QStringLiteral("every record timestamp is ISO-8601 with milliseconds"));
        check(record.value(QStringLiteral("affectedPid")).isDouble(),
              QStringLiteral("every record exports affectedPid as a number"));
    }

    // Enum values are exported as their documented names, not raw integers, so
    // an exported report can be read without the binary.
    const QJsonObject dropped = records.at(0).toObject();
    checkEqual(dropped.value(QStringLiteral("dropReason")).toString(),
               QStringLiteral("BufferOverflow"),
               QStringLiteral("drop reason export name"));
    checkEqual(dropped.value(QStringLiteral("pidStatus")).toString(),
               QStringLiteral("Resolved"), QStringLiteral("pid status export name"));
    checkEqual(dropped.value(QStringLiteral("adapterStatus")).toString(),
               QStringLiteral("AdapterAvailable"),
               QStringLiteral("adapter status export name"));
    check(dropped.value(QStringLiteral("details")).toString().contains(QStringLiteral("3 packets")),
          QStringLiteral("dropped-packet details name the count"));

    const QJsonObject unresolved = records.at(1).toObject();
    checkEqual(unresolved.value(QStringLiteral("pidStatus")).toString(),
               QStringLiteral("Unresolved"), QStringLiteral("unresolved PID export name"));
    checkEqual(unresolved.value(QStringLiteral("affectedPid")).toInt(), 4321,
               QStringLiteral("unresolved PID record keeps the PID"));
    checkEqual(unresolved.value(QStringLiteral("affectedProcess")).toString(),
               QStringLiteral("unknown.exe"),
               QStringLiteral("unresolved PID record keeps the process name"));

    checkEqual(records.at(2).toObject().value(QStringLiteral("directionStatus")).toString(),
               QStringLiteral("UnknownDirection"),
               QStringLiteral("unknown direction export name"));

    const QJsonObject stale = records.at(3).toObject();
    checkEqual(stale.value(QStringLiteral("mappingStatus")).toString(),
               QStringLiteral("StaleMapping"), QStringLiteral("stale mapping export name"));
    checkEqual(stale.value(QStringLiteral("affectedPid")).toInt(), 77,
               QStringLiteral("stale mapping record keeps the PID"));

    const QJsonObject adapter = records.at(4).toObject();
    checkEqual(adapter.value(QStringLiteral("adapterStatus")).toString(),
               QStringLiteral("AdapterUnavailable"),
               QStringLiteral("adapter unavailable export name"));
    check(adapter.value(QStringLiteral("context")).toString().contains(QStringLiteral("Wi-Fi")),
          QStringLiteral("adapter record names the adapter"));

    const QJsonObject service = records.at(5).toObject();
    checkEqual(service.value(QStringLiteral("pidStatus")).toString(),
               QStringLiteral("ServiceHost"),
               QStringLiteral("service lookup failure is not counted as an unresolved PID"));

    const QJsonObject reuse = records.at(6).toObject();
    checkEqual(reuse.value(QStringLiteral("pidStatus")).toString(),
               QStringLiteral("PidReuse"), QStringLiteral("PID reuse export name"));
    checkEqual(reuse.value(QStringLiteral("affectedPid")).toInt(), 99,
               QStringLiteral("PID reuse record keeps the PID"));
    checkEqual(reuse.value(QStringLiteral("affectedProcess")).toString(),
               QStringLiteral("new.exe"),
               QStringLiteral("PID reuse record names the replacement process"));

    // Retention: the model keeps a bounded window, and the export's own record
    // count must describe what survived rather than what was reported.
    for (int i = 0; i < static_cast<int>(DiagnosticsModel::MaxRecords) + 5; ++i) {
        DiagnosticRecord record;
        record.timestamp = QDateTime::currentDateTimeUtc();
        record.details = QStringLiteral("synthetic %1").arg(i);
        model.addRecord(record);
    }

    checkEqual(model.rowCount(), static_cast<int>(DiagnosticsModel::MaxRecords),
               QStringLiteral("diagnostics model keeps at most MaxRecords records"));

    const QJsonObject bounded = objectOf(model.toJson());
    checkEqual(bounded.value(QStringLiteral("summary")).toObject()
                   .value(QStringLiteral("records")).toInt(),
               static_cast<int>(DiagnosticsModel::MaxRecords),
               QStringLiteral("bounded export reports the retained count"));
    const QJsonArray kept = bounded.value(QStringLiteral("records")).toArray();
    checkEqual(kept.at(0).toObject().value(QStringLiteral("details")).toString(),
               QStringLiteral("synthetic 5"),
               QStringLiteral("the oldest records are evicted first"));
    checkEqual(kept.last().toObject().value(QStringLiteral("details")).toString(),
               QStringLiteral("synthetic 504"),
               QStringLiteral("the newest record is retained"));

    model.clear();
    const QJsonObject cleared = objectOf(model.toJson());
    check(cleared.value(QStringLiteral("records")).toArray().isEmpty(),
          QStringLiteral("clear() empties the export"));
    checkEqual(cleared.value(QStringLiteral("summary")).toObject()
                   .value(QStringLiteral("records")).toInt(),
               0, QStringLiteral("clear() resets the summary"));
}

// ─── NG-026 / NG-027 helpers ──────────────────────────────────────────────
// The store tests below run under their own application name, so they never
// touch a real NetGuard policy set.
NetworkPolicy makePolicy(const QString &id, const QString &source,
                         NetworkPolicy::Action action = NetworkPolicy::Action::Allow)
{
    NetworkPolicy policy;
    policy.id = id;
    policy.scope = QStringLiteral("path");
    policy.targetId = QStringLiteral("C:/Apps/%1.exe").arg(id);
    policy.action = action;
    policy.source = source;
    return policy;
}

// ─── NG-026: emergency restore only removes the product's own policies ─────
void testPolicyOriginClassification()
{
    NetworkPolicy policy;
    check(policyOrigin(policy) == PolicyOrigin::Unknown,
          QStringLiteral("an unrecorded source is not treated as automatic"));

    policy.source = QStringLiteral("user");
    check(policyOrigin(policy) == PolicyOrigin::User,
          QStringLiteral("a user policy is recognised as the user's"));
    policy.source = QStringLiteral(" USER ");
    check(policyOrigin(policy) == PolicyOrigin::User,
          QStringLiteral("origin matching ignores case and padding"));

    for (const QString &source : {QStringLiteral("automatic"), QStringLiteral("AUTO"),
                                  QStringLiteral("system"), QStringLiteral("ai")}) {
        policy.source = source;
        check(policyOrigin(policy) == PolicyOrigin::Automatic,
              QStringLiteral("source '%1' counts as automatic").arg(source));
    }

    for (const QString &source : {QString(), QStringLiteral("unknown"),
                                  QStringLiteral("user-created"),
                                  QStringLiteral("administrator")}) {
        policy.source = source;
        check(policyOrigin(policy) == PolicyOrigin::Unknown,
              QStringLiteral("source '%1' is preserved rather than guessed at").arg(source));
    }
}

void testEmergencyRestorePlan()
{
    const QList<NetworkPolicy> policies{
        makePolicy(QStringLiteral("auto-1"), QStringLiteral("automatic"),
                   NetworkPolicy::Action::Throttle),
        makePolicy(QStringLiteral("user-1"), QStringLiteral("user"),
                   NetworkPolicy::Action::Block),
        makePolicy(QStringLiteral("system-1"), QStringLiteral("system"),
                   NetworkPolicy::Action::Throttle),
        makePolicy(QStringLiteral("unknown-1"), QString(), NetworkPolicy::Action::Allow),
        makePolicy(QStringLiteral("ai-1"), QStringLiteral("ai"),
                   NetworkPolicy::Action::Throttle),
        makePolicy(QStringLiteral("auto-2"), QStringLiteral("auto"),
                   NetworkPolicy::Action::Block)
    };

    const EmergencyRestorePlan plan = buildEmergencyRestorePlan(policies);
    check(plan.automatic.size() == 4, QStringLiteral("the plan removes the automatic policies"));
    check(plan.preserved.size() == 2, QStringLiteral("the plan preserves user and unknown origin"));
    checkEqual(plan.automatic.at(0).id, QStringLiteral("auto-1"),
               QStringLiteral("plan removal keeps the stored order"));
    checkEqual(plan.automatic.at(2).id, QStringLiteral("ai-1"),
               QStringLiteral("plan removal keeps its order across automatic sources"));
    checkEqual(plan.automatic.at(3).id, QStringLiteral("auto-2"),
               QStringLiteral("plan removal covers every automatic source"));
    checkEqual(plan.preserved.at(0).id, QStringLiteral("user-1"),
               QStringLiteral("plan preservation keeps the stored order"));
    checkEqual(plan.preserved.at(1).id, QStringLiteral("unknown-1"),
               QStringLiteral("a policy without a source is preserved"));

    const EmergencyRestorePlan empty = buildEmergencyRestorePlan({});
    check(empty.automatic.isEmpty() && empty.preserved.isEmpty(),
          QStringLiteral("an empty store produces an empty plan"));
}

void testEmergencyRestoreReport()
{
    EmergencyRestorePlan plan;
    plan.automatic << makePolicy(QStringLiteral("auto-1"), QStringLiteral("automatic"),
                                 NetworkPolicy::Action::Throttle);
    plan.automatic << makePolicy(QStringLiteral("auto-2"), QStringLiteral("system"),
                                 NetworkPolicy::Action::Block);
    plan.preserved << makePolicy(QStringLiteral("user-1"), QStringLiteral("user"),
                                 NetworkPolicy::Action::Block);
    plan.preserved << makePolicy(QStringLiteral("unknown-1"), QStringLiteral("mystery"),
                                 NetworkPolicy::Action::Allow);

    const EmergencyRestoreReport report =
        applyEmergencyRestorePlan(plan, true, QStringLiteral("worker asked"));

    checkEqual(report.removed, 2, QStringLiteral("report counts removed policies"));
    checkEqual(report.preserved, 2, QStringLiteral("report counts preserved policies"));
    checkEqual(report.failed, 0, QStringLiteral("a successful write reports no failure"));
    check(report.ok(), QStringLiteral("the report is ok when nothing failed"));
    check(report.throttleRestoreRequested, QStringLiteral("report records the throttle request"));
    checkEqual(report.removedIds, QStringList{QStringLiteral("auto-1"), QStringLiteral("auto-2")},
               QStringLiteral("report lists the removed policy ids"));
    checkEqual(report.preservedIds,
               QStringList{QStringLiteral("user-1"), QStringLiteral("unknown-1")},
               QStringLiteral("report lists the preserved policy ids"));
    check(report.entries.size() == 5,
          QStringLiteral("report has one entry per policy plus the throttle channel"));

    checkEqual(report.entries.at(0).channel, QStringLiteral("policy store"),
               QStringLiteral("policy actions name the store channel"));
    checkEqual(report.entries.at(0).outcome, QStringLiteral("removed"),
               QStringLiteral("an automatic policy is reported as removed"));
    check(report.entries.at(0).message.contains(QStringLiteral("automatic enforcement")),
          QStringLiteral("a removal says why it was allowed"));
    checkEqual(report.entries.at(2).outcome, QStringLiteral("preserved"),
               QStringLiteral("a user policy is reported as preserved"));
    checkEqual(report.entries.at(2).message, QStringLiteral("Kept: created by the user"),
               QStringLiteral("a user policy says who created it"));
    checkEqual(report.entries.at(3).message,
               QStringLiteral("Kept: origin not recorded, so it was not removed"),
               QStringLiteral("an unknown origin says why it was kept"));

    const EmergencyRestoreEntry &throttle = report.entries.last();
    checkEqual(throttle.channel, QStringLiteral("throttle"),
               QStringLiteral("the last entry covers the throttle channel"));
    checkEqual(throttle.outcome, QStringLiteral("requested"),
               QStringLiteral("an attached throttle worker reports a request, not a result"));
    checkEqual(throttle.message, QStringLiteral("worker asked"),
               QStringLiteral("the throttle message is passed through"));

    const QString summary = report.summary();
    check(summary.contains(QStringLiteral("Removed 2 automatic policies")),
          QStringLiteral("summary counts the removals"));
    check(summary.contains(QStringLiteral("kept 2 policies")),
          QStringLiteral("summary counts the preserved policies"));
    check(summary.contains(QStringLiteral("bandwidth limits being restored")),
          QStringLiteral("summary mentions the throttle restore"));

    const QStringList lines = report.lines();
    check(lines.size() == 5, QStringLiteral("the dialog gets one line per entry"));
    check(lines.at(0).contains(QStringLiteral("C:/Apps/auto-1.exe")),
          QStringLiteral("a line names the policy target"));
    check(lines.last().contains(QStringLiteral("throttle")),
          QStringLiteral("the throttle line names its channel"));

    // Wording and the throttle-skipped path.
    EmergencyRestorePlan single;
    single.automatic << makePolicy(QStringLiteral("auto-1"), QStringLiteral("automatic"),
                                   NetworkPolicy::Action::Block);
    const EmergencyRestoreReport one =
        applyEmergencyRestorePlan(single, false, QStringLiteral("no limits"));
    checkEqual(one.summary(),
               QStringLiteral("Removed 1 automatic policy; no bandwidth limits to restore"),
               QStringLiteral("summary uses the singular and reports a skipped throttle"));
    checkEqual(one.entries.last().outcome, QStringLiteral("skipped"),
               QStringLiteral("an unattached throttle channel is reported as skipped"));

    const EmergencyRestoreReport none =
        applyEmergencyRestorePlan(EmergencyRestorePlan{}, false, QStringLiteral("no limits"));
    checkEqual(none.summary(),
               QStringLiteral("No automatic policies to remove; no bandwidth limits to restore"),
               QStringLiteral("an empty store reports nothing to remove"));
    check(none.ok(), QStringLiteral("nothing to remove is not a failure"));
    check(none.entries.size() == 1,
          QStringLiteral("an empty plan still reports the throttle channel"));

    // A failed store write must be reported, not counted as removed.
    const EmergencyRestoreReport failed =
        applyEmergencyRestorePlan(plan, true, QStringLiteral("worker asked"), false);
    checkEqual(failed.removed, 0, QStringLiteral("a failed write removes nothing"));
    checkEqual(failed.failed, 2, QStringLiteral("a failed write reports one failure per policy"));
    checkEqual(failed.preserved, 2, QStringLiteral("a failed write does not lose the preserved count"));
    check(!failed.ok(), QStringLiteral("a failed write makes the report not ok"));
    check(failed.removedIds.isEmpty(), QStringLiteral("a failed write lists no removed id"));
    checkEqual(failed.entries.at(0).outcome, QStringLiteral("failed"),
               QStringLiteral("a failed store entry is reported as failed"));
    check(failed.entries.at(0).message.contains(QStringLiteral("store write failed")),
          QStringLiteral("the failure explains that the store write failed"));
    check(failed.summary().contains(QStringLiteral("2 failed")),
          QStringLiteral("summary counts the failures"));

    // A policy with no usable target still produces an attributable line.
    EmergencyRestorePlan noTarget;
    NetworkPolicy bare = makePolicy(QStringLiteral("bare-id"), QStringLiteral("automatic"),
                                    NetworkPolicy::Action::Block);
    bare.targetId.clear();
    noTarget.automatic << bare;
    check(applyEmergencyRestorePlan(noTarget, false, QString()).lines().first()
              .contains(QStringLiteral("bare-id")),
          QStringLiteral("a missing target falls back to the policy id"));
}

// ─── NG-026: what is left behind actually reloads ─────────────────────────
void testEmergencyRestoreStoreRoundTrip()
{
    QSettings().clear();

    QList<NetworkPolicy> policies;
    policies << makePolicy(QStringLiteral("auto-1"), QStringLiteral("automatic"),
                           NetworkPolicy::Action::Throttle);
    policies << makePolicy(QStringLiteral("user-1"), QStringLiteral("user"),
                           NetworkPolicy::Action::Block);
    policies << makePolicy(QStringLiteral("system-1"), QStringLiteral("system"),
                           NetworkPolicy::Action::Schedule);
    policies << makePolicy(QStringLiteral("unknown-1"), QString(),
                           NetworkPolicy::Action::Allow);
    policies[1].direction = NetworkDirection::Upload;
    policies[1].rateBitsPerSecond = 123456;
    policies[1].description = QStringLiteral("keep me");

    check(PolicyStore::savePolicies(policies),
          QStringLiteral("the seeded policy set is written"));
    check(PolicyStore::loadPolicies().size() == 4,
          QStringLiteral("the seeded policy set loads back"));

    const EmergencyRestorePlan plan = buildEmergencyRestorePlan(PolicyStore::loadPolicies());
    const EmergencyRestoreReport report =
        applyEmergencyRestorePlan(plan, true, QStringLiteral("worker asked"));
    check(report.ok(), QStringLiteral("restoring the stored set succeeds"));

    // This is the coordinator's store step: write back only the preserved set.
    check(PolicyStore::savePolicies(plan.preserved),
          QStringLiteral("the preserved set is written back"));

    const QList<NetworkPolicy> remaining = PolicyStore::loadPolicies();
    check(remaining.size() == 2,
          QStringLiteral("only the preserved policies survive the restore"));

    QStringList ids;
    for (const NetworkPolicy &policy : remaining) ids << policy.id;
    checkEqual(ids, QStringList{QStringLiteral("user-1"), QStringLiteral("unknown-1")},
               QStringLiteral("user and unknown-origin policies survive the restore"));

    for (const NetworkPolicy &policy : remaining) {
        if (policy.id != QStringLiteral("user-1")) continue;
        checkEqual(policy.source, QStringLiteral("user"),
                   QStringLiteral("the preserved policy keeps its source"));
        checkEqual(static_cast<int>(policy.direction), static_cast<int>(NetworkDirection::Upload),
                   QStringLiteral("the preserved policy keeps its direction"));
        checkEqual(policy.rateBitsPerSecond, static_cast<quint64>(123456),
                   QStringLiteral("the preserved policy keeps its rate"));
        checkEqual(policy.description, QStringLiteral("keep me"),
                   QStringLiteral("the preserved policy keeps its description"));
        check(policy.action == NetworkPolicy::Action::Block,
              QStringLiteral("the preserved policy keeps its action"));
    }

    check(PolicyStore::savePolicies({}), QStringLiteral("clearing the store succeeds"));
    check(PolicyStore::loadPolicies().isEmpty(),
          QStringLiteral("a cleared store loads no policies"));
    QSettings().clear();
}

// ─── NG-024: attribution and reconciliation planning ───────────────────────
QString normPath(const QString &path)
{
    return QDir::cleanPath(QDir::toNativeSeparators(path)).toLower();
}

FirewallObservation observedRule(const QString &name, const QString &path, bool block,
                                 bool inbound, const QString &policyId,
                                 bool enabled = true)
{
    FirewallObservation rule;
    rule.name = name;
    rule.path = path;
    rule.block = block;
    rule.inbound = inbound;
    rule.enabled = enabled;
    rule.policyId = policyId;
    return rule;
}

int actionCount(const ReconciliationReport &report, ReconciliationAction::Kind kind)
{
    int count = 0;
    for (const ReconciliationAction &action : report.actions) {
        if (action.kind == kind) ++count;
    }
    return count;
}

const ReconciliationAction *firstAction(const ReconciliationReport &report,
                                        ReconciliationAction::Kind kind)
{
    for (const ReconciliationAction &action : report.actions) {
        if (action.kind == kind) return &action;
    }
    return nullptr;
}

void testReconciledPolicyId()
{
    const QString id = QStringLiteral("policy-42");
    checkEqual(reconciledPolicyId(QStringLiteral("NetGuard policy %1").arg(id)), id,
               QStringLiteral("a rule description written by a policy yields its id"));
    checkEqual(reconciledPolicyId(QStringLiteral("  netguard POLICY   policy-42  ")), id,
               QStringLiteral("attribution ignores case and padding"));
    checkEqual(reconciledPolicyId(QStringLiteral("NetGuard policy")), QString(),
               QStringLiteral("a description without an id yields nothing"));
    checkEqual(reconciledPolicyId(QString()), QString(),
               QStringLiteral("an empty description is not attributed"));
    checkEqual(reconciledPolicyId(QStringLiteral("Ultimate NetGuard AIO")), QString(),
               QStringLiteral("a rule from the Firewall tab is not attributed"));
}

void testReconciliationFirewall()
{
    const QDateTime now(QDate(2026, 11, 9), QTime(12, 0));
    const QHash<QString, QStringList> noGroups;
    const QString blockedPath = QStringLiteral("C:/Apps/Blocked.exe");

    NetworkPolicy block = makePolicy(QStringLiteral("p-block"), QStringLiteral("user"),
                                     NetworkPolicy::Action::Block);
    block.targetId = blockedPath;

    ReconciliationReport report =
        planPolicyReconciliation({block}, noGroups, PolicyObservation(), now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 1,
               QStringLiteral("an active block policy with no rules creates them"));
    const ReconciliationAction *create =
        firstAction(report, ReconciliationAction::Kind::CreateFirewallRule);
    if (create) {
        checkEqual(create->path, blockedPath,
                   QStringLiteral("the repaired rule uses the policy's target"));
        check(create->block, QStringLiteral("a block policy repairs a block rule"));
        checkEqual(create->policyId, QStringLiteral("p-block"),
                   QStringLiteral("the repaired rule carries the policy id"));
    }

    // Both directions, attributed to this policy: nothing to do.
    PolicyObservation covered;
    covered.firewallRules << observedRule(QStringLiteral("NetGuard_Blocked_BLOCK_OUT"),
                                          blockedPath, true, false, QStringLiteral("p-block"))
                          << observedRule(QStringLiteral("NetGuard_Blocked_BLOCK_IN"),
                                          blockedPath, true, true, QStringLiteral("p-block"));
    report = planPolicyReconciliation({block}, noGroups, covered, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 0,
               QStringLiteral("attributed rules in both directions cover the policy"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveFirewallRule), 0,
               QStringLiteral("covering rules are not removed"));
    checkEqual(report.summary(),
               QStringLiteral("All stored policies match the enforced state."),
               QStringLiteral("a covered policy produces a clean report"));

    // A rule made from the Firewall tab is adopted rather than duplicated.
    PolicyObservation userRules;
    userRules.firewallRules << observedRule(QStringLiteral("NetGuard_Blocked_BLOCK_OUT"),
                                            blockedPath, true, false, QString())
                            << observedRule(QStringLiteral("NetGuard_Blocked_BLOCK_IN"),
                                            blockedPath, true, true, QString());
    report = planPolicyReconciliation({block}, noGroups, userRules, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 1,
               QStringLiteral("an unattributed rule is rewritten with the policy id"));
    checkEqual(report.unattributed, 0,
               QStringLiteral("a rule that a policy adopts is not counted as left in place"));

    // One direction disabled is as good as missing.
    PolicyObservation half;
    half.firewallRules << observedRule(QStringLiteral("NetGuard_Blocked_BLOCK_OUT"),
                                       blockedPath, true, false, QStringLiteral("p-block"))
                       << observedRule(QStringLiteral("NetGuard_Blocked_BLOCK_IN"),
                                       blockedPath, true, true, QStringLiteral("p-block"), false);
    report = planPolicyReconciliation({block}, noGroups, half, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 1,
               QStringLiteral("a disabled rule does not cover the policy"));
    create = firstAction(report, ReconciliationAction::Kind::CreateFirewallRule);
    if (create) {
        check(create->message.contains(QStringLiteral("inbound")),
              QStringLiteral("the report names the missing direction"));
    }

    // Attributed rules whose policy is gone are removed; the current policy is
    // still repaired, and unrelated user rules are left alone.
    NetworkPolicy other = makePolicy(QStringLiteral("p-other"), QStringLiteral("user"),
                                     NetworkPolicy::Action::Block);
    other.targetId = QStringLiteral("C:/Apps/Other.exe");
    PolicyObservation stale;
    stale.firewallRules << observedRule(QStringLiteral("NetGuard_Gone_BLOCK_OUT"),
                                        QStringLiteral("C:/Apps/Gone.exe"), true, false,
                                        QStringLiteral("p-gone"))
                        << observedRule(QStringLiteral("NetGuard_Gone_BLOCK_IN"),
                                        QStringLiteral("C:/Apps/Gone.exe"), true, true,
                                        QStringLiteral("p-gone"))
                        << observedRule(QStringLiteral("NetGuard_Custom_BLOCK_OUT"),
                                        QStringLiteral("C:/Apps/Custom.exe"), true, false,
                                        QString());
    report = planPolicyReconciliation({other}, noGroups, stale, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveFirewallRule), 2,
               QStringLiteral("both directions of a stale attributed rule are removed"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 1,
               QStringLiteral("the current policy is still repaired"));
    checkEqual(report.unattributed, 1,
               QStringLiteral("an unrelated user rule is left in place and reported"));
    check(report.actions.last().kind == ReconciliationAction::Kind::Report,
          QStringLiteral("the plan ends with the left-in-place summary"));
    checkEqual(report.summary(), QStringLiteral("0 repaired, 0 removed, 1 left in place"),
               QStringLiteral("left-in-place controls appear in the summary"));

    // Changing the action withdraws the old rules and creates the new ones.
    NetworkPolicy allow = makePolicy(QStringLiteral("p-same"), QStringLiteral("user"),
                                     NetworkPolicy::Action::Allow);
    allow.targetId = QStringLiteral("C:/Apps/Same.exe");
    PolicyObservation wasBlocked;
    wasBlocked.firewallRules << observedRule(QStringLiteral("NetGuard_Same_BLOCK_OUT"),
                                             allow.targetId, true, false, QStringLiteral("p-same"))
                             << observedRule(QStringLiteral("NetGuard_Same_BLOCK_IN"),
                                             allow.targetId, true, true, QStringLiteral("p-same"));
    report = planPolicyReconciliation({allow}, noGroups, wasBlocked, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 1,
               QStringLiteral("switching to allow creates an allow rule"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveFirewallRule), 2,
               QStringLiteral("switching to allow removes both block rules"));
    create = firstAction(report, ReconciliationAction::Kind::CreateFirewallRule);
    check(!create || !create->block,
          QStringLiteral("the created rule matches the new action"));

    // Disabled and expired policies want nothing; their rules are withdrawn.
    NetworkPolicy disabled = block;
    disabled.enabled = false;
    report = planPolicyReconciliation({disabled}, noGroups, covered, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 0,
               QStringLiteral("a disabled policy creates no rules"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveFirewallRule), 2,
               QStringLiteral("disabling a policy withdraws its attributed rules"));

    NetworkPolicy expired = block;
    expired.expiration = now.addSecs(-60);
    report = planPolicyReconciliation({expired}, noGroups, covered, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 0,
               QStringLiteral("an expired policy creates no rules"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveFirewallRule), 2,
               QStringLiteral("expiring a policy withdraws its attributed rules"));

    // Two policies wanting the same action agree; the first keeps ownership.
    NetworkPolicy second = block;
    second.id = QStringLiteral("p-block-2");
    report = planPolicyReconciliation({block, second}, noGroups, PolicyObservation(), now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 1,
               QStringLiteral("policies that agree need only one rule"));
    create = firstAction(report, ReconciliationAction::Kind::CreateFirewallRule);
    checkEqual(create ? create->policyId : QString(), QStringLiteral("p-block"),
               QStringLiteral("the first policy keeps ownership"));

    // Two policies disagreeing about the same target are not guessed at.
    NetworkPolicy opposite = block;
    opposite.id = QStringLiteral("p-opposite");
    opposite.action = NetworkPolicy::Action::Allow;
    report = planPolicyReconciliation({block, opposite}, noGroups, PolicyObservation(), now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 0,
               QStringLiteral("a conflict creates no rule"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveFirewallRule), 0,
               QStringLiteral("a conflict removes no rule"));
    checkEqual(report.unresolved, 1, QStringLiteral("a conflict is reported as unresolved"));

    // Group scope expands to the cached running members.
    NetworkPolicy group = makePolicy(QStringLiteral("p-group"), QStringLiteral("user"),
                                     NetworkPolicy::Action::Block);
    group.scope = QStringLiteral("group");
    group.targetId = QStringLiteral("group-1");
    QHash<QString, QStringList> groups;
    groups.insert(QStringLiteral("group-1"), QStringList{blockedPath});
    report = planPolicyReconciliation({group}, groups, PolicyObservation(), now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 1,
               QStringLiteral("a group policy repairs each running member"));
    create = firstAction(report, ReconciliationAction::Kind::CreateFirewallRule);
    checkEqual(create ? create->path : QString(), blockedPath,
               QStringLiteral("the group member path is used, not the group id"));

    report = planPolicyReconciliation({group}, noGroups, PolicyObservation(), now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 0,
               QStringLiteral("a group with no running members changes nothing"));
    checkEqual(static_cast<int>(report.actions.size()), 1,
               QStringLiteral("a group with no running members is explained"));
    check(report.actions.first().message.contains(QStringLiteral("no running members")),
          QStringLiteral("the group note names the reason"));

    // Scopes this build cannot resolve are reported, never guessed at.
    NetworkPolicy publisher = makePolicy(QStringLiteral("p-pub"), QStringLiteral("user"),
                                         NetworkPolicy::Action::Block);
    publisher.scope = QStringLiteral("publisher");
    publisher.targetId = QStringLiteral("Google LLC");
    report = planPolicyReconciliation({publisher}, noGroups, PolicyObservation(), now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::CreateFirewallRule), 0,
               QStringLiteral("an unresolved scope creates no rule"));
    checkEqual(report.unresolved, 1, QStringLiteral("an unresolved scope is counted"));

    // The rendered report mentions the created rule.
    report = planPolicyReconciliation({block}, noGroups, PolicyObservation(), now);
    checkEqual(static_cast<int>(report.lines().size()), 1,
               QStringLiteral("one line per action"));
    check(!report.lines().isEmpty() &&
              report.lines().first().contains(QStringLiteral("created block")),
          QStringLiteral("the rendered line describes the created block rule"));
}

void testReconciliationThrottle()
{
    const QDateTime now(QDate(2026, 11, 9), QTime(12, 0));
    const QHash<QString, QStringList> noGroups;

    NetworkPolicy throttle = makePolicy(QStringLiteral("p-throttle"), QStringLiteral("user"),
                                        NetworkPolicy::Action::Throttle);
    throttle.direction = NetworkDirection::Both;
    throttle.rateBitsPerSecond = 1000000;

    ReconciliationReport report =
        planPolicyReconciliation({throttle}, noGroups, PolicyObservation(), now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::ApplyThrottle), 1,
               QStringLiteral("an active throttle policy requests a limit"));
    const ReconciliationAction *apply =
        firstAction(report, ReconciliationAction::Kind::ApplyThrottle);
    if (apply) {
        checkEqual(apply->path, throttle.targetId,
                   QStringLiteral("the limit uses the policy's target"));
        checkEqual(apply->policyId, QStringLiteral("p-throttle"),
                   QStringLiteral("the request carries the policy id"));
        check(!apply->automatic,
              QStringLiteral("a user policy's limit is not marked automatic"));
    }

    const QString key = normPath(throttle.targetId);

    PolicyObservation limited;
    limited.throttledPaths.insert(key);
    limited.downloadLimits.insert(key, 1000000);
    report = planPolicyReconciliation({throttle}, noGroups, limited, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::ApplyThrottle), 0,
               QStringLiteral("an existing upload and download limit covers the policy"));

    PolicyObservation throttledOnly;
    throttledOnly.throttledPaths.insert(key);
    report = planPolicyReconciliation({throttle}, noGroups, throttledOnly, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::ApplyThrottle), 1,
               QStringLiteral("a missing download limit is requested again"));
    apply = firstAction(report, ReconciliationAction::Kind::ApplyThrottle);
    check(apply && apply->message.contains(QStringLiteral("download")),
          QStringLiteral("the request names the missing download limit"));

    NetworkPolicy upload = throttle;
    upload.direction = NetworkDirection::Upload;
    report = planPolicyReconciliation({upload}, noGroups, throttledOnly, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::ApplyThrottle), 0,
               QStringLiteral("an upload-only policy needs no download limit"));

    NetworkPolicy automatic = makePolicy(QStringLiteral("p-auto"),
                                         QStringLiteral("automatic"),
                                         NetworkPolicy::Action::Throttle);
    automatic.direction = NetworkDirection::Both;
    report = planPolicyReconciliation({automatic}, noGroups, PolicyObservation(), now);
    apply = firstAction(report, ReconciliationAction::Kind::ApplyThrottle);
    check(apply && apply->automatic,
          QStringLiteral("an automatically created policy's limit may be withdrawn later"));

    const QString automaticKey = normPath(automatic.targetId);

    // A limit the product applied for a policy that is gone is withdrawn.
    PolicyObservation staleAuto;
    staleAuto.throttledPaths.insert(automaticKey);
    staleAuto.autoAppliedPaths.insert(automaticKey);
    report = planPolicyReconciliation({}, noGroups, staleAuto, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveThrottle), 1,
               QStringLiteral("a stale automatic limit is removed"));
    checkEqual(report.unattributed, 0,
               QStringLiteral("an automatic limit is attributed to the product"));

    // A limit attributed to a policy that no longer exists is withdrawn.
    PolicyObservation attributedGone;
    attributedGone.throttledPaths.insert(key);
    attributedGone.throttlePolicyIds.insert(key, QStringLiteral("p-gone"));
    report = planPolicyReconciliation({}, noGroups, attributedGone, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveThrottle), 1,
               QStringLiteral("a limit attributed to a deleted policy is removed"));
    checkEqual(report.unattributed, 0,
               QStringLiteral("an attributed limit is not counted as left in place"));
    const ReconciliationAction *removed =
        firstAction(report, ReconciliationAction::Kind::RemoveThrottle);
    checkEqual(removed ? removed->policyId : QString(), QStringLiteral("p-gone"),
               QStringLiteral("the removal reports the owning policy"));
    check(removed && removed->message.contains(QStringLiteral("no longer active")),
          QStringLiteral("the removal explains why the limit goes"));

    // A policy that still exists but is disabled no longer wants its limit.
    NetworkPolicy paused = throttle;
    paused.enabled = false;
    PolicyObservation attributedPaused;
    attributedPaused.throttledPaths.insert(key);
    attributedPaused.throttlePolicyIds.insert(key, QStringLiteral("p-throttle"));
    report = planPolicyReconciliation({paused}, noGroups, attributedPaused, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::ApplyThrottle), 0,
               QStringLiteral("a disabled throttle policy does not request a limit"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveThrottle), 1,
               QStringLiteral("disabling a throttle policy withdraws its limit"));

    // A still-wanted path keeps its limit; only its owner is handed over.
    PolicyObservation otherOwner;
    otherOwner.throttledPaths.insert(key);
    otherOwner.downloadLimits.insert(key, 1000000);
    otherOwner.throttlePolicyIds.insert(key, QStringLiteral("p-old-owner"));
    report = planPolicyReconciliation({throttle}, noGroups, otherOwner, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveThrottle), 0,
               QStringLiteral("a still-wanted path keeps its limit"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::ApplyThrottle), 0,
               QStringLiteral("a still-wanted path is not re-applied"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::ReassignThrottle), 1,
               QStringLiteral("a limit owned by an older policy is handed over"));
    const ReconciliationAction *reassign =
        firstAction(report, ReconciliationAction::Kind::ReassignThrottle);
    checkEqual(reassign ? reassign->policyId : QString(), QStringLiteral("p-throttle"),
               QStringLiteral("the new owner is the active policy"));
    check(reassign && !reassign->automatic,
          QStringLiteral("a user policy takes over without becoming automatic"));

    PolicyObservation sameOwner;
    sameOwner.throttledPaths.insert(key);
    sameOwner.downloadLimits.insert(key, 1000000);
    sameOwner.throttlePolicyIds.insert(key, QStringLiteral("p-throttle"));
    report = planPolicyReconciliation({throttle}, noGroups, sameOwner, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::ReassignThrottle), 0,
               QStringLiteral("a limit already owned by the active policy is left alone"));

    // A limit with no owner stays manual; a policy does not quietly adopt it.
    PolicyObservation manualLimit;
    manualLimit.throttledPaths.insert(key);
    manualLimit.downloadLimits.insert(key, 1000000);
    report = planPolicyReconciliation({throttle}, noGroups, manualLimit, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::ReassignThrottle), 0,
               QStringLiteral("a manual limit is not adopted by a policy"));
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveThrottle), 0,
               QStringLiteral("a manual limit is not removed by the planner"));

    // An automatic policy taking over marks the limit as automatic.
    PolicyObservation automaticOwner;
    automaticOwner.throttledPaths.insert(automaticKey);
    automaticOwner.downloadLimits.insert(automaticKey, 1000000);
    automaticOwner.throttlePolicyIds.insert(automaticKey, QStringLiteral("p-old-owner"));
    report = planPolicyReconciliation({automatic}, noGroups, automaticOwner, now);
    reassign = firstAction(report, ReconciliationAction::Kind::ReassignThrottle);
    check(reassign && reassign->automatic,
          QStringLiteral("an automatic policy takes over the limit as automatic"));

    // A limit that cannot be attributed is reported, not removed.
    PolicyObservation unattributedLimit;
    unattributedLimit.throttledPaths.insert(key);
    report = planPolicyReconciliation({}, noGroups, unattributedLimit, now);
    checkEqual(actionCount(report, ReconciliationAction::Kind::RemoveThrottle), 0,
               QStringLiteral("an unattributed limit is not removed"));
    checkEqual(report.unattributed, 1,
               QStringLiteral("an unattributed limit is counted as left in place"));
    checkEqual(report.summary(), QStringLiteral("0 repaired, 0 removed, 1 left in place"),
               QStringLiteral("the unattributed limit appears in the summary"));
}

// ─── Firewall rule names are unique per executable path ────────────────────
void testFirewallRuleNames()
{
    const QString installed = QStringLiteral("C:/Program Files/App/app.exe");
    const QString portable = QStringLiteral("D:/Portable/App/app.exe");

    // The old naming collided; the new naming must not.
    checkEqual(legacyFirewallRuleName(installed, QStringLiteral("BLOCK_OUT")),
               legacyFirewallRuleName(portable, QStringLiteral("BLOCK_OUT")),
               QStringLiteral("the legacy name only used the base name"));
    checkEqual(legacyFirewallRuleName(installed, QStringLiteral("BLOCK_OUT")),
               QStringLiteral("NetGuard_app_BLOCK_OUT"),
               QStringLiteral("the legacy format is still recognised"));

    const QString installedName = firewallRuleName(installed, QStringLiteral("BLOCK_OUT"));
    const QString portableName = firewallRuleName(portable, QStringLiteral("BLOCK_OUT"));
    check(installedName != portableName,
          QStringLiteral("same base name in different folders gets distinct rule names"));
    check(installedName.startsWith(QStringLiteral("NetGuard_app_")),
          QStringLiteral("the rule name keeps the executable base name readable"));
    check(installedName.endsWith(QStringLiteral("_BLOCK_OUT")),
          QStringLiteral("the rule name keeps its action/direction suffix"));
    checkEqual(firewallRuleName(installed, QStringLiteral("BLOCK_OUT")), installedName,
               QStringLiteral("the same path always yields the same rule name"));
    checkEqual(firewallRuleName(QStringLiteral("C:\\Program Files\\App\\APP.EXE"),
                                QStringLiteral("BLOCK_OUT")),
               installedName,
               QStringLiteral("case and separator style do not change the rule name"));
    checkEqual(firewallRuleName(QStringLiteral("C:/Program Files/App/./app.exe"),
                                QStringLiteral("BLOCK_OUT")),
               installedName,
               QStringLiteral("redundant path segments do not change the rule name"));
    check(firewallRuleName(installed, QStringLiteral("BLOCK_IN")) != installedName,
          QStringLiteral("the inbound and outbound rules have distinct names"));
    check(firewallRuleName(installed, QStringLiteral("ALLOW_OUT")) != installedName,
          QStringLiteral("the block and allow rules have distinct names"));

    const QString longPath = QStringLiteral("C:/") + QString(100, QLatin1Char('x')) +
                             QStringLiteral("/tool.exe");
    check(firewallRuleName(longPath, QStringLiteral("BLOCK_OUT")).size() < 100,
          QStringLiteral("a long folder name still fits the firewall name limit"));

    const QString longBase = QStringLiteral("C:/Tools/") + QString(200, QLatin1Char('n')) +
                             QStringLiteral(".exe");
    const QString longBaseName = firewallRuleName(longBase, QStringLiteral("BLOCK_OUT"));
    check(longBaseName.size() < 100,
          QStringLiteral("a very long executable name is shortened"));
    check(longBaseName != firewallRuleName(QStringLiteral("C:/Other/") +
                                               QString(200, QLatin1Char('n')) +
                                               QStringLiteral(".exe"),
                                           QStringLiteral("BLOCK_OUT")),
          QStringLiteral("shortening the base name keeps distinct paths distinct"));
}

void testDnsObserverParse()
{
    auto u16 = [](QByteArray &out, quint16 value) {
        out.append(static_cast<char>((value >> 8) & 0xFF));
        out.append(static_cast<char>(value & 0xFF));
    };
    auto u32 = [](QByteArray &out, quint32 value) {
        out.append(static_cast<char>((value >> 24) & 0xFF));
        out.append(static_cast<char>((value >> 16) & 0xFF));
        out.append(static_cast<char>((value >> 8) & 0xFF));
        out.append(static_cast<char>(value & 0xFF));
    };
    auto encodedName = [](const QString &name) {
        QByteArray out;
        const QStringList labels = name.split(QLatin1Char('.'));
        for (const QString &label : labels) {
            if (label.isEmpty()) continue;
            out.append(static_cast<char>(label.size()));
            out.append(label.toLatin1());
        }
        out.append('\0');
        return out;
    };
    auto header = [&](quint16 id, quint16 flags, quint16 questions, quint16 answers) {
        QByteArray out;
        u16(out, id);
        u16(out, flags);
        u16(out, questions);
        u16(out, answers);
        u16(out, 0);
        u16(out, 0);
        return out;
    };
    auto question = [&](const QString &name, quint16 type) {
        QByteArray out = encodedName(name);
        u16(out, type);
        u16(out, 1);
        return out;
    };

    // A visible query: lower-cased name, type, no addresses yet.
    QByteArray query = header(0x1234, 0x0100, 1, 0);
    query += question(QStringLiteral("Ads.Example.COM"), 1);
    const QList<DnsEvent> queries = DnsObserver::parseMessage(
        reinterpret_cast<const uint8_t *>(query.constData()), query.size());
    checkEqual(static_cast<int>(queries.size()), 1,
               QStringLiteral("DNS query produces one event"));
    if (queries.size() == 1) {
        const DnsEvent &event = queries.first();
        checkEqual(event.name, QStringLiteral("ads.example.com"),
                   QStringLiteral("DNS names are lower-cased without the root dot"));
        checkEqual(event.recordTypeName, QStringLiteral("A"),
                   QStringLiteral("the query record type is reported"));
        check(!event.response, QStringLiteral("a query is not marked as a response"));
        check(event.addresses.isEmpty(), QStringLiteral("a query carries no addresses"));
        check(event.confidence == ApplicationIdentity::Confidence::Unknown,
              QStringLiteral("a bare query has unknown attribution confidence"));
        checkEqual(event.transactionId, QStringLiteral("1234"),
                   QStringLiteral("the DNS transaction id is retained"));
    }

    // A response with a compressed owner name, a CNAME, one A, and one AAAA.
    QByteArray response = header(0xbeef, 0x8180, 1, 3);
    response += question(QStringLiteral("ads.example.com"), 1);
    response.append(static_cast<char>(0xC0));
    response.append(static_cast<char>(0x0C)); // owner: pointer to offset 12
    u16(response, 5);
    u16(response, 1);
    u32(response, 300);
    const QByteArray alias = encodedName(QStringLiteral("edge.example.net"));
    u16(response, static_cast<quint16>(alias.size()));
    response += alias;
    response.append(static_cast<char>(0xC0));
    response.append(static_cast<char>(0x0C));
    u16(response, 1);
    u16(response, 1);
    u32(response, 60);
    u16(response, 4);
    response += QByteArray::fromHex("5db8d822"); // 93.184.216.34
    response.append(static_cast<char>(0xC0));
    response.append(static_cast<char>(0x0C));
    u16(response, 28);
    u16(response, 1);
    u32(response, 120);
    u16(response, 16);
    response += QByteArray::fromHex("26062800022000010248189325c81946");

    const QList<DnsEvent> answers = DnsObserver::parseMessage(
        reinterpret_cast<const uint8_t *>(response.constData()), response.size());
    checkEqual(static_cast<int>(answers.size()), 1,
               QStringLiteral("DNS response produces one event"));
    if (answers.size() == 1) {
        const DnsEvent &event = answers.first();
        check(event.response, QStringLiteral("the response flag is reported"));
        checkEqual(event.name, QStringLiteral("ads.example.com"),
                   QStringLiteral("the question name is used for the response"));
        checkEqual(event.recordTypeName, QStringLiteral("A"),
                   QStringLiteral("the response record type follows the question"));
        check(event.addresses.contains(QStringLiteral("93.184.216.34")),
              QStringLiteral("an A answer is exposed as an address"));
        check(event.addresses.contains(
                  QStringLiteral("2606:2800:0220:0001:0248:1893:25c8:1946")),
              QStringLiteral("an AAAA answer is exposed as an address"));
        checkEqual(event.aliases, QStringList{QStringLiteral("edge.example.net")},
                   QStringLiteral("a CNAME target is reported"));
        checkEqual(event.ttlSeconds, quint32(60),
                   QStringLiteral("the event carries the smallest answer TTL"));
        checkEqual(event.transactionId, QStringLiteral("beef"),
                   QStringLiteral("a response keeps its transaction id"));
        check(event.confidence == ApplicationIdentity::Confidence::StrongInference,
              QStringLiteral("an answered name is a strong inference"));
    }

    // An AAAA question names its type, and an unknown type stays printable.
    QByteArray aaaaQuery = header(1, 0x0100, 1, 0);
    aaaaQuery += question(QStringLiteral("v6.example"), 28);
    const QList<DnsEvent> aaaa = DnsObserver::parseMessage(
        reinterpret_cast<const uint8_t *>(aaaaQuery.constData()), aaaaQuery.size());
    check(aaaa.size() == 1 && aaaa.first().recordTypeName == QStringLiteral("AAAA"),
          QStringLiteral("an AAAA question reports its record type"));
    checkEqual(DnsObserver::recordTypeName(99), QStringLiteral("TYPE99"),
               QStringLiteral("an unknown record type stays printable"));

    // Malformed messages are ignored instead of trusted or crashed on.
    auto parseEmpty = [](const QByteArray &message) {
        return DnsObserver::parseMessage(
                   reinterpret_cast<const uint8_t *>(message.constData()), message.size())
            .isEmpty();
    };
    check(parseEmpty(QByteArray(11, '\0')), QStringLiteral("a truncated header is ignored"));
    check(parseEmpty(header(1, 0x0100, 1, 0)),
          QStringLiteral("a missing question is ignored"));

    QByteArray longLabel = header(2, 0x0100, 1, 0);
    longLabel.append(static_cast<char>(64));
    longLabel += QByteArray(64, 'a');
    longLabel.append('\0');
    check(parseEmpty(longLabel), QStringLiteral("a label over 63 bytes is ignored"));

    QByteArray pointerLoop = header(3, 0x0100, 1, 0);
    pointerLoop.append(static_cast<char>(0xC0));
    pointerLoop.append(static_cast<char>(0x0C));
    pointerLoop.append('\0');
    u16(pointerLoop, 1);
    u16(pointerLoop, 1);
    check(parseEmpty(pointerLoop), QStringLiteral("a self-referencing name pointer is ignored"));

    QByteArray overrun = header(4, 0x8100, 1, 1);
    overrun += question(QStringLiteral("short.example"), 1);
    overrun.append(static_cast<char>(0xC0));
    overrun.append(static_cast<char>(0x0C));
    u16(overrun, 1);
    u16(overrun, 1);
    u32(overrun, 60);
    u16(overrun, 4);
    overrun += QByteArray(2, '\x7f');
    check(parseEmpty(overrun), QStringLiteral("an answer past the message end is ignored"));

    QByteArray otherOpcode = header(5, 0x0900, 1, 0);
    otherOpcode += question(QStringLiteral("example.com"), 1);
    check(parseEmpty(otherOpcode),
          QStringLiteral("a non-standard DNS opcode is ignored"));

    // Datagram framing: IP + UDP headers are skipped and a non-53 port is not DNS.
    QByteArray udp;
    u16(udp, 53);
    u16(udp, 49152);
    u16(udp, static_cast<quint16>(8 + query.size()));
    u16(udp, 0);
    udp += query;

    QByteArray ipv4(20, '\0');
    ipv4[0] = static_cast<char>(0x45);
    ipv4[9] = 17;
    ipv4 += udp;
    const QList<DnsEvent> framed = DnsObserver::parseDatagram(
        reinterpret_cast<const uint8_t *>(ipv4.constData()), ipv4.size());
    check(framed.size() == 1 && framed.first().name == QStringLiteral("ads.example.com"),
          QStringLiteral("an IPv4 UDP/53 datagram is parsed"));

    QByteArray otherPort = ipv4;
    otherPort[20] = static_cast<char>(0x01);
    otherPort[21] = static_cast<char>(0xBB); // source 443, destination 49152
    check(DnsObserver::parseDatagram(reinterpret_cast<const uint8_t *>(otherPort.constData()),
                                     otherPort.size()).isEmpty(),
          QStringLiteral("a UDP datagram that is not port 53 is not DNS"));

    QByteArray ipv6(40, '\0');
    ipv6[0] = static_cast<char>(0x60);
    ipv6[6] = 17;
    ipv6 += udp;
    check(DnsObserver::parseDatagram(reinterpret_cast<const uint8_t *>(ipv6.constData()),
                                     ipv6.size()).size() == 1,
          QStringLiteral("an IPv6 UDP/53 datagram is parsed"));
    check(DnsObserver::parseDatagram(nullptr, 0).isEmpty(),
          QStringLiteral("an empty datagram is ignored"));
}

void testDnsCorrelator()
{
    const QDateTime base = QDateTime::fromString(
        QStringLiteral("2026-01-01T00:00:00Z"), Qt::ISODate);
    check(base.isValid(), QStringLiteral("the correlator test clock is valid"));

    auto answer = [](const QString &name, const QString &address, quint32 ttl,
                     quint32 pid) {
        DnsEvent event;
        event.response = true;
        event.name = name;
        event.addresses = QStringList{address};
        event.ttlSeconds = ttl;
        event.pid = pid;
        if (pid != 0) {
            event.processName = QStringLiteral("browser.exe");
            event.identityId = QStringLiteral("sha256:browser");
        }
        event.confidence = ApplicationIdentity::Confidence::StrongInference;
        return event;
    };

    // A response creates a record with its owner and source, and the TTL bounds
    // how long a later connection may use it.
    DnsCorrelator correlator;
    correlator.observe(answer(QStringLiteral("example.com"),
                              QStringLiteral("93.184.216.34"), 60, 123),
                       base);
    const QList<DomainAttribution> fresh =
        correlator.lookup(QStringLiteral("93.184.216.34"), base.addSecs(59));
    checkEqual(static_cast<int>(fresh.size()), 1,
               QStringLiteral("a DNS answer is available before its TTL"));
    if (!fresh.isEmpty()) {
        const DomainAttribution &record = fresh.first();
        checkEqual(record.name, QStringLiteral("example.com"),
                   QStringLiteral("the answer name is stored"));
        checkEqual(record.pid, quint32(123),
                   QStringLiteral("the querying PID is stored"));
        checkEqual(record.identityId, QStringLiteral("sha256:browser"),
                   QStringLiteral("the querying identity is stored"));
        check(record.confidence == ApplicationIdentity::Confidence::StrongInference,
              QStringLiteral("the answer confidence is stored"));
        check(record.source == AttributionSource::DnsAnswer,
              QStringLiteral("the attribution source is a DNS answer"));
        checkEqual(attributionSourceName(record.source), QStringLiteral("DNS answer"),
                   QStringLiteral("the attribution source is printable"));
        checkEqual(record.firstSeen, base,
                   QStringLiteral("first seen is the observation time"));
        checkEqual(record.expiresAt, base.addSecs(60),
                   QStringLiteral("the record expires at the DNS TTL"));
    }
    check(correlator.lookup(QStringLiteral("93.184.216.34"), base.addSecs(60)).isEmpty(),
          QStringLiteral("an answer expires exactly at its TTL"));
    check(correlator.lookup(QStringLiteral("  93.184.216.34  "), base.addSecs(1)).size() == 1,
          QStringLiteral("address lookup ignores surrounding whitespace"));

    // Several names can share an address; the most recent is returned first and
    // a repeated name refreshes its lifetime without losing the first sighting.
    DnsCorrelator multi;
    multi.observe(answer(QStringLiteral("a.example"), QStringLiteral("203.0.113.7"),
                         100, 11), base);
    multi.observe(answer(QStringLiteral("b.example"), QStringLiteral("203.0.113.7"),
                         100, 11), base.addSecs(10));
    const QList<DomainAttribution> shared =
        multi.lookup(QStringLiteral("203.0.113.7"), base.addSecs(11));
    checkEqual(static_cast<int>(shared.size()), 2,
               QStringLiteral("one address keeps multiple names"));
    if (shared.size() == 2) {
        checkEqual(shared.at(0).name, QStringLiteral("b.example"),
                   QStringLiteral("the most recently seen name comes first"));
        checkEqual(shared.at(1).name, QStringLiteral("a.example"),
                   QStringLiteral("the older name is still available"));
    }
    multi.observe(answer(QStringLiteral("a.example"), QStringLiteral("203.0.113.7"),
                         300, 22), base.addSecs(20));
    const QList<DomainAttribution> refreshed =
        multi.lookup(QStringLiteral("203.0.113.7"), base.addSecs(21));
    checkEqual(static_cast<int>(refreshed.size()), 2,
               QStringLiteral("refreshing a name does not duplicate it"));
    if (!refreshed.isEmpty()) {
        const DomainAttribution &record = refreshed.first();
        checkEqual(record.name, QStringLiteral("a.example"),
                   QStringLiteral("a refreshed name becomes the most recent"));
        checkEqual(record.firstSeen, base,
                   QStringLiteral("refreshing keeps the first-seen time"));
        checkEqual(record.lastSeen, base.addSecs(20),
                   QStringLiteral("refreshing moves the last-seen time"));
        checkEqual(record.expiresAt, base.addSecs(320),
                   QStringLiteral("refreshing applies the new TTL"));
        checkEqual(record.pid, quint32(22),
                   QStringLiteral("refreshing replaces the owner PID"));
    }

    // An unresolved refresh must not erase the owner learned earlier.
    DnsCorrelator identity;
    identity.observe(answer(QStringLiteral("keep.example"), QStringLiteral("192.0.2.8"),
                            300, 77), base);
    identity.observe(answer(QStringLiteral("keep.example"), QStringLiteral("192.0.2.8"),
                            300, 0), base.addSecs(1));
    const QList<DomainAttribution> kept =
        identity.lookup(QStringLiteral("192.0.2.8"), base.addSecs(2));
    check(kept.size() == 1 && kept.first().pid == 77 &&
              kept.first().identityId == QStringLiteral("sha256:browser"),
          QStringLiteral("an unresolved refresh keeps the earlier identity"));

    // Queries and nameless events never create a mapping.
    DnsEvent query = answer(QStringLiteral("query.example"),
                            QStringLiteral("192.0.2.9"), 300, 5);
    query.response = false;
    identity.observe(query, base);
    check(identity.lookup(QStringLiteral("192.0.2.9"), base).isEmpty(),
          QStringLiteral("a DNS query does not create a destination mapping"));
    identity.observe(answer(QString(), QStringLiteral("192.0.2.10"), 300, 5), base);
    check(identity.lookup(QStringLiteral("192.0.2.10"), base).isEmpty(),
          QStringLiteral("an answer without a name is ignored"));

    // Per-address names and per-store addresses are capped, evicting the least
    // recently seen entries first.
    DnsCorrelator names(3600, 300, 16);
    for (int i = 0; i < 10; ++i) {
        names.observe(answer(QStringLiteral("n%1.example").arg(i),
                             QStringLiteral("198.51.100.9"), 300, 1),
                      base.addSecs(i));
    }
    const QList<DomainAttribution> capped =
        names.lookup(QStringLiteral("198.51.100.9"), base.addSecs(10));
    checkEqual(static_cast<int>(capped.size()), 8,
               QStringLiteral("an address keeps at most eight names"));
    if (capped.size() == 8) {
        checkEqual(capped.first().name, QStringLiteral("n9.example"),
                   QStringLiteral("the newest name survives the name cap"));
        check(capped.first().name != QStringLiteral("n0.example"),
              QStringLiteral("the oldest name is evicted first"));
    }

    DnsCorrelator addresses(3600, 300, 2);
    addresses.observe(answer(QStringLiteral("one.example"), QStringLiteral("192.0.2.1"),
                             300, 1), base);
    addresses.observe(answer(QStringLiteral("two.example"), QStringLiteral("192.0.2.2"),
                             300, 1), base.addSecs(1));
    addresses.observe(answer(QStringLiteral("three.example"), QStringLiteral("192.0.2.3"),
                             300, 1), base.addSecs(2));
    check(addresses.lookup(QStringLiteral("192.0.2.1"), base.addSecs(3)).isEmpty(),
          QStringLiteral("the least recently seen address is evicted"));
    check(addresses.lookup(QStringLiteral("192.0.2.2"), base.addSecs(3)).size() == 1,
          QStringLiteral("the retained addresses still resolve"));
    check(addresses.lookup(QStringLiteral("192.0.2.3"), base.addSecs(3)).size() == 1,
          QStringLiteral("the newest address is retained"));

    // Lifetime is bounded above and falls back when the DNS TTL is missing.
    DnsCorrelator lifetime;
    lifetime.observe(answer(QStringLiteral("long.example"), QStringLiteral("192.0.2.20"),
                            7200, 1), base);
    lifetime.observe(answer(QStringLiteral("default.example"), QStringLiteral("192.0.2.21"),
                            0, 1), base);
    const QList<DomainAttribution> longLived =
        lifetime.lookup(QStringLiteral("192.0.2.20"), base.addSecs(1));
    check(!longLived.isEmpty() && longLived.first().expiresAt == base.addSecs(3600),
          QStringLiteral("a long DNS TTL is clamped to one hour"));
    const QList<DomainAttribution> defaultLived =
        lifetime.lookup(QStringLiteral("192.0.2.21"), base.addSecs(1));
    check(!defaultLived.isEmpty() && defaultLived.first().expiresAt == base.addSecs(300),
          QStringLiteral("a missing DNS TTL gets the bounded default"));

    // A visible TLS SNI joins the same address index as a DNS answer. The same
    // name from both observers is confirmed; either source alone is Likely.
    DnsCorrelator joined(3600, 60);
    joined.observe(answer(QStringLiteral("example.com"),
                          QStringLiteral("93.184.216.34"), 300, 123), base);
    TlsObservation sni;
    sni.status = TlsSniStatus::Available;
    sni.serverName = QStringLiteral("example.com");
    sni.remoteAddress = QStringLiteral("93.184.216.34");
    sni.pid = 456;
    sni.processName = QStringLiteral("browser.exe");
    sni.identityId = QStringLiteral("sha256:browser");
    joined.observeTls(sni, base.addSecs(5));

    const QList<DomainAttribution> joinedRecords =
        joined.lookup(QStringLiteral("93.184.216.34"), base.addSecs(10));
    checkEqual(static_cast<int>(joinedRecords.size()), 2,
               QStringLiteral("DNS and TLS records are kept separately so they expire independently"));
    DestinationNameSummary joinedSummary =
        summarizeDestinationNames(joinedRecords, QStringLiteral("93.184.216.34"));
    checkEqual(joinedSummary.name, QStringLiteral("example.com"),
               QStringLiteral("the shared DNS and SNI name is selected"));
    check(joinedSummary.source == AttributionSource::DnsAndTls,
          QStringLiteral("the summary reports both sources"));
    check(joinedSummary.confidence == ApplicationIdentity::Confidence::Confirmed,
          QStringLiteral("matching DNS and SNI observations confirm the name"));
    check(joinedSummary.evidence.size() >= 2,
          QStringLiteral("both DNS and SNI evidence are retained"));
    checkEqual(attributionSourceName(joinedSummary.source),
               QStringLiteral("DNS answer + TLS SNI"),
               QStringLiteral("a combined source is printable"));

    // The shorter SNI lifetime removes only the SNI evidence; the DNS name is
    // still available and falls back to a strong inference.
    const DestinationNameSummary expiredSni = summarizeDestinationNames(
        joined.lookup(QStringLiteral("93.184.216.34"), base.addSecs(66)),
        QStringLiteral("93.184.216.34"));
    check(expiredSni.source == AttributionSource::DnsAnswer &&
              expiredSni.confidence == ApplicationIdentity::Confidence::StrongInference,
          QStringLiteral("an expired SNI does not keep a DNS name confirmed"));

    // A SNI without an address, or an unavailable handshake, cannot attribute a
    // destination. A SNI-only name is still a strong inference.
    DnsCorrelator sniOnly(3600, 60);
    TlsObservation nameless = sni;
    nameless.remoteAddress.clear();
    sniOnly.observeTls(nameless, base);
    check(sniOnly.lookup(QStringLiteral("93.184.216.34"), base).isEmpty(),
          QStringLiteral("a SNI without a remote address is ignored"));

    TlsObservation unavailable = sni;
    unavailable.status = TlsSniStatus::EchHidden;
    unavailable.serverName.clear();
    sniOnly.observeTls(unavailable, base);
    check(sniOnly.lookup(QStringLiteral("93.184.216.34"), base).isEmpty(),
          QStringLiteral("an unavailable handshake does not create a name"));

    sni.remoteAddress = QStringLiteral("203.0.113.44");
    sniOnly.observeTls(sni, base);
    DestinationNameSummary sniSummary = summarizeDestinationNames(
        sniOnly.lookup(QStringLiteral("203.0.113.44"), base),
        QStringLiteral("203.0.113.44"));
    check(sniSummary.name == QStringLiteral("example.com") &&
              sniSummary.source == AttributionSource::TlsSni &&
              sniSummary.confidence == ApplicationIdentity::Confidence::StrongInference,
          QStringLiteral("a SNI without a DNS answer is a strong inference"));

    // Different names from the two observers are not a confirmation; each stays
    // an inference and both names remain visible.
    DnsCorrelator conflict(3600, 60);
    conflict.observe(answer(QStringLiteral("dns.example"),
                            QStringLiteral("198.51.100.44"), 300, 1), base);
    TlsObservation otherSni = sni;
    otherSni.remoteAddress = QStringLiteral("198.51.100.44");
    otherSni.serverName = QStringLiteral("sni.example");
    conflict.observeTls(otherSni, base.addSecs(5));
    const DestinationNameSummary conflictSummary = summarizeDestinationNames(
        conflict.lookup(QStringLiteral("198.51.100.44"), base.addSecs(10)),
        QStringLiteral("198.51.100.44"));
    check(conflictSummary.name == QStringLiteral("sni.example") &&
              conflictSummary.confidence == ApplicationIdentity::Confidence::StrongInference &&
              conflictSummary.names.size() == 2,
          QStringLiteral("different DNS and SNI names are not confirmed and both are kept"));

    checkEqual(attributionSourceName(AttributionSource::Unknown), QStringLiteral("Unknown"),
               QStringLiteral("an unknown attribution source is printable"));
}

void testTlsObserver()
{
    auto u16 = [](QByteArray &out, quint16 value) {
        out.append(static_cast<char>((value >> 8) & 0xFF));
        out.append(static_cast<char>(value & 0xFF));
    };
    auto u24 = [](QByteArray &out, quint32 value) {
        out.append(static_cast<char>((value >> 16) & 0xFF));
        out.append(static_cast<char>((value >> 8) & 0xFF));
        out.append(static_cast<char>(value & 0xFF));
    };
    auto extension = [&](quint16 type, const QByteArray &body) {
        QByteArray out;
        u16(out, type);
        u16(out, static_cast<quint16>(body.size()));
        out += body;
        return out;
    };
    auto sniExtension = [&](const QByteArray &name, quint8 nameType = 0) {
        QByteArray entry;
        entry.append(static_cast<char>(nameType));
        u16(entry, static_cast<quint16>(name.size()));
        entry += name;
        QByteArray list;
        u16(list, static_cast<quint16>(entry.size()));
        list += entry;
        return extension(0, list);
    };
    auto clientHello = [&](const QByteArray &extensions, quint8 contentType = 22,
                           quint8 handshakeType = 1) {
        QByteArray hello;
        u16(hello, 0x0303); // legacy_version
        hello += QByteArray(32, 'R');
        hello.append(static_cast<char>(0)); // session id length
        u16(hello, 2);
        hello.append(static_cast<char>(0x13));
        hello.append(static_cast<char>(0x01)); // TLS_AES_128_GCM_SHA256
        hello.append(static_cast<char>(1));
        hello.append(static_cast<char>(0)); // null compression
        u16(hello, static_cast<quint16>(extensions.size()));
        hello += extensions;

        QByteArray handshake;
        handshake.append(static_cast<char>(handshakeType));
        u24(handshake, static_cast<quint32>(hello.size()));
        handshake += hello;

        QByteArray record;
        record.append(static_cast<char>(contentType));
        u16(record, 0x0301); // TLS 1.0 legacy record version, as TLS 1.3 uses
        u16(record, static_cast<quint16>(handshake.size()));
        record += handshake;
        return record;
    };
    auto parse = [](const QByteArray &record) {
        return TlsObserver::parseRecord(
            reinterpret_cast<const uint8_t *>(record.constData()), record.size());
    };

    // A normal ClientHello exposes its SNI, normalized for comparison.
    const QByteArray valid = clientHello(sniExtension(QByteArray("Example.COM.")));
    const TlsObservation observed = parse(valid);
    check(observed.status == TlsSniStatus::Available,
          QStringLiteral("a ClientHello with SNI is available"));
    checkEqual(observed.serverName, QStringLiteral("example.com"),
               QStringLiteral("SNI is lower-cased without the trailing dot"));
    check(observed.isAvailable(), QStringLiteral("the availability helper agrees"));
    checkEqual(tlsSniStatusName(observed.status), QStringLiteral("available"),
               QStringLiteral("the TLS status is printable"));

    // Missing, unknown, and encrypted handshakes are unavailable, not guessed.
    const TlsObservation noSni = parse(clientHello(QByteArray()));
    check(noSni.status == TlsSniStatus::NoSni && noSni.serverName.isEmpty(),
          QStringLiteral("a ClientHello without SNI is unavailable"));
    checkEqual(tlsSniStatusName(noSni.status), QStringLiteral("no SNI"),
               QStringLiteral("the no-SNI status is printable"));

    const TlsObservation unknownType =
        parse(clientHello(sniExtension(QByteArray("mail.example"), 7)));
    check(unknownType.status == TlsSniStatus::NoSni && unknownType.serverName.isEmpty(),
          QStringLiteral("a non-host_name SNI entry is unavailable"));

    const TlsObservation encrypted = parse(clientHello(QByteArray(), 23));
    check(encrypted.status == TlsSniStatus::Encrypted && encrypted.serverName.isEmpty(),
          QStringLiteral("encrypted TLS application data yields no name"));

    const TlsObservation ech = parse(clientHello(
        sniExtension(QByteArray("public.example")) +
        extension(0xFE0D, QByteArray())));
    check(ech.status == TlsSniStatus::EchHidden && ech.serverName.isEmpty(),
          QStringLiteral("ECH hides the destination name"));

    const TlsObservation notClientHello = parse(clientHello(QByteArray(), 22, 2));
    check(notClientHello.status == TlsSniStatus::NotClientHello,
          QStringLiteral("a ServerHello is not treated as a ClientHello"));

    // Split handshakes are reported as fragmented at both layers.
    const TlsObservation truncatedRecord = parse(valid.left(valid.size() - 5));
    check(truncatedRecord.status == TlsSniStatus::Fragmented &&
              truncatedRecord.serverName.isEmpty(),
          QStringLiteral("a ClientHello past the visible bytes is fragmented"));
    check(parse(valid.left(3)).status == TlsSniStatus::Fragmented,
          QStringLiteral("a partial TLS record header is fragmented"));

    QByteArray splitHandshake = valid;
    const int partialHandshake = 14; // 4-byte handshake header + 10 body bytes
    splitHandshake.truncate(5 + partialHandshake);
    splitHandshake[3] = static_cast<char>((partialHandshake >> 8) & 0xFF);
    splitHandshake[4] = static_cast<char>(partialHandshake & 0xFF);
    const TlsObservation fragmentedHandshake = parse(splitHandshake);
    check(fragmentedHandshake.status == TlsSniStatus::Fragmented,
          QStringLiteral("a ClientHello split across records is fragmented"));

    // Malformed length fields and names never produce a partial SNI.
    QByteArray shortHandshake;
    shortHandshake.append(static_cast<char>(1));
    u24(shortHandshake, 5);
    shortHandshake += QByteArray(5, '\0');
    QByteArray shortRecord;
    shortRecord.append(static_cast<char>(22));
    u16(shortRecord, 0x0301);
    u16(shortRecord, static_cast<quint16>(shortHandshake.size()));
    shortRecord += shortHandshake;
    check(parse(shortRecord).status == TlsSniStatus::Malformed,
          QStringLiteral("a ClientHello shorter than its fields is malformed"));

    QByteArray badList;
    u16(badList, 5); // list claims five bytes, only one follows
    badList.append(static_cast<char>(0));
    check(parse(clientHello(extension(0, badList))).status == TlsSniStatus::Malformed,
          QStringLiteral("an over-long SNI list is malformed"));

    QByteArray badExtension;
    u16(badExtension, 0);
    u16(badExtension, 50); // no extension body follows
    check(parse(clientHello(badExtension)).status == TlsSniStatus::Malformed,
          QStringLiteral("an over-long extension is malformed"));

    const QByteArray nulName("bad\0name", 8);
    check(parse(clientHello(sniExtension(nulName))).status == TlsSniStatus::Malformed,
          QStringLiteral("an SNI name containing NUL is malformed"));

    // Non-TLS traffic is cheaply ignored rather than classified.
    const QByteArray http("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const TlsObservation notTls = TlsObserver::parseRecord(
        reinterpret_cast<const uint8_t *>(http.constData()), http.size());
    check(notTls.status == TlsSniStatus::NotTls,
          QStringLiteral("plain HTTP is not a TLS handshake"));
    checkEqual(tlsSniStatusName(notTls.status), QStringLiteral("not TLS"),
               QStringLiteral("the not-TLS status is printable"));
    check(parse(clientHello(QByteArray(), 21)).status == TlsSniStatus::NotTls,
          QStringLiteral("a TLS alert is not a handshake"));

    // IP and TCP framing are skipped for both address families.
    auto tcpFrame = [&](const QByteArray &payload) {
        QByteArray tcp;
        u16(tcp, 40000);
        u16(tcp, 443);
        tcp += QByteArray(8, '\0'); // sequence and acknowledgement numbers
        tcp.append(static_cast<char>(0x50)); // data offset 5 (20 bytes)
        tcp.append(static_cast<char>(0x18)); // PSH + ACK
        u16(tcp, 65535);
        u16(tcp, 0);
        u16(tcp, 0);
        tcp += payload;
        return tcp;
    };

    const QByteArray tcp = tcpFrame(valid);
    QByteArray ipv4(20, '\0');
    ipv4[0] = static_cast<char>(0x45);
    ipv4[9] = 6;
    ipv4 += tcp;
    check(TlsObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(ipv4.constData()), ipv4.size())
                  .status == TlsSniStatus::Available,
          QStringLiteral("an IPv4 TLS ClientHello is parsed"));

    QByteArray ipv6(40, '\0');
    ipv6[0] = static_cast<char>(0x60);
    ipv6[6] = 6;
    ipv6 += tcp;
    check(TlsObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(ipv6.constData()), ipv6.size())
                  .status == TlsSniStatus::Available,
          QStringLiteral("an IPv6 TLS ClientHello is parsed"));

    QByteArray udp = ipv4;
    udp[9] = 17; // not TCP
    check(TlsObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(udp.constData()), udp.size())
                  .status == TlsSniStatus::NotTls,
          QStringLiteral("a UDP datagram is not TLS-over-TCP"));

    QByteArray shortTcp = ipv4;
    shortTcp.truncate(20 + 10);
    check(TlsObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(shortTcp.constData()), shortTcp.size())
                  .status == TlsSniStatus::NotTls,
          QStringLiteral("a truncated TCP header is ignored"));

    QByteArray badOffset = ipv4;
    badOffset[20 + 12] = static_cast<char>(0x40); // data offset 4 (16 bytes)
    check(TlsObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(badOffset.constData()), badOffset.size())
                  .status == TlsSniStatus::NotTls,
          QStringLiteral("a TCP header shorter than 20 bytes is ignored"));
    check(TlsObserver::parseDatagram(nullptr, 0).status == TlsSniStatus::NotTls,
          QStringLiteral("an empty datagram is ignored"));
}

void testQuicObserver()
{
    auto u16 = [](QByteArray &out, quint16 value) {
        out.append(static_cast<char>((value >> 8) & 0xFF));
        out.append(static_cast<char>(value & 0xFF));
    };
    auto u32 = [](QByteArray &out, quint32 value) {
        out.append(static_cast<char>((value >> 24) & 0xFF));
        out.append(static_cast<char>((value >> 16) & 0xFF));
        out.append(static_cast<char>((value >> 8) & 0xFF));
        out.append(static_cast<char>(value & 0xFF));
    };
    auto varint = [](QByteArray &out, quint64 value) {
        if (value < (1ULL << 6)) {
            out.append(static_cast<char>(value));
        } else if (value < (1ULL << 14)) {
            out.append(static_cast<char>(0x40 | ((value >> 8) & 0x3F)));
            out.append(static_cast<char>(value & 0xFF));
        } else if (value < (1ULL << 30)) {
            out.append(static_cast<char>(0x80 | ((value >> 24) & 0x3F)));
            out.append(static_cast<char>((value >> 16) & 0xFF));
            out.append(static_cast<char>((value >> 8) & 0xFF));
            out.append(static_cast<char>(value & 0xFF));
        } else {
            out.append(static_cast<char>(0xC0 | ((value >> 56) & 0x3F)));
            for (int shift = 48; shift >= 0; shift -= 8) {
                out.append(static_cast<char>((value >> shift) & 0xFF));
            }
        }
    };
    auto longHeader = [&](quint32 version, quint8 typeBits) {
        QByteArray packet;
        packet.append(static_cast<char>(0xC0 | ((typeBits & 0x03) << 4)));
        u32(packet, version);
        packet.append(static_cast<char>(8));
        packet += QByteArray(8, 'D');
        packet.append(static_cast<char>(0));
        return packet;
    };
    auto initial = [&](quint32 version, quint8 typeBits = 0) {
        QByteArray packet = longHeader(version, typeBits);
        varint(packet, 0);      // no token
        varint(packet, 1 + 32); // one packet-number byte + ciphertext
        packet.append(static_cast<char>(0));
        packet += QByteArray(32, 'C');
        return packet;
    };
    auto parse = [](const QByteArray &packet) {
        return QuicObserver::parsePacket(
            reinterpret_cast<const uint8_t *>(packet.constData()), packet.size());
    };

    // Supported versions expose only clear header facts; the hostname is not
    // available because the ClientHello inside the Initial is encrypted.
    const QByteArray v1 = initial(0x00000001);
    const QuicObservation observed = parse(v1);
    check(observed.status == QuicMetadataStatus::InitialEncrypted,
          QStringLiteral("a QUIC v1 Initial is encrypted, not decrypted"));
    checkEqual(observed.versionName, QStringLiteral("QUIC v1"),
               QStringLiteral("the QUIC v1 version is printable"));
    checkEqual(observed.packetType, QStringLiteral("initial"),
               QStringLiteral("the v1 Initial packet type is identified"));
    check(!observed.hasHostname(),
          QStringLiteral("an encrypted QUIC Initial never claims a hostname"));
    checkEqual(quicMetadataStatusName(observed.status),
               QStringLiteral("encrypted QUIC Initial"),
               QStringLiteral("the encrypted Initial status is printable"));

    const QuicObservation v2 = parse(initial(0x6B3343CF, 1));
    check(v2.status == QuicMetadataStatus::InitialEncrypted &&
              v2.versionName == QStringLiteral("QUIC v2"),
          QStringLiteral("the v2 Initial packet type is identified"));

    const QuicObservation zeroRtt = parse(initial(0x00000001, 1));
    check(zeroRtt.status == QuicMetadataStatus::NotInitial &&
              zeroRtt.packetType == QStringLiteral("0-RTT"),
          QStringLiteral("a v1 0-RTT packet is not an Initial"));
    const QuicObservation retry = parse(initial(0x6B3343CF, 0));
    check(retry.status == QuicMetadataStatus::NotInitial &&
              retry.packetType == QStringLiteral("retry"),
          QStringLiteral("a v2 Retry packet is not an Initial"));

    // Unsupported versions and version negotiation remain explicitly unknown.
    const QuicObservation draft = parse(initial(0xFF00001D));
    check(draft.status == QuicMetadataStatus::UnsupportedVersion &&
              draft.versionName.contains(QStringLiteral("ff00001d")),
          QStringLiteral("an unsupported QUIC version yields no attribution"));
    QByteArray negotiation = longHeader(0, 0);
    check(parse(negotiation).status == QuicMetadataStatus::VersionNegotiation,
          QStringLiteral("a version-negotiation packet is recognized"));

    // Non-QUIC payloads are ignored cheaply.
    check(parse(QByteArray("hello")).status == QuicMetadataStatus::NotQuic,
          QStringLiteral("ordinary UDP is not QUIC"));
    check(parse(QByteArray(1, static_cast<char>(0x40))).status ==
              QuicMetadataStatus::NotQuic,
          QStringLiteral("short-header QUIC has no usable metadata"));
    check(QuicObserver::parsePacket(nullptr, 0).status == QuicMetadataStatus::NotQuic,
          QStringLiteral("an empty payload is ignored"));

    // Malformed long headers never produce a packet type or a guessed version.
    check(parse(v1.left(3)).status == QuicMetadataStatus::Malformed,
          QStringLiteral("a truncated QUIC version is malformed"));

    QByteArray badDestinationId;
    badDestinationId.append(static_cast<char>(0xC0));
    u32(badDestinationId, 0x00000001);
    badDestinationId.append(static_cast<char>(21)); // maximum is 20
    badDestinationId += QByteArray(21, 'D');
    check(parse(badDestinationId).status == QuicMetadataStatus::Malformed,
          QStringLiteral("an over-long destination connection ID is malformed"));

    QByteArray shortDestinationId;
    shortDestinationId.append(static_cast<char>(0xC0));
    u32(shortDestinationId, 0x00000001);
    shortDestinationId.append(static_cast<char>(8));
    shortDestinationId += QByteArray(3, 'D');
    check(parse(shortDestinationId).status == QuicMetadataStatus::Malformed,
          QStringLiteral("a truncated destination connection ID is malformed"));

    QByteArray badSourceId = longHeader(0x00000001, 0);
    badSourceId[badSourceId.size() - 1] = static_cast<char>(20);
    check(parse(badSourceId).status == QuicMetadataStatus::Malformed,
          QStringLiteral("a truncated source connection ID is malformed"));

    QByteArray oversizedToken = longHeader(0x00000001, 0);
    varint(oversizedToken, 100);
    check(parse(oversizedToken).status == QuicMetadataStatus::Malformed,
          QStringLiteral("an over-long token is malformed"));

    QByteArray zeroLength = longHeader(0x00000001, 0);
    varint(zeroLength, 0);
    varint(zeroLength, 0);
    check(parse(zeroLength).status == QuicMetadataStatus::Malformed,
          QStringLiteral("a zero-length QUIC packet payload is malformed"));

    QByteArray noCiphertext = longHeader(0x00000001, 0);
    varint(noCiphertext, 0);
    varint(noCiphertext, 1); // one packet-number byte, no ciphertext
    noCiphertext.append(static_cast<char>(0));
    check(parse(noCiphertext).status == QuicMetadataStatus::Malformed,
          QStringLiteral("an Initial without ciphertext is malformed"));

    QByteArray pastEnd = longHeader(0x00000001, 0);
    varint(pastEnd, 0);
    varint(pastEnd, 100);
    pastEnd.append(static_cast<char>(0));
    check(parse(pastEnd).status == QuicMetadataStatus::Malformed,
          QStringLiteral("a packet length past the datagram is malformed"));

    QByteArray truncatedVarint = longHeader(0x00000001, 0);
    truncatedVarint.append(static_cast<char>(0xC0)); // needs eight bytes
    truncatedVarint.append(static_cast<char>(0x00));
    check(parse(truncatedVarint).status == QuicMetadataStatus::Malformed,
          QStringLiteral("a truncated variable-length integer is malformed"));

    QByteArray noFixedBit = v1;
    noFixedBit[0] = static_cast<char>(noFixedBit[0] & 0xBF);
    check(parse(noFixedBit).status == QuicMetadataStatus::Malformed,
          QStringLiteral("an Initial without the fixed bit is malformed"));

    QByteArray twoByteLength = longHeader(0x00000001, 0);
    varint(twoByteLength, 0);
    varint(twoByteLength, 1 + 200); // encoded with a two-byte varint
    twoByteLength.append(static_cast<char>(0));
    twoByteLength += QByteArray(200, 'C');
    check(parse(twoByteLength).status == QuicMetadataStatus::InitialEncrypted,
          QStringLiteral("multi-byte QUIC lengths are decoded"));

    // IP/UDP framing is skipped for both address families.
    QByteArray udp;
    u16(udp, 50000);
    u16(udp, 443);
    u16(udp, static_cast<quint16>(8 + v1.size()));
    u16(udp, 0);
    udp += v1;

    QByteArray ipv4(20, '\0');
    ipv4[0] = static_cast<char>(0x45);
    ipv4[9] = 17;
    ipv4 += udp;
    check(QuicObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(ipv4.constData()), ipv4.size())
                  .status == QuicMetadataStatus::InitialEncrypted,
          QStringLiteral("an IPv4 QUIC Initial is parsed"));

    QByteArray ipv6(40, '\0');
    ipv6[0] = static_cast<char>(0x60);
    ipv6[6] = 17;
    ipv6 += udp;
    check(QuicObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(ipv6.constData()), ipv6.size())
                  .status == QuicMetadataStatus::InitialEncrypted,
          QStringLiteral("an IPv6 QUIC Initial is parsed"));

    QByteArray tcp = ipv4;
    tcp[9] = 6;
    check(QuicObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(tcp.constData()), tcp.size())
                  .status == QuicMetadataStatus::NotQuic,
          QStringLiteral("TCP is not QUIC-over-UDP"));

    QByteArray shortUdp = ipv4;
    shortUdp.truncate(20 + 4);
    check(QuicObserver::parseDatagram(
              reinterpret_cast<const uint8_t *>(shortUdp.constData()), shortUdp.size())
                  .status == QuicMetadataStatus::NotQuic,
          QStringLiteral("a truncated UDP header is ignored"));
}


void testEndpointCatalog()
{
    QSettings().clear();

    CatalogCategory parsedCategory = CatalogCategory::Unknown;
    check(catalogCategoryFromToken(QStringLiteral("cloud-sync"), &parsedCategory) &&
              parsedCategory == CatalogCategory::CloudSync,
          QStringLiteral("a category token round-trips"));
    check(!catalogCategoryFromToken(QStringLiteral("not-a-category"), &parsedCategory),
          QStringLiteral("an unknown category token is rejected"));
    checkEqual(catalogCategoryToken(CatalogCategory::Unknown), QStringLiteral("unknown"),
               QStringLiteral("the unknown category has a stable token"));
    checkEqual(catalogCategoryDisplayName(CatalogCategory::WindowsUpdate),
               QStringLiteral("Windows Update"),
               QStringLiteral("the category has a printable name"));
    checkEqual(QString::number(catalogCategoryTokens().size()), QStringLiteral("9"),
               QStringLiteral("all categories have tokens"));

    CatalogRuleSource parsedSource = CatalogRuleSource::BuiltIn;
    check(catalogRuleSourceFromToken(QStringLiteral("user"), &parsedSource) &&
              parsedSource == CatalogRuleSource::User,
          QStringLiteral("a rule source token round-trips"));

    EndpointCatalog catalog;
    check(catalog.rules().size() >= 12,
          QStringLiteral("the bundled catalog contains rules"));
    check(!catalog.catalogVersion().isEmpty(),
          QStringLiteral("the bundled catalog is versioned"));
    bool hasWindowsService = false;
    for (const CatalogRule &rule : catalog.rules()) {
        if (rule.id == QStringLiteral("builtin-windows-update-service")) {
            hasWindowsService = true;
            break;
        }
    }
    check(hasWindowsService, QStringLiteral("the bundled rules are inspectable"));

    // Service, publisher/product, executable, and endpoint evidence each match.
    CatalogQuery query;
    query.serviceName = QStringLiteral("WUAUSERV");
    CatalogMatch match = catalog.bestMatch(query);
    check(match.matched && match.category == CatalogCategory::WindowsUpdate &&
              match.ruleId == QStringLiteral("builtin-windows-update-service"),
          QStringLiteral("a service key matches its category"));
    check(match.matchedOn.join(QStringLiteral(" | ")).contains(QStringLiteral("service")),
          QStringLiteral("the match explains the service evidence"));

    query = CatalogQuery();
    query.publisher = QStringLiteral("Google LLC");
    query.product = QStringLiteral("Google Update");
    match = catalog.bestMatch(query);
    check(match.matched && match.category == CatalogCategory::BrowserUpdate &&
              match.ruleId == QStringLiteral("builtin-chrome-update"),
          QStringLiteral("a verified publisher and product match together"));
    query.product.clear();
    check(!catalog.bestMatch(query).matched,
          QStringLiteral("publisher alone does not satisfy a narrower rule"));

    query = CatalogQuery();
    query.executableName = QStringLiteral("C:\\Program Files (x86)\\Steam\\steam.exe");
    match = catalog.bestMatch(query);
    check(match.matched && match.category == CatalogCategory::GameLauncher,
          QStringLiteral("an executable basename matches case-insensitively"));

    query = CatalogQuery();
    query.domain = QStringLiteral("FE3.DELIVERY.MP.MICROSOFT.COM.");
    match = catalog.bestMatch(query);
    check(match.matched && match.category == CatalogCategory::WindowsUpdate,
          QStringLiteral("a wildcard endpoint domain matches a subdomain"));
    query.domain = QStringLiteral("delivery.mp.microsoft.com");
    check(!catalog.bestMatch(query).matched,
          QStringLiteral("a wildcard endpoint does not match its bare suffix"));
    query.domain = QStringLiteral("UPDATE.GOOGLEAPIS.COM.");
    check(catalog.bestMatch(query).category == CatalogCategory::BrowserUpdate,
          QStringLiteral("an exact endpoint domain is normalized"));
    query.domain = QStringLiteral("cdn.update.googleapis.com");
    check(!catalog.bestMatch(query).matched,
          QStringLiteral("an exact endpoint does not match a subdomain"));

    // Local rules can use address prefixes and identity evidence.
    CatalogRule rangeRule;
    rangeRule.id = QStringLiteral("user-corporate-range");
    rangeRule.category = CatalogCategory::ForegroundDownload;
    rangeRule.explanation = QStringLiteral("Corporate download range");
    rangeRule.addressPrefixes = { QStringLiteral("10.20.0.0/16") };
    QString error;
    check(catalog.upsertRule(rangeRule, &error), error);
    query = CatalogQuery();
    query.remoteAddress = QStringLiteral("10.20.4.5");
    match = catalog.bestMatch(query);
    check(match.matched && match.category == CatalogCategory::ForegroundDownload &&
              match.source == CatalogRuleSource::User,
          QStringLiteral("an IPv4 address prefix matches inside its range"));
    query.remoteAddress = QStringLiteral("10.21.4.5");
    check(!catalog.bestMatch(query).matched,
          QStringLiteral("an IPv4 address prefix does not match outside its range"));

    CatalogRule ipv6Rule;
    ipv6Rule.id = QStringLiteral("user-ipv6-range");
    ipv6Rule.category = CatalogCategory::CloudSync;
    ipv6Rule.explanation = QStringLiteral("IPv6 test range");
    ipv6Rule.addressPrefixes = { QStringLiteral("2001:db8::/32") };
    check(catalog.upsertRule(ipv6Rule, &error), error);
    query = CatalogQuery();
    query.remoteAddress = QStringLiteral("2001:db8:1::5");
    check(catalog.bestMatch(query).category == CatalogCategory::CloudSync,
          QStringLiteral("an IPv6 address prefix matches inside its range"));
    query.remoteAddress = QStringLiteral("2001:db9::1");
    check(!catalog.bestMatch(query).matched,
          QStringLiteral("an IPv6 address prefix does not match outside its range"));

    CatalogRule combinedRule;
    combinedRule.id = QStringLiteral("user-contoso-sync");
    combinedRule.category = CatalogCategory::CloudSync;
    combinedRule.explanation = QStringLiteral("Contoso sync client");
    combinedRule.publisherContains = QStringLiteral("contoso");
    combinedRule.serviceName = QStringLiteral("syncsvc");
    check(catalog.upsertRule(combinedRule, &error), error);
    query = CatalogQuery();
    query.publisher = QStringLiteral("Contoso Corporation");
    check(!catalog.bestMatch(query).matched,
          QStringLiteral("one criterion of a combined rule is not enough"));
    query.serviceName = QStringLiteral("SyncSvc");
    check(catalog.bestMatch(query).matched,
          QStringLiteral("all criteria of a combined rule must match"));

    CatalogRule specificRule;
    specificRule.id = QStringLiteral("user-windows-update-microsoft");
    specificRule.category = CatalogCategory::PackageManager;
    specificRule.explanation = QStringLiteral("Microsoft-signed update carrier");
    specificRule.serviceName = QStringLiteral("wuauserv");
    specificRule.publisherContains = QStringLiteral("microsoft");
    check(catalog.upsertRule(specificRule, &error), error);
    query = CatalogQuery();
    query.serviceName = QStringLiteral("wuauserv");
    query.publisher = QStringLiteral("Microsoft Corporation");
    const QList<CatalogMatch> ranked = catalog.matches(query);
    check(ranked.size() >= 2,
          QStringLiteral("all matching rules remain inspectable"));
    check(ranked.first().ruleId == QStringLiteral("user-windows-update-microsoft") &&
              ranked.first().category == CatalogCategory::PackageManager,
          QStringLiteral("the more specific rule wins"));

    CatalogRule pathRule;
    pathRule.id = QStringLiteral("user-contoso-path");
    pathRule.category = CatalogCategory::CloudSync;
    pathRule.explanation = QStringLiteral("Contoso sync executable path");
    pathRule.executablePath = QStringLiteral("C:\\Program Files\\Contoso\\sync.exe");
    check(catalog.upsertRule(pathRule, &error), error);
    query = CatalogQuery();
    query.executablePath = QStringLiteral("c:/program files/contoso/sync.exe");
    check(catalog.bestMatch(query).ruleId == QStringLiteral("user-contoso-path"),
          QStringLiteral("an executable path matches case-insensitively"));

    CatalogRule identityRule;
    identityRule.id = QStringLiteral("user-identity");
    identityRule.category = CatalogCategory::DeveloperTool;
    identityRule.explanation = QStringLiteral("Known developer identity");
    identityRule.identityId = QStringLiteral("AbC123");
    check(catalog.upsertRule(identityRule, &error), error);
    query = CatalogQuery();
    query.identityId = QStringLiteral("abc123");
    check(catalog.bestMatch(query).category == CatalogCategory::DeveloperTool,
          QStringLiteral("a durable identity id matches"));

    // Invalid and unsafe rules are rejected atomically.
    CatalogRule invalid;
    invalid.id = QStringLiteral("broken-rule");
    invalid.category = CatalogCategory::WindowsUpdate;
    invalid.explanation = QStringLiteral("invalid for testing");
    check(!EndpointCatalog::validateRule(invalid, &error),
          QStringLiteral("a rule without criteria is invalid"));
    invalid.domainPatterns = { QStringLiteral("*.bad..example") };
    check(!EndpointCatalog::validateRule(invalid, &error),
          QStringLiteral("an invalid domain pattern is rejected"));
    invalid.domainPatterns.clear();
    invalid.addressPrefixes = { QStringLiteral("10.0.0.0/33") };
    check(!EndpointCatalog::validateRule(invalid, &error),
          QStringLiteral("an invalid IPv4 prefix is rejected"));
    invalid.addressPrefixes.clear();
    invalid.executableName = QStringLiteral("C:\\evil.exe");
    check(!EndpointCatalog::validateRule(invalid, &error),
          QStringLiteral("an executable criterion cannot contain a path"));
    invalid.executableName.clear();
    invalid.id = QStringLiteral("bad id");
    invalid.publisherContains = QStringLiteral("example");
    check(!EndpointCatalog::validateRule(invalid, &error),
          QStringLiteral("an invalid rule id is rejected"));
    const int ruleCount = catalog.rules().size();
    check(!catalog.upsertRule(invalid, &error),
          QStringLiteral("an invalid rule is not stored"));
    checkEqual(QString::number(catalog.rules().size()), QString::number(ruleCount),
               QStringLiteral("a rejected rule leaves the catalog unchanged"));

    check(!catalog.removeRule(QStringLiteral("builtin-steam"), &error),
          QStringLiteral("a bundled rule cannot be removed"));
    check(catalog.setRuleEnabled(QStringLiteral("builtin-steam"), false),
          QStringLiteral("a bundled rule can be disabled"));
    query = CatalogQuery();
    query.executableName = QStringLiteral("steam.exe");
    check(!catalog.bestMatch(query).matched,
          QStringLiteral("a disabled rule stops matching"));
    check(catalog.setRuleEnabled(QStringLiteral("builtin-steam"), true),
          QStringLiteral("a bundled rule can be re-enabled"));
    check(catalog.bestMatch(query).matched,
          QStringLiteral("a re-enabled rule matches again"));

    // Import is versioned and atomic.
    auto makeDocument = [](const QJsonArray &rules, int schemaVersion = 1) {
        QJsonObject root;
        root.insert(QStringLiteral("format"), QStringLiteral("netguard.endpoint-catalog"));
        root.insert(QStringLiteral("schemaVersion"), schemaVersion);
        root.insert(QStringLiteral("catalogVersion"), QStringLiteral("2026.12.1"));
        root.insert(QStringLiteral("rules"), rules);
        return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
    };

    QJsonObject importedObject;
    importedObject.insert(QStringLiteral("id"), QStringLiteral("imported-contoso"));
    importedObject.insert(QStringLiteral("category"), QStringLiteral("cloud-sync"));
    importedObject.insert(QStringLiteral("explanation"),
                          QStringLiteral("Imported Contoso sync"));
    importedObject.insert(QStringLiteral("serviceName"), QStringLiteral("contoso-sync"));
    QJsonArray importedRules;
    importedRules.append(importedObject);
    const QString importedJson = makeDocument(importedRules);

    EndpointCatalog importedCatalog;
    check(importedCatalog.importJson(importedJson, &error), error);
    checkEqual(importedCatalog.catalogVersion(), QStringLiteral("2026.12.1"),
               QStringLiteral("an imported catalog carries its version"));
    checkEqual(QString::number(importedCatalog.rules().size()),
               QString::number(EndpointCatalog::builtinRules().size() + 1),
               QStringLiteral("an import replaces prior imported rules"));
    query = CatalogQuery();
    query.serviceName = QStringLiteral("contoso-sync");
    match = importedCatalog.bestMatch(query);
    check(match.matched && match.category == CatalogCategory::CloudSync &&
              match.source == CatalogRuleSource::Imported,
          QStringLiteral("an imported rule matches and is marked imported"));

    check(!importedCatalog.importJson(makeDocument(importedRules, 2), &error),
          QStringLiteral("a newer catalog schema is rejected"));
    check(importedCatalog.bestMatch(query).matched,
          QStringLiteral("a rejected import leaves the catalog unchanged"));

    QJsonObject noCriteria;
    noCriteria.insert(QStringLiteral("id"), QStringLiteral("imported-broken"));
    noCriteria.insert(QStringLiteral("category"), QStringLiteral("cloud-sync"));
    noCriteria.insert(QStringLiteral("explanation"), QStringLiteral("no criteria"));
    QJsonArray noCriteriaRules;
    noCriteriaRules.append(noCriteria);
    check(!importedCatalog.importJson(makeDocument(noCriteriaRules), &error),
          QStringLiteral("an imported rule without criteria is rejected"));
    check(importedCatalog.bestMatch(query).matched,
          QStringLiteral("an invalid rule does not replace the catalog"));

    QJsonArray duplicateRules;
    duplicateRules.append(importedObject);
    duplicateRules.append(importedObject);
    check(!importedCatalog.importJson(makeDocument(duplicateRules), &error),
          QStringLiteral("duplicate imported ids are rejected"));
    check(!importedCatalog.importJson(QStringLiteral("{not-json"), &error),
          QStringLiteral("malformed catalog JSON is rejected"));

    // A full export can be imported back, and local rules survive the round trip.
    const QString fullJson = catalog.toJson();
    check(fullJson.contains(QStringLiteral("\"schemaVersion\":1")) &&
              fullJson.contains(QStringLiteral("netguard.endpoint-catalog")),
          QStringLiteral("the export carries its format and schema version"));
    EndpointCatalog roundTrip;
    check(roundTrip.importJson(fullJson, &error), error);
    query = CatalogQuery();
    query.publisher = QStringLiteral("Contoso Corporation");
    query.serviceName = QStringLiteral("syncsvc");
    match = roundTrip.bestMatch(query);
    check(match.matched && match.category == CatalogCategory::CloudSync,
          QStringLiteral("local rules survive a full export/import round trip"));
    check(roundTrip.bestMatch([]{ CatalogQuery q; q.serviceName = QStringLiteral("wuauserv"); return q; }())
              .category == CatalogCategory::WindowsUpdate,
          QStringLiteral("bundled rules survive a full export/import round trip"));

    // Local changes persist through QSettings, and a malformed stored document
    // fails without disturbing the loaded catalog.
    QSettings().clear();
    EndpointCatalog persisted;
    CatalogRule persistedRule;
    persistedRule.id = QStringLiteral("user-persisted");
    persistedRule.category = CatalogCategory::CloudSync;
    persistedRule.explanation = QStringLiteral("Persisted sync service");
    persistedRule.serviceName = QStringLiteral("persisted-svc");
    check(persisted.upsertRule(persistedRule, &error), error);
    check(persisted.save(&error), error);

    EndpointCatalog loaded;
    check(loaded.load(&error), error);
    query = CatalogQuery();
    query.serviceName = QStringLiteral("persisted-svc");
    match = loaded.bestMatch(query);
    check(match.matched && match.source == CatalogRuleSource::User,
          QStringLiteral("a local rule persists and reloads as a user rule"));

    QSettings settings;
    settings.beginGroup(QStringLiteral("NetGuard/EndpointCatalog"));
    settings.setValue(QStringLiteral("document"), QStringLiteral("{broken"));
    settings.endGroup();
    check(!loaded.load(&error),
          QStringLiteral("a malformed stored catalog is rejected"));
    check(loaded.bestMatch(query).matched,
          QStringLiteral("a failed load leaves the in-memory catalog usable"));

    QSettings().clear();
}

void testAttributionConfidence()
{
    using namespace AttributionConfidenceModel;

    checkEqual(displayName(Confidence::Confirmed), QStringLiteral("Confirmed"),
               QStringLiteral("confirmed confidence has a plain label"));
    checkEqual(displayName(Confidence::StrongInference), QStringLiteral("Likely"),
               QStringLiteral("strong inference is labelled Likely"));
    checkEqual(displayName(Confidence::WeakInference), QStringLiteral("Possible"),
               QStringLiteral("weak inference is labelled Possible"));
    checkEqual(displayName(Confidence::Unknown), QStringLiteral("Unknown"),
               QStringLiteral("unknown confidence has a plain label"));
    checkEqual(technicalName(Confidence::StrongInference),
               QStringLiteral("strong inference"),
               QStringLiteral("technical names are retained for diagnostics"));
    check(isCertain(Confidence::Confirmed) && !isCertain(Confidence::StrongInference) &&
              !isCertain(Confidence::WeakInference),
          QStringLiteral("only confirmed evidence may be treated as fact"));
    checkEqual(qualifiedText(QStringLiteral("example.com"), Confidence::Confirmed),
               QStringLiteral("example.com"),
               QStringLiteral("a confirmed name is shown without a qualifier"));
    checkEqual(qualifiedText(QStringLiteral("example.com"), Confidence::WeakInference),
               QStringLiteral("Possible: example.com"),
               QStringLiteral("a weak name is not presented as fact"));
    checkEqual(qualifiedText(QStringLiteral("example.com"), Confidence::StrongInference),
               QStringLiteral("Likely: example.com"),
               QStringLiteral("a strong inference is qualified"));

    // Domain evidence: independent DNS and TLS observations confirm a name.
    DomainEvidence domain;
    domain.name = QStringLiteral("example.com");
    domain.address = QStringLiteral("93.184.216.34");
    domain.dnsAnswer = true;
    Assessment assessment = forDomain(domain);
    check(assessment.confidence == Confidence::StrongInference,
          QStringLiteral("a DNS answer alone is a strong inference"));
    check(assessment.descriptions().join(QStringLiteral(" "))
              .contains(QStringLiteral("DNS answer")),
          QStringLiteral("the DNS evidence is explained"));

    domain.dnsAnswer = false;
    domain.tlsSni = true;
    assessment = forDomain(domain);
    check(assessment.confidence == Confidence::StrongInference &&
              assessment.descriptions().join(QStringLiteral(" "))
                  .contains(QStringLiteral("TLS")),
          QStringLiteral("a visible TLS SNI alone is explained and strong"));

    domain.dnsAnswer = true;
    assessment = forDomain(domain);
    check(assessment.confidence == Confidence::Confirmed,
          QStringLiteral("matching DNS and TLS observations confirm the name"));
    check(assessment.descriptions().size() >= 2,
          QStringLiteral("both independent domain observations are retained"));

    DomainEvidence catalogOnly;
    catalogOnly.name = QStringLiteral("updates.example");
    catalogOnly.endpointCatalogMatch = true;
    assessment = forDomain(catalogOnly);
    check(assessment.confidence == Confidence::WeakInference,
          QStringLiteral("an endpoint rule without an observed name is weak"));

    DomainEvidence unnamed;
    unnamed.address = QStringLiteral("203.0.113.9");
    assessment = forDomain(unnamed);
    check(assessment.confidence == Confidence::Unknown &&
              assessment.summary().contains(QStringLiteral("destination address")),
          QStringLiteral("a direct address stays unknown and says why"));

    DomainEvidence hidden;
    hidden.metadataUnavailable = true;
    hidden.unavailableReason = QStringLiteral("ECH hid the ClientHello name.");
    assessment = forDomain(hidden);
    check(assessment.confidence == Confidence::Unknown &&
              assessment.summary().contains(QStringLiteral("ECH")),
          QStringLiteral("unavailable metadata is reported without a guess"));

    // Category evidence: service identity is direct, catalog rules scale with
    // the number of matched criteria, name-only and group evidence stay weak.
    CategoryEvidence categoryEvidence;
    categoryEvidence.protectedService = true;
    assessment = forCategory(categoryEvidence);
    check(assessment.confidence == Confidence::Confirmed &&
              assessment.summary().contains(QStringLiteral("protected")),
          QStringLiteral("a protected service category is confirmed"));

    categoryEvidence = CategoryEvidence();
    categoryEvidence.catalogMatch = true;
    categoryEvidence.catalogCriteria = 1;
    categoryEvidence.catalogRuleId = QStringLiteral("builtin-steam");
    assessment = forCategory(categoryEvidence);
    check(assessment.confidence == Confidence::WeakInference &&
              assessment.summary().contains(QStringLiteral("builtin-steam")),
          QStringLiteral("a one-criterion catalog match is possible, not fact"));

    categoryEvidence.catalogCriteria = 2;
    assessment = forCategory(categoryEvidence);
    check(assessment.confidence == Confidence::StrongInference,
          QStringLiteral("two catalog criteria raise the category to likely"));

    categoryEvidence = CategoryEvidence();
    categoryEvidence.catalogMatch = true;
    categoryEvidence.catalogCriteria = 1;
    categoryEvidence.exactExecutable = true;
    categoryEvidence.verifiedPublisher = true;
    check(forCategory(categoryEvidence).confidence == Confidence::StrongInference,
          QStringLiteral("an exact executable and verified publisher are strong"));

    CategoryEvidence named;
    named.executableNameRule = true;
    assessment = forCategory(named);
    check(assessment.confidence == Confidence::WeakInference &&
              assessment.summary().startsWith(QStringLiteral("Possible:")),
          QStringLiteral("a name-only category is displayed as Possible"));

    CategoryEvidence grouped;
    grouped.activityGroup = true;
    grouped.activityGroupName = QStringLiteral("Contoso Sync");
    assessment = forCategory(grouped);
    check(assessment.confidence == Confidence::WeakInference &&
              assessment.summary().contains(QStringLiteral("Contoso Sync")),
          QStringLiteral("a learned group category names the group as evidence"));

    CategoryEvidence overrideEvidence;
    overrideEvidence.userOverride = true;
    assessment = forCategory(overrideEvidence);
    check(assessment.confidence == Confidence::StrongInference,
          QStringLiteral("a user override is strong but not an observed fact"));

    assessment = forCategory(CategoryEvidence());
    check(assessment.confidence == Confidence::Unknown &&
              assessment.summary().contains(QStringLiteral("No category evidence")),
          QStringLiteral("a category without evidence stays Unknown"));

    Evidence weakEvidence;
    weakEvidence.strength = Confidence::WeakInference;
    weakEvidence.detail = QStringLiteral("one weak clue");
    Evidence strongEvidence;
    strongEvidence.strength = Confidence::StrongInference;
    strongEvidence.detail = QStringLiteral("one strong clue");
    assessment = aggregate({ weakEvidence, strongEvidence });
    check(assessment.confidence == Confidence::StrongInference &&
              assessment.descriptions().size() == 2,
          QStringLiteral("aggregation keeps the strongest clue and all evidence"));

    // The Data Saver classifier exposes the same confidence and evidence.
    ClassificationEvidence processEvidence;
    processEvidence.processName = QStringLiteral("chrome.exe");
    ProcessClassification classified = BandwidthGuard::classifyWithEvidence(processEvidence);
    check(classified.category == ProcessCategory::AskFirst &&
              classified.confidence == Confidence::WeakInference &&
              !classified.evidence.isEmpty(),
          QStringLiteral("a name-only process category is Possible with evidence"));

    processEvidence = ClassificationEvidence();
    processEvidence.processName = QStringLiteral("googleupdater.exe");
    processEvidence.publisher = QStringLiteral("Google LLC");
    processEvidence.displayName = QStringLiteral("Google Update");
    classified = BandwidthGuard::classifyWithEvidence(processEvidence);
    check(classified.category == ProcessCategory::AutoCandidate &&
              classified.confidence == Confidence::StrongInference &&
              !classified.evidence.isEmpty(),
          QStringLiteral("a verified publisher raises the category to Likely"));

    processEvidence = ClassificationEvidence();
    processEvidence.processName = QStringLiteral("svchost.exe");
    processEvidence.isService = true;
    classified = BandwidthGuard::classifyWithEvidence(processEvidence);
    check(classified.category == ProcessCategory::Protected &&
              classified.confidence == Confidence::Confirmed,
          QStringLiteral("a protected service category is confirmed"));
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    // Policy-store tests write real settings, so keep them in a scope of their
    // own and start from a clean slate.
    QCoreApplication::setOrganizationName(QStringLiteral("UltimateNetGuardTests"));
    QCoreApplication::setApplicationName(QStringLiteral("netguard_tests"));
    QSettings().clear();

    testApplicationIdentityRoundTrip();
    testActivityObservationRoundTrip();
    testNetworkPolicyRoundTrip();
    testThrottleResultRoundTrip();
    testAuditEventRoundTrip();
    testSchemaVersionGate();

    testFixtures();
    testDiagnosticsExportSchema();

    testPolicyOriginClassification();
    testEmergencyRestorePlan();
    testEmergencyRestoreReport();
    testEmergencyRestoreStoreRoundTrip();

    testReconciledPolicyId();
    testReconciliationFirewall();
    testReconciliationThrottle();
    testFirewallRuleNames();
    testDnsObserverParse();
    testDnsCorrelator();
    testTlsObserver();
    testQuicObserver();
    testEndpointCatalog();
    testAttributionConfidence();

    QSettings().clear();

    qInfo() << "checks:" << g_checks << "failures:" << g_failures;
    return g_failures == 0 ? 0 : 1;
}
