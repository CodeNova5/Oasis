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

    QSettings().clear();

    qInfo() << "checks:" << g_checks << "failures:" << g_failures;
    return g_failures == 0 ? 0 : 1;
}
