/**
 * @file   contract_tests.cpp
 * @brief  Contract, fixture, and diagnostics-export tests (NG-001..NG-003).
 */

#include "testharness.h"
#include "testdeclarations.h"

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

void runContractTests()
{
    testApplicationIdentityRoundTrip();
    testActivityObservationRoundTrip();
    testNetworkPolicyRoundTrip();
    testThrottleResultRoundTrip();
    testAuditEventRoundTrip();
    testSchemaVersionGate();
    testFixtures();
    testDiagnosticsExportSchema();
}
