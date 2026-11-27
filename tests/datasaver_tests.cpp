/**
 * @file   datasaver_tests.cpp
 * @brief  Data Saver contract, decision, and enforcement tests (DS-002..DS-008).
 */

#include "testharness.h"
#include "testdeclarations.h"

// ─── DS-002: Data Saver Off/Enforce persistence and migration ──────────────
// The automation contract has exactly two modes. The legacy three-state control
// maps Monitor to Off, an unsupported value fails closed, and the migration runs
// exactly once.

void clearDataSaverModeSettings()
{
    QSettings settings;
    settings.beginGroup(QLatin1String(DataSaverMode::Store::kGroup));
    settings.remove(QString());
    settings.endGroup();
    settings.sync();
}

QString storedDataSaverMode()
{
    QSettings settings;
    settings.beginGroup(QLatin1String(DataSaverMode::Store::kGroup));
    const QString value = settings.value(QLatin1String(DataSaverMode::Store::kModeKey)).toString();
    settings.endGroup();
    return value;
}

int storedDataSaverVersion()
{
    QSettings settings;
    settings.beginGroup(QLatin1String(DataSaverMode::Store::kGroup));
    const int value = settings.value(QLatin1String(DataSaverMode::Store::kVersionKey), -1).toInt();
    settings.endGroup();
    return value;
}

void testDataSaverModeContract()
{
    clearDataSaverModeSettings();

    // Clean install. There is no Monitor default any more, and the versioned
    // form is written so the next start does not have to guess.
    QSettings settings;
    DataSaverMode::LoadResult fresh = DataSaverMode::load(settings);
    check(fresh.mode == DataSaverMode::Mode::Off,
          QStringLiteral("a clean install starts Off"));
    check(!fresh.migrated && !fresh.invalid && !fresh.writeFailed,
          QStringLiteral("a clean install is neither a migration nor a rejection"));
    checkEqual(storedDataSaverVersion(), DataSaverMode::Store::kCurrentVersion,
               QStringLiteral("the versioned mode is written on first start"));
    checkEqual(storedDataSaverMode(), QStringLiteral("off"),
               QStringLiteral("the stored token for a clean install is off"));

    // Legacy Monitor migrates to Off, and the raw value is retained for support.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), 1);
    settings.sync();
    DataSaverMode::LoadResult monitor = DataSaverMode::load(settings);
    check(monitor.mode == DataSaverMode::Mode::Off,
          QStringLiteral("legacy Monitor migrates to Off"));
    check(monitor.migrated && monitor.legacyValueKnown && monitor.legacyValue == 1,
          QStringLiteral("the migration reports the legacy value it saw"));
    checkEqual(storedDataSaverMode(), QStringLiteral("off"),
               QStringLiteral("Monitor is persisted as off"));
    checkEqual(settings.value(QStringLiteral("Oasis/DataSaver/legacyValue")).toInt(), 1,
               QStringLiteral("the legacy value is retained for diagnostics"));

    // Idempotent: once version 2 exists the old key is ignored, even if an old
    // build writes a Monitor value back.
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), 1);
    settings.sync();
    DataSaverMode::LoadResult again = DataSaverMode::load(settings);
    check(again.mode == DataSaverMode::Mode::Off,
          QStringLiteral("a resubmitted legacy Monitor value stays Off"));
    check(!again.migrated,
          QStringLiteral("an existing versioned mode is not migrated a second time"));
    checkEqual(storedDataSaverMode(), QStringLiteral("off"),
               QStringLiteral("a reload leaves the stored mode untouched"));

    // Legacy Enforce keeps enforcing.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), 2);
    settings.sync();
    DataSaverMode::LoadResult legacyEnforce = DataSaverMode::load(settings);
    check(legacyEnforce.mode == DataSaverMode::Mode::Enforce && legacyEnforce.migrated,
          QStringLiteral("legacy Enforce migrates to Enforce"));
    checkEqual(storedDataSaverMode(), QStringLiteral("enforce"),
               QStringLiteral("Enforce is persisted as a token"));

    // Legacy Off stays Off.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), 0);
    settings.sync();
    check(DataSaverMode::load(settings).mode == DataSaverMode::Mode::Off,
          QStringLiteral("legacy Off stays Off"));

    // An out-of-range legacy value fails closed and is diagnosable.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), 7);
    settings.sync();
    DataSaverMode::LoadResult invalidLegacy = DataSaverMode::load(settings);
    check(invalidLegacy.mode == DataSaverMode::Mode::Off && invalidLegacy.invalid,
          QStringLiteral("an unsupported legacy value fails closed to Off"));
    check(!invalidLegacy.diagnostic.isEmpty(),
          QStringLiteral("an unsupported legacy value produces a diagnostic"));

    // A string in the legacy slot is not guessed at.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), QStringLiteral("enforce"));
    settings.sync();
    DataSaverMode::LoadResult stringLegacy = DataSaverMode::load(settings);
    check(stringLegacy.mode == DataSaverMode::Mode::Off && stringLegacy.invalid,
          QStringLiteral("a string legacy value fails closed"));

    // Enforce survives a restart.
    clearDataSaverModeSettings();
    check(DataSaverMode::save(settings, DataSaverMode::Mode::Enforce),
          QStringLiteral("saving Enforce succeeds"));
    settings.sync();
    checkEqual(storedDataSaverMode(), QStringLiteral("enforce"),
               QStringLiteral("Enforce is written as a token"));
    check(DataSaverMode::load(settings).mode == DataSaverMode::Mode::Enforce,
          QStringLiteral("Enforce survives a reload"));

    // A newer version is rejected whole and left for the newer build.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/modeVersion"), 3);
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), QStringLiteral("enforce"));
    settings.sync();
    DataSaverMode::LoadResult newer = DataSaverMode::load(settings);
    check(newer.mode == DataSaverMode::Mode::Off && newer.invalid,
          QStringLiteral("a newer stored mode version fails closed"));
    checkEqual(storedDataSaverVersion(), 3,
               QStringLiteral("a newer version is not overwritten"));
    checkEqual(storedDataSaverMode(), QStringLiteral("enforce"),
               QStringLiteral("a newer version's mode value is not overwritten"));

    // A version 2 payload with the retired Monitor token fails closed.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/modeVersion"), 2);
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), QStringLiteral("monitor"));
    settings.sync();
    DataSaverMode::LoadResult monitorToken = DataSaverMode::load(settings);
    check(monitorToken.mode == DataSaverMode::Mode::Off && monitorToken.invalid,
          QStringLiteral("the retired monitor token fails closed"));
    checkEqual(storedDataSaverMode(), QStringLiteral("off"),
               QStringLiteral("an unsupported current-version token is repaired to off"));

    // Missing mode under version 2 fails closed.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/modeVersion"), 2);
    settings.sync();
    check(DataSaverMode::load(settings).mode == DataSaverMode::Mode::Off,
          QStringLiteral("a missing mode under version 2 fails closed"));

    // A non-numeric version is not coerced.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/modeVersion"), QStringLiteral("2"));
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), QStringLiteral("enforce"));
    settings.sync();
    DataSaverMode::LoadResult stringVersion = DataSaverMode::load(settings);
    check(stringVersion.mode == DataSaverMode::Mode::Off && stringVersion.invalid,
          QStringLiteral("a string version fails closed"));

    // Tokens are normalized; an explicit Off persists.
    clearDataSaverModeSettings();
    settings.setValue(QStringLiteral("Oasis/DataSaver/modeVersion"), 2);
    settings.setValue(QStringLiteral("Oasis/DataSaver/mode"), QStringLiteral("ENFORCE"));
    settings.sync();
    check(DataSaverMode::load(settings).mode == DataSaverMode::Mode::Enforce,
          QStringLiteral("a stored token is read case-insensitively"));
    check(DataSaverMode::save(settings, DataSaverMode::Mode::Off),
          QStringLiteral("saving Off succeeds"));
    check(DataSaverMode::load(settings).mode == DataSaverMode::Mode::Off,
          QStringLiteral("Off survives a reload"));

    clearDataSaverModeSettings();
}

// ─── DS-003: FlowObservation v1 contract and bounded aggregation ────────────

QDateTime flowTestTime(qint64 offsetMs = 0)
{
    const QDateTime base = QDateTime::fromString(QStringLiteral("2026-11-25T18:00:00Z"),
                                                 Qt::ISODate);
    return base.addMSecs(offsetMs);
}

FlowCaptureSample makeFlowSample(quint32 pid, qint64 processStartMs, qint64 monotonicMs,
                                 const QString &protocol = QStringLiteral("TCP"),
                                 const QString &remoteAddress = QStringLiteral("13.107.246.40"),
                                 quint16 remotePort = 443, quint32 bytes = 1024,
                                 bool download = true)
{
    FlowCaptureSample sample;
    sample.timestamp = flowTestTime(monotonicMs);
    sample.monotonicMs = monotonicMs;
    sample.pid = pid;
    sample.processStartMs = processStartMs;
    sample.processName = QStringLiteral("Code.exe");
    sample.executablePath = QStringLiteral("C:/Program Files/Microsoft VS Code/Code.exe");
    sample.executableVersion = QStringLiteral("1.95.2");
    sample.identityId = QStringLiteral("app_7f3c11a0");
    sample.protocol = protocol;
    sample.localAddress = QStringLiteral("192.168.1.100");
    sample.localPort = 54312;
    sample.remoteAddress = remoteAddress;
    sample.remotePort = remotePort;
    sample.bytes = bytes;
    sample.download = download;
    sample.foreground = FlowCaptureSample::Foreground::App;
    sample.foregroundRootPid = pid;
    return sample;
}

void testFlowObservationContract()
{
    FlowObservation in;
    in.observationId = QStringLiteral("obs_0123456789abcdef");
    in.timestamp = flowTestTime();
    in.process.processInstanceId = QStringLiteral("pid:14820:1764093600000");
    in.process.pid = 14820;
    in.process.parentPid = 9104;
    in.process.identityId = QStringLiteral("app_7f3c11a0");
    in.process.exeName = QStringLiteral("Code.exe");
    in.process.exePath = QStringLiteral("C:/Program Files/Microsoft VS Code/Code.exe");
    in.process.exeVersion = QStringLiteral("1.95.2");
    in.process.role = FlowProcessRole::Main;
    in.process.foregroundState = FlowForegroundState::ForegroundActive;
    in.process.foregroundRootPid = 14820;
    in.process.interactionState = FlowInteractionState::Interactive;
    in.flow.flowId = QStringLiteral("flow_3ab19d0e");
    in.flow.protocol = QStringLiteral("TCP");
    in.flow.localEndpoint = QStringLiteral("192.168.1.100:54312");
    in.flow.remoteEndpoint = QStringLiteral("13.107.246.40:443");
    in.flow.domain = QStringLiteral("update.code.visualstudio.com");
    in.flow.domainSource = FlowDomainSource::Sni;
    in.flow.domainConfidence = FlowDomainConfidence::StrongInference;
    in.flow.multiplexed = false;
    in.flow.shared = true;
    in.metrics.rxBytes = 10485760;
    in.metrics.txBytes = 18432;
    in.metrics.durationMs = 4200;
    in.metrics.rateRxBitsPerSecond = 19972876;
    in.metrics.milestoneBytes = 10485760;
    in.metrics.milestoneIndex = 1;
    in.uxSignals.blockingToUser = false;
    in.uxSignals.latencySensitive = true;
    in.uxSignals.deferrable = true;
    in.uxSignals.avoidable = true;
    in.uxSignals.detectorTags << QStringLiteral("ide_core_update_signature")
                              << QStringLiteral("background_update");

    const QJsonObject json = toJson(in);
    checkEqual(json.value(QStringLiteral("schemaVersion")).toInt(), 1,
               QStringLiteral("FlowObservation writes schemaVersion 1"));
    check(json.value(QStringLiteral("process")).toObject()
              .contains(QStringLiteral("processInstanceId")),
          QStringLiteral("FlowObservation uses camelCase process fields"));
    check(json.value(QStringLiteral("flow")).toObject()
              .contains(QStringLiteral("remoteEndpoint")),
          QStringLiteral("FlowObservation uses camelCase flow fields"));

    FlowObservation out;
    QString error;
    check(fromJson(json, &out, &error),
          QStringLiteral("FlowObservation round-trips: %1").arg(error));
    checkEqual(out.observationId, in.observationId, QStringLiteral("observationId"));
    checkEqual(out.timestamp, in.timestamp, QStringLiteral("timestamp"));
    checkEqual(out.process.processInstanceId, in.process.processInstanceId,
               QStringLiteral("processInstanceId"));
    checkEqual(out.process.exeName, in.process.exeName, QStringLiteral("exeName"));
    checkEqual(out.process.exeVersion, in.process.exeVersion, QStringLiteral("exeVersion"));
    check(out.process.role == FlowProcessRole::Main, QStringLiteral("processRole"));
    check(out.process.foregroundState == FlowForegroundState::ForegroundActive,
          QStringLiteral("foregroundState"));
    check(out.process.interactionState == FlowInteractionState::Interactive,
          QStringLiteral("interactionState"));
    checkEqual(out.flow.domain, in.flow.domain, QStringLiteral("domain"));
    check(out.flow.domainSource == FlowDomainSource::Sni, QStringLiteral("domainSource"));
    check(out.flow.domainConfidence == FlowDomainConfidence::StrongInference,
          QStringLiteral("domainConfidence"));
    check(out.flow.shared, QStringLiteral("shared"));
    checkEqual(out.metrics.rxBytes, in.metrics.rxBytes, QStringLiteral("rxBytes"));
    checkEqual(out.metrics.durationMs, in.metrics.durationMs, QStringLiteral("durationMs"));
    checkEqual(out.metrics.milestoneIndex, in.metrics.milestoneIndex,
               QStringLiteral("milestoneIndex"));
    checkEqual(out.uxSignals.detectorTags, in.uxSignals.detectorTags,
               QStringLiteral("detectorTags"));
    check(out.uxSignals.latencySensitive && out.uxSignals.deferrable && out.uxSignals.avoidable,
          QStringLiteral("uxSignals booleans"));

    // §1 versioning: absent means 1; newer is rejected whole.
    QJsonObject withoutVersion = json;
    withoutVersion.remove(QStringLiteral("schemaVersion"));
    check(fromJson(withoutVersion, &out, &error),
          QStringLiteral("a payload without schemaVersion reads as v1"));
    QJsonObject newer = json;
    newer.insert(QStringLiteral("schemaVersion"), 2);
    check(!fromJson(newer, &out, &error),
          QStringLiteral("a newer FlowObservation schema is rejected"));
    check(error.contains(QStringLiteral("newer")),
          QStringLiteral("the newer-schema error names the version problem"));
    QJsonObject zero = json;
    zero.insert(QStringLiteral("schemaVersion"), 0);
    check(!fromJson(zero, &out, &error), QStringLiteral("schemaVersion 0 is rejected"));

    // Malformed payloads reject instead of being partially accepted.
    QJsonObject badId = json;
    badId.insert(QStringLiteral("observationId"), QStringLiteral("obs_NOTHEX"));
    check(!fromJson(badId, &out, &error), QStringLiteral("a malformed observationId is rejected"));

    QJsonObject missingMetrics = json;
    missingMetrics.remove(QStringLiteral("metrics"));
    check(!fromJson(missingMetrics, &out, &error),
          QStringLiteral("a missing metrics object is rejected"));

    QJsonObject negativeBytes = json;
    QJsonObject negativeMetrics = negativeBytes.value(QStringLiteral("metrics")).toObject();
    negativeMetrics.insert(QStringLiteral("rxBytes"), -1);
    negativeBytes.insert(QStringLiteral("metrics"), negativeMetrics);
    check(!fromJson(negativeBytes, &out, &error),
          QStringLiteral("a negative byte counter is rejected"));

    QJsonObject unknownRole = json;
    QJsonObject roleProcess = unknownRole.value(QStringLiteral("process")).toObject();
    roleProcess.insert(QStringLiteral("processRole"), QStringLiteral("root"));
    unknownRole.insert(QStringLiteral("process"), roleProcess);
    check(!fromJson(unknownRole, &out, &error),
          QStringLiteral("an unknown processRole is rejected"));

    QJsonObject badEndpoint = json;
    QJsonObject endpointFlow = badEndpoint.value(QStringLiteral("flow")).toObject();
    endpointFlow.insert(QStringLiteral("remoteEndpoint"), QStringLiteral("13.107.246.40"));
    badEndpoint.insert(QStringLiteral("flow"), endpointFlow);
    check(!fromJson(badEndpoint, &out, &error),
          QStringLiteral("an endpoint without a port is rejected"));

    QJsonObject domainWithoutSource = json;
    QJsonObject domainFlow = domainWithoutSource.value(QStringLiteral("flow")).toObject();
    domainFlow.remove(QStringLiteral("domainSource"));
    domainWithoutSource.insert(QStringLiteral("flow"), domainFlow);
    check(!fromJson(domainWithoutSource, &out, &error),
          QStringLiteral("a domain without a source is rejected"));

    QJsonObject missingProcess = json;
    missingProcess.remove(QStringLiteral("process"));
    check(!fromJson(missingProcess, &out, &error),
          QStringLiteral("a missing process object is rejected"));

    // A process instance id must agree with the pid, so a stale record cannot
    // be re-labelled onto another process.
    QJsonObject mismatchedInstance = json;
    QJsonObject instanceProcess = mismatchedInstance.value(QStringLiteral("process")).toObject();
    instanceProcess.insert(QStringLiteral("processInstanceId"),
                           QStringLiteral("pid:999:1764093600000"));
    mismatchedInstance.insert(QStringLiteral("process"), instanceProcess);
    check(!fromJson(mismatchedInstance, &out, &error),
          QStringLiteral("a processInstanceId that disagrees with pid is rejected"));

    // The contract keeps a base name, never a path.
    QJsonObject pathExe = json;
    QJsonObject pathProcess = pathExe.value(QStringLiteral("process")).toObject();
    pathProcess.insert(QStringLiteral("exeName"),
                       QStringLiteral("C:/Program Files/Code.exe"));
    pathExe.insert(QStringLiteral("process"), pathProcess);
    check(!fromJson(pathExe, &out, &error),
          QStringLiteral("exeName containing a path is rejected"));
}

void testFlowObservationBuilder()
{
    FlowObservationBuilder builder(4242, 512);
    builder.addSample(makeFlowSample(100, 1000, 0, QStringLiteral("TCP"),
                                     QStringLiteral("13.107.246.40"), 443,
                                     1024 * 1024));
    builder.addSample(makeFlowSample(100, 1000, 1000, QStringLiteral("TCP"),
                                     QStringLiteral("13.107.246.40"), 443,
                                     1024 * 1024));
    builder.addSample(makeFlowSample(100, 1000, 1000, QStringLiteral("TCP"),
                                     QStringLiteral("13.107.246.40"), 443,
                                     1024, false));

    QList<FlowObservation> observations = builder.observations();
    checkEqual(static_cast<int>(observations.size()), 1,
               QStringLiteral("one flow aggregates every sample"));
    if (observations.size() == 1) {
        const FlowObservation &observation = observations.first();
        check(isFlowIdentifier(observation.observationId, QStringLiteral("obs_")),
              QStringLiteral("the observation id follows the contract format"));
        check(isFlowIdentifier(observation.flow.flowId, QStringLiteral("flow_")),
              QStringLiteral("the flow id follows the contract format"));
        checkEqual(observation.process.processInstanceId,
                   QStringLiteral("pid:100:1000"),
                   QStringLiteral("processInstanceId carries the process start time"));
        checkEqual(observation.process.exeName, QStringLiteral("Code.exe"),
                   QStringLiteral("exeName is normalized"));
        checkEqual(observation.metrics.rxBytes, quint64(2 * 1024 * 1024),
                   QStringLiteral("rxBytes accumulates downloads"));
        checkEqual(observation.metrics.txBytes, quint64(1024),
                   QStringLiteral("txBytes accumulates uploads"));
        checkEqual(observation.metrics.durationMs, qint64(1000),
                   QStringLiteral("durationMs is the monotonic flow age"));
        checkEqual(observation.metrics.rateRxBitsPerSecond, quint64(16777216),
                   QStringLiteral("rateRxBitsPerSecond is bits per second"));
        check(observation.process.role == FlowProcessRole::Main,
              QStringLiteral("a foreground app is the main process"));
        check(observation.process.foregroundState == FlowForegroundState::ForegroundActive,
              QStringLiteral("a foreground app is foreground_active"));
        check(!observation.flow.shared,
              QStringLiteral("a single owner is not marked shared"));

        const QList<FlowObservation> second = builder.observations();
        check(second.size() == 1
                  && second.first().observationId != observation.observationId,
              QStringLiteral("each snapshot mints a fresh observationId"));
    }

    // IPv6 endpoints stay unambiguous.
    FlowObservationBuilder ipv6(9);
    FlowCaptureSample v6 = makeFlowSample(101, 2000, 0, QStringLiteral("UDP"),
                                          QStringLiteral("2001:db8::1"), 443, 512);
    v6.localAddress = QStringLiteral("fe80::1");
    ipv6.addSample(v6);
    const QList<FlowObservation> v6List = ipv6.observations();
    checkEqual(static_cast<int>(v6List.size()), 1,
               QStringLiteral("an IPv6 flow is observed"));
    if (!v6List.isEmpty()) {
        checkEqual(v6List.first().flow.remoteEndpoint,
                   QStringLiteral("[2001:db8::1]:443"),
                   QStringLiteral("an IPv6 endpoint is bracketed"));
        FlowObservation parsed;
        QString error;
        check(fromJson(toJson(v6List.first()), &parsed, &error),
              QStringLiteral("an IPv6 observation round-trips: %1").arg(error));
    }

    // A reused PID with a new start time cannot inherit the old flow.
    FlowObservationBuilder reuse(77);
    reuse.addSample(makeFlowSample(200, 5000, 0));
    const QString firstId = reuse.observations().first().flow.flowId;
    const QString firstInstance = reuse.observations().first().process.processInstanceId;
    reuse.expireIdleFlows(200000, 60000);
    checkEqual(reuse.flowCount(), 0, QStringLiteral("an idle flow expires"));
    reuse.addSample(makeFlowSample(200, 9000, 200000));
    const QList<FlowObservation> reused = reuse.observations();
    checkEqual(static_cast<int>(reused.size()), 1,
               QStringLiteral("the reused PID produces one new flow"));
    if (!reused.isEmpty()) {
        check(reused.first().flow.flowId != firstId,
              QStringLiteral("a re-established flow gets a new flowId"));
        check(reused.first().process.processInstanceId != firstInstance,
              QStringLiteral("a reused PID gets a new processInstanceId"));
        checkEqual(reused.first().metrics.rxBytes, quint64(1024),
                   QStringLiteral("the new process does not inherit old counters"));
    }

    // Two processes on one 4-tuple are shared, not a single owner.
    FlowObservationBuilder shared(88);
    shared.addSample(makeFlowSample(300, 1000, 0));
    shared.addSample(makeFlowSample(301, 1000, 10));
    const QList<FlowObservation> sharedList = shared.observations();
    checkEqual(static_cast<int>(sharedList.size()), 2,
               QStringLiteral("a shared 4-tuple yields two observations"));
    for (const FlowObservation &observation : sharedList) {
        check(observation.flow.shared, QStringLiteral("both observations are marked shared"));
    }

    // Missing process evidence is dropped and counted, never invented.
    FlowObservationBuilder missing(99);
    FlowCaptureSample noPid = makeFlowSample(0, 1000, 0);
    missing.addSample(noPid);
    FlowCaptureSample noName = makeFlowSample(400, 1000, 0);
    noName.processName = QStringLiteral("   ");
    missing.addSample(noName);
    FlowCaptureSample noProtocol = makeFlowSample(400, 1000, 0);
    noProtocol.protocol.clear();
    missing.addSample(noProtocol);
    FlowCaptureSample noRemote = makeFlowSample(400, 1000, 0);
    noRemote.remoteAddress.clear();
    missing.addSample(noRemote);
    checkEqual(missing.droppedSamples(), 4,
               QStringLiteral("samples without an owner or endpoints are dropped"));
    check(missing.observations().isEmpty(),
          QStringLiteral("a dropped sample produces no observation"));

    // Domain evidence stays explicit and never downgrades.
    FlowObservationBuilder domains(123);
    domains.addSample(makeFlowSample(500, 1000, 0));
    domains.setDestinationName(QStringLiteral("13.107.246.40"), QStringLiteral("Example.COM."),
                               FlowDomainSource::Dns, FlowDomainConfidence::WeakInference);
    FlowObservation weak = domains.observations().first();
    checkEqual(weak.flow.domain, QStringLiteral("example.com"),
               QStringLiteral("a domain is normalized"));
    check(weak.flow.domainSource == FlowDomainSource::Dns,
          QStringLiteral("the DNS source is preserved"));
    check(weak.flow.domainConfidence == FlowDomainConfidence::WeakInference,
          QStringLiteral("DNS-only evidence stays a weak inference"));

    domains.setDestinationName(QStringLiteral("13.107.246.40"), QStringLiteral("example.com"),
                               FlowDomainSource::Sni, FlowDomainConfidence::StrongInference);
    FlowObservation strong = domains.observations().first();
    check(strong.flow.domainConfidence == FlowDomainConfidence::StrongInference,
          QStringLiteral("stronger evidence upgrades the domain"));
    domains.setDestinationName(QStringLiteral("13.107.246.40"),
                               QStringLiteral("other.example.com"),
                               FlowDomainSource::Dns, FlowDomainConfidence::WeakInference);
    checkEqual(domains.observations().first().flow.domain, QStringLiteral("example.com"),
               QStringLiteral("weaker evidence never downgrades the domain"));

    // Unknown attribution is absent, not invented, and a wildcard is not a name.
    FlowObservationBuilder unknownDomain(321);
    unknownDomain.addSample(makeFlowSample(600, 1000, 0, QStringLiteral("TCP"),
                                           QStringLiteral("93.184.216.34")));
    unknownDomain.setDestinationName(QStringLiteral("93.184.216.34"),
                                     QStringLiteral("*.example.com"),
                                     FlowDomainSource::Dns, FlowDomainConfidence::WeakInference);
    const FlowObservation unknown = unknownDomain.observations().first();
    check(unknown.flow.domain.isEmpty(),
          QStringLiteral("an unknown domain stays absent"));
    const QJsonObject unknownJson = toJson(unknown);
    check(!unknownJson.value(QStringLiteral("flow")).toObject()
               .contains(QStringLiteral("domain")),
          QStringLiteral("an absent domain is omitted from the payload"));
    FlowObservation unknownParsed;
    check(fromJson(unknownJson, &unknownParsed, nullptr),
          QStringLiteral("an observation without a domain round-trips"));

    // Bounded storage evicts the oldest flow instead of growing without limit.
    FlowObservationBuilder bounded(555, 2);
    for (int i = 0; i < 5; ++i) {
        bounded.addSample(makeFlowSample(700 + static_cast<quint32>(i), 1000,
                                         i * 1000, QStringLiteral("TCP"),
                                         QStringLiteral("13.107.246.40"),
                                         static_cast<quint16>(4000 + i)));
    }
    checkEqual(bounded.flowCount(), 2, QStringLiteral("the flow store is bounded"));
    checkEqual(static_cast<int>(bounded.observations().size()), 2,
               QStringLiteral("only live flows are observed"));
    check(bounded.evictedFlows() >= 3, QStringLiteral("evictions are counted"));

    // Milestones are carried, not invented.
    FlowObservationBuilder milestones(777);
    FlowCaptureSample milestone = makeFlowSample(800, 1000, 0);
    milestone.milestoneBytes = 10485760;
    milestone.milestoneIndex = 1;
    milestones.addSample(milestone);
    const FlowObservation withMilestone = milestones.observations().first();
    checkEqual(withMilestone.metrics.milestoneBytes, quint64(10485760),
               QStringLiteral("milestoneBytes comes from the caller"));
    checkEqual(withMilestone.metrics.milestoneIndex, 1,
               QStringLiteral("milestoneIndex comes from the caller"));

    // A service is represented as a service, even without foreground evidence.
    FlowObservationBuilder services(888);
    FlowCaptureSample service = makeFlowSample(900, 1000, 0);
    service.service = true;
    service.foreground = FlowCaptureSample::Foreground::Unknown;
    services.addSample(service);
    const FlowObservation serviceObservation = services.observations().first();
    check(serviceObservation.process.role == FlowProcessRole::Service,
          QStringLiteral("a service sample has the service role"));
    check(serviceObservation.process.foregroundState == FlowForegroundState::Unknown,
          QStringLiteral("missing foreground evidence stays unknown"));
}

// ─── DS-004: volume milestones and evaluation dedupe ────────────────────────

FlowObservation makeMilestoneObservation(const QString &flowId,
                                         const QString &processInstanceId,
                                         const QString &domain,
                                         quint64 rxBytes)
{
    FlowObservation observation;
    observation.observationId = QStringLiteral("obs_0123456789abcdef");
    observation.timestamp = flowTestTime();
    observation.process.processInstanceId = processInstanceId;
    observation.process.pid = 100;
    observation.process.exeName = QStringLiteral("Code.exe");
    observation.process.foregroundState = FlowForegroundState::Background;
    observation.flow.flowId = flowId;
    observation.flow.protocol = QStringLiteral("TCP");
    observation.flow.localEndpoint = QStringLiteral("192.168.1.100:54312");
    observation.flow.remoteEndpoint = QStringLiteral("13.107.246.40:443");
    observation.flow.domain = domain;
    if (!domain.isEmpty()) {
        observation.flow.domainSource = FlowDomainSource::Dns;
        observation.flow.domainConfidence = FlowDomainConfidence::StrongInference;
    }
    observation.metrics.rxBytes = rxBytes;
    return observation;
}

void testVolumeMilestones()
{
    using namespace VolumeMilestone;

    checkEqual(thresholdBytes(1), quint64(10 * kMiB),
               QStringLiteral("milestone 1 is 10 MiB"));
    checkEqual(thresholdBytes(2), quint64(25 * kMiB),
               QStringLiteral("milestone 2 is 25 MiB"));
    checkEqual(thresholdBytes(3), quint64(50 * kMiB),
               QStringLiteral("milestone 3 is 50 MiB"));
    checkEqual(thresholdBytes(4), quint64(100 * kMiB),
               QStringLiteral("milestone 4 is 100 MiB"));
    checkEqual(thresholdBytes(5), quint64(200 * kMiB),
               QStringLiteral("later milestones double"));
    checkEqual(thresholdBytes(6), quint64(400 * kMiB),
               QStringLiteral("later milestones keep doubling"));
    checkEqual(thresholdBytes(0), quint64(0),
               QStringLiteral("index 0 has no threshold"));

    checkEqual(highestCrossedIndex(10 * kMiB - 1), 0,
               QStringLiteral("one byte below 10 MiB has not crossed a milestone"));
    checkEqual(highestCrossedIndex(10 * kMiB), 1,
               QStringLiteral("exactly 10 MiB crosses milestone 1"));
    checkEqual(highestCrossedIndex(100 * kMiB), 4,
               QStringLiteral("100 MiB crosses milestone 4"));
    checkEqual(highestCrossedIndex(200 * kMiB), 5,
               QStringLiteral("200 MiB crosses milestone 5"));

    // One 12 MiB flow with a domain crosses flow, process, and domain scopes.
    VolumeMilestoneEvaluator evaluator(600000);
    const FlowObservation first = makeMilestoneObservation(
        QStringLiteral("flow_aaaaaaaaaaaaaaaa"), QStringLiteral("pid:100:1000"),
        QStringLiteral("example.com"), 12 * kMiB);
    const QList<MilestoneCrossing> crossings = evaluator.evaluate({first}, 1000);
    checkEqual(static_cast<int>(crossings.size()), 3,
               QStringLiteral("flow, process, and domain each cross once"));
    bool sawFlow = false;
    bool sawProcess = false;
    bool sawDomain = false;
    for (const MilestoneCrossing &crossing : crossings) {
        check(isFlowIdentifier(crossing.observationId, QStringLiteral("obs_")),
              QStringLiteral("a crossing mints a contract observationId"));
        checkEqual(crossing.milestoneIndex, 1,
                   QStringLiteral("the crossing names milestone 1"));
        checkEqual(crossing.milestoneBytes, quint64(10 * kMiB),
                   QStringLiteral("the crossing carries the MiB threshold"));
        checkEqual(crossing.cumulativeBytes, quint64(12 * kMiB),
                   QStringLiteral("the crossing carries the scope total"));
        switch (crossing.scope) {
        case MilestoneScope::Flow:
            sawFlow = true;
            checkEqual(crossing.flowId, first.flow.flowId,
                       QStringLiteral("a flow crossing names its flow"));
            break;
        case MilestoneScope::Process:
            sawProcess = true;
            checkEqual(crossing.processInstanceId, first.process.processInstanceId,
                       QStringLiteral("a process crossing names its process instance"));
            break;
        case MilestoneScope::Domain:
            sawDomain = true;
            checkEqual(crossing.domain, QStringLiteral("example.com"),
                       QStringLiteral("a domain crossing names its domain"));
            break;
        }
    }
    check(sawFlow && sawProcess && sawDomain,
          QStringLiteral("the three accounting scopes are reported"));

    // Repeating the same snapshot inside the window adds no evaluations.
    check(evaluator.evaluate({first}, 2000).isEmpty(),
          QStringLiteral("the same snapshot is deduplicated"));

    // Exact boundary.
    VolumeMilestoneEvaluator boundary(600000);
    check(boundary.evaluate({makeMilestoneObservation(
              QStringLiteral("flow_bbbbbbbbbbbbbbbb"), QStringLiteral("pid:110:1000"),
              QString(), 10 * kMiB - 1)}, 0).isEmpty(),
          QStringLiteral("just below the threshold emits nothing"));
    checkEqual(static_cast<int>(boundary.evaluate({makeMilestoneObservation(
                   QStringLiteral("flow_bbbbbbbbbbbbbbbb"), QStringLiteral("pid:110:1000"),
                   QString(), 10 * kMiB)}, 0).size()), 2,
               QStringLiteral("the exact threshold emits flow and process crossings"));

    // Process scope aggregates several flows of one process instance.
    VolumeMilestoneEvaluator processes(600000);
    const QList<MilestoneCrossing> processCrossings = processes.evaluate(
        {makeMilestoneObservation(QStringLiteral("flow_cccccccccccccccc"),
                                  QStringLiteral("pid:200:1000"), QString(), 6 * kMiB),
         makeMilestoneObservation(QStringLiteral("flow_dddddddddddddddd"),
                                  QStringLiteral("pid:200:1000"), QString(), 6 * kMiB)},
        0);
    checkEqual(static_cast<int>(processCrossings.size()), 1,
               QStringLiteral("two small flows cross once at the process scope"));
    if (!processCrossings.isEmpty()) {
        check(processCrossings.first().scope == MilestoneScope::Process,
              QStringLiteral("the aggregate crossing is a process crossing"));
        checkEqual(processCrossings.first().cumulativeBytes, quint64(12 * kMiB),
                   QStringLiteral("the process total sums its flows"));
    }

    // Domain scope aggregates different processes on one domain.
    VolumeMilestoneEvaluator domains(600000);
    const QList<MilestoneCrossing> domainCrossings = domains.evaluate(
        {makeMilestoneObservation(QStringLiteral("flow_eeeeeeeeeeeeeeee"),
                                  QStringLiteral("pid:300:1000"),
                                  QStringLiteral("cdn.example.com"), 6 * kMiB),
         makeMilestoneObservation(QStringLiteral("flow_ffffffffffffffff"),
                                  QStringLiteral("pid:301:1000"),
                                  QStringLiteral("cdn.example.com"), 6 * kMiB)},
        0);
    checkEqual(static_cast<int>(domainCrossings.size()), 1,
               QStringLiteral("two small flows cross once at the domain scope"));
    if (!domainCrossings.isEmpty()) {
        check(domainCrossings.first().scope == MilestoneScope::Domain,
              QStringLiteral("the aggregate crossing is a domain crossing"));
        checkEqual(domainCrossings.first().domain, QStringLiteral("cdn.example.com"),
                   QStringLiteral("the domain crossing names the normalized domain"));
    }

    // A missing domain must not aggregate into an empty domain key.
    VolumeMilestoneEvaluator noDomain(600000);
    const QList<MilestoneCrossing> noDomainCrossings = noDomain.evaluate(
        {makeMilestoneObservation(QStringLiteral("flow_1111111111111111"),
                                  QStringLiteral("pid:400:1000"), QString(), 12 * kMiB)},
        0);
    checkEqual(static_cast<int>(noDomainCrossings.size()), 2,
               QStringLiteral("a flow without a domain has only flow and process scopes"));
    for (const MilestoneCrossing &crossing : noDomainCrossings) {
        check(crossing.scope != MilestoneScope::Domain,
              QStringLiteral("no domain crossing is invented"));
    }

    // Counter rollover resets the scope but cannot reuse a crossing inside the
    // evaluation window.
    VolumeMilestoneEvaluator rollover(600000);
    const FlowObservation high = makeMilestoneObservation(
        QStringLiteral("flow_2222222222222222"), QStringLiteral("pid:500:1000"),
        QString(), 12 * kMiB);
    checkEqual(static_cast<int>(rollover.evaluate({high}, 1000).size()), 2,
               QStringLiteral("the original crossing is accepted"));
    FlowObservation low = high;
    low.metrics.rxBytes = 1 * kMiB;
    check(rollover.evaluate({low}, 2000).isEmpty(),
          QStringLiteral("a reset counter emits nothing"));
    check(rollover.evaluate({high}, 3000).isEmpty(),
          QStringLiteral("re-crossing inside the window is suppressed"));
    check(rollover.suppressedCount() >= 2,
          QStringLiteral("suppressed crossings are counted"));

    check(rollover.evaluate({low}, 700000).isEmpty(),
          QStringLiteral("the reset after the window still emits nothing"));
    check(!rollover.evaluate({high}, 700001).isEmpty(),
          QStringLiteral("re-crossing after the window is accepted"));

    // PID reuse and flow replacement are new scopes, so they emit immediately.
    VolumeMilestoneEvaluator reuse(600000);
    reuse.evaluate({makeMilestoneObservation(QStringLiteral("flow_3333333333333333"),
                                             QStringLiteral("pid:600:1000"),
                                             QString(), 12 * kMiB)}, 1000);
    check(!reuse.evaluate({makeMilestoneObservation(QStringLiteral("flow_4444444444444444"),
                                                    QStringLiteral("pid:600:2000"),
                                                    QString(), 12 * kMiB)}, 2000).isEmpty(),
          QStringLiteral("a reused PID with a new start time is a new scope"));

    // An application restart starts with an empty evaluator, so the same
    // observation is evaluated again rather than remembered.
    VolumeMilestoneEvaluator restarted;
    check(!restarted.evaluate({first}, 3000).isEmpty(),
          QStringLiteral("a restarted evaluator does not reuse prior dedupe state"));
}

// ─── DS-005: pinned rules, session overrides, and precedence ───────────────

void clearPinnedRuleStore()
{
    QSettings settings;
    settings.beginGroup(PinnedRuleStore::storageGroup());
    settings.remove(QString());
    settings.endGroup();
    settings.sync();
}

int storedPinnedRuleSchemaVersion()
{
    QSettings settings;
    settings.beginGroup(PinnedRuleStore::storageGroup());
    const int version = settings.value(QStringLiteral("schemaVersion"), -1).toInt();
    settings.endGroup();
    return version;
}

PinnedRule makePinnedRule(const QString &executable, const QString &domain,
                          NetworkPolicy::Action action = NetworkPolicy::Action::Allow,
                          quint64 rate = 0)
{
    PinnedRule rule;
    rule.executable = executable;
    rule.domainPattern = domain;
    rule.action = action;
    rule.rateBitsPerSecond = rate;
    rule.direction = NetworkDirection::Download;
    return rule;
}

void testDataSaverRules()
{
    using namespace DataSaverRules;

    clearPinnedRuleStore();

    // A throttle pin needs no Always Allow confirmation and round-trips.
    PinnedRule wildcard = makePinnedRule(
        QStringLiteral("Code.exe"), QStringLiteral("*.VisualStudio.com."),
        NetworkPolicy::Action::Throttle, kDefaultThrottleBitsPerSecond);
    QString error;
    check(PinnedRuleStore::add(wildcard, false, &error),
          QStringLiteral("a throttle pin persists without confirmation: %1").arg(error));
    check(isFlowIdentifier(wildcard.id, QStringLiteral("pin_")),
          QStringLiteral("a pinned rule gets a pin_ id"));

    const PinnedRuleLoadResult reloaded = PinnedRuleStore::load();
    checkEqual(static_cast<int>(reloaded.rules.size()), 1,
               QStringLiteral("a pinned rule survives a reload"));
    if (!reloaded.rules.isEmpty()) {
        const PinnedRule &rule = reloaded.rules.first();
        checkEqual(rule.executable, QStringLiteral("code.exe"),
                   QStringLiteral("the executable is normalized"));
        checkEqual(rule.domainPattern, QStringLiteral("*.visualstudio.com"),
                   QStringLiteral("the wildcard domain is normalized"));
        check(rule.action == NetworkPolicy::Action::Throttle,
              QStringLiteral("the pin action round-trips"));
        checkEqual(rule.rateBitsPerSecond, quint64(kDefaultThrottleBitsPerSecond),
                   QStringLiteral("the pin rate round-trips"));
        check(rule.direction == NetworkDirection::Download,
              QStringLiteral("the pin direction round-trips"));
    }

    // Always Allow is gated on explicit confirmation.
    PinnedRule allow = makePinnedRule(QStringLiteral("chrome.exe"),
                                      QStringLiteral("example.com"));
    error.clear();
    check(!PinnedRuleStore::add(allow, false, &error),
          QStringLiteral("Always Allow without confirmation is refused"));
    check(error.contains(QStringLiteral("confirmation")),
          QStringLiteral("the refusal explains the confirmation requirement"));
    checkEqual(static_cast<int>(PinnedRuleStore::load().rules.size()), 1,
               QStringLiteral("a refused Always Allow is not stored"));
    check(PinnedRuleStore::add(allow, true, &error),
          QStringLiteral("a confirmed Always Allow persists"));
    check(isFlowIdentifier(allow.id, QStringLiteral("pin_")),
          QStringLiteral("the confirmed pin gets an id"));
    checkEqual(static_cast<int>(PinnedRuleStore::load().rules.size()), 2,
               QStringLiteral("the confirmed Always Allow is stored"));

    // Invalid pinned data is refused without touching the store.
    PinnedRule zeroRate = makePinnedRule(QStringLiteral("code.exe"),
                                         QStringLiteral("example.com"),
                                         NetworkPolicy::Action::Throttle, 0);
    check(!PinnedRuleStore::save(QList<PinnedRule>() << zeroRate, &error),
          QStringLiteral("a throttle pin without a positive rate is rejected"));

    // A newer store is rejected whole and never overwritten.
    clearPinnedRuleStore();
    {
        QSettings settings;
        settings.beginGroup(PinnedRuleStore::storageGroup());
        settings.setValue(QStringLiteral("schemaVersion"), 2);
        settings.setValue(QStringLiteral("rules"), QStringLiteral("[]"));
        settings.endGroup();
        settings.sync();
    }
    const PinnedRuleLoadResult newer = PinnedRuleStore::load();
    check(newer.rejectedNewer && newer.rules.isEmpty(),
          QStringLiteral("a newer pinned-rule schema is rejected whole"));
    PinnedRule blockedWrite = makePinnedRule(QStringLiteral("code.exe"),
                                             QStringLiteral("example.com"));
    check(!PinnedRuleStore::add(blockedWrite, true, &error),
          QStringLiteral("writing over a newer pinned-rule store is refused"));
    checkEqual(storedPinnedRuleSchemaVersion(), 2,
               QStringLiteral("the newer store version is left in place"));

    // Malformed rules are skipped; one valid rule survives a missing version.
    clearPinnedRuleStore();
    PinnedRule good = makePinnedRule(QStringLiteral("code.exe"), QStringLiteral("example.com"),
                                     NetworkPolicy::Action::Throttle,
                                     kDefaultThrottleBitsPerSecond);
    good.id = QStringLiteral("pin_0123456789abcdef");
    good.createdAt = flowTestTime();
    QJsonArray storedRules;
    storedRules.append(PinnedRuleStore::toJson(good));
    QJsonObject missingExecutable = PinnedRuleStore::toJson(good);
    missingExecutable.remove(QStringLiteral("executable"));
    storedRules.append(missingExecutable);
    QJsonObject badAction = PinnedRuleStore::toJson(good);
    badAction.insert(QStringLiteral("action"), QStringLiteral("ask"));
    storedRules.append(badAction);
    QJsonObject foreignOrigin = PinnedRuleStore::toJson(good);
    foreignOrigin.insert(QStringLiteral("origin"), QStringLiteral("system"));
    storedRules.append(foreignOrigin);
    QJsonObject badExpiry = PinnedRuleStore::toJson(good);
    badExpiry.insert(QStringLiteral("expiresAt"), QStringLiteral("not-a-date"));
    storedRules.append(badExpiry);
    {
        QSettings settings;
        settings.beginGroup(PinnedRuleStore::storageGroup());
        settings.setValue(QStringLiteral("rules"),
                          QString::fromUtf8(QJsonDocument(storedRules)
                                                .toJson(QJsonDocument::Compact)));
        settings.endGroup();
        settings.sync();
    }
    const PinnedRuleLoadResult malformed = PinnedRuleStore::load();
    checkEqual(static_cast<int>(malformed.rules.size()), 1,
               QStringLiteral("the valid pinned rule survives malformed neighbours"));
    checkEqual(malformed.skipped, 4,
               QStringLiteral("four malformed pinned rules are skipped"));
    check(!malformed.diagnostic.isEmpty(),
          QStringLiteral("malformed pinned rules produce a diagnostic"));
    if (!malformed.rules.isEmpty()) {
        checkEqual(malformed.rules.first().id, good.id,
                   QStringLiteral("the valid rule keeps its id"));
    }

    // Session overrides are in-memory, expire, and do not survive restart.
    SessionOverrideStore sessions;
    SessionOverride flowOverride;
    flowOverride.scope = SessionScope::Flow;
    flowOverride.flowId = QStringLiteral("flow_aaaaaaaaaaaaaaaa");
    flowOverride.action = NetworkPolicy::Action::Notify;
    flowOverride.continueAfterNotify = true;
    check(sessions.add(flowOverride, &error),
          QStringLiteral("a session flow override is accepted: %1").arg(error));
    check(isFlowIdentifier(flowOverride.id, QStringLiteral("ses_")),
          QStringLiteral("a session override gets a ses_ id"));
    checkEqual(static_cast<int>(sessions.activeOverrides(flowTestTime()).size()), 1,
               QStringLiteral("the session override is active"));
    SessionOverrideStore restarted;
    checkEqual(restarted.count(), 0,
               QStringLiteral("session overrides do not survive an app restart"));
    checkEqual(sessions.count(), 1,
               QStringLiteral("the live session keeps its override"));

    SessionOverride expiring;
    expiring.scope = SessionScope::ExecutableDomain;
    expiring.executable = QStringLiteral("Code.exe");
    expiring.domainPattern = QStringLiteral("*.VisualStudio.com");
    expiring.action = NetworkPolicy::Action::Throttle;
    expiring.rateBitsPerSecond = kDefaultThrottleBitsPerSecond;
    expiring.createdAt = flowTestTime();
    expiring.expiresAt = flowTestTime().addSecs(3600);
    check(sessions.add(expiring, &error),
          QStringLiteral("an expiring session override is accepted: %1").arg(error));
    checkEqual(static_cast<int>(sessions.activeOverrides(flowTestTime().addSecs(3599)).size()), 2,
               QStringLiteral("both session overrides are active before expiry"));
    checkEqual(static_cast<int>(sessions.activeOverrides(flowTestTime().addSecs(3601)).size()), 1,
               QStringLiteral("the expiring session override is inactive after expiry"));

    SessionOverride sessionBlock;
    sessionBlock.scope = SessionScope::ExecutableDomain;
    sessionBlock.executable = QStringLiteral("code.exe");
    sessionBlock.domainPattern = QStringLiteral("example.com");
    sessionBlock.action = NetworkPolicy::Action::Block;
    check(!sessions.add(sessionBlock, &error),
          QStringLiteral("a session override cannot block"));
    check(error.contains(QStringLiteral("block")),
          QStringLiteral("the session block refusal names the restriction"));

    // Precedence: a pin wins over a matching session and reports the conflict.
    const QDateTime now = flowTestTime();
    FlowObservation observation = makeMilestoneObservation(
        QStringLiteral("flow_aaaaaaaaaaaaaaaa"), QStringLiteral("pid:100:1000"),
        QStringLiteral("update.code.visualstudio.com"), 12 * VolumeMilestone::kMiB);
    observation.process.exeName = QStringLiteral("Code.exe");

    PinnedRule pin = makePinnedRule(QStringLiteral("code.exe"),
                                    QStringLiteral("*.visualstudio.com"),
                                    NetworkPolicy::Action::Throttle,
                                    kDefaultThrottleBitsPerSecond);
    pin.id = QStringLiteral("pin_1111111111111111");
    pin.createdAt = now;
    SessionOverride session;
    session.id = QStringLiteral("ses_2222222222222222");
    session.scope = SessionScope::ExecutableDomain;
    session.executable = QStringLiteral("code.exe");
    session.domainPattern = QStringLiteral("*");
    session.action = NetworkPolicy::Action::Allow;

    const RuleResolution pinned = RuleResolver::resolve(
        observation, QList<PinnedRule>() << pin, QList<SessionOverride>() << session, now);
    check(pinned.matched && pinned.winner.tier == 1,
          QStringLiteral("a pinned rule is tier 1"));
    checkEqual(pinned.winner.ruleId, pin.id,
               QStringLiteral("the pinned rule is the winner"));
    check(pinned.winner.action == NetworkPolicy::Action::Throttle
              && pinned.winner.origin == QStringLiteral("pinned"),
          QStringLiteral("the pinned action and origin are reported"));
    check(pinned.conflict.hasConflict && pinned.conflict.conflictingTier == 2,
          QStringLiteral("the disagreeing session is reported as a tier-2 conflict"));
    checkEqual(pinned.conflict.resolution, QStringLiteral("higher_tier_won"),
               QStringLiteral("the conflict records that the higher tier won"));
    check(pin.action == NetworkPolicy::Action::Throttle
              && pin.domainPattern == QStringLiteral("*.visualstudio.com"),
          QStringLiteral("the pinned rule is not mutated by the conflict"));

    // A session alone is tier 2.
    const RuleResolution sessionOnly = RuleResolver::resolve(
        observation, QList<PinnedRule>(), QList<SessionOverride>() << session, now);
    check(sessionOnly.matched && sessionOnly.winner.tier == 2
              && sessionOnly.winner.origin == QStringLiteral("session"),
          QStringLiteral("a session override is tier 2"));
    check(!sessionOnly.conflict.hasConflict,
          QStringLiteral("a session winner has no lower-tier conflict here"));

    // A disagreeing lower tier is reported without touching the pin.
    LowerTierVote vote;
    vote.tier = 3;
    vote.action = NetworkPolicy::Action::Block;
    vote.source = QStringLiteral("profile");
    const RuleResolution lower = RuleResolver::resolve(
        observation, QList<PinnedRule>() << pin, QList<SessionOverride>(), now,
        QList<LowerTierVote>() << vote);
    check(lower.conflict.hasConflict && lower.conflict.conflictingTier == 3,
          QStringLiteral("a disagreeing profile tier is reported as a conflict"));
    check(pin.action == NetworkPolicy::Action::Throttle,
          QStringLiteral("a lower-tier conflict leaves the pin unchanged"));

    LowerTierVote agreeing;
    agreeing.tier = 3;
    agreeing.action = NetworkPolicy::Action::Throttle;
    agreeing.source = QStringLiteral("profile");
    const RuleResolution noConflict = RuleResolver::resolve(
        observation, QList<PinnedRule>() << pin, QList<SessionOverride>(), now,
        QList<LowerTierVote>() << agreeing);
    check(!noConflict.conflict.hasConflict,
          QStringLiteral("a lower tier that agrees is not a conflict"));

    // Wildcard semantics and exact-over-wildcard selection.
    check(RuleResolver::domainPatternMatches(QStringLiteral("*.example.com"),
                                             QStringLiteral("cdn.example.com")),
          QStringLiteral("a wildcard matches a subdomain"));
    check(!RuleResolver::domainPatternMatches(QStringLiteral("*.example.com"),
                                              QStringLiteral("example.com")),
          QStringLiteral("a wildcard does not match the apex"));
    check(RuleResolver::domainPatternMatches(QStringLiteral("*"),
                                             QStringLiteral("anything.example")),
          QStringLiteral("a full wildcard matches a known domain"));
    check(!RuleResolver::domainPatternMatches(QStringLiteral("*"), QString()),
          QStringLiteral("an unknown domain matches no domain pattern"));
    check(RuleResolver::domainPatternMatches(QStringLiteral("Example.COM."),
                                             QStringLiteral("example.com")),
          QStringLiteral("exact domain matching is normalized"));

    PinnedRule exact = makePinnedRule(QStringLiteral("code.exe"),
                                      QStringLiteral("update.code.visualstudio.com"),
                                      NetworkPolicy::Action::Allow);
    exact.id = QStringLiteral("pin_3333333333333333");
    exact.createdAt = now;
    PinnedRule broad = makePinnedRule(QStringLiteral("code.exe"),
                                      QStringLiteral("*.visualstudio.com"),
                                      NetworkPolicy::Action::Block);
    broad.id = QStringLiteral("pin_4444444444444444");
    broad.createdAt = now;
    const RuleResolution specific = RuleResolver::resolve(
        observation, QList<PinnedRule>() << broad << exact, QList<SessionOverride>(), now);
    checkEqual(specific.winner.ruleId, exact.id,
               QStringLiteral("an exact domain pin beats a wildcard pin"));

    PinnedRule expired = pin;
    expired.id = QStringLiteral("pin_5555555555555555");
    expired.expiresAt = now.addSecs(-1);
    check(!RuleResolver::resolve(observation, QList<PinnedRule>() << expired,
                                 QList<SessionOverride>(), now).matched,
          QStringLiteral("an expired pin does not match"));

    FlowObservation unknownDomain = observation;
    unknownDomain.flow.domain.clear();
    check(!RuleResolver::resolve(unknownDomain, QList<PinnedRule>() << pin,
                                 QList<SessionOverride>(), now).matched,
          QStringLiteral("an unknown domain does not match a domain pin"));

    clearPinnedRuleStore();
}

// ─── DS-006: local signatures and profile rules ─────────────────────────────

void testLocalSignatures()
{
    FlowObservation updaterObservation = makeMilestoneObservation(
        QStringLiteral("flow_aaaaaaaaaaaaaaaa"), QStringLiteral("pid:100:1000"),
        QStringLiteral("update.googleapis.com"), 12 * VolumeMilestone::kMiB);
    updaterObservation.process.exeName = QStringLiteral("chromeupdate.exe");
    updaterObservation.process.foregroundState = FlowForegroundState::Background;
    updaterObservation.process.interactionState = FlowInteractionState::Idle;

    ActivityQuery updaterQuery;
    updaterQuery.executableName = QStringLiteral("chromeupdate.exe");
    updaterQuery.publisher = QStringLiteral("Google LLC");
    updaterQuery.publisherVerified = true;
    updaterQuery.product = QStringLiteral("Google Update");
    updaterQuery.displayName = QStringLiteral("Google Update");
    updaterQuery.domain = QStringLiteral("update.googleapis.com");

    LocalSignatureInput updaterInput;
    updaterInput.observation = updaterObservation;
    updaterInput.activity = updaterQuery;

    LocalSignatureEngine engine;
    const SignatureResult background = engine.classify(updaterInput);
    check(background.classification == SignatureClassification::AppUpdate,
          QStringLiteral("a known browser updater is classified as an app update"));
    check(background.confidence > 0.70,
          QStringLiteral("a catalog match carries usable confidence"));
    check(!background.matchedSignatureIds.isEmpty(),
          QStringLiteral("the signature match is named"));
    check(background.detectorTags.contains(QStringLiteral("browser_update_signature")),
          QStringLiteral("a browser updater gets its detector tag"));
    check(background.action == NetworkPolicy::Action::Throttle
              && background.rateBitsPerSecond == 409600,
          QStringLiteral("background updates recommend the canonical gentle throttle"));
    check(!background.advisoryOnly,
          QStringLiteral("a throttle recommendation is not advisory-only"));
    check(!background.profileRuleId.isEmpty()
              && background.reason.contains(QStringLiteral("signatures:")),
          QStringLiteral("the profile match is explainable"));

    // Foreground-active traffic is never throttled.
    FlowObservation activeObservation = updaterObservation;
    activeObservation.process.foregroundState = FlowForegroundState::ForegroundActive;
    activeObservation.process.interactionState = FlowInteractionState::Interactive;
    updaterInput.observation = activeObservation;
    const SignatureResult active = engine.classify(updaterInput);
    check(active.foreground == ProfileForeground::Active,
          QStringLiteral("fresh interaction evidence gives foreground-active"));
    check(active.action == NetworkPolicy::Action::Notify
              && active.continueAfterNotify && active.advisoryOnly,
          QStringLiteral("a foreground updater is notify-only"));

    // A visible app with no interaction evidence is foreground-idle.
    FlowObservation idleObservation = updaterObservation;
    idleObservation.process.foregroundState = FlowForegroundState::ForegroundActive;
    idleObservation.process.interactionState = FlowInteractionState::Idle;
    updaterInput.observation = idleObservation;
    const SignatureResult idle = engine.classify(updaterInput);
    check(idle.foreground == ProfileForeground::Idle,
          QStringLiteral("idle interaction gives foreground-idle"));
    check(idle.action == NetworkPolicy::Action::Notify,
          QStringLiteral("a foreground-idle updater is not throttled"));

    // Stale or missing foreground evidence is unknown, never guessed.
    FlowObservation staleObservation = updaterObservation;
    staleObservation.process.foregroundState = FlowForegroundState::Unknown;
    staleObservation.process.interactionState = FlowInteractionState::Unknown;
    updaterInput.observation = staleObservation;
    const SignatureResult stale = engine.classify(updaterInput);
    check(stale.foreground == ProfileForeground::Unknown,
          QStringLiteral("stale foreground evidence stays unknown"));
    check(stale.action != NetworkPolicy::Action::Throttle
              && stale.action != NetworkPolicy::Action::Block,
          QStringLiteral("unknown foreground evidence never throttles or blocks"));

    // Protected services are allow-only.
    FlowObservation serviceObservation = updaterObservation;
    serviceObservation.process.exeName = QStringLiteral("svchost.exe");
    serviceObservation.process.role = FlowProcessRole::Service;
    serviceObservation.flow.domain.clear();
    ActivityQuery serviceQuery;
    serviceQuery.executableName = QStringLiteral("svchost.exe");
    serviceQuery.service = true;
    LocalSignatureInput serviceInput;
    serviceInput.observation = serviceObservation;
    serviceInput.activity = serviceQuery;
    const SignatureResult service = engine.classify(serviceInput);
    check(service.detectorTags.contains(QStringLiteral("protected_signature")),
          QStringLiteral("a protected service is tagged as protected"));
    check(service.action == NetworkPolicy::Action::Allow && service.advisoryOnly,
          QStringLiteral("a protected service is advisory-only"));

    // Latency-sensitive activity cannot be throttled or blocked.
    FlowObservation latencyObservation = updaterObservation;
    latencyObservation.uxSignals.latencySensitive = true;
    updaterInput.observation = latencyObservation;
    const SignatureResult latency = engine.classify(updaterInput);
    check(latency.detectorTags.contains(QStringLiteral("latency_sensitive_signature")),
          QStringLiteral("a latency-sensitive signal is tagged"));
    check(latency.action == NetworkPolicy::Action::Notify && latency.advisoryOnly,
          QStringLiteral("latency-sensitive activity is notify-only"));

    // Unknown activity gets a conservative notify and is not a signature match.
    FlowObservation unknownObservation = makeMilestoneObservation(
        QStringLiteral("flow_bbbbbbbbbbbbbbbb"), QStringLiteral("pid:200:1000"),
        QString(), 1 * VolumeMilestone::kMiB);
    unknownObservation.process.exeName = QStringLiteral("mystery.exe");
    unknownObservation.process.foregroundState = FlowForegroundState::Background;
    ActivityQuery unknownQuery;
    unknownQuery.executableName = QStringLiteral("mystery.exe");
    LocalSignatureInput unknownInput;
    unknownInput.observation = unknownObservation;
    unknownInput.activity = unknownQuery;
    const SignatureResult unknown = engine.classify(unknownInput);
    check(unknown.classification == SignatureClassification::Unknown
              && !unknown.matched,
          QStringLiteral("an unlisted executable stays unknown"));
    check(unknown.detectorTags.contains(QStringLiteral("unknown_signature"))
              && unknown.action == NetworkPolicy::Action::Notify
              && unknown.advisoryOnly,
          QStringLiteral("unknown activity gets a conservative notification"));

    // A package-manager catalog rule drives the package-install profile.
    EndpointCatalog catalog;
    CatalogRule packageRule;
    packageRule.id = QStringLiteral("test-package-install");
    packageRule.category = CatalogCategory::PackageManager;
    packageRule.executableName = QStringLiteral("setup.exe");
    packageRule.explanation = QStringLiteral("Test package installer");
    QString error;
    check(catalog.upsertRule(packageRule, &error),
          QStringLiteral("the test package rule is valid: %1").arg(error));
    LocalSignatureEngine packageEngine(catalog, defaultProfileRules());

    FlowObservation packageObservation = makeMilestoneObservation(
        QStringLiteral("flow_cccccccccccccccc"), QStringLiteral("pid:300:1000"),
        QString(), 12 * VolumeMilestone::kMiB);
    packageObservation.process.exeName = QStringLiteral("setup.exe");
    packageObservation.process.foregroundState = FlowForegroundState::ForegroundActive;
    packageObservation.process.interactionState = FlowInteractionState::Interactive;
    ActivityQuery packageQuery;
    packageQuery.executableName = QStringLiteral("setup.exe");
    LocalSignatureInput packageInput;
    packageInput.observation = packageObservation;
    packageInput.activity = packageQuery;
    const SignatureResult interactivePackage = packageEngine.classify(packageInput);
    check(interactivePackage.classification == SignatureClassification::PackageInstall,
          QStringLiteral("a package manager is classified as a package install"));
    check(interactivePackage.action == NetworkPolicy::Action::Allow
              && interactivePackage.advisoryOnly,
          QStringLiteral("an interactive package install is allowed"));

    packageObservation.process.foregroundState = FlowForegroundState::Background;
    packageObservation.process.interactionState = FlowInteractionState::Idle;
    packageInput.observation = packageObservation;
    const SignatureResult backgroundPackage = packageEngine.classify(packageInput);
    check(backgroundPackage.action == NetworkPolicy::Action::Notify
              && backgroundPackage.action != NetworkPolicy::Action::Block,
          QStringLiteral("a background package install is notify-only"));

    // A custom profile change is applied and explainable.
    ProfileRule custom;
    custom.id = QStringLiteral("profile_custom_app_update");
    custom.detectorTag = QStringLiteral("app_update_signature");
    custom.foreground = ProfileForeground::Background;
    custom.classification = SignatureClassification::AppUpdate;
    custom.action = NetworkPolicy::Action::Notify;
    custom.continueAfterNotify = true;
    custom.scope = QStringLiteral("executable");
    custom.advisoryOnly = true;
    LocalSignatureEngine profileEngine;
    check(profileEngine.setProfileRules(QList<ProfileRule>() << custom, &error),
          QStringLiteral("a custom profile is accepted: %1").arg(error));
    updaterInput.observation = updaterObservation;
    const SignatureResult customResult = profileEngine.classify(updaterInput);
    check(customResult.action == NetworkPolicy::Action::Notify
              && customResult.profileRuleId == custom.id,
          QStringLiteral("the custom profile changes the recommendation"));

    ProfileRule invalidRule = custom;
    invalidRule.id.clear();
    check(!profileEngine.setProfileRules(QList<ProfileRule>() << invalidRule, &error),
          QStringLiteral("an invalid profile rule is rejected"));
    check(profileEngine.profileRules().size() == 1
              && profileEngine.profileRules().first().id == custom.id,
          QStringLiteral("a rejected profile change leaves the active profile untouched"));

    // Even a custom block rule is downgraded for an active package install.
    ProfileRule blockRule;
    blockRule.id = QStringLiteral("profile_block_package");
    blockRule.detectorTag = QStringLiteral("package_install_signature");
    blockRule.foreground = ProfileForeground::Active;
    blockRule.classification = SignatureClassification::PackageInstall;
    blockRule.action = NetworkPolicy::Action::Block;
    blockRule.scope = QStringLiteral("executable");
    blockRule.minimumConfidence = 0.0;
    check(packageEngine.setProfileRules(QList<ProfileRule>() << blockRule, &error),
          QStringLiteral("the custom block profile is accepted: %1").arg(error));
    packageObservation.process.foregroundState = FlowForegroundState::ForegroundActive;
    packageObservation.process.interactionState = FlowInteractionState::Interactive;
    packageInput.observation = packageObservation;
    const SignatureResult guarded = packageEngine.classify(packageInput);
    check(guarded.action == NetworkPolicy::Action::Notify
              && guarded.reason.contains(QStringLiteral("guards:")),
          QStringLiteral("a package install block is downgraded to a notice"));
}

// ─── DS-008: fixed precedence and safe fallback ─────────────────────────────

void testDataSaverDecisionResolver()
{
    using namespace DataSaverDecision;
    using Action = NetworkPolicy::Action;

    DecisionResolver resolver;
    const QDateTime now = flowTestTime();

    FlowObservation observation = makeMilestoneObservation(
        QStringLiteral("flow_aaaaaaaaaaaaaaaa"), QStringLiteral("pid:100:1000"),
        QStringLiteral("update.googleapis.com"), 12 * VolumeMilestone::kMiB);
    observation.metrics.milestoneBytes = 12 * VolumeMilestone::kMiB;
    observation.metrics.milestoneIndex = 1;
    observation.process.exeName = QStringLiteral("chromeupdate.exe");
    observation.process.foregroundState = FlowForegroundState::Background;

    ActivityQuery query;
    query.executableName = QStringLiteral("chromeupdate.exe");
    query.publisher = QStringLiteral("Google LLC");
    query.publisherVerified = true;
    query.product = QStringLiteral("Google Update");
    query.displayName = QStringLiteral("Google Update");
    query.domain = QStringLiteral("update.googleapis.com");

    ResolverInput input;
    input.signature.observation = observation;
    input.signature.activity = query;
    input.mode = DataSaverMode::Mode::Enforce;
    input.now = now;
    input.gentleThrottleAvailable = true;

    // Tier 3 is the DS-006 recommendation, converted into a validated decision.
    const DecisionResolution profile = resolver.resolve(input);
    check(profile.evaluated && !profile.automationSuppressed,
          QStringLiteral("Enforce produces an automatic decision"));
    check(profile.decision.origin == DecisionOrigin::Profile
              && profile.decision.tier == 3,
          QStringLiteral("the DS-006 recommendation is tier 3"));
    check(profile.decision.action == Action::Throttle
              && profile.decision.rateBitsPerSecond == 409600,
          QStringLiteral("a background updater resolves to the canonical gentle throttle"));
    check(profile.decision.classification == SignatureClassification::AppUpdate
              && profile.decision.confidence > 0.70,
          QStringLiteral("the profile decision keeps its classification and confidence"));
    check(profile.decision.target.domain == QStringLiteral("update.googleapis.com"),
          QStringLiteral("the decision carries the attributed domain"));
    check(!profile.matchedRuleId.isEmpty() && profile.matchedCacheKey.isEmpty(),
          QStringLiteral("the profile resolution reports the matched rule, not a cache key"));
    QString error;
    check(profile.decision.validate(&error),
          QStringLiteral("the profile decision passes local validation: %1").arg(error));

    PolicyDecision parsed;
    check(PolicyDecision::fromJson(profile.decision.toJson(), &parsed, &error),
          QStringLiteral("the decision round-trips through the v1 contract: %1").arg(error));
    check(parsed.decisionId == profile.decision.decisionId
              && parsed.origin == DecisionOrigin::Profile
              && parsed.action == Action::Throttle
              && parsed.rateBitsPerSecond == 409600,
          QStringLiteral("the round-trip keeps identity, origin, and rate"));

    // A pinned user rule wins and the profile disagreement is reported, not applied.
    PinnedRule pin = makePinnedRule(QStringLiteral("chromeupdate.exe"),
                                    QStringLiteral("*"), Action::Allow);
    pin.id = QStringLiteral("pin_1111111111111111");
    pin.createdAt = now;
    input.pinnedRules << pin;
    const DecisionResolution pinned = resolver.resolve(input);
    check(pinned.evaluated && pinned.decision.origin == DecisionOrigin::Pinned
              && pinned.decision.tier == 1,
          QStringLiteral("a pinned rule wins over the profile recommendation"));
    check(pinned.decision.action == Action::Allow
              && pinned.decision.rateBitsPerSecond == 0,
          QStringLiteral("the pinned allow is applied without a rate"));
    checkEqual(pinned.matchedRuleId, pin.id,
               QStringLiteral("the pinned resolution reports the winning rule id"));
    check(pinned.decision.confidence == 1.0,
          QStringLiteral("a user decision carries confidence 1.0"));
    check(pinned.decision.conflict.hasConflict
              && pinned.decision.conflict.conflictingTier == 3
              && pinned.decision.conflict.resolution == QStringLiteral("higher_tier_won"),
          QStringLiteral("the lower-profile disagreement is reported"));
    check(pinned.decision.validate(&error),
          QStringLiteral("the pinned decision validates: %1").arg(error));

    // Off still honors the pin but never evaluates automation.
    input.mode = DataSaverMode::Mode::Off;
    const DecisionResolution offWithPin = resolver.resolve(input);
    check(offWithPin.evaluated && offWithPin.automationSuppressed
              && offWithPin.decision.tier == 1,
          QStringLiteral("Off keeps the pinned decision and withholds automation"));
    input.pinnedRules.clear();
    const DecisionResolution suppressed = resolver.resolve(input);
    check(!suppressed.evaluated && suppressed.automationSuppressed
              && suppressed.decision.decisionId.isEmpty(),
          QStringLiteral("Off produces no automatic decision"));

    // A session override is tier 2 and also reports the profile conflict.
    input.mode = DataSaverMode::Mode::Enforce;
    SessionOverride session;
    session.id = QStringLiteral("ses_2222222222222222");
    session.scope = SessionScope::ExecutableDomain;
    session.executable = QStringLiteral("chromeupdate.exe");
    session.domainPattern = QStringLiteral("*");
    session.action = Action::Allow;
    session.createdAt = now;
    input.sessionOverrides << session;
    const DecisionResolution sessionOnly = resolver.resolve(input);
    check(sessionOnly.decision.origin == DecisionOrigin::Session
              && sessionOnly.decision.tier == 2,
          QStringLiteral("a session override is tier 2"));
    check(sessionOnly.decision.conflict.hasConflict
              && sessionOnly.decision.conflict.conflictingTier == 3,
          QStringLiteral("the session decision reports the profile disagreement"));
    input.sessionOverrides.clear();

    // Foreground-active traffic is downgraded to an advisory notice.
    FlowObservation active = observation;
    active.process.foregroundState = FlowForegroundState::ForegroundActive;
    active.process.interactionState = FlowInteractionState::Interactive;
    input.signature.observation = active;
    const DecisionResolution activeResolution = resolver.resolve(input);
    check(activeResolution.decision.action == Action::Notify
              && activeResolution.decision.continueAfterNotify,
          QStringLiteral("a foreground profile match is notify-then-continue"));
    check(activeResolution.decision.validate(&error),
          QStringLiteral("the foreground notice validates: %1").arg(error));
    input.signature.observation = observation;

    // The cache seam is tier 4 and is rejected when it targets another app.
    EndpointCatalog emptyCatalog;
    const QList<ProfileRule> noProfileRules;
    LocalSignatureEngine emptyEngine(emptyCatalog, noProfileRules);
    DecisionResolver emptyProfile(emptyEngine);
    PolicyDecision cached;
    cached.origin = DecisionOrigin::Cache;
    cached.tier = 4;
    cached.decisionId = QStringLiteral("dec_3333333333333333");
    cached.observationId = observation.observationId;
    cached.createdAt = now;
    cached.action = Action::Throttle;
    cached.scope = DecisionScope::Executable;
    cached.target.executable = QStringLiteral("chromeupdate.exe");
    cached.target.domain = QStringLiteral("update.googleapis.com");
    cached.direction = NetworkDirection::Download;
    cached.rateBitsPerSecond = 409600;
    cached.confidence = 0.90;
    cached.classification = SignatureClassification::AppUpdate;
    cached.evidence.foregroundState = QStringLiteral("background");
    cached.evidence.uxProfile = QStringLiteral("cached_app_update");
    cached.evidence.domainConfidence = QStringLiteral("strong_inference");
    cached.reasonShort = QStringLiteral("Cached local profile decision.");
    input.cachedDecision = &cached;

    const DecisionResolution cachedResolution = emptyProfile.resolve(input);
    check(cachedResolution.decision.origin == DecisionOrigin::Cache
              && cachedResolution.decision.tier == 4
              && cachedResolution.decision.action == Action::Throttle,
          QStringLiteral("a valid cache candidate is used as tier 4"));
    check(cachedResolution.decision.validate(&error),
          QStringLiteral("the cache decision validates after reuse: %1").arg(error));

    cached.target.executable = QStringLiteral("other.exe");
    const DecisionResolution mismatched = emptyProfile.resolve(input);
    check(mismatched.decision.origin == DecisionOrigin::Fallback
              && mismatched.decision.tier == 5,
          QStringLiteral("a cache candidate for another executable is ignored"));
    check(mismatched.diagnostic.contains(QStringLiteral("different executable")),
          QStringLiteral("the ignored cache candidate is explained"));

    // Without an enforceable channel the fallback stays notify-only.
    input.cachedDecision = nullptr;
    input.gentleThrottleAvailable = false;
    const DecisionResolution notifyFallback = emptyProfile.resolve(input);
    check(notifyFallback.decision.origin == DecisionOrigin::Fallback
              && notifyFallback.decision.action == Action::Notify
              && notifyFallback.decision.continueAfterNotify,
          QStringLiteral("the fallback is notify-only without channel ownership"));

    // Malformed or unsafe contract payloads are rejected whole.
    const QJsonObject decisionJson = profile.decision.toJson();
    QJsonObject newer = decisionJson;
    newer.insert(QStringLiteral("schemaVersion"), 2);
    check(!PolicyDecision::fromJson(newer, &parsed, &error),
          QStringLiteral("a newer decision schema is rejected"));

    QJsonObject badAction = decisionJson;
    badAction.insert(QStringLiteral("action"), QStringLiteral("drop"));
    check(!PolicyDecision::fromJson(badAction, &parsed, &error),
          QStringLiteral("an unknown decision action is rejected"));

    QJsonObject noTarget = decisionJson;
    noTarget.remove(QStringLiteral("target"));
    check(!PolicyDecision::fromJson(noTarget, &parsed, &error),
          QStringLiteral("a decision without a target is rejected"));

    QJsonObject weakBlock = decisionJson;
    weakBlock.remove(QStringLiteral("throttle"));
    weakBlock.insert(QStringLiteral("origin"), QStringLiteral("profile"));
    weakBlock.insert(QStringLiteral("tier"), 3);
    weakBlock.insert(QStringLiteral("action"), QStringLiteral("block"));
    weakBlock.insert(QStringLiteral("confidence"), 0.90);
    QJsonObject weakEvidence = weakBlock.value(QStringLiteral("evidenceSummary")).toObject();
    weakEvidence.insert(QStringLiteral("domainConfidence"), QStringLiteral("weak_inference"));
    weakBlock.insert(QStringLiteral("evidenceSummary"), weakEvidence);
    check(!PolicyDecision::fromJson(weakBlock, &parsed, &error),
          QStringLiteral("an automatic block on weak domain evidence is rejected"));

    // A cache-supplied block cannot bypass the profile-origin requirement.
    PolicyDecision cachedBlock = cached;
    cachedBlock.target.executable = QStringLiteral("chromeupdate.exe");
    cachedBlock.action = Action::Block;
    cachedBlock.rateBitsPerSecond = 0;
    cachedBlock.confidence = 0.95;
    input.cachedDecision = &cachedBlock;
    const DecisionResolution blocked = emptyProfile.resolve(input);
            check(blocked.decision.origin == DecisionOrigin::Fallback
              && blocked.decision.action != Action::Block,
          QStringLiteral("a cached block is rejected and the fallback stays safe"));
}

PolicyDecision makeCacheableProfileDecision(const FlowObservation &observation)
{
    using namespace DataSaverDecision;

    PolicyDecision decision;
    decision.decisionId = QStringLiteral("dec_4444444444444444");
    decision.observationId = observation.observationId;
    decision.createdAt = flowTestTime();
    decision.origin = DecisionOrigin::Profile;
    decision.tier = 3;
    decision.action = NetworkPolicy::Action::Throttle;
    decision.scope = DecisionScope::Executable;
    decision.target.executable = QStringLiteral("Code.exe");
    decision.target.domain = observation.flow.domain;
    decision.direction = NetworkDirection::Download;
    decision.rateBitsPerSecond = 409600;
    decision.confidence = 0.94;
    decision.classification = SignatureClassification::AppUpdate;
    decision.evidence.executable = QStringLiteral("code.exe");
    decision.evidence.domain = observation.flow.domain;
    decision.evidence.foregroundState = QStringLiteral("background");
    decision.evidence.uxProfile = QStringLiteral("deferrable_non_blocking");
    decision.evidence.domainConfidence = QStringLiteral("strong_inference");
    decision.reasonShort = QStringLiteral("The local profile matched a background updater.");
    return decision;
}

void testDataSaverDecisionCache()
{
    using namespace DataSaverCache;
    using Action = NetworkPolicy::Action;

    // The contract's receive and duration buckets.
    checkEqual(receiveBucket(9 * VolumeMilestone::kMiB), QStringLiteral("below_10MB"),
               QStringLiteral("bytes below 10 MiB use the pre-milestone bucket"));
    checkEqual(receiveBucket(10 * VolumeMilestone::kMiB), QStringLiteral("10_25MB"),
               QStringLiteral("10 MiB starts the 10_25MB bucket"));
    checkEqual(receiveBucket(25 * VolumeMilestone::kMiB - 1), QStringLiteral("10_25MB"),
               QStringLiteral("one byte below 25 MiB is still 10_25MB"));
    checkEqual(receiveBucket(25 * VolumeMilestone::kMiB), QStringLiteral("25_50MB"),
               QStringLiteral("25 MiB starts the 25_50MB bucket"));
    checkEqual(receiveBucket(50 * VolumeMilestone::kMiB), QStringLiteral("50_100MB"),
               QStringLiteral("50 MiB starts the 50_100MB bucket"));
    checkEqual(receiveBucket(100 * VolumeMilestone::kMiB), QStringLiteral("100MB_plus"),
               QStringLiteral("100 MiB starts the 100MB_plus bucket"));
    checkEqual(durationBucket(9999), QStringLiteral("burst_<10s"),
               QStringLiteral("under ten seconds is a burst"));
    checkEqual(durationBucket(10000), QStringLiteral("sustained_10_60s"),
               QStringLiteral("ten seconds starts the sustained bucket"));
    checkEqual(durationBucket(60000), QStringLiteral("long_>60s"),
               QStringLiteral("sixty seconds starts the long bucket"));

    FlowObservation observation = makeMilestoneObservation(
        QStringLiteral("flow_aaaaaaaaaaaaaaaa"), QStringLiteral("pid:100:1000"),
        QStringLiteral("update.googleapis.com"), 12 * VolumeMilestone::kMiB);
    observation.process.exeName = QStringLiteral("Code.exe");
    observation.process.exeVersion = QStringLiteral("1.95.2");
    observation.process.role = FlowProcessRole::Child;
    observation.metrics.durationMs = 30000;

    CacheContext context;
    context.catalogVersion = QStringLiteral("2026.11.11");

    const CacheKey key = buildCacheKey(observation, context);
    checkEqual(key.executableKey, QStringLiteral("code.exe@1.95.2"),
               QStringLiteral("the executable key is the base name plus version"));
    checkEqual(key.domainKey, QStringLiteral("update.googleapis.com"),
               QStringLiteral("the domain key is normalized"));
    checkEqual(key.processRole, QStringLiteral("child"),
               QStringLiteral("the process role is part of the key"));
    checkEqual(key.receiveBucket, QStringLiteral("10_25MB"),
               QStringLiteral("the receive bucket is part of the key"));
    checkEqual(key.durationBucket, QStringLiteral("sustained_10_60s"),
               QStringLiteral("the duration bucket is part of the key"));
    checkEqual(key.source, QStringLiteral("manual_toggle"),
               QStringLiteral("the Data Saver source is part of the key"));
    checkEqual(key.canonical(), buildCacheKey(observation, context).canonical(),
               QStringLiteral("the same evidence produces the same canonical key"));

    const QString fingerprint = fingerprintFor(key);
    check(fingerprint.startsWith(QStringLiteral("fp_")),
          QStringLiteral("the fingerprint uses the fp_ prefix"));
    checkEqual(static_cast<int>(fingerprint.size()), 67,
               QStringLiteral("the fingerprint is fp_ plus 64 SHA-256 hex characters"));
    checkEqual(fingerprint.mid(3), fingerprint.mid(3).toLower(),
               QStringLiteral("the fingerprint hash is lower-case hex"));

    const QDateTime now = flowTestTime();
    const PolicyDecision decision = makeCacheableProfileDecision(observation);
    QString error;
    check(decision.validate(&error),
          QStringLiteral("the profile decision used as cache input validates: %1").arg(error));

    DecisionCache cache;
    check(cache.insert(observation, context, decision, QStringLiteral("audit_1234"),
                       now, &error),
          QStringLiteral("a valid profile decision is cached: %1").arg(error));
    checkEqual(cache.count(), 1, QStringLiteral("the cache holds one entry"));

    const CacheEntry stored = cache.entries().value(0);
    checkEqual(stored.schemaVersion, DataSaverCache::kSchemaVersion,
               QStringLiteral("the entry records its schema version"));
    checkEqual(stored.fingerprint, fingerprint,
               QStringLiteral("the entry records the computed fingerprint"));
    checkEqual(stored.observationId, observation.observationId,
               QStringLiteral("the entry records the source observation"));
    checkEqual(stored.decisionId, decision.decisionId,
               QStringLiteral("the entry records the decision id"));
    checkEqual(stored.auditId, QStringLiteral("audit_1234"),
               QStringLiteral("the entry keeps its audit link"));
    checkEqual(stored.catalogVersion, QStringLiteral("2026.11.11"),
               QStringLiteral("the entry records the catalog version"));
    checkEqual(stored.createdAt, now.toUTC(),
               QStringLiteral("the entry records its creation time"));
    checkEqual(stored.expiresAt, now.toUTC().addSecs(DataSaverCache::kProfileTtlSeconds),
               QStringLiteral("a local profile entry lives for 30 days"));
    checkEqual(ttlSeconds(DecisionOrigin::Profile, 0.20, false),
               DataSaverCache::kProfileTtlSeconds,
               QStringLiteral("the profile TTL does not depend on confidence"));
    checkEqual(ttlSeconds(DecisionOrigin::Pinned, 1.0, true), qint64(0),
               QStringLiteral("pinned decisions are never cached"));
    checkEqual(ttlSeconds(DecisionOrigin::Session, 1.0, true), qint64(0),
               QStringLiteral("session decisions are never cached"));
    checkEqual(ttlSeconds(DecisionOrigin::Fallback, 0.40, false), qint64(0),
               QStringLiteral("fallback decisions are never cached"));

    PolicyDecision hit;
    check(cache.lookup(observation, context, &hit, now.addDays(29), &error),
          QStringLiteral("the entry is reused inside its TTL: %1").arg(error));
    check(hit.origin == DecisionOrigin::Cache && hit.tier == 4,
          QStringLiteral("a hit is returned as a tier-4 cache candidate"));
    checkEqual(hit.decisionId, decision.decisionId,
               QStringLiteral("the hit keeps the cached decision identity"));
    check(hit.action == Action::Throttle && hit.rateBitsPerSecond == 409600,
          QStringLiteral("the hit carries the cached outcome and rate"));
    check(hit.validate(&error),
          QStringLiteral("the cache candidate validates locally: %1").arg(error));

    // The TTL boundary is exclusive: at exactly expiresAt the entry is gone.
    check(!cache.lookup(observation, context, &hit,
                        now.addSecs(DataSaverCache::kProfileTtlSeconds), &error),
          QStringLiteral("the entry expires at its TTL boundary"));
    checkEqual(cache.count(), 0, QStringLiteral("an expired entry is discarded"));

    // Every key dimension invalidates the entry rather than matching it.
    const auto reinsert = [&]() {
        cache.clear();
        return cache.insert(observation, context, decision, QString(), now, &error);
    };
    const auto lookupWith = [&](const FlowObservation &changed,
                                const CacheContext &changedContext) {
        PolicyDecision candidate;
        return cache.lookup(changed, changedContext, &candidate, now, &error);
    };
    const auto lookupAgainstDefaultContext = [&](const FlowObservation &changed) {
        return lookupWith(changed, context);
    };

    check(reinsert(), QStringLiteral("the entry is reinserted for invalidation checks"));
    FlowObservation changed = observation;
    changed.process.exeVersion = QStringLiteral("1.96.0");
    check(!lookupAgainstDefaultContext(changed),
          QStringLiteral("an executable version change misses"));

    changed = observation;
    changed.flow.domain = QStringLiteral("example.com");
    check(!lookupAgainstDefaultContext(changed), QStringLiteral("a domain change misses"));

    changed = observation;
    changed.process.role = FlowProcessRole::Service;
    check(!lookupAgainstDefaultContext(changed),
          QStringLiteral("a process role change misses"));

    changed = observation;
    changed.process.foregroundState = FlowForegroundState::ForegroundActive;
    check(!lookupAgainstDefaultContext(changed),
          QStringLiteral("a foreground change misses"));

    changed = observation;
    changed.metrics.rxBytes = 30 * VolumeMilestone::kMiB;
    check(!lookupAgainstDefaultContext(changed),
          QStringLiteral("a receive bucket change misses"));

    changed = observation;
    changed.metrics.durationMs = 5 * 1000;
    check(!lookupAgainstDefaultContext(changed),
          QStringLiteral("a duration bucket change misses"));

    check(reinsert(), QStringLiteral("the entry is reinserted for a source change"));
    CacheContext hotspot = context;
    hotspot.source = CacheSource::MeteredHotspot;
    check(!lookupWith(observation, hotspot),
          QStringLiteral("a Data Saver source change misses"));
    checkEqual(cache.count(), 1,
               QStringLiteral("a key miss leaves the original entry in place"));

    // A catalog change is not in the key; it invalidates and removes the entry.
    CacheContext newerCatalog = context;
    newerCatalog.catalogVersion = QStringLiteral("2027.01.01");
    check(!lookupWith(observation, newerCatalog),
          QStringLiteral("a catalog version change invalidates the entry"));
    checkEqual(cache.count(), 0, QStringLiteral("the invalidated entry is removed"));

    // A flow with no domain uses the address fallback token.
    FlowObservation noDomain = makeMilestoneObservation(
        QStringLiteral("flow_bbbbbbbbbbbbbbbb"), QStringLiteral("pid:100:1000"),
        QString(), 12 * VolumeMilestone::kMiB);
    noDomain.process.exeName = QStringLiteral("Code.exe");
    const CacheKey addressKey = buildCacheKey(noDomain, CacheContext());
    checkEqual(addressKey.domainKey, QStringLiteral("addr:13.107.246.40"),
               QStringLiteral("a missing domain falls back to the remote address"));

    // Uncacheable or mismatched inputs are refused, not normalized.
    DecisionCache rejections;
    PolicyDecision pinned = decision;
    pinned.origin = DecisionOrigin::Pinned;
    pinned.tier = 1;
    pinned.confidence = 1.0;
    check(!rejections.insert(observation, context, pinned, QString(), now, &error),
          QStringLiteral("a pinned decision is refused"));

    PolicyDecision block = decision;
    block.action = Action::Block;
    block.rateBitsPerSecond = 0;
    check(block.validate(&error),
          QStringLiteral("the test block decision validates as a profile block: %1").arg(error));
    check(!rejections.insert(observation, context, block, QString(), now, &error),
          QStringLiteral("a block decision is refused by the cache"));

    PolicyDecision other = decision;
    other.target.executable = QStringLiteral("other.exe");
    check(!rejections.insert(observation, context, other, QString(), now, &error),
          QStringLiteral("a decision for another executable is refused"));
    checkEqual(rejections.count(), 0, QStringLiteral("no refused decision was stored"));

    // Entries serialize without payload or path fields and round-trip.
    const QJsonObject entryJson = cacheEntryToJson(stored);
    const QString serialized = QString::fromUtf8(
        QJsonDocument(entryJson).toJson(QJsonDocument::Compact));
    check(!serialized.contains(QStringLiteral("exePath"))
              && !serialized.contains(QStringLiteral("192.168.1.100"))
              && !serialized.contains(QStringLiteral("C:\\")),
          QStringLiteral("the entry carries metadata only"));
    CacheEntry parsedEntry;
    check(cacheEntryFromJson(entryJson, &parsedEntry, &error),
          QStringLiteral("the entry round-trips through its schema: %1").arg(error));
    checkEqual(parsedEntry.fingerprint, stored.fingerprint,
               QStringLiteral("the round-trip keeps the fingerprint"));

    QJsonObject newerEntry = entryJson;
    newerEntry.insert(QStringLiteral("schemaVersion"),
                      DataSaverCache::kSchemaVersion + 1);
    check(!cacheEntryFromJson(newerEntry, &parsedEntry, &error),
          QStringLiteral("a newer cache entry is rejected"));
    QJsonObject malformedEntry = entryJson;
    malformedEntry.remove(QStringLiteral("key"));
    check(!cacheEntryFromJson(malformedEntry, &parsedEntry, &error),
          QStringLiteral("a cache entry without a key is rejected"));

    // Persistence: save, reload, and refuse a newer store.
    const QString path = QDir::tempPath()
                         + QStringLiteral("/oasis_datasaver_cache_test.ini");
    QFile::remove(path);
    {
        QSettings settings(path, QSettings::IniFormat);
        DecisionCache persisted;
        check(persisted.insert(observation, context, decision, QStringLiteral("audit_5678"),
                               now, &error),
              QStringLiteral("the persisted cache accepts the entry: %1").arg(error));
        check(persisted.save(&settings, &error),
              QStringLiteral("the cache persists: %1").arg(error));

        DecisionCache reloaded;
        check(reloaded.loadInto(&settings, &error),
              QStringLiteral("the cache reloads: %1").arg(error));
        checkEqual(reloaded.count(), 1, QStringLiteral("the persisted entry is restored"));
        const CacheEntry reloadedEntry = reloaded.entries().value(0);
        checkEqual(reloadedEntry.auditId, QStringLiteral("audit_5678"),
                   QStringLiteral("the audit link survives persistence"));
        PolicyDecision reloadedHit;
        check(reloaded.lookup(observation, context, &reloadedHit, now, &error),
              QStringLiteral("the restored entry is reusable: %1").arg(error));

        // A newer root schema is rejected whole and is never overwritten.
        settings.beginGroup(DecisionCache::storageGroup());
        settings.setValue(QStringLiteral("schemaVersion"),
                          DataSaverCache::kSchemaVersion + 1);
        settings.endGroup();
        settings.sync();
        check(!reloaded.loadInto(&settings, &error),
              QStringLiteral("a newer cache store is reported and not loaded"));
        checkEqual(reloaded.count(), 0,
                   QStringLiteral("a newer store leaves the cache empty"));
        check(!reloaded.save(&settings, &error),
              QStringLiteral("saving over a newer store is refused"));
    }
    QFile::remove(path);

    // A malformed entry is skipped without failing the load.
    {
        QSettings settings(path, QSettings::IniFormat);
        settings.beginGroup(DecisionCache::storageGroup());
        settings.setValue(QStringLiteral("schemaVersion"), DataSaverCache::kSchemaVersion);
        settings.setValue(QStringLiteral("entries"),
                          QStringLiteral("[{\"schemaVersion\":1},42]"));
        settings.endGroup();
        settings.sync();
        const CacheLoadResult loaded = DecisionCache::load(&settings);
        checkEqual(loaded.skipped, 2, QStringLiteral("malformed entries are skipped"));
        checkEqual(static_cast<int>(loaded.entries.size()), 0,
                   QStringLiteral("malformed entries never reach the decision path"));
        check(!loaded.rejectedNewer, QStringLiteral("a malformed store is not a newer store"));
    }
    QFile::remove(path);

    // A tampered block entry is discarded on lookup, never enforced.
    {
        QSettings settings(path, QSettings::IniFormat);
        DecisionCache persisted;
        persisted.insert(observation, context, decision, QString(), now, &error);
        persisted.save(&settings, &error);

        settings.beginGroup(DecisionCache::storageGroup());
        const QJsonArray entries =
            QJsonDocument::fromJson(settings.value(QStringLiteral("entries"))
                                        .toString().toUtf8())
                .array();
        QJsonObject tampered = entries.at(0).toObject();
        QJsonObject tamperedDecision = tampered.value(QStringLiteral("decision")).toObject();
        tamperedDecision.insert(QStringLiteral("action"), QStringLiteral("block"));
        tamperedDecision.remove(QStringLiteral("throttle"));
        tampered.insert(QStringLiteral("decision"), tamperedDecision);
        QJsonArray replaced;
        replaced.append(tampered);
        settings.setValue(QStringLiteral("entries"),
                          QString::fromUtf8(QJsonDocument(replaced)
                                                .toJson(QJsonDocument::Compact)));
        settings.endGroup();
        settings.sync();

        DecisionCache tamperedCache;
        tamperedCache.loadInto(&settings, &error);
        PolicyDecision blockedHit;
        check(!tamperedCache.lookup(observation, context, &blockedHit, now, &error),
              QStringLiteral("a cached hard block is never returned"));
        checkEqual(tamperedCache.count(), 0,
                   QStringLiteral("the tampered block entry is discarded"));
    }
    QFile::remove(path);

    // The cache is bounded; the soonest-expiring entry is evicted first.
    DecisionCache bounded(2);
    QString firstFingerprint;
    for (int index = 0; index < 3; ++index) {
        FlowObservation varied = observation;
        varied.metrics.rxBytes = (12 + index * 30) * VolumeMilestone::kMiB;
        if (index == 0)
            firstFingerprint = fingerprintFor(buildCacheKey(varied, context));
        check(bounded.insert(varied, context, decision, QString(),
                             now.addSecs(index), &error),
              QStringLiteral("the bounded cache accepts entry %1: %2").arg(index).arg(error));
    }
    checkEqual(bounded.count(), 2,
               QStringLiteral("the bounded cache evicts down to its capacity"));
    check(!firstFingerprint.isEmpty() && !bounded.contains(firstFingerprint),
          QStringLiteral("the soonest-expiring entry is the eviction victim"));
}

void testDataSaverCacheResolution()
{
    using namespace DataSaverDecision;
    using Action = NetworkPolicy::Action;

    const QDateTime now = flowTestTime();
    FlowObservation observation = makeMilestoneObservation(
        QStringLiteral("flow_cccccccccccccccc"), QStringLiteral("pid:100:1000"),
        QStringLiteral("update.googleapis.com"), 12 * VolumeMilestone::kMiB);
    observation.metrics.milestoneBytes = 12 * VolumeMilestone::kMiB;
    observation.metrics.milestoneIndex = 1;
    observation.metrics.durationMs = 30000;
    observation.process.exeName = QStringLiteral("chromeupdate.exe");
    observation.process.foregroundState = FlowForegroundState::Background;

    ActivityQuery query;
    query.executableName = QStringLiteral("chromeupdate.exe");
    query.publisher = QStringLiteral("Google LLC");
    query.publisherVerified = true;
    query.product = QStringLiteral("Google Update");
    query.displayName = QStringLiteral("Google Update");
    query.domain = QStringLiteral("update.googleapis.com");

    DecisionCache cache;
    CacheContext context;
    context.catalogVersion = QStringLiteral("2026.11.11");

    ResolverInput input;
    input.signature.observation = observation;
    input.signature.activity = query;
    input.mode = DataSaverMode::Mode::Enforce;
    input.now = now;
    input.gentleThrottleAvailable = true;
    input.cache = &cache;
    input.cacheContext = &context;

    DecisionResolver resolver;
    const DecisionResolution fresh = resolver.resolve(input);
    check(fresh.evaluated && fresh.decision.origin == DecisionOrigin::Profile
              && fresh.decision.tier == 3,
          QStringLiteral("the resolver still resolves the local profile first"));
    check(fresh.decision.action == Action::Throttle,
          QStringLiteral("the profile decision is a throttle in this fixture"));
    checkEqual(cache.count(), 1,
               QStringLiteral("the resolver stores a fresh profile decision"));
    check(fresh.diagnostic.contains(QStringLiteral("stored in the evidence cache")),
          QStringLiteral("the resolver reports the cache write"));
    const CacheEntry stored = cache.entries().value(0);
    checkEqual(stored.decisionId, fresh.decision.decisionId,
               QStringLiteral("the cached entry is the committed decision"));
    checkEqual(stored.observationId, observation.observationId,
               QStringLiteral("the cached entry names the source observation"));
    checkEqual(stored.catalogVersion, context.catalogVersion,
               QStringLiteral("the cached entry keeps the catalog version"));

    // With no matching local signature, the stored decision becomes tier 4.
    EndpointCatalog emptyCatalog;
    DecisionResolver noProfile(LocalSignatureEngine(emptyCatalog, QList<ProfileRule>()));
    const DecisionResolution reused = noProfile.resolve(input);
    check(reused.evaluated && reused.decision.origin == DecisionOrigin::Cache
              && reused.decision.tier == 4,
          QStringLiteral("a cache hit is the tier-4 candidate when no profile matches"));
    check(reused.decision.action == Action::Throttle
              && reused.decision.rateBitsPerSecond == 409600,
          QStringLiteral("the cache hit carries the stored gentle throttle"));
    check(reused.diagnostic.contains(QStringLiteral("supplied the tier-4 candidate")),
          QStringLiteral("the resolver reports the cache hit"));
    check(!reused.matchedCacheKey.isEmpty() && reused.matchedRuleId.isEmpty(),
          QStringLiteral("the cache resolution reports the matched fingerprint, not a rule"));
    checkEqual(reused.decision.observationId, observation.observationId,
               QStringLiteral("the cache hit names the current observation"));
    checkEqual(reused.decision.target.flowId, observation.flow.flowId,
               QStringLiteral("the cache hit retargets the current flow"));
    checkEqual(cache.count(), 1,
               QStringLiteral("a cache hit is not stored again"));

    // A different evidence bucket misses instead of reusing the decision.
    FlowObservation changed = observation;
    changed.metrics.rxBytes = 30 * VolumeMilestone::kMiB;
    input.signature.observation = changed;
    const DecisionResolution missed = noProfile.resolve(input);
    check(missed.evaluated && missed.decision.origin == DecisionOrigin::Fallback
              && missed.decision.tier == 5,
          QStringLiteral("a different bucket falls through to the safe fallback"));

    // Off suppresses automatic tiers, so the cache is neither read nor written.
    input.mode = DataSaverMode::Mode::Off;
    input.signature.observation = observation;
    const DecisionResolution off = noProfile.resolve(input);
    check(off.automationSuppressed && !off.evaluated,
          QStringLiteral("Off produces no automatic decision"));
    check(!off.diagnostic.contains(QStringLiteral("evidence cache")),
          QStringLiteral("Off never consults the evidence cache"));
    checkEqual(cache.count(), 1, QStringLiteral("Off leaves the cache unchanged"));

    // A catalog change invalidates the stored entry on the next lookup.
    input.mode = DataSaverMode::Mode::Enforce;
    context.catalogVersion = QStringLiteral("2027.01.01");
    const DecisionResolution catalogChanged = noProfile.resolve(input);
    check(catalogChanged.decision.origin == DecisionOrigin::Fallback,
          QStringLiteral("a catalog change disables the cached decision"));
    checkEqual(cache.count(), 0,
               QStringLiteral("the stale cache entry is discarded"));
}

class MockEnforcementBackend final : public DataSaverEnforcementBackend
{
public:
    bool available = true;
    EnforcementResult::Status throttleStatus = EnforcementResult::Status::Requested;
    EnforcementResult::Status blockStatus = EnforcementResult::Status::Applied;
    EnforcementResult::Status throttleWithdrawStatus = EnforcementResult::Status::Requested;
    EnforcementResult::Status blockWithdrawStatus = EnforcementResult::Status::Applied;

    int throttleCalls = 0;
    int blockCalls = 0;
    int throttleWithdrawCalls = 0;
    int blockWithdrawCalls = 0;
    QString lastPolicyId;
    QString lastPath;
    quint64 lastRate = 0;
    NetworkDirection lastDirection = NetworkDirection::Download;

    bool isAvailable() const override { return available; }

    EnforcementResult applyThrottle(const QString &executablePath, const QString &policyId,
                                    quint64 rateBitsPerSecond,
                                    NetworkDirection direction) override
    {
        ++throttleCalls;
        lastPolicyId = policyId;
        lastPath = executablePath;
        lastRate = rateBitsPerSecond;
        lastDirection = direction;
        EnforcementResult result;
        result.status = throttleStatus;
        result.policyId = policyId;
        result.executablePath = executablePath;
        result.channels = QStringLiteral("QoS upload + WinDivert download");
        result.message = QStringLiteral("mock throttle request");
        return result;
    }

    EnforcementResult withdrawThrottle(const QString &executablePath,
                                       const QString &policyId) override
    {
        ++throttleWithdrawCalls;
        EnforcementResult result;
        result.status = throttleWithdrawStatus;
        result.policyId = policyId;
        result.executablePath = executablePath;
        result.message = QStringLiteral("mock throttle withdrawal");
        return result;
    }

    EnforcementResult applyBlock(const QString &executablePath,
                                 const QString &policyId) override
    {
        ++blockCalls;
        lastPolicyId = policyId;
        lastPath = executablePath;
        EnforcementResult result;
        result.status = blockStatus;
        result.policyId = policyId;
        result.executablePath = executablePath;
        result.channels = QStringLiteral("firewall");
        result.message = QStringLiteral("mock block request");
        return result;
    }

    EnforcementResult withdrawBlock(const QString &executablePath,
                                    const QString &policyId) override
    {
        ++blockWithdrawCalls;
        EnforcementResult result;
        result.status = blockWithdrawStatus;
        result.policyId = policyId;
        result.executablePath = executablePath;
        result.message = QStringLiteral("mock block withdrawal");
        return result;
    }
};

void testDataSaverEnforcement()
{
    using namespace DataSaverEnforcement;
    using Action = NetworkPolicy::Action;
    using Status = EnforcementResult::Status;

    const QDateTime now = flowTestTime();
    FlowObservation observation = makeMilestoneObservation(
        QStringLiteral("flow_dddddddddddddddd"), QStringLiteral("pid:100:1000"),
        QStringLiteral("update.googleapis.com"), 12 * VolumeMilestone::kMiB);
    observation.process.exeName = QStringLiteral("chromeupdate.exe");
    PolicyDecision throttle = makeCacheableProfileDecision(observation);
    throttle.until = ThrottleUntil::MilestoneNext;

    checkEqual(normalizedPath(QStringLiteral("C:\\Apps\\Code.exe")),
               QStringLiteral("c:/apps/code.exe"),
               QStringLiteral("control paths are normalized for ownership"));
    const QString policyIdA = automaticPolicyId(QStringLiteral("C:\\Apps\\A.exe"));
    check(policyIdA.startsWith(QStringLiteral("dsauto_")),
          QStringLiteral("the automatic policy id uses the dsauto_ prefix"));
    checkEqual(policyIdA, automaticPolicyId(QStringLiteral("c:\\apps\\a.exe")),
               QStringLiteral("the automatic policy id is stable across separators and case"));
    check(policyIdA != automaticPolicyId(QStringLiteral("C:\\Apps\\B.exe")),
          QStringLiteral("different executable paths get different policy ids"));
    check(throttleBelongsTo(policyIdA, policyIdA),
          QStringLiteral("a limit attributed to this policy is owned"));
    check(!throttleBelongsTo(QString(), policyIdA),
          QStringLiteral("a manual limit with no attribution is not owned"));
    check(!throttleBelongsTo(automaticPolicyId(QStringLiteral("C:\\Apps\\B.exe")),
                             policyIdA),
          QStringLiteral("another policy's limit is not owned"));
    check(firewallRuleBelongsTo(QStringLiteral("Oasis policy ") + policyIdA, policyIdA),
          QStringLiteral("a rule whose description names this policy is owned"));
    check(!firewallRuleBelongsTo(QStringLiteral("Managed by Oasis"), policyIdA),
          QStringLiteral("a user-created firewall rule is not owned"));
    check(!firewallRuleBelongsTo(
              QStringLiteral("Oasis policy ")
                  + automaticPolicyId(QStringLiteral("C:\\Apps\\B.exe")),
              policyIdA),
          QStringLiteral("another policy's rule is not owned"));

    MockEnforcementBackend backend;
    DataSaverEnforcer enforcer(&backend);
    check(enforcer.canThrottle(), QStringLiteral("an available backend can throttle"));

    // The enforcer refuses a decision whose target executable does not match
    // the resolved path; route through a helper so each control targets its
    // own lease.
    const auto route = [&enforcer](const PolicyDecision &decision,
                                   const ControlLease &lease,
                                   const QDateTime &when) {
        PolicyDecision targeted = decision;
        targeted.target.executable = QFileInfo(lease.executablePath).fileName();
        return enforcer.apply(targeted, lease, when);
    };

    ControlLease leaseA;
    leaseA.executablePath = QStringLiteral("C:\\Apps\\A.exe");
    leaseA.reason = QStringLiteral("test");

    const EnforcementOutcome mismatched = enforcer.apply(throttle, leaseA, now);
    check(mismatched.failed() && !enforcer.owns(leaseA.executablePath),
          QStringLiteral("a decision for another executable is not enforced"));

    PolicyDecision allow = throttle;
    allow.action = Action::Allow;
    allow.rateBitsPerSecond = 0;
    const EnforcementOutcome allowed = route(allow, leaseA, now);
    check(allowed.evaluated && allowed.status == Status::NotApplied && !allowed.changed,
          QStringLiteral("an allow decision needs no channel"));
    checkEqual(backend.throttleCalls, 0,
               QStringLiteral("an allow decision never reaches the throttle channel"));

    const EnforcementOutcome applied = route(throttle, leaseA, now);
    check(applied.changed && applied.status == Status::Requested,
          QStringLiteral("a throttle decision requests the channel"));
    checkEqual(backend.throttleCalls, 1, QStringLiteral("the throttle channel was asked once"));
    checkEqual(backend.lastRate, quint64(409600),
               QStringLiteral("the canonical 409600 bits/s rate is requested"));
    check(backend.lastDirection == NetworkDirection::Download,
          QStringLiteral("the decision direction reaches the channel"));
    checkEqual(backend.lastPolicyId, policyIdA,
               QStringLiteral("the control carries its stable automatic policy id"));
    checkEqual(backend.lastPath, leaseA.executablePath,
               QStringLiteral("the channel receives the resolved executable path"));

    const DataSaverControl stored = enforcer.controlFor(leaseA.executablePath);
    check(stored.action == Action::Throttle,
          QStringLiteral("the enforcer records the throttle control"));
    checkEqual(stored.policyId, policyIdA, QStringLiteral("the control records its owner"));
    checkEqual(stored.executablePath, normalizedPath(leaseA.executablePath),
               QStringLiteral("the control is keyed by the normalized path"));
    check(stored.until == ThrottleUntil::MilestoneNext,
          QStringLiteral("the control records its lease basis"));
    checkEqual(stored.rateBitsPerSecond, quint64(409600),
               QStringLiteral("the control records the requested rate"));

    const EnforcementOutcome repeated = route(throttle, leaseA, now.addSecs(5));
    check(!repeated.changed && repeated.status == Status::Requested,
          QStringLiteral("re-applying the same decision is idempotent"));
    checkEqual(backend.throttleCalls, 1,
               QStringLiteral("an idempotent re-apply does not call the channel again"));

    // A higher automatic rate is capped, and a direction change forces a fresh
    // request so the cap is observable.
    PolicyDecision fast = throttle;
    fast.rateBitsPerSecond = 1000000;
    fast.direction = NetworkDirection::Upload;
    const EnforcementOutcome capped = route(fast, leaseA, now.addSecs(10));
    checkEqual(backend.throttleCalls, 2, QStringLiteral("the changed request reaches the channel"));
    checkEqual(backend.lastRate, quint64(409600),
               QStringLiteral("a higher automatic rate is capped to 409600"));
    check(backend.lastDirection == NetworkDirection::Upload,
          QStringLiteral("the updated direction reaches the channel"));
    check(capped.message.contains(QStringLiteral("capped")),
          QStringLiteral("the cap is reported in the outcome"));

    PolicyDecision slow = throttle;
    slow.rateBitsPerSecond = 1024;
    const EnforcementOutcome refused = route(slow, leaseA, now);
    check(refused.failed(), QStringLiteral("a rate below the gentle floor is refused"));
    checkEqual(backend.throttleCalls, 2,
               QStringLiteral("a refused rate never reaches the channel"));
    check(enforcer.owns(leaseA.executablePath),
          QStringLiteral("a refused request leaves the previous control in place"));

    // Block goes to the firewall channel and is idempotent too.
    ControlLease leaseB;
    leaseB.executablePath = QStringLiteral("C:\\Apps\\B.exe");
    PolicyDecision block = throttle;
    block.action = Action::Block;
    block.rateBitsPerSecond = 0;
    const EnforcementOutcome blocked = route(block, leaseB, now);
    check(blocked.changed && blocked.status == Status::Applied,
          QStringLiteral("a block decision applies through the firewall channel"));
    checkEqual(backend.blockCalls, 1, QStringLiteral("the firewall channel was asked once"));
    const EnforcementOutcome blockedAgain = route(block, leaseB, now);
    check(!blockedAgain.changed && blockedAgain.status == Status::Applied,
          QStringLiteral("re-applying the same block is idempotent"));
    checkEqual(backend.blockCalls, 1,
               QStringLiteral("an idempotent block does not touch the firewall again"));

    // A partial channel outcome is kept as partial, never reported as applied.
    backend.throttleStatus = Status::Partial;
    ControlLease leaseC;
    leaseC.executablePath = QStringLiteral("C:\\Apps\\C.exe");
    const EnforcementOutcome partial = route(throttle, leaseC, now);
    check(partial.changed && partial.status == Status::Partial,
          QStringLiteral("a partial channel outcome stays partial"));
    check(enforcer.owns(leaseC.executablePath),
          QStringLiteral("a partial control is recorded for later withdrawal"));
    backend.throttleStatus = Status::Requested;

    // A failed apply records no control that claims to be enforced.
    backend.throttleStatus = Status::Failed;
    ControlLease leaseD;
    leaseD.executablePath = QStringLiteral("C:\\Apps\\D.exe");
    const EnforcementOutcome failedApply = route(throttle, leaseD, now);
    check(failedApply.failed() && !failedApply.changed,
          QStringLiteral("a failed channel outcome is reported as failed"));
    check(!enforcer.owns(leaseD.executablePath),
          QStringLiteral("a failed apply leaves no control behind"));
    backend.throttleStatus = Status::Requested;

    // Switching a path from throttle to block withdraws the old control first.
    const EnforcementOutcome switched = route(block, leaseA, now);
    checkEqual(backend.throttleWithdrawCalls, 1,
               QStringLiteral("replacing a throttle withdraws it first"));
    check(switched.changed && switched.status == Status::Applied,
          QStringLiteral("the replacement block is applied"));
    check(enforcer.controlFor(leaseA.executablePath).action == Action::Block,
          QStringLiteral("the control now records the block"));

    // A user rule wins: only the automatic control for that path is withdrawn.
    PolicyDecision pin = allow;
    pin.origin = DecisionOrigin::Pinned;
    pin.tier = 1;
    pin.confidence = 1.0;
    const int blockCallsBefore = backend.blockCalls;
    const EnforcementOutcome userWon = route(pin, leaseA, now);
    check(userWon.status == Status::NotApplied && userWon.changed,
          QStringLiteral("a user rule withdraws the automatic control"));
    checkEqual(backend.blockWithdrawCalls, 1,
               QStringLiteral("the user rule withdraws the control it replaces"));
    checkEqual(backend.blockCalls, blockCallsBefore,
               QStringLiteral("a user rule is never applied as an automatic control"));
    check(!enforcer.owns(leaseA.executablePath) && enforcer.owns(leaseB.executablePath),
          QStringLiteral("only the rule's own path is withdrawn"));

    const EnforcementOutcome withdrawnB =
        enforcer.withdraw(leaseB.executablePath, QStringLiteral("test"));
    check(withdrawnB.changed && withdrawnB.status == Status::Applied,
          QStringLiteral("withdraw reports the channel outcome"));
    check(!enforcer.owns(leaseB.executablePath),
          QStringLiteral("a withdrawn control is forgotten"));

    // A failed withdrawal keeps ownership so a later restore can retry.
    backend.throttleWithdrawStatus = Status::Failed;
    const EnforcementOutcome failedWithdrawal =
        enforcer.withdraw(leaseC.executablePath, QStringLiteral("test"));
    check(failedWithdrawal.failed() && !failedWithdrawal.changed,
          QStringLiteral("a failed withdrawal is reported and kept"));
    check(enforcer.owns(leaseC.executablePath),
          QStringLiteral("a failed withdrawal keeps the control for retry"));
    backend.throttleWithdrawStatus = Status::Requested;
    const EnforcementOutcome retried =
        enforcer.withdraw(leaseC.executablePath, QStringLiteral("test"));
    check(retried.changed && retried.status == Status::Requested,
          QStringLiteral("the retried withdrawal succeeds"));

    // Without a channel, a throttle fails visibly; an allow still needs none.
    backend.available = false;
    ControlLease leaseE;
    leaseE.executablePath = QStringLiteral("C:\\Apps\\E.exe");
    const EnforcementOutcome unavailable = route(throttle, leaseE, now);
    check(unavailable.failed() && !unavailable.changed,
          QStringLiteral("no channel produces a failed, not an optimistic, outcome"));
    check(!enforcer.owns(leaseE.executablePath),
          QStringLiteral("an unavailable channel records no control"));
    const EnforcementOutcome allowWithoutChannel = route(allow, leaseE, now);
    check(!allowWithoutChannel.failed() && allowWithoutChannel.status == Status::NotApplied,
          QStringLiteral("an allow decision does not depend on a channel"));
    backend.available = true;

    // Absolute leases expire only when elapsed.
    ControlLease timed;
    timed.executablePath = QStringLiteral("C:\\Apps\\Timed.exe");
    timed.expiresAt = now.addSecs(60);
    route(throttle, timed, now);
    check(enforcer.expire(now.addSecs(59)).isEmpty(),
          QStringLiteral("a live lease is not expired early"));
    const QList<EnforcementOutcome> expired = enforcer.expire(now.addSecs(60));
    checkEqual(static_cast<int>(expired.size()), 1,
               QStringLiteral("the elapsed lease is withdrawn"));
    check(expired.first().changed,
          QStringLiteral("the expiry reports the withdrawal"));
    check(!enforcer.owns(timed.executablePath),
          QStringLiteral("the expired control is forgotten"));

    // only the matching lease basis is withdrawn on a foreground change.
    PolicyDecision foreground = throttle;
    foreground.until = ThrottleUntil::ForegroundChange;
    ControlLease leaseF;
    leaseF.executablePath = QStringLiteral("C:\\Apps\\F.exe");
    route(foreground, leaseF, now);
    check(enforcer.withdrawUntil(ThrottleUntil::SessionEnd, QStringLiteral("test")).isEmpty(),
          QStringLiteral("a different lease basis is left alone"));
    const QList<EnforcementOutcome> foregroundChanged =
        enforcer.withdrawUntil(ThrottleUntil::ForegroundChange,
                               QStringLiteral("foreground changed"));
    checkEqual(static_cast<int>(foregroundChanged.size()), 1,
               QStringLiteral("the foreground lease is withdrawn on a change"));
    check(!enforcer.owns(leaseF.executablePath),
          QStringLiteral("the foreground control is forgotten"));

    // withdrawAll removes every remaining Data Saver control.
    ControlLease leaseH;
    leaseH.executablePath = QStringLiteral("C:\\Apps\\H.exe");
    route(throttle, leaseH, now);
    const int remaining = enforcer.count();
    const QList<EnforcementOutcome> all =
        enforcer.withdrawAll(QStringLiteral("test disable"));
    checkEqual(static_cast<int>(all.size()), remaining,
               QStringLiteral("withdrawAll reports every control it owns"));
    checkEqual(enforcer.count(), 0, QStringLiteral("withdrawAll leaves no controls"));
}

void testDataSaverDecisionAudit()
{
    using namespace DataSaverAudit;
    using Status = EnforcementResult::Status;

    const QDateTime now = flowTestTime();
    FlowObservation observation = makeMilestoneObservation(
        QStringLiteral("flow_eeeeeeeeeeeeeeee"), QStringLiteral("pid:200:2000"),
        QStringLiteral("update.googleapis.com"), 12 * VolumeMilestone::kMiB);
    observation.process.exeName = QStringLiteral("chromeupdate.exe");
    observation.process.exePath =
        QStringLiteral("C:\\Users\\tester\\AppData\\chromeupdate.exe");
    observation.process.identityId = QStringLiteral("id_chromeupdate");
    observation.flow.localEndpoint = QStringLiteral("192.168.1.50:51515");
    observation.flow.remoteEndpoint = QStringLiteral("93.184.216.34:443");
    observation.metrics.milestoneBytes = 10 * VolumeMilestone::kMiB;
    observation.metrics.milestoneIndex = 1;

    PolicyDecision decision = makeCacheableProfileDecision(observation);
    decision.createdAt = now;
    decision.target.executable = QStringLiteral("chromeupdate.exe");
    decision.target.identityId = QStringLiteral("id_chromeupdate");
    decision.evidence.executable = QStringLiteral("chromeupdate.exe");
    decision.evidence.milestoneBytes = observation.metrics.milestoneBytes;
    decision.evidence.milestoneIndex = observation.metrics.milestoneIndex;

    DecisionRecord record;
    record.observation = observation;
    record.decision = decision;
    record.matchedRuleId = QStringLiteral("profile_updater");
    record.diagnostic = QStringLiteral("the profile recommendation was applied");
    // A directory path is handed in on purpose; the builder must keep only the
    // base name.
    record.executableName = observation.process.exePath;
    record.enforcementStatus = Status::Requested;
    record.enforcementChanged = true;
    record.enforcementMessage = QStringLiteral("QoS shaping requested");
    record.enforcementPolicyId = QStringLiteral("dsauto_0123456789ab");
    record.enforcementChannels = QStringLiteral("WinDivert download");

    check(!isUserOrigin(DecisionOrigin::Profile)
              && !isUserOrigin(DecisionOrigin::Fallback)
              && isUserOrigin(DecisionOrigin::Pinned)
              && isUserOrigin(DecisionOrigin::Session),
          QStringLiteral("only pins and session overrides count as user decisions"));

    const AuditEvent automatic = eventFor(record, now);
    check(automatic.type == AuditEvent::EventType::AutomaticDecision,
          QStringLiteral("a profile decision is audited as an automatic decision"));
    checkEqual(automatic.scope, QStringLiteral("chromeupdate.exe"),
               QStringLiteral("the audit scope keeps the executable base name only"));
    check(automatic.result.contains(QStringLiteral("throttle"))
              && automatic.result.contains(QStringLiteral("requested")),
          QStringLiteral("the audit result names the action and enforcement status"));
    checkEqual(automatic.relatedPolicyId, record.enforcementPolicyId,
               QStringLiteral("the automatic audit names its enforcement policy id"));
    checkEqual(automatic.relatedIdentityId, QStringLiteral("id_chromeupdate"),
               QStringLiteral("the audit links the decision identity"));
    check(automatic.reason.contains(QStringLiteral("profile match")),
          QStringLiteral("the audit reason names the automatic origin"));
    checkEqual(automatic.timestamp, now,
               QStringLiteral("the audit timestamp is the decision commit time"));

    const QJsonObject details = objectOf(automatic.details);
    checkEqual(details.value(QStringLiteral("schemaVersion")).toInt(), kSchemaVersion,
               QStringLiteral("the decision audit details carry their schema version"));
    checkEqual(details.value(QStringLiteral("decisionId")).toString(),
               decision.decisionId,
               QStringLiteral("the audit records the decision id"));
    checkEqual(details.value(QStringLiteral("observationId")).toString(),
               observation.observationId,
               QStringLiteral("the audit records the observation id"));
    checkEqual(details.value(QStringLiteral("flowId")).toString(),
               observation.flow.flowId,
               QStringLiteral("the audit records the flow id"));
    checkEqual(details.value(QStringLiteral("milestoneIndex")).toInt(), 1,
               QStringLiteral("the audit records the milestone index"));
    checkEqual(details.value(QStringLiteral("milestoneBytes")).toDouble(),
               static_cast<double>(observation.metrics.milestoneBytes),
               QStringLiteral("the audit records the milestone volume"));
    checkEqual(details.value(QStringLiteral("origin")).toString(),
               QStringLiteral("profile"),
               QStringLiteral("the audit records the winning origin"));
    check(details.value(QStringLiteral("automatic")).toBool(),
          QStringLiteral("the audit marks a profile decision automatic"));
    checkEqual(details.value(QStringLiteral("tier")).toInt(), 3,
               QStringLiteral("the audit records the precedence tier"));
    checkEqual(details.value(QStringLiteral("action")).toString(),
               QStringLiteral("throttle"),
               QStringLiteral("the audit records the committed action"));
    checkEqual(details.value(QStringLiteral("scope")).toString(),
               QStringLiteral("executable"),
               QStringLiteral("the audit records the decision scope"));
    checkEqual(details.value(QStringLiteral("rateBitsPerSecond")).toDouble(), 409600.0,
               QStringLiteral("the audit records the throttle rate"));
    checkEqual(details.value(QStringLiteral("until")).toString(),
               QStringLiteral("milestone_next"),
               QStringLiteral("the audit records the throttle horizon"));
    checkEqual(details.value(QStringLiteral("targetExecutable")).toString(),
               QStringLiteral("chromeupdate.exe"),
               QStringLiteral("the audit records the target base name"));
    checkEqual(details.value(QStringLiteral("domain")).toString(),
               QStringLiteral("update.googleapis.com"),
               QStringLiteral("the audit records the attributed domain"));
    checkEqual(details.value(QStringLiteral("matchedRuleId")).toString(),
               QStringLiteral("profile_updater"),
               QStringLiteral("the audit records the matched rule id"));
    checkEqual(details.value(QStringLiteral("reason")).toString(),
               decision.reasonShort,
               QStringLiteral("the audit records the decision reason"));
    checkEqual(details.value(QStringLiteral("resolverDiagnostic")).toString(),
               record.diagnostic,
               QStringLiteral("the audit records the resolver diagnostic"));

    const QJsonObject evidence = details.value(QStringLiteral("evidence")).toObject();
    checkEqual(evidence.value(QStringLiteral("foregroundState")).toString(),
               decision.evidence.foregroundState,
               QStringLiteral("the evidence summary records the foreground state"));
    checkEqual(evidence.value(QStringLiteral("domainConfidence")).toString(),
               decision.evidence.domainConfidence,
               QStringLiteral("the evidence summary records the domain confidence"));
    checkEqual(evidence.value(QStringLiteral("uxProfile")).toString(),
               decision.evidence.uxProfile,
               QStringLiteral("the evidence summary records the UX profile"));

    const QJsonObject enforcement = details.value(QStringLiteral("enforcement")).toObject();
    checkEqual(enforcement.value(QStringLiteral("status")).toString(),
               QStringLiteral("requested"),
               QStringLiteral("the audit records the enforcement status"));
    checkEqual(enforcement.value(QStringLiteral("policyId")).toString(),
               record.enforcementPolicyId,
               QStringLiteral("the enforcement summary records the policy id"));
    check(enforcement.value(QStringLiteral("changed")).toBool(),
          QStringLiteral("the enforcement summary records whether a control changed"));
    checkEqual(enforcement.value(QStringLiteral("channels")).toString(),
               record.enforcementChannels,
               QStringLiteral("the enforcement summary records the channels"));
    checkEqual(enforcement.value(QStringLiteral("executable")).toString(),
               QStringLiteral("chromeupdate.exe"),
               QStringLiteral("the enforcement summary keeps the base name only"));

    // Metadata only: the observation endpoints and the executable directory are
    // never part of the record.
    check(!automatic.details.contains(QStringLiteral("192.168.1.50"))
              && !automatic.details.contains(QStringLiteral("93.184.216.34")),
          QStringLiteral("the decision audit never records local or remote addresses"));
    check(!automatic.details.contains(QStringLiteral("tester")),
          QStringLiteral("the decision audit never records an executable path"));
    check(!automatic.details.contains(QStringLiteral("localEndpoint"))
              && !automatic.details.contains(QStringLiteral("remoteEndpoint"))
              && !automatic.details.contains(QStringLiteral("exePath"))
              && !automatic.details.contains(QStringLiteral("payload")),
          QStringLiteral("the decision audit has no endpoint, path, or payload key"));

    // A pinned win is a user decision and names the rule instead of an
    // automatic control.
    DecisionRecord pinned = record;
    pinned.decision.origin = DecisionOrigin::Pinned;
    pinned.decision.tier = 1;
    pinned.decision.action = NetworkPolicy::Action::Allow;
    pinned.decision.rateBitsPerSecond = 0;
    pinned.decision.confidence = 1.0;
    pinned.matchedRuleId = QStringLiteral("pin_1111111111111111");
    pinned.enforcementPolicyId.clear();
    pinned.enforcementStatus = Status::NotApplied;
    pinned.enforcementChannels.clear();
    pinned.enforcementMessage.clear();
    const AuditEvent pinnedEvent = eventFor(pinned, now);
    check(pinnedEvent.type == AuditEvent::EventType::UserDecision,
          QStringLiteral("a pinned win is audited as a user decision"));
    checkEqual(pinnedEvent.result, QStringLiteral("allow (not_applied)"),
               QStringLiteral("the pinned audit records its action and no enforcement"));
    checkEqual(pinnedEvent.relatedPolicyId, pinned.matchedRuleId,
               QStringLiteral("a pinned audit falls back to its rule id for the policy link"));
    const QJsonObject pinnedDetails = objectOf(pinnedEvent.details);
    checkEqual(pinnedDetails.value(QStringLiteral("origin")).toString(),
               QStringLiteral("pinned"),
               QStringLiteral("the pinned audit records the pinned origin"));
    check(!pinnedDetails.value(QStringLiteral("automatic")).toBool(),
          QStringLiteral("the pinned audit is not automatic"));
    checkEqual(pinnedDetails.value(QStringLiteral("matchedRuleId")).toString(),
               pinned.matchedRuleId,
               QStringLiteral("the pinned audit names the winning rule"));
    check(pinnedEvent.reason.contains(QStringLiteral("pinned rule")),
          QStringLiteral("the pinned audit reason distinguishes the origin"));

    // A cache hit is automatic and carries the fingerprint it matched.
    DecisionRecord cached = record;
    cached.decision.origin = DecisionOrigin::Cache;
    cached.decision.tier = 4;
    cached.matchedRuleId.clear();
    cached.matchedCacheKey = QStringLiteral("fp_abcdef0123456789");
    const AuditEvent cachedEvent = eventFor(cached, now);
    const QJsonObject cachedDetails = objectOf(cachedEvent.details);
    check(cachedEvent.type == AuditEvent::EventType::AutomaticDecision,
          QStringLiteral("a cache hit is audited as an automatic decision"));
    checkEqual(cachedDetails.value(QStringLiteral("origin")).toString(),
               QStringLiteral("cache"),
               QStringLiteral("the cache audit records the cache origin"));
    check(cachedDetails.value(QStringLiteral("automatic")).toBool(),
          QStringLiteral("the cache audit is automatic"));
    checkEqual(cachedDetails.value(QStringLiteral("matchedCacheKey")).toString(),
               cached.matchedCacheKey,
               QStringLiteral("the cache audit records the matched fingerprint"));

    // Failed and partial outcomes keep their status; a failed enforcement is
    // reported as failed, never as success.
    DecisionRecord failed = record;
    failed.enforcementStatus = Status::Failed;
    failed.enforcementMessage = QStringLiteral("the WinDivert handle is unavailable");
    failed.enforcementPolicyId.clear();
    const AuditEvent failedEvent = eventFor(failed, now);
    checkEqual(failedEvent.result, QStringLiteral("throttle (failed)"),
               QStringLiteral("a failed enforcement is recorded as failed"));
    check(failedEvent.errorInfo.contains(QStringLiteral("WinDivert")),
          QStringLiteral("the failed audit carries the channel error"));
    checkEqual(failedEvent.relatedPolicyId, failed.matchedRuleId,
               QStringLiteral("a failed audit still names the matched rule"));
    checkEqual(objectOf(failedEvent.details)
                   .value(QStringLiteral("enforcement")).toObject()
                   .value(QStringLiteral("status")).toString(),
               QStringLiteral("failed"),
               QStringLiteral("the failed audit details keep the failed status"));

    DecisionRecord partial = record;
    partial.enforcementStatus = Status::Partial;
    partial.enforcementMessage = QStringLiteral("download shaped; upload unavailable");
    const AuditEvent partialEvent = eventFor(partial, now);
    checkEqual(partialEvent.result, QStringLiteral("throttle (partial)"),
               QStringLiteral("a partial enforcement is recorded as partial"));
    check(partialEvent.errorInfo.isEmpty(),
          QStringLiteral("a partial enforcement is not reported as an error"));

    // The audit export keeps the origin, automatic flag, matched rule or cache
    // key, and enforcement fields, so a reader can tell user and automatic
    // actions apart.
    AuditRetentionSettings retention;
    const QString exported = EvidenceExport::auditJson(
        QList<AuditEvent>() << automatic, retention, false,
        QStringLiteral("2026-11-27T00:00:00Z"));
    const QJsonObject root = objectOf(exported);
    checkEqual(root.value(QStringLiteral("format")).toString(),
               QStringLiteral("oasis.audit-log"),
               QStringLiteral("the audit export carries its format"));
    checkEqual(root.value(QStringLiteral("count")).toInt(), 1,
               QStringLiteral("the audit export counts the decision record"));
    const QJsonArray exportedEvents = root.value(QStringLiteral("events")).toArray();
    checkEqual(static_cast<int>(exportedEvents.size()), 1,
               QStringLiteral("the audit export contains the decision record"));
    const QJsonObject exportedEvent = exportedEvents.first().toObject();
    checkEqual(exportedEvent.value(QStringLiteral("type")).toInt(),
               static_cast<int>(AuditEvent::EventType::AutomaticDecision),
               QStringLiteral("the export preserves the decision type"));
    const QJsonObject exportedDetails =
        objectOf(exportedEvent.value(QStringLiteral("details")).toString());
    checkEqual(exportedDetails.value(QStringLiteral("origin")).toString(),
               QStringLiteral("profile"),
               QStringLiteral("the export preserves the decision origin"));
    check(exportedDetails.value(QStringLiteral("automatic")).toBool(),
          QStringLiteral("the export preserves the automatic flag"));
    check(exportedDetails.contains(QStringLiteral("matchedRuleId"))
              && exportedDetails.contains(QStringLiteral("matchedCacheKey")),
          QStringLiteral("the export preserves the matched rule and cache key fields"));
    check(exportedDetails.contains(QStringLiteral("enforcement")),
          QStringLiteral("the export preserves the enforcement result"));
}

void runDataSaverTests()
{
    testDataSaverModeContract();
    testFlowObservationContract();
    testFlowObservationBuilder();
    testVolumeMilestones();
    testDataSaverRules();
    testLocalSignatures();
    testDataSaverDecisionResolver();
    testDataSaverDecisionCache();
    testDataSaverCacheResolution();
    testDataSaverEnforcement();
    testDataSaverDecisionAudit();
}
