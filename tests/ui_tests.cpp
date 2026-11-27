/**
 * @file   ui_tests.cpp
 * @brief  Audit, evidence, and dashboard model tests (NG-050..NG-055).
 */

#include "testharness.h"
#include "testdeclarations.h"

// ─── NG-050: audit event store ──────────────────────────────────────────────
// The store must timestamp, bound, persist, query, and export events, and the
// export must never add packet content.
void testAuditEventStore()
{
    QSettings().clear();

    // Names and parsing are stable and shared by the export.
    checkEqual(auditEventTypeName(AuditEvent::EventType::EnforcementResult),
               QStringLiteral("EnforcementResult"),
               QStringLiteral("an audit event type has a stable name"));
    checkEqual(static_cast<int>(auditEventTypeNames().size()), 9,
               QStringLiteral("every audit event type is named"));
    AuditEvent::EventType parsedType = AuditEvent::EventType::Detection;
    check(auditEventTypeFromName(QStringLiteral("policychange"), &parsedType),
          QStringLiteral("event type names parse case-insensitively"));
    check(parsedType == AuditEvent::EventType::PolicyChange,
          QStringLiteral("a parsed event type names the right value"));
    check(!auditEventTypeFromName(QStringLiteral("Bogus"), &parsedType),
          QStringLiteral("an unknown event type name is rejected"));

    // Retention is clamped in both directions.
    AuditEventStore store;
    checkEqual(store.count(), 0, QStringLiteral("a new audit store starts empty"));
    checkEqual(store.retention().retentionDays, 30,
               QStringLiteral("the default retention window is 30 days"));
    checkEqual(store.retention().maxEvents, 2000,
               QStringLiteral("the default event bound is 2000"));
    AuditRetentionSettings tooSmall;
    tooSmall.retentionDays = 0;
    tooSmall.maxEvents = 0;
    store.setRetention(tooSmall);
    checkEqual(store.retention().retentionDays, 1,
               QStringLiteral("retention below one day is clamped up"));
    checkEqual(store.retention().maxEvents, 1,
               QStringLiteral("an event bound below one is clamped up"));
    AuditRetentionSettings tooLarge;
    tooLarge.retentionDays = 100000;
    tooLarge.maxEvents = 100000;
    store.setRetention(tooLarge);
    checkEqual(store.retention().retentionDays, 365,
               QStringLiteral("retention above one year is clamped down"));
    checkEqual(store.retention().maxEvents, 20000,
               QStringLiteral("an event bound above 20000 is clamped down"));
    store.setRetention(AuditRetentionSettings());

    const QDateTime now = QDateTime::currentDateTime();

    AuditEvent detection;
    detection.type = AuditEvent::EventType::Detection;
    detection.scope = QStringLiteral("C:/Apps/updater.exe");
    detection.reason = QStringLiteral("sustained upload observed");
    detection.result = QStringLiteral("observed");
    store.append(detection);
    checkEqual(store.count(), 1, QStringLiteral("append stores one event"));
    check(store.events().first().timestamp.isValid(),
          QStringLiteral("an event with no timestamp is stamped on append"));

    AuditEvent policyChange;
    policyChange.timestamp = now.addSecs(-10);
    policyChange.type = AuditEvent::EventType::PolicyChange;
    policyChange.scope = QStringLiteral("group:chrome");
    policyChange.reason = QStringLiteral("user created a policy");
    policyChange.result = QStringLiteral("saved");
    policyChange.relatedPolicyId = QStringLiteral("policy-1");
    policyChange.relatedIdentityId = QStringLiteral("sha1:abc");
    store.append(policyChange);

    AuditEvent enforcement;
    enforcement.timestamp = now.addSecs(-5);
    enforcement.type = AuditEvent::EventType::EnforcementResult;
    enforcement.scope = QStringLiteral("C:/Apps/updater.exe");
    enforcement.reason = QStringLiteral("throttle requested");
    enforcement.result = QStringLiteral("applied");
    enforcement.errorInfo = QStringLiteral("upload channel unavailable");
    enforcement.relatedPolicyId = QStringLiteral("policy-1");
    enforcement.details = QStringLiteral("{\"direction\":\"download\"}");
    store.append(enforcement);
    checkEqual(store.count(), 3, QStringLiteral("the store keeps every appended event"));

    AuditQuery byType;
    byType.types << AuditEvent::EventType::EnforcementResult;
    const QList<AuditEvent> enforcementEvents = store.query(byType);
    checkEqual(static_cast<int>(enforcementEvents.size()), 1,
               QStringLiteral("query filters by event type"));
    checkEqual(enforcementEvents.first().result, QStringLiteral("applied"),
               QStringLiteral("the filtered event keeps its outcome"));

    AuditQuery byIdentity;
    byIdentity.identityId = QStringLiteral("sha1:abc");
    checkEqual(static_cast<int>(store.query(byIdentity).size()), 1,
               QStringLiteral("query filters by related identity"));

    AuditQuery byPolicy;
    byPolicy.policyId = QStringLiteral("policy-1");
    checkEqual(static_cast<int>(store.query(byPolicy).size()), 2,
               QStringLiteral("query filters by related policy"));

    AuditQuery byScope;
    byScope.scope = QStringLiteral("group:chrome");
    checkEqual(static_cast<int>(store.query(byScope).size()), 1,
               QStringLiteral("query filters by exact scope"));

    AuditQuery byText;
    byText.text = QStringLiteral("UNAVAILABLE");
    checkEqual(static_cast<int>(store.query(byText).size()), 1,
               QStringLiteral("query matches free text case-insensitively"));

    AuditQuery byWindow;
    byWindow.from = now.addSecs(-7);
    const QList<AuditEvent> window = store.query(byWindow);
    checkEqual(static_cast<int>(window.size()), 2,
               QStringLiteral("query honours the start of a time window"));
    check(window.first().timestamp <= window.last().timestamp,
          QStringLiteral("query results are chronological"));

    AuditQuery newest;
    newest.limit = 2;
    const QList<AuditEvent> recent = store.query(newest);
    checkEqual(static_cast<int>(recent.size()), 2,
               QStringLiteral("query limit keeps two events"));
    checkEqual(static_cast<int>(recent.first().type),
               static_cast<int>(AuditEvent::EventType::EnforcementResult),
               QStringLiteral("a limited query keeps the newest events"));

    // The event bound evicts the oldest first.
    AuditRetentionSettings tiny;
    tiny.maxEvents = 2;
    store.setRetention(tiny);
    checkEqual(store.count(), 2,
               QStringLiteral("the event bound is enforced immediately"));
    check(store.events().first().type == AuditEvent::EventType::EnforcementResult,
          QStringLiteral("the oldest event is evicted first"));

    // Shortening the window forgets an older event immediately.
    store.setRetention(AuditRetentionSettings());
    AuditEvent outdated;
    outdated.timestamp = QDateTime::currentDateTime().addDays(-3);
    outdated.type = AuditEvent::EventType::Detection;
    outdated.reason = QStringLiteral("old detection");
    store.append(outdated);
    const int beforeWindowShrink = store.count();
    AuditRetentionSettings shortWindow;
    shortWindow.retentionDays = 1;
    store.setRetention(shortWindow);
    checkEqual(store.count(), beforeWindowShrink - 1,
               QStringLiteral("shortening retention forgets an older event"));
    bool oldSeen = false;
    for (const AuditEvent &event : store.events())
        if (event.reason == QStringLiteral("old detection")) oldSeen = true;
    check(!oldSeen, QStringLiteral("the expired event is gone from the store"));

    // Clearing keeps the bounds but removes every event, on disk too.
    store.clear();
    checkEqual(store.count(), 0, QStringLiteral("clear empties the log"));
    checkEqual(store.retention().retentionDays, 1,
               QStringLiteral("clear keeps the retention settings"));
    {
        AuditEventStore reloadedEmpty;
        checkEqual(reloadedEmpty.count(), 0,
                   QStringLiteral("the cleared log is persisted"));
    }

    // Persistence round-trip.
    QSettings().clear();
    {
        AuditEventStore persisted;
        AuditRetentionSettings bounds;
        bounds.retentionDays = 7;
        bounds.maxEvents = 100;
        persisted.setRetention(bounds);
        AuditEvent first;
        first.timestamp = now.addSecs(-20);
        first.type = AuditEvent::EventType::PolicyChange;
        first.scope = QStringLiteral("group:chrome");
        first.reason = QStringLiteral("user created a policy");
        first.result = QStringLiteral("saved");
        first.relatedPolicyId = QStringLiteral("policy-1");
        first.relatedIdentityId = QStringLiteral("sha1:abc");
        first.details = QStringLiteral("status metadata");
        persisted.append(first);
        AuditEvent second;
        second.timestamp = now.addSecs(-1);
        second.type = AuditEvent::EventType::EnforcementResult;
        second.scope = QStringLiteral("C:/Apps/updater.exe");
        second.reason = QStringLiteral("policy channel reported an outcome");
        second.result = QStringLiteral("applied");
        second.relatedPolicyId = QStringLiteral("policy-1");
        persisted.append(second);
    }
    AuditEventStore reloaded;
    checkEqual(reloaded.retention().retentionDays, 7,
               QStringLiteral("retention days survive a restart"));
    checkEqual(reloaded.retention().maxEvents, 100,
               QStringLiteral("the event bound survives a restart"));
    checkEqual(reloaded.count(), 2, QStringLiteral("audit events survive a restart"));
    checkEqual(reloaded.events().first().scope, QStringLiteral("group:chrome"),
               QStringLiteral("a reloaded event keeps its scope"));
    checkEqual(reloaded.events().last().result, QStringLiteral("applied"),
               QStringLiteral("a reloaded event keeps its outcome"));

    // Export: versioned, named, counted, and metadata only.
    const QString exportJson = reloaded.exportJson();
    const QJsonObject root = objectOf(exportJson);
    checkEqual(root.value(QStringLiteral("format")).toString(),
               QStringLiteral("oasis.audit-log"),
               QStringLiteral("the audit export carries its format marker"));
    checkEqual(root.value(QStringLiteral("schemaVersion")).toInt(), 1,
               QStringLiteral("the audit export carries the schema version"));
    check(QDateTime::fromString(root.value(QStringLiteral("exportedAt")).toString(),
                                Qt::ISODateWithMs).isValid(),
          QStringLiteral("the audit export is timestamped"));
    checkEqual(root.value(QStringLiteral("count")).toInt(), 2,
               QStringLiteral("the audit export counts its events"));
    const QJsonObject retentionObject =
        root.value(QStringLiteral("retention")).toObject();
    checkEqual(retentionObject.value(QStringLiteral("days")).toInt(), 7,
               QStringLiteral("the audit export reports the retention window"));
    checkEqual(retentionObject.value(QStringLiteral("maxEvents")).toInt(), 100,
               QStringLiteral("the audit export reports the event bound"));

    const QJsonArray exportedEvents = root.value(QStringLiteral("events")).toArray();
    checkEqual(static_cast<int>(exportedEvents.size()), 2,
               QStringLiteral("the audit export lists every event"));
    const QJsonObject exportedEvent = exportedEvents.first().toObject();
    checkEqual(exportedEvent.value(QStringLiteral("type")).toString(),
               QStringLiteral("PolicyChange"),
               QStringLiteral("the export names the event type"));
    check(exportedEvent.value(QStringLiteral("timestamp")).toString().contains(QLatin1Char('T')),
          QStringLiteral("the exported event has an ISO timestamp"));
    const QStringList allowedKeys = {
        QStringLiteral("details"), QStringLiteral("errorInfo"),
        QStringLiteral("reason"), QStringLiteral("relatedIdentityId"),
        QStringLiteral("relatedPolicyId"), QStringLiteral("result"),
        QStringLiteral("scope"), QStringLiteral("timestamp"),
        QStringLiteral("type")
    };
    for (const QString &key : exportedEvent.keys()) {
        check(allowedKeys.contains(key),
              QStringLiteral("the export writes only contract fields (unexpected %1)").arg(key));
    }
    const QString exportText = exportJson.toLower();
    check(!exportText.contains(QStringLiteral("payload")) &&
          !exportText.contains(QStringLiteral("packetcontent")),
          QStringLiteral("the audit export adds no packet-payload key"));

    // Corrupt or newer persisted data is rejected rather than half-applied.
    QSettings().clear();
    {
        QSettings settings;
        settings.beginGroup(QStringLiteral("Oasis/Audit"));
        settings.setValue(QStringLiteral("storeVersion"), 99);
        settings.setValue(QStringLiteral("events"),
                          QStringLiteral("[{\"timestamp\":\"2026-01-01T00:00:00\",\"type\":7}]"));
        settings.endGroup();
    }
    AuditEventStore newer;
    checkEqual(newer.count(), 0,
               QStringLiteral("a newer audit store version is ignored as a whole"));
    checkEqual(newer.retention().retentionDays, 30,
               QStringLiteral("a rejected store falls back to default bounds"));

    QSettings().clear();
    {
        QSettings settings;
        settings.beginGroup(QStringLiteral("Oasis/Audit"));
        settings.setValue(QStringLiteral("storeVersion"), 1);
        settings.setValue(QStringLiteral("events"), QStringLiteral("not json"));
        settings.endGroup();
    }
    AuditEventStore malformed;
    checkEqual(malformed.count(), 0,
               QStringLiteral("a malformed audit payload loads as empty"));

    QSettings().clear();
    {
        QSettings settings;
        settings.beginGroup(QStringLiteral("Oasis/Audit"));
        settings.setValue(QStringLiteral("storeVersion"), 1);
        settings.setValue(QStringLiteral("events"),
                          QStringLiteral("[{\"timestamp\":\"%1\",\"type\":0,"
                                         "\"reason\":\"kept\"},{\"type\":0}]")
                              .arg(QDateTime::currentDateTime().addDays(-1)
                                       .toString(Qt::ISODate)));
        settings.endGroup();
    }
    AuditEventStore partial;
    checkEqual(partial.count(), 1,
               QStringLiteral("an unreadable event is skipped and the rest are kept"));
    checkEqual(partial.events().first().reason, QStringLiteral("kept"),
               QStringLiteral("the readable event keeps its fields"));

    QSettings().clear();
}

// ─── NG-050 view: filterable audit log model ───────────────────────────────
// The model is the view's only data path: it must re-query on every store
// change, apply type/text/time filters, and expose exactly the rows an export
// would write.
void testAuditLogModel()
{
    QSettings().clear();

    AuditEventStore store;
    AuditLogModel model;
    checkEqual(model.rowCount(), 0, QStringLiteral("a model without a store is empty"));
    model.setStore(&store);
    checkEqual(model.rowCount(), 0, QStringLiteral("a model over an empty store is empty"));
    checkEqual(model.columnCount(), 6, QStringLiteral("the audit view has six columns"));
    checkEqual(model.headerData(AuditLogModel::TypeColumn, Qt::Horizontal).toString(),
               QStringLiteral("Type"),
               QStringLiteral("the audit view names its type column"));

    int changes = 0;
    QObject::connect(&store, &AuditEventStore::changed, &store, [&changes]() { ++changes; });

    const QDateTime now = QDateTime::currentDateTime();

    AuditEvent detection;
    detection.type = AuditEvent::EventType::Detection;
    detection.scope = QStringLiteral("C:/Apps/updater.exe");
    detection.reason = QStringLiteral("sustained upload observed");
    detection.result = QStringLiteral("observed");
    store.append(detection);

    AuditEvent policyChange;
    policyChange.timestamp = now.addSecs(-10);
    policyChange.type = AuditEvent::EventType::PolicyChange;
    policyChange.scope = QStringLiteral("group:chrome");
    policyChange.reason = QStringLiteral("user created a policy");
    policyChange.result = QStringLiteral("saved");
    policyChange.relatedPolicyId = QStringLiteral("policy-1");
    store.append(policyChange);

    AuditEvent enforcement;
    enforcement.timestamp = now.addSecs(-5);
    enforcement.type = AuditEvent::EventType::EnforcementResult;
    enforcement.scope = QStringLiteral("C:/Apps/updater.exe");
    enforcement.reason = QStringLiteral("throttle requested");
    enforcement.result = QStringLiteral("applied");
    enforcement.relatedPolicyId = QStringLiteral("policy-1");
    enforcement.details = QStringLiteral("{\"direction\":\"download\"}");
    store.append(enforcement);

    AuditEvent oldDetection;
    oldDetection.timestamp = now.addDays(-10);
    oldDetection.type = AuditEvent::EventType::Detection;
    oldDetection.scope = QStringLiteral("C:/Apps/old.exe");
    oldDetection.reason = QStringLiteral("old detection");
    store.append(oldDetection);

    checkEqual(changes, 4, QStringLiteral("every append notifies the view"));
    checkEqual(model.rowCount(), 4,
               QStringLiteral("the model follows the store automatically"));

    // Chronological rows, typed display strings, and a detailed tooltip.
    checkEqual(model.data(model.index(1, AuditLogModel::ReasonColumn)).toString(),
               QStringLiteral("user created a policy"),
               QStringLiteral("the model shows the event reason"));
    checkEqual(model.data(model.index(2, AuditLogModel::TypeColumn)).toString(),
               QStringLiteral("EnforcementResult"),
               QStringLiteral("the model shows the event type name"));
    check(!model.data(model.index(2, AuditLogModel::TimeColumn)).toString().isEmpty(),
          QStringLiteral("the model shows a formatted timestamp"));
    check(model.data(model.index(2, AuditLogModel::TypeColumn),
                     AuditLogModel::TypeRole).toInt() ==
              static_cast<int>(AuditEvent::EventType::EnforcementResult),
          QStringLiteral("the type role carries the enum value"));
    check(model.data(model.index(2, AuditLogModel::TypeColumn), Qt::ToolTipRole)
              .toString()
              .contains(QStringLiteral("Policy: policy-1")),
          QStringLiteral("the tooltip explains the related policy"));

    // Type, text (including scope), and time-window filters.
    model.setFilters(static_cast<int>(AuditEvent::EventType::EnforcementResult), QString(), 0);
    checkEqual(model.rowCount(), 1, QStringLiteral("the model filters by event type"));
    checkEqual(model.eventAt(0).relatedPolicyId, QStringLiteral("policy-1"),
               QStringLiteral("a filtered row keeps its event"));

    model.setFilters(-1, QStringLiteral("GROUP:CHROME"), 0);
    checkEqual(model.rowCount(), 1,
               QStringLiteral("text filtering includes the scope case-insensitively"));

    model.setFilters(-1, QStringLiteral("direction"), 0);
    checkEqual(model.rowCount(), 1,
               QStringLiteral("text filtering searches the details"));

    model.setFilters(-1, QString(), 24);
    checkEqual(model.rowCount(), 3,
               QStringLiteral("the time window hides an older event"));

    model.setFilters(-1, QString(), 0);
    checkEqual(model.rowCount(), 4, QStringLiteral("clearing the filters shows every event"));
    check(model.eventAt(-1).scope.isEmpty(),
          QStringLiteral("an out-of-range row returns an empty event"));

    // The visible snapshot is what an export writes, with the same envelope.
    model.setFilters(static_cast<int>(AuditEvent::EventType::EnforcementResult), QString(), 0);
    const QJsonObject filtered = objectOf(store.exportJson(model.visibleEvents()));
    checkEqual(filtered.value(QStringLiteral("count")).toInt(), 1,
               QStringLiteral("exporting the visible rows counts one event"));
    checkEqual(static_cast<int>(filtered.value(QStringLiteral("events")).toArray().size()), 1,
               QStringLiteral("exporting the visible rows writes one object"));
    checkEqual(objectOf(store.exportJson()).value(QStringLiteral("count")).toInt(), 4,
               QStringLiteral("exporting the whole log still counts every event"));

    store.clear();
    checkEqual(changes, 5, QStringLiteral("clearing notifies the view"));
    checkEqual(model.rowCount(), 0, QStringLiteral("clearing empties the view too"));

    QSettings().clear();
}

void testNotificationCoordinator()
{
    NotificationSettings settings;
    settings.cooldownMs = 60 * 1000;
    settings.windowMs = 60 * 1000;
    settings.maxDeliveriesPerWindow = 3;
    NotificationCoordinator coordinator(settings);

    AppNotification alert;
    alert.key = QStringLiteral("bandwidth:updater.exe:limited");
    alert.title = QStringLiteral("Bandwidth limited");
    alert.message = QStringLiteral("updater.exe was limited to 50 KiB/s.");
    alert.priority = NotificationPriority::Info;

    const qint64 start = 1000000;

    const NotificationDecision first = coordinator.submit(alert, start);
    check(first.deliver, QStringLiteral("the first notification is delivered"));
    checkEqual(first.suppressedCount, 0,
               QStringLiteral("a first delivery folds nothing"));
    checkEqual(first.reason, QStringLiteral("delivered"),
               QStringLiteral("a first delivery reports why it was shown"));

    const NotificationDecision repeat = coordinator.submit(alert, start + 1000);
    check(!repeat.deliver, QStringLiteral("a repeat inside the cooldown is suppressed"));
    checkEqual(repeat.reason, QStringLiteral("duplicate"),
               QStringLiteral("a repeat is attributed to the per-key cooldown"));
    checkEqual(coordinator.suppressedCount(alert.key), 1,
               QStringLiteral("the suppressed repeat is counted"));

    coordinator.submit(alert, start + 2000);
    checkEqual(coordinator.suppressedCount(alert.key), 2,
               QStringLiteral("a second suppressed repeat is counted too"));

    const NotificationDecision aggregated = coordinator.submit(alert, start + 60000);
    check(aggregated.deliver,
          QStringLiteral("the same key is delivered once its cooldown ends"));
    checkEqual(aggregated.suppressedCount, 2,
               QStringLiteral("the delivery folds in the suppressed repeats"));
    checkEqual(coordinator.suppressedCount(alert.key), 0,
               QStringLiteral("folding a delivery clears the pending count"));

    // A critical failure is never hidden by the per-key cooldown.
    AppNotification failure;
    failure.key = QStringLiteral("enforcement:policy-1:updater.exe");
    failure.title = QStringLiteral("Enforcement failed");
    failure.message = QStringLiteral("The QoS channel failed.");
    failure.priority = NotificationPriority::Critical;
    check(coordinator.submit(failure, start + 60500).deliver,
          QStringLiteral("a critical failure is delivered"));
    check(coordinator.submit(failure, start + 60600).deliver,
          QStringLiteral("a critical failure bypasses its own cooldown"));

    // A burst of different info notifications is capped per window, and the
    // folded count survives until the window clears.
    NotificationCoordinator capped(settings);
    AppNotification one = alert;
    one.key = QStringLiteral("bandwidth:one.exe");
    AppNotification two = alert;
    two.key = QStringLiteral("bandwidth:two.exe");
    AppNotification three = alert;
    three.key = QStringLiteral("bandwidth:three.exe");

    check(capped.submit(one, start).deliver,
          QStringLiteral("the first distinct notification is delivered"));
    check(capped.submit(two, start + 10).deliver,
          QStringLiteral("the second distinct notification is delivered"));
    check(capped.submit(three, start + 20).deliver,
          QStringLiteral("the third distinct notification is delivered"));

    AppNotification four = alert;
    four.key = QStringLiteral("bandwidth:four.exe");
    const NotificationDecision limited = capped.submit(four, start + 30);
    check(!limited.deliver, QStringLiteral("a burst beyond the window cap is suppressed"));
    check(limited.rateLimited,
          QStringLiteral("the cap is reported separately from a duplicate"));
    checkEqual(limited.reason, QStringLiteral("rate-limited"),
               QStringLiteral("the rate-limit reason is explicit"));

    check(capped.submit(failure, start + 40).deliver,
          QStringLiteral("critical bypasses the cross-key window cap"));

    const NotificationDecision afterWindow = capped.submit(four, start + 60000);
    check(afterWindow.deliver, QStringLiteral("the cap clears once its window passes"));
    checkEqual(afterWindow.suppressedCount, 1,
               QStringLiteral("the rate-limited notification is folded into the next one"));

    // An empty key falls back to the title and message.
    NotificationCoordinator fallback;
    AppNotification anonymous;
    anonymous.title = QStringLiteral("Scan finished");
    anonymous.message = QStringLiteral("No threats were found.");
    check(fallback.submit(anonymous, start).deliver,
          QStringLiteral("an empty key still delivers the first time"));
    check(!fallback.submit(anonymous, start + 100).deliver,
          QStringLiteral("an identical notification deduplicates without a key"));
    anonymous.message = QStringLiteral("One item needs review.");
    check(fallback.submit(anonymous, start + 200).deliver,
          QStringLiteral("a different message is not folded without a key"));

    // Warning follows the same dedupe as info; critical does not.
    NotificationCoordinator priorities(settings);
    AppNotification warning = alert;
    warning.key = QStringLiteral("bandwidth:warning.exe");
    warning.priority = NotificationPriority::Warning;
    check(priorities.submit(warning, start).deliver,
          QStringLiteral("a warning is delivered"));
    check(!priorities.submit(warning, start + 500).deliver,
          QStringLiteral("a repeated warning is deduplicated"));

    // A zero cooldown allows immediate repeats; settings are clamped.
    NotificationSettings noCooldown = settings;
    noCooldown.cooldownMs = 0;
    NotificationCoordinator immediate(noCooldown);
    check(immediate.submit(alert, start).deliver,
          QStringLiteral("the first notification with no cooldown is delivered"));
    check(immediate.submit(alert, start).deliver,
          QStringLiteral("a zero cooldown permits an immediate repeat"));

    NotificationSettings bad;
    bad.cooldownMs = -5;
    bad.windowMs = 0;
    bad.maxDeliveriesPerWindow = 0;
    const NotificationSettings clean = NotificationCoordinator::sanitized(bad);
    checkEqual(clean.cooldownMs, 0, QStringLiteral("a negative cooldown is clamped to zero"));
    checkEqual(clean.windowMs, 60 * 1000,
               QStringLiteral("a non-positive window falls back to one minute"));
    checkEqual(clean.maxDeliveriesPerWindow, 1,
               QStringLiteral("the delivery cap is at least one"));

    checkEqual(coordinator.suppressedCount(QStringLiteral("never-seen")), 0,
               QStringLiteral("an unknown key has no pending repeats"));
    coordinator.reset();
    checkEqual(coordinator.suppressedCount(alert.key), 0,
               QStringLiteral("reset forgets pending repeats"));
    check(coordinator.submit(alert, start).deliver,
          QStringLiteral("reset forgets delivery times too"));
}


void testApplicationDetailModel()
{
    using namespace ApplicationDetail;

    // ── Which stored policy targets an application ──
    ActivityQuery query;
    query.executablePath = QStringLiteral("C:/Apps/Google/GoogleUpdater.exe");
    query.groupId = QStringLiteral("group-google");
    query.serviceName = QStringLiteral("wuauserv");
    query.publisher = QStringLiteral("Google LLC");

    NetworkPolicy pathPolicy;
    pathPolicy.scope = QStringLiteral("path");
    pathPolicy.targetId = QStringLiteral("c:/apps/google/googleupdater.exe");
    check(policyTargets(pathPolicy, query, 0),
          QStringLiteral("an executable path matches a path policy case-insensitively"));

    NetworkPolicy pidPolicy;
    pidPolicy.scope = QStringLiteral("pid");
    pidPolicy.targetId = QStringLiteral("4321");
    check(policyTargets(pidPolicy, query, 4321),
          QStringLiteral("a pid policy matches the running process"));
    check(!policyTargets(pidPolicy, query, 0),
          QStringLiteral("a pid policy matches no other process"));
    check(!policyTargets(pidPolicy, query, 9999),
          QStringLiteral("a different pid is not covered"));

    NetworkPolicy groupPolicy;
    groupPolicy.scope = QStringLiteral("group");
    groupPolicy.targetId = QStringLiteral("GROUP-GOOGLE");
    check(policyTargets(groupPolicy, query, 0),
          QStringLiteral("a group policy matches its group id case-insensitively"));

    NetworkPolicy servicePolicy;
    servicePolicy.scope = QStringLiteral("service");
    servicePolicy.targetId = QStringLiteral("WUAUSERV");
    check(policyTargets(servicePolicy, query, 0),
          QStringLiteral("a service policy matches the service key"));

    NetworkPolicy publisherPolicy;
    publisherPolicy.scope = QStringLiteral("publisher");
    publisherPolicy.targetId = QStringLiteral("google llc");
    check(policyTargets(publisherPolicy, query, 0),
          QStringLiteral("a publisher policy matches case-insensitively"));

    NetworkPolicy packagePolicy;
    packagePolicy.scope = QStringLiteral("package");
    packagePolicy.targetId = QStringLiteral("SpotifyAB.SpotifyMusic");
    check(!policyTargets(packagePolicy, query, 0),
          QStringLiteral("a package scope is not claimed from process evidence"));

    NetworkPolicy emptyTarget;
    emptyTarget.scope = QStringLiteral("path");
    check(!policyTargets(emptyTarget, query, 0),
          QStringLiteral("a policy without a target matches nothing"));

    NetworkPolicy described;
    described.scope = QStringLiteral("path");
    described.targetId = QStringLiteral("C:/Apps/a.exe");
    described.description = QStringLiteral("Nightly package downloads");
    checkEqual(policySummaryText(described), QStringLiteral("Nightly package downloads"),
               QStringLiteral("the description is the policy summary when present"));
    described.description.clear();
    checkEqual(policySummaryText(described), QStringLiteral("path: C:/Apps/a.exe"),
               QStringLiteral("the scope and target are the summary when there is no description"));

    // ── Destinations ──
    Destination dns;
    dns.address = QStringLiteral("142.250.190.78");
    dns.name = QStringLiteral("update.googleapis.com");
    dns.source = attributionSourceName(AttributionSource::DnsAnswer);
    dns.confidence = ApplicationIdentity::Confidence::StrongInference;
    dns.evidence << QStringLiteral("DNS answer for update.googleapis.com");

    Destination tls = dns;
    tls.source = attributionSourceName(AttributionSource::TlsSni);
    tls.confidence = ApplicationIdentity::Confidence::Confirmed;
    tls.evidence = QStringList{QStringLiteral("visible TLS SNI")};

    Destination direct;
    direct.address = QStringLiteral("203.0.113.9");

    const QList<Destination> merged = mergeDestinations({direct, dns, tls});
    checkEqual(int(merged.size()), 2, QStringLiteral("the same name and address is one destination"));
    checkEqual(merged.first().name, QStringLiteral("update.googleapis.com"),
               QStringLiteral("a named destination ranks before a direct address"));
    checkEqual(static_cast<int>(merged.first().confidence),
               static_cast<int>(ApplicationIdentity::Confidence::Confirmed),
               QStringLiteral("the strongest attribution wins the row"));
    checkEqual(int(merged.first().evidence.size()), 2,
               QStringLiteral("evidence from both observations is kept"));
    check(merged.first().source.contains(QStringLiteral("TLS SNI"))
              && merged.first().source.contains(QStringLiteral("DNS answer")),
          QStringLiteral("both attribution sources are reported"));
    checkEqual(merged.last().address, QStringLiteral("203.0.113.9"),
               QStringLiteral("a direct address stays listed"));
    check(merged.last().name.isEmpty(),
          QStringLiteral("a direct address gets no invented name"));

    DestinationNameSummary summary;
    summary.address = QStringLiteral("198.51.100.7");
    summary.name = QStringLiteral("cdn.example.com");
    summary.source = AttributionSource::DnsAndTls;
    summary.confidence = ApplicationIdentity::Confidence::Confirmed;
    summary.evidence << QStringLiteral("DNS and TLS agree");
    const Destination converted = destinationFromSummary(summary);
    checkEqual(converted.name, QStringLiteral("cdn.example.com"),
               QStringLiteral("a correlator summary becomes a destination row"));
    checkEqual(converted.source, attributionSourceName(AttributionSource::DnsAndTls),
               QStringLiteral("the attribution source is carried through"));
    checkEqual(static_cast<int>(converted.confidence),
               static_cast<int>(ApplicationIdentity::Confidence::Confirmed),
               QStringLiteral("the destination confidence is carried through"));
    checkEqual(converted.evidence.value(0), QStringLiteral("DNS and TLS agree"),
               QStringLiteral("the destination evidence is carried through"));

    // ── Assembled view ──
    ActivityClassifier classifier;
    ActivityQuery chromeQuery;
    chromeQuery.executableName = QStringLiteral("updater.exe");
    chromeQuery.publisher = QStringLiteral("Google LLC");
    chromeQuery.product = QStringLiteral("Google Update");
    chromeQuery.publisherVerified = true;

    const QDateTime now = QDateTime::currentDateTimeUtc();

    Input input;
    input.executableName = QStringLiteral("updater.exe");
    input.displayName = QStringLiteral("Google Update");
    input.executablePath = QStringLiteral("C:/Program Files/Google/updater.exe");
    input.identityId = QStringLiteral("identity-1234");
    input.publisher = QStringLiteral("Google LLC");
    input.signerStatus = ApplicationIdentity::SignerStatus::Signed;
    input.pid = 1200;
    input.processStartMs = QDateTime(QDate(2026, 11, 12), QTime(9, 0)).toMSecsSinceEpoch();
    input.groupId = QStringLiteral("group-google");
    input.groupName = QStringLiteral("Google Chrome");
    input.services << QStringLiteral("GoogleUpdaterService");
    input.query = chromeQuery;
    input.query.executablePath = input.executablePath;
    input.query.groupId = input.groupId;
    input.activity = classifier.classify(chromeQuery);
    input.usage.rxBytes = 5ULL * 1024 * 1024;
    input.usage.txBytes = 512ULL * 1024;
    input.usage.rxBytesPerSecond = 1024ULL * 1024;
    input.usage.packets = 4200;
    input.usage.foreground = true;
    input.destinations = {dns, direct};

    RelatedProcess parent;
    parent.name = QStringLiteral("chrome.exe");
    parent.pid = 900;
    parent.role = QStringLiteral("Parent process");
    input.related << parent;
    input.related << parent; // a repeated relationship is folded
    RelatedProcess self;
    self.name = QStringLiteral("self.exe");
    self.pid = input.pid;
    self.role = QStringLiteral("Self");
    input.related << self;

    NetworkPolicy activePolicy;
    activePolicy.id = QStringLiteral("policy-active");
    activePolicy.scope = QStringLiteral("path");
    activePolicy.targetId = input.executablePath;
    activePolicy.description = QStringLiteral("Chrome updates");
    activePolicy.action = NetworkPolicy::Action::Throttle;
    activePolicy.direction = NetworkDirection::Download;
    activePolicy.source = QStringLiteral("user");
    activePolicy.expiration = now.addSecs(3600);

    NetworkPolicy expiredPolicy;
    expiredPolicy.id = QStringLiteral("policy-expired");
    expiredPolicy.scope = QStringLiteral("group");
    expiredPolicy.targetId = input.groupId;
    expiredPolicy.action = NetworkPolicy::Action::Block;
    expiredPolicy.source = QStringLiteral("automatic");
    expiredPolicy.expiration = now.addSecs(-60);

    NetworkPolicy unrelatedPolicy;
    unrelatedPolicy.id = QStringLiteral("policy-unrelated");
    unrelatedPolicy.scope = QStringLiteral("path");
    unrelatedPolicy.targetId = QStringLiteral("C:/Other/other.exe");

    input.policies = {activePolicy, expiredPolicy, unrelatedPolicy};

    AuditEvent older;
    older.timestamp = now.addSecs(-600);
    older.type = AuditEvent::EventType::Detection;
    older.reason = QStringLiteral("sustained download observed");
    older.result = QStringLiteral("observed");
    AuditEvent newer;
    newer.timestamp = now.addSecs(-60);
    newer.type = AuditEvent::EventType::EnforcementResult;
    newer.reason = QStringLiteral("throttle applied");
    newer.result = QStringLiteral("applied");
    input.audit = {older, newer};

    input.internetBlocked = false;
    input.throttleApplied = true;
    input.throttleOwner = QStringLiteral("Chrome updates");
    input.now = now;

    const Snapshot snapshot = build(input);

    checkEqual(snapshot.title, QStringLiteral("Google Update (updater.exe)"),
               QStringLiteral("the title pairs the display name with the executable"));
    check(snapshot.subtitle.contains(QStringLiteral("PID 1200"))
              && snapshot.subtitle.contains(QStringLiteral("foreground")),
          QStringLiteral("the subtitle names the pid and the foreground role"));
    check(snapshot.activitySummary.contains(QStringLiteral("Browser update")),
          QStringLiteral("the activity summary shows the classified category"));
    check(snapshot.activityDetail.contains(QStringLiteral("builtin-chrome-update")),
          QStringLiteral("the activity detail names the matched rule"));
    check(!snapshot.evidence.isEmpty(),
          QStringLiteral("classification evidence is carried into the view"));
    check(snapshot.activitySummary.contains(QStringLiteral("Likely")),
          QStringLiteral("the summary qualifies a Likely classification"));

    bool hasPath = false;
    bool hasIdentity = false;
    bool hasGroup = false;
    bool hasLimit = false;
    for (const QPair<QString, QString> &fact : snapshot.facts) {
        if (fact.first == QStringLiteral("Executable"))
            hasPath = fact.second == input.executablePath;
        if (fact.first == QStringLiteral("Identity"))
            hasIdentity = fact.second == QStringLiteral("identity-1234");
        if (fact.first == QStringLiteral("Activity group"))
            hasGroup = fact.second == QStringLiteral("Google Chrome");
        if (fact.first == QStringLiteral("Bandwidth limit"))
            hasLimit = fact.second.contains(QStringLiteral("Chrome updates"));
    }
    check(hasPath, QStringLiteral("the identity facts name the executable path"));
    check(hasIdentity, QStringLiteral("the identity facts name the durable identity"));
    check(hasGroup, QStringLiteral("the identity facts name the activity group"));
    check(hasLimit, QStringLiteral("a limit names the policy that owns it"));
    checkEqual(int(snapshot.destinations.size()), 2, QStringLiteral("only the known destinations are listed"));
    checkEqual(int(snapshot.related.size()), 1,
               QStringLiteral("related processes are de-duplicated and exclude this process"));
    checkEqual(snapshot.related.first().pid, 900u,
               QStringLiteral("the parent process is the related process"));
    checkEqual(int(snapshot.policies.size()), 2,
               QStringLiteral("only policies targeting this application are listed"));
    QString activeState;
    QString expiredState;
    bool activeInForce = false;
    for (const PolicyEntry &entry : snapshot.policies) {
        if (entry.id == QStringLiteral("policy-active")) {
            activeState = entry.state;
            activeInForce = entry.inForce;
        }
        if (entry.id == QStringLiteral("policy-expired")) expiredState = entry.state;
    }
    checkEqual(activeState, QStringLiteral("Active"),
               QStringLiteral("a live policy is reported Active"));
    check(activeInForce, QStringLiteral("an Active policy is in force"));
    checkEqual(expiredState, QStringLiteral("Expired"),
               QStringLiteral("a past expiration is reported Expired"));
    check(snapshot.policySummary.contains(QStringLiteral("2 policies"))
              && snapshot.policySummary.contains(QStringLiteral("1 in force")),
          QStringLiteral("the policy summary counts matched and in-force policies"));
    checkEqual(snapshot.policies.value(0).action, QStringLiteral("Throttle"),
               QStringLiteral("the policy action is shown by name"));
    checkEqual(snapshot.policies.value(0).origin, QStringLiteral("created by you"),
               QStringLiteral("the policy origin is explained"));
    checkEqual(int(snapshot.audit.size()), 2, QStringLiteral("the audit history lists both events"));
    check(snapshot.audit.first().at > snapshot.audit.last().at,
          QStringLiteral("the newest audit event is first"));
    checkEqual(snapshot.audit.first().summary, QStringLiteral("throttle applied"),
               QStringLiteral("the audit line prefers the reason"));
    checkEqual(snapshot.auditSummary, QStringLiteral("2 events · newest first"),
               QStringLiteral("the audit summary counts the entries"));

    auto actionFor = [](const QList<ActionState> &actions, const QString &key) {
        for (const ActionState &action : actions)
            if (action.key == key) return action;
        return ActionState();
    };

    const auto actions = snapshot.actions;
    check(actionFor(actions, QStringLiteral("policy")).enabled,
          QStringLiteral("a policy can be created when a target is known"));
    check(actionFor(actions, QStringLiteral("internet")).label
              == QStringLiteral("Block internet access"),
          QStringLiteral("an unblocked application offers blocking"));
    check(actionFor(actions, QStringLiteral("throttle")).label
              == QStringLiteral("Remove bandwidth limit…"),
          QStringLiteral("a limited application offers removal"));
    check(actionFor(actions, QStringLiteral("group")).enabled,
          QStringLiteral("the activity group action is available for a grouped process"));
    checkEqual(int(actions.size()), 7, QStringLiteral("every reversible action is offered"));

    // An application with no path, scope, or identity still renders, but the
    // actions that need evidence are disabled with a reason.
    Input bare;
    bare.executableName = QStringLiteral("mystery.exe");
    bare.now = now;
    const Snapshot bareSnapshot = build(bare);
    check(bareSnapshot.activityDetail.contains(QStringLiteral("No local rule matched")),
          QStringLiteral("unclassified activity is explained instead of guessed"));
    checkEqual(bareSnapshot.title, QStringLiteral("mystery.exe"),
               QStringLiteral("an unknown application is still named"));
    check(!actionFor(bareSnapshot.actions, QStringLiteral("policy")).enabled,
          QStringLiteral("a policy action is unavailable without a target"));
    check(!actionFor(bareSnapshot.actions, QStringLiteral("internet")).enabled,
          QStringLiteral("blocking is unavailable without a path"));
    check(actionFor(bareSnapshot.actions, QStringLiteral("internet")).reason
              .contains(QStringLiteral("path")),
          QStringLiteral("the disabled action explains what is missing"));
    check(bareSnapshot.policySummary.contains(QStringLiteral("No stored policy")),
          QStringLiteral("an uncovered application says no policy applies"));
    checkEqual(bareSnapshot.relatedSummary,
               QStringLiteral("No related process is known. Activity groups are built from "
                              "identity, publisher, service, and lineage evidence as traffic "
                              "is observed."),
               QStringLiteral("an empty related section explains where groups come from"));

    // Audit history is a sample: the store keeps the rest.
    Input many;
    many.now = now;
    for (int index = 0; index < ApplicationDetail::kMaxAuditEntries + 5; ++index) {
        AuditEvent event;
        event.timestamp = now.addSecs(index);
        event.reason = QStringLiteral("event %1").arg(index);
        many.audit << event;
    }
    checkEqual(int(build(many).audit.size()), ApplicationDetail::kMaxAuditEntries,
               QStringLiteral("the audit history is capped"));

    checkEqual(formatBytes(1536), QStringLiteral("1.5 KiB"),
               QStringLiteral("bytes are formatted in binary units"));
    checkEqual(formatRate(0), QStringLiteral("0 B/s"),
               QStringLiteral("a zero rate is still readable"));
    checkEqual(signerLabel(ApplicationIdentity::SignerStatus::Signed), QStringLiteral("signed"),
               QStringLiteral("the signer status is spelled out"));
}

// ─── NG-055: filtered evidence exports ──────────────────────────────────────
void testEvidenceExport()
{
    // CSV escaping: only the fields that need it are quoted, and an embedded
    // quote is doubled rather than dropped.
    checkEqual(EvidenceExport::csvField(QStringLiteral("plain")), QStringLiteral("plain"),
               QStringLiteral("a plain CSV field stays unquoted"));
    checkEqual(EvidenceExport::csvField(QStringLiteral("a,b")), QStringLiteral("\"a,b\""),
               QStringLiteral("a field with a comma is quoted"));
    checkEqual(EvidenceExport::csvField(QStringLiteral("say \"hi\"")),
               QStringLiteral("\"say \"\"hi\"\"\""),
               QStringLiteral("an embedded quote is doubled"));
    checkEqual(EvidenceExport::csvField(QStringLiteral("line\nbreak")), QStringLiteral("\"line\nbreak\""),
               QStringLiteral("a field with a line break is quoted"));
    checkEqual(EvidenceExport::csvField(QStringLiteral(" padded ")), QStringLiteral("\" padded \""),
               QStringLiteral("leading or trailing spaces force quotes"));
    checkEqual(EvidenceExport::csvRow({QStringLiteral("a"), QStringLiteral("b,c")}),
               QStringLiteral("a,\"b,c\"\n"),
               QStringLiteral("a CSV row joins quoted fields"));

    const QString stamp = QStringLiteral("2026-11-12T10:00:00.000Z");
    const QDateTime when = QDateTime::fromString(stamp, Qt::ISODate);

    AuditEvent event;
    event.timestamp = when;
    event.type = AuditEvent::EventType::EnforcementResult;
    event.scope = QStringLiteral("path:C:/Apps/browser.exe");
    event.reason = QStringLiteral("connected to example.com and 93.184.216.34");
    event.result = QStringLiteral("blocked");
    event.details = QStringLiteral("host api.example.com:443, file C:/Apps/browser.exe");

    AuditRetentionSettings retention;
    retention.retentionDays = 7;
    retention.maxEvents = 100;

    const QJsonObject auditVerbatim =
        objectOf(EvidenceExport::auditJson({event}, retention, false, stamp));
    checkEqual(auditVerbatim.value(QStringLiteral("format")).toString(),
               QStringLiteral("oasis.audit-log"),
               QStringLiteral("the audit export keeps its format marker"));
    checkEqual(auditVerbatim.value(QStringLiteral("schemaVersion")).toInt(), 1,
               QStringLiteral("the audit export carries the schema version"));
    checkEqual(auditVerbatim.value(QStringLiteral("exportedAt")).toString(), stamp,
               QStringLiteral("the audit export uses the injected timestamp"));
    checkEqual(auditVerbatim.value(QStringLiteral("redacted")).toBool(true), false,
               QStringLiteral("the verbatim audit export says it is not redacted"));
    checkEqual(auditVerbatim.value(QStringLiteral("count")).toInt(), 1,
               QStringLiteral("the audit export counts its rows"));
    checkEqual(auditVerbatim.value(QStringLiteral("retention")).toObject()
                   .value(QStringLiteral("days")).toInt(),
               7, QStringLiteral("the audit export reports the retention window"));
    const QString verbatimReason = auditVerbatim.value(QStringLiteral("events")).toArray()
                                       .first().toObject()
                                       .value(QStringLiteral("reason")).toString();
    check(verbatimReason.contains(QStringLiteral("example.com")) &&
              verbatimReason.contains(QStringLiteral("93.184.216.34")),
          QStringLiteral("a verbatim audit export keeps the destination"));

    const QJsonObject auditRedacted =
        objectOf(EvidenceExport::auditJson({event}, retention, true, stamp));
    checkEqual(auditRedacted.value(QStringLiteral("redacted")).toBool(false), true,
               QStringLiteral("the redacted audit export says so"));
    const QJsonObject redactedAuditEvent =
        auditRedacted.value(QStringLiteral("events")).toArray().first().toObject();
    const QString redactedReason = redactedAuditEvent.value(QStringLiteral("reason")).toString();
    check(!redactedReason.contains(QStringLiteral("example.com")) &&
              redactedReason.contains(QStringLiteral("***.com")),
          QStringLiteral("a host name in the audit export is redacted"));
    check(redactedReason.contains(QStringLiteral("93.184.216.x")) &&
              !redactedReason.contains(QStringLiteral("93.184.216.34")),
          QStringLiteral("an address in the audit export is redacted"));
    check(redactedAuditEvent.value(QStringLiteral("scope")).toString()
              .endsWith(QStringLiteral("browser.exe")),
          QStringLiteral("the executable path is not mistaken for a destination"));
    check(redactedAuditEvent.value(QStringLiteral("details")).toString()
              .contains(QStringLiteral("***.com:443")),
          QStringLiteral("a host with a port keeps the port"));

    // The JSON stays metadata-only: no payload key anywhere in the export.
    const QString auditText = EvidenceExport::auditJson({event}, retention, true).toLower();
    check(!auditText.contains(QStringLiteral("payload")) &&
              !auditText.contains(QStringLiteral("packetcontent")),
          QStringLiteral("the audit export adds no payload key"));

    const QString auditCsv = EvidenceExport::auditCsv({event}, true, stamp);
    const QStringList auditLines = auditCsv.split(QLatin1Char('\n'));
    checkEqual(auditLines.value(0), QStringLiteral("# format oasis.audit-log"),
               QStringLiteral("the CSV names its format"));
    checkEqual(auditLines.value(1), QStringLiteral("# schemaVersion 1"),
               QStringLiteral("the CSV carries the schema version"));
    checkEqual(auditLines.value(2), QStringLiteral("# exportedAt %1").arg(stamp),
               QStringLiteral("the CSV is timestamped"));
    checkEqual(auditLines.value(3), QStringLiteral("# redacted true"),
               QStringLiteral("the CSV records the redaction state"));
    checkEqual(auditLines.value(4),
               QStringLiteral("timestamp,type,scope,reason,result,errorInfo,"
                              "relatedIdentityId,relatedPolicyId,details"),
               QStringLiteral("the CSV has one documented header row"));
    checkEqual(int(auditLines.size()), 7,
               QStringLiteral("the CSV has one metadata block, a header, and one row"));
    check(auditLines.value(5).startsWith(QStringLiteral("2026-11-12T10:00:00.000")),
          QStringLiteral("the CSV row starts with the event time"));
    check(auditLines.value(5).contains(QStringLiteral("EnforcementResult")),
          QStringLiteral("the CSV row names the event type in plain words"));
    check(auditLines.value(5).contains(QStringLiteral("\"host ***.com:443, file")),
          QStringLiteral("the CSV row is quoted when it contains a comma and is redacted"));

    // Attribution: one resolved destination with its confidence and evidence.
    DestinationNameSummary summary;
    summary.address = QStringLiteral("93.184.216.34");
    summary.name = QStringLiteral("example.com");
    summary.names << QStringLiteral("example.com") << QStringLiteral("cdn.example.net");
    summary.source = AttributionSource::DnsAndTls;
    summary.confidence = ApplicationIdentity::Confidence::Confirmed;
    summary.expiresAt = QDateTime::fromString(QStringLiteral("2026-11-12T11:00:00Z"), Qt::ISODate);
    summary.evidence << QStringLiteral("DNS answer observed")
                     << QStringLiteral("TLS SNI observed for example.com")
                     << QStringLiteral("endpoint 93.184.216.34");

    const QJsonObject attributionVerbatim =
        objectOf(EvidenceExport::attributionJson({summary}, false, stamp));
    checkEqual(attributionVerbatim.value(QStringLiteral("format")).toString(),
               QStringLiteral("oasis.attribution"),
               QStringLiteral("the attribution export has its own format marker"));
    checkEqual(attributionVerbatim.value(QStringLiteral("schemaVersion")).toInt(), 1,
               QStringLiteral("the attribution export carries the schema version"));
    checkEqual(attributionVerbatim.value(QStringLiteral("count")).toInt(), 1,
               QStringLiteral("the attribution export counts its destinations"));
    const QJsonObject verbatimSummary = attributionVerbatim
        .value(QStringLiteral("destinations")).toArray().first().toObject();
    checkEqual(verbatimSummary.value(QStringLiteral("confidence")).toString(),
               QStringLiteral("confirmed"),
               QStringLiteral("the attribution export names the confidence"));
    checkEqual(verbatimSummary.value(QStringLiteral("source")).toString(),
               QStringLiteral("DNS answer + TLS SNI"),
               QStringLiteral("the attribution export names the sources"));
    checkEqual(verbatimSummary.value(QStringLiteral("name")).toString(),
               QStringLiteral("example.com"),
               QStringLiteral("a verbatim attribution export keeps the name"));

    const QJsonObject attributionRedacted =
        objectOf(EvidenceExport::attributionJson({summary}, true, stamp));
    checkEqual(attributionRedacted.value(QStringLiteral("redacted")).toBool(false), true,
               QStringLiteral("the redacted attribution export says so"));
    const QJsonObject redactedSummary = attributionRedacted
        .value(QStringLiteral("destinations")).toArray().first().toObject();
    checkEqual(redactedSummary.value(QStringLiteral("address")).toString(),
               QStringLiteral("93.184.216.x"),
               QStringLiteral("a redacted destination keeps its network part"));
    checkEqual(redactedSummary.value(QStringLiteral("name")).toString(),
               QStringLiteral("***.com"),
               QStringLiteral("a redacted destination keeps its top-level label"));
    checkEqual(redactedSummary.value(QStringLiteral("confidence")).toString(),
               QStringLiteral("confirmed"),
               QStringLiteral("redaction does not touch the confidence"));
    checkEqual(int(redactedSummary.value(QStringLiteral("names")).toArray().size()), 2,
               QStringLiteral("every observed name is exported"));
    checkEqual(redactedSummary.value(QStringLiteral("names")).toArray().at(1).toString(),
               QStringLiteral("***.net"),
               QStringLiteral("each exported name is redacted"));
    const QString redactedEvidence = redactedSummary.value(QStringLiteral("evidence"))
                                         .toArray().at(1).toString();
    check(!redactedEvidence.contains(QStringLiteral("example.com")) &&
              redactedEvidence.contains(QStringLiteral("***.com")),
          QStringLiteral("the exported evidence is redacted too"));

    const QString attributionCsv = EvidenceExport::attributionCsv({summary}, true, stamp);
    const QStringList attributionLines = attributionCsv.split(QLatin1Char('\n'));
    checkEqual(attributionLines.value(0), QStringLiteral("# format oasis.attribution"),
               QStringLiteral("the attribution CSV names its format"));
    checkEqual(attributionLines.value(4),
               QStringLiteral("address,name,names,source,confidence,expiresAt,evidence"),
               QStringLiteral("the attribution CSV has a confidence column"));
    check(attributionLines.value(5).contains(QStringLiteral("***.com; ***.net")),
          QStringLiteral("the attribution CSV joins every observed name"));
    check(attributionLines.value(5).contains(QStringLiteral("confirmed")),
          QStringLiteral("the attribution CSV row carries the confidence"));

    // An empty selection still produces a valid, readable file.
    const QJsonObject emptyAttribution =
        objectOf(EvidenceExport::attributionJson({}, true, stamp));
    checkEqual(emptyAttribution.value(QStringLiteral("count")).toInt(), 0,
               QStringLiteral("an empty attribution export claims no rows"));
    checkEqual(int(EvidenceExport::attributionCsv({}, true, stamp).split(QLatin1Char('\n')).size()),
               6, QStringLiteral("an empty attribution CSV is metadata plus a header"));
}

// ─── NG-053: scope, effect, duration, and enforcement wording ─────────────
void testPolicyScopePresentation()
{
    PolicyScopeKind parsed = PolicyScopeKind::Service;
    check(policyScopeKindFromKey(QStringLiteral(" group "), &parsed) &&
              parsed == PolicyScopeKind::ApplicationGroup,
          QStringLiteral("a padded group key parses to the group scope"));
    check(!policyScopeKindFromKey(QStringLiteral("package"), &parsed),
          QStringLiteral("a scope the editor cannot represent is reported as unknown"));

    check(policyScopeIsBroad(PolicyScopeKind::Publisher),
          QStringLiteral("publisher scope is broad"));
    check(policyScopeIsBroad(PolicyScopeKind::ApplicationGroup),
          QStringLiteral("application-group scope is broad"));
    check(!policyScopeIsBroad(PolicyScopeKind::Pid) &&
              !policyScopeIsBroad(PolicyScopeKind::ExecutablePath),
          QStringLiteral("PID and path scopes are not broad"));

    check(policyScopeRequiresConfirmation(PolicyScopeKind::Publisher, true),
          QStringLiteral("an enabled publisher policy is confirmed"));
    check(policyScopeRequiresConfirmation(PolicyScopeKind::ApplicationGroup, true),
          QStringLiteral("an enabled group policy is confirmed"));
    check(!policyScopeRequiresConfirmation(PolicyScopeKind::Publisher, false),
          QStringLiteral("a disabled broad policy does not interrupt"));
    check(!policyScopeRequiresConfirmation(PolicyScopeKind::ExecutablePath, true),
          QStringLiteral("a narrow policy is saved without a confirmation"));

    checkEqual(policyRateText(400000), QStringLiteral("0.40 Mbit/s"),
               QStringLiteral("a stored rate is shown in Mbit/s"));
    checkEqual(policyRateText(409600), QStringLiteral("0.41 Mbit/s"),
               QStringLiteral("the default throttle rate formats the same way"));
    checkEqual(policyEffectSummary(NetworkPolicy::Action::Throttle, NetworkDirection::Both,
                                   400000),
               QStringLiteral("Throttle to 0.40 Mbit/s, both directions"),
               QStringLiteral("a throttle effect names the rate and direction"));
    checkEqual(policyEffectSummary(NetworkPolicy::Action::Block, NetworkDirection::Download, 0),
               QStringLiteral("Block, downloads"),
               QStringLiteral("a block effect names the direction"));

    checkEqual(humanizedPolicyDuration(45), QStringLiteral("45 s"),
               QStringLiteral("seconds are shown below a minute"));
    checkEqual(humanizedPolicyDuration(3600), QStringLiteral("1 h"),
               QStringLiteral("a whole hour has no trailing minutes"));
    checkEqual(humanizedPolicyDuration(5400), QStringLiteral("1 h 30 min"),
               QStringLiteral("hours and minutes combine"));
    checkEqual(humanizedPolicyDuration(90000), QStringLiteral("1 d 1 h"),
               QStringLiteral("days and hours combine"));

    const QDateTime now(QDate(2026, 11, 12), QTime(9, 0));
    checkEqual(policyExpirationSummary(QDateTime(), now), QStringLiteral("No expiration"),
               QStringLiteral("a persistent policy says so"));
    checkEqual(policyExpirationSummary(now.addSecs(1800), now),
               QStringLiteral("Expires in 30 min (2026-11-12 09:30)"),
               QStringLiteral("a temporary policy shows its remaining time and stamp"));
    checkEqual(policyExpirationSummary(now.addSecs(-7200), now),
               QStringLiteral("Expired 2 h ago (2026-11-12 07:00)"),
               QStringLiteral("an expired policy shows how long ago"));

    PolicyImpact publisher;
    publisher.scope = PolicyScopeKind::Publisher;
    publisher.target = QStringLiteral("Contoso Ltd.");
    publisher.action = NetworkPolicy::Action::Throttle;
    publisher.direction = NetworkDirection::Both;
    publisher.rateBitsPerSecond = 400000;
    publisher.expiration = now.addSecs(3600);

    const QString impact = policyImpactSummary(publisher, now);
    check(impact.contains(QStringLiteral("Scope: This publisher (Broad)")),
          QStringLiteral("the preview states the scope and its breadth"));
    check(impact.contains(QStringLiteral("Target: Contoso Ltd.")),
          QStringLiteral("the preview states the target"));
    check(impact.contains(
              QStringLiteral("Effect: Throttle to 0.40 Mbit/s, both directions.")),
          QStringLiteral("the preview states the effect and rate"));
    check(impact.contains(QStringLiteral("Duration: Expires in 1 h (2026-11-12 10:00).")),
          QStringLiteral("the preview states the duration"));
    check(impact.contains(QStringLiteral("State: enabled.")),
          QStringLiteral("the preview states the enabled switch"));
    check(impact.contains(
              QStringLiteral("Enforcement: Stored only: this build cannot resolve "
                             "publisher policies")),
          QStringLiteral("the preview admits a stored-only scope"));
    check(!impact.contains(QStringLiteral("0.41 Mbit/s")),
          QStringLiteral("the preview no longer claims a different applied rate"));
    check(impact.contains(QStringLiteral("processes that appear later")),
          QStringLiteral("the preview says the scope reaches future processes"));
    check(!impact.contains(QStringLiteral("Window:")),
          QStringLiteral("no recurring-window line without a schedule"));

    publisher.schedule = QStringLiteral("work-hours");
    const QString windowed = policyImpactSummary(publisher, now);
    check(windowed.contains(QStringLiteral("Window: work-hours (in force now? yes).")),
          QStringLiteral("a recurring window says whether it is in force now"));

    const QString confirmation = policyConfirmationText(publisher, now);
    check(confirmation.startsWith(
              QStringLiteral("Apply this policy to every process signed by "
                             "\"Contoso Ltd.\"?")),
          QStringLiteral("the confirmation names what the broad scope covers"));
    check(confirmation.contains(QStringLiteral("Effect: Throttle to 0.40 Mbit/s")),
          QStringLiteral("the confirmation repeats the impact"));

    PolicyImpact group = publisher;
    group.scope = PolicyScopeKind::ApplicationGroup;
    group.schedule.clear();
    check(policyConfirmationText(group, now).startsWith(
              QStringLiteral("Apply this policy to every member of the group")),
          QStringLiteral("a group confirmation names future members"));

    publisher.enabled = false;
    check(policyImpactSummary(publisher, now).contains(
              QStringLiteral("State: disabled by the user")),
          QStringLiteral("a disabled policy says it is not enforced"));

    NetworkPolicy pathPolicy;
    pathPolicy.scope = QStringLiteral("path");
    pathPolicy.action = NetworkPolicy::Action::Allow;
    checkEqual(policyEnforcementSummary(pathPolicy), QStringLiteral("Enforced"),
               QStringLiteral("a path policy is enforced by this build"));
    // The stored rate is now the enforced rate, so a policy with any rate is
    // simply enforced rather than flagged as an approximation.
    pathPolicy.action = NetworkPolicy::Action::Throttle;
    pathPolicy.rateBitsPerSecond = 400000;
    checkEqual(policyEnforcementSummary(pathPolicy), QStringLiteral("Enforced"),
               QStringLiteral("a throttle policy enforces its own stored rate"));

    NetworkPolicy publisherPolicy;
    publisherPolicy.scope = QStringLiteral("publisher");
    check(policyEnforcementSummary(publisherPolicy).startsWith(QStringLiteral("Stored only")),
          QStringLiteral("a publisher policy is listed as stored only"));
    check(policyEnforcementSummary(publisherPolicy).contains(QStringLiteral("publisher scope")),
          QStringLiteral("the stored-only line names the unresolved scope"));
    publisherPolicy.enabled = false;
    checkEqual(policyEnforcementSummary(publisherPolicy), QStringLiteral("Not enforced (disabled)"),
               QStringLiteral("a disabled policy is reported as not enforced"));

    NetworkPolicy packagePolicy;
    packagePolicy.scope = QStringLiteral("package");
    check(policyEnforcementSummary(packagePolicy).contains(
              QStringLiteral("not known to this build")),
          QStringLiteral("an unknown stored scope is not guessed at"));

    check(policyScopeRiskSummary(PolicyScopeKind::Publisher).contains(QStringLiteral("Broad")),
          QStringLiteral("the risk summary still starts from the breadth"));
}

// ─── NG-054: dashboard ranking, controls, unresolved traffic ──────────────
void testTopConsumers()
{
    const QDateTime now(QDate(2026, 11, 12), QTime(9, 0));

    TopConsumers::Consumer game;
    game.pid = 200;
    game.name = QStringLiteral("game.exe");
    game.rxBytesPerSecond = 5000;
    game.rxBytes = 9000;

    TopConsumers::Consumer chrome;
    chrome.pid = 100;
    chrome.name = QStringLiteral("chrome.exe");
    chrome.identity = QStringLiteral("Google Chrome");
    chrome.path = QStringLiteral("C:/Apps/chrome.exe");
    chrome.rxBytesPerSecond = 3000;
    chrome.txBytesPerSecond = 1000;
    chrome.rxBytes = 40000;
    chrome.txBytes = 20000;
    chrome.activity = QStringLiteral("Browser (Likely)");
    chrome.blocked = true;

    TopConsumers::Consumer updater;
    updater.pid = 300;
    updater.name = QStringLiteral("updater.exe");
    updater.path = QStringLiteral("C:/Apps/updater.exe");
    updater.rxBytesPerSecond = 1000;
    updater.rxBytes = 20000;
    updater.activity = QStringLiteral("Updater (Likely)");
    updater.throttled = true;
    updater.controlOwner = QStringLiteral("Limit background updates");
    updater.recommendation = QStringLiteral("Limit background updates");
    updater.recommendationReason = QStringLiteral("Updates run while the app is idle");

    const QList<TopConsumers::Consumer> consumers{game, chrome, updater};

    check(TopConsumers::isUnresolved(game),
          QStringLiteral("a consumer without a path or activity is unresolved"));
    check(!TopConsumers::isUnresolved(chrome),
          QStringLiteral("a consumer with a path and activity is resolved"));

    const QList<const TopConsumers::Consumer *> top2 =
        TopConsumers::rankConsumers(consumers, 2);
    checkEqual(int(top2.size()), 2, QStringLiteral("the ranking honours its limit"));
    checkEqual(top2.value(0)->name, QStringLiteral("game.exe"),
               QStringLiteral("the highest current rate ranks first"));
    checkEqual(top2.value(1)->name, QStringLiteral("chrome.exe"),
               QStringLiteral("the second-highest rate ranks second"));
    checkEqual(int(TopConsumers::rankConsumers(consumers, 0).size()), 3,
               QStringLiteral("a zero limit means no limit"));
    checkEqual(int(TopConsumers::rankConsumers(consumers, 9).size()), 3,
               QStringLiteral("a limit larger than the list returns the list"));

    TopConsumers::Consumer tieA;
    tieA.pid = 2;
    tieA.name = QStringLiteral("b.exe");
    tieA.rxBytesPerSecond = 100;
    TopConsumers::Consumer tieB;
    tieB.pid = 1;
    tieB.name = QStringLiteral("a.exe");
    tieB.rxBytesPerSecond = 100;
    const QList<const TopConsumers::Consumer *> ties =
        TopConsumers::rankConsumers({tieA, tieB}, 0);
    checkEqual(ties.value(0)->name, QStringLiteral("a.exe"),
               QStringLiteral("equal consumers are ordered by name, not insertion"));

    NetworkPolicy block;
    block.id = QStringLiteral("p-block");
    block.scope = QStringLiteral("path");
    block.targetId = QStringLiteral("C:/Apps/chrome.exe");
    block.action = NetworkPolicy::Action::Block;
    block.description = QStringLiteral("Block Chrome");
    block.expiration = now.addSecs(3600);
    block.scheduleType = NetworkPolicy::ScheduleType::Expiration;

    NetworkPolicy publisher;
    publisher.id = QStringLiteral("p-publisher");
    publisher.scope = QStringLiteral("publisher");
    publisher.targetId = QStringLiteral("Contoso");
    publisher.action = NetworkPolicy::Action::Allow;

    NetworkPolicy expired;
    expired.id = QStringLiteral("p-expired");
    expired.scope = QStringLiteral("path");
    expired.targetId = QStringLiteral("C:/Apps/old.exe");
    expired.expiration = now.addSecs(-60);
    expired.scheduleType = NetworkPolicy::ScheduleType::Expiration;

    NetworkPolicy disabled;
    disabled.id = QStringLiteral("p-disabled");
    disabled.scope = QStringLiteral("path");
    disabled.targetId = QStringLiteral("C:/Apps/off.exe");
    disabled.enabled = false;

    const QList<NetworkPolicy> policies{block, publisher, expired, disabled};
    const TopConsumers::Summary summary =
        TopConsumers::build(consumers, policies, now, 3);

    checkEqual(summary.consumerCount, 3, QStringLiteral("every consumer is counted"));
    checkEqual(int(summary.rows.size()), 3,
               QStringLiteral("the panel shows one row per consumer"));
    checkEqual(summary.topPid, 200u, QStringLiteral("the top consumer is the highest rate"));
    check(summary.headline.contains(QStringLiteral("game.exe is the top consumer at")),
          QStringLiteral("the headline names the top consumer and its rate"));
    check(summary.topSummary.contains(QStringLiteral("game.exe")),
          QStringLiteral("the top summary starts from the process name"));
    check(summary.rows.value(0).unresolved,
          QStringLiteral("the unresolved row is marked"));
    checkEqual(summary.rows.value(0).activity, QStringLiteral("Unresolved"),
               QStringLiteral("a row with no activity says so"));
    checkEqual(summary.rows.value(1).control, QStringLiteral("Blocked"),
               QStringLiteral("a blocked consumer shows the control"));
    checkEqual(summary.rows.value(2).control,
               QStringLiteral("Limited by Limit background updates"),
               QStringLiteral("a limited consumer names the owning policy"));
    checkEqual(summary.rows.value(1).identity, QStringLiteral("Google Chrome"),
               QStringLiteral("a row carries the resolved identity"));

    checkEqual(summary.unresolvedConsumers, 1,
               QStringLiteral("one consumer cannot be explained"));
    checkEqual(summary.unresolvedBytes, quint64(9000),
               QStringLiteral("its bytes are counted as unresolved"));
    check(summary.unresolvedSummary.contains(QStringLiteral("1 consumer")),
          QStringLiteral("the unresolved line is singular for one consumer"));

    checkEqual(int(summary.controls.size()), 2,
               QStringLiteral("only policies in force count as active controls"));
    checkEqual(summary.controls.value(0).policyId, QStringLiteral("p-block"),
               QStringLiteral("an in-force block is listed first when it is stored first"));
    checkEqual(summary.controls.value(0).effect, QStringLiteral("Block, downloads"),
               QStringLiteral("a control states its effect"));
    check(summary.controls.value(0).temporary,
          QStringLiteral("a control with an expiration is temporary"));
    check(summary.controls.value(1).enforcement.contains(QStringLiteral("Stored only")),
          QStringLiteral("a stored-only control admits it is not enforced"));
    checkEqual(summary.controlSummary, QStringLiteral("2 controls in force (1 temporary)"),
               QStringLiteral("the control line counts what is in force"));

    checkEqual(int(summary.recommendations.size()), 1,
               QStringLiteral("one suggestion is surfaced"));
    checkEqual(summary.recommendations.value(0).pid, 300u,
               QStringLiteral("the suggestion carries its consumer"));
    checkEqual(summary.recommendationSummary, QStringLiteral("1 suggested action"),
               QStringLiteral("the suggestion line is singular"));

    const TopConsumers::Summary empty =
        TopConsumers::build({}, policies, now, 3);
    check(empty.isEmpty(), QStringLiteral("no consumers is an empty dashboard"));
    checkEqual(empty.headline, QStringLiteral("Waiting for traffic"),
               QStringLiteral("an empty dashboard says it is waiting"));
    checkEqual(empty.controlSummary, QStringLiteral("2 controls in force (1 temporary)"),
               QStringLiteral("controls still show before traffic arrives"));
    checkEqual(empty.unresolvedSummary,
               QStringLiteral("Every consumer has an executable path and an activity match"),
               QStringLiteral("an empty unresolved section is reassuring, not blank"));
    checkEqual(empty.recommendationSummary,
               QStringLiteral("No action is suggested right now"),
               QStringLiteral("an empty suggestion section says so"));
}

// ============================================================================
// Activity (Screen 02) data layer
// ============================================================================

void testActivityEventModel()
{
    const QDateTime at = QDateTime::currentDateTime();

    Activity::Event spike;
    spike.id = Activity::makeEventId(Activity::Category::Spike, at,
                                     QStringLiteral("chrome.exe"));
    spike.at = at;
    spike.category = Activity::Category::Spike;
    spike.appName = QStringLiteral("chrome.exe");
    spike.destination = QStringLiteral("203.0.113.9");

    Activity::Event unresolved;
    unresolved.id = Activity::makeEventId(Activity::Category::Unresolved, at,
                                          QStringLiteral("unresolved"));
    unresolved.at = at.addSecs(-5);
    unresolved.category = Activity::Category::Unresolved;
    unresolved.appName = QStringLiteral("Unrecognized traffic");
    unresolved.attribution = QStringLiteral("Unknown");
    unresolved.extra.append({ QStringLiteral("Local match"), QStringLiteral("None") });

    QList<Activity::Event> events{ spike, unresolved };

    Activity::EventFilter byApp;
    byApp.app = QStringLiteral("chrome.exe");
    checkEqual(int(Activity::filterEvents(events, byApp).size()), 1,
               QStringLiteral("activity app filter matches one event"));

    Activity::EventFilter byText;
    byText.text = QStringLiteral("203.0.113.9");
    checkEqual(int(Activity::filterEvents(events, byText).size()), 1,
               QStringLiteral("activity search covers the destination"));

    Activity::EventFilter byUnresolved;
    byUnresolved.hasCategory = true;
    byUnresolved.category = Activity::Category::Unresolved;
    checkEqual(int(Activity::filterEvents(events, byUnresolved).size()), 1,
               QStringLiteral("activity category filter matches unresolved"));

    const QHash<int, int> counts = Activity::categoryCounts(events, Activity::EventFilter());
    checkEqual(counts.value(static_cast<int>(Activity::Category::Spike)), 1,
               QStringLiteral("activity counts spikes"));
    checkEqual(counts.value(static_cast<int>(Activity::Category::Unresolved)), 1,
               QStringLiteral("activity counts unresolved"));

    const QString json = Activity::exportJson(events, true);
    const QJsonObject root = QJsonDocument::fromJson(json.toUtf8()).object();
    checkEqual(root.value(QStringLiteral("format")).toString(),
               QStringLiteral("oasis.activity-feed"),
               QStringLiteral("activity export names its format"));
    checkEqual(root.value(QStringLiteral("count")).toInt(), 2,
               QStringLiteral("activity export counts events"));
    check(!json.contains(QStringLiteral("203.0.113.9")),
          QStringLiteral("activity JSON export redacts the destination by default"));

    const QString csv = Activity::exportCsv(events, true);
    check(csv.contains(QStringLiteral("volume_bytes")),
          QStringLiteral("activity CSV export has the volume column"));
    check(!csv.contains(QStringLiteral("203.0.113.9")),
          QStringLiteral("activity CSV export redacts the destination by default"));
}

void testActivitySeries()
{
    const QDateTime now = QDateTime::currentDateTime();
    Activity::SeriesStore store;
    QList<Activity::AppRate> apps;
    apps.append({ QStringLiteral("chrome.exe"), 80, 20 });
    store.addSample(now, 100, 50, apps, 1);

    const QVector<Activity::SeriesPoint> points = store.series(Activity::Range::Hour);
    checkEqual(int(points.size()), Activity::rangeBucketCount(Activity::Range::Hour),
               QStringLiteral("activity hour series has one bucket per minute"));

    quint64 rx = 0;
    quint64 tx = 0;
    for (const Activity::SeriesPoint &point : points) {
        rx += point.rxBytes;
        tx += point.txBytes;
    }
    check(rx >= 100, QStringLiteral("activity series keeps the downloaded bytes"));
    check(tx >= 50, QStringLiteral("activity series keeps the uploaded bytes"));
    check(store.appNames(Activity::Range::Hour).contains(QStringLiteral("chrome.exe")),
          QStringLiteral("activity series retains application names"));

    const QString json = store.toJsonString();
    Activity::SeriesStore restored;
    check(restored.fromJsonString(json),
          QStringLiteral("activity series JSON round-trips"));
    const Activity::SeriesTotals before = store.totals(Activity::Range::Hour);
    const Activity::SeriesTotals after = restored.totals(Activity::Range::Hour);
    checkEqual(after.rxBytes, before.rxBytes,
               QStringLiteral("activity series round-trip keeps download totals"));
    checkEqual(after.txBytes, before.txBytes,
               QStringLiteral("activity series round-trip keeps upload totals"));

    Activity::SeriesStore empty;
    check(empty.series(Activity::Range::Week).isEmpty(),
          QStringLiteral("an empty activity store returns no week points"));
}

void testActivityDetector()
{
    Activity::DetectorSettings settings;
    settings.absoluteFloorBytesPerSecond = 1000;
    settings.baselineMultiplier = 3.0;
    settings.sustainSeconds = 3;
    settings.baselineSeconds = 5;
    settings.cooldownSeconds = 60;
    settings.unresolvedBytesThreshold = 100;
    settings.unresolvedWindowSeconds = 300;
    settings.unresolvedCooldownSeconds = 60;
    // The rate gate is tested through the baseline, so keep the absolute floor
    // out of the way of these small byte counts.
    settings.unresolvedFloorBytesPerSecond = 0;

    Activity::Detector detector(settings);
    const QDateTime start = QDateTime::currentDateTime();

    Activity::ProcessRate calm;
    calm.name = QStringLiteral("chrome.exe");
    calm.pid = 42;
    calm.rxBytesPerSecond = 100;
    calm.txBytesPerSecond = 0;

    for (int i = 0; i < 5; ++i)
        detector.observe(start.addSecs(i), { calm }, 0);

    Activity::ProcessRate spike = calm;
    spike.rxBytesPerSecond = 5000;
    spike.destination = QStringLiteral("cdn.example.net");
    spike.attribution = QStringLiteral("Likely");

    QList<Activity::Event> events;
    for (int i = 0; i < 3; ++i)
        events += detector.observe(start.addSecs(5 + i), { spike }, 0);

    checkEqual(int(events.size()), 1, QStringLiteral("a sustained spike produces one event"));
    if (!events.isEmpty()) {
        check(events.first().category == Activity::Category::Spike,
              QStringLiteral("the detected event is a spike"));
        checkEqual(events.first().appName, QStringLiteral("chrome.exe"),
                   QStringLiteral("the spike names the application"));
        checkEqual(events.first().destination, QStringLiteral("cdn.example.net"),
                   QStringLiteral("the spike carries the observed destination"));
        check(events.first().peakBytesPerSecond >= 5000,
              QStringLiteral("the spike records its peak rate"));
    }

    // Same application, immediately above the threshold again: the cooldown
    // suppresses a second card for the same sustained transfer.
    for (int i = 0; i < 4; ++i)
        events += detector.observe(start.addSecs(10 + i), { spike }, 0);
    checkEqual(int(events.size()), 1, QStringLiteral("the spike cooldown prevents duplicates"));

    Activity::Detector brief(settings);
    brief.observe(start, { calm }, 0);
    brief.observe(start.addSecs(1), { spike }, 0);
    brief.observe(start.addSecs(2), { calm }, 0);
    brief.observe(start.addSecs(3), { calm }, 0);
    checkEqual(int(brief.observe(start.addSecs(4), { calm }, 0).size()), 0,
               QStringLiteral("a one-second burst is not a spike"));

    // Unresolved traffic that never lifts above its own baseline is background
    // noise: it crosses the 100-byte window but must not produce a card.
    Activity::Detector trickle(settings);
    trickle.observe(start, {}, 0);
    int trickleEvents = 0;
    for (int i = 1; i <= 10; ++i)
        trickleEvents += int(trickle.observe(start.addSecs(i), {},
                                             quint64(60 * i)).size());
    checkEqual(trickleEvents, 0,
               QStringLiteral("constant unresolved background traffic stays quiet"));

    // A transfer that keeps climbing clears its baseline and the volume window,
    // so it still produces an event and names what it could not attribute.
    Activity::ProcessRate unresolvedRow;
    unresolvedRow.name = QStringLiteral("svchost.exe");
    unresolvedRow.pid = 4;
    unresolvedRow.rxBytesPerSecond = 2 * 1024 * 1024;

    Activity::Detector unresolved(settings);
    unresolved.observe(start, { unresolvedRow }, 0);
    checkEqual(int(unresolved.observe(start.addSecs(1), { unresolvedRow }, 60).size()), 0,
               QStringLiteral("a small unresolved sample stays quiet"));
    checkEqual(int(unresolved.observe(start.addSecs(2), { unresolvedRow }, 660).size()), 0,
               QStringLiteral("a rising unresolved sample waits for the window"));
    const QList<Activity::Event> unresolvedEvents =
        unresolved.observe(start.addSecs(3), { unresolvedRow }, 6660);
    checkEqual(int(unresolvedEvents.size()), 1,
               QStringLiteral("a rising unresolved transfer produces an event"));
    if (!unresolvedEvents.isEmpty()) {
        check(unresolvedEvents.first().category == Activity::Category::Unresolved,
              QStringLiteral("the event is classified unresolved"));
        checkEqual(unresolvedEvents.first().attribution, QStringLiteral("Unknown"),
                   QStringLiteral("unresolved attribution stays explicitly unknown"));
        check(unresolvedEvents.first().appPath.isEmpty(),
              QStringLiteral("unresolved traffic claims no executable"));

        QString named;
        for (const Activity::MetaItem &item : unresolvedEvents.first().extra) {
            if (item.key == QStringLiteral("Most active without a match"))
                named = item.value;
        }
        check(named.contains(QStringLiteral("svchost.exe")),
              QStringLiteral("the event names the busiest unattributed process"));
        check(named.contains(QStringLiteral("2.0 MiB/s")),
              QStringLiteral("the named process carries its current rate"));
    }
}

void runUiTests()
{
    testAuditEventStore();
    testAuditLogModel();
    testNotificationCoordinator();
    testApplicationDetailModel();
    testEvidenceExport();
    testPolicyScopePresentation();
    testTopConsumers();
    testActivityEventModel();
    testActivitySeries();
    testActivityDetector();
}
