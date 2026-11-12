/**
 * @file   auditeventstore.cpp
 * @brief  Bounded, queryable audit event store (NG-050).
 * @author Codebuff
 */

#include "auditeventstore.h"

#include <QDebug>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSettings>

#include <algorithm>

namespace {

constexpr const char *kSettingsGroup = "NetGuard/Audit";
constexpr const char *kStoreVersionKey = "storeVersion";
constexpr const char *kRetentionDaysKey = "retentionDays";
constexpr const char *kMaxEventsKey = "maxEvents";
constexpr const char *kEventsKey = "events";
constexpr int kStoreVersion = 1;

bool isKnownEventType(int value)
{
    return value >= static_cast<int>(AuditEvent::EventType::Detection) &&
           value <= static_cast<int>(AuditEvent::EventType::ProcessGroupMembershipChange);
}

// An event is only worth keeping when it says when it happened and what it is.
bool isUsableEvent(const AuditEvent &event)
{
    return event.timestamp.isValid() && isKnownEventType(static_cast<int>(event.type));
}

void sortByTimestamp(QList<AuditEvent> &events)
{
    std::stable_sort(events.begin(), events.end(),
                     [](const AuditEvent &a, const AuditEvent &b) {
                         return a.timestamp < b.timestamp;
                     });
}

QString eventTextMatches(const AuditEvent &event, const QString &needle)
{
    if (needle.isEmpty()) return QString();
    if (event.reason.contains(needle, Qt::CaseInsensitive)) return event.reason;
    if (event.result.contains(needle, Qt::CaseInsensitive)) return event.result;
    if (event.errorInfo.contains(needle, Qt::CaseInsensitive)) return event.errorInfo;
    if (event.details.contains(needle, Qt::CaseInsensitive)) return event.details;
    return QString();
}

} // namespace

// ─── Event type names ───────────────────────────────────────────────────────

QString auditEventTypeName(AuditEvent::EventType type)
{
    switch (type) {
    case AuditEvent::EventType::Detection:                   return QStringLiteral("Detection");
    case AuditEvent::EventType::Classification:              return QStringLiteral("Classification");
    case AuditEvent::EventType::Recommendation:              return QStringLiteral("Recommendation");
    case AuditEvent::EventType::UserDecision:                return QStringLiteral("UserDecision");
    case AuditEvent::EventType::AutomaticDecision:           return QStringLiteral("AutomaticDecision");
    case AuditEvent::EventType::EnforcementRequest:          return QStringLiteral("EnforcementRequest");
    case AuditEvent::EventType::EnforcementResult:           return QStringLiteral("EnforcementResult");
    case AuditEvent::EventType::PolicyChange:                return QStringLiteral("PolicyChange");
    case AuditEvent::EventType::ProcessGroupMembershipChange:return QStringLiteral("ProcessGroupMembershipChange");
    }
    return QStringLiteral("Detection");
}

QStringList auditEventTypeNames()
{
    QStringList names;
    for (int i = static_cast<int>(AuditEvent::EventType::Detection);
         i <= static_cast<int>(AuditEvent::EventType::ProcessGroupMembershipChange); ++i) {
        names.append(auditEventTypeName(static_cast<AuditEvent::EventType>(i)));
    }
    return names;
}

bool auditEventTypeFromName(const QString &name, AuditEvent::EventType *type)
{
    const QString wanted = name.trimmed();
    if (wanted.isEmpty()) return false;

    for (int i = static_cast<int>(AuditEvent::EventType::Detection);
         i <= static_cast<int>(AuditEvent::EventType::ProcessGroupMembershipChange); ++i) {
        const AuditEvent::EventType candidate = static_cast<AuditEvent::EventType>(i);
        if (auditEventTypeName(candidate).compare(wanted, Qt::CaseInsensitive) == 0) {
            if (type) *type = candidate;
            return true;
        }
    }
    return false;
}

QJsonObject auditEventToObject(const AuditEvent &event)
{
    QJsonObject obj;
    obj[QStringLiteral("timestamp")]         = event.timestamp.toString(Qt::ISODateWithMs);
    obj[QStringLiteral("type")]              = auditEventTypeName(event.type);
    obj[QStringLiteral("scope")]             = event.scope;
    obj[QStringLiteral("reason")]            = event.reason;
    obj[QStringLiteral("result")]            = event.result;
    obj[QStringLiteral("errorInfo")]         = event.errorInfo;
    obj[QStringLiteral("relatedIdentityId")] = event.relatedIdentityId;
    obj[QStringLiteral("relatedPolicyId")]   = event.relatedPolicyId;
    obj[QStringLiteral("details")]           = event.details;
    return obj;
}

AuditRetentionSettings sanitizedAuditRetention(const AuditRetentionSettings &settings)
{
    AuditRetentionSettings clean = settings;
    clean.retentionDays = qBound(AuditStore::kMinRetentionDays, clean.retentionDays,
                                 AuditStore::kMaxRetentionDays);
    clean.maxEvents = qBound(AuditStore::kMinEvents, clean.maxEvents,
                             AuditStore::kMaxEvents);
    return clean;
}

// ─── Store ──────────────────────────────────────────────────────────────────

AuditEventStore::AuditEventStore()
{
    load();
}

AuditRetentionSettings AuditEventStore::retention() const
{
    return m_retention;
}

void AuditEventStore::setRetention(const AuditRetentionSettings &settings)
{
    m_retention = sanitizedAuditRetention(settings);
    prune();
    save();
}

void AuditEventStore::append(const AuditEvent &event)
{
    AuditEvent stored = event;
    if (!stored.timestamp.isValid())
        stored.timestamp = QDateTime::currentDateTime();

    m_events.append(stored);
    sortByTimestamp(m_events);
    prune();
    save();
}

void AuditEventStore::appendAll(const QList<AuditEvent> &events)
{
    if (events.isEmpty()) return;

    const QDateTime now = QDateTime::currentDateTime();
    for (const AuditEvent &event : events) {
        AuditEvent stored = event;
        if (!stored.timestamp.isValid())
            stored.timestamp = now;
        m_events.append(stored);
    }
    sortByTimestamp(m_events);
    prune();
    save();
}

int AuditEventStore::count() const
{
    return m_events.size();
}

QList<AuditEvent> AuditEventStore::events() const
{
    return m_events;
}

QList<AuditEvent> AuditEventStore::query(const AuditQuery &filter) const
{
    QList<AuditEvent> matches;
    for (const AuditEvent &event : m_events) {
        if (!filter.types.isEmpty() && !filter.types.contains(event.type))
            continue;
        if (filter.from.isValid() && event.timestamp < filter.from)
            continue;
        if (filter.to.isValid() && event.timestamp > filter.to)
            continue;
        if (!filter.identityId.isEmpty() && event.relatedIdentityId != filter.identityId)
            continue;
        if (!filter.policyId.isEmpty() && event.relatedPolicyId != filter.policyId)
            continue;
        if (!filter.scope.isEmpty() && event.scope != filter.scope)
            continue;
        if (!filter.text.isEmpty() && eventTextMatches(event, filter.text).isEmpty())
            continue;
        matches.append(event);
    }

    // m_events is chronological, so keeping the tail keeps the newest matches.
    if (filter.limit > 0 && matches.size() > filter.limit)
        matches = matches.mid(matches.size() - filter.limit);
    return matches;
}

void AuditEventStore::prune()
{
    sortByTimestamp(m_events);

    const QDateTime cutoff = QDateTime::currentDateTime()
                                 .addDays(-m_retention.retentionDays);
    while (!m_events.isEmpty() &&
           (!m_events.first().timestamp.isValid() ||
            m_events.first().timestamp < cutoff)) {
        m_events.removeFirst();
    }

    while (m_events.size() > m_retention.maxEvents)
        m_events.removeFirst();
}

void AuditEventStore::clear()
{
    m_events.clear();
    save();
}

QString AuditEventStore::exportJson() const
{
    QJsonArray events;
    for (const AuditEvent &event : m_events)
        events.append(auditEventToObject(event));

    QJsonObject retentionObject;
    retentionObject[QStringLiteral("days")]      = m_retention.retentionDays;
    retentionObject[QStringLiteral("maxEvents")] = m_retention.maxEvents;

    QJsonObject root;
    root[QStringLiteral("format")]        = QLatin1String(AuditStore::kFormat);
    root[QStringLiteral("schemaVersion")] = AuditStore::kSchemaVersion;
    root[QStringLiteral("exportedAt")]    = QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
    root[QStringLiteral("retention")]     = retentionObject;
    root[QStringLiteral("count")]         = events.size();
    root[QStringLiteral("events")]        = events;

    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

bool AuditEventStore::load()
{
    m_events.clear();
    m_retention = AuditRetentionSettings();

    QSettings settings;
    settings.beginGroup(QLatin1String(kSettingsGroup));
    const int version = settings.value(QLatin1String(kStoreVersionKey), kStoreVersion).toInt();
    if (version < 1 || version > kStoreVersion) {
        qWarning() << "AuditEventStore: ignoring unsupported store version" << version;
        settings.endGroup();
        prune();
        return false;
    }

    AuditRetentionSettings stored;
    stored.retentionDays = settings.value(QLatin1String(kRetentionDaysKey),
                                          AuditStore::kDefaultRetentionDays).toInt();
    stored.maxEvents = settings.value(QLatin1String(kMaxEventsKey),
                                      AuditStore::kDefaultMaxEvents).toInt();
    m_retention = sanitizedAuditRetention(stored);

    const QString json = settings.value(QLatin1String(kEventsKey)).toString();
    settings.endGroup();

    if (json.isEmpty()) {
        prune();
        return true;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isArray()) {
        qWarning() << "AuditEventStore: ignoring malformed event payload";
        m_events.clear();
        prune();
        return false;
    }

    int rejected = 0;
    for (const QJsonValue &value : doc.array()) {
        if (!value.isObject()) { ++rejected; continue; }
        const AuditEvent event = fromJsonAuditEvent(
            QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact)));
        if (!isUsableEvent(event)) { ++rejected; continue; }
        m_events.append(event);
    }
    if (rejected > 0)
        qWarning() << "AuditEventStore: skipped" << rejected << "unreadable audit events";

    sortByTimestamp(m_events);
    prune();
    return true;
}

bool AuditEventStore::save() const
{
    QJsonArray events;
    for (const AuditEvent &event : m_events) {
        events.append(QJsonDocument::fromJson(toJson(event).toUtf8()).object());
    }

    QSettings settings;
    settings.beginGroup(QLatin1String(kSettingsGroup));
    settings.setValue(QLatin1String(kStoreVersionKey), kStoreVersion);
    settings.setValue(QLatin1String(kRetentionDaysKey), m_retention.retentionDays);
    settings.setValue(QLatin1String(kMaxEventsKey), m_retention.maxEvents);
    settings.setValue(QLatin1String(kEventsKey),
                      QString::fromUtf8(QJsonDocument(events).toJson(QJsonDocument::Compact)));
    settings.endGroup();
    settings.sync();
    return settings.status() == QSettings::NoError;
}
