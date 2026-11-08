/**

  * @file   policy.cpp
  * @brief  Telemetry contracts and Qt metatypes implementation for observations, identities, attribution, policies, and audit events (NG-002).
  * @author Codebuff
  */

#include "policy.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>
#include <QSettings>

namespace {

// A payload with no version predates versioning and is read as version 1. A
// payload from a newer build is rejected rather than half-parsed, so new field
// meanings can never be mistaken for current ones.
bool schemaVersionOk(const QJsonObject &object)
{
    const QLatin1String key(PolicyContract::kSchemaVersionKey);
    if (!object.contains(key)) return true;

    const int version = object.value(key).toInt(-1);
    if (version >= 1 && version <= PolicyContract::kSchemaVersion) return true;

    qWarning() << "policy: rejecting payload with unsupported contract schema version"
               << version;
    return false;
}

} // namespace

// ─── Application Identity serialization ─────────────────────────────────────

QString toJson(const ApplicationIdentity &id)
{
    QJsonObject obj;
    obj[QLatin1String(PolicyContract::kSchemaVersionKey)] = PolicyContract::kSchemaVersion;
    obj[QStringLiteral("id")] = id.id;
    obj[QStringLiteral("displayName")] = id.displayName;
    QJsonArray paths;
    for (const QString &p : id.executablePaths)
        paths.append(p);
    obj[QStringLiteral("executablePaths")] = paths;
    obj[QStringLiteral("publisher")] = id.publisher;
    obj[QStringLiteral("signerStatus")] = static_cast<int>(id.signerStatus);
    obj[QStringLiteral("productName")] = id.productName;
    obj[QStringLiteral("originalFileName")] = id.originalFileName;
    obj[QStringLiteral("fileVersion")] = id.fileVersion;
    obj[QStringLiteral("companyName")] = id.companyName;
    obj[QStringLiteral("packageFamilyName")] = id.packageFamilyName;
    QJsonArray svcs;
    for (const QString &s : id.services)
        svcs.append(s);
    obj[QStringLiteral("services")] = svcs;
    QJsonArray pnames;
    for (const QString &n : id.processNames)
        pnames.append(n);
    obj[QStringLiteral("processNames")] = pnames;
    obj[QStringLiteral("fingerprints")] = QString::fromLatin1(id.fingerprints.toBase64());
    obj[QStringLiteral("confidence")] = static_cast<int>(id.confidence);
    QJsonDocument doc(obj);
    return QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
}

ApplicationIdentity fromJsonApplicationIdentity(const QString &json)
{
    ApplicationIdentity id;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (doc.isNull() || !doc.isObject() || !schemaVersionOk(doc.object())) {
        qWarning() << "Invalid JSON for ApplicationIdentity";
        return id;
    }
    QJsonObject obj = doc.object();
    id.id = obj.value("id").toString();
    id.displayName = obj.value("displayName").toString();
    QJsonArray paths = obj.value("executablePaths").toArray();
    for (const QJsonValue &v : paths)
        id.executablePaths.append(v.toString());
    id.publisher = obj.value("publisher").toString();
    id.signerStatus = static_cast<ApplicationIdentity::SignerStatus>(
        obj.value("signerStatus").toInt());
    id.productName = obj.value("productName").toString();
    id.originalFileName = obj.value("originalFileName").toString();
    id.fileVersion = obj.value("fileVersion").toString();
    id.companyName = obj.value("companyName").toString();
    id.packageFamilyName = obj.value("packageFamilyName").toString();
    QJsonArray svcs = obj.value("services").toArray();
    for (const QJsonValue &v : svcs)
        id.services.append(v.toString());
    QJsonArray pnames = obj.value("processNames").toArray();
    for (const QJsonValue &v : pnames)
        id.processNames.append(v.toString());
    id.fingerprints = QByteArray::fromBase64(
        obj.value("fingerprints").toString().toLatin1());
    id.confidence = static_cast<ApplicationIdentity::Confidence>(
        obj.value("confidence").toInt());
    return id;
}

// ─── Activity Observation serialization ─────────────────────────────────────

QString toJson(const ActivityObservation &obs)
{
    QJsonObject obj;
    obj[QLatin1String(PolicyContract::kSchemaVersionKey)] = PolicyContract::kSchemaVersion;
    obj[QStringLiteral("timestamp")] = obs.timestamp.toString(Qt::ISODate);
    obj[QStringLiteral("identityId")] = obs.identityId;
    obj[QStringLiteral("pid")] = static_cast<qint64>(obs.pid);
    obj[QStringLiteral("direction")] = static_cast<int>(obs.direction);
    obj[QStringLiteral("bytes")] = static_cast<qint64>(obs.bytes);
    obj[QStringLiteral("protocol")] = obs.protocol;
    obj[QStringLiteral("localEndpoint")] = obs.localEndpoint;
    obj[QStringLiteral("remoteEndpoint")] = obs.remoteEndpoint;
    obj[QStringLiteral("domain")] = obs.domain;
    obj[QStringLiteral("attributionSource")] = static_cast<int>(obs.attributionSource);
    obj[QStringLiteral("classification")] = static_cast<int>(obs.classification);
    obj[QStringLiteral("details")] = obs.details;
    QJsonDocument doc(obj);
    return QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
}

ActivityObservation fromJsonActivityObservation(const QString &json)
{
    ActivityObservation obs;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (doc.isNull() || !doc.isObject() || !schemaVersionOk(doc.object())) {
        qWarning() << "Invalid JSON for ActivityObservation";
        return obs;
    }
    QJsonObject obj = doc.object();
    obs.timestamp = QDateTime::fromString(
        obj.value("timestamp").toString(), Qt::ISODate);
    obs.identityId = obj.value("identityId").toString();
    obs.pid = static_cast<quint32>(obj.value("pid").toDouble());
    obs.direction = static_cast<NetworkDirection>(
        obj.value("direction").toInt());
    obs.bytes = static_cast<quint64>(obj.value("bytes").toDouble());
    obs.protocol = obj.value("protocol").toString();
    obs.localEndpoint = obj.value("localEndpoint").toString();
    obs.remoteEndpoint = obj.value("remoteEndpoint").toString();
    obs.domain = obj.value("domain").toString();
    obs.attributionSource = static_cast<ActivityObservation::AttributionSource>(
        obj.value("attributionSource").toInt());
    obs.classification = static_cast<ActivityObservation::Classification>(
        obj.value("classification").toInt());
    obs.details = obj.value("details").toString();
    return obs;
}

// ─── Network Policy serialization ───────────────────────────────────────────

QString toJson(const NetworkPolicy &policy)
{
    QJsonObject obj;
    obj[QLatin1String(PolicyContract::kSchemaVersionKey)] = PolicyContract::kSchemaVersion;
    obj[QStringLiteral("id")] = policy.id;
    obj[QStringLiteral("scope")] = policy.scope;
    obj[QStringLiteral("targetId")] = policy.targetId;
    obj[QStringLiteral("direction")] = static_cast<int>(policy.direction);
    obj[QStringLiteral("action")] = static_cast<int>(policy.action);
    obj[QStringLiteral("rateBitsPerSecond")] = static_cast<qint64>(policy.rateBitsPerSecond);
    obj[QStringLiteral("schedule")] = policy.schedule;
    obj[QStringLiteral("scheduleType")] = static_cast<int>(policy.scheduleType);
    obj[QStringLiteral("expiration")] = policy.expiration.toString(Qt::ISODate);
    obj[QStringLiteral("source")] = policy.source;
    obj[QStringLiteral("enabled")] = policy.enabled;
    obj[QStringLiteral("description")] = policy.description;
    QJsonDocument doc(obj);
    return QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
}

NetworkPolicy fromJsonNetworkPolicy(const QString &json)
{
    NetworkPolicy policy;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (doc.isNull() || !doc.isObject() || !schemaVersionOk(doc.object())) {
        qWarning() << "Invalid JSON for NetworkPolicy";
        return policy;
    }
    QJsonObject obj = doc.object();
    policy.id = obj.value("id").toString();
    policy.scope = obj.value("scope").toString();
    policy.targetId = obj.value("targetId").toString();
    policy.direction = static_cast<NetworkDirection>(
        obj.value("direction").toInt());
    policy.action = static_cast<NetworkPolicy::Action>(
        obj.value("action").toInt());
    policy.rateBitsPerSecond = static_cast<quint64>(
        obj.value("rateBitsPerSecond").toDouble());
    policy.schedule = obj.value("schedule").toString();
    policy.scheduleType = static_cast<NetworkPolicy::ScheduleType>(obj.value("scheduleType").toInt());
    policy.expiration = QDateTime::fromString(
        obj.value("expiration").toString(), Qt::ISODate);
    policy.source = obj.value("source").toString();
    policy.enabled = obj.value("enabled").toBool();
    policy.description = obj.value("description").toString();
    return policy;
}

// ─── Scope matching ─────────────────────────────────────────────────────────
// Check if a policy's scope matches the given executable scope identifier.
// Group scope acts as a persistent learned category - once a group has learned
// a category, new members inherit it (read-only inspection, never changes the group).
bool scopeMatches(const NetworkPolicy &policy, const QString &scopeIdentifier)
{
    if (scopeIdentifier.isEmpty()) return false;
    const QString policyScope = policy.scope;
    // Exact match
    if (policyScope == scopeIdentifier) return true;
    // Group scope: if policy is scope "group" and identifier starts with "group:"
    if (policyScope == QStringLiteral("group") && scopeIdentifier.startsWith(QStringLiteral("group:"))) return true;
    // Publisher scope
    if (policyScope == QStringLiteral("publisher") && scopeIdentifier == QStringLiteral("publisher")) return true;
    // Service scope
    if (policyScope == QStringLiteral("service") && scopeIdentifier == QStringLiteral("service")) return true;
    // Package scope
    if (policyScope == QStringLiteral("package") && scopeIdentifier == QStringLiteral("package")) return true;
    // Executable (path) scope
    if (policyScope == QStringLiteral("executable") || policyScope == QStringLiteral("path"))
    {
        // Simple substring match for path/executable
        if (scopeIdentifier.contains(policyScope, Qt::CaseInsensitive) ||
            policyScope.contains(scopeIdentifier, Qt::CaseInsensitive))
            return true;
    }
    return false;
}

// ─── Policy reconciliation ─────────────────────────────────────────────────────
// Reconcile stored policies against current format and validity.
// Returns a pair: (validPolicies, invalidPolicyIds) where invalidPolicyIds
// are those that are malformed, have missing required fields, or are from
// an unsupported old format that cannot be auto-migrated.
// After calling this, call savePolicies() to persist the cleaned set.
std::pair<QList<NetworkPolicy>, QList<QString>> reconcilePolicies()
{
    QList<NetworkPolicy> valid;
    QList<QString> invalid;
    QSettings settings;
    // Read format version first (outside any group to avoid QSettings::value() no-arg issues)
    int version = settings.value("NetGuard/Policies/formatVersion", 1).toInt();
    settings.beginGroup("NetGuard/Policies");
    // Read policies sub-group
    if (version == PolicyStore::kLegacyStoreVersion)
    {
        // Legacy format: QVariantMap where each value is a QVariantMap of policy fields,
        // keyed by policy id under the "policies" group.
        const QVariantMap store = settings.value("policies").toMap();
        for (auto it = store.constBegin(); it != store.constEnd(); ++it)
        {
            const QString policyId = it.key();
            const QVariantMap fields = it.value().toMap();
            NetworkPolicy p;
            p.id = fields.value("id").toString();
            p.scope = fields.value("scope").toString();
            p.targetId = fields.value("targetId").toString();
            p.direction = static_cast<NetworkDirection>(
                fields.value("direction").toInt());
            p.action = static_cast<NetworkPolicy::Action>(
                fields.value("action").toInt());
            p.rateBitsPerSecond = static_cast<quint64>(
                fields.value("rateBitsPerSecond").toLongLong());
            p.schedule = fields.value("schedule").toString();
            p.expiration = QDateTime::fromString(fields.value("expiration").toString(), Qt::ISODate);
            p.source = fields.value("source").toString();
            p.enabled = fields.value("enabled").toBool();
            p.description = fields.value("description").toString();
            // Validate required fields
            if (!p.id.isEmpty() && !p.scope.isEmpty())
            {
                valid.append(p);
            }
            else
            {
                invalid.append(policyId);
            }
        }
    }
    else
    {
        // Version 2: JSON array under "policies" key
        const QString json = settings.value("policies").toString();
        QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
        if (doc.isArray())
        {
            const QJsonArray arr = doc.array();
            for (const QJsonValue &val : arr)
            {
                if (!val.isObject()) continue;
                NetworkPolicy p = fromJsonNetworkPolicy(QJsonDocument(val.toObject()).toJson(QJsonDocument::Compact));
                // Validate required fields
                if (!p.id.isEmpty() && !p.scope.isEmpty())
                {
                    // Preserve the id from the stored data if the JSON one is empty
                    if (p.id.isEmpty()) p.id = val.toObject().value("id").toString();
                    valid.append(p);
                }
                else
                {
                    invalid.append(val.toObject().value("id").toString());
                }
            }
        }
    }
    settings.endGroup();
    settings.endGroup();
    return {valid, invalid};
}

// ─── Throttle Result serialization ──────────────────────────────────────────

QString toJson(const NetworkPolicyThrottleResult &result)
{
    QJsonObject obj;
    obj[QLatin1String(PolicyContract::kSchemaVersionKey)] = PolicyContract::kSchemaVersion;
    obj[QStringLiteral("status")] = static_cast<int>(result.status);
    obj[QStringLiteral("message")] = result.message;
    obj[QStringLiteral("policyId")] = result.policyId;
    obj[QStringLiteral("executablePath")] = result.executablePath;
    obj[QStringLiteral("uploadLimited")] = result.uploadLimited;
    obj[QStringLiteral("downloadLimited")] = result.downloadLimited;
    obj[QStringLiteral("uploadReason")] = result.uploadReason;
    obj[QStringLiteral("downloadReason")] = result.downloadReason;
    QJsonDocument doc(obj);
    return QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
}

NetworkPolicyThrottleResult fromJsonNetworkPolicyThrottleResult(const QString &json)
{
    NetworkPolicyThrottleResult result;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (doc.isNull() || !doc.isObject() || !schemaVersionOk(doc.object())) {
        qWarning() << "Invalid JSON for NetworkPolicyThrottleResult";
        return result;
    }
    QJsonObject obj = doc.object();
    result.status = static_cast<NetworkPolicyThrottleResult::Status>(
        obj.value("status").toInt());
    result.message = obj.value("message").toString();
    result.policyId = obj.value("policyId").toString();
    result.executablePath = obj.value("executablePath").toString();
    result.uploadLimited = obj.value("uploadLimited").toBool();
    result.downloadLimited = obj.value("downloadLimited").toBool();
    result.uploadReason = obj.value("uploadReason").toString();

    result.downloadReason = obj.value("downloadReason").toString();
    return result;
}

// ─── Audit Event serialization ──────────────────────────────────────────────

QString toJson(const AuditEvent &event)
{
    QJsonObject obj;
    obj[QLatin1String(PolicyContract::kSchemaVersionKey)] = PolicyContract::kSchemaVersion;
    obj[QStringLiteral("timestamp")] = event.timestamp.toString(Qt::ISODate);
    obj[QStringLiteral("type")] = static_cast<int>(event.type);
    obj[QStringLiteral("scope")] = event.scope;
    obj[QStringLiteral("reason")] = event.reason;
    obj[QStringLiteral("result")] = event.result;
    obj[QStringLiteral("errorInfo")] = event.errorInfo;
    obj[QStringLiteral("relatedIdentityId")] = event.relatedIdentityId;
    obj[QStringLiteral("relatedPolicyId")] = event.relatedPolicyId;
    obj[QStringLiteral("details")] = event.details;
    QJsonDocument doc(obj);
    return QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
}

AuditEvent fromJsonAuditEvent(const QString &json)
{
    AuditEvent event;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (doc.isNull() || !doc.isObject() || !schemaVersionOk(doc.object())) {
        qWarning() << "Invalid JSON for AuditEvent";
        return event;
    }
    QJsonObject obj = doc.object();
    event.timestamp = QDateTime::fromString(
        obj.value("timestamp").toString(), Qt::ISODate);
    event.type = static_cast<AuditEvent::EventType>(
        obj.value("type").toInt());
    event.scope = obj.value("scope").toString();
    event.reason = obj.value("reason").toString();
    event.result = obj.value("result").toString();
    event.errorInfo = obj.value("errorInfo").toString();
    event.relatedIdentityId = obj.value("relatedIdentityId").toString();
    event.relatedPolicyId = obj.value("relatedPolicyId").toString();
    event.details = obj.value("details").toString();
    return event;
}

// ─── Policy store ──────────────────────────────────────────────────────────────
// Persistent policy store with versioned persistence, migration, and JSON import/export.
// Policies are stored under QSettings group "NetGuard/Policies".
// Version 1 format: QSettings map with key "policies" containing a QVariantMap per policy.
// Version 2 format: JSON array under "policies" key (introduced for NG-020).
// Malformed entries are rejected with a warning and omitted; the store never throws.


QList<NetworkPolicy> PolicyStore::loadPolicies()
{
    QList<NetworkPolicy> result;
    QSettings settings;
    // Read format version first (outside any group to avoid QSettings::value() no-arg issues)
    int version = settings.value("NetGuard/Policies/formatVersion", 1).toInt();
    settings.beginGroup("NetGuard/Policies");

    if (version == PolicyStore::kLegacyStoreVersion)
    {
        // Legacy format: QVariantMap where each value is a QVariantMap of policy fields,
        // keyed by policy id under the "policies" group.
        const QVariantMap store = settings.value("policies").toMap();
        for (auto it = store.constBegin(); it != store.constEnd(); ++it)
        {
            const QString policyId = it.key();
            const QVariantMap fields = it.value().toMap();
            NetworkPolicy p;
            p.id = fields.value("id").toString();
            p.scope = fields.value("scope").toString();
            p.targetId = fields.value("targetId").toString();
            p.direction = static_cast<NetworkDirection>(
                fields.value("direction").toInt());
            p.action = static_cast<NetworkPolicy::Action>(
                fields.value("action").toInt());
            p.rateBitsPerSecond = static_cast<quint64>(
                fields.value("rateBitsPerSecond").toLongLong());
            p.schedule = fields.value("schedule").toString();
            p.expiration = QDateTime::fromString(
                fields.value("expiration").toString(), Qt::ISODate);
            p.source = fields.value("source").toString();
            p.enabled = fields.value("enabled").toBool();
            p.description = fields.value("description").toString();
            // Validate required fields
            if (!p.id.isEmpty() && !p.scope.isEmpty())
            {
                result.append(p);
            }
            else
            {
                qWarning() << "PolicyStore: skipping malformed policy id" << policyId;
            }
        }
    }
    else
    {
        // Version 2: JSON array under "policies" key
        const QString json = settings.value("policies").toString();
        QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
        if (doc.isArray())
        {
            const QJsonArray arr = doc.array();
            for (const QJsonValue &val : arr)
            {
                if (!val.isObject()) continue;
                NetworkPolicy p = fromJsonNetworkPolicy(QJsonDocument(val.toObject()).toJson(QJsonDocument::Compact));
                // Validate required fields
                if (!p.id.isEmpty() && !p.scope.isEmpty())
                {
                    // Preserve the id from the stored data if the JSON one is empty
                    if (p.id.isEmpty()) p.id = val.toObject().value("id").toString();
                    result.append(p);
                }
                else
                {
                    qWarning() << "PolicyStore: skipping malformed policy from JSON";
                }
            }
        }
    }
    settings.endGroup();
    return result;
}

void PolicyStore::savePolicies(const QList<NetworkPolicy> &policies)
{
    QSettings settings;
    settings.beginGroup("NetGuard/Policies");
    settings.setValue("formatVersion", PolicyStore::kCurrentStoreVersion);
    QVariantMap store;
    for (const NetworkPolicy &p : policies)
    {
        QVariantMap fields;
        fields["id"] = p.id;
        fields["scope"] = p.scope;
        fields["targetId"] = p.targetId;
        fields["direction"] = static_cast<int>(p.direction);
        fields["action"] = static_cast<int>(p.action);
        fields["rateBitsPerSecond"] = p.rateBitsPerSecond;
        fields["schedule"] = p.schedule;
        fields["expiration"] = p.expiration.toString(Qt::ISODate);
        fields["source"] = p.source;
        fields["enabled"] = p.enabled;
        fields["description"] = p.description;
        store[p.id] = fields;
    }
    settings.setValue("policies", store);
    settings.endGroup();
}

QString PolicyStore::exportPoliciesJson()
{
    QSettings settings;
    settings.beginGroup("NetGuard/Policies");
    const QString json = settings.value("policies").toString();
    settings.endGroup();
    return json; // return empty string if none stored
}

bool PolicyStore::importPoliciesJson(const QString &json)
{
    bool changed = false;
    QSettings settings;
    settings.beginGroup("NetGuard/Policies");

    // Read existing policies to merge into
    QList<NetworkPolicy> existing = loadPolicies();
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (doc.isArray())
    {
        const QJsonArray arr = doc.array();
        for (const QJsonValue &val : arr)
        {
            if (!val.isObject()) continue;
            NetworkPolicy p = fromJsonNetworkPolicy(QJsonDocument(val.toObject()).toJson(QJsonDocument::Compact));
            if (p.id.isEmpty())
            {
                qWarning() << "PolicyStore: cannot import policy without id";
                continue;
            }
            // Find existing policy with same id, or append
            bool found = false;
            for (NetworkPolicy &ep : existing)
            {
                if (ep.id == p.id)
                {
                    ep = p; // replace
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                existing.append(p);
            }
            changed = true;
        }
    }

    // Write back the merged list
    savePolicies(existing);
    settings.endGroup();
    return changed;
}

bool PolicyStore::migrateOldFormat(QSettings &settings)
{
    // Check if we already migrated
    if (settings.value("NetGuard/Policies/migrated").toBool()) return false;
    settings.beginGroup("NetGuard/Policies");
    int version = settings.value("formatVersion", 1).toInt();
    if (version >= PolicyStore::kCurrentStoreVersion)
    {
        settings.endGroup();
        return false;
    }
    // Legacy format: QVariantMap under "policies" key, keyed by policy id
    settings.beginGroup("policies");
    const QVariantMap legacy = settings.value(QString()).toMap();
    QList<NetworkPolicy> result;
    for (auto it = legacy.constBegin(); it != legacy.constEnd(); ++it)
    {
        const QString policyId = it.key();
        const QVariantMap fields = it.value().toMap();
        NetworkPolicy p;
        p.id = fields.value("id").toString();
        p.scope = fields.value("scope").toString();
        p.targetId = fields.value("targetId").toString();
        p.direction = static_cast<NetworkDirection>(
            fields.value("direction").toInt());
        p.action = static_cast<NetworkPolicy::Action>(
            fields.value("action").toInt());
        p.rateBitsPerSecond = static_cast<quint64>(
            fields.value("rateBitsPerSecond").toLongLong());
        p.schedule = fields.value("schedule").toString();
        p.expiration = QDateTime::fromString(
            fields.value("expiration").toString(), Qt::ISODate);
        p.source = fields.value("source").toString();
        p.enabled = fields.value("enabled").toBool();
        p.description = fields.value("description").toString();
        if (!p.id.isEmpty() && !p.scope.isEmpty())
        {
            result.append(p);
        }
        else
        {
            qWarning() << "PolicyStore: skipping malformed policy during migration id" << policyId;
        }
    }
    settings.endGroup();
    settings.endGroup();
    // Now save in new format
    savePolicies(result);
    settings.setValue("NetGuard/Policies/migrated", true);
    return true;
}