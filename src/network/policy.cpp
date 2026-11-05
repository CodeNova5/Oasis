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

// ─── Application Identity serialization ─────────────────────────────────────

QString toJson(const ApplicationIdentity &id)
{
    QJsonObject obj;
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
    if (doc.isNull() || !doc.isObject()) {
        qWarning() << "Invalid JSON for ApplicationIdentity";
        return id;
    }
    QJsonObject obj = doc.object();
    id.id = obj.value(QStringLiteral("id")).toString();
    id.displayName = obj.value(QStringLiteral("displayName")).toString();
    QJsonArray paths = obj.value(QStringLiteral("executablePaths")).toArray();
    for (const QJsonValue &v : paths)
        id.executablePaths.append(v.toString());
    id.publisher = obj.value(QStringLiteral("publisher")).toString();
    id.signerStatus = static_cast<ApplicationIdentity::SignerStatus>(
        obj.value(QStringLiteral("signerStatus")).toInt());
    id.productName = obj.value(QStringLiteral("productName")).toString();
    id.originalFileName = obj.value(QStringLiteral("originalFileName")).toString();
    id.fileVersion = obj.value(QStringLiteral("fileVersion")).toString();
    id.companyName = obj.value(QStringLiteral("companyName")).toString();
    id.packageFamilyName = obj.value(QStringLiteral("packageFamilyName")).toString();
    QJsonArray svcs = obj.value(QStringLiteral("services")).toArray();
    for (const QJsonValue &v : svcs)
        id.services.append(v.toString());
    QJsonArray pnames = obj.value(QStringLiteral("processNames")).toArray();
    for (const QJsonValue &v : pnames)
        id.processNames.append(v.toString());
    id.fingerprints = QByteArray::fromBase64(
        obj.value(QStringLiteral("fingerprints")).toString().toLatin1());
    id.confidence = static_cast<ApplicationIdentity::Confidence>(
        obj.value(QStringLiteral("confidence")).toInt());
    return id;
}

// ─── Activity Observation serialization ─────────────────────────────────────

QString toJson(const ActivityObservation &obs)
{
    QJsonObject obj;
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
    if (doc.isNull() || !doc.isObject()) {
        qWarning() << "Invalid JSON for ActivityObservation";
        return obs;
    }
    QJsonObject obj = doc.object();
    obs.timestamp = QDateTime::fromString(
        obj.value(QStringLiteral("timestamp")).toString(), Qt::ISODate);
    obs.identityId = obj.value(QStringLiteral("identityId")).toString();
    obs.pid = static_cast<quint32>(obj.value(QStringLiteral("pid")).toDouble());
    obs.direction = static_cast<NetworkDirection>(
        obj.value(QStringLiteral("direction")).toInt());
    obs.bytes = static_cast<quint64>(obj.value(QStringLiteral("bytes")).toDouble());
    obs.protocol = obj.value(QStringLiteral("protocol")).toString();
    obs.localEndpoint = obj.value(QStringLiteral("localEndpoint")).toString();
    obs.remoteEndpoint = obj.value(QStringLiteral("remoteEndpoint")).toString();
    obs.domain = obj.value(QStringLiteral("domain")).toString();
    obs.attributionSource = static_cast<ActivityObservation::AttributionSource>(
        obj.value(QStringLiteral("attributionSource")).toInt());
    obs.classification = static_cast<ActivityObservation::Classification>(
        obj.value(QStringLiteral("classification")).toInt());
    obs.details = obj.value(QStringLiteral("details")).toString();
    return obs;
}

// ─── Network Policy serialization ───────────────────────────────────────────

QString toJson(const NetworkPolicy &policy)
{
    QJsonObject obj;
    obj[QStringLiteral("id")] = policy.id;
    obj[QStringLiteral("scope")] = policy.scope;
    obj[QStringLiteral("targetId")] = policy.targetId;
    obj[QStringLiteral("direction")] = static_cast<int>(policy.direction);
    obj[QStringLiteral("action")] = static_cast<int>(policy.action);
    obj[QStringLiteral("rateBitsPerSecond")] = static_cast<qint64>(policy.rateBitsPerSecond);
    obj[QStringLiteral("schedule")] = policy.schedule;
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
    if (doc.isNull() || !doc.isObject()) {
        qWarning() << "Invalid JSON for NetworkPolicy";
        return policy;
    }
    QJsonObject obj = doc.object();
    policy.id = obj.value(QStringLiteral("id")).toString();
    policy.scope = obj.value(QStringLiteral("scope")).toString();
    policy.targetId = obj.value(QStringLiteral("targetId")).toString();
    policy.direction = static_cast<NetworkDirection>(
        obj.value(QStringLiteral("direction")).toInt());
    policy.action = static_cast<NetworkPolicy::Action>(
        obj.value(QStringLiteral("action")).toInt());
    policy.rateBitsPerSecond = static_cast<quint64>(
        obj.value(QStringLiteral("rateBitsPerSecond")).toDouble());
    policy.schedule = obj.value(QStringLiteral("schedule")).toString();
    policy.expiration = QDateTime::fromString(
        obj.value(QStringLiteral("expiration")).toString(), Qt::ISODate);
    policy.source = obj.value(QStringLiteral("source")).toString();
    policy.enabled = obj.value(QStringLiteral("enabled")).toBool();
    policy.description = obj.value(QStringLiteral("description")).toString();
    return policy;
}

// ─── Throttle Result serialization ──────────────────────────────────────────

QString toJson(const ThrottleResult &result)
{
    QJsonObject obj;
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

ThrottleResult fromJsonThrottleResult(const QString &json)
{
    ThrottleResult result;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (doc.isNull() || !doc.isObject()) {
        qWarning() << "Invalid JSON for ThrottleResult";
        return result;
    }
    QJsonObject obj = doc.object();
    result.status = static_cast<ThrottleResult::Status>(
        obj.value(QStringLiteral("status")).toInt());
    result.message = obj.value(QStringLiteral("message")).toString();
    result.policyId = obj.value(QStringLiteral("policyId")).toString();
    result.executablePath = obj.value(QStringLiteral("executablePath")).toString();
    result.uploadLimited = obj.value(QStringLiteral("uploadLimited")).toBool();
    result.downloadLimited = obj.value(QStringLiteral("downloadLimited")).toBool();
    result.uploadReason = obj.value(QStringLiteral("uploadReason")).toString();
    result.downloadReason = obj.value(QStringLiteral("downloadReason")).toString();
    return result;
}

// ─── Audit Event serialization ──────────────────────────────────────────────

QString toJson(const AuditEvent &event)
{
    QJsonObject obj;
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
    if (doc.isNull() || !doc.isObject()) {
        qWarning() << "Invalid JSON for AuditEvent";
        return event;
    }
    QJsonObject obj = doc.object();
    event.timestamp = QDateTime::fromString(
        obj.value(QStringLiteral("timestamp")).toString(), Qt::ISODate);
    event.type = static_cast<AuditEvent::EventType>(
        obj.value(QStringLiteral("type")).toInt());
    event.scope = obj.value(QStringLiteral("scope")).toString();
    event.reason = obj.value(QStringLiteral("reason")).toString();
    event.result = obj.value(QStringLiteral("result")).toString();
    event.errorInfo = obj.value(QStringLiteral("errorInfo")).toString();
    event.relatedIdentityId = obj.value(QStringLiteral("relatedIdentityId")).toString();
    event.relatedPolicyId = obj.value(QStringLiteral("relatedPolicyId")).toString();
    event.details = obj.value(QStringLiteral("details")).toString();
    return event;
}
