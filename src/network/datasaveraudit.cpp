/**
 * @file    datasaveraudit.cpp
 * @brief   Metadata-only audit records for committed Data Saver decisions
 *          (DS-010).
 * @author  Oasis
 */
#include "datasaveraudit.h"

#include <QFileInfo>
#include <QJsonDocument>

namespace {

QString bounded(const QString &text, int maximum)
{
    if (maximum <= 0) return QString();
    const QString value = text.simplified();
    if (value.size() <= maximum) return value;
    return value.left(maximum - 1) + QChar(0x2026);
}

/// Base name only. The audit never keeps a directory path, even when a caller
/// hands one in.
QString executableBaseName(const QString &value)
{
    QString cleaned = value.trimmed();
    while (cleaned.endsWith(QLatin1Char('/')) || cleaned.endsWith(QLatin1Char(92)))
        cleaned.chop(1);
    if (cleaned.isEmpty()) return QString();
    const QString name = QFileInfo(cleaned).fileName();
    // A value with no file component is not a name; drop it rather than keep a
    // directory path in the record.
    if (name.isEmpty() || name == QLatin1String(".") || name == QLatin1String(".."))
        return QString();
    return bounded(name, DataSaverAudit::kMaxNameChars);
}

QString actionToken(NetworkPolicy::Action action)
{
    switch (action) {
    case NetworkPolicy::Action::Allow:     return QStringLiteral("allow");
    case NetworkPolicy::Action::Notify:    return QStringLiteral("notify");
    case NetworkPolicy::Action::Ask:       return QStringLiteral("ask");
    case NetworkPolicy::Action::Throttle:  return QStringLiteral("throttle");
    case NetworkPolicy::Action::Block:     return QStringLiteral("block");
    case NetworkPolicy::Action::Schedule:  return QStringLiteral("schedule");
    case NetworkPolicy::Action::NoAction:  return QStringLiteral("no_action");
    }
    return QStringLiteral("no_action");
}

QString directionToken(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("download");
    case NetworkDirection::Upload:   return QStringLiteral("upload");
    case NetworkDirection::Both:     return QStringLiteral("both");
    }
    return QStringLiteral("download");
}

QString enforcementStatusToken(EnforcementResult::Status status)
{
    switch (status) {
    case EnforcementResult::Status::NotApplied: return QStringLiteral("not_applied");
    case EnforcementResult::Status::Requested:  return QStringLiteral("requested");
    case EnforcementResult::Status::Applied:    return QStringLiteral("applied");
    case EnforcementResult::Status::Partial:    return QStringLiteral("partial");
    case EnforcementResult::Status::Failed:     return QStringLiteral("failed");
    }
    return QStringLiteral("not_applied");
}

QString identityIdFor(const DataSaverAudit::DecisionRecord &record)
{
    const QString id = record.decision.target.identityId.isEmpty()
                           ? record.observation.process.identityId
                           : record.decision.target.identityId;
    return bounded(id, DataSaverAudit::kMaxRuleIdChars);
}

QString executableFor(const DataSaverAudit::DecisionRecord &record)
{
    return executableBaseName(record.executableName.isEmpty()
                                  ? record.decision.target.executable
                                  : record.executableName);
}

} // namespace

namespace DataSaverAudit {

bool isUserOrigin(DecisionOrigin origin)
{
    return origin == DecisionOrigin::Pinned || origin == DecisionOrigin::Session;
}

QString originLabel(DecisionOrigin origin)
{
    switch (origin) {
    case DecisionOrigin::Pinned:  return QStringLiteral("pinned rule");
    case DecisionOrigin::Session: return QStringLiteral("session override");
    case DecisionOrigin::Profile: return QStringLiteral("profile match");
    case DecisionOrigin::Cache:   return QStringLiteral("cache hit");
    case DecisionOrigin::Fallback: return QStringLiteral("fallback");
    }
    return QStringLiteral("fallback");
}

QJsonObject detailObject(const DecisionRecord &record)
{
    const PolicyDecision &decision = record.decision;

    QJsonObject details;
    details[QStringLiteral("schemaVersion")] = kSchemaVersion;
    details[QStringLiteral("decisionId")] = bounded(decision.decisionId, 64);
    details[QStringLiteral("observationId")] = bounded(
        decision.observationId.isEmpty() ? record.observation.observationId
                                         : decision.observationId,
        64);
    details[QStringLiteral("flowId")] = bounded(record.observation.flow.flowId, 64);
    details[QStringLiteral("milestoneIndex")] = record.observation.metrics.milestoneIndex;
    details[QStringLiteral("milestoneBytes")] =
        static_cast<double>(record.observation.metrics.milestoneBytes);

    details[QStringLiteral("origin")] = decisionOriginToken(decision.origin);
    details[QStringLiteral("automatic")] = decision.isAutomatic();
    details[QStringLiteral("tier")] = decision.tier;
    details[QStringLiteral("action")] = actionToken(decision.action);
    details[QStringLiteral("scope")] = decisionScopeToken(decision.scope);
    details[QStringLiteral("direction")] = directionToken(decision.direction);
    details[QStringLiteral("rateBitsPerSecond")] =
        static_cast<double>(decision.rateBitsPerSecond);
    details[QStringLiteral("until")] = throttleUntilToken(decision.until);
    details[QStringLiteral("confidence")] = decision.confidence;

    details[QStringLiteral("targetExecutable")] = executableFor(record);
    details[QStringLiteral("identityId")] = identityIdFor(record);
    details[QStringLiteral("domain")] = bounded(decision.evidence.domain, 253);
    details[QStringLiteral("matchedRuleId")] =
        bounded(record.matchedRuleId, kMaxRuleIdChars);
    details[QStringLiteral("matchedCacheKey")] =
        bounded(record.matchedCacheKey, kMaxCacheKeyChars);
    details[QStringLiteral("policyId")] =
        bounded(record.enforcementPolicyId.isEmpty() ? record.matchedRuleId
                                                     : record.enforcementPolicyId,
                kMaxRuleIdChars);
    details[QStringLiteral("reason")] = bounded(decision.reasonShort, kMaxReasonChars);
    details[QStringLiteral("resolverDiagnostic")] =
        bounded(record.diagnostic, kMaxDiagnosticChars);

    QJsonObject evidence;
    evidence[QStringLiteral("milestoneBytes")] =
        static_cast<double>(decision.evidence.milestoneBytes);
    evidence[QStringLiteral("milestoneIndex")] = decision.evidence.milestoneIndex;
    evidence[QStringLiteral("foregroundState")] =
        bounded(decision.evidence.foregroundState, 32);
    evidence[QStringLiteral("uxProfile")] =
        bounded(decision.evidence.uxProfile, 64);
    evidence[QStringLiteral("domainConfidence")] =
        bounded(decision.evidence.domainConfidence, 32);
    evidence[QStringLiteral("multiplexed")] = decision.evidence.multiplexed;
    evidence[QStringLiteral("shared")] = decision.evidence.shared;
    details[QStringLiteral("evidence")] = evidence;

    if (decision.conflict.hasConflict) {
        QJsonObject conflict;
        conflict[QStringLiteral("conflictingTier")] = decision.conflict.conflictingTier;
        conflict[QStringLiteral("resolution")] =
            bounded(decision.conflict.resolution, 64);
        conflict[QStringLiteral("detail")] =
            bounded(decision.conflict.detail, kMaxMessageChars);
        details[QStringLiteral("conflict")] = conflict;
    }

    QJsonObject enforcement;
    enforcement[QStringLiteral("status")] =
        enforcementStatusToken(record.enforcementStatus);
    enforcement[QStringLiteral("changed")] = record.enforcementChanged;
    enforcement[QStringLiteral("policyId")] =
        bounded(record.enforcementPolicyId, kMaxRuleIdChars);
    enforcement[QStringLiteral("channels")] =
        bounded(record.enforcementChannels, kMaxNameChars);
    enforcement[QStringLiteral("message")] =
        bounded(record.enforcementMessage, kMaxMessageChars);
    enforcement[QStringLiteral("executable")] = executableFor(record);
    details[QStringLiteral("enforcement")] = enforcement;

    return details;
}

QString detailsText(const DecisionRecord &record)
{
    return QString::fromUtf8(
        QJsonDocument(detailObject(record)).toJson(QJsonDocument::Compact));
}

AuditEvent eventFor(const DecisionRecord &record, const QDateTime &now)
{
    const PolicyDecision &decision = record.decision;
    // The audit timestamp is the commit, not when a cached decision was first
    // produced; a cache hit is committed again for this observation.
    const QDateTime stamp = now.isValid()
                                ? now
                                : (decision.createdAt.isValid()
                                       ? decision.createdAt
                                       : QDateTime::currentDateTimeUtc());

    AuditEvent event;
    event.timestamp = stamp.toUTC();
    event.type = isUserOrigin(decision.origin) ? AuditEvent::EventType::UserDecision
                                               : AuditEvent::EventType::AutomaticDecision;
    event.scope = executableFor(record);
    const QString reason = bounded(decision.reasonShort, kMaxReasonChars);
    event.reason = QStringLiteral("Data Saver ") + originLabel(decision.origin);
    if (!reason.isEmpty())
        event.reason += QStringLiteral(": ") + reason;
    event.result = QStringLiteral("%1 (%2)")
                       .arg(actionToken(decision.action),
                            enforcementStatusToken(record.enforcementStatus));
    if (record.enforcementStatus == EnforcementResult::Status::Failed)
        event.errorInfo = bounded(record.enforcementMessage, kMaxMessageChars);
    event.relatedIdentityId = identityIdFor(record);
    event.relatedPolicyId =
        bounded(record.enforcementPolicyId.isEmpty() ? record.matchedRuleId
                                                     : record.enforcementPolicyId,
                kMaxRuleIdChars);
    event.details = detailsText(record);
    return event;
}

} // namespace DataSaverAudit
