/**
 * @file    datasaveraudit.h
 * @brief   Metadata-only audit records for committed Data Saver decisions
 *          (DS-010).
 *
 * Every evaluated decision becomes one `AuditEvent`:
 *  - pinned/session wins are typed `UserDecision`, automatic origins are typed
 *    `AutomaticDecision`, and the origin is repeated in the details JSON;
 *  - the details carry the decision and observation ids, flow id, milestone,
 *    action/scope/direction, precedence tier, matched rule id or cache
 *    fingerprint, a bounded evidence summary, the reason, and the enforcement
 *    result;
 *  - the payload is metadata only. The builder never reads observation
 *    endpoints or a full executable path; it keeps the executable base name,
 *    the attributed domain, and the bounded decision evidence.
 *
 * The details field is a compact JSON object inside the existing `AuditEvent`
 * contract, so the audit view, JSON export, and CSV export keep working
 * without a schema change. A failed or partial enforcement is recorded with
 * that status and the channel message; building the audit record never changes
 * the enforcement outcome.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QString>

#include "datasaverdecision.h"
#include "enforcementcoordinator.h"
#include "policy.h"

namespace DataSaverAudit {
constexpr int kSchemaVersion = 1;
constexpr int kMaxReasonChars = 200;
constexpr int kMaxMessageChars = 300;
constexpr int kMaxDiagnosticChars = 400;
constexpr int kMaxRuleIdChars = 128;
constexpr int kMaxCacheKeyChars = 96;
constexpr int kMaxNameChars = 96;

/// Everything one committed decision contributes to its audit record. Fields
/// are metadata only; `executableName` is reduced to a base name and never
/// stores a directory path.
struct DecisionRecord
{
    FlowObservation observation;
    PolicyDecision decision;
    QString matchedRuleId;
    QString matchedCacheKey;
    QString diagnostic;
    QString executableName;
    EnforcementResult::Status enforcementStatus = EnforcementResult::Status::NotApplied;
    bool enforcementChanged = false;
    QString enforcementMessage;
    QString enforcementPolicyId;
    QString enforcementChannels;
};

/// True for a decision the user owns (a pin or a session override).
bool isUserOrigin(DecisionOrigin origin);

/// "pinned rule", "session override", "profile match", "cache hit", "fallback".
QString originLabel(DecisionOrigin origin);

/// The bounded metadata JSON stored in `AuditEvent::details`.
QJsonObject detailObject(const DecisionRecord &record);

/// Compact form of detailObject(), still bounded.
QString detailsText(const DecisionRecord &record);

/// Builds the audit event. `now` is the commit time; the decision timestamp is
/// only a fallback. The record's enforcement outcome is copied, never
/// reinterpreted.
AuditEvent eventFor(const DecisionRecord &record,
                    const QDateTime &now = QDateTime());
} // namespace DataSaverAudit
