/**
 * @file    datasaverdecision.cpp
 * @brief   Decision contract validation and the fixed-precedence resolver (DS-008).
 * @author  Oasis
 */
#include "datasaverdecision.h"

#include "datasavercache.h"

#include <QJsonArray>
#include <QRandomGenerator>

#include <cmath>

using Action = NetworkPolicy::Action;

namespace {

constexpr quint64 kGentleRate = DataSaverDecision::kGentleThrottleBitsPerSecond;
constexpr int kMaxReasonLength = 200;
constexpr int kMaxNextSteps = 5;
constexpr int kMaxNextStepLength = 160;

bool fail(QString *error, const QString &message)
{
    if (error) *error = message;
    return false;
}

QString boundedReason(QString text)
{
    text = text.simplified();
    if (text.isEmpty())
        text = QStringLiteral("Data Saver decision.");
    return text.left(kMaxReasonLength);
}

QString actionWireToken(const PolicyDecision &decision)
{
    switch (decision.action) {
    case Action::Allow: return QStringLiteral("allow");
    case Action::Notify:
        return decision.continueAfterNotify ? QStringLiteral("notify_then_continue")
                                            : QStringLiteral("notify");
    case Action::Throttle: return QStringLiteral("throttle");
    case Action::Block: return QStringLiteral("block");
    case Action::Ask:
    case Action::Schedule:
    case Action::NoAction:
        break;
    }
    return QString();
}

bool actionFromWireToken(const QString &text, Action *action, bool *continueAfterNotify)
{
    const QString token = text.trimmed().toLower();
    bool continuation = false;
    Action parsed = Action::NoAction;
    if (token == QStringLiteral("allow")) {
        parsed = Action::Allow;
    } else if (token == QStringLiteral("notify")) {
        parsed = Action::Notify;
    } else if (token == QStringLiteral("notify_then_continue")) {
        parsed = Action::Notify;
        continuation = true;
    } else if (token == QStringLiteral("throttle")) {
        parsed = Action::Throttle;
    } else if (token == QStringLiteral("block")) {
        parsed = Action::Block;
    } else {
        return false;
    }
    if (action) *action = parsed;
    if (continueAfterNotify) *continueAfterNotify = continuation;
    return true;
}

QString directionToken(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("download");
    case NetworkDirection::Upload: return QStringLiteral("upload");
    case NetworkDirection::Both: return QStringLiteral("both");
    }
    return QStringLiteral("download");
}

bool directionFromToken(const QString &text, NetworkDirection *direction)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("download")) { if (direction) *direction = NetworkDirection::Download; return true; }
    if (token == QStringLiteral("upload")) { if (direction) *direction = NetworkDirection::Upload; return true; }
    if (token == QStringLiteral("both")) { if (direction) *direction = NetworkDirection::Both; return true; }
    return false;
}

QString foregroundToken(FlowForegroundState state)
{
    switch (state) {
    case FlowForegroundState::ForegroundActive: return QStringLiteral("foreground_active");
    case FlowForegroundState::ForegroundIdle: return QStringLiteral("foreground_idle");
    case FlowForegroundState::Background: return QStringLiteral("background");
    case FlowForegroundState::Unknown: break;
    }
    return QStringLiteral("unknown");
}

bool foregroundFromToken(const QString &text, FlowForegroundState *state)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("foreground_active")) { if (state) *state = FlowForegroundState::ForegroundActive; return true; }
    if (token == QStringLiteral("foreground_idle")) { if (state) *state = FlowForegroundState::ForegroundIdle; return true; }
    if (token == QStringLiteral("background")) { if (state) *state = FlowForegroundState::Background; return true; }
    if (token == QStringLiteral("unknown")) { if (state) *state = FlowForegroundState::Unknown; return true; }
    return false;
}

QString domainConfidenceToken(FlowDomainConfidence confidence)
{
    switch (confidence) {
    case FlowDomainConfidence::Confirmed: return QStringLiteral("confirmed");
    case FlowDomainConfidence::StrongInference: return QStringLiteral("strong_inference");
    case FlowDomainConfidence::WeakInference: return QStringLiteral("weak_inference");
    case FlowDomainConfidence::Unknown: break;
    }
    return QStringLiteral("unknown");
}

bool domainConfidenceFromToken(const QString &text, FlowDomainConfidence *confidence)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("confirmed")) { if (confidence) *confidence = FlowDomainConfidence::Confirmed; return true; }
    if (token == QStringLiteral("strong_inference")) { if (confidence) *confidence = FlowDomainConfidence::StrongInference; return true; }
    if (token == QStringLiteral("weak_inference")) { if (confidence) *confidence = FlowDomainConfidence::WeakInference; return true; }
    if (token == QStringLiteral("unknown")) { if (confidence) *confidence = FlowDomainConfidence::Unknown; return true; }
    return false;
}

QString mintDecisionId()
{
    return QStringLiteral("dec_%1").arg(
        QString::number(QRandomGenerator::global()->generate64(), 16).rightJustified(16, QLatin1Char('0')));
}

DecisionTarget buildTarget(const FlowObservation &observation)
{
    DecisionTarget target;
    target.executable = RuleResolver::normalizeExecutable(observation.process.exeName);
    target.identityId = observation.process.identityId;
    target.domain = normalizeFlowDomain(observation.flow.domain);
    target.flowId = observation.flow.flowId;
    return target;
}

DecisionEvidence buildEvidence(const FlowObservation &observation,
                               const QString &uxProfile)
{
    DecisionEvidence evidence;
    evidence.executable = RuleResolver::normalizeExecutable(observation.process.exeName);
    evidence.domain = normalizeFlowDomain(observation.flow.domain);
    evidence.milestoneBytes = observation.metrics.milestoneBytes;
    evidence.milestoneIndex = observation.metrics.milestoneIndex;
    evidence.foregroundState = foregroundToken(observation.process.foregroundState);
    evidence.domainConfidence = domainConfidenceToken(observation.flow.domainConfidence);
    evidence.multiplexed = observation.flow.multiplexed;
    evidence.shared = observation.flow.shared;
    evidence.uxProfile = uxProfile.simplified().left(kMaxNextStepLength);
    return evidence;
}

bool sameOpinion(const PolicyDecision &left, const PolicyDecision &right)
{
    if (left.action != right.action)
        return false;
    if (left.action == Action::Notify)
        return left.continueAfterNotify == right.continueAfterNotify;
    return true;
}

DecisionConflict toDecisionConflict(const ConflictReport &report)
{
    DecisionConflict conflict;
    conflict.hasConflict = report.hasConflict;
    conflict.conflictingTier = report.conflictingTier;
    conflict.resolution = report.resolution;
    conflict.detail = report.detail;
    return conflict;
}

bool readRequiredString(const QJsonObject &object, const QString &key,
                        QString *value, QString *error)
{
    const QJsonValue entry = object.value(key);
    if (!entry.isString() || entry.toString().trimmed().isEmpty())
        return fail(error, QStringLiteral("policy decision is missing %1").arg(key));
    *value = entry.toString();
    return true;
}

bool readOptionalString(const QJsonObject &object, const QString &key, QString *value)
{
    const QJsonValue entry = object.value(key);
    if (!entry.isString()) return false;
    *value = entry.toString();
    return true;
}

bool readUnsigned(const QJsonValue &value, quint64 *number)
{
    if (!value.isDouble()) return false;
    const double raw = value.toDouble();
    if (raw < 0.0 || !std::isfinite(raw)) return false;
    *number = static_cast<quint64>(raw);
    return true;
}

bool readBool(const QJsonValue &value, bool *flag)
{
    if (!value.isBool()) return false;
    *flag = value.toBool();
    return true;
}

bool weakDomain(const DecisionEvidence &evidence)
{
    return evidence.domain.isEmpty()
           || evidence.domainConfidence.isEmpty()
           || evidence.domainConfidence == QStringLiteral("weak_inference")
           || evidence.domainConfidence == QStringLiteral("unknown");
}

bool strongDomain(const FlowObservation &observation)
{
    return !observation.flow.domain.isEmpty()
           && (observation.flow.domainConfidence == FlowDomainConfidence::Confirmed
               || observation.flow.domainConfidence == FlowDomainConfidence::StrongInference);
}

/// Re-checks a candidate against the automatic-origin safety rules. The
/// signature engine already guards its own recommendation, but a profile rule
/// can be replaced at runtime and a cache entry is untrusted input, so the
/// resolver never trusts an automatic action it did not just check.
void applyAutomaticGuards(PolicyDecision *decision, const ResolverInput &input,
                          const SignatureResult &signature, QStringList *notes)
{
    const FlowObservation &observation = input.signature.observation;

    auto downgrade = [&](const QString &reason) {
        if (decision->action != Action::Throttle && decision->action != Action::Block)
            return;
        decision->action = Action::Notify;
        decision->continueAfterNotify = true;
        decision->rateBitsPerSecond = 0;
        decision->scope = DecisionScope::Executable;
        if (notes) notes->append(reason);
    };

    const bool protectedActivity = input.signature.protectedExecutable
                                   || signature.detectorTags.contains(QStringLiteral("protected_signature"));
    const bool latencySensitive = input.signature.latencySensitive
                                  || observation.uxSignals.latencySensitive;
    const bool packageInstall = signature.classification == SignatureClassification::PackageInstall
                                || input.signature.interactivePackageInstall;

    if (observation.process.foregroundState == FlowForegroundState::ForegroundActive)
        downgrade(QStringLiteral("foreground-active traffic"));
    if (protectedActivity)
        downgrade(QStringLiteral("protected executable"));
    if (latencySensitive)
        downgrade(QStringLiteral("latency-sensitive activity"));
    if (packageInstall)
        downgrade(QStringLiteral("package install"));
    if (decision->confidence + 1e-9 < 0.70)
        downgrade(QStringLiteral("confidence below 0.70"));

    if (decision->action == Action::Block) {
        if (decision->origin != DecisionOrigin::Profile)
            downgrade(QStringLiteral("an automatic block requires a profile rule"));
        else if (decision->confidence + 1e-9 < 0.85)
            downgrade(QStringLiteral("profile block confidence below 0.85"));
        else if (decision->scope != DecisionScope::Executable)
            downgrade(QStringLiteral("automatic block scope is not executable"));
        else if (weakDomain(decision->evidence))
            downgrade(QStringLiteral("weak domain evidence"));
        else if (observation.flow.domainSource == FlowDomainSource::EchOuter)
            downgrade(QStringLiteral("ECH-only attribution"));
        else if (decision->evidence.multiplexed || decision->evidence.shared)
            downgrade(QStringLiteral("shared or multiplexed flow"));
    }

    if (decision->action == Action::Throttle) {
        if (decision->scope != DecisionScope::Executable) {
            decision->scope = DecisionScope::Executable;
            if (notes) notes->append(QStringLiteral("throttle widened to executable scope"));
        }
        if (decision->rateBitsPerSecond < kGentleRate) {
            downgrade(QStringLiteral("automatic throttle below 50 KiB/s"));
        } else {
            if (decision->rateBitsPerSecond > kGentleRate && notes)
                notes->append(QStringLiteral("throttle capped to 50 KiB/s"));
            decision->rateBitsPerSecond = kGentleRate;
        }
        decision->direction = NetworkDirection::Download;
    }

    if (decision->action != Action::Notify)
        decision->continueAfterNotify = false;
}

PolicyDecision makeBaseDecision(const FlowObservation &observation,
                                const QDateTime &now)
{
    PolicyDecision decision;
    decision.decisionId = mintDecisionId();
    decision.observationId = observation.observationId;
    decision.createdAt = now;
    decision.target = buildTarget(observation);
    return decision;
}

PolicyDecision buildProfileDecision(const ResolverInput &input,
                                    const SignatureResult &signature,
                                    const QDateTime &now,
                                    QStringList *notes)
{
    const FlowObservation &observation = input.signature.observation;

    PolicyDecision decision = makeBaseDecision(observation, now);
    decision.origin = DecisionOrigin::Profile;
    decision.tier = decisionOriginTier(DecisionOrigin::Profile);
    decision.action = signature.action;
    decision.continueAfterNotify = signature.continueAfterNotify;
    decision.scope = DecisionScope::Executable;
    decisionScopeFromToken(signature.scope, &decision.scope);
    decision.direction = NetworkDirection::Download;
    decision.rateBitsPerSecond =
        decision.action == Action::Throttle
            ? (signature.rateBitsPerSecond > 0 ? signature.rateBitsPerSecond : kGentleRate)
            : 0;
    decision.confidence = signature.confidence;
    decision.classification = signature.classification;
    decision.evidence = buildEvidence(observation,
                                      signature.detectorTags.join(QLatin1Char('+')));
    decision.reasonShort = boundedReason(signature.reason);
    decision.nextSteps << QStringLiteral("Review the activity or create a rule to change it.");

    applyAutomaticGuards(&decision, input, signature, notes);
    return decision;
}

PolicyDecision buildFallbackDecision(const ResolverInput &input,
                                     const SignatureResult &signature,
                                     const QDateTime &now)
{
    const FlowObservation &observation = input.signature.observation;

    PolicyDecision decision = makeBaseDecision(observation, now);
    decision.origin = DecisionOrigin::Fallback;
    decision.tier = decisionOriginTier(DecisionOrigin::Fallback);
    decision.action = Action::Notify;
    decision.continueAfterNotify = true;
    decision.scope = DecisionScope::Executable;
    decision.direction = NetworkDirection::Download;
    decision.confidence = signature.confidence > 0.0 ? signature.confidence : 0.30;
    decision.classification = signature.classification;
    decision.evidence = buildEvidence(observation, QStringLiteral("safe_fallback"));

    const bool protectedActivity = input.signature.protectedExecutable
                                   || signature.detectorTags.contains(QStringLiteral("protected_signature"));
    const bool latencySensitive = input.signature.latencySensitive
                                  || observation.uxSignals.latencySensitive;
    const bool packageInstall = signature.classification == SignatureClassification::PackageInstall
                                || input.signature.interactivePackageInstall;

    const bool canThrottle = input.gentleThrottleAvailable
                             && observation.process.foregroundState == FlowForegroundState::Background
                             && !protectedActivity
                             && !latencySensitive
                             && !packageInstall
                             && !observation.flow.shared
                             && !observation.flow.multiplexed
                             && strongDomain(observation)
                             && decision.confidence + 1e-9 >= 0.70;

    if (canThrottle) {
        decision.action = Action::Throttle;
        decision.continueAfterNotify = false;
        decision.rateBitsPerSecond = kGentleRate;
        decision.reasonShort = QStringLiteral(
            "No higher rule matched; background traffic is limited to 50 KiB/s.");
        decision.nextSteps << QStringLiteral("Tune Data Saver mode or pin a rule to stop the limit.");
    } else {
        decision.reasonShort = QStringLiteral(
            "No higher rule matched; traffic continues with a conservative notice.");
        decision.nextSteps << QStringLiteral("Create a pinned rule to choose a different outcome.");
    }
    return decision;
}

PolicyDecision buildRuleDecision(const RuleMatch &match,
                                 const FlowObservation &observation,
                                 const SignatureResult &signature,
                                 bool classified,
                                 const QDateTime &now,
                                 QStringList *diagnostics)
{
    PolicyDecision decision = makeBaseDecision(observation, now);
    decision.origin = match.tier == 1 ? DecisionOrigin::Pinned : DecisionOrigin::Session;
    decision.tier = match.tier;
    decision.action = match.action;
    decision.continueAfterNotify = match.continueAfterNotify;
    decision.scope = DecisionScope::Executable;
    decisionScopeFromToken(match.scope, &decision.scope);
    decision.direction = match.direction;
    decision.rateBitsPerSecond = match.action == Action::Throttle ? match.rateBitsPerSecond : 0;
    decision.confidence = 1.0;
    decision.classification = classified ? signature.classification
                                         : SignatureClassification::Unknown;
    decision.evidence = buildEvidence(
        observation, match.tier == 1 ? QStringLiteral("user_pinned")
                                     : QStringLiteral("user_session"));
    if (!match.executable.isEmpty())
        decision.target.executable = RuleResolver::normalizeExecutable(match.executable);
    if (!match.domain.isEmpty())
        decision.target.domain = normalizeFlowDomain(match.domain);

    if (decision.action == Action::Throttle && decision.rateBitsPerSecond == 0) {
        decision.action = Action::Notify;
        decision.continueAfterNotify = true;
        if (diagnostics)
            diagnostics->append(QStringLiteral("the winning user rule had no throttle rate"));
    }
    if (decision.action != Action::Notify)
        decision.continueAfterNotify = false;

    decision.reasonShort =
        boundedReason(QStringLiteral("%1 rule %2 selected the %3 outcome.")
                          .arg(match.tier == 1 ? QStringLiteral("Pinned")
                                               : QStringLiteral("Session"),
                               match.ruleId, actionWireToken(decision)));
    decision.nextSteps << (match.tier == 1
                               ? QStringLiteral("Edit or remove the pinned rule to change this.")
                               : QStringLiteral("End the session or remove the override to change this."));
    return decision;
}

bool buildCacheDecision(const PolicyDecision *candidate, const ResolverInput &input,
                        const SignatureResult &signature, const QDateTime &now,
                        PolicyDecision *decision, QString *why)
{
    if (!candidate || !decision) return false;
    const FlowObservation &observation = input.signature.observation;

    PolicyDecision cached = *candidate;
    if (cached.origin != DecisionOrigin::Cache || cached.tier != 4) {
        if (why) *why = QStringLiteral("the cache candidate is not a tier-4 cache decision");
        return false;
    }

    QString error;
    if (!cached.validate(&error)) {
        if (why) *why = QStringLiteral("the cache candidate was rejected: %1").arg(error);
        return false;
    }

    const QString executable = RuleResolver::normalizeExecutable(observation.process.exeName);
    if (cached.target.executable.isEmpty()
        || RuleResolver::normalizeExecutable(cached.target.executable) != executable) {
        if (why) *why = QStringLiteral("the cache candidate targets a different executable");
        return false;
    }
    const QString domain = normalizeFlowDomain(observation.flow.domain);
    if (!cached.target.domain.isEmpty()
        && normalizeFlowDomain(cached.target.domain) != domain) {
        if (why) *why = QStringLiteral("the cache candidate targets a different domain");
        return false;
    }

    cached.decisionId = mintDecisionId();
    cached.observationId = observation.observationId;
    cached.createdAt = now;
    cached.origin = DecisionOrigin::Cache;
    cached.tier = 4;
    cached.conflict = DecisionConflict();
    // The evidence key matched, but the flow identity belongs to this
    // observation, not the one that populated the entry.
    cached.target = buildTarget(observation);
    cached.evidence = buildEvidence(observation, cached.evidence.uxProfile);
    applyAutomaticGuards(&cached, input, signature, nullptr);

    if (!cached.validate(&error)) {
        if (why) *why = QStringLiteral("the guarded cache candidate was rejected: %1").arg(error);
        return false;
    }
    *decision = cached;
    return true;
}

} // namespace

QString decisionOriginToken(DecisionOrigin origin)
{
    switch (origin) {
    case DecisionOrigin::Pinned: return QStringLiteral("pinned");
    case DecisionOrigin::Session: return QStringLiteral("session");
    case DecisionOrigin::Profile: return QStringLiteral("profile");
    case DecisionOrigin::Cache: return QStringLiteral("cache");
    case DecisionOrigin::Fallback: return QStringLiteral("fallback");
    }
    return QStringLiteral("fallback");
}

bool decisionOriginFromToken(const QString &text, DecisionOrigin *origin)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("pinned")) { if (origin) *origin = DecisionOrigin::Pinned; return true; }
    if (token == QStringLiteral("session")) { if (origin) *origin = DecisionOrigin::Session; return true; }
    if (token == QStringLiteral("profile")) { if (origin) *origin = DecisionOrigin::Profile; return true; }
    if (token == QStringLiteral("cache")) { if (origin) *origin = DecisionOrigin::Cache; return true; }
    if (token == QStringLiteral("fallback")) { if (origin) *origin = DecisionOrigin::Fallback; return true; }
    return false;
}

int decisionOriginTier(DecisionOrigin origin)
{
    switch (origin) {
    case DecisionOrigin::Pinned: return 1;
    case DecisionOrigin::Session: return 2;
    case DecisionOrigin::Profile: return 3;
    case DecisionOrigin::Cache: return 4;
    case DecisionOrigin::Fallback: return 5;
    }
    return 5;
}

QString decisionScopeToken(DecisionScope scope)
{
    switch (scope) {
    case DecisionScope::Flow: return QStringLiteral("flow");
    case DecisionScope::Domain: return QStringLiteral("domain");
    case DecisionScope::Executable: return QStringLiteral("executable");
    case DecisionScope::Group: return QStringLiteral("group");
    }
    return QStringLiteral("executable");
}

bool decisionScopeFromToken(const QString &text, DecisionScope *scope)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("flow")) { if (scope) *scope = DecisionScope::Flow; return true; }
    if (token == QStringLiteral("domain")) { if (scope) *scope = DecisionScope::Domain; return true; }
    if (token == QStringLiteral("executable")) { if (scope) *scope = DecisionScope::Executable; return true; }
    if (token == QStringLiteral("group")) { if (scope) *scope = DecisionScope::Group; return true; }
    return false;
}

QString throttleUntilToken(ThrottleUntil until)
{
    switch (until) {
    case ThrottleUntil::ForegroundChange: return QStringLiteral("foreground_change");
    case ThrottleUntil::MilestoneNext: return QStringLiteral("milestone_next");
    case ThrottleUntil::SessionEnd: return QStringLiteral("session_end");
    case ThrottleUntil::ManualOverride: return QStringLiteral("manual_override");
    }
    return QStringLiteral("milestone_next");
}

bool throttleUntilFromToken(const QString &text, ThrottleUntil *until)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("foreground_change")) { if (until) *until = ThrottleUntil::ForegroundChange; return true; }
    if (token == QStringLiteral("milestone_next")) { if (until) *until = ThrottleUntil::MilestoneNext; return true; }
    if (token == QStringLiteral("session_end")) { if (until) *until = ThrottleUntil::SessionEnd; return true; }
    if (token == QStringLiteral("manual_override")) { if (until) *until = ThrottleUntil::ManualOverride; return true; }
    return false;
}

QJsonObject PolicyDecision::toJson() const
{
    QJsonObject object;
    object.insert(QStringLiteral("schemaVersion"), schemaVersion);
    object.insert(QStringLiteral("decisionId"), decisionId);
    object.insert(QStringLiteral("observationId"), observationId);
    object.insert(QStringLiteral("createdAt"), createdAt.toUTC().toString(Qt::ISODate));
    object.insert(QStringLiteral("origin"), decisionOriginToken(origin));
    object.insert(QStringLiteral("tier"), tier);
    object.insert(QStringLiteral("action"), actionWireToken(*this));
    object.insert(QStringLiteral("continueAfterNotify"), continueAfterNotify);
    object.insert(QStringLiteral("scope"), decisionScopeToken(scope));

    QJsonObject targetObject;
    if (!target.executable.isEmpty())
        targetObject.insert(QStringLiteral("executable"), target.executable);
    if (!target.identityId.isEmpty())
        targetObject.insert(QStringLiteral("identityId"), target.identityId);
    if (!target.domain.isEmpty())
        targetObject.insert(QStringLiteral("domain"), target.domain);
    if (!target.flowId.isEmpty())
        targetObject.insert(QStringLiteral("flowId"), target.flowId);
    object.insert(QStringLiteral("target"), targetObject);

    object.insert(QStringLiteral("direction"), directionToken(direction));
    if (action == Action::Throttle) {
        QJsonObject throttle;
        throttle.insert(QStringLiteral("rxBitsPerSecond"),
                        static_cast<double>(direction == NetworkDirection::Upload ? 0 : rateBitsPerSecond));
        throttle.insert(QStringLiteral("txBitsPerSecond"),
                        static_cast<double>(direction == NetworkDirection::Download ? 0 : rateBitsPerSecond));
        throttle.insert(QStringLiteral("until"), throttleUntilToken(until));
        object.insert(QStringLiteral("throttle"), throttle);
    }
    object.insert(QStringLiteral("confidence"), confidence);
    object.insert(QStringLiteral("classification"), signatureClassificationToken(classification));

    QJsonObject conflictObject;
    conflictObject.insert(QStringLiteral("hasConflict"), conflict.hasConflict);
    if (conflict.hasConflict)
        conflictObject.insert(QStringLiteral("conflictingTier"), conflict.conflictingTier);
    conflictObject.insert(QStringLiteral("resolution"), conflict.resolution);
    object.insert(QStringLiteral("conflict"), conflictObject);

    QJsonObject evidenceObject;
    if (!evidence.executable.isEmpty())
        evidenceObject.insert(QStringLiteral("exe"), evidence.executable);
    if (!evidence.domain.isEmpty())
        evidenceObject.insert(QStringLiteral("domain"), evidence.domain);
    evidenceObject.insert(QStringLiteral("milestoneBytes"),
                          static_cast<double>(evidence.milestoneBytes));
    evidenceObject.insert(QStringLiteral("milestoneIndex"), evidence.milestoneIndex);
    evidenceObject.insert(QStringLiteral("foregroundState"), evidence.foregroundState);
    evidenceObject.insert(QStringLiteral("uxProfile"), evidence.uxProfile);
    evidenceObject.insert(QStringLiteral("domainConfidence"), evidence.domainConfidence);
    evidenceObject.insert(QStringLiteral("multiplexed"), evidence.multiplexed);
    evidenceObject.insert(QStringLiteral("shared"), evidence.shared);
    object.insert(QStringLiteral("evidenceSummary"), evidenceObject);

    object.insert(QStringLiteral("reasonShort"), reasonShort);
    QJsonArray steps;
    for (const QString &step : nextSteps)
        steps.append(step);
    object.insert(QStringLiteral("nextSteps"), steps);
    return object;
}

bool PolicyDecision::fromJson(const QJsonObject &object, PolicyDecision *decision,
                              QString *error)
{
    if (!decision)
        return fail(error, QStringLiteral("missing decision destination"));

    int version = kSchemaVersion;
    if (object.contains(QStringLiteral("schemaVersion"))) {
        const QJsonValue value = object.value(QStringLiteral("schemaVersion"));
        if (!value.isDouble())
            return fail(error, QStringLiteral("the policy decision schema version is not a number"));
        version = value.toInt();
        if (version < 1)
            return fail(error, QStringLiteral("invalid policy decision schema version"));
        if (version > kSchemaVersion)
            return fail(error, QStringLiteral("newer policy decision schema version %1").arg(version));
    }

    PolicyDecision parsed;
    parsed.schemaVersion = version;

    QString originToken;
    if (!readRequiredString(object, QStringLiteral("decisionId"), &parsed.decisionId, error)
        || !readRequiredString(object, QStringLiteral("observationId"), &parsed.observationId, error)
        || !readRequiredString(object, QStringLiteral("origin"), &originToken, error)) {
        return false;
    }
    DecisionOrigin origin = DecisionOrigin::Fallback;
    if (!decisionOriginFromToken(originToken, &origin))
        return fail(error, QStringLiteral("unknown policy decision origin"));
    parsed.origin = origin;

    const QJsonValue tierValue = object.value(QStringLiteral("tier"));
    if (!tierValue.isDouble())
        return fail(error, QStringLiteral("policy decision is missing tier"));
    parsed.tier = tierValue.toInt();

    const QString createdAt = object.value(QStringLiteral("createdAt")).toString();
    parsed.createdAt = QDateTime::fromString(createdAt, Qt::ISODate);
    if (!parsed.createdAt.isValid())
        return fail(error, QStringLiteral("policy decision has an invalid createdAt"));

    QString actionText;
    if (!readRequiredString(object, QStringLiteral("action"), &actionText, error))
        return false;
    if (!actionFromWireToken(actionText, &parsed.action, &parsed.continueAfterNotify))
        return fail(error, QStringLiteral("unknown policy decision action"));
    if (object.contains(QStringLiteral("continueAfterNotify"))) {
        bool explicitContinuation = false;
        if (!readBool(object.value(QStringLiteral("continueAfterNotify")), &explicitContinuation))
            return fail(error, QStringLiteral("continueAfterNotify is not a boolean"));
        if (parsed.action == Action::Notify && explicitContinuation != parsed.continueAfterNotify)
            return fail(error, QStringLiteral("the action and continueAfterNotify disagree"));
        if (parsed.action != Action::Notify && explicitContinuation)
            return fail(error, QStringLiteral("only a notice may continue after notify"));
    }

    QString scopeText;
    if (!readRequiredString(object, QStringLiteral("scope"), &scopeText, error))
        return false;
    if (!decisionScopeFromToken(scopeText, &parsed.scope))
        return fail(error, QStringLiteral("unknown policy decision scope"));

    const QJsonValue targetValue = object.value(QStringLiteral("target"));
    if (!targetValue.isObject())
        return fail(error, QStringLiteral("policy decision is missing target"));
    const QJsonObject targetObject = targetValue.toObject();
    readOptionalString(targetObject, QStringLiteral("executable"), &parsed.target.executable);
    readOptionalString(targetObject, QStringLiteral("identityId"), &parsed.target.identityId);
    readOptionalString(targetObject, QStringLiteral("domain"), &parsed.target.domain);
    readOptionalString(targetObject, QStringLiteral("flowId"), &parsed.target.flowId);

    QString directionText;
    if (!readRequiredString(object, QStringLiteral("direction"), &directionText, error))
        return false;
    if (!directionFromToken(directionText, &parsed.direction))
        return fail(error, QStringLiteral("unknown policy decision direction"));

    if (object.contains(QStringLiteral("throttle"))) {
        if (!object.value(QStringLiteral("throttle")).isObject())
            return fail(error, QStringLiteral("the throttle block is not an object"));
        const QJsonObject throttle = object.value(QStringLiteral("throttle")).toObject();
        quint64 rx = 0;
        quint64 tx = 0;
        if (!readUnsigned(throttle.value(QStringLiteral("rxBitsPerSecond")), &rx)
            || !readUnsigned(throttle.value(QStringLiteral("txBitsPerSecond")), &tx)) {
            return fail(error, QStringLiteral("the throttle rates are not non-negative integers"));
        }
        parsed.rateBitsPerSecond = rx > 0 ? rx : tx;
        if (throttle.contains(QStringLiteral("until"))) {
            if (!throttleUntilFromToken(throttle.value(QStringLiteral("until")).toString(),
                                        &parsed.until)) {
                return fail(error, QStringLiteral("unknown throttle until value"));
            }
        }
    }

    const QJsonValue confidenceValue = object.value(QStringLiteral("confidence"));
    if (!confidenceValue.isDouble())
        return fail(error, QStringLiteral("policy decision is missing confidence"));
    parsed.confidence = confidenceValue.toDouble();

    QString classificationText;
    if (!readRequiredString(object, QStringLiteral("classification"), &classificationText, error))
        return false;
    if (!signatureClassificationFromToken(classificationText, &parsed.classification))
        return fail(error, QStringLiteral("unknown policy decision classification"));

    if (object.contains(QStringLiteral("conflict"))) {
        if (!object.value(QStringLiteral("conflict")).isObject())
            return fail(error, QStringLiteral("the conflict block is not an object"));
        const QJsonObject conflict = object.value(QStringLiteral("conflict")).toObject();
        bool hasConflict = false;
        if (conflict.contains(QStringLiteral("hasConflict"))
            && !readBool(conflict.value(QStringLiteral("hasConflict")), &hasConflict)) {
            return fail(error, QStringLiteral("conflict.hasConflict is not a boolean"));
        }
        parsed.conflict.hasConflict = hasConflict;
        if (conflict.contains(QStringLiteral("conflictingTier"))) {
            const QJsonValue tier = conflict.value(QStringLiteral("conflictingTier"));
            if (!tier.isDouble())
                return fail(error, QStringLiteral("conflict.conflictingTier is not a number"));
            parsed.conflict.conflictingTier = tier.toInt();
        }
        if (conflict.contains(QStringLiteral("resolution"))
            && !readOptionalString(conflict, QStringLiteral("resolution"),
                                   &parsed.conflict.resolution)) {
            return fail(error, QStringLiteral("conflict.resolution is not a string"));
        }
    }

    const QJsonValue evidenceValue = object.value(QStringLiteral("evidenceSummary"));
    if (!evidenceValue.isObject())
        return fail(error, QStringLiteral("policy decision is missing evidenceSummary"));
    const QJsonObject evidenceObject = evidenceValue.toObject();
    readOptionalString(evidenceObject, QStringLiteral("exe"), &parsed.evidence.executable);
    readOptionalString(evidenceObject, QStringLiteral("domain"), &parsed.evidence.domain);
    if (evidenceObject.contains(QStringLiteral("milestoneBytes"))) {
        if (!readUnsigned(evidenceObject.value(QStringLiteral("milestoneBytes")),
                          &parsed.evidence.milestoneBytes)) {
            return fail(error, QStringLiteral("evidenceSummary.milestoneBytes is invalid"));
        }
    }
    if (evidenceObject.contains(QStringLiteral("milestoneIndex"))) {
        const QJsonValue index = evidenceObject.value(QStringLiteral("milestoneIndex"));
        if (!index.isDouble())
            return fail(error, QStringLiteral("evidenceSummary.milestoneIndex is not a number"));
        parsed.evidence.milestoneIndex = index.toInt();
    }
    readRequiredString(evidenceObject, QStringLiteral("foregroundState"),
                       &parsed.evidence.foregroundState, error);
    readRequiredString(evidenceObject, QStringLiteral("uxProfile"),
                       &parsed.evidence.uxProfile, error);
    if (!parsed.evidence.foregroundState.isEmpty()
        && !parsed.evidence.uxProfile.isEmpty()) {
        // Required strings above already reported a failure; keep going only
        // when both are present.
    } else {
        return false;
    }
    if (evidenceObject.contains(QStringLiteral("domainConfidence")))
        readOptionalString(evidenceObject, QStringLiteral("domainConfidence"),
                           &parsed.evidence.domainConfidence);
    if (evidenceObject.contains(QStringLiteral("multiplexed"))
        && !readBool(evidenceObject.value(QStringLiteral("multiplexed")),
                     &parsed.evidence.multiplexed)) {
        return fail(error, QStringLiteral("evidenceSummary.multiplexed is not a boolean"));
    }
    if (evidenceObject.contains(QStringLiteral("shared"))
        && !readBool(evidenceObject.value(QStringLiteral("shared")),
                     &parsed.evidence.shared)) {
        return fail(error, QStringLiteral("evidenceSummary.shared is not a boolean"));
    }

    readRequiredString(object, QStringLiteral("reasonShort"), &parsed.reasonShort, error);
    if (parsed.reasonShort.isEmpty())
        return false;

    if (!object.contains(QStringLiteral("nextSteps")))
        return fail(error, QStringLiteral("policy decision is missing nextSteps"));
    const QJsonValue stepsValue = object.value(QStringLiteral("nextSteps"));
    if (!stepsValue.isArray())
        return fail(error, QStringLiteral("nextSteps is not an array"));
    const QJsonArray steps = stepsValue.toArray();
    if (steps.size() > kMaxNextSteps)
        return fail(error, QStringLiteral("nextSteps has too many entries"));
    for (const QJsonValue &step : steps) {
        if (!step.isString())
            return fail(error, QStringLiteral("a nextSteps entry is not a string"));
        parsed.nextSteps.append(step.toString());
    }

    if (!parsed.validate(error))
        return false;
    *decision = parsed;
    return true;
}

bool PolicyDecision::validate(QString *error) const
{
    if (schemaVersion != kSchemaVersion)
        return fail(error, QStringLiteral("unsupported policy decision schema version"));
    if (!isFlowIdentifier(decisionId, QStringLiteral("dec_")))
        return fail(error, QStringLiteral("invalid decisionId"));
    if (!isFlowIdentifier(observationId, QStringLiteral("obs_")))
        return fail(error, QStringLiteral("invalid observationId"));
    if (!createdAt.isValid())
        return fail(error, QStringLiteral("invalid createdAt"));

    if (tier != decisionOriginTier(origin))
        return fail(error, QStringLiteral("tier %1 does not match origin %2")
                               .arg(tier)
                               .arg(decisionOriginToken(origin)));

    switch (action) {
    case Action::Allow:
    case Action::Notify:
    case Action::Throttle:
    case Action::Block:
        break;
    case Action::Ask:
    case Action::Schedule:
    case Action::NoAction:
        return fail(error, QStringLiteral("unsupported policy decision action"));
    }

    if (target.isEmpty())
        return fail(error, QStringLiteral("policy decision has no target"));
    if (target.executable.isEmpty() && target.identityId.isEmpty() && target.flowId.isEmpty())
        return fail(error, QStringLiteral(
            "the target needs an executable, identity, or flow"));
    if (scope == DecisionScope::Domain && target.domain.isEmpty())
        return fail(error, QStringLiteral("a domain-scoped decision needs a domain target"));

    if (confidence < 0.0 || confidence > 1.0 || !std::isfinite(confidence))
        return fail(error, QStringLiteral("confidence is outside 0.0-1.0"));
    if ((origin == DecisionOrigin::Pinned || origin == DecisionOrigin::Session)
        && std::fabs(confidence - 1.0) > 1e-9) {
        return fail(error, QStringLiteral("user decisions must carry confidence 1.0"));
    }

    FlowForegroundState foreground = FlowForegroundState::Unknown;
    if (!foregroundFromToken(evidence.foregroundState, &foreground))
        return fail(error, QStringLiteral("invalid evidence foregroundState"));
    FlowDomainConfidence domainConfidence = FlowDomainConfidence::Unknown;
    if (!evidence.domainConfidence.isEmpty()
        && !domainConfidenceFromToken(evidence.domainConfidence, &domainConfidence)) {
        return fail(error, QStringLiteral("invalid evidence domainConfidence"));
    }
    if (evidence.uxProfile.trimmed().isEmpty())
        return fail(error, QStringLiteral("the evidence summary has no uxProfile"));

    if (action == Action::Notify) {
        // Both notify and notify_then_continue are valid notices.
    } else if (continueAfterNotify) {
        return fail(error, QStringLiteral("only a notice may continue after notify"));
    }

    if (action == Action::Throttle) {
        if (rateBitsPerSecond == 0)
            return fail(error, QStringLiteral("a throttle decision needs a positive rate"));
        if (isAutomatic()) {
            if (rateBitsPerSecond < DataSaverDecision::kGentleThrottleBitsPerSecond) {
                return fail(error, QStringLiteral(
                    "an automatic throttle below 50 KiB/s is a de facto block"));
            }
            if (scope != DecisionScope::Executable)
                return fail(error, QStringLiteral(
                    "an automatic throttle must be applied at executable scope"));
            if (foreground == FlowForegroundState::ForegroundActive)
                return fail(error, QStringLiteral(
                    "foreground-active traffic cannot be throttled automatically"));
        }
    } else if (rateBitsPerSecond != 0) {
        return fail(error, QStringLiteral("a non-throttle decision has a rate"));
    }

    if (confidence + 1e-9 < 0.70 && (action == Action::Throttle || action == Action::Block))
        return fail(error, QStringLiteral("confidence below 0.70 cannot throttle or block"));
    if (confidence + 1e-9 < 0.85 && action == Action::Block)
        return fail(error, QStringLiteral("confidence below 0.85 cannot block"));

    if (action == Action::Block) {
        if (origin != DecisionOrigin::Pinned && origin != DecisionOrigin::Profile)
            return fail(error, QStringLiteral("an automatic block requires a profile rule"));
        if (isAutomatic()) {
            if (scope != DecisionScope::Executable)
                return fail(error, QStringLiteral("an automatic block needs executable scope"));
            if (foreground == FlowForegroundState::ForegroundActive)
                return fail(error, QStringLiteral(
                    "foreground-active traffic cannot be blocked automatically"));
            if (evidence.multiplexed || evidence.shared)
                return fail(error, QStringLiteral(
                    "a shared or multiplexed flow cannot be blocked automatically"));
            if (weakDomain(evidence))
                return fail(error, QStringLiteral(
                    "weak domain evidence cannot justify an automatic block"));
        }
    }

    if (reasonShort.trimmed().isEmpty() || reasonShort.size() > kMaxReasonLength)
        return fail(error, QStringLiteral("reasonShort is missing or too long"));
    if (nextSteps.size() > kMaxNextSteps)
        return fail(error, QStringLiteral("too many nextSteps entries"));
    for (const QString &step : nextSteps) {
        if (step.trimmed().isEmpty() || step.size() > kMaxNextStepLength)
            return fail(error, QStringLiteral("a nextSteps entry is empty or too long"));
    }

    if (conflict.hasConflict) {
        if (conflict.conflictingTier < 1 || conflict.conflictingTier > 5)
            return fail(error, QStringLiteral("conflictingTier is outside 1-5"));
        if (conflict.conflictingTier <= tier)
            return fail(error, QStringLiteral("conflictingTier is not below the winning tier"));
        if (conflict.resolution != QStringLiteral("higher_tier_won"))
            return fail(error, QStringLiteral("a conflict must record higher_tier_won"));
    } else if (conflict.resolution != QStringLiteral("applied")) {
        return fail(error, QStringLiteral("a conflict-free decision must record applied"));
    }

    return true;
}

DecisionResolver::DecisionResolver()
    : m_engine()
{
}

DecisionResolver::DecisionResolver(LocalSignatureEngine engine)
    : m_engine(engine)
{
}

bool DecisionResolver::setProfileRules(const QList<ProfileRule> &rules, QString *error)
{
    return m_engine.setProfileRules(rules, error);
}

DecisionResolution DecisionResolver::resolve(const ResolverInput &input) const
{
    DecisionResolution resolution;
    const FlowObservation &observation = input.signature.observation;
    const QDateTime now = input.now.isValid() ? input.now.toUTC()
                                              : QDateTime::currentDateTimeUtc();
    const bool enforcing = input.mode == DataSaverMode::Mode::Enforce;
    const DataSaverCache::CacheContext cacheContext =
        input.cacheContext ? *input.cacheContext : DataSaverCache::CacheContext();

    QStringList diagnostics;
    SignatureResult signature;
    if (enforcing)
        signature = m_engine.classify(input.signature);

    PolicyDecision profileDecision;
    bool hasProfile = false;
    if (enforcing && !signature.profileRuleId.isEmpty()) {
        profileDecision = buildProfileDecision(input, signature, now, &diagnostics);
        QString profileError;
        if (profileDecision.validate(&profileError)) {
            hasProfile = true;
        } else {
            diagnostics.append(QStringLiteral("the profile recommendation was rejected: %1")
                                   .arg(profileError));
        }
    }

    PolicyDecision cacheDecision;
    bool hasCache = false;
    bool cacheStoreHit = false;
    if (enforcing) {
        // DS-007: the evidence cache is read first; an explicit candidate from
        // the caller is the fallback seam for tests and for a cache that cannot
        // answer. A miss is not a failure; tier 5 still resolves.
        PolicyDecision storedCandidate;
        const PolicyDecision *candidate = input.cachedDecision;
        if (input.cache) {
            QString cacheWhy;
            if (input.cache->lookup(observation, cacheContext, &storedCandidate, now,
                                    &cacheWhy)) {
                candidate = &storedCandidate;
                cacheStoreHit = true;
                diagnostics.append(
                    QStringLiteral("the evidence cache supplied the tier-4 candidate"));
            } else if (!cacheWhy.isEmpty()) {
                diagnostics.append(QStringLiteral("cache: %1").arg(cacheWhy));
            }
        }

        QString why;
        if (buildCacheDecision(candidate, input, signature, now, &cacheDecision, &why)) {
            hasCache = true;
        } else if (!why.isEmpty()) {
            diagnostics.append(why);
        }
    }

    const PolicyDecision fallback = enforcing
                                        ? buildFallbackDecision(input, signature, now)
                                        : PolicyDecision();

    QList<LowerTierVote> votes;
    if (hasProfile) {
        LowerTierVote vote;
        vote.tier = 3;
        vote.action = profileDecision.action;
        vote.continueAfterNotify = profileDecision.continueAfterNotify;
        vote.source = QStringLiteral("profile");
        vote.ruleId = signature.profileRuleId;
        votes.append(vote);
    }
    if (hasCache) {
        LowerTierVote vote;
        vote.tier = 4;
        vote.action = cacheDecision.action;
        vote.continueAfterNotify = cacheDecision.continueAfterNotify;
        vote.source = QStringLiteral("cache");
        votes.append(vote);
    }
    if (enforcing) {
        LowerTierVote vote;
        vote.tier = 5;
        vote.action = fallback.action;
        vote.continueAfterNotify = fallback.continueAfterNotify;
        vote.source = QStringLiteral("fallback");
        votes.append(vote);
    }

    const RuleResolution rules = RuleResolver::resolve(
        observation, input.pinnedRules, input.sessionOverrides, now, votes);

    if (rules.matched) {
        resolution.automationSuppressed = !enforcing;
        PolicyDecision decision = buildRuleDecision(
            rules.winner, observation, signature, enforcing, now, &diagnostics);
        decision.conflict = toDecisionConflict(rules.conflict);
        QString error;
        if (!decision.validate(&error)) {
            resolution.diagnostic =
                QStringLiteral("the winning user rule produced an invalid decision: %1").arg(error);
            return resolution;
        }
        resolution.evaluated = true;
        resolution.decision = decision;
        resolution.matchedRuleId = rules.winner.ruleId;
        resolution.diagnostic = diagnostics.join(QStringLiteral("; "));
        return resolution;
    }

    if (!enforcing) {
        resolution.automationSuppressed = true;
        resolution.diagnostic = QStringLiteral(
            "Data Saver is off; automatic tiers were not evaluated.");
        return resolution;
    }

    PolicyDecision winner;
    if (hasProfile)
        winner = profileDecision;
    else if (hasCache)
        winner = cacheDecision;
    else
        winner = fallback;

    // A lower automatic tier that disagrees is reported, never applied.
    auto noteConflict = [&](int tier, const PolicyDecision &other,
                            const QString &source) {
        if (winner.conflict.hasConflict && winner.conflict.conflictingTier <= tier)
            return;
        winner.conflict.hasConflict = true;
        winner.conflict.conflictingTier = tier;
        winner.conflict.resolution = QStringLiteral("higher_tier_won");
        winner.conflict.detail =
            QStringLiteral("tier %1 (%2) disagrees with %3")
                .arg(tier)
                .arg(source, decisionOriginToken(winner.origin));
    };

    if (hasProfile) {
        if (hasCache && !sameOpinion(winner, cacheDecision))
            noteConflict(4, cacheDecision, QStringLiteral("cache"));
        if (!sameOpinion(winner, fallback))
            noteConflict(5, fallback, QStringLiteral("fallback"));
    } else if (hasCache && !sameOpinion(winner, fallback)) {
        noteConflict(5, fallback, QStringLiteral("fallback"));
    }

    QString error;
    if (!winner.validate(&error)) {
        // Fail closed: replace an invalid automatic decision with a notice.
        PolicyDecision safe;
        safe.decisionId = mintDecisionId();
        safe.observationId = observation.observationId;
        safe.createdAt = now;
        safe.origin = DecisionOrigin::Fallback;
        safe.tier = decisionOriginTier(DecisionOrigin::Fallback);
        safe.action = Action::Notify;
        safe.continueAfterNotify = true;
        safe.scope = DecisionScope::Executable;
        safe.target = buildTarget(observation);
        safe.confidence = signature.confidence > 0.0 ? signature.confidence : 0.30;
        safe.classification = signature.classification;
        safe.evidence = buildEvidence(observation, QStringLiteral("invalid_decision_fallback"));
        safe.reasonShort = QStringLiteral(
            "The resolved decision failed local validation; traffic continues with a notice.");
        safe.nextSteps << QStringLiteral("Review the Data Saver rules for an invalid entry.");
        winner = safe;
        diagnostics.append(QStringLiteral("the resolved decision was rejected: %1").arg(error));
    }

    // DS-007: only a fresh local profile decision is evidence worth reusing.
    // A cache hit is already stored, and user or fallback outcomes are not
    // cached. Hard blocks never enter the cache, so a hit can never block.
    if (input.cache && winner.origin == DecisionOrigin::Profile
        && winner.action != NetworkPolicy::Action::Block) {
        QString cacheError;
        if (input.cache->insert(observation, cacheContext, winner, QString(), now, &cacheError)) {
            diagnostics.append(QStringLiteral("the decision was stored in the evidence cache"));
        } else {
            diagnostics.append(QStringLiteral("the decision was not cached: %1").arg(cacheError));
        }
    }

    if (winner.origin == DecisionOrigin::Profile)
        resolution.matchedRuleId = signature.profileRuleId;
    if (winner.origin == DecisionOrigin::Cache && cacheStoreHit) {
        resolution.matchedCacheKey = DataSaverCache::fingerprintFor(
            DataSaverCache::buildCacheKey(observation, cacheContext));
    }

    resolution.evaluated = true;
    resolution.decision = winner;
    resolution.diagnostic = diagnostics.join(QStringLiteral("; "));
    return resolution;
}
