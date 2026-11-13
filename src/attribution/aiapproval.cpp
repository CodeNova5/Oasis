/**
 * @file    aiapproval.cpp
 * @brief   AI approval flow (NG-046).
 * @author  Oasis
 */
#include "aiapproval.h"

#include <QUuid>

namespace {

QString normalizedScope(const QString &scope)
{
    const QString key = scope.trimmed().toLower();
    if (key == QLatin1String("executable")) return QStringLiteral("path");
    return key;
}

bool scopeIsApprovable(const QString &scope)
{
    const QString key = normalizedScope(scope);
    return key == QLatin1String("path") || key == QLatin1String("group")
        || key == QLatin1String("service") || key == QLatin1String("publisher")
        || key == QLatin1String("pid");
}

bool isEnforceableAction(NetworkPolicy::Action action)
{
    return action == NetworkPolicy::Action::Throttle
        || action == NetworkPolicy::Action::Block
        || action == NetworkPolicy::Action::Schedule;
}

} // namespace

// ─── Duration ──────────────────────────────────────────────────────────────

QString aiApprovalDurationToken(AiApprovalDuration duration)
{
    switch (duration) {
    case AiApprovalDuration::OneHour:  return QStringLiteral("1h");
    case AiApprovalDuration::OneDay:   return QStringLiteral("1d");
    case AiApprovalDuration::OneWeek:  return QStringLiteral("1w");
    case AiApprovalDuration::UntilRemoved: return QStringLiteral("until-removed");
    }
    return QStringLiteral("until-removed");
}

QString aiApprovalDurationDisplayName(AiApprovalDuration duration)
{
    switch (duration) {
    case AiApprovalDuration::OneHour:
        return QStringLiteral("One hour");
    case AiApprovalDuration::OneDay:
        return QStringLiteral("One day");
    case AiApprovalDuration::OneWeek:
        return QStringLiteral("One week");
    case AiApprovalDuration::UntilRemoved:
        return QStringLiteral("Until I remove it");
    }
    return QString();
}

qint64 aiApprovalDurationSeconds(AiApprovalDuration duration)
{
    switch (duration) {
    case AiApprovalDuration::OneHour:  return 60 * 60;
    case AiApprovalDuration::OneDay:   return 24 * 60 * 60;
    case AiApprovalDuration::OneWeek:  return 7 * 24 * 60 * 60;
    case AiApprovalDuration::UntilRemoved: return 0;
    }
    return 0;
}

QDateTime aiApprovalExpiration(AiApprovalDuration duration, const QDateTime &nowUtc)
{
    const qint64 seconds = aiApprovalDurationSeconds(duration);
    if (seconds <= 0) return QDateTime();
    return nowUtc.addSecs(seconds);
}

QList<AiApprovalDuration> aiApprovalDurations()
{
    return {AiApprovalDuration::OneHour, AiApprovalDuration::OneDay,
            AiApprovalDuration::OneWeek, AiApprovalDuration::UntilRemoved};
}

// ─── Scope ─────────────────────────────────────────────────────────────────

QString aiApprovalScopeDisplayName(const QString &scope)
{
    const QString key = normalizedScope(scope);
    if (key == QLatin1String("pid"))       return QStringLiteral("This process only (PID)");
    if (key == QLatin1String("path"))      return QStringLiteral("This executable path");
    if (key == QLatin1String("publisher")) return QStringLiteral("This publisher");
    if (key == QLatin1String("service"))   return QStringLiteral("This Windows service");
    if (key == QLatin1String("group"))     return QStringLiteral("This application group");
    return QStringLiteral("Unknown scope");
}

QList<AiApprovalScopeOption> aiApprovalScopeOptions(const RecommendationContext &context,
                                                    const Recommendation &recommendation)
{
    QList<AiApprovalScopeOption> options;

    auto labelFor = [&context](const QString &scope, const QString &targetId) {
        for (const ActivityPolicyTarget &target : context.activity.manualPolicyTargets) {
            if (normalizedScope(target.scope) == normalizedScope(scope)
                && target.targetId.compare(targetId, Qt::CaseInsensitive) == 0
                && !target.label.trimmed().isEmpty()) {
                return target.label.trimmed();
            }
        }
        return QStringLiteral("%1 — %2").arg(aiApprovalScopeDisplayName(scope), targetId);
    };

    auto add = [&options, &labelFor](const QString &scope, const QString &targetId) {
        const QString key = normalizedScope(scope);
        const QString target = targetId.trimmed();
        if (!scopeIsApprovable(key) || target.isEmpty()) return;
        for (const AiApprovalScopeOption &existing : options) {
            if (normalizedScope(existing.scope) == key
                && existing.targetId.compare(target, Qt::CaseInsensitive) == 0) {
                return;
            }
        }
        AiApprovalScopeOption option;
        option.scope = key;
        option.targetId = target;
        option.label = labelFor(key, target);
        options.append(option);
    };

    // The recommendation's own target comes first, because it is the narrowest
    // scope the deterministic engine could justify for this activity.
    if (recommendation.hasSuggestedPolicy())
        add(recommendation.suggestedPolicy.scope, recommendation.suggestedPolicy.targetId);

    for (const ActivityPolicyTarget &target : context.activity.manualPolicyTargets)
        add(target.scope, target.targetId);

    return options;
}

AiApprovalDuration aiApprovalDefaultDuration(const Recommendation &recommendation,
                                             const QDateTime &nowUtc)
{
    const QDateTime expiration = recommendation.suggestedPolicy.expiration;
    if (!expiration.isValid()) return AiApprovalDuration::UntilRemoved;

    const qint64 remaining = nowUtc.secsTo(expiration.toUTC());
    if (remaining <= aiApprovalDurationSeconds(AiApprovalDuration::OneHour))
        return AiApprovalDuration::OneHour;
    if (remaining <= aiApprovalDurationSeconds(AiApprovalDuration::OneDay))
        return AiApprovalDuration::OneDay;
    return AiApprovalDuration::OneWeek;
}

// ─── Choice and approval ───────────────────────────────────────────────────

QStringList aiApprovalProblems(const Recommendation &recommendation,
                               const AiApprovalChoices &choices,
                               const QDateTime &nowUtc)
{
    QStringList problems;

    if (!recommendation.hasSuggestedPolicy()) {
        problems << QStringLiteral(
            "This recommendation does not propose a policy, so there is nothing to approve.");
    } else if (!isEnforceableAction(recommendation.suggestedPolicy.action)) {
        problems << QStringLiteral(
            "The suggested action is advisory only; it cannot be approved as a policy.");
    }

    if (choices.scope.trimmed().isEmpty())
        problems << QStringLiteral("Choose what the policy covers.");
    else if (!scopeIsApprovable(choices.scope))
        problems << QStringLiteral("The selected scope is not one this build can store.");
    else if (choices.targetId.trimmed().isEmpty())
        problems << QStringLiteral("The selected scope has no target.");

    if (recommendation.suggestedPolicy.action == NetworkPolicy::Action::Throttle
        && recommendation.suggestedPolicy.rateBitsPerSecond == 0) {
        problems << QStringLiteral("A throttle policy needs a rate above zero.");
    }

    if (recommendation.suggestedPolicy.action == NetworkPolicy::Action::Block
        && aiApprovalExpiration(choices.duration, nowUtc).isValid()
        && aiApprovalExpiration(choices.duration, nowUtc) <= nowUtc) {
        problems << QStringLiteral("The chosen duration has already expired.");
    }

    return problems;
}

NetworkPolicy aiApprovalBuildPolicy(const Recommendation &recommendation,
                                    const AiApprovalChoices &choices,
                                    const QDateTime &nowUtc)
{
    NetworkPolicy policy = recommendation.suggestedPolicy;

    policy.id = QStringLiteral("policy-")
        + QUuid::createUuid().toString(QUuid::WithoutBraces);
    policy.scope = normalizedScope(choices.scope);
    policy.targetId = choices.targetId.trimmed();
    policy.enabled = true;

    // Approval never changes what the deterministic recommendation decided. The
    // provider's text can only be noted; an explanation cannot alter the action,
    // direction, rate, or recurring window.
    policy.source = QStringLiteral("user");

    QString note = policy.description.trimmed();
    if (note.isEmpty())
        note = QStringLiteral("Approved from recommendation: %1")
                   .arg(recommendation.title.trimmed().isEmpty()
                            ? QStringLiteral("data saver suggestion")
                            : recommendation.title.trimmed());
    if (choices.explanationReviewed)
        note += QStringLiteral(" (AI explanation reviewed; the policy itself is local)");
    note += QStringLiteral(" Approved %1, duration: %2.")
                .arg(nowUtc.toLocalTime().toString(Qt::ISODate),
                     aiApprovalDurationDisplayName(choices.duration).toLower());
    policy.description = note;

    const QDateTime expiration = aiApprovalExpiration(choices.duration, nowUtc);
    policy.expiration = expiration;
    if (expiration.isValid()) {
        policy.scheduleType = policy.schedule.trimmed().isEmpty()
            ? NetworkPolicy::ScheduleType::Expiration
            : NetworkPolicy::ScheduleType::Both;
    } else {
        policy.scheduleType = policy.schedule.trimmed().isEmpty()
            ? NetworkPolicy::ScheduleType::None
            : NetworkPolicy::ScheduleType::Recurring;
    }

    return policy;
}

bool aiApprovalApprove(const NetworkPolicy &policy)
{
    if (policy.id.trimmed().isEmpty() || policy.scope.trimmed().isEmpty()
        || policy.targetId.trimmed().isEmpty()) {
        return false;
    }

    QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    bool replaced = false;
    for (NetworkPolicy &existing : policies) {
        if (existing.id != policy.id) continue;
        existing = policy;
        replaced = true;
        break;
    }
    if (!replaced) policies.append(policy);
    return PolicyStore::savePolicies(policies);
}
