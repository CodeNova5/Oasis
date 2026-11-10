/**
 * @file    recommendationengine.cpp
 * @author  Ali Sakkaf
 */
#include "recommendationengine.h"

#include <QDateTime>
#include <QFileInfo>

namespace {

QString rateText(quint64 bytesPerSecond)
{
    const double kib = static_cast<double>(bytesPerSecond) / 1024.0;
    if (kib >= 1024.0)
        return QStringLiteral("%1 MiB/s").arg(kib / 1024.0, 0, 'f', 1);
    return QStringLiteral("%1 KiB/s").arg(kib, 0, 'f', 0);
}

QString subjectOf(const ActivityQuery &query)
{
    if (!query.executableName.trimmed().isEmpty())
        return query.executableName.trimmed();
    if (!query.executablePath.trimmed().isEmpty())
        return QFileInfo(query.executablePath).fileName();
    if (!query.displayName.trimmed().isEmpty())
        return query.displayName.trimmed();
    if (!query.serviceName.trimmed().isEmpty())
        return QStringLiteral("service %1").arg(query.serviceName.trimmed());
    return QStringLiteral("This application");
}

QString titleFor(CatalogCategory category, RecommendationAction action)
{
    switch (action) {
    case RecommendationAction::Throttle:
        switch (category) {
        case CatalogCategory::WindowsUpdate:      return QStringLiteral("Limit Windows Update traffic");
        case CatalogCategory::BackgroundTransfer: return QStringLiteral("Limit background transfers");
        case CatalogCategory::BrowserUpdate:      return QStringLiteral("Limit browser updater traffic");
        case CatalogCategory::PackageManager:     return QStringLiteral("Limit package-download traffic");
        default:                                  return QStringLiteral("Limit this app's bandwidth");
        }
    case RecommendationAction::Pause:
        return QStringLiteral("Pause this traffic temporarily");
    case RecommendationAction::Schedule:
        return QStringLiteral("Defer cloud sync to overnight");
    case RecommendationAction::ReviewSettings:
        return category == CatalogCategory::Unknown
            ? QStringLiteral("Review this unclassified activity")
            : QStringLiteral("Review this activity's settings");
    case RecommendationAction::NoAction:
        break;
    }
    return QStringLiteral("No action recommended");
}

QString expectedEffectFor(RecommendationAction action, quint64 rateBitsPerSecond)
{
    switch (action) {
    case RecommendationAction::Throttle:
        return QStringLiteral("Caps this app at %1; other applications and the foreground "
                              "session are unaffected.")
            .arg(rateText(rateBitsPerSecond / 8));
    case RecommendationAction::Pause:
        return QStringLiteral("Blocks this app's transfers for one hour, then restores them "
                              "automatically. The process keeps running.");
    case RecommendationAction::Schedule:
        return QStringLiteral("Moves this app's transfers to the overnight window "
                              "(22:00-06:00) so they do not compete with daytime work.");
    case RecommendationAction::ReviewSettings:
        return QStringLiteral("Nothing is limited or blocked. You look at the app and decide "
                              "whether to limit, allow, or leave it alone.");
    case RecommendationAction::NoAction:
        break;
    }
    return QStringLiteral("No change: nothing is limited or blocked.");
}

QString reversalFor(RecommendationAction action)
{
    switch (action) {
    case RecommendationAction::Throttle:
        return QStringLiteral("Remove the bandwidth limit from Policies > Limits..., or delete "
                              "the policy that carries it.");
    case RecommendationAction::Pause:
        return QStringLiteral("Delete the policy early from Policies... to resume immediately; "
                              "otherwise it expires on its own after one hour.");
    case RecommendationAction::Schedule:
        return QStringLiteral("Delete the policy, or change its window to always, in "
                              "Policies....");
    case RecommendationAction::ReviewSettings:
        return QStringLiteral("Nothing to reverse: no policy is applied.");
    case RecommendationAction::NoAction:
        break;
    }
    return QStringLiteral("Nothing to reverse: no policy is applied.");
}

} // namespace

QString recommendationActionToken(RecommendationAction action)
{
    switch (action) {
    case RecommendationAction::Throttle:       return QStringLiteral("throttle");
    case RecommendationAction::Pause:          return QStringLiteral("pause");
    case RecommendationAction::Schedule:       return QStringLiteral("schedule");
    case RecommendationAction::ReviewSettings: return QStringLiteral("review-settings");
    case RecommendationAction::NoAction:       break;
    }
    return QStringLiteral("no-action");
}

QString recommendationActionDisplayName(RecommendationAction action)
{
    switch (action) {
    case RecommendationAction::Throttle:       return QStringLiteral("Throttle");
    case RecommendationAction::Pause:          return QStringLiteral("Pause");
    case RecommendationAction::Schedule:       return QStringLiteral("Schedule");
    case RecommendationAction::ReviewSettings: return QStringLiteral("Review settings");
    case RecommendationAction::NoAction:       break;
    }
    return QStringLiteral("No action");
}

bool Recommendation::hasSuggestedPolicy() const
{
    return !suggestedPolicy.scope.trimmed().isEmpty() &&
           !suggestedPolicy.targetId.trimmed().isEmpty();
}

QString Recommendation::confidenceName() const
{
    return AttributionConfidenceModel::displayName(assessment.confidence);
}

QStringList Recommendation::lines() const
{
    QStringList lines;
    lines << QStringLiteral("%1 (%2, %3)")
                 .arg(title, recommendationActionDisplayName(action), confidenceName());
    if (!whatObserved.trimmed().isEmpty())
        lines << QStringLiteral("Observed: %1").arg(whatObserved);
    if (!whyLikely.trimmed().isEmpty())
        lines << QStringLiteral("Why: %1").arg(whyLikely);
    if (!expectedEffect.trimmed().isEmpty())
        lines << QStringLiteral("Expected effect: %1").arg(expectedEffect);
    if (!reversalAction.trimmed().isEmpty())
        lines << QStringLiteral("To reverse: %1").arg(reversalAction);
    for (const QString &item : evidence)
        lines << QStringLiteral("Evidence: %1").arg(item);
    return lines;
}

RecommendationAction RecommendationEngine::recommendedActionFor(CatalogCategory category)
{
    switch (category) {
    case CatalogCategory::WindowsUpdate:
    case CatalogCategory::BackgroundTransfer:
    case CatalogCategory::BrowserUpdate:
    case CatalogCategory::PackageManager:
        return RecommendationAction::Throttle;
    case CatalogCategory::CloudSync:
        return RecommendationAction::Schedule;
    case CatalogCategory::GameLauncher:
        return RecommendationAction::Pause;
    case CatalogCategory::DeveloperTool:
        return RecommendationAction::ReviewSettings;
    case CatalogCategory::ForegroundDownload:
        return RecommendationAction::NoAction;
    case CatalogCategory::Unknown:
        break;
    }
    return RecommendationAction::ReviewSettings;
}

quint64 RecommendationEngine::suggestedRateBitsPerSecond(quint64 observedBytesPerSecond)
{
    constexpr quint64 kMinBytes = 256ULL * 1024ULL;
    constexpr quint64 kMaxBytes = 4ULL * 1024ULL * 1024ULL;
    constexpr quint64 kDefaultBytes = 1024ULL * 1024ULL;

    quint64 bytes = observedBytesPerSecond == 0
        ? kDefaultBytes
        : observedBytesPerSecond / 2;
    if (bytes < kMinBytes) bytes = kMinBytes;
    if (bytes > kMaxBytes) bytes = kMaxBytes;
    return bytes * 8ULL;
}

Recommendation RecommendationEngine::recommend(const RecommendationContext &context) const
{
    Recommendation result;
    result.category = context.activity.category;
    result.assessment = context.activity.assessment;
    result.evidence = context.activity.evidence;

    const ActivityQuery &query = context.observation;
    const QString subject = subjectOf(query);
    const QString rate = context.bytesPerSecond > 0
        ? rateText(context.bytesPerSecond)
        : QString();

    QString observed = subject;
    if (!query.publisher.trimmed().isEmpty())
        observed += QStringLiteral(" (signed by %1)").arg(query.publisher.trimmed());
    if (!rate.isEmpty())
        observed += QStringLiteral(" is transferring %1").arg(rate);
    else if (!query.serviceName.trimmed().isEmpty())
        observed += QStringLiteral(" is a Windows service");
    if (!query.groupName.trimmed().isEmpty())
        observed += QStringLiteral(" in activity group \"%1\"").arg(query.groupName.trimmed());
    if (!query.domain.trimmed().isEmpty())
        observed += QStringLiteral(" while contacting %1").arg(query.domain.trimmed());
    observed += QLatin1Char('.');
    result.whatObserved = observed;

    // An explicit decision always wins. The recommendation still carries the
    // evidence, so the user can see why nothing was suggested.
    if (context.exempt) {
        result.action = RecommendationAction::NoAction;
        result.title = QStringLiteral("This app is exempt");
        result.whyLikely = QStringLiteral("You exempted this app from Data Saver limits.");
        result.expectedEffect = QStringLiteral("No change: the exemption is left in place.");
        result.reversalAction = QStringLiteral("Nothing to reverse: no policy is applied.");
        return result;
    }
    if (context.explicitPolicyCovers) {
        result.action = RecommendationAction::NoAction;
        result.title = QStringLiteral("Already covered by your policy");
        result.whyLikely = QStringLiteral("An explicit user policy already applies to this app; "
                                          "recommendations never override it.");
        result.expectedEffect = QStringLiteral("No change: your policy stays in force.");
        result.reversalAction = QStringLiteral("Nothing to reverse: no new policy is applied.");
        return result;
    }

    RecommendationAction action = recommendedActionFor(context.activity.category);

    // A foreground transfer may be intentional, so it is never throttled or
    // paused behind the user's back; the suggestion becomes a review instead.
    if (context.foreground &&
        (action == RecommendationAction::Throttle ||
         action == RecommendationAction::Pause)) {
        action = RecommendationAction::ReviewSettings;
    }
    // A metered connection makes an otherwise harmless foreground transfer worth
    // a look, but still without changing anything.
    if (context.meteredConnection &&
        action == RecommendationAction::NoAction &&
        context.activity.category == CatalogCategory::ForegroundDownload) {
        action = RecommendationAction::ReviewSettings;
    }

    result.action = action;
    result.title = titleFor(context.activity.category, action);

    if (!context.activity.matchedRules.isEmpty()) {
        const CatalogMatch &rule = context.activity.matchedRules.first();
        result.whyLikely = QStringLiteral("Local rule \"%1\": %2")
                               .arg(rule.ruleId,
                                    rule.explanation.trimmed().isEmpty()
                                        ? context.activity.categoryName()
                                        : rule.explanation.trimmed());
    } else if (context.activity.category == CatalogCategory::ForegroundDownload) {
        result.whyLikely = QStringLiteral("It is the foreground application and is transferring "
                                          "above the sustained-download threshold, which is an "
                                          "inference rather than an observed category.");
    } else if (context.activity.category == CatalogCategory::Unknown) {
        result.whyLikely = QStringLiteral("No local rule matched it, so its purpose is unknown; "
                                          "the evidence stays visible instead of guessing.");
    }

    if (context.meteredConnection)
        result.whyLikely += QStringLiteral(" The connection is metered, so its cost matters.");

    quint64 rateBits = 0;
    if (action == RecommendationAction::Throttle)
        rateBits = suggestedRateBitsPerSecond(context.bytesPerSecond);

    result.expectedEffect = expectedEffectFor(action, rateBits);
    result.reversalAction = reversalFor(action);

    if (action == RecommendationAction::Throttle ||
        action == RecommendationAction::Pause ||
        action == RecommendationAction::Schedule) {
        const ActivityPolicyTarget target = context.activity.preferredPolicyTarget();
        if (!target.targetId.trimmed().isEmpty()) {
            NetworkPolicy policy;
            policy.scope = target.scope;
            policy.targetId = target.targetId;
            policy.direction = NetworkDirection::Both;
            policy.source = QStringLiteral("user");
            policy.enabled = true;
            policy.description = QStringLiteral("Recommended: %1").arg(result.title);

            switch (action) {
            case RecommendationAction::Throttle:
                policy.action = NetworkPolicy::Action::Throttle;
                policy.rateBitsPerSecond = rateBits;
                break;
            case RecommendationAction::Pause:
                policy.action = NetworkPolicy::Action::Block;
                policy.scheduleType = NetworkPolicy::ScheduleType::Expiration;
                policy.expiration = QDateTime::currentDateTimeUtc().addSecs(3600);
                break;
            case RecommendationAction::Schedule:
                policy.action = NetworkPolicy::Action::Schedule;
                policy.scheduleType = NetworkPolicy::ScheduleType::Recurring;
                policy.schedule = QStringLiteral("overnight");
                break;
            default:
                break;
            }
            result.suggestedPolicy = policy;
        }
    }

    return result;
}
