/**
 * @file    datasavernotification.cpp
 * @brief   Deduplicated, actionable Data Saver notices (DS-011).
 * @author  Oasis
 */
#include "datasavernotification.h"

#include <QFileInfo>
#include <QStringList>

namespace {

const QString kAllowOnceToken = QStringLiteral("allow_once");
const QString kAlwaysAllowToken = QStringLiteral("always_allow");
const QString kInspectToken = QStringLiteral("inspect");

QString bounded(const QString &text, int maximum)
{
    if (maximum <= 0) return QString();
    const QString value = text.simplified();
    if (value.size() <= maximum) return value;
    return value.left(maximum - 1) + QChar(0x2026);
}

/// Length-bounded but line-preserving: the notice body is a list of lines and
/// must not be flattened into one paragraph.
QString boundedBlock(const QString &text, int maximum)
{
    if (maximum <= 0) return QString();
    const QString value = text.trimmed();
    if (value.size() <= maximum) return value;
    return value.left(maximum - 1) + QChar(0x2026);
}

QString actionToken(NetworkPolicy::Action action)
{
    switch (action) {
    case NetworkPolicy::Action::Allow:    return QStringLiteral("allow");
    case NetworkPolicy::Action::Notify:   return QStringLiteral("notify");
    case NetworkPolicy::Action::Throttle: return QStringLiteral("throttle");
    case NetworkPolicy::Action::Block:    return QStringLiteral("block");
    case NetworkPolicy::Action::Ask:
    case NetworkPolicy::Action::Schedule:
    case NetworkPolicy::Action::NoAction:
        break;
    }
    return QStringLiteral("none");
}

QString directionToken(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("download");
    case NetworkDirection::Upload:   return QStringLiteral("upload");
    case NetworkDirection::Both:     return QStringLiteral("download and upload");
    }
    return QStringLiteral("download");
}

QString statusToken(EnforcementResult::Status status)
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

/// Base name only; a caller-supplied path never reaches the notice.
QString baseName(const QString &value)
{
    QString cleaned = value.trimmed();
    while (cleaned.endsWith(QLatin1Char('/')) || cleaned.endsWith(QLatin1Char(92)))
        cleaned.chop(1);
    if (cleaned.isEmpty()) return QString();
    const QString name = QFileInfo(cleaned).fileName();
    if (name.isEmpty() || name == QLatin1String(".") || name == QLatin1String(".."))
        return QString();
    return name;
}

QString executableFor(const DataSaverNotifications::DecisionNotice &notice)
{
    QString name = baseName(notice.executableName);
    if (name.isEmpty()) name = baseName(notice.decision.target.executable);
    if (name.isEmpty()) name = baseName(notice.observation.process.exeName);
    return bounded(name, 96);
}

/// The attributed domain, already reduced to a canonical form.
QString domainFor(const DataSaverNotifications::DecisionNotice &notice)
{
    QString domain = notice.decision.evidence.domain;
    if (domain.trimmed().isEmpty()) domain = notice.observation.flow.domain;
    return normalizeFlowDomain(domain);
}

QString volumeText(quint64 bytes)
{
    const double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
    const int precision = mib >= 10.0 ? 0 : 1;
    return QStringLiteral("%1 MiB").arg(mib, 0, 'f', precision);
}

QString rateText(quint64 bitsPerSecond)
{
    const quint64 kibPerSecond = bitsPerSecond / 8 / 1024;
    return QStringLiteral("%1 bits/s (%2 KiB/s)")
        .arg(bitsPerSecond)
        .arg(kibPerSecond);
}

/// Status-aware verbs. A requested control is never described as applied.
QString titleFor(const DataSaverNotifications::DecisionNotice &notice,
                 const QString &application)
{
    const QString app = application.isEmpty() ? QStringLiteral("an application")
                                               : application;
    if (notice.decision.action == NetworkPolicy::Action::Notify)
        return QStringLiteral("Data Saver notice: %1").arg(app);

    const bool blocking = notice.decision.action == NetworkPolicy::Action::Block;
    const QString verb = blocking ? QStringLiteral("block") : QStringLiteral("limit");
    const QString past = blocking ? QStringLiteral("blocked") : QStringLiteral("limited");
    switch (notice.status) {
    case EnforcementResult::Status::Applied:
        return QStringLiteral("Data Saver %1 %2").arg(past, app);
    case EnforcementResult::Status::Requested:
        return QStringLiteral("Data Saver requested a %1 for %2").arg(verb, app);
    case EnforcementResult::Status::Partial:
        return QStringLiteral("Data Saver partially %1 %2").arg(past, app);
    case EnforcementResult::Status::Failed:
    case EnforcementResult::Status::NotApplied:
        break;
    }
    return QStringLiteral("Data Saver could not %1 %2").arg(verb, app);
}

/// Domain naming uses the decision evidence first; the observation's own
/// confidence is the fallback when a caller built the decision without it.
bool noticeCanNameDomain(const DataSaverNotifications::DecisionNotice &notice)
{
    if (DataSaverNotifications::canNameDomain(notice.decision)) return true;
    if (!notice.decision.evidence.domainConfidence.trimmed().isEmpty()) return false;
    return notice.observation.flow.domainConfidence == FlowDomainConfidence::Confirmed
           || notice.observation.flow.domainConfidence == FlowDomainConfidence::StrongInference;
}

QString changeText(const DataSaverNotifications::DecisionNotice &notice)
{
    const PolicyDecision &decision = notice.decision;
    switch (decision.action) {
    case NetworkPolicy::Action::Throttle:
        return QStringLiteral("throttle %1 at %2")
            .arg(directionToken(decision.direction), rateText(decision.rateBitsPerSecond));
    case NetworkPolicy::Action::Block:
        return QStringLiteral("block %1").arg(directionToken(decision.direction));
    case NetworkPolicy::Action::Notify:
        return decision.continueAfterNotify ? QStringLiteral("advisory notice; traffic continues")
                                            : QStringLiteral("advisory notice");
    case NetworkPolicy::Action::Allow:
        return QStringLiteral("allow");
    case NetworkPolicy::Action::Ask:
    case NetworkPolicy::Action::Schedule:
    case NetworkPolicy::Action::NoAction:
        break;
    }
    return QStringLiteral("no change");
}

QString messageFor(const DataSaverNotifications::DecisionNotice &notice)
{
    const PolicyDecision &decision = notice.decision;
    QStringList lines;

    const QString application = executableFor(notice);
    if (!application.isEmpty())
        lines << QStringLiteral("Application: %1").arg(application);

    const QString domain = domainFor(notice);
    if (!domain.isEmpty() && noticeCanNameDomain(notice))
        lines << QStringLiteral("Domain: %1").arg(domain);

    const quint64 milestoneBytes = notice.observation.metrics.milestoneBytes != 0
                                       ? notice.observation.metrics.milestoneBytes
                                       : decision.evidence.milestoneBytes;
    const int milestoneIndex = notice.observation.metrics.milestoneIndex != 0
                                   ? notice.observation.metrics.milestoneIndex
                                   : decision.evidence.milestoneIndex;
    lines << QStringLiteral("Milestone: %1 (index %2)")
                 .arg(volumeText(milestoneBytes))
                 .arg(milestoneIndex);

    lines << QStringLiteral("Change: %1").arg(changeText(notice));
    const QString reason = bounded(decision.reasonShort,
                                   DataSaverNotifications::kMaxReasonChars);
    if (!reason.isEmpty())
        lines << QStringLiteral("Reason: %1").arg(reason);

    QString enforcement = QStringLiteral("Enforcement: %1").arg(statusToken(notice.status));
    if (!notice.enforcementChannels.trimmed().isEmpty())
        enforcement += QStringLiteral("; channels: %1")
                           .arg(bounded(notice.enforcementChannels, 96));
    lines << enforcement;
    if (!notice.enforcementMessage.trimmed().isEmpty())
        lines << QStringLiteral("Enforcement detail: %1")
                     .arg(bounded(notice.enforcementMessage, 200));

    if (!decision.nextSteps.isEmpty()) {
        const QString step = bounded(decision.nextSteps.first(),
                                     DataSaverNotifications::kMaxNextStepChars);
        if (!step.isEmpty())
            lines << QStringLiteral("Next step: %1").arg(step);
    }

    lines << QStringLiteral("Details: decision %1, observation %2")
                 .arg(bounded(decision.decisionId, 64),
                      bounded(decision.observationId.isEmpty()
                                  ? notice.observation.observationId
                                  : decision.observationId,
                              64));
    lines << QStringLiteral("Actions: Allow once (expires in %1 minutes); "
                            "Always allow (asks for confirmation); Inspect application")
                 .arg(DataSaverNotifications::kAllowOnceTtlSeconds / 60);

    return boundedBlock(lines.join(QLatin1Char('\n')),
                        DataSaverNotifications::kMaxMessageChars);
}

} // namespace

namespace DataSaverNotifications {

QString allowOnceActionToken() { return kAllowOnceToken; }
QString alwaysAllowActionToken() { return kAlwaysAllowToken; }
QString inspectActionToken() { return kInspectToken; }

bool shouldNotify(const PolicyDecision &decision)
{
    return decision.action == NetworkPolicy::Action::Throttle
           || decision.action == NetworkPolicy::Action::Block
           || decision.action == NetworkPolicy::Action::Notify;
}

QString notificationKey(const FlowObservation &observation,
                        const PolicyDecision &decision)
{
    const QString executable = RuleResolver::normalizeExecutable(
        observation.process.exeName.isEmpty() ? decision.target.executable
                                              : observation.process.exeName);
    QString subject = normalizeFlowDomain(
        observation.flow.domain.isEmpty() ? decision.evidence.domain
                                          : observation.flow.domain);
    if (subject.isEmpty())
        subject = bounded(observation.flow.flowId, 64);
    if (subject.isEmpty())
        subject = QStringLiteral("unknown");
    const int milestone = observation.metrics.milestoneIndex != 0
                              ? observation.metrics.milestoneIndex
                              : decision.evidence.milestoneIndex;
    return QStringLiteral("datasaver:%1:%2:%3:%4")
        .arg(actionToken(decision.action),
             executable.isEmpty() ? QStringLiteral("unknown") : executable,
             subject)
        .arg(milestone);
}

bool canNameDomain(const PolicyDecision &decision)
{
    const QString token = decision.evidence.domainConfidence.trimmed().toLower();
    return token == QStringLiteral("confirmed")
           || token == QStringLiteral("strong_inference");
}

AppNotification forDecision(const DecisionNotice &notice)
{
    AppNotification notification;
    notification.key = notificationKey(notice.observation, notice.decision);
    const QString application = executableFor(notice);
    notification.title = bounded(titleFor(notice, application), kMaxTitleChars);
    notification.message = messageFor(notice);
    notification.priority = notice.status == EnforcementResult::Status::Failed
                                ? NotificationPriority::Critical
                                : (notice.decision.action == NetworkPolicy::Action::Throttle
                                           || notice.decision.action == NetworkPolicy::Action::Block
                                       ? NotificationPriority::Warning
                                       : NotificationPriority::Info);
    notification.route = NotificationRoute::TrayAndApp;
    notification.identityId = notice.decision.target.identityId.isEmpty()
                                  ? notice.observation.process.identityId
                                  : notice.decision.target.identityId;
    notification.policyId = notice.enforcementPolicyId.isEmpty()
                                ? notice.decision.decisionId
                                : notice.enforcementPolicyId;
    notification.actions = QStringList() << allowOnceActionToken()
                                         << alwaysAllowActionToken()
                                         << inspectActionToken();
    return notification;
}

bool allowOnce(const FlowObservation &observation, const PolicyDecision &decision,
               SessionOverrideStore *store, const QDateTime &now,
               SessionOverride *created, QString *error)
{
    if (!store) {
        if (error) *error = QStringLiteral("no session override store");
        return false;
    }

    const QDateTime reference = now.isValid() ? now.toUTC() : QDateTime::currentDateTimeUtc();
    SessionOverride override;
    override.action = NetworkPolicy::Action::Allow;
    override.direction = NetworkDirection::Both;
    override.createdAt = reference;
    override.expiresAt = reference.addSecs(kAllowOnceTtlSeconds);

    const QString flowId = observation.flow.flowId;
    if (isFlowIdentifier(flowId, QStringLiteral("flow_"))) {
        override.scope = SessionScope::Flow;
        override.flowId = flowId;
    } else {
        override.scope = SessionScope::ExecutableDomain;
        override.executable = RuleResolver::normalizeExecutable(
            observation.process.exeName.isEmpty() ? decision.target.executable
                                                  : observation.process.exeName);
        if (override.executable.isEmpty()) {
            if (error) *error = QStringLiteral("the observation has no executable identity");
            return false;
        }
        DecisionNotice lookup;
        lookup.observation = observation;
        lookup.decision = decision;
        const QString pattern = domainFor(lookup);
        override.domainPattern = pattern.isEmpty() ? QStringLiteral("*") : pattern;
    }

    if (!store->add(override, error))
        return false;
    if (created) *created = override;
    return true;
}

bool alwaysAllow(const FlowObservation &observation, const PolicyDecision &decision,
                 bool confirmed, const QDateTime &now, PinnedRule *created,
                 QString *error)
{
    const QDateTime reference = now.isValid() ? now.toUTC() : QDateTime::currentDateTimeUtc();

    PinnedRule rule;
    rule.action = NetworkPolicy::Action::Allow;
    rule.direction = NetworkDirection::Both;
    rule.createdAt = reference;
    rule.executable = RuleResolver::normalizeExecutable(
        observation.process.exeName.isEmpty() ? decision.target.executable
                                              : observation.process.exeName);
    if (rule.executable.isEmpty()) {
        if (error) *error = QStringLiteral("the observation has no executable identity");
        return false;
    }
    DecisionNotice lookup;
    lookup.observation = observation;
    lookup.decision = decision;
    const QString domain = domainFor(lookup);
    rule.domainPattern = domain.isEmpty() ? QStringLiteral("*") : domain;
    rule.description = bounded(
        QStringLiteral("Always allow %1 from a Data Saver notice").arg(rule.executable),
        160);

    if (!PinnedRuleStore::add(rule, confirmed, error))
        return false;
    if (created) *created = rule;
    return true;
}

} // namespace DataSaverNotifications
