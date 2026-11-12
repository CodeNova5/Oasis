/**
 * @file   policyscope.cpp
 * @brief  Scope, effect, duration, and enforcement wording for policies (NG-053).
 * @author Codebuff
 */

#include "policyscope.h"

#include "policyschedule.h"

namespace {

QString scopeToken(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid: return QStringLiteral("PID");
    case PolicyScopeKind::ExecutablePath: return QStringLiteral("path");
    case PolicyScopeKind::Publisher: return QStringLiteral("publisher");
    case PolicyScopeKind::Service: return QStringLiteral("service");
    case PolicyScopeKind::ApplicationGroup: return QStringLiteral("group");
    }
    return QString();
}

QString directionPhrase(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("downloads");
    case NetworkDirection::Upload: return QStringLiteral("uploads");
    case NetworkDirection::Both: return QStringLiteral("both directions");
    }
    return QString();
}

// The impact preview is evaluated through the same activation rules the list
// and the scheduler use, so the preview cannot disagree with what is stored.
NetworkPolicy policyForImpact(const PolicyImpact &impact)
{
    NetworkPolicy policy;
    policy.scope = policyScopeKey(impact.scope);
    policy.targetId = impact.target;
    policy.action = impact.action;
    policy.direction = impact.direction;
    policy.rateBitsPerSecond = impact.rateBitsPerSecond;
    policy.expiration = impact.expiration;
    policy.schedule = impact.schedule;
    policy.enabled = impact.enabled;

    const bool expires = impact.expiration.isValid();
    const bool recurring = !impact.schedule.isEmpty();
    if (expires && recurring) {
        policy.scheduleType = NetworkPolicy::ScheduleType::Both;
    } else if (expires) {
        policy.scheduleType = NetworkPolicy::ScheduleType::Expiration;
    } else if (recurring) {
        policy.scheduleType = NetworkPolicy::ScheduleType::Recurring;
    } else {
        policy.scheduleType = NetworkPolicy::ScheduleType::None;
    }
    return policy;
}

} // namespace

// ─── Scope descriptions ─────────────────────────────────────────────────────

QString policyScopeDisplayName(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid: return QStringLiteral("This process only (PID)");
    case PolicyScopeKind::ExecutablePath: return QStringLiteral("This executable path");
    case PolicyScopeKind::Publisher: return QStringLiteral("This publisher");
    case PolicyScopeKind::Service: return QStringLiteral("This Windows service");
    case PolicyScopeKind::ApplicationGroup: return QStringLiteral("This application group");
    }
    return QString();
}

QString policyScopeKey(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid: return QStringLiteral("pid");
    case PolicyScopeKind::ExecutablePath: return QStringLiteral("path");
    case PolicyScopeKind::Publisher: return QStringLiteral("publisher");
    case PolicyScopeKind::Service: return QStringLiteral("service");
    case PolicyScopeKind::ApplicationGroup: return QStringLiteral("group");
    }
    return QString();
}

bool policyScopeKindFromKey(const QString &key, PolicyScopeKind *scope)
{
    const QString k = key.trimmed().toLower();
    if (k == QLatin1String("pid")) { *scope = PolicyScopeKind::Pid; return true; }
    if (k == QLatin1String("path") || k == QLatin1String("executable")) {
        *scope = PolicyScopeKind::ExecutablePath;
        return true;
    }
    if (k == QLatin1String("publisher")) { *scope = PolicyScopeKind::Publisher; return true; }
    if (k == QLatin1String("service")) { *scope = PolicyScopeKind::Service; return true; }
    if (k == QLatin1String("group")) { *scope = PolicyScopeKind::ApplicationGroup; return true; }
    return false;
}

QString policyScopeBreadth(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid: return QStringLiteral("Narrowest");
    case PolicyScopeKind::ExecutablePath: return QStringLiteral("One file");
    case PolicyScopeKind::Publisher: return QStringLiteral("Broad");
    case PolicyScopeKind::Service: return QStringLiteral("One service");
    case PolicyScopeKind::ApplicationGroup: return QStringLiteral("Broad");
    }
    return QString();
}

QString policyScopeExplanation(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid:
        return QStringLiteral(
            "Applies only while this process instance is running. A restart, a "
            "respawn, or a reused PID is a different process, so the policy "
            "does not follow it.");
    case PolicyScopeKind::ExecutablePath:
        return QStringLiteral(
            "Applies to the file at this path, now and on later runs. A copy of "
            "the file elsewhere, or an update installed to a new path, is not "
            "covered.");
    case PolicyScopeKind::Publisher:
        return QStringLiteral(
            "Applies to every process signed by this publisher, including "
            "products and updates you have not seen yet. A broad certificate "
            "affects unrelated software too.");
    case PolicyScopeKind::Service:
        return QStringLiteral(
            "Applies to this Windows service and the processes that host it, "
            "including instances started later.");
    case PolicyScopeKind::ApplicationGroup:
        return QStringLiteral(
            "Applies to every current and future member of this activity group, "
            "including helpers and updaters that appear later. Adding a member "
            "to the group widens what the policy affects.");
    }
    return QString();
}

bool policyScopeAffectsFutureProcesses(PolicyScopeKind scope)
{
    return scope != PolicyScopeKind::Pid;
}

bool policyScopeEnforcedByThisBuild(PolicyScopeKind scope)
{
    // Path and group policies are resolved to executables and applied by the
    // enforcement coordinator; the other scopes are stored but not resolved.
    return scope == PolicyScopeKind::ExecutablePath ||
           scope == PolicyScopeKind::ApplicationGroup;
}

bool policyScopeIsBroad(PolicyScopeKind scope)
{
    return scope == PolicyScopeKind::Publisher ||
           scope == PolicyScopeKind::ApplicationGroup;
}

bool policyScopeRequiresConfirmation(PolicyScopeKind scope, bool enabled)
{
    return enabled && policyScopeIsBroad(scope);
}

QString policyScopeEnforcementNote(PolicyScopeKind scope)
{
    if (policyScopeEnforcedByThisBuild(scope)) {
        return scope == PolicyScopeKind::ApplicationGroup
            ? QStringLiteral("Enforced: this build applies the policy to the "
                             "group's running processes.")
            : QStringLiteral("Enforced: this build applies the policy to the "
                             "executable path.");
    }
    return QStringLiteral("Stored only: this build cannot resolve %1 policies to "
                          "running processes, so no rule or limit is applied.")
        .arg(scopeToken(scope));
}

QString policyScopeRiskSummary(PolicyScopeKind scope)
{
    QString text = policyScopeBreadth(scope) + QStringLiteral(": ") +
                   policyScopeExplanation(scope);

    if (policyScopeAffectsFutureProcesses(scope))
        text += QStringLiteral("\n\nThis scope also affects processes that appear later.");

    if (!policyScopeEnforcedByThisBuild(scope))
        text += QStringLiteral("\n\n") + policyScopeEnforcementNote(scope);

    return text;
}

// ─── Effect and impact ──────────────────────────────────────────────────────

QString policyActionDisplayName(NetworkPolicy::Action action)
{
    switch (action) {
    case NetworkPolicy::Action::Allow: return QStringLiteral("Allow");
    case NetworkPolicy::Action::Notify: return QStringLiteral("Notify");
    case NetworkPolicy::Action::Ask: return QStringLiteral("Ask");
    case NetworkPolicy::Action::Throttle: return QStringLiteral("Throttle");
    case NetworkPolicy::Action::Block: return QStringLiteral("Block");
    case NetworkPolicy::Action::Schedule: return QStringLiteral("Schedule");
    case NetworkPolicy::Action::NoAction: return QStringLiteral("No action");
    }
    return QStringLiteral("Unknown");
}

QString policyDirectionDisplayName(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("Download");
    case NetworkDirection::Upload: return QStringLiteral("Upload");
    case NetworkDirection::Both: return QStringLiteral("Both");
    }
    return QStringLiteral("Unknown");
}

QString policyRateText(quint64 bitsPerSecond)
{
    return QStringLiteral("%1 Mbit/s")
        .arg(static_cast<double>(bitsPerSecond) / 1000000.0, 0, 'f', 2);
}

QString policyEffectSummary(NetworkPolicy::Action action, NetworkDirection direction,
                            quint64 rateBitsPerSecond)
{
    const QString name = policyActionDisplayName(action);
    if (action == NetworkPolicy::Action::Throttle)
        return QStringLiteral("%1 to %2, %3").arg(name, policyRateText(rateBitsPerSecond),
                                                  directionPhrase(direction));
    if (action == NetworkPolicy::Action::NoAction)
        return QStringLiteral("No action, %1").arg(directionPhrase(direction));
    return QStringLiteral("%1, %2").arg(name, directionPhrase(direction));
}

QString policyImpactSummary(const PolicyImpact &impact, const QDateTime &now)
{
    const NetworkPolicy policy = policyForImpact(impact);
    const PolicyActivationState activation = policyActivationAt(policy, now);

    const QString target = impact.target.trimmed().isEmpty()
        ? QStringLiteral("(no target yet)") : impact.target.trimmed();

    QStringList lines;
    lines << QStringLiteral("Scope: %1 (%2)")
                 .arg(policyScopeDisplayName(impact.scope), policyScopeBreadth(impact.scope));
    lines << policyScopeExplanation(impact.scope);
    lines << QStringLiteral("Target: %1").arg(target);
    lines << QStringLiteral("Effect: %1.")
                 .arg(policyEffectSummary(impact.action, impact.direction,
                                          impact.rateBitsPerSecond));
    lines << QStringLiteral("Duration: %1.")
                 .arg(policyExpirationSummary(impact.expiration, now));

    if (!impact.schedule.isEmpty()) {
        const QString window = activation == PolicyActivationState::Unsupported
            ? QStringLiteral("not recognised, so the policy stays inactive")
            : activation == PolicyActivationState::Inactive
                  ? QStringLiteral("in force now? no, outside the window")
                  : QStringLiteral("in force now? yes");
        lines << QStringLiteral("Window: %1 (%2).").arg(impact.schedule, window);
    }

    lines << (impact.enabled
                  ? QStringLiteral("State: enabled.")
                  : QStringLiteral("State: disabled by the user — stored but not enforced."));

    QString enforcement = policyScopeEnforcementNote(impact.scope);
    if (impact.action == NetworkPolicy::Action::Throttle &&
        impact.rateBitsPerSecond != kEnforcedThrottleBitsPerSecond) {
        enforcement += QStringLiteral(" The throttle channel requests %1 in this build, "
                                      "so the stored rate is not the applied one.")
                           .arg(policyRateText(kEnforcedThrottleBitsPerSecond));
    }
    lines << QStringLiteral("Enforcement: %1").arg(enforcement);

    if (policyScopeAffectsFutureProcesses(impact.scope))
        lines << QStringLiteral("This scope also affects processes that appear later.");

    return lines.join(QStringLiteral("\n"));
}

QString policyConfirmationText(const PolicyImpact &impact, const QDateTime &now)
{
    const QString target = impact.target.trimmed().isEmpty()
        ? QStringLiteral("this target") : impact.target.trimmed();

    QString covers;
    switch (impact.scope) {
    case PolicyScopeKind::Publisher:
        covers = QStringLiteral("every process signed by \"%1\"").arg(target);
        break;
    case PolicyScopeKind::ApplicationGroup:
        covers = QStringLiteral("every member of the group \"%1\", including members "
                                "that join later").arg(target);
        break;
    default:
        covers = QStringLiteral("\"%1\"").arg(target);
        break;
    }

    return QStringLiteral("Apply this policy to %1?\n\n%2\n\nBroad scopes cover "
                          "software you have not selected yourself. You can delete "
                          "the policy later, but it is in force until you do.")
        .arg(covers, policyImpactSummary(impact, now));
}

QString policyEnforcementSummary(const NetworkPolicy &policy)
{
    if (!policy.enabled) return QStringLiteral("Not enforced (disabled)");

    PolicyScopeKind scope = PolicyScopeKind::ExecutablePath;
    if (!policyScopeKindFromKey(policy.scope, &scope)) {
        return QStringLiteral("Stored only — scope \"%1\" is not known to this build")
            .arg(policy.scope);
    }

    if (!policyScopeEnforcedByThisBuild(scope)) {
        return QStringLiteral("Stored only — %1 scope is not resolved yet")
            .arg(scopeToken(scope));
    }

    if (policy.action == NetworkPolicy::Action::Throttle &&
        policy.rateBitsPerSecond != 0 &&
        policy.rateBitsPerSecond != kEnforcedThrottleBitsPerSecond) {
        return QStringLiteral("Enforced at %1 (stored rate differs)")
            .arg(policyRateText(kEnforcedThrottleBitsPerSecond));
    }

    return QStringLiteral("Enforced");
}
