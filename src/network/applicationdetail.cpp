/**
 * @file   applicationdetail.cpp
 * @brief  Snapshot assembly for the application detail view (NG-052).
 */
#include "applicationdetail.h"

#include "policyschedule.h"

#include <QFileInfo>
#include <QHash>
#include <QSet>

#include <algorithm>

namespace {

constexpr int kMaxRelatedProcesses = 32;

QString orDash(const QString &value)
{
    const QString trimmed = value.trimmed();
    return trimmed.isEmpty() ? QStringLiteral("—") : trimmed;
}

QString startedText(qint64 millisSinceEpoch)
{
    if (millisSinceEpoch <= 0) return QStringLiteral("unknown");
    return QDateTime::fromMSecsSinceEpoch(millisSinceEpoch)
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

int confidenceRank(ApplicationIdentity::Confidence confidence)
{
    switch (confidence) {
    case ApplicationIdentity::Confidence::Confirmed: return 3;
    case ApplicationIdentity::Confidence::StrongInference: return 2;
    case ApplicationIdentity::Confidence::WeakInference: return 1;
    case ApplicationIdentity::Confidence::Unknown: return 0;
    }
    return 0;
}

QString destinationKey(const ApplicationDetail::Destination &destination)
{
    return destination.address.trimmed().toLower() + QLatin1Char('\n')
           + destination.name.trimmed().toLower();
}

} // namespace

namespace ApplicationDetail {

QString formatBytes(quint64 bytes)
{
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    const int precision = (unit == 0 || value >= 10.0) ? 0 : 1;
    return QStringLiteral("%1 %2").arg(value, 0, 'f', precision).arg(units[unit]);
}

QString formatRate(quint64 bytesPerSecond)
{
    return formatBytes(bytesPerSecond) + QStringLiteral("/s");
}

QString actionLabel(NetworkPolicy::Action action)
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

QString directionLabel(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("Download");
    case NetworkDirection::Upload: return QStringLiteral("Upload");
    case NetworkDirection::Both: return QStringLiteral("Both");
    }
    return QStringLiteral("Unknown");
}

QString signerLabel(ApplicationIdentity::SignerStatus status)
{
    switch (status) {
    case ApplicationIdentity::SignerStatus::Signed: return QStringLiteral("signed");
    case ApplicationIdentity::SignerStatus::Unsigned: return QStringLiteral("unsigned");
    case ApplicationIdentity::SignerStatus::Invalid: return QStringLiteral("invalid signature");
    case ApplicationIdentity::SignerStatus::Unknown: return QStringLiteral("signature unknown");
    }
    return QStringLiteral("signature unknown");
}

QString originLabel(const QString &source)
{
    const QString value = source.trimmed().toLower();
    if (value == QLatin1String("user")) return QStringLiteral("created by you");
    if (value == QLatin1String("automatic") || value == QLatin1String("auto"))
        return QStringLiteral("applied automatically");
    if (value == QLatin1String("ai")) return QStringLiteral("approved from an AI explanation");
    if (value == QLatin1String("system")) return QStringLiteral("applied by the system");
    return value.isEmpty() ? QStringLiteral("origin unknown") : value;
}

bool policyTargets(const NetworkPolicy &policy, const ActivityQuery &query, quint32 pid)
{
    const QString scope = policy.scope.trimmed().toLower();
    const QString target = policy.targetId.trimmed();
    if (target.isEmpty()) return false;

    const QString path = query.executablePath.trimmed();
    if (scope == QLatin1String("pid"))
        return pid != 0 && target == QString::number(pid);
    if (scope == QLatin1String("path") || scope == QLatin1String("executable")) {
        return !path.isEmpty()
               && QFileInfo(target).absoluteFilePath().compare(
                      QFileInfo(path).absoluteFilePath(), Qt::CaseInsensitive) == 0;
    }
    if (scope == QLatin1String("group"))
        return !query.groupId.isEmpty()
               && target.compare(query.groupId, Qt::CaseInsensitive) == 0;
    if (scope == QLatin1String("service"))
        return !query.serviceName.isEmpty()
               && target.compare(query.serviceName, Qt::CaseInsensitive) == 0;
    if (scope == QLatin1String("publisher"))
        return !query.publisher.isEmpty()
               && target.compare(query.publisher, Qt::CaseInsensitive) == 0;
    // package, port, and protocol scopes cannot be matched from this evidence;
    // they are simply not claimed as covering the application.
    return false;
}

QString policySummaryText(const NetworkPolicy &policy)
{
    const QString description = policy.description.trimmed();
    if (!description.isEmpty()) return description;
    return QStringLiteral("%1: %2").arg(orDash(policy.scope), orDash(policy.targetId));
}

QString auditSummaryLine(const AuditEvent &event)
{
    if (!event.reason.trimmed().isEmpty()) return event.reason.trimmed();
    if (!event.result.trimmed().isEmpty()) return event.result.trimmed();
    if (!event.errorInfo.trimmed().isEmpty()) return event.errorInfo.trimmed();
    return orDash(event.scope);
}

Destination destinationFromSummary(const DestinationNameSummary &summary)
{
    Destination destination;
    destination.address = summary.address;
    destination.name = summary.name;
    destination.source = attributionSourceName(summary.source);
    destination.confidence = summary.confidence;
    destination.evidence = summary.evidence;
    destination.expiresAt = summary.expiresAt;
    return destination;
}

QList<Destination> mergeDestinations(const QList<Destination> &destinations)
{
    QList<Destination> merged;
    QHash<QString, int> indexByKey;

    for (const Destination &destination : destinations) {
        if (destination.address.trimmed().isEmpty() && destination.name.trimmed().isEmpty())
            continue;
        const QString key = destinationKey(destination);
        const auto existing = indexByKey.constFind(key);
        if (existing == indexByKey.constEnd()) {
            indexByKey.insert(key, merged.size());
            merged.append(destination);
            continue;
        }

        Destination &kept = merged[existing.value()];
        // Stronger attribution wins the row, but evidence from every record is
        // kept: two observers naming the same endpoint is exactly the fact the
        // confidence model calls Confirmed.
        QStringList evidence = kept.evidence;
        const QString previousSource = kept.source;
        const ApplicationIdentity::Confidence strongest =
            confidenceRank(destination.confidence) > confidenceRank(kept.confidence)
                ? destination.confidence
                : kept.confidence;
        const QDateTime latestExpiry = (kept.expiresAt.isValid() && destination.expiresAt.isValid()
                                        && destination.expiresAt > kept.expiresAt)
                                           ? destination.expiresAt
                                           : kept.expiresAt;

        if (confidenceRank(destination.confidence) > confidenceRank(kept.confidence))
            kept = destination;

        for (const QString &line : evidence) {
            if (!line.trimmed().isEmpty() && !kept.evidence.contains(line))
                kept.evidence.append(line);
        }
        if (!previousSource.isEmpty() && !kept.source.contains(previousSource)) {
            kept.source = kept.source.isEmpty()
                              ? previousSource
                              : kept.source + QStringLiteral(" + ") + previousSource;
        }
        kept.confidence = strongest;
        if (latestExpiry.isValid()) kept.expiresAt = latestExpiry;
    }

    std::sort(merged.begin(), merged.end(), [](const Destination &a, const Destination &b) {
        const bool aNamed = !a.name.trimmed().isEmpty();
        const bool bNamed = !b.name.trimmed().isEmpty();
        if (aNamed != bNamed) return aNamed;
        if (a.confidence != b.confidence)
            return confidenceRank(a.confidence) > confidenceRank(b.confidence);
        const QString aKey = a.name.isEmpty() ? a.address : a.name;
        const QString bKey = b.name.isEmpty() ? b.address : b.name;
        return aKey.compare(bKey, Qt::CaseInsensitive) < 0;
    });
    return merged;
}

QList<ActionState> buildActions(const Input &input)
{
    const QString path = input.executablePath.trimmed();
    const bool haveScope = !path.isEmpty() || !input.groupId.trimmed().isEmpty()
                           || !input.services.isEmpty()
                           || !input.publisher.trimmed().isEmpty()
                           || input.pid != 0;

    QList<ActionState> actions;

    ActionState policy;
    policy.key = QStringLiteral("policy");
    policy.label = QStringLiteral("Create policy…");
    policy.enabled = haveScope;
    if (!haveScope) {
        policy.reason = QStringLiteral(
            "No executable path, group, service, or publisher is known yet, so a "
            "policy has nothing to target.");
    }
    actions.append(policy);

    ActionState recommendation;
    recommendation.key = QStringLiteral("recommendation");
    recommendation.label = QStringLiteral("Recommendation…");
    recommendation.enabled = true;
    actions.append(recommendation);

    ActionState approval;
    approval.key = QStringLiteral("approval");
    approval.label = QStringLiteral("Review AI & approve…");
    approval.enabled = true;
    actions.append(approval);

    ActionState internet;
    internet.key = QStringLiteral("internet");
    internet.label = input.internetBlocked ? QStringLiteral("Restore internet access")
                                           : QStringLiteral("Block internet access");
    internet.enabled = !path.isEmpty();
    if (!internet.enabled)
        internet.reason = QStringLiteral("The executable path is unknown, so no firewall rule can be written.");
    actions.append(internet);

    ActionState throttle;
    throttle.key = QStringLiteral("throttle");
    throttle.label = input.throttleApplied ? QStringLiteral("Remove bandwidth limit…")
                                           : QStringLiteral("Limit bandwidth…");
    throttle.enabled = !path.isEmpty();
    if (!throttle.enabled)
        throttle.reason = QStringLiteral("The executable path is unknown, so no limit can be applied.");
    actions.append(throttle);

    ActionState verify;
    verify.key = QStringLiteral("verify");
    verify.label = QStringLiteral("Verify enforcement…");
    verify.enabled = true;
    actions.append(verify);

    ActionState group;
    group.key = QStringLiteral("group");
    group.label = QStringLiteral("Activity group…");
    group.enabled = !input.groupId.trimmed().isEmpty();
    if (!group.enabled)
        group.reason = QStringLiteral("This process has not been grouped with anything yet.");
    actions.append(group);

    return actions;
}

Snapshot build(const Input &input)
{
    Snapshot snapshot;
    const QDateTime now = input.now.isValid() ? input.now : QDateTime::currentDateTimeUtc();

    // ── Header ──
    const QString executableName = input.executableName.trimmed().isEmpty()
        ? QFileInfo(input.executablePath).fileName()
        : input.executableName.trimmed();
    const QString displayName = input.displayName.trimmed();
    if (!displayName.isEmpty() && !executableName.isEmpty()
        && displayName.compare(executableName, Qt::CaseInsensitive) != 0) {
        snapshot.title = QStringLiteral("%1 (%2)").arg(displayName, executableName);
    } else if (!displayName.isEmpty()) {
        snapshot.title = displayName;
    } else if (!executableName.isEmpty()) {
        snapshot.title = executableName;
    } else if (!input.executablePath.trimmed().isEmpty()) {
        snapshot.title = input.executablePath.trimmed();
    } else {
        snapshot.title = QStringLiteral("Unknown application");
    }

    QStringList subtitleParts;
    subtitleParts << (input.pid != 0 ? QStringLiteral("PID %1").arg(input.pid)
                                     : QStringLiteral("Process ID unknown"));
    if (input.usage.foreground)
        subtitleParts << QStringLiteral("foreground application");
    else if (input.usage.foregroundHelper)
        subtitleParts << QStringLiteral("helper of the foreground application");
    snapshot.subtitle = subtitleParts.join(QStringLiteral(" · "));

    // ── Identity ──
    snapshot.facts.append(qMakePair(QStringLiteral("Executable"),
                                    orDash(input.executablePath)));
    snapshot.facts.append(qMakePair(QStringLiteral("Identity"),
                                    input.identityId.trimmed().isEmpty()
                                        ? QStringLiteral("not resolved")
                                        : input.identityId.trimmed()));
    snapshot.facts.append(qMakePair(QStringLiteral("Publisher"),
                                    input.publisher.trimmed().isEmpty()
                                        ? QStringLiteral("not known")
                                        : input.publisher.trimmed()));
    snapshot.facts.append(qMakePair(QStringLiteral("Signature"),
                                    signerLabel(input.signerStatus)));
    snapshot.facts.append(qMakePair(QStringLiteral("Activity group"),
                                    input.groupName.trimmed().isEmpty()
                                        ? (input.groupId.trimmed().isEmpty()
                                               ? QStringLiteral("not grouped")
                                               : input.groupId.trimmed())
                                        : input.groupName.trimmed()));
    snapshot.facts.append(qMakePair(QStringLiteral("Services"),
                                    input.services.isEmpty()
                                        ? QStringLiteral("—")
                                        : input.services.join(QStringLiteral(", "))));
    snapshot.facts.append(qMakePair(QStringLiteral("Started"),
                                    startedText(input.processStartMs)));
    snapshot.facts.append(qMakePair(QStringLiteral("Internet access"),
                                    input.internetBlocked
                                        ? QStringLiteral("blocked by a NetGuard firewall rule")
                                        : QStringLiteral("not blocked by NetGuard")));
    QString limitText = QStringLiteral("no NetGuard limit");
    if (input.throttleApplied) {
        limitText = input.throttleOwner.trimmed().isEmpty()
                        ? QStringLiteral("limited (applied outside a policy)")
                        : QStringLiteral("limited by \"%1\"").arg(input.throttleOwner.trimmed());
    }
    snapshot.facts.append(qMakePair(QStringLiteral("Bandwidth limit"), limitText));

    // ── Activity ──
    snapshot.activitySummary = input.activity.summary();
    if (input.activity.isKnown()) {
        QString detail = QStringLiteral("A local rule classifies this application as %1.")
                             .arg(input.activity.categoryName());
        if (!input.activity.matchedRules.isEmpty()) {
            QStringList ruleIds;
            for (const CatalogMatch &match : input.activity.matchedRules)
                ruleIds << match.ruleId;
            detail += QStringLiteral(" Matched %1: %2.")
                          .arg(ruleIds.size() == 1 ? QStringLiteral("rule")
                                                   : QStringLiteral("rules"),
                               ruleIds.join(QStringLiteral(", ")));
        }
        snapshot.activityDetail = detail;
    } else {
        snapshot.activityDetail = QStringLiteral(
            "No local rule matched this application, so the category stays Unknown. "
            "The actions below still work from the executable path, activity group, "
            "service, or publisher.");
    }
    snapshot.evidence = input.activity.evidence;

    // ── Usage ──
    snapshot.usageText = QStringLiteral("Now: ↓ %1 · ↑ %2     Total: ↓ %3 · ↑ %4 · %5 packets")
                             .arg(formatRate(input.usage.rxBytesPerSecond),
                                  formatRate(input.usage.txBytesPerSecond),
                                  formatBytes(input.usage.rxBytes),
                                  formatBytes(input.usage.txBytes))
                             .arg(input.usage.packets);
    if (input.usage.foreground) {
        snapshot.foregroundText = QStringLiteral(
            "This is the foreground application now. Traffic it starts is treated as "
            "user-initiated, so suggestions stay advisory (NG-041).");
    } else if (input.usage.foregroundHelper) {
        snapshot.foregroundText = QStringLiteral(
            "This process is a live helper of the foreground application (advisory).");
    } else {
        snapshot.foregroundText = QStringLiteral("Not the foreground application.");
    }

    // ── Destinations ──
    snapshot.destinations = mergeDestinations(input.destinations);
    int named = 0;
    for (const Destination &destination : snapshot.destinations) {
        if (!destination.name.trimmed().isEmpty()) ++named;
    }
    if (snapshot.destinations.isEmpty()) {
        snapshot.destinationSummary = QStringLiteral(
            "No destination has been attributed to this application yet. DNS names and "
            "visible TLS SNI names are collected only while the capture is running.");
    } else {
        snapshot.destinationSummary = QStringLiteral("%1 destination%2 · %3 named")
                                          .arg(snapshot.destinations.size())
                                          .arg(snapshot.destinations.size() == 1
                                                   ? QString()
                                                   : QStringLiteral("s"))
                                          .arg(named);
    }

    // ── Related processes ──
    QSet<quint32> seenPids;
    for (const RelatedProcess &related : input.related) {
        RelatedProcess entry = related;
        entry.name = entry.name.trimmed().isEmpty() ? QStringLiteral("unknown process")
                                                    : entry.name.trimmed();
        if (entry.pid != 0 && entry.pid == input.pid) continue;
        if (entry.pid != 0) {
            if (seenPids.contains(entry.pid)) continue;
            seenPids.insert(entry.pid);
        }
        if (snapshot.related.size() >= kMaxRelatedProcesses) break;
        snapshot.related.append(entry);
    }
    if (snapshot.related.isEmpty()) {
        snapshot.relatedSummary = QStringLiteral(
            "No related process is known. Activity groups are built from identity, "
            "publisher, service, and lineage evidence as traffic is observed.");
    } else {
        snapshot.relatedSummary = QStringLiteral("%1 related process%2")
                                      .arg(snapshot.related.size())
                                      .arg(snapshot.related.size() == 1
                                               ? QString()
                                               : QStringLiteral("es"));
    }

    // ── Policy ──
    int inForce = 0;
    for (const NetworkPolicy &policy : input.policies) {
        if (!policyTargets(policy, input.query, input.pid)) continue;
        const PolicyActivationState state = policyActivationAt(policy, now);
        PolicyEntry entry;
        entry.id = policy.id;
        entry.summary = policySummaryText(policy);
        entry.scope = policy.scope;
        entry.targetId = policy.targetId;
        entry.action = actionLabel(policy.action);
        entry.direction = directionLabel(policy.direction);
        // policyActivationName() is the lower-case token used by the scheduler;
        // the view sentence-capitalises it so a table cell reads as a state.
        entry.state = policyActivationName(state);
        if (!entry.state.isEmpty())
            entry.state[0] = entry.state.at(0).toUpper();
        entry.origin = originLabel(policy.source);
        entry.expiration = policy.expiration;
        entry.inForce = state == PolicyActivationState::Active;
        if (entry.inForce) ++inForce;
        snapshot.policies.append(entry);
    }
    if (snapshot.policies.isEmpty()) {
        snapshot.policySummary = QStringLiteral(
            "No stored policy targets this application. It is only affected by the "
            "Data Saver mode and any manual limit listed above.");
    } else {
        snapshot.policySummary = QStringLiteral("%1 polic%2 target this application · %3 in force now")
                                     .arg(snapshot.policies.size())
                                     .arg(snapshot.policies.size() == 1
                                              ? QStringLiteral("y")
                                              : QStringLiteral("ies"))
                                     .arg(inForce);
    }

    // ── Audit ──
    QList<AuditEvent> events = input.audit;
    std::sort(events.begin(), events.end(), [](const AuditEvent &a, const AuditEvent &b) {
        if (a.timestamp != b.timestamp) return a.timestamp > b.timestamp;
        return a.reason < b.reason;
    });
    for (const AuditEvent &event : events) {
        if (snapshot.audit.size() >= kMaxAuditEntries) break;
        AuditEntry entry;
        entry.at = event.timestamp;
        entry.type = auditEventTypeName(event.type);
        entry.summary = auditSummaryLine(event);
        entry.result = event.result;
        snapshot.audit.append(entry);
    }
    if (snapshot.audit.isEmpty()) {
        snapshot.auditSummary = QStringLiteral(
            "No audit event references this application yet. Detections, policy "
            "changes, and enforcement results are recorded as they happen.");
    } else {
        snapshot.auditSummary = QStringLiteral("%1 event%2 · newest first")
                                    .arg(snapshot.audit.size())
                                    .arg(snapshot.audit.size() == 1
                                             ? QString()
                                             : QStringLiteral("s"));
    }

    // ── Actions ──
    snapshot.actions = buildActions(input);

    return snapshot;
}

} // namespace ApplicationDetail
