/**
 * @file   topconsumers.cpp
 * @brief  Ranking and wording for the top-consumer dashboard (NG-054).
 * @author Codebuff
 */

#include "topconsumers.h"

#include "applicationdetail.h"
#include "policyschedule.h"
#include "policyscope.h"

#include <algorithm>

namespace TopConsumers {

namespace {

QString plural(int count, const QString &singular, const QString &pluralForm)
{
    return count == 1 ? singular : pluralForm;
}

QString usageText(const Consumer &consumer)
{
    const quint64 rate = consumer.totalBytesPerSecond();
    const QString bytes = ApplicationDetail::formatBytes(consumer.totalBytes());
    if (rate == 0) return bytes;
    return ApplicationDetail::formatRate(rate) + QStringLiteral(" · ") + bytes;
}

QString activityText(const Consumer &consumer)
{
    return consumer.activity.trimmed().isEmpty()
        ? QStringLiteral("Unresolved")
        : consumer.activity.trimmed();
}

QString controlText(const Consumer &consumer)
{
    if (consumer.blocked) return QStringLiteral("Blocked");
    if (consumer.throttled) {
        const QString owner = consumer.controlOwner.trimmed();
        return owner.isEmpty()
            ? QStringLiteral("Limited")
            : QStringLiteral("Limited by %1").arg(owner);
    }
    if (consumer.foreground) return QStringLiteral("Foreground");
    return QStringLiteral("—");
}

} // namespace

bool isUnresolved(const Consumer &consumer)
{
    return consumer.path.trimmed().isEmpty() || consumer.activity.trimmed().isEmpty();
}

QList<const Consumer *> rankConsumers(const QList<Consumer> &consumers, int limit)
{
    QList<const Consumer *> ranked;
    ranked.reserve(consumers.size());
    for (const Consumer &consumer : consumers) ranked.append(&consumer);

    std::stable_sort(ranked.begin(), ranked.end(),
                     [](const Consumer *a, const Consumer *b) {
        if (a->totalBytesPerSecond() != b->totalBytesPerSecond())
            return a->totalBytesPerSecond() > b->totalBytesPerSecond();
        if (a->totalBytes() != b->totalBytes())
            return a->totalBytes() > b->totalBytes();
        const int byName = QString::compare(a->name, b->name, Qt::CaseInsensitive);
        if (byName != 0) return byName < 0;
        return a->pid < b->pid;
    });

    if (limit > 0 && ranked.size() > limit) ranked = ranked.mid(0, limit);
    return ranked;
}

Summary build(const QList<Consumer> &consumers, const QList<NetworkPolicy> &policies,
              const QDateTime &now, int limit)
{
    Summary summary;
    summary.consumerCount = consumers.size();

    for (const Consumer &consumer : consumers) {
        summary.totalRxBytes += consumer.rxBytes;
        summary.totalTxBytes += consumer.txBytes;
        summary.totalBytesPerSecond += consumer.totalBytesPerSecond();

        if (isUnresolved(consumer)) {
            ++summary.unresolvedConsumers;
            summary.unresolvedBytes += consumer.totalBytes();
        }
    }

    const QList<const Consumer *> ranked = rankConsumers(consumers, limit);
    int rank = 0;
    for (const Consumer *consumer : ranked) {
        Row row;
        row.rank = ++rank;
        row.pid = consumer->pid;
        row.name = consumer->name;
        row.identity = consumer->identity;
        row.path = consumer->path;
        row.usage = usageText(*consumer);
        row.bytesPerSecond = consumer->totalBytesPerSecond();
        row.totalBytes = consumer->totalBytes();
        row.activity = activityText(*consumer);
        row.control = controlText(*consumer);
        row.unresolved = isUnresolved(*consumer);
        summary.rows.append(row);
    }

    if (!ranked.isEmpty()) {
        const Consumer *top = ranked.first();
        summary.topPid = top->pid;
        summary.topName = top->name;
        summary.topPath = top->path;

        const quint64 rate = top->totalBytesPerSecond();
        summary.headline = rate > 0
            ? QStringLiteral("%1 is the top consumer at %2")
                  .arg(top->name, ApplicationDetail::formatRate(rate))
            : QStringLiteral("%1 has moved the most data (%2)")
                  .arg(top->name, ApplicationDetail::formatBytes(top->totalBytes()));

        QString detail = top->name;
        if (!top->identity.trimmed().isEmpty() && top->identity != top->name)
            detail += QStringLiteral(" (%1)").arg(top->identity);
        detail += QStringLiteral(" — ") + usageText(*top);
        const QString control = controlText(*top);
        if (control != QStringLiteral("—"))
            detail += QStringLiteral(", ") + control.toLower();
        summary.topSummary = detail;
    } else {
        summary.headline = QStringLiteral("Waiting for traffic");
        summary.topSummary = QStringLiteral(
            "No traffic has been observed yet. Start capture or wait for the "
            "current connections to move data.");
    }

    // "Active controls" means in force now, not merely stored: the same
    // activation rules the scheduler uses decide that.
    for (const NetworkPolicy &policy : policies) {
        if (policyActivationAt(policy, now) != PolicyActivationState::Active) continue;

        const bool temporary = policy.expiration.isValid();
        Control control;
        control.policyId = policy.id;
        control.summary = ApplicationDetail::policySummaryText(policy);
        control.effect = policyEffectSummary(
            policy.action, policy.direction,
            policy.action == NetworkPolicy::Action::Throttle
                ? policy.rateBitsPerSecond : 0);
        control.state = policyActivationName(PolicyActivationState::Active);
        control.enforcement = policyEnforcementSummary(policy);
        control.expiration = policy.expiration;
        control.temporary = temporary;
        summary.controls.append(control);
    }

    int temporaryCount = 0;
    for (const Control &control : summary.controls) {
        if (control.temporary) ++temporaryCount;
    }
    if (summary.controls.isEmpty()) {
        summary.controlSummary = QStringLiteral("No policies are in force right now");
    } else {
        summary.controlSummary = QStringLiteral("%1 %2 in force")
            .arg(summary.controls.size())
            .arg(plural(summary.controls.size(), QStringLiteral("control"),
                        QStringLiteral("controls")));
        if (temporaryCount > 0) {
            summary.controlSummary += QStringLiteral(" (%1 %2)")
                .arg(temporaryCount)
                .arg(plural(temporaryCount, QStringLiteral("temporary"),
                            QStringLiteral("temporary")));
        }
    }

    if (summary.unresolvedConsumers == 0) {
        summary.unresolvedSummary = QStringLiteral(
            "Every consumer has an executable path and an activity match");
    } else {
        summary.unresolvedSummary = QStringLiteral("%1 %2 with %3 and no executable "
                                                   "path or activity match")
            .arg(summary.unresolvedConsumers)
            .arg(plural(summary.unresolvedConsumers, QStringLiteral("consumer"),
                        QStringLiteral("consumers")))
            .arg(ApplicationDetail::formatBytes(summary.unresolvedBytes));
    }

    for (const Consumer &consumer : consumers) {
        if (summary.recommendations.size() >= kMaxRecommendations) break;
        if (consumer.recommendation.trimmed().isEmpty()) continue;

        Recommendation recommendation;
        recommendation.pid = consumer.pid;
        recommendation.name = consumer.name;
        recommendation.path = consumer.path;
        recommendation.title = consumer.recommendation.trimmed();
        recommendation.reason = consumer.recommendationReason.trimmed();
        summary.recommendations.append(recommendation);
    }

    if (summary.recommendations.isEmpty()) {
        summary.recommendationSummary = QStringLiteral("No action is suggested right now");
    } else {
        summary.recommendationSummary = QStringLiteral("%1 suggested %2")
            .arg(summary.recommendations.size())
            .arg(plural(summary.recommendations.size(), QStringLiteral("action"),
                        QStringLiteral("actions")));
    }

    return summary;
}

} // namespace TopConsumers
