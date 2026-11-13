/**
 * @file    activityclassifier.cpp
 * @author  Oasis
 */
#include "activityclassifier.h"

#include <QFileInfo>

namespace {

CatalogQuery toCatalogQuery(const ActivityQuery &query)
{
    CatalogQuery catalog;
    catalog.identityId = query.identityId;
    catalog.publisher = query.publisher;
    // The identity's display name carries version resource metadata such as
    // "Google Update", so it is the best available product evidence.
    catalog.product = query.product.trimmed().isEmpty() ? query.displayName
                                                        : query.product;
    catalog.executableName = query.executableName;
    catalog.executablePath = query.executablePath;
    catalog.serviceName = query.serviceName;
    catalog.domain = query.domain;
    catalog.remoteAddress = query.remoteAddress;
    return catalog;
}

bool matchedOn(const CatalogMatch &match, const QString &prefix)
{
    for (const QString &item : match.matchedOn) {
        if (item.startsWith(prefix)) return true;
    }
    return false;
}

QList<ActivityPolicyTarget> policyTargetsFor(const ActivityQuery &query)
{
    QList<ActivityPolicyTarget> targets;

    auto add = [&targets](const QString &scope, const QString &id,
                          const QString &label) {
        if (id.trimmed().isEmpty()) return;
        for (const ActivityPolicyTarget &existing : targets) {
            if (existing.scope == scope && existing.targetId == id) return;
        }
        ActivityPolicyTarget target;
        target.scope = scope;
        target.targetId = id;
        target.label = label;
        targets.append(target);
    };

    if (!query.executablePath.trimmed().isEmpty()) {
        add(QStringLiteral("path"), query.executablePath.trimmed(),
            QStringLiteral("Executable \"%1\"")
                .arg(QFileInfo(query.executablePath).fileName()));
    }
    if (!query.groupId.trimmed().isEmpty()) {
        add(QStringLiteral("group"), query.groupId.trimmed(),
            query.groupName.trimmed().isEmpty()
                ? QStringLiteral("Its activity group")
                : QStringLiteral("Activity group \"%1\"").arg(query.groupName.trimmed()));
    }
    if (!query.serviceName.trimmed().isEmpty()) {
        add(QStringLiteral("service"), query.serviceName.trimmed(),
            QStringLiteral("Windows service \"%1\"").arg(query.serviceName.trimmed()));
    }
    if (!query.publisher.trimmed().isEmpty()) {
        add(QStringLiteral("publisher"), query.publisher.trimmed(),
            QStringLiteral("Publisher \"%1\"").arg(query.publisher.trimmed()));
    }
    return targets;
}

QString displaySubject(const ActivityQuery &query)
{
    if (!query.executableName.trimmed().isEmpty())
        return query.executableName.trimmed();
    if (!query.executablePath.trimmed().isEmpty())
        return QFileInfo(query.executablePath).fileName();
    if (!query.serviceName.trimmed().isEmpty())
        return QStringLiteral("service %1").arg(query.serviceName.trimmed());
    if (!query.displayName.trimmed().isEmpty())
        return query.displayName.trimmed();
    return QStringLiteral("this activity");
}

QString rateText(quint64 bytesPerSecond)
{
    const double kib = static_cast<double>(bytesPerSecond) / 1024.0;
    if (kib >= 1024.0)
        return QStringLiteral("%1 MiB/s").arg(kib / 1024.0, 0, 'f', 1);
    return QStringLiteral("%1 KiB/s").arg(kib, 0, 'f', 0);
}

} // namespace

bool ActivityClassification::isForegroundDownload() const
{
    return category == CatalogCategory::ForegroundDownload;
}

QString ActivityClassification::categoryName() const
{
    return catalogCategoryDisplayName(category);
}

QString ActivityClassification::confidenceName() const
{
    return AttributionConfidenceModel::displayName(assessment.confidence);
}

ActivityPolicyTarget ActivityClassification::preferredPolicyTarget() const
{
    return manualPolicyTargets.isEmpty() ? ActivityPolicyTarget()
                                         : manualPolicyTargets.first();
}

QString ActivityClassification::summary() const
{
    return isKnown()
        ? QStringLiteral("%1 (%2)").arg(categoryName(), confidenceName())
        : QStringLiteral("Unknown activity (%1)").arg(confidenceName());
}

ActivityClassifier::ActivityClassifier() = default;

ActivityClassifier::ActivityClassifier(const EndpointCatalog &catalog)
    : m_catalog(catalog)
{
}

void ActivityClassifier::setCatalog(const EndpointCatalog &catalog)
{
    m_catalog = catalog;
}

void ActivityClassifier::setForegroundDownloadThreshold(quint64 bytesPerSecond)
{
    m_foregroundThreshold = bytesPerSecond;
}

ActivityClassification ActivityClassifier::classify(const ActivityQuery &query) const
{
    ActivityClassification result;
    result.manualPolicyTargets = policyTargetsFor(query);

    const QList<CatalogMatch> matches = m_catalog.matches(toCatalogQuery(query));
    result.matchedRules = matches;

    if (!matches.isEmpty()) {
        // The catalog orders matches by specificity, so the first one decides
        // the category while every other match stays visible as evidence.
        const CatalogMatch best = matches.first();
        result.category = best.category;
        result.catalogMatched = true;

        AttributionConfidenceModel::CategoryEvidence category;
        category.catalogMatch = true;
        category.catalogCriteria = best.matchedOn.size();
        category.catalogRuleId = best.ruleId;
        category.exactExecutable = matchedOn(best, QStringLiteral("executable name was"));
        category.executableNameRule = category.exactExecutable;
        category.productMatched = matchedOn(best, QStringLiteral("product contained"));
        category.verifiedPublisher =
            query.publisherVerified && matchedOn(best, QStringLiteral("publisher contained"));
        category.activityGroup = !query.groupId.trimmed().isEmpty();
        category.activityGroupName = query.groupName;
        result.assessment = AttributionConfidenceModel::forCategory(category);

        result.evidence.append(
            QStringLiteral("Matched local rule \"%1\": %2 (%3).")
                .arg(best.ruleId,
                     best.explanation.trimmed().isEmpty()
                         ? catalogCategoryDisplayName(best.category)
                         : best.explanation.trimmed(),
                     best.matchedOn.join(QStringLiteral("; "))));

        if (matches.size() > 1) {
            QStringList others;
            for (int i = 1; i < matches.size(); ++i) {
                const CatalogMatch &other = matches.at(i);
                others.append(QStringLiteral("\"%1\" (%2)")
                                  .arg(other.ruleId,
                                       catalogCategoryDisplayName(other.category)));
            }
            result.evidence.append(
                QStringLiteral("Also matched %1; the most specific rule decided the "
                               "category.")
                    .arg(others.join(QStringLiteral(", "))));
        }

        for (const QString &detail : result.assessment.descriptions())
            result.evidence.append(detail);
        return result;
    }

    if (query.foreground && m_foregroundThreshold > 0 &&
        query.bytesPerSecond >= m_foregroundThreshold) {
        // No rule knows this application, but the foreground session plus a
        // sustained rate is enough to say it is a foreground download. It stays
        // a weak inference because the association itself is not observed.
        result.category = CatalogCategory::ForegroundDownload;

        AttributionConfidenceModel::Evidence foreground;
        foreground.kind = AttributionConfidenceModel::Evidence::Kind::ForegroundActivity;
        foreground.strength = AttributionConfidenceModel::Confidence::WeakInference;
        foreground.detail =
            QStringLiteral("The foreground application is transferring %1; the "
                           "category is an inference from the foreground session, "
                           "not an observed fact.")
                .arg(rateText(query.bytesPerSecond));
        result.assessment = AttributionConfidenceModel::aggregate({foreground});
        result.evidence = result.assessment.descriptions();
        return result;
    }

    AttributionConfidenceModel::CategoryEvidence unknown;
    unknown.metadataUnavailable = true;
    unknown.unavailableReason =
        QStringLiteral("No local rule matched %1.").arg(displaySubject(query));
    result.assessment = AttributionConfidenceModel::forCategory(unknown);
    result.evidence = result.assessment.descriptions();

    // Unclassified activity is still actionable: the user can scope a manual
    // policy to the executable, its group, its service, or its publisher.
    if (!result.manualPolicyTargets.isEmpty()) {
        result.evidence.append(
            QStringLiteral("It can still be scoped into a manual policy (%1).")
                .arg(result.preferredPolicyTarget().label));
    }
    return result;
}
