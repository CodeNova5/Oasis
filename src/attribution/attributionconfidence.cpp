/**
 * @file    attributionconfidence.cpp
 * @author  Oasis
 */
#include "attributionconfidence.h"

namespace {

int confidenceRank(AttributionConfidenceModel::Confidence confidence)
{
    switch (confidence) {
    case AttributionConfidenceModel::Confidence::Confirmed:       return 3;
    case AttributionConfidenceModel::Confidence::StrongInference: return 2;
    case AttributionConfidenceModel::Confidence::WeakInference:   return 1;
    case AttributionConfidenceModel::Confidence::Unknown:         break;
    }
    return 0;
}

void appendEvidence(QList<AttributionConfidenceModel::Evidence> &list,
                    AttributionConfidenceModel::Evidence::Kind kind,
                    AttributionConfidenceModel::Confidence strength,
                    const QString &detail)
{
    AttributionConfidenceModel::Evidence evidence;
    evidence.kind = kind;
    evidence.strength = strength;
    evidence.detail = detail;
    list.append(evidence);
}

} // namespace

QString AttributionConfidenceModel::displayName(Confidence confidence)
{
    switch (confidence) {
    case Confidence::Confirmed:       return QStringLiteral("Confirmed");
    case Confidence::StrongInference: return QStringLiteral("Likely");
    case Confidence::WeakInference:   return QStringLiteral("Possible");
    case Confidence::Unknown:         break;
    }
    return QStringLiteral("Unknown");
}

QString AttributionConfidenceModel::technicalName(Confidence confidence)
{
    switch (confidence) {
    case Confidence::Confirmed:       return QStringLiteral("confirmed");
    case Confidence::StrongInference: return QStringLiteral("strong inference");
    case Confidence::WeakInference:   return QStringLiteral("weak inference");
    case Confidence::Unknown:         break;
    }
    return QStringLiteral("unknown");
}

bool AttributionConfidenceModel::isCertain(Confidence confidence)
{
    return confidence == Confidence::Confirmed;
}

QString AttributionConfidenceModel::qualifiedText(const QString &text,
                                                  Confidence confidence)
{
    const QString value = text.trimmed();
    if (value.isEmpty()) return displayName(confidence);
    if (confidence == Confidence::Confirmed) return value;
    return QStringLiteral("%1: %2").arg(displayName(confidence), value);
}

QStringList AttributionConfidenceModel::Assessment::descriptions() const
{
    QStringList result;
    for (const Evidence &item : evidence) {
        if (!item.detail.trimmed().isEmpty()) result.append(item.detail.trimmed());
    }
    return result;
}

QString AttributionConfidenceModel::Assessment::summary() const
{
    const QStringList details = descriptions();
    if (details.isEmpty()) {
        return QStringLiteral("%1: no attribution evidence was available.")
            .arg(displayName(confidence));
    }
    return QStringLiteral("%1: %2").arg(displayName(confidence),
                                       details.join(QStringLiteral("; ")));
}

AttributionConfidenceModel::Assessment AttributionConfidenceModel::aggregate(
    const QList<Evidence> &evidence)
{
    Assessment result;
    result.evidence = evidence;
    for (const Evidence &item : evidence) {
        if (confidenceRank(item.strength) > confidenceRank(result.confidence)) {
            result.confidence = item.strength;
        }
    }
    return result;
}

AttributionConfidenceModel::Assessment AttributionConfidenceModel::forDomain(
    const DomainEvidence &evidence)
{
    QList<Evidence> list;
    const QString name = evidence.name.trimmed();
    const QString address = evidence.address.trimmed();

    if (!name.isEmpty()) {
        if (evidence.dnsAnswer) {
            appendEvidence(list, Evidence::Kind::DnsAnswer, Confidence::StrongInference,
                           address.isEmpty()
                               ? QStringLiteral("DNS answer named \"%1\".").arg(name)
                               : QStringLiteral("DNS answer associated \"%1\" with %2.")
                                     .arg(name, address));
        }
        if (evidence.tlsSni) {
            appendEvidence(list, Evidence::Kind::TlsSni, Confidence::StrongInference,
                           QStringLiteral("TLS ClientHello named \"%1\".").arg(name));
        }
        if (evidence.endpointCatalogMatch) {
            appendEvidence(list, Evidence::Kind::EndpointCatalog,
                           Confidence::WeakInference,
                           QStringLiteral("A local endpoint rule matched \"%1\".").arg(name));
        }
    } else if (evidence.metadataUnavailable) {
        appendEvidence(
            list, Evidence::Kind::UnavailableMetadata, Confidence::Unknown,
            evidence.unavailableReason.trimmed().isEmpty()
                ? QStringLiteral("TLS or DNS metadata was unavailable.")
                : evidence.unavailableReason.trimmed());
    } else {
        appendEvidence(list, Evidence::Kind::DirectAddress, Confidence::Unknown,
                       QStringLiteral("Only the destination address was observed; "
                                      "no domain name is known."));
    }

    Assessment result = aggregate(list);
    // Two independent observations of the same name confirm it. Either one
    // alone cannot: a DNS answer can be stale and a shared endpoint can serve
    // many names.
    if (!name.isEmpty() && evidence.dnsAnswer && evidence.tlsSni) {
        result.confidence = Confidence::Confirmed;
    }
    return result;
}

AttributionConfidenceModel::Assessment AttributionConfidenceModel::forCategory(
    const CategoryEvidence &evidence)
{
    QList<Evidence> list;

    if (evidence.protectedService) {
        appendEvidence(list, Evidence::Kind::ProtectedService, Confidence::Confirmed,
                       QStringLiteral("The traffic belongs to a protected Windows "
                                      "service or the kernel."));
    }
    if (evidence.userOverride) {
        appendEvidence(list, Evidence::Kind::UserOverride, Confidence::StrongInference,
                       QStringLiteral("A local user override selected this category."));
    }

    if (evidence.catalogMatch) {
        const bool strong = evidence.catalogCriteria >= 2 ||
                            (evidence.exactExecutable && evidence.verifiedPublisher);
        const QString source = evidence.catalogRuleId.trimmed().isEmpty()
            ? QStringLiteral("A local endpoint rule")
            : QStringLiteral("Catalog rule \"%1\"").arg(evidence.catalogRuleId.trimmed());
        appendEvidence(
            list, Evidence::Kind::EndpointCatalog,
            strong ? Confidence::StrongInference : Confidence::WeakInference,
            QStringLiteral("%1 matched %2 piece%3 of evidence.")
                .arg(source)
                .arg(evidence.catalogCriteria)
                .arg(evidence.catalogCriteria == 1 ? QString() : QStringLiteral("s")));
    } else if (evidence.verifiedPublisher && evidence.productMatched) {
        appendEvidence(list, Evidence::Kind::VerifiedPublisher,
                       Confidence::StrongInference,
                       QStringLiteral("A verified publisher and product metadata matched "
                                      "a known application."));
    }

    if (evidence.executableNameRule) {
        appendEvidence(list, Evidence::Kind::ExecutableName, Confidence::WeakInference,
                       QStringLiteral("The executable name matched a known rule."));
    }
    if (evidence.activityGroup) {
        appendEvidence(
            list, Evidence::Kind::ActivityGroup, Confidence::WeakInference,
            evidence.activityGroupName.trimmed().isEmpty()
                ? QStringLiteral("The category was learned from an activity group.")
                : QStringLiteral("The category was learned from activity group \"%1\".")
                      .arg(evidence.activityGroupName.trimmed()));
    }

    if (list.isEmpty()) {
        appendEvidence(list, Evidence::Kind::UnavailableMetadata, Confidence::Unknown,
                       evidence.metadataUnavailable &&
                               !evidence.unavailableReason.trimmed().isEmpty()
                           ? evidence.unavailableReason.trimmed()
                           : QStringLiteral("No category evidence was available."));
    }
    return aggregate(list);
}
