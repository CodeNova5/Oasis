/**
 * @file    attributionconfidence.h
 * @brief   Attribution confidence model (NG-035): turns evidence into
 *          Confirmed / Likely / Possible / Unknown and keeps the evidence text.
 * @author  Ali Sakkaf
 */
#pragma once

#include <QList>
#include <QString>
#include <QStringList>

#include "network/policy.h"

namespace AttributionConfidenceModel {

using Confidence = ApplicationIdentity::Confidence;

/**
 * Plain interface labels required by PRD.md 9.4. The technical names remain
 * available for diagnostics and persisted evidence.
 */
QString displayName(Confidence confidence);
QString technicalName(Confidence confidence);

/// `Confirmed` is the only state that may be shown as a fact. Every other state
/// is prefixed, so a weak inference cannot look like an observed fact.
bool isCertain(Confidence confidence);
QString qualifiedText(const QString &text, Confidence confidence);

/// One item of evidence and the strength it contributes.
struct Evidence
{
    enum class Kind {
        DnsAnswer,
        TlsSni,
        EndpointCatalog,
        ExecutableName,
        VerifiedPublisher,
        Service,
        ActivityGroup,
        UserOverride,
        ProtectedService,
        DirectAddress,
        UnavailableMetadata
    };

    Kind kind = Kind::UnavailableMetadata;
    Confidence strength = Confidence::Unknown;
    QString detail;
};

/// Aggregated confidence plus every contributing detail.
struct Assessment
{
    Confidence confidence = Confidence::Unknown;
    QList<Evidence> evidence;

    QStringList descriptions() const;
    QString summary() const;
};

/// Strongest evidence wins; Unknown evidence is retained for explanation.
Assessment aggregate(const QList<Evidence> &evidence);

/**
 * Domain evidence. A resolver answer and a visible TLS SNI are independent
 * observations; when both are present the name is confirmed. Either alone is a
 * strong inference, and an endpoint-catalog match without an observed name is
 * only a weak inference. A direct address with no name stays Unknown.
 */
struct DomainEvidence
{
    QString name;
    QString address;
    bool dnsAnswer = false;
    bool tlsSni = false;
    bool endpointCatalogMatch = false;
    bool metadataUnavailable = false;
    QString unavailableReason;
};

Assessment forDomain(const DomainEvidence &evidence);

/**
 * Category evidence. A protected service is directly observed; a catalog match
 * with at least two criteria, or an exact executable plus verified publisher, is
 * strong; a single-criterion catalog match, a name-only rule, or a category
 * learned from an activity group is weak. A user override is an explicit local
 * decision and is reported as strong rather than as an observed fact.
 */
struct CategoryEvidence
{
    bool protectedService = false;
    bool userOverride = false;
    bool catalogMatch = false;
    int catalogCriteria = 0;
    QString catalogRuleId;
    bool exactExecutable = false;
    bool verifiedPublisher = false;
    bool productMatched = false;
    bool executableNameRule = false;
    bool activityGroup = false;
    QString activityGroupName;
    bool metadataUnavailable = false;
    QString unavailableReason;
};

Assessment forCategory(const CategoryEvidence &evidence);

} // namespace AttributionConfidenceModel
