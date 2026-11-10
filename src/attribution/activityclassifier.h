/**
 * @file    activityclassifier.h
 * @brief   Rule-based activity classification (NG-040): turns process, identity,
 *          group, and destination evidence into a catalog category with the
 *          matched rules and confidence behind it.
 * @author  Ali Sakkaf
 *
 * The classifier is a decision aid. It has no policy action and no enforcement
 * channel, so a classification can never block, shape, or terminate traffic.
 */
#pragma once

#include <QList>
#include <QString>
#include <QStringList>

#include "attribution/attributionconfidence.h"
#include "attribution/endpointcatalog.h"

/**
 * Everything the classifier may consider for one observation. Empty fields
 * simply fail the criteria that ask for them; they never count as a match.
 *
 * `product` is the identity's product metadata and falls back to `displayName`
 * (which carries version metadata such as "Google Update") when empty.
 */
struct ActivityQuery
{
    // NG-010 to NG-014: identity, publisher, service, and activity-group evidence.
    QString identityId;
    QString displayName;
    QString publisher;
    QString product;
    QString executableName;
    QString executablePath;
    QString serviceName;
    QString groupId;
    QString groupName;
    bool service = false;
    bool publisherVerified = false;

    // NG-030/NG-032: destination evidence, when the caller has it.
    QString domain;
    QString remoteAddress;

    // Session facts. `foreground` is only ever set by a caller that actually
    // knows the answer (NG-041), never guessed here.
    bool foreground = false;
    quint64 bytesPerSecond = 0;
};

/**
 * A policy scope the user can act on for this activity. Present even when the
 * activity is unclassified, which is what keeps "unknown" usable for manual
 * policy creation.
 */
struct ActivityPolicyTarget
{
    QString scope;      // "path", "group", "service", "publisher"
    QString targetId;
    QString label;
};

/**
 * One classification. `category == CatalogCategory::Unknown` means no local
 * rule matched, not that the observation lacked evidence: `matchedRules` stays
 * empty, the assessment explains why, and `manualPolicyTargets` still names the
 * scopes the user can create a policy for.
 */
struct ActivityClassification
{
    CatalogCategory category = CatalogCategory::Unknown;
    bool catalogMatched = false;
    QList<CatalogMatch> matchedRules;
    AttributionConfidenceModel::Assessment assessment;
    QStringList evidence;
    QList<ActivityPolicyTarget> manualPolicyTargets;

    bool isKnown() const { return category != CatalogCategory::Unknown; }
    bool isForegroundDownload() const;
    QString categoryName() const;
    QString confidenceName() const;
    /// Best scope for a manual policy, or an empty target when nothing is known.
    ActivityPolicyTarget preferredPolicyTarget() const;
    /// e.g. "Browser update (Likely)" or "Unknown activity (Unknown)".
    QString summary() const;
};

class ActivityClassifier
{
public:
    /// Starts with the bundled catalog.
    ActivityClassifier();
    explicit ActivityClassifier(const EndpointCatalog &catalog);

    /// Replace the rule source, for example after the catalog was reloaded or
    /// an imported catalog was accepted.
    void setCatalog(const EndpointCatalog &catalog);
    const EndpointCatalog &catalog() const { return m_catalog; }

    /// A foreground application moving at least this rate is classified as a
    /// foreground download when no local rule matches it. The signal is
    /// advisory: it is a weak inference, never an observed fact. A threshold of
    /// 0 disables the foreground rule, so only catalog matches classify.
    static constexpr quint64 kForegroundDownloadBytesPerSecond = 256ULL * 1024ULL;
    quint64 foregroundDownloadThreshold() const { return m_foregroundThreshold; }
    void setForegroundDownloadThreshold(quint64 bytesPerSecond);

    ActivityClassification classify(const ActivityQuery &query) const;

private:
    EndpointCatalog m_catalog;
    quint64 m_foregroundThreshold = kForegroundDownloadBytesPerSecond;
};
