/**
 * @file    aicontext.h
 * @brief   Structured AI context (NG-044): a versioned, redacted, size-limited
 *          snapshot that a future optional AI provider would receive.
 * @author  Oasis
 *
 * The payload is metadata only. It carries an application's identity
 * attributes, its activity classification with the matched local rules, an
 * aggregate rate, and a redacted destination token — never a packet payload, a
 * full file path, a raw host name, or an address. Destinations are redacted
 * with the NG-036 helpers, so a name keeps only its top-level label and an
 * address literal keeps only its network part.
 *
 * The schema is explicit about what it does not know: `unknownFields()` names
 * every expected field the caller could not supply, and that list is serialised
 * under "unknown". Fields dropped or shortened to satisfy the byte limit are
 * listed separately under "truncated", so an omitted field is never confused
 * with a field the application simply did not observe.
 *
 * `boundedJson()` is the exact payload; nothing else is ever sent. `previewText()`
 * renders the same context for a review screen, where the user can inspect it
 * before deciding whether to send anything.
 */
#pragma once

#include <QDateTime>
#include <QString>
#include <QStringList>

#include "attribution/activityclassifier.h"
#include "attribution/recommendationengine.h"

struct AiContextPayload
{
    QString json;              ///< The exact bounded payload, one JSON object.
    QStringList truncatedFields; ///< Field paths shortened or omitted for size.

    int bytes() const;
    bool fits() const;
};

struct AiContext
{
    /// Bumped when a field is removed, renamed, or changes meaning.
    static constexpr int kSchemaVersion = 1;
    /// Hard ceiling on `json`. Bounding shortens optional fields, then drops
    /// evidence, rules, the destination, and identity detail, in that order,
    /// until the payload fits.
    static constexpr int kMaxBytes = 4096;
    /// Longest single string value; longer text is shortened, not rejected.
    static constexpr int kMaxStringLength = 256;
    static constexpr int kMaxEvidenceEntries = 8;
    static constexpr int kMaxRuleIds = 8;

    /// Stable document marker, so a reader can tell this payload from another
    /// JSON object that happens to carry a schemaVersion.
    static QString formatToken();

    // ─── Identity metadata (NG-010 to NG-014) ───────────────────────────────
    QString identityId;      ///< Durable local identity, never a path.
    QString displayName;
    QString executableName;  ///< Base name only: no directory, no user name.
    QString publisher;
    bool publisherVerified = false;
    QString serviceName;
    QString groupName;

    // ─── Classification metadata (NG-040) ──────────────────────────────────
    QString categoryToken;
    QString categoryName;
    QString confidenceToken;
    bool confidenceIsCertain = false;
    QStringList matchedRuleIds;
    QStringList evidence;    ///< Redacted free text; no destinations.

    // ─── Aggregate activity (no per-packet detail) ─────────────────────────
    quint64 bytesPerSecond = 0;
    bool foreground = false;
    bool meteredConnection = false;
    QString destination;     ///< Already redacted: "***.com" or "10.0.0.x".

    // ─── Recommendation metadata (NG-042) ──────────────────────────────────
    QString recommendedAction;   ///< Token, e.g. "throttle".
    quint64 suggestedRateBitsPerSecond = 0;
    QString policyScope;         ///< Scope token only; the target id is omitted.

    QDateTime generatedAt;

    bool isEmpty() const;

    /// Every expected field the context does not carry, as dotted paths
    /// ("identity.publisher", "activity.destination", ...).
    QStringList unknownFields() const;

    /// Build from a local classification and recommendation. The suggested
    /// policy's scope token is copied, but never its target id, which can be an
    /// absolute path.
    static AiContext forRecommendation(const RecommendationContext &context,
                                       const Recommendation &recommendation);

    /// The exact payload after sanitising and bounding. Always at most
    /// kMaxBytes, and always safe to show: destinations are redacted and control
    /// characters are removed even if a caller assigned fields directly.
    AiContextPayload boundedJson() const;
    QString toJson() const;

    /// Read back a payload for inspection. A malformed document, or one written
    /// by a newer schema, is rejected as a whole (`ok` is false).
    static AiContext fromJson(const QString &json, bool *ok = nullptr);

    /// Human-readable review of what would be sent, one line per fact, ending
    /// with the payload size against the limit.
    QStringList previewLines() const;
    QString previewText() const;
};
