/**
 * @file    aicontext.cpp
 * @brief   Structured AI context (NG-044).
 * @author  Oasis
 */
#include "aicontext.h"

#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

#include "attribution/attributionprivacy.h"

namespace {

const int kNoLimit = 0;

/// One section-selection the bounding loop may try. Later shapes are strict
/// subsets of earlier ones, so the first shape that fits also gives an accurate
/// "truncated" list.
struct Shape
{
    int stringLimit;
    bool evidence;
    bool rules;
    bool destination;
    bool identityDetail;
};

/// Visible text, one line, no control characters. Every free-text field passes
/// through here so a newline in a display name cannot rewrite the payload.
QString plain(const QString &text)
{
    QString result;
    result.reserve(text.size());
    for (const QChar c : text) {
        if (c == QLatin1Char('\r') || c == QLatin1Char('\n')
            || c == QLatin1Char('\t')) {
            result.append(QLatin1Char(' '));
        } else if (c.isPrint()) {
            result.append(c);
        }
    }
    return result.trimmed();
}

QString shorten(const QString &text, int limit)
{
    if (limit <= 0 || text.size() <= limit) return text;
    if (limit <= 3) return text.left(limit);
    return text.left(limit - 3) + QStringLiteral("...");
}

QString sanitized(const QString &text, int limit)
{
    return shorten(plain(text), limit);
}

QString sanitizedDestination(const QString &text, int limit)
{
    return shorten(plain(AttributionPrivacy::redactDestination(text)), limit);
}

QString sanitizedFreeText(const QString &text, int limit)
{
    return shorten(plain(AttributionPrivacy::redactDestinationText(text)), limit);
}

QStringList sanitizedList(const QStringList &values, int maxEntries, int limit,
                          bool redact, int *dropped)
{
    QStringList result;
    int skipped = 0;
    for (const QString &value : values) {
        const QString cleaned =
            redact ? sanitizedFreeText(value, limit) : sanitized(value, limit);
        if (cleaned.isEmpty()) continue;
        if (result.size() >= maxEntries) {
            ++skipped;
            continue;
        }
        result.append(cleaned);
    }
    if (dropped) *dropped = skipped;
    return result;
}

/// The context with every string sanitised; `limit` also shortens each value.
struct View
{
    QString identityId;
    QString displayName;
    QString executableName;
    QString publisher;
    bool publisherVerified = false;
    QString serviceName;
    QString groupName;

    QString categoryToken;
    QString categoryName;
    QString confidenceToken;
    bool confidenceIsCertain = false;
    QStringList rules;
    QStringList evidence;
    int droppedRules = 0;
    int droppedEvidence = 0;

    quint64 bytesPerSecond = 0;
    bool foreground = false;
    bool meteredConnection = false;
    QString destination;

    QString recommendedAction;
    quint64 suggestedRateBitsPerSecond = 0;
    QString policyScope;

    QDateTime generatedAt;
};

View sanitizedView(const AiContext &context, int limit)
{
    View view;
    view.identityId = sanitized(context.identityId, limit);
    view.displayName = sanitizedFreeText(context.displayName, limit);
    view.executableName = sanitizedFreeText(context.executableName, limit);
    view.publisher = sanitizedFreeText(context.publisher, limit);
    view.publisherVerified = context.publisherVerified;
    view.serviceName = sanitizedFreeText(context.serviceName, limit);
    view.groupName = sanitizedFreeText(context.groupName, limit);

    view.categoryToken = sanitized(context.categoryToken, limit);
    view.categoryName = sanitizedFreeText(context.categoryName, limit);
    view.confidenceToken = sanitized(context.confidenceToken, limit);
    view.confidenceIsCertain = context.confidenceIsCertain;
    view.rules = sanitizedList(context.matchedRuleIds, AiContext::kMaxRuleIds,
                               limit, false, &view.droppedRules);
    view.evidence = sanitizedList(context.evidence, AiContext::kMaxEvidenceEntries,
                                  limit, true, &view.droppedEvidence);

    view.bytesPerSecond = context.bytesPerSecond;
    view.foreground = context.foreground;
    view.meteredConnection = context.meteredConnection;
    view.destination = sanitizedDestination(context.destination, limit);

    view.recommendedAction = sanitized(context.recommendedAction, limit);
    view.suggestedRateBitsPerSecond = context.suggestedRateBitsPerSecond;
    view.policyScope = sanitized(context.policyScope, limit);

    view.generatedAt = context.generatedAt;
    return view;
}

/// Dotted paths of every expected field the view does not carry.
QStringList unknownFieldNames(const View &view)
{
    QStringList names;
    if (view.identityId.isEmpty()) names << QStringLiteral("identity.id");
    if (view.displayName.isEmpty()) names << QStringLiteral("identity.name");
    if (view.executableName.isEmpty()) names << QStringLiteral("identity.executable");
    if (view.publisher.isEmpty()) names << QStringLiteral("identity.publisher");
    if (view.serviceName.isEmpty()) names << QStringLiteral("identity.service");
    if (view.groupName.isEmpty()) names << QStringLiteral("identity.group");
    if (view.rules.isEmpty()) names << QStringLiteral("classification.rules");
    if (view.evidence.isEmpty()) names << QStringLiteral("classification.evidence");
    if (view.destination.isEmpty()) names << QStringLiteral("activity.destination");
    if (view.suggestedRateBitsPerSecond == 0)
        names << QStringLiteral("recommendation.suggestedRateBitsPerSecond");
    if (view.policyScope.isEmpty()) names << QStringLiteral("recommendation.policyScope");
    return names;
}

QStringList truncatedFieldNames(const View &full, const View &shortened,
                                const Shape &shape)
{
    QStringList names;
    auto add = [&names](const QString &name) {
        if (!names.contains(name)) names << name;
    };

    if (!shape.identityDetail) {
        if (!full.publisher.isEmpty()) add(QStringLiteral("identity.publisher"));
        if (full.publisherVerified) add(QStringLiteral("identity.publisherVerified"));
        if (!full.serviceName.isEmpty()) add(QStringLiteral("identity.service"));
        if (!full.groupName.isEmpty()) add(QStringLiteral("identity.group"));
    }
    if (!shape.rules && !full.rules.isEmpty())
        add(QStringLiteral("classification.rules"));
    else if (shape.rules && full.droppedRules > 0)
        add(QStringLiteral("classification.rules"));
    if (!shape.evidence && !full.evidence.isEmpty())
        add(QStringLiteral("classification.evidence"));
    else if (shape.evidence && full.droppedEvidence > 0)
        add(QStringLiteral("classification.evidence"));
    if (!shape.destination && !full.destination.isEmpty())
        add(QStringLiteral("activity.destination"));

    // A value that the shorter per-field cap changed is reported too, so a
    // shortened string is never mistaken for the whole value.
    auto changed = [&add](const QString &name, const QString &before,
                          const QString &after) {
        if (before != after) add(name);
    };
    changed(QStringLiteral("identity.id"), full.identityId, shortened.identityId);
    changed(QStringLiteral("identity.name"), full.displayName, shortened.displayName);
    changed(QStringLiteral("identity.executable"), full.executableName,
            shortened.executableName);
    changed(QStringLiteral("identity.publisher"), full.publisher, shortened.publisher);
    changed(QStringLiteral("identity.service"), full.serviceName, shortened.serviceName);
    changed(QStringLiteral("identity.group"), full.groupName, shortened.groupName);
    changed(QStringLiteral("classification.categoryName"), full.categoryName,
            shortened.categoryName);
    changed(QStringLiteral("activity.destination"), full.destination,
            shortened.destination);
    changed(QStringLiteral("recommendation.policyScope"), full.policyScope,
            shortened.policyScope);

    auto changedList = [&add](const QString &name, const QStringList &before,
                              const QStringList &after) {
        if (before == after) return;
        add(name);
    };
    changedList(QStringLiteral("classification.rules"), full.rules, shortened.rules);
    changedList(QStringLiteral("classification.evidence"), full.evidence,
                shortened.evidence);
    return names;
}

QJsonObject serializedObject(const View &view, const QStringList &unknown,
                             const QStringList &truncated, const Shape &shape)
{
    QJsonObject root;
    root[QStringLiteral("schemaVersion")] = AiContext::kSchemaVersion;
    root[QStringLiteral("format")] = AiContext::formatToken();
    if (view.generatedAt.isValid()) {
        root[QStringLiteral("generatedAt")] =
            view.generatedAt.toUTC().toString(Qt::ISODate);
    }

    QJsonObject identity;
    if (!view.identityId.isEmpty())
        identity[QStringLiteral("id")] = view.identityId;
    if (!view.displayName.isEmpty())
        identity[QStringLiteral("name")] = view.displayName;
    if (!view.executableName.isEmpty())
        identity[QStringLiteral("executable")] = view.executableName;
    if (shape.identityDetail) {
        if (!view.publisher.isEmpty()) {
            identity[QStringLiteral("publisher")] = view.publisher;
            identity[QStringLiteral("publisherVerified")] = view.publisherVerified;
        }
        if (!view.serviceName.isEmpty())
            identity[QStringLiteral("service")] = view.serviceName;
        if (!view.groupName.isEmpty())
            identity[QStringLiteral("group")] = view.groupName;
    }
    if (!identity.isEmpty()) root[QStringLiteral("identity")] = identity;

    QJsonObject classification;
    classification[QStringLiteral("category")] =
        view.categoryToken.isEmpty() ? QStringLiteral("unknown") : view.categoryToken;
    if (!view.categoryName.isEmpty())
        classification[QStringLiteral("categoryName")] = view.categoryName;
    classification[QStringLiteral("confidence")] =
        view.confidenceToken.isEmpty() ? QStringLiteral("unknown")
                                       : view.confidenceToken;
    classification[QStringLiteral("confidenceIsCertain")] = view.confidenceIsCertain;
    if (shape.rules && !view.rules.isEmpty())
        classification[QStringLiteral("rules")] = QJsonArray::fromStringList(view.rules);
    if (shape.evidence && !view.evidence.isEmpty()) {
        classification[QStringLiteral("evidence")] =
            QJsonArray::fromStringList(view.evidence);
    }
    root[QStringLiteral("classification")] = classification;

    QJsonObject activity;
    activity[QStringLiteral("bytesPerSecond")] =
        static_cast<qint64>(view.bytesPerSecond);
    activity[QStringLiteral("foreground")] = view.foreground;
    activity[QStringLiteral("metered")] = view.meteredConnection;
    if (shape.destination && !view.destination.isEmpty())
        activity[QStringLiteral("destination")] = view.destination;
    root[QStringLiteral("activity")] = activity;

    QJsonObject recommendation;
    recommendation[QStringLiteral("action")] =
        view.recommendedAction.isEmpty() ? QStringLiteral("no-action")
                                         : view.recommendedAction;
    if (view.suggestedRateBitsPerSecond > 0) {
        recommendation[QStringLiteral("suggestedRateBitsPerSecond")] =
            static_cast<qint64>(view.suggestedRateBitsPerSecond);
    }
    if (!view.policyScope.isEmpty())
        recommendation[QStringLiteral("policyScope")] = view.policyScope;
    root[QStringLiteral("recommendation")] = recommendation;

    root[QStringLiteral("unknown")] = QJsonArray::fromStringList(unknown);
    if (!truncated.isEmpty())
        root[QStringLiteral("truncated")] = QJsonArray::fromStringList(truncated);

    return root;
}

QString compactJson(const QJsonObject &object)
{
    return QString::fromUtf8(
        QJsonDocument(object).toJson(QJsonDocument::Compact));
}

QString boundedText(const QJsonValue &value)
{
    return shorten(plain(value.toString()), AiContext::kMaxStringLength);
}

QStringList boundedList(const QJsonValue &value, int maxEntries)
{
    QStringList result;
    if (!value.isArray()) return result;
    const QJsonArray array = value.toArray();
    for (const QJsonValue &entry : array) {
        if (!entry.isString()) continue;
        const QString cleaned = boundedText(entry);
        if (cleaned.isEmpty()) continue;
        if (result.size() >= maxEntries) break;
        result.append(cleaned);
    }
    return result;
}

QString formatBytesPerSecond(quint64 bytesPerSecond)
{
    const double kib = 1024.0;
    if (bytesPerSecond >= 1024ULL * 1024ULL * 1024ULL) {
        return QStringLiteral("%1 GiB/s")
            .arg(bytesPerSecond / (kib * kib * kib), 0, 'f', 1);
    }
    if (bytesPerSecond >= 1024ULL * 1024ULL) {
        return QStringLiteral("%1 MiB/s")
            .arg(bytesPerSecond / (kib * kib), 0, 'f', 1);
    }
    if (bytesPerSecond >= 1024ULL) {
        return QStringLiteral("%1 KiB/s").arg(bytesPerSecond / kib, 0, 'f', 1);
    }
    return QStringLiteral("%1 B/s").arg(bytesPerSecond);
}

QString formatBitsPerSecond(quint64 bitsPerSecond)
{
    if (bitsPerSecond >= 1000000ULL) {
        return QStringLiteral("%1 Mbit/s").arg(bitsPerSecond / 1000000.0, 0, 'f', 1);
    }
    if (bitsPerSecond >= 1000ULL) {
        return QStringLiteral("%1 kbit/s").arg(bitsPerSecond / 1000.0, 0, 'f', 1);
    }
    return QStringLiteral("%1 bit/s").arg(bitsPerSecond);
}

} // namespace

// ─── AiContextPayload ──────────────────────────────────────────────────────

int AiContextPayload::bytes() const
{
    return json.toUtf8().size();
}

bool AiContextPayload::fits() const
{
    return bytes() <= AiContext::kMaxBytes;
}

// ─── AiContext ─────────────────────────────────────────────────────────────

QString AiContext::formatToken()
{
    return QStringLiteral("oasis.ai-context");
}

bool AiContext::isEmpty() const
{
    return identityId.isEmpty() && displayName.isEmpty()
        && executableName.isEmpty() && categoryToken.isEmpty()
        && destination.isEmpty();
}

QStringList AiContext::unknownFields() const
{
    return unknownFieldNames(sanitizedView(*this, kNoLimit));
}

AiContext AiContext::forRecommendation(const RecommendationContext &context,
                                       const Recommendation &recommendation)
{
    AiContext out;
    out.generatedAt = QDateTime::currentDateTimeUtc();

    const ActivityQuery &query = context.observation;
    out.identityId = query.identityId;
    out.displayName = query.displayName;
    out.executableName = query.executableName;
    // A full path is never part of the context, so keep only the base name.
    if (out.executableName.isEmpty() && !query.executablePath.isEmpty())
        out.executableName = QFileInfo(query.executablePath).fileName();
    out.publisher = query.publisher;
    out.publisherVerified = query.publisherVerified;
    out.serviceName = query.serviceName;
    out.groupName = query.groupName;

    out.categoryToken = catalogCategoryToken(recommendation.category);
    out.categoryName = catalogCategoryDisplayName(recommendation.category);
    out.confidenceToken =
        AttributionConfidenceModel::technicalName(recommendation.assessment.confidence);
    out.confidenceIsCertain =
        AttributionConfidenceModel::isCertain(recommendation.assessment.confidence);

    for (const CatalogMatch &match : context.activity.matchedRules) {
        if (match.ruleId.isEmpty()) continue;
        if (!out.matchedRuleIds.contains(match.ruleId))
            out.matchedRuleIds.append(match.ruleId);
    }
    out.evidence = context.activity.evidence;

    out.bytesPerSecond = context.bytesPerSecond;
    out.foreground = context.foreground;
    out.meteredConnection = context.meteredConnection;

    const QString destination =
        query.domain.isEmpty() ? query.remoteAddress : query.domain;
    // NG-036 redaction: the context carries enough to correlate the activity,
    // never where the user went.
    out.destination = AttributionPrivacy::redactDestination(destination);

    out.recommendedAction = recommendationActionToken(recommendation.action);
    if (recommendation.hasSuggestedPolicy()) {
        out.suggestedRateBitsPerSecond =
            recommendation.suggestedPolicy.rateBitsPerSecond;
        // The scope is a token ("path", "group", ...). The target id can be an
        // absolute path, so it is deliberately not copied.
        out.policyScope = recommendation.suggestedPolicy.scope;
    }
    return out;
}

AiContextPayload AiContext::boundedJson() const
{
    static const Shape shapes[] = {
        // Full context: every optional field, each capped at kMaxStringLength.
        {kMaxStringLength, true, true, true, true},
        // Drop the evidence text first; the classification itself remains.
        {kMaxStringLength, false, true, true, true},
        {kMaxStringLength, false, false, true, true},
        {kMaxStringLength, false, false, false, true},
        // Then shorten what is left, then drop the secondary identity fields.
        {64, false, false, false, true},
        {32, false, false, false, false},
    };

    const View full = sanitizedView(*this, kNoLimit);
    const QStringList unknown = unknownFieldNames(full);

    for (const Shape &shape : shapes) {
        const View view = sanitizedView(*this, shape.stringLimit);
        const QStringList truncated = truncatedFieldNames(full, view, shape);
        const QString json = compactJson(serializedObject(view, unknown, truncated, shape));
        if (json.toUtf8().size() <= kMaxBytes)
            return AiContextPayload{json, truncated};
    }

    // Last resort: the section list alone. A few hundred bytes at most, so the
    // limit always holds even for a pathological caller.
    QJsonObject root;
    root[QStringLiteral("schemaVersion")] = kSchemaVersion;
    root[QStringLiteral("format")] = formatToken();
    root[QStringLiteral("unknown")] = QJsonArray::fromStringList(unknown);
    root[QStringLiteral("truncated")] = QJsonArray::fromStringList(
        {QStringLiteral("identity"), QStringLiteral("classification"),
         QStringLiteral("activity"), QStringLiteral("recommendation")});
    return AiContextPayload{
        compactJson(root),
        {QStringLiteral("identity"), QStringLiteral("classification"),
         QStringLiteral("activity"), QStringLiteral("recommendation")}};
}

QString AiContext::toJson() const
{
    return boundedJson().json;
}

AiContext AiContext::fromJson(const QString &json, bool *ok)
{
    AiContext context;
    if (ok) *ok = false;

    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8());
    if (!document.isObject()) return context;
    const QJsonObject root = document.object();

    if (root.value(QStringLiteral("format")).toString() != formatToken())
        return context;

    // A newer schema may give an existing field a new meaning; reject it as a
    // whole instead of presenting a payload the local rules did not produce.
    const int schemaVersion =
        root.value(QStringLiteral("schemaVersion")).toInt(kSchemaVersion);
    if (schemaVersion > kSchemaVersion) return context;

    const QJsonObject identity = root.value(QStringLiteral("identity")).toObject();
    context.identityId = boundedText(identity.value(QStringLiteral("id")));
    context.displayName = boundedText(identity.value(QStringLiteral("name")));
    context.executableName = boundedText(identity.value(QStringLiteral("executable")));
    context.publisher = boundedText(identity.value(QStringLiteral("publisher")));
    context.publisherVerified =
        identity.value(QStringLiteral("publisherVerified")).toBool(false);
    context.serviceName = boundedText(identity.value(QStringLiteral("service")));
    context.groupName = boundedText(identity.value(QStringLiteral("group")));

    const QJsonObject classification =
        root.value(QStringLiteral("classification")).toObject();
    context.categoryToken = boundedText(classification.value(QStringLiteral("category")));
    context.categoryName =
        boundedText(classification.value(QStringLiteral("categoryName")));
    context.confidenceToken =
        boundedText(classification.value(QStringLiteral("confidence")));
    context.confidenceIsCertain =
        classification.value(QStringLiteral("confidenceIsCertain")).toBool(false);
    context.matchedRuleIds =
        boundedList(classification.value(QStringLiteral("rules")), kMaxRuleIds);
    context.evidence =
        boundedList(classification.value(QStringLiteral("evidence")), kMaxEvidenceEntries);

    const QJsonObject activity = root.value(QStringLiteral("activity")).toObject();
    context.bytesPerSecond = static_cast<quint64>(
        activity.value(QStringLiteral("bytesPerSecond")).toDouble());
    context.foreground = activity.value(QStringLiteral("foreground")).toBool(false);
    context.meteredConnection = activity.value(QStringLiteral("metered")).toBool(false);
    context.destination =
        boundedText(activity.value(QStringLiteral("destination")));

    const QJsonObject recommendation =
        root.value(QStringLiteral("recommendation")).toObject();
    context.recommendedAction =
        boundedText(recommendation.value(QStringLiteral("action")));
    context.suggestedRateBitsPerSecond = static_cast<quint64>(
        recommendation.value(QStringLiteral("suggestedRateBitsPerSecond")).toDouble());
    context.policyScope =
        boundedText(recommendation.value(QStringLiteral("policyScope")));

    // Stored with a trailing Z, so the parsed value already carries UTC.
    context.generatedAt =
        QDateTime::fromString(root.value(QStringLiteral("generatedAt")).toString(),
                              Qt::ISODate)
            .toUTC();

    if (ok) *ok = true;
    return context;
}

QStringList AiContext::previewLines() const
{
    const AiContextPayload payload = boundedJson();
    const View view = sanitizedView(*this, kMaxStringLength);

    QStringList lines;
    lines << QStringLiteral("Context %1 (schema %2)")
                 .arg(formatToken())
                 .arg(kSchemaVersion);
    if (view.generatedAt.isValid()) {
        lines << QStringLiteral("Generated: %1")
                     .arg(view.generatedAt.toUTC().toString(Qt::ISODate));
    }

    QStringList identity;
    if (!view.displayName.isEmpty()) identity << view.displayName;
    if (!view.executableName.isEmpty())
        identity << QStringLiteral("(%1)").arg(view.executableName);
    if (!view.publisher.isEmpty()) {
        identity << QStringLiteral("published by %1%2")
                        .arg(view.publisher,
                             view.publisherVerified ? QStringLiteral(" (verified)")
                                                    : QString());
    }
    if (!view.serviceName.isEmpty())
        identity << QStringLiteral("service %1").arg(view.serviceName);
    if (!view.groupName.isEmpty())
        identity << QStringLiteral("group %1").arg(view.groupName);
    if (!view.identityId.isEmpty())
        identity << QStringLiteral("identity %1").arg(view.identityId);
    if (!identity.isEmpty())
        lines << QStringLiteral("Identity: ") + identity.join(QLatin1Char(' '));

    lines << QStringLiteral("Classification: %1, confidence %2%3")
                 .arg(view.categoryName.isEmpty() ? QStringLiteral("Unknown activity")
                                                  : view.categoryName,
                      view.confidenceToken.isEmpty() ? QStringLiteral("unknown")
                                                     : view.confidenceToken,
                      view.confidenceIsCertain
                          ? QStringLiteral(" (observed)")
                          : QStringLiteral(" (not a fact)"));

    if (!view.rules.isEmpty())
        lines << QStringLiteral("Matched rules: ") + view.rules.join(QStringLiteral(", "));
    if (!view.evidence.isEmpty())
        lines << QStringLiteral("Evidence: ") + view.evidence.join(QStringLiteral("; "));

    QStringList activity;
    activity << formatBytesPerSecond(view.bytesPerSecond);
    activity << (view.foreground ? QStringLiteral("foreground")
                                 : QStringLiteral("not foreground"));
    activity << (view.meteredConnection ? QStringLiteral("metered connection")
                                        : QStringLiteral("not metered"));
    activity << (view.destination.isEmpty()
                     ? QStringLiteral("destination unknown")
                     : QStringLiteral("destination %1").arg(view.destination));
    lines << QStringLiteral("Observed: ") + activity.join(QStringLiteral(", "));

    QString recommendation = view.recommendedAction.isEmpty()
        ? QStringLiteral("no action")
        : view.recommendedAction;
    if (!view.policyScope.isEmpty())
        recommendation += QStringLiteral(", scope ") + view.policyScope;
    if (view.suggestedRateBitsPerSecond > 0) {
        recommendation += QStringLiteral(", suggested ")
            + formatBitsPerSecond(view.suggestedRateBitsPerSecond);
    }
    lines << QStringLiteral("Recommendation: ") + recommendation;

    const QStringList unknown = unknownFields();
    if (!unknown.isEmpty()) {
        lines << QStringLiteral("Not included (unknown): ")
                     + unknown.join(QStringLiteral(", "));
    }
    if (!payload.truncatedFields.isEmpty()) {
        lines << QStringLiteral("Shortened for the %1-byte limit: ").arg(kMaxBytes)
                     + payload.truncatedFields.join(QStringLiteral(", "));
    }
    lines << QStringLiteral("Payload: %1 of %2 bytes")
                 .arg(payload.bytes())
                 .arg(kMaxBytes);
    return lines;
}

QString AiContext::previewText() const
{
    return previewLines().join(QLatin1Char('\n'));
}
