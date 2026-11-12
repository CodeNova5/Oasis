/**
 * @file   evidenceexport.cpp
 * @brief  Audit and attribution export formats (NG-055).
 * @author Codebuff
 */

#include "evidenceexport.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "attribution/attributionprivacy.h"

namespace {

QString exportTimestamp(const QString &exportedAt)
{
    if (!exportedAt.isEmpty())
        return exportedAt;
    return QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
}

// A redacted event must not leak a destination through a field the export
// copies verbatim, so every free-text field goes through the NG-036 redactor.
AuditEvent redactedEvent(const AuditEvent &event)
{
    AuditEvent copy = event;
    copy.scope = AttributionPrivacy::redactDestinationText(copy.scope);
    copy.reason = AttributionPrivacy::redactDestinationText(copy.reason);
    copy.result = AttributionPrivacy::redactDestinationText(copy.result);
    copy.errorInfo = AttributionPrivacy::redactDestinationText(copy.errorInfo);
    copy.details = AttributionPrivacy::redactDestinationText(copy.details);
    return copy;
}

QJsonObject attributionObject(const DestinationNameSummary &summary, bool redact)
{
    QStringList names;
    for (const QString &name : summary.names)
        names.append(EvidenceExport::exportName(name, redact));

    QStringList evidence = summary.evidence;
    if (redact) {
        evidence.clear();
        for (const QString &line : summary.evidence)
            evidence.append(AttributionPrivacy::redactDestinationText(line));
    }

    QJsonObject object;
    object[QStringLiteral("address")]    = EvidenceExport::exportAddress(summary.address, redact);
    object[QStringLiteral("name")]       = EvidenceExport::exportName(summary.name, redact);
    object[QStringLiteral("names")]      = QJsonArray::fromStringList(names);
    object[QStringLiteral("source")]     = attributionSourceName(summary.source);
    object[QStringLiteral("confidence")] = EvidenceExport::confidenceName(summary.confidence);
    object[QStringLiteral("expiresAt")]  = summary.expiresAt.isValid()
        ? summary.expiresAt.toString(Qt::ISODate)
        : QString();
    object[QStringLiteral("evidence")]   = QJsonArray::fromStringList(evidence);
    return object;
}

QString metadataLines(const QString &format, const QString &exportedAt, bool redact)
{
    QString text;
    text += QStringLiteral("# format %1\n").arg(format);
    text += QStringLiteral("# schemaVersion %1\n").arg(EvidenceExport::kSchemaVersion);
    text += QStringLiteral("# exportedAt %1\n").arg(exportedAt);
    text += QStringLiteral("# redacted %1\n")
                .arg(redact ? QStringLiteral("true") : QStringLiteral("false"));
    return text;
}

} // namespace

namespace EvidenceExport {

QString csvField(const QString &value)
{
    const bool needsQuotes = value.contains(QLatin1Char(',')) ||
                             value.contains(QLatin1Char('"')) ||
                             value.contains(QLatin1Char('\n')) ||
                             value.contains(QLatin1Char('\r')) ||
                             value.startsWith(QLatin1Char(' ')) ||
                             value.endsWith(QLatin1Char(' '));
    if (!needsQuotes) return value;

    QString escaped = value;
    escaped.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    return QLatin1Char('"') + escaped + QLatin1Char('"');
}

QString csvRow(const QStringList &values)
{
    QStringList fields;
    fields.reserve(values.size());
    for (const QString &value : values)
        fields.append(csvField(value));
    return fields.join(QLatin1Char(',')) + QLatin1Char('\n');
}

QString confidenceName(ApplicationIdentity::Confidence confidence)
{
    switch (confidence) {
    case ApplicationIdentity::Confidence::Confirmed:       return QStringLiteral("confirmed");
    case ApplicationIdentity::Confidence::StrongInference: return QStringLiteral("strong inference");
    case ApplicationIdentity::Confidence::WeakInference:   return QStringLiteral("weak inference");
    case ApplicationIdentity::Confidence::Unknown:         break;
    }
    return QStringLiteral("unknown");
}

QString exportAddress(const QString &address, bool redactDestinations)
{
    if (!redactDestinations || address.isEmpty()) return address;
    // An address that is not a literal is either already absent or a name, and
    // redactDestination() leaves non-destinations alone in both cases.
    return AttributionPrivacy::redactDestination(address);
}

QString exportName(const QString &name, bool redactDestinations)
{
    if (!redactDestinations || name.isEmpty()) return name;
    return AttributionPrivacy::redactDestination(name);
}

QString auditJson(const QList<AuditEvent> &events,
                  const AuditRetentionSettings &retention,
                  bool redactDestinations,
                  const QString &exportedAt)
{
    QJsonArray exported;
    for (const AuditEvent &event : events) {
        exported.append(auditEventToObject(redactDestinations ? redactedEvent(event) : event));
    }

    QJsonObject retentionObject;
    retentionObject[QStringLiteral("days")]      = retention.retentionDays;
    retentionObject[QStringLiteral("maxEvents")] = retention.maxEvents;

    QJsonObject root;
    root[QStringLiteral("format")]        = QLatin1String(AuditStore::kFormat);
    root[QStringLiteral("schemaVersion")] = AuditStore::kSchemaVersion;
    root[QStringLiteral("exportedAt")]    = exportTimestamp(exportedAt);
    root[QStringLiteral("redacted")]      = redactDestinations;
    root[QStringLiteral("retention")]     = retentionObject;
    root[QStringLiteral("count")]         = exported.size();
    root[QStringLiteral("events")]        = exported;

    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

QString auditCsv(const QList<AuditEvent> &events,
                 bool redactDestinations,
                 const QString &exportedAt)
{
    QString text = metadataLines(QLatin1String(AuditStore::kFormat),
                                 exportTimestamp(exportedAt), redactDestinations);
    text += csvRow({QStringLiteral("timestamp"), QStringLiteral("type"),
                    QStringLiteral("scope"), QStringLiteral("reason"),
                    QStringLiteral("result"), QStringLiteral("errorInfo"),
                    QStringLiteral("relatedIdentityId"), QStringLiteral("relatedPolicyId"),
                    QStringLiteral("details")});

    for (const AuditEvent &source : events) {
        const AuditEvent event = redactDestinations ? redactedEvent(source) : source;
        text += csvRow({event.timestamp.toString(Qt::ISODateWithMs),
                        auditEventTypeName(event.type),
                        event.scope,
                        event.reason,
                        event.result,
                        event.errorInfo,
                        event.relatedIdentityId,
                        event.relatedPolicyId,
                        event.details});
    }
    return text;
}

QString attributionJson(const QList<DestinationNameSummary> &destinations,
                        bool redactDestinations,
                        const QString &exportedAt)
{
    QJsonArray rows;
    for (const DestinationNameSummary &summary : destinations)
        rows.append(attributionObject(summary, redactDestinations));

    QJsonObject root;
    root[QStringLiteral("format")]        = QLatin1String(kAttributionFormat);
    root[QStringLiteral("schemaVersion")] = kSchemaVersion;
    root[QStringLiteral("exportedAt")]    = exportTimestamp(exportedAt);
    root[QStringLiteral("redacted")]      = redactDestinations;
    root[QStringLiteral("count")]         = rows.size();
    root[QStringLiteral("destinations")]  = rows;

    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

QString attributionCsv(const QList<DestinationNameSummary> &destinations,
                       bool redactDestinations,
                       const QString &exportedAt)
{
    QString text = metadataLines(QLatin1String(kAttributionFormat),
                                 exportTimestamp(exportedAt), redactDestinations);
    text += csvRow({QStringLiteral("address"), QStringLiteral("name"),
                    QStringLiteral("names"), QStringLiteral("source"),
                    QStringLiteral("confidence"), QStringLiteral("expiresAt"),
                    QStringLiteral("evidence")});

    for (const DestinationNameSummary &summary : destinations) {
        QStringList names;
        for (const QString &name : summary.names)
            names.append(exportName(name, redactDestinations));

        QStringList evidence = summary.evidence;
        if (redactDestinations) {
            evidence.clear();
            for (const QString &line : summary.evidence)
                evidence.append(AttributionPrivacy::redactDestinationText(line));
        }

        text += csvRow({exportAddress(summary.address, redactDestinations),
                        exportName(summary.name, redactDestinations),
                        names.join(QStringLiteral("; ")),
                        attributionSourceName(summary.source),
                        confidenceName(summary.confidence),
                        summary.expiresAt.isValid()
                            ? summary.expiresAt.toString(Qt::ISODate)
                            : QString(),
                        evidence.join(QStringLiteral("; "))});
    }
    return text;
}

} // namespace EvidenceExport
