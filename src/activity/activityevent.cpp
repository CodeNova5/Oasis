/**
 * @file    activityevent.cpp
 * @author  Oasis
 */
#include "activityevent.h"

#include "network/evidenceexport.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

namespace Activity {

namespace {

QString redactedDestination(const QString &destination, bool redact)
{
    if (destination.isEmpty())
        return QString();
    // A literal address and a host name need different redaction, so let the
    // audit/attribution exporter decide which one this is.
    if (destination.contains(QLatin1Char(':')))
        return EvidenceExport::exportAddress(destination, redact);
    return EvidenceExport::exportName(destination, redact);
}

QJsonObject eventObject(const Event &event, bool redactDestinations)
{
    QJsonObject object;
    object.insert(QStringLiteral("timestamp"),
                  event.at.toUTC().toString(Qt::ISODateWithMs));
    object.insert(QStringLiteral("category"), categoryKey(event.category));
    object.insert(QStringLiteral("badge"), event.badge);
    object.insert(QStringLiteral("title"), event.title);
    object.insert(QStringLiteral("description"), event.description);
    object.insert(QStringLiteral("application"), event.appName);
    object.insert(QStringLiteral("executable"), event.appPath);
    object.insert(QStringLiteral("pid"), static_cast<double>(event.pid));
    object.insert(QStringLiteral("destination"),
                  redactedDestination(event.destination, redactDestinations));
    object.insert(QStringLiteral("attribution"), event.attribution);
    object.insert(QStringLiteral("volumeBytes"), static_cast<double>(event.volumeBytes));
    object.insert(QStringLiteral("peakBytesPerSecond"),
                  static_cast<double>(event.peakBytesPerSecond));
    object.insert(QStringLiteral("simulated"), event.simulated);

    QJsonArray meta;
    for (const MetaItem &item : event.extra) {
        QJsonObject pair;
        pair.insert(QStringLiteral("key"), item.key);
        pair.insert(QStringLiteral("value"),
                    item.key.compare(QStringLiteral("Destination"), Qt::CaseInsensitive) == 0
                        ? redactedDestination(item.value, redactDestinations)
                        : item.value);
        meta.append(pair);
    }
    object.insert(QStringLiteral("evidence"), meta);
    return object;
}

} // namespace

QString categoryTone(Category category)
{
    switch (category) {
    case Category::Spike:      return QStringLiteral("warning");
    case Category::Unresolved: return QStringLiteral("danger");
    case Category::Policy:     return QStringLiteral("success");
    case Category::Respawn:    return QStringLiteral("info");
    }
    return QStringLiteral("info");
}

QString categoryKey(Category category)
{
    switch (category) {
    case Category::Spike:      return QStringLiteral("spike");
    case Category::Unresolved: return QStringLiteral("unresolved");
    case Category::Policy:     return QStringLiteral("policy");
    case Category::Respawn:    return QStringLiteral("respawn");
    }
    return QStringLiteral("spike");
}

QString categoryLabel(Category category)
{
    switch (category) {
    case Category::Spike:      return QStringLiteral("Spikes & Surges");
    case Category::Unresolved: return QStringLiteral("Unrecognized");
    case Category::Policy:     return QStringLiteral("Policy Actions");
    case Category::Respawn:    return QStringLiteral("Respawns");
    }
    return QStringLiteral("Events");
}

QString categoryBadge(Category category)
{
    switch (category) {
    case Category::Spike:      return QStringLiteral("Spike");
    case Category::Unresolved: return QStringLiteral("Unresolved");
    case Category::Policy:     return QStringLiteral("Policy");
    case Category::Respawn:    return QStringLiteral("Respawn");
    }
    return QStringLiteral("Event");
}

bool categoryFromKey(const QString &key, Category *category)
{
    if (!category)
        return false;
    const QString normalized = key.trimmed().toLower();
    if (normalized == QLatin1String("spike")) {
        *category = Category::Spike;
        return true;
    }
    if (normalized == QLatin1String("unresolved")) {
        *category = Category::Unresolved;
        return true;
    }
    if (normalized == QLatin1String("policy")) {
        *category = Category::Policy;
        return true;
    }
    if (normalized == QLatin1String("respawn")) {
        *category = Category::Respawn;
        return true;
    }
    return false;
}

QList<Category> allCategories()
{
    return { Category::Spike, Category::Unresolved, Category::Policy, Category::Respawn };
}

QString makeEventId(Category category, const QDateTime &at, const QString &subject,
                    const QString &suffix)
{
    QString normalized = subject;
    normalized.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9._-]")),
                       QStringLiteral("-"));
    if (normalized.size() > 48)
        normalized = normalized.left(48);
    if (normalized.isEmpty())
        normalized = QStringLiteral("event");
    QString id = QStringLiteral("%1-%2-%3")
                     .arg(categoryKey(category),
                          at.toUTC().toString(QStringLiteral("yyyyMMddHHmmsszzz")),
                          normalized);
    if (!suffix.isEmpty())
        id += QLatin1Char('-') + suffix;
    return id;
}

QString searchableText(const Event &event)
{
    QStringList parts;
    parts << event.title << event.description << event.appName << event.appPath
          << event.badge << event.destination << event.attribution;
    for (const MetaItem &item : event.extra)
        parts << item.key << item.value;
    return parts.join(QLatin1Char(' '));
}

QList<Event> filterEvents(const QList<Event> &events, const EventFilter &filter)
{
    QList<Event> result;
    const QString appQuery = filter.app.trimmed();
    const QString textQuery = filter.text.trimmed();
    for (const Event &event : events) {
        if (filter.from.isValid() && event.at < filter.from)
            continue;
        if (filter.to.isValid() && event.at > filter.to)
            continue;
        if (!appQuery.isEmpty()
            && event.appName.compare(appQuery, Qt::CaseInsensitive) != 0)
            continue;
        if (filter.hasCategory && event.category != filter.category)
            continue;
        if (!textQuery.isEmpty()
            && !searchableText(event).contains(textQuery, Qt::CaseInsensitive))
            continue;
        result.append(event);
    }
    return result;
}

QHash<int, int> categoryCounts(const QList<Event> &events, const EventFilter &filter)
{
    EventFilter withoutCategory = filter;
    withoutCategory.hasCategory = false;
    const QList<Event> candidates = filterEvents(events, withoutCategory);

    QHash<int, int> counts;
    for (Category category : allCategories())
        counts.insert(static_cast<int>(category), 0);
    for (const Event &event : candidates)
        counts[static_cast<int>(event.category)] += 1;
    return counts;
}

QString exportJson(const QList<Event> &events, bool redactDestinations,
                   const QString &exportedAt)
{
    QJsonArray array;
    for (const Event &event : events)
        array.append(eventObject(event, redactDestinations));

    QJsonObject root;
    root.insert(QStringLiteral("format"), QStringLiteral("oasis.activity-feed"));
    root.insert(QStringLiteral("schemaVersion"), 1);
    root.insert(QStringLiteral("exportedAt"),
                exportedAt.isEmpty()
                    ? QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)
                    : exportedAt);
    root.insert(QStringLiteral("redacted"), redactDestinations);
    root.insert(QStringLiteral("count"), events.size());
    root.insert(QStringLiteral("events"), array);
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

QString exportCsv(const QList<Event> &events, bool redactDestinations,
                  const QString &exportedAt)
{
    QString out;
    out += QStringLiteral("# format: oasis.activity-feed\n");
    out += QStringLiteral("# schema: 1\n");
    out += QStringLiteral("# exported: %1\n")
               .arg(exportedAt.isEmpty()
                        ? QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)
                        : exportedAt);
    out += QStringLiteral("# redacted: %1\n")
               .arg(redactDestinations ? QStringLiteral("true")
                                       : QStringLiteral("false"));
    out += EvidenceExport::csvRow({
        QStringLiteral("timestamp"), QStringLiteral("category"),
        QStringLiteral("badge"), QStringLiteral("title"),
        QStringLiteral("application"), QStringLiteral("executable"),
        QStringLiteral("pid"), QStringLiteral("destination"),
        QStringLiteral("attribution"), QStringLiteral("volume_bytes"),
        QStringLiteral("peak_bytes_per_second"), QStringLiteral("description"),
        QStringLiteral("simulated")
    });

    for (const Event &event : events) {
        out += EvidenceExport::csvRow({
            event.at.toUTC().toString(Qt::ISODateWithMs),
            categoryKey(event.category),
            event.badge,
            event.title,
            event.appName,
            event.appPath,
            QString::number(event.pid),
            redactedDestination(event.destination, redactDestinations),
            event.attribution,
            QString::number(event.volumeBytes),
            QString::number(event.peakBytesPerSecond),
            event.description,
            event.simulated ? QStringLiteral("true") : QStringLiteral("false")
        });
    }
    return out;
}

} // namespace Activity
