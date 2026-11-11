/**
 * @file    recommendationfeedback.cpp
 * @brief   Local recommendation feedback (NG-043).
 * @author  Ali Sakkaf
 */
#include "recommendationfeedback.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

#include <limits>

namespace {

const QString kSettingsGroup = QStringLiteral("NetGuard/RecommendationFeedback");
const QString kSettingsKey   = QStringLiteral("document");

QString normalizedKey(const QString &key)
{
    return key.trimmed();
}

} // namespace

QString recommendationFeedbackToken(RecommendationFeedback feedback)
{
    switch (feedback) {
    case RecommendationFeedback::Useful:    return QStringLiteral("useful");
    case RecommendationFeedback::Incorrect: return QStringLiteral("incorrect");
    case RecommendationFeedback::Unwanted:  return QStringLiteral("unwanted");
    case RecommendationFeedback::None:      break;
    }
    return QStringLiteral("none");
}

QString recommendationFeedbackDisplayName(RecommendationFeedback feedback)
{
    switch (feedback) {
    case RecommendationFeedback::Useful:    return QStringLiteral("Useful");
    case RecommendationFeedback::Incorrect: return QStringLiteral("Incorrect");
    case RecommendationFeedback::Unwanted:  return QStringLiteral("Not wanted");
    case RecommendationFeedback::None:      break;
    }
    return QStringLiteral("No feedback");
}

bool recommendationFeedbackFromToken(const QString &token,
                                     RecommendationFeedback *feedback)
{
    const QString normalized = token.trimmed().toLower();
    if (normalized == QStringLiteral("useful")) {
        if (feedback) *feedback = RecommendationFeedback::Useful;
        return true;
    }
    if (normalized == QStringLiteral("incorrect")) {
        if (feedback) *feedback = RecommendationFeedback::Incorrect;
        return true;
    }
    if (normalized == QStringLiteral("unwanted")) {
        if (feedback) *feedback = RecommendationFeedback::Unwanted;
        return true;
    }
    if (normalized == QStringLiteral("none")) {
        if (feedback) *feedback = RecommendationFeedback::None;
        return true;
    }
    return false;
}

QString RecommendationFeedbackStore::settingsGroup()
{
    return kSettingsGroup;
}

QString RecommendationFeedbackStore::settingsKey()
{
    return kSettingsKey;
}

RecommendationFeedbackStore::RecommendationFeedbackStore()
{
    QSettings settings;
    settings.beginGroup(kSettingsGroup);
    const QString stored = settings.value(kSettingsKey).toString();
    settings.endGroup();

    bool ok = false;
    const QList<RecommendationFeedbackEntry> entries = fromJson(stored, &ok);
    if (!ok) return;

    for (const RecommendationFeedbackEntry &entry : entries) {
        if (entry.key.isEmpty() || entry.feedback == RecommendationFeedback::None)
            continue;
        m_entries.insert(entry.key, entry);
    }
}

RecommendationFeedback RecommendationFeedbackStore::feedbackFor(const QString &key) const
{
    const auto it = m_entries.constFind(normalizedKey(key));
    return it == m_entries.constEnd() ? RecommendationFeedback::None
                                      : it->feedback;
}

bool RecommendationFeedbackStore::contains(const QString &key) const
{
    return m_entries.contains(normalizedKey(key));
}

int RecommendationFeedbackStore::count() const
{
    return m_entries.size();
}

QList<RecommendationFeedbackEntry> RecommendationFeedbackStore::entries() const
{
    return m_entries.values();
}

bool RecommendationFeedbackStore::setFeedback(const QString &key,
                                              RecommendationFeedback feedback)
{
    const QString normalized = normalizedKey(key);
    if (normalized.isEmpty()) return false;

    if (feedback == RecommendationFeedback::None) {
        m_entries.remove(normalized);
    } else {
        RecommendationFeedbackEntry entry;
        entry.key = normalized;
        entry.feedback = feedback;
        entry.updatedAt = QDateTime::currentDateTimeUtc();
        m_entries.insert(normalized, entry);
    }

    evictOldest();

    QSettings settings;
    settings.beginGroup(kSettingsGroup);
    settings.setValue(kSettingsKey, toJson(m_entries.values()));
    settings.endGroup();
    settings.sync();
    return settings.status() == QSettings::NoError;
}

bool RecommendationFeedbackStore::clear()
{
    m_entries.clear();

    QSettings settings;
    settings.beginGroup(kSettingsGroup);
    settings.remove(kSettingsKey);
    settings.endGroup();
    settings.sync();
    return settings.status() == QSettings::NoError;
}

void RecommendationFeedbackStore::evictOldest()
{
    while (m_entries.size() > kMaxEntries) {
        QString oldestKey;
        qint64 oldestStamp = std::numeric_limits<qint64>::max();
        for (auto it = m_entries.constBegin(); it != m_entries.constEnd(); ++it) {
            const qint64 stamp = it->updatedAt.isValid()
                ? it->updatedAt.toMSecsSinceEpoch()
                : 0;
            if (oldestKey.isEmpty() || stamp < oldestStamp) {
                oldestStamp = stamp;
                oldestKey = it.key();
            }
        }
        if (oldestKey.isEmpty()) break;
        m_entries.remove(oldestKey);
    }
}

QString RecommendationFeedbackStore::toJson(
    const QList<RecommendationFeedbackEntry> &entries)
{
    QJsonObject root;
    root[QStringLiteral("schemaVersion")] = kSchemaVersion;

    QJsonArray array;
    for (const RecommendationFeedbackEntry &entry : entries) {
        if (entry.key.trimmed().isEmpty()
            || entry.feedback == RecommendationFeedback::None)
            continue;

        QJsonObject object;
        object[QStringLiteral("key")] = entry.key.trimmed();
        object[QStringLiteral("feedback")] =
            recommendationFeedbackToken(entry.feedback);
        if (entry.updatedAt.isValid()) {
            object[QStringLiteral("updatedAt")] =
                entry.updatedAt.toUTC().toString(Qt::ISODate);
        }
        array.append(object);
    }
    root[QStringLiteral("entries")] = array;

    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
}

QList<RecommendationFeedbackEntry> RecommendationFeedbackStore::fromJson(
    const QString &json, bool *ok)
{
    QList<RecommendationFeedbackEntry> result;
    if (ok) *ok = false;

    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8());
    if (!document.isObject()) return result;
    const QJsonObject root = document.object();

    // A payload from a newer build may give existing keys new meanings, so it
    // is rejected as a whole rather than partially adopted.
    const int schemaVersion =
        root.value(QStringLiteral("schemaVersion")).toInt(kSchemaVersion);
    if (schemaVersion > kSchemaVersion) return result;

    const QJsonValue entriesValue = root.value(QStringLiteral("entries"));
    if (!entriesValue.isUndefined() && !entriesValue.isArray()) return result;

    QMap<QString, RecommendationFeedbackEntry> byKey;
    const QJsonArray array = entriesValue.toArray();
    for (const QJsonValue &value : array) {
        if (!value.isObject()) continue;
        const QJsonObject object = value.toObject();

        const QString key =
            object.value(QStringLiteral("key")).toString().trimmed();
        if (key.isEmpty()) continue;

        RecommendationFeedback feedback = RecommendationFeedback::None;
        if (!recommendationFeedbackFromToken(
                object.value(QStringLiteral("feedback")).toString(),
                &feedback)
            || feedback == RecommendationFeedback::None) {
            continue;
        }

        RecommendationFeedbackEntry entry;
        entry.key = key;
        entry.feedback = feedback;
        entry.updatedAt = QDateTime::fromString(
            object.value(QStringLiteral("updatedAt")).toString(), Qt::ISODate);
        byKey.insert(key, entry);
    }

    // Keep the most recently updated verdicts when the payload is over the
    // bound. Ties and missing timestamps fall back to the key order.
    while (byKey.size() > kMaxEntries) {
        QString oldestKey;
        qint64 oldestStamp = std::numeric_limits<qint64>::max();
        for (auto it = byKey.constBegin(); it != byKey.constEnd(); ++it) {
            const qint64 stamp = it->updatedAt.isValid()
                ? it->updatedAt.toMSecsSinceEpoch()
                : 0;
            if (oldestKey.isEmpty() || stamp < oldestStamp) {
                oldestStamp = stamp;
                oldestKey = it.key();
            }
        }
        if (oldestKey.isEmpty()) break;
        byKey.remove(oldestKey);
    }

    if (ok) *ok = true;
    return byKey.values();
}
