/**
 * @file    attributionprivacy.cpp
 * @author  Ali Sakkaf
 */
#include "attributionprivacy.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSettings>
#include <QStringList>

namespace {

const QString kSettingsKey = QStringLiteral("settings");

QStringList fileExtensionLabels()
{
    // A dot-separated token ending in one of these is a file name, not a host.
    return {QStringLiteral("exe"),  QStringLiteral("dll"), QStringLiteral("sys"),
            QStringLiteral("log"),  QStringLiteral("json"), QStringLiteral("txt"),
            QStringLiteral("ini"),  QStringLiteral("cpp"), QStringLiteral("h"),
            QStringLiteral("bat"),  QStringLiteral("ps1"), QStringLiteral("msi"),
            QStringLiteral("tmp"),  QStringLiteral("dat"), QStringLiteral("xml"),
            QStringLiteral("csv"),  QStringLiteral("md"),  QStringLiteral("cfg")};
}

bool validIpv4Octet(const QString &octet)
{
    bool ok = false;
    const int value = octet.toInt(&ok);
    return ok && value >= 0 && value <= 255;
}

bool isIpv4Literal(const QString &text)
{
    const QStringList parts = text.split('.');
    if (parts.size() != 4) return false;
    for (const QString &part : parts) {
        if (part.isEmpty() || !validIpv4Octet(part)) return false;
    }
    return true;
}

bool isIpv6Literal(const QString &text)
{
    if (!text.contains(':')) return false;
    QString body = text;
    const int zone = body.indexOf('%');
    if (zone >= 0) body = body.left(zone);
    if (body.count(':') < 2) return false;
    for (const QChar c : body) {
        const QChar lower = c.toLower();
        const bool hexDigit =
            (lower >= QLatin1Char('0') && lower <= QLatin1Char('9')) ||
            (lower >= QLatin1Char('a') && lower <= QLatin1Char('f'));
        if (!(hexDigit || c == QLatin1Char(':') || c == QLatin1Char('.')))
            return false;
    }
    return true;
}

QString redactIpv4(const QString &address)
{
    const int dot = address.lastIndexOf('.');
    return dot > 0 ? address.left(dot) + QStringLiteral(".x") : QStringLiteral("x.x.x.x");
}

QString redactIpv6(const QString &address)
{
    QString body = address;
    const int zone = body.indexOf('%');
    if (zone >= 0) body = body.left(zone);

    const QStringList groups = body.split(':');
    for (int i = groups.size() - 1; i >= 0; --i) {
        if (groups.at(i).isEmpty()) continue;   // part of "::"
        QStringList replaced = groups;
        replaced[i] = QStringLiteral("x");
        return replaced.join(':');
    }
    return QStringLiteral("x::");
}

bool looksLikeHostName(const QString &token, QString *tldOut)
{
    const QString trimmed = token.trimmed();
    if (trimmed.isEmpty() || trimmed.contains(' ') || trimmed.contains('@'))
        return false;
    if (!trimmed.contains('.')) return false;

    const QStringList labels = trimmed.split('.');
    if (labels.size() < 2) return false;
    for (const QString &label : labels) {
        if (label.isEmpty()) return false;
        for (const QChar c : label) {
            if (!(c.isLetterOrNumber() || c == '-' || c == '_')) return false;
        }
    }

    const QString tld = labels.last().toLower();
    if (tld.size() < 2 || tld.size() > 24) return false;
    if (fileExtensionLabels().contains(tld)) return false;
    if (tldOut) *tldOut = tld;
    return true;
}

} // namespace

namespace AttributionPrivacy {

QString settingsGroup()
{
    return QStringLiteral("NetGuard/AttributionPrivacy");
}

int clampedRetentionSeconds(int seconds)
{
    return qBound(kMinRetentionSeconds, seconds, kMaxRetentionSeconds);
}

QString retentionDescription(int seconds)
{
    const int clamped = clampedRetentionSeconds(seconds);
    if (clamped % 3600 == 0)
        return QStringLiteral("%1 h").arg(clamped / 3600);
    return QStringLiteral("%1 min").arg(clamped / 60);
}

QString Store::toJson(const AttributionPrivacySettings &settings)
{
    QJsonObject root;
    root[QStringLiteral("schemaVersion")] = kSchemaVersion;
    root[QStringLiteral("collectDns")] = settings.collectDns;
    root[QStringLiteral("collectTlsSni")] = settings.collectTlsSni;
    root[QStringLiteral("collectQuic")] = settings.collectQuic;
    root[QStringLiteral("retentionSeconds")] =
        clampedRetentionSeconds(settings.retentionSeconds);
    root[QStringLiteral("redactDestinationsInExport")] =
        settings.redactDestinationsInExport;
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
}

AttributionPrivacySettings Store::fromJson(const QString &json, bool *ok)
{
    AttributionPrivacySettings settings;
    if (ok) *ok = false;

    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8());
    if (!document.isObject()) return settings;
    const QJsonObject root = document.object();

    // A payload from a newer build may give existing keys new meanings, so it
    // is rejected as a whole rather than partially adopted.
    const int schemaVersion = root.value(QStringLiteral("schemaVersion")).toInt(kSchemaVersion);
    if (schemaVersion > kSchemaVersion) return settings;

    if (root.contains(QStringLiteral("collectDns")))
        settings.collectDns = root.value(QStringLiteral("collectDns")).toBool(true);
    if (root.contains(QStringLiteral("collectTlsSni")))
        settings.collectTlsSni = root.value(QStringLiteral("collectTlsSni")).toBool(true);
    if (root.contains(QStringLiteral("collectQuic")))
        settings.collectQuic = root.value(QStringLiteral("collectQuic")).toBool(true);
    if (root.contains(QStringLiteral("redactDestinationsInExport")))
        settings.redactDestinationsInExport =
            root.value(QStringLiteral("redactDestinationsInExport")).toBool(true);
    settings.retentionSeconds = clampedRetentionSeconds(
        root.value(QStringLiteral("retentionSeconds")).toInt(kDefaultRetentionSeconds));

    if (ok) *ok = true;
    return settings;
}

AttributionPrivacySettings Store::load() const
{
    QSettings settings;
    return load(settings);
}

AttributionPrivacySettings Store::load(QSettings &settings) const
{
    settings.beginGroup(settingsGroup());
    const QString stored = settings.value(kSettingsKey).toString();
    settings.endGroup();
    return fromJson(stored);
}

bool Store::save(const AttributionPrivacySettings &settings) const
{
    QSettings store;
    return save(settings, store);
}

bool Store::save(const AttributionPrivacySettings &settings, QSettings &store) const
{
    store.beginGroup(settingsGroup());
    store.setValue(kSettingsKey, toJson(settings));
    store.endGroup();
    store.sync();
    return store.status() == QSettings::NoError;
}

void Store::reset() const
{
    QSettings settings;
    reset(settings);
}

void Store::reset(QSettings &settings) const
{
    settings.beginGroup(settingsGroup());
    settings.remove(QString());
    settings.endGroup();
    settings.sync();
}

bool isAddressLiteral(const QString &text)
{
    const QString trimmed = text.trimmed();
    return isIpv4Literal(trimmed) || isIpv6Literal(trimmed);
}

QString redactDestination(const QString &text)
{
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) return text;

    // "host:port" keeps the port, so a report can still show which service was
    // contacted without naming the host.
    QString host = trimmed;
    QString port;
    const int firstColon = trimmed.indexOf(':');
    const int lastColon = trimmed.lastIndexOf(':');
    if (firstColon > 0 && firstColon == lastColon &&
        trimmed.mid(lastColon + 1).toInt() > 0) {
        host = trimmed.left(lastColon);
        port = trimmed.mid(lastColon);
    }

    if (isIpv4Literal(host)) return redactIpv4(host) + port;
    if (isIpv6Literal(host)) return redactIpv6(host) + port;

    QString tld;
    if (looksLikeHostName(host, &tld))
        return QStringLiteral("***.") + tld + port;

    return text;
}

QString redactDestinationText(const QString &text)
{
    QString result = text;

    static const QRegularExpression ipv4(
        QStringLiteral("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"));
    QRegularExpressionMatchIterator it = ipv4.globalMatch(result);
    // Replace from the end so earlier match offsets stay valid.
    QList<QRegularExpressionMatch> matches;
    while (it.hasNext()) matches.append(it.next());
    for (int i = matches.size() - 1; i >= 0; --i) {
        const QRegularExpressionMatch &match = matches.at(i);
        if (!isIpv4Literal(match.captured()))
            continue;
        result.replace(match.capturedStart(), match.capturedLength(),
                       redactIpv4(match.captured()));
    }

    static const QRegularExpression ipv6(
        QStringLiteral("\\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\\b"));
    matches = QList<QRegularExpressionMatch>();
    it = ipv6.globalMatch(result);
    while (it.hasNext()) matches.append(it.next());
    for (int i = matches.size() - 1; i >= 0; --i) {
        const QRegularExpressionMatch &match = matches.at(i);
        result.replace(match.capturedStart(), match.capturedLength(),
                       redactIpv6(match.captured()));
    }

    static const QRegularExpression host(
        QStringLiteral("\\b(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?\\.)+"
                       "[A-Za-z]{2,24}\\b"));
    matches = QList<QRegularExpressionMatch>();
    it = host.globalMatch(result);
    while (it.hasNext()) matches.append(it.next());
    for (int i = matches.size() - 1; i >= 0; --i) {
        const QRegularExpressionMatch &match = matches.at(i);
        QString tld;
        if (!looksLikeHostName(match.captured(), &tld))
            continue;   // file name or extension, not a destination
        result.replace(match.capturedStart(), match.capturedLength(),
                       QStringLiteral("***.") + tld);
    }

    return result;
}

} // namespace AttributionPrivacy
