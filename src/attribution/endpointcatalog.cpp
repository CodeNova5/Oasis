/**
 * @file    endpointcatalog.cpp
 * @author  Ali Sakkaf
 */
#include "endpointcatalog.h"

#include <QAbstractSocket>
#include <QDir>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QSettings>
#include <QSet>

#include <algorithm>

namespace {

const char *const kSettingsGroup = "NetGuard/EndpointCatalog";
const char *const kSettingsDocumentKey = "document";

QString lowerTrimmed(const QString &value)
{
    return value.trimmed().toLower();
}

QString normalizedDomain(const QString &value)
{
    QString result = lowerTrimmed(value);
    while (result.endsWith(QLatin1Char('.'))) result.chop(1);
    return result;
}

QString normalizedExecutableName(const QString &value)
{
    QString name = value.trimmed();
    const int slash = qMax(name.lastIndexOf(QLatin1Char('/')),
                           name.lastIndexOf(QLatin1Char('\\')));
    if (slash >= 0) name = name.mid(slash + 1);
    return name.toLower();
}

QString normalizedPath(const QString &value)
{
    QString path = value.trimmed();
    if (path.isEmpty()) return {};
    path = QDir::fromNativeSeparators(QDir::cleanPath(path));
    return path.toLower();
}

bool validDomainLabel(const QString &label)
{
    if (label.isEmpty() || label.size() > 63) return false;
    if (label.startsWith(QLatin1Char('-')) || label.endsWith(QLatin1Char('-'))) {
        return false;
    }
    for (const QChar character : label) {
        const ushort code = character.unicode();
        const bool letter = (code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z');
        const bool digit = code >= '0' && code <= '9';
        if (!letter && !digit && character != QLatin1Char('-')) return false;
    }
    return true;
}

bool validDomainPattern(const QString &pattern)
{
    QString value = normalizedDomain(pattern);
    if (value.isEmpty()) return false;

    if (value.startsWith(QStringLiteral("*."))) {
        value = value.mid(2);
        if (value.contains(QLatin1Char('*'))) return false;
    } else if (value.contains(QLatin1Char('*'))) {
        return false;
    }
    if (value.isEmpty() || value.size() > 253) return false;

    const QStringList labels = value.split(QLatin1Char('.'));
    for (const QString &label : labels) {
        if (!validDomainLabel(label)) return false;
    }
    return true;
}

bool validQueryDomain(const QString &domain)
{
    const QString value = normalizedDomain(domain);
    if (value.isEmpty() || value.size() > 253 || value.contains(QLatin1Char('*'))) {
        return false;
    }
    const QStringList labels = value.split(QLatin1Char('.'));
    for (const QString &label : labels) {
        if (!validDomainLabel(label)) return false;
    }
    return true;
}

bool domainMatches(const QString &pattern, const QString &domain)
{
    const QString rule = normalizedDomain(pattern);
    const QString value = normalizedDomain(domain);
    if (rule.startsWith(QStringLiteral("*."))) {
        const QString suffix = rule.mid(2);
        return value.size() > suffix.size() + 1 &&
               value.endsWith(QLatin1Char('.') + suffix);
    }
    return value == rule;
}

struct AddressPrefix
{
    QHostAddress network;
    int bits = 0;
};

bool parseAddressPrefix(const QString &text, AddressPrefix &result)
{
    QString value = text.trimmed();
    if (value.isEmpty() || value.contains(QLatin1Char('%'))) return false;

    int prefixBits = -1;
    const int slash = value.lastIndexOf(QLatin1Char('/'));
    if (slash >= 0) {
        const QString prefix = value.mid(slash + 1).trimmed();
        value = value.left(slash).trimmed();
        bool ok = false;
        prefixBits = prefix.toInt(&ok);
        if (!ok || prefixBits < 0) return false;
    }

    QHostAddress address;
    if (!address.setAddress(value)) return false;

    int maximumBits = 0;
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        maximumBits = 32;
    } else if (address.protocol() == QAbstractSocket::IPv6Protocol) {
        maximumBits = 128;
    } else {
        return false;
    }
    if (prefixBits < 0) prefixBits = maximumBits;
    if (prefixBits > maximumBits) return false;

    result.network = address;
    result.bits = prefixBits;
    return true;
}

bool addressMatches(const QString &pattern, const QString &addressText)
{
    AddressPrefix prefix;
    if (!parseAddressPrefix(pattern, prefix)) return false;

    QHostAddress address;
    if (!address.setAddress(addressText.trimmed())) return false;
    if (address.protocol() != prefix.network.protocol()) return false;

    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 left = prefix.network.toIPv4Address();
        const quint32 right = address.toIPv4Address();
        if (prefix.bits == 0) return true;
        const quint32 mask = prefix.bits == 32
            ? 0xFFFFFFFFu
            : ~((1u << (32 - prefix.bits)) - 1u);
        return (left & mask) == (right & mask);
    }

    const QIPv6Address left = prefix.network.toIPv6Address();
    const QIPv6Address right = address.toIPv6Address();
    const int fullBytes = prefix.bits / 8;
    const int remainingBits = prefix.bits % 8;
    for (int i = 0; i < fullBytes; ++i) {
        if (left[i] != right[i]) return false;
    }
    if (remainingBits > 0) {
        const quint8 mask = static_cast<quint8>(0xFF << (8 - remainingBits));
        if ((left[fullBytes] & mask) != (right[fullBytes] & mask)) return false;
    }
    return true;
}

int criteriaCount(const CatalogRule &rule)
{
    int count = 0;
    if (!rule.identityId.trimmed().isEmpty()) ++count;
    if (!rule.publisherContains.trimmed().isEmpty()) ++count;
    if (!rule.productContains.trimmed().isEmpty()) ++count;
    if (!rule.executableName.trimmed().isEmpty()) ++count;
    if (!rule.executablePath.trimmed().isEmpty()) ++count;
    if (!rule.serviceName.trimmed().isEmpty()) ++count;
    if (!rule.domainPatterns.isEmpty()) ++count;
    if (!rule.addressPrefixes.isEmpty()) ++count;
    return count;
}

int sourceRank(CatalogRuleSource source)
{
    switch (source) {
    case CatalogRuleSource::User:     return 2;
    case CatalogRuleSource::Imported: return 1;
    case CatalogRuleSource::BuiltIn:  break;
    }
    return 0;
}

struct MatchResult
{
    CatalogMatch match;
    int specificity = 0;
};

bool matchRule(const CatalogRule &rule, const CatalogQuery &query, CatalogMatch *match)
{
    if (!rule.enabled) return false;

    CatalogMatch result;
    result.ruleId = rule.id;
    result.category = rule.category;
    result.explanation = rule.explanation;
    result.source = rule.source;

    if (!rule.identityId.trimmed().isEmpty()) {
        if (lowerTrimmed(rule.identityId) != lowerTrimmed(query.identityId)) return false;
        result.matchedOn.append(QStringLiteral("identity id matched"));
    }
    if (!rule.publisherContains.trimmed().isEmpty()) {
        const QString pattern = lowerTrimmed(rule.publisherContains);
        if (!lowerTrimmed(query.publisher).contains(pattern)) return false;
        result.matchedOn.append(QStringLiteral("publisher contained \"%1\"").arg(pattern));
    }
    if (!rule.productContains.trimmed().isEmpty()) {
        const QString pattern = lowerTrimmed(rule.productContains);
        if (!lowerTrimmed(query.product).contains(pattern)) return false;
        result.matchedOn.append(QStringLiteral("product contained \"%1\"").arg(pattern));
    }
    if (!rule.executableName.trimmed().isEmpty()) {
        const QString expected = normalizedExecutableName(rule.executableName);
        if (expected.isEmpty() ||
            normalizedExecutableName(query.executableName) != expected) {
            return false;
        }
        result.matchedOn.append(QStringLiteral("executable name was %1").arg(expected));
    }
    if (!rule.executablePath.trimmed().isEmpty()) {
        const QString expected = normalizedPath(rule.executablePath);
        if (expected.isEmpty() || normalizedPath(query.executablePath) != expected) {
            return false;
        }
        result.matchedOn.append(QStringLiteral("executable path matched"));
    }
    if (!rule.serviceName.trimmed().isEmpty()) {
        const QString expected = lowerTrimmed(rule.serviceName);
        if (lowerTrimmed(query.serviceName) != expected) return false;
        result.matchedOn.append(QStringLiteral("service was %1").arg(expected));
    }
    if (!rule.domainPatterns.isEmpty()) {
        if (!validQueryDomain(query.domain)) return false;
        bool matched = false;
        for (const QString &pattern : rule.domainPatterns) {
            if (!domainMatches(pattern, query.domain)) continue;
            result.matchedOn.append(
                QStringLiteral("domain matched %1").arg(normalizedDomain(pattern)));
            matched = true;
            break;
        }
        if (!matched) return false;
    }
    if (!rule.addressPrefixes.isEmpty()) {
        bool matched = false;
        for (const QString &prefix : rule.addressPrefixes) {
            if (!addressMatches(prefix, query.remoteAddress)) continue;
            result.matchedOn.append(
                QStringLiteral("address matched %1").arg(prefix.trimmed()));
            matched = true;
            break;
        }
        if (!matched) return false;
    }

    result.matched = true;
    *match = result;
    return true;
}

QString errorText(const QString &message)
{
    return message;
}

CatalogRule builtinRule(const QString &id, CatalogCategory category,
                        const QString &explanation)
{
    CatalogRule rule;
    rule.id = id;
    rule.category = category;
    rule.explanation = explanation;
    rule.source = CatalogRuleSource::BuiltIn;
    return rule;
}

QJsonObject ruleToJson(const CatalogRule &rule)
{
    QJsonObject object;
    object.insert(QStringLiteral("id"), rule.id);
    object.insert(QStringLiteral("category"), catalogCategoryToken(rule.category));
    object.insert(QStringLiteral("explanation"), rule.explanation);
    object.insert(QStringLiteral("source"), catalogRuleSourceToken(rule.source));
    object.insert(QStringLiteral("enabled"), rule.enabled);

    if (!rule.identityId.isEmpty())
        object.insert(QStringLiteral("identityId"), rule.identityId);
    if (!rule.publisherContains.isEmpty())
        object.insert(QStringLiteral("publisherContains"), rule.publisherContains);
    if (!rule.productContains.isEmpty())
        object.insert(QStringLiteral("productContains"), rule.productContains);
    if (!rule.executableName.isEmpty())
        object.insert(QStringLiteral("executableName"), rule.executableName);
    if (!rule.executablePath.isEmpty())
        object.insert(QStringLiteral("executablePath"), rule.executablePath);
    if (!rule.serviceName.isEmpty())
        object.insert(QStringLiteral("serviceName"), rule.serviceName);
    if (!rule.domainPatterns.isEmpty()) {
        object.insert(QStringLiteral("domainPatterns"),
                      QJsonArray::fromStringList(rule.domainPatterns));
    }
    if (!rule.addressPrefixes.isEmpty()) {
        object.insert(QStringLiteral("addressPrefixes"),
                      QJsonArray::fromStringList(rule.addressPrefixes));
    }
    return object;
}

QString serializeDocument(const QList<CatalogRule> &rules, const QString &version)
{
    QJsonArray array;
    for (const CatalogRule &rule : rules) array.append(ruleToJson(rule));

    QJsonObject root;
    root.insert(QStringLiteral("format"),
                QString::fromLatin1(EndpointCatalogContract::kFormat));
    root.insert(QStringLiteral("schemaVersion"),
                EndpointCatalogContract::kSchemaVersion);
    root.insert(QStringLiteral("catalogVersion"), version);
    root.insert(QStringLiteral("rules"), array);
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
}

bool readOptionalString(const QJsonObject &object, const QString &key,
                        const QString &ruleId, QString &value, QString *error)
{
    if (!object.contains(key)) return true;
    const QJsonValue field = object.value(key);
    if (!field.isString()) {
        if (error) *error = errorText(QStringLiteral(
            "rule \"%1\" field \"%2\" must be a string").arg(ruleId, key));
        return false;
    }
    value = field.toString();
    return true;
}

bool readOptionalStringList(const QJsonObject &object, const QString &key,
                            const QString &ruleId, QStringList &value, QString *error)
{
    if (!object.contains(key)) return true;
    const QJsonValue field = object.value(key);
    if (!field.isArray()) {
        if (error) *error = errorText(QStringLiteral(
            "rule \"%1\" field \"%2\" must be an array").arg(ruleId, key));
        return false;
    }
    const QJsonArray array = field.toArray();
    for (const QJsonValue &entry : array) {
        if (!entry.isString()) {
            if (error) *error = errorText(QStringLiteral(
                "rule \"%1\" field \"%2\" must contain only strings").arg(ruleId, key));
            return false;
        }
        value.append(entry.toString());
    }
    return true;
}

bool parseDocument(const QString &json, QList<CatalogRule> *rules, QString *version,
                   QString *error)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        if (error) *error = errorText(QStringLiteral("catalog JSON is invalid: %1")
                                          .arg(parseError.errorString()));
        return false;
    }
    if (!document.isObject()) {
        if (error) *error = errorText(QStringLiteral("catalog root must be an object"));
        return false;
    }

    const QJsonObject root = document.object();
    if (root.value(QStringLiteral("format")).toString() !=
        QString::fromLatin1(EndpointCatalogContract::kFormat)) {
        if (error) *error = errorText(QStringLiteral("unknown catalog format"));
        return false;
    }

    const QJsonValue schemaValue = root.value(QStringLiteral("schemaVersion"));
    if (!schemaValue.isDouble() ||
        schemaValue.toInt(-1) != EndpointCatalogContract::kSchemaVersion) {
        if (error) *error = errorText(QStringLiteral(
            "unsupported catalog schema version (expected %1)")
            .arg(EndpointCatalogContract::kSchemaVersion));
        return false;
    }

    const QString documentVersion = root.value(QStringLiteral("catalogVersion")).toString();
    if (documentVersion.trimmed().isEmpty() || documentVersion.size() > 64) {
        if (error) *error = errorText(QStringLiteral("catalogVersion is missing or too long"));
        return false;
    }

    const QJsonValue rulesValue = root.value(QStringLiteral("rules"));
    if (!rulesValue.isArray()) {
        if (error) *error = errorText(QStringLiteral("catalog rules must be an array"));
        return false;
    }
    const QJsonArray array = rulesValue.toArray();
    if (array.size() > EndpointCatalogContract::kMaxRulesPerJson) {
        if (error) *error = errorText(QStringLiteral("catalog has too many rules"));
        return false;
    }

    QSet<QString> seenIds;
    QList<CatalogRule> parsed;
    for (const QJsonValue &entry : array) {
        if (!entry.isObject()) {
            if (error) *error = errorText(QStringLiteral("each catalog rule must be an object"));
            return false;
        }
        const QJsonObject object = entry.toObject();

        CatalogRule rule;
        rule.id = object.value(QStringLiteral("id")).toString().trimmed();
        rule.explanation = object.value(QStringLiteral("explanation")).toString();
        if (rule.id.isEmpty()) {
            if (error) *error = errorText(QStringLiteral("catalog rule id is missing"));
            return false;
        }
        if (seenIds.contains(rule.id)) {
            if (error) *error = errorText(QStringLiteral(
                "duplicate catalog rule id \"%1\"").arg(rule.id));
            return false;
        }
        seenIds.insert(rule.id);

        CatalogCategory category = CatalogCategory::Unknown;
        if (!catalogCategoryFromToken(
                object.value(QStringLiteral("category")).toString(), &category)) {
            if (error) *error = errorText(QStringLiteral(
                "rule \"%1\" has an unknown category").arg(rule.id));
            return false;
        }
        rule.category = category;

        CatalogRuleSource source = CatalogRuleSource::Imported;
        if (object.contains(QStringLiteral("source")) &&
            !catalogRuleSourceFromToken(object.value(QStringLiteral("source")).toString(),
                                        &source)) {
            if (error) *error = errorText(QStringLiteral(
                "rule \"%1\" has an unknown source").arg(rule.id));
            return false;
        }
        rule.source = source;

        if (object.contains(QStringLiteral("enabled"))) {
            if (!object.value(QStringLiteral("enabled")).isBool()) {
                if (error) *error = errorText(QStringLiteral(
                    "rule \"%1\" enabled field must be a boolean").arg(rule.id));
                return false;
            }
            rule.enabled = object.value(QStringLiteral("enabled")).toBool();
        }

        if (!readOptionalString(object, QStringLiteral("identityId"), rule.id,
                                rule.identityId, error) ||
            !readOptionalString(object, QStringLiteral("publisherContains"), rule.id,
                                rule.publisherContains, error) ||
            !readOptionalString(object, QStringLiteral("productContains"), rule.id,
                                rule.productContains, error) ||
            !readOptionalString(object, QStringLiteral("executableName"), rule.id,
                                rule.executableName, error) ||
            !readOptionalString(object, QStringLiteral("executablePath"), rule.id,
                                rule.executablePath, error) ||
            !readOptionalString(object, QStringLiteral("serviceName"), rule.id,
                                rule.serviceName, error) ||
            !readOptionalStringList(object, QStringLiteral("domainPatterns"), rule.id,
                                    rule.domainPatterns, error) ||
            !readOptionalStringList(object, QStringLiteral("addressPrefixes"), rule.id,
                                    rule.addressPrefixes, error)) {
            return false;
        }

        if (!EndpointCatalog::validateRule(rule, error)) return false;
        parsed.append(rule);
    }

    *rules = parsed;
    *version = documentVersion.trimmed();
    return true;
}

} // namespace

QString catalogCategoryToken(CatalogCategory category)
{
    switch (category) {
    case CatalogCategory::WindowsUpdate:      return QStringLiteral("windows-update");
    case CatalogCategory::BackgroundTransfer: return QStringLiteral("background-transfer");
    case CatalogCategory::BrowserUpdate:      return QStringLiteral("browser-update");
    case CatalogCategory::CloudSync:          return QStringLiteral("cloud-sync");
    case CatalogCategory::GameLauncher:       return QStringLiteral("game-launcher");
    case CatalogCategory::DeveloperTool:      return QStringLiteral("developer-tool");
    case CatalogCategory::PackageManager:     return QStringLiteral("package-manager");
    case CatalogCategory::ForegroundDownload: return QStringLiteral("foreground-download");
    case CatalogCategory::Unknown:            break;
    }
    return QStringLiteral("unknown");
}

QString catalogCategoryDisplayName(CatalogCategory category)
{
    switch (category) {
    case CatalogCategory::WindowsUpdate:      return QStringLiteral("Windows Update");
    case CatalogCategory::BackgroundTransfer: return QStringLiteral("Background transfer");
    case CatalogCategory::BrowserUpdate:      return QStringLiteral("Browser update");
    case CatalogCategory::CloudSync:          return QStringLiteral("Cloud sync");
    case CatalogCategory::GameLauncher:       return QStringLiteral("Game launcher");
    case CatalogCategory::DeveloperTool:      return QStringLiteral("Developer tool");
    case CatalogCategory::PackageManager:     return QStringLiteral("Package manager");
    case CatalogCategory::ForegroundDownload: return QStringLiteral("Foreground download");
    case CatalogCategory::Unknown:            break;
    }
    return QStringLiteral("Unknown");
}

bool catalogCategoryFromToken(const QString &token, CatalogCategory *category)
{
    if (!category) return false;
    const QString value = lowerTrimmed(token);
    if (value == QStringLiteral("windows-update")) {
        *category = CatalogCategory::WindowsUpdate;
    } else if (value == QStringLiteral("background-transfer")) {
        *category = CatalogCategory::BackgroundTransfer;
    } else if (value == QStringLiteral("browser-update")) {
        *category = CatalogCategory::BrowserUpdate;
    } else if (value == QStringLiteral("cloud-sync")) {
        *category = CatalogCategory::CloudSync;
    } else if (value == QStringLiteral("game-launcher")) {
        *category = CatalogCategory::GameLauncher;
    } else if (value == QStringLiteral("developer-tool")) {
        *category = CatalogCategory::DeveloperTool;
    } else if (value == QStringLiteral("package-manager")) {
        *category = CatalogCategory::PackageManager;
    } else if (value == QStringLiteral("foreground-download")) {
        *category = CatalogCategory::ForegroundDownload;
    } else if (value == QStringLiteral("unknown")) {
        *category = CatalogCategory::Unknown;
    } else {
        return false;
    }
    return true;
}

QStringList catalogCategoryTokens()
{
    return {
        QStringLiteral("windows-update"),
        QStringLiteral("background-transfer"),
        QStringLiteral("browser-update"),
        QStringLiteral("cloud-sync"),
        QStringLiteral("game-launcher"),
        QStringLiteral("developer-tool"),
        QStringLiteral("package-manager"),
        QStringLiteral("foreground-download"),
        QStringLiteral("unknown")
    };
}

QString catalogRuleSourceToken(CatalogRuleSource source)
{
    switch (source) {
    case CatalogRuleSource::Imported: return QStringLiteral("imported");
    case CatalogRuleSource::User:     return QStringLiteral("user");
    case CatalogRuleSource::BuiltIn:  break;
    }
    return QStringLiteral("builtin");
}

bool catalogRuleSourceFromToken(const QString &token, CatalogRuleSource *source)
{
    if (!source) return false;
    const QString value = lowerTrimmed(token);
    if (value == QStringLiteral("builtin")) {
        *source = CatalogRuleSource::BuiltIn;
    } else if (value == QStringLiteral("imported")) {
        *source = CatalogRuleSource::Imported;
    } else if (value == QStringLiteral("user")) {
        *source = CatalogRuleSource::User;
    } else {
        return false;
    }
    return true;
}

bool CatalogRule::hasCriteria() const
{
    return criteriaCount(*this) > 0;
}

EndpointCatalog::EndpointCatalog()
{
    resetToBuiltins();
}

QList<CatalogRule> EndpointCatalog::builtinRules()
{
    QList<CatalogRule> rules;

    CatalogRule windowsUpdateService = builtinRule(
        QStringLiteral("builtin-windows-update-service"),
        CatalogCategory::WindowsUpdate,
        QStringLiteral("Windows Update service traffic"));
    windowsUpdateService.serviceName = QStringLiteral("wuauserv");
    rules.append(windowsUpdateService);

    CatalogRule deliveryOptimization = builtinRule(
        QStringLiteral("builtin-delivery-optimization-service"),
        CatalogCategory::WindowsUpdate,
        QStringLiteral("Delivery Optimization service traffic"));
    deliveryOptimization.serviceName = QStringLiteral("dosvc");
    rules.append(deliveryOptimization);

    CatalogRule bits = builtinRule(
        QStringLiteral("builtin-bits-service"),
        CatalogCategory::BackgroundTransfer,
        QStringLiteral("Background Intelligent Transfer Service traffic"));
    bits.serviceName = QStringLiteral("bits");
    rules.append(bits);

    CatalogRule windowsUpdateEndpoints = builtinRule(
        QStringLiteral("builtin-windows-update-endpoints"),
        CatalogCategory::WindowsUpdate,
        QStringLiteral("Known Windows Update delivery endpoint"));
    windowsUpdateEndpoints.domainPatterns = {
        QStringLiteral("*.windowsupdate.com"),
        QStringLiteral("*.delivery.mp.microsoft.com"),
        QStringLiteral("*.windowsupdate.microsoft.com")
    };
    rules.append(windowsUpdateEndpoints);

    CatalogRule chromeUpdate = builtinRule(
        QStringLiteral("builtin-chrome-update"),
        CatalogCategory::BrowserUpdate,
        QStringLiteral("Google-signed Chrome updater"));
    chromeUpdate.publisherContains = QStringLiteral("google");
    chromeUpdate.productContains = QStringLiteral("update");
    rules.append(chromeUpdate);

    CatalogRule chromeEndpoint = builtinRule(
        QStringLiteral("builtin-chrome-update-endpoint"),
        CatalogCategory::BrowserUpdate,
        QStringLiteral("Chrome update endpoint"));
    chromeEndpoint.domainPatterns = { QStringLiteral("update.googleapis.com") };
    rules.append(chromeEndpoint);

    CatalogRule edgeUpdate = builtinRule(
        QStringLiteral("builtin-edge-update"),
        CatalogCategory::BrowserUpdate,
        QStringLiteral("Microsoft-signed Edge updater"));
    edgeUpdate.publisherContains = QStringLiteral("microsoft");
    edgeUpdate.productContains = QStringLiteral("edge update");
    rules.append(edgeUpdate);

    CatalogRule braveUpdate = builtinRule(
        QStringLiteral("builtin-brave-update"),
        CatalogCategory::BrowserUpdate,
        QStringLiteral("Brave-signed updater"));
    braveUpdate.publisherContains = QStringLiteral("brave");
    braveUpdate.productContains = QStringLiteral("update");
    rules.append(braveUpdate);

    CatalogRule onedrive = builtinRule(
        QStringLiteral("builtin-onedrive"),
        CatalogCategory::CloudSync,
        QStringLiteral("Microsoft-signed OneDrive sync client"));
    onedrive.publisherContains = QStringLiteral("microsoft");
    onedrive.productContains = QStringLiteral("onedrive");
    rules.append(onedrive);

    CatalogRule steam = builtinRule(
        QStringLiteral("builtin-steam"),
        CatalogCategory::GameLauncher,
        QStringLiteral("Steam launcher"));
    steam.executableName = QStringLiteral("steam.exe");
    rules.append(steam);

    CatalogRule epic = builtinRule(
        QStringLiteral("builtin-epic-games-launcher"),
        CatalogCategory::GameLauncher,
        QStringLiteral("Epic Games launcher"));
    epic.executableName = QStringLiteral("epicgameslauncher.exe");
    rules.append(epic);

    CatalogRule visualStudioCode = builtinRule(
        QStringLiteral("builtin-visual-studio-code"),
        CatalogCategory::DeveloperTool,
        QStringLiteral("Visual Studio Code"));
    visualStudioCode.executableName = QStringLiteral("code.exe");
    rules.append(visualStudioCode);

    CatalogRule npm = builtinRule(
        QStringLiteral("builtin-npm-registry"),
        CatalogCategory::PackageManager,
        QStringLiteral("npm package registry"));
    npm.domainPatterns = { QStringLiteral("registry.npmjs.org") };
    rules.append(npm);

    return rules;
}

void EndpointCatalog::resetToBuiltins()
{
    m_rules = builtinRules();
    m_catalogVersion = QString::fromLatin1(EndpointCatalogContract::kBuiltinVersion);
}

bool EndpointCatalog::setCatalogVersion(const QString &version, QString *error)
{
    const QString value = version.trimmed();
    if (value.isEmpty() || value.size() > 64) {
        if (error) *error = errorText(QStringLiteral("catalog version is invalid"));
        return false;
    }
    m_catalogVersion = value;
    return true;
}

bool EndpointCatalog::validateRule(const CatalogRule &rule, QString *error)
{
    auto fail = [error](const QString &message) {
        if (error) *error = message;
        return false;
    };

    const QString id = rule.id.trimmed();
    if (id.isEmpty() || id.size() > 128) {
        return fail(QStringLiteral("catalog rule id is missing or too long"));
    }
    for (const QChar character : id) {
        const ushort code = character.unicode();
        const bool letter = (code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z');
        const bool digit = code >= '0' && code <= '9';
        if (!letter && !digit && character != QLatin1Char('-') &&
            character != QLatin1Char('_') && character != QLatin1Char('.')) {
            return fail(QStringLiteral("catalog rule \"%1\" has an invalid id").arg(id));
        }
    }
    if (rule.category == CatalogCategory::Unknown) {
        return fail(QStringLiteral("catalog rule \"%1\" has no category").arg(id));
    }
    if (rule.explanation.trimmed().isEmpty() || rule.explanation.size() > 512) {
        return fail(QStringLiteral(
            "catalog rule \"%1\" needs a short explanation").arg(id));
    }

    if (rule.identityId.size() > 128)
        return fail(QStringLiteral("catalog rule \"%1\" identity id is too long").arg(id));
    if (rule.publisherContains.size() > 128 || rule.productContains.size() > 128) {
        return fail(QStringLiteral(
            "catalog rule \"%1\" publisher/product pattern is too long").arg(id));
    }
    if (rule.executableName.size() > 260 ||
        rule.executableName.contains(QLatin1Char('/')) ||
        rule.executableName.contains(QLatin1Char('\\'))) {
        return fail(QStringLiteral(
            "catalog rule \"%1\" executable name is invalid").arg(id));
    }
    if (rule.executablePath.size() > 1024) {
        return fail(QStringLiteral(
            "catalog rule \"%1\" executable path is too long").arg(id));
    }
    if (rule.serviceName.size() > 256)
        return fail(QStringLiteral("catalog rule \"%1\" service name is too long").arg(id));

    if (rule.domainPatterns.size() > 32)
        return fail(QStringLiteral("catalog rule \"%1\" has too many domains").arg(id));
    for (const QString &pattern : rule.domainPatterns) {
        if (!validDomainPattern(pattern)) {
            return fail(QStringLiteral(
                "catalog rule \"%1\" has an invalid domain pattern \"%2\"")
                .arg(id, pattern));
        }
    }

    if (rule.addressPrefixes.size() > 32)
        return fail(QStringLiteral(
            "catalog rule \"%1\" has too many address prefixes").arg(id));
    for (const QString &prefix : rule.addressPrefixes) {
        AddressPrefix parsed;
        if (!parseAddressPrefix(prefix, parsed)) {
            return fail(QStringLiteral(
                "catalog rule \"%1\" has an invalid address prefix \"%2\"")
                .arg(id, prefix));
        }
    }

    if (!rule.hasCriteria()) {
        return fail(QStringLiteral(
            "catalog rule \"%1\" has no matching criteria").arg(id));
    }
    return true;
}

QList<CatalogMatch> EndpointCatalog::matches(const CatalogQuery &query) const
{
    QList<MatchResult> ranked;
    for (const CatalogRule &rule : m_rules) {
        CatalogMatch match;
        if (!matchRule(rule, query, &match)) continue;
        MatchResult entry;
        entry.match = match;
        entry.specificity = criteriaCount(rule);
        ranked.append(entry);
    }

    std::stable_sort(ranked.begin(), ranked.end(),
                     [](const MatchResult &left, const MatchResult &right) {
        if (left.specificity != right.specificity)
            return left.specificity > right.specificity;
        return sourceRank(left.match.source) > sourceRank(right.match.source);
    });

    QList<CatalogMatch> result;
    result.reserve(ranked.size());
    for (const MatchResult &entry : ranked) result.append(entry.match);
    return result;
}

CatalogMatch EndpointCatalog::bestMatch(const CatalogQuery &query) const
{
    const QList<CatalogMatch> all = matches(query);
    return all.isEmpty() ? CatalogMatch() : all.first();
}

bool EndpointCatalog::upsertRule(const CatalogRule &rule, QString *error)
{
    CatalogRule stored = rule;
    stored.source = CatalogRuleSource::User;
    if (!validateRule(stored, error)) return false;

    int existing = -1;
    for (int i = 0; i < m_rules.size(); ++i) {
        if (m_rules.at(i).id == stored.id) {
            existing = i;
            break;
        }
    }
    if (existing < 0 && m_rules.size() >= EndpointCatalogContract::kMaxRules) {
        if (error) *error = errorText(QStringLiteral("catalog rule limit reached"));
        return false;
    }
    if (existing >= 0) m_rules.removeAt(existing);
    m_rules.append(stored);
    return true;
}

bool EndpointCatalog::removeRule(const QString &id, QString *error)
{
    for (int i = 0; i < m_rules.size(); ++i) {
        if (m_rules.at(i).id != id) continue;
        if (m_rules.at(i).source == CatalogRuleSource::BuiltIn) {
            if (error) *error = errorText(QStringLiteral(
                "bundled rule \"%1\" cannot be removed; disable it instead").arg(id));
            return false;
        }
        m_rules.removeAt(i);
        return true;
    }
    if (error) *error = errorText(QStringLiteral("catalog rule \"%1\" was not found").arg(id));
    return false;
}

bool EndpointCatalog::setRuleEnabled(const QString &id, bool enabled, QString *error)
{
    for (int i = 0; i < m_rules.size(); ++i) {
        if (m_rules.at(i).id != id) continue;
        CatalogRule rule = m_rules.at(i);
        // A bundled rule is disabled by a local override, not by mutating the
        // built-in set, so resetToBuiltins() always restores a safe default.
        if (rule.source == CatalogRuleSource::BuiltIn)
            rule.source = CatalogRuleSource::User;
        rule.enabled = enabled;
        m_rules[i] = rule;
        return true;
    }
    if (error) *error = errorText(QStringLiteral("catalog rule \"%1\" was not found").arg(id));
    return false;
}

QString EndpointCatalog::toJson() const
{
    return serializeDocument(m_rules, m_catalogVersion);
}

bool EndpointCatalog::importJson(const QString &json, QString *error)
{
    QList<CatalogRule> imported;
    QString version;
    if (!parseDocument(json, &imported, &version, error)) return false;

    for (CatalogRule &rule : imported) rule.source = CatalogRuleSource::Imported;

    QList<CatalogRule> userRules;
    QSet<QString> userIds;
    for (const CatalogRule &rule : m_rules) {
        if (rule.source != CatalogRuleSource::User) continue;
        userRules.append(rule);
        userIds.insert(rule.id);
    }
    QSet<QString> importedIds;
    for (const CatalogRule &rule : imported) importedIds.insert(rule.id);

    QList<CatalogRule> merged;
    for (const CatalogRule &rule : builtinRules()) {
        if (importedIds.contains(rule.id) || userIds.contains(rule.id)) continue;
        merged.append(rule);
    }
    for (const CatalogRule &rule : imported) {
        if (userIds.contains(rule.id)) continue;
        merged.append(rule);
    }
    merged += userRules;
    if (merged.size() > EndpointCatalogContract::kMaxRules) {
        if (error) *error = errorText(QStringLiteral("catalog rule limit reached"));
        return false;
    }

    m_rules = merged;
    m_catalogVersion = version;
    return true;
}

bool EndpointCatalog::save(QString *error) const
{
    QList<CatalogRule> custom;
    for (const CatalogRule &rule : m_rules) {
        if (rule.source != CatalogRuleSource::BuiltIn) custom.append(rule);
    }

    QSettings settings;
    settings.beginGroup(QString::fromLatin1(kSettingsGroup));
    settings.setValue(QString::fromLatin1(kSettingsDocumentKey),
                      serializeDocument(custom, m_catalogVersion));
    settings.endGroup();
    settings.sync();

    if (settings.status() != QSettings::NoError) {
        if (error) *error = errorText(QStringLiteral("catalog settings could not be saved"));
        return false;
    }
    return true;
}

bool EndpointCatalog::load(QString *error)
{
    QSettings settings;
    settings.beginGroup(QString::fromLatin1(kSettingsGroup));
    const QString document = settings.value(
        QString::fromLatin1(kSettingsDocumentKey)).toString();
    settings.endGroup();

    if (document.trimmed().isEmpty()) {
        resetToBuiltins();
        return true;
    }

    QList<CatalogRule> stored;
    QString version;
    if (!parseDocument(document, &stored, &version, error)) return false;

    if (stored.size() > EndpointCatalogContract::kMaxRules) {
        if (error) *error = errorText(QStringLiteral("stored catalog has too many rules"));
        return false;
    }

    QList<CatalogRule> custom;
    for (CatalogRule &rule : stored) {
        // Only the binary can claim a bundled rule; a local document cannot.
        if (rule.source == CatalogRuleSource::BuiltIn)
            rule.source = CatalogRuleSource::User;
        custom.append(rule);
    }

    QSet<QString> customIds;
    for (const CatalogRule &rule : custom) customIds.insert(rule.id);

    QList<CatalogRule> merged;
    for (const CatalogRule &rule : builtinRules()) {
        if (customIds.contains(rule.id)) continue;
        merged.append(rule);
    }
    merged += custom;
    if (merged.size() > EndpointCatalogContract::kMaxRules) {
        if (error) *error = errorText(QStringLiteral("catalog rule limit reached"));
        return false;
    }

    m_rules = merged;
    m_catalogVersion = version;
    return true;
}
