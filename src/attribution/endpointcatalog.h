/**
 * @file    endpointcatalog.h
 * @brief   Versioned local rules linking publisher, executable identity,
 *          service, and endpoint evidence to activity categories (NG-034).
 * @author  Ali Sakkaf
 *
 * The catalog is a classification aid only. It contains no policy action and no
 * enforcement channel, so loading or importing a catalog can never block, shape,
 * or terminate traffic by itself.
 */
#pragma once

#include <QList>
#include <QMetaType>
#include <QString>
#include <QStringList>

/**
 * Activity categories the catalog can attribute. These follow the scenarios in
 * PRD.md FR-5; `Unknown` is the absence of a match and is never valid on a rule.
 */
enum class CatalogCategory
{
    WindowsUpdate,
    BackgroundTransfer,
    BrowserUpdate,
    CloudSync,
    GameLauncher,
    DeveloperTool,
    PackageManager,
    ForegroundDownload,
    Unknown
};

QString catalogCategoryToken(CatalogCategory category);
QString catalogCategoryDisplayName(CatalogCategory category);
bool catalogCategoryFromToken(const QString &token, CatalogCategory *category);
QStringList catalogCategoryTokens();

/// Where a rule came from. Bundled rules ship with the binary; imported rules
/// come from a versioned catalog file; user rules are local edits.
enum class CatalogRuleSource { BuiltIn, Imported, User };

QString catalogRuleSourceToken(CatalogRuleSource source);
bool catalogRuleSourceFromToken(const QString &token, CatalogRuleSource *source);

/**
 * One catalog rule. Every populated criterion must match (a logical AND), and
 * each list criterion matches when any of its patterns matches. At least one
 * criterion is required, so a rule cannot match everything.
 *
 * Scalar criteria are matched case-insensitively. `publisherContains` and
 * `productContains` are substring matches against verified identity metadata.
 * Domain patterns are exact names or a leading `*.` suffix wildcard. Address
 * prefixes are IPv4/IPv6 literals with an optional CIDR prefix length.
 */
struct CatalogRule
{
    QString id;
    CatalogCategory category = CatalogCategory::Unknown;
    QString explanation;
    CatalogRuleSource source = CatalogRuleSource::BuiltIn;
    bool enabled = true;

    QString identityId;
    QString publisherContains;
    QString productContains;
    QString executableName;
    QString executablePath;
    QString serviceName;
    QStringList domainPatterns;
    QStringList addressPrefixes;

    bool hasCriteria() const;
};

/// Evidence supplied by the observation/identity layers. Empty fields simply do
/// not satisfy a criterion that asks for them; they never count as a match.
struct CatalogQuery
{
    QString identityId;
    QString publisher;
    QString product;
    QString executableName;
    QString executablePath;
    QString serviceName;
    QString domain;
    QString remoteAddress;
};

/// The explanation of one matched rule. There is intentionally no action field.
struct CatalogMatch
{
    bool matched = false;
    QString ruleId;
    CatalogCategory category = CatalogCategory::Unknown;
    QString explanation;
    QStringList matchedOn;
    CatalogRuleSource source = CatalogRuleSource::BuiltIn;
};
Q_DECLARE_METATYPE(CatalogMatch)

/**
 * Local catalog. The constructor loads the bundled rules. `load()` then merges
 * persisted user/imported rules, `save()` writes only those local rules, and
 * `importJson()` atomically replaces imported rules from a versioned document.
 *
 * JSON documents use `format` = "netguard.endpoint-catalog" and schema version
 * 1. A document from a newer schema, a malformed rule, a duplicate id, or an
 * invalid domain/address pattern is rejected as a whole; the current catalog is
 * left untouched.
 */
class EndpointCatalog
{
public:
    EndpointCatalog();

    static QList<CatalogRule> builtinRules();

    const QList<CatalogRule> &rules() const { return m_rules; }
    QString catalogVersion() const { return m_catalogVersion; }
    bool setCatalogVersion(const QString &version, QString *error = nullptr);

    /// Every matching rule, most specific first (more populated criteria win,
    /// then user rules over imported over bundled rules).
    QList<CatalogMatch> matches(const CatalogQuery &query) const;
    CatalogMatch bestMatch(const CatalogQuery &query) const;

    /// Replace a rule by id, marking it as a user rule. Bundled rules can be
    /// overridden this way.
    bool upsertRule(const CatalogRule &rule, QString *error = nullptr);
    /// Remove a user/imported rule. Bundled rules cannot be removed; disable
    /// them instead so the blocklist-free default survives a reset.
    bool removeRule(const QString &id, QString *error = nullptr);
    /// Disable or re-enable a rule. Disabling a bundled rule creates a local
    /// user override, so the choice survives a reload.
    bool setRuleEnabled(const QString &id, bool enabled, QString *error = nullptr);

    QString toJson() const;
    bool importJson(const QString &json, QString *error = nullptr);

    bool save(QString *error = nullptr) const;
    bool load(QString *error = nullptr);
    void resetToBuiltins();

    static bool validateRule(const CatalogRule &rule, QString *error = nullptr);

private:
    QList<CatalogRule> m_rules;
    QString m_catalogVersion;
};

namespace EndpointCatalogContract {
constexpr int kSchemaVersion = 1;
constexpr int kMaxRules = 500;
constexpr int kMaxRulesPerJson = 2000;
const char *const kFormat = "netguard.endpoint-catalog";
const char *const kBuiltinVersion = "2026.11.1";
}
