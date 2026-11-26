/**
 * @file    datasaverrules.cpp
 * @brief   Pinned rules and session overrides (DS-005).
 * @author  Oasis
 */
#include "datasaverrules.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QMetaType>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSettings>
#include <QVariant>

namespace {

using Action = NetworkPolicy::Action;

bool fail(QString *error, const QString &message)
{
    if (error) *error = message;
    return false;
}

QDateTime utcNow()
{
    return QDateTime::currentDateTimeUtc();
}

QDateTime normalizedTime(const QDateTime &value)
{
    return value.isValid() ? value.toUTC() : QDateTime();
}

QString generatedId(const QString &prefix, const QString &material)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(material.toUtf8());
    hash.addData(QByteArray::number(QRandomGenerator::global()->generate64()));
    return prefix + QString::fromLatin1(hash.result().toHex().left(16));
}

bool validId(const QString &id, const QString &prefix)
{
    static const QRegularExpression hex(QStringLiteral("^[0-9a-f]{8,32}$"));
    return id.startsWith(prefix) && hex.match(id.mid(prefix.size())).hasMatch();
}

bool validFlowId(const QString &id)
{
    return validId(id, QStringLiteral("flow_"));
}

QString actionToken(Action action, bool continueAfterNotify)
{
    switch (action) {
    case Action::Allow: return QStringLiteral("allow");
    case Action::Notify:
        return continueAfterNotify ? QStringLiteral("notify_then_continue")
                                   : QStringLiteral("notify");
    case Action::Throttle: return QStringLiteral("throttle");
    case Action::Block: return QStringLiteral("block");
    case Action::Ask:
    case Action::Schedule:
    case Action::NoAction:
        break;
    }
    return QString();
}

bool actionFromToken(const QString &text, Action *action, bool *continueAfterNotify)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("allow")) {
        if (action) *action = Action::Allow;
        if (continueAfterNotify) *continueAfterNotify = false;
        return true;
    }
    if (token == QStringLiteral("notify")) {
        if (action) *action = Action::Notify;
        if (continueAfterNotify) *continueAfterNotify = false;
        return true;
    }
    if (token == QStringLiteral("notify_then_continue")) {
        if (action) *action = Action::Notify;
        if (continueAfterNotify) *continueAfterNotify = true;
        return true;
    }
    if (token == QStringLiteral("throttle")) {
        if (action) *action = Action::Throttle;
        if (continueAfterNotify) *continueAfterNotify = false;
        return true;
    }
    if (token == QStringLiteral("block")) {
        if (action) *action = Action::Block;
        if (continueAfterNotify) *continueAfterNotify = false;
        return true;
    }
    return false;
}

QString directionToken(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("download");
    case NetworkDirection::Upload: return QStringLiteral("upload");
    case NetworkDirection::Both: return QStringLiteral("both");
    }
    return QStringLiteral("both");
}

bool directionFromToken(const QString &text, NetworkDirection *direction)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("download")) { if (direction) *direction = NetworkDirection::Download; return true; }
    if (token == QStringLiteral("upload")) { if (direction) *direction = NetworkDirection::Upload; return true; }
    if (token == QStringLiteral("both")) { if (direction) *direction = NetworkDirection::Both; return true; }
    return false;
}

bool validDirection(NetworkDirection direction)
{
    return direction == NetworkDirection::Download || direction == NetworkDirection::Upload
           || direction == NetworkDirection::Both;
}

bool pinnedActionSupported(Action action, QString *error)
{
    switch (action) {
    case Action::Allow:
    case Action::Notify:
    case Action::Throttle:
    case Action::Block:
        return true;
    case Action::Ask:
    case Action::Schedule:
    case Action::NoAction:
        break;
    }
    return fail(error, QStringLiteral("unsupported pinned action"));
}

bool sessionActionSupported(Action action, QString *error)
{
    switch (action) {
    case Action::Allow:
    case Action::Notify:
    case Action::Throttle:
        return true;
    case Action::Block:
        return fail(error, QStringLiteral("a session override cannot block; a block requires a pinned rule"));
    case Action::Ask:
    case Action::Schedule:
    case Action::NoAction:
        break;
    }
    return fail(error, QStringLiteral("unsupported session action"));
}

QString pinnedDomainPattern(const QJsonObject &object)
{
    if (object.value(QStringLiteral("domain")).isString())
        return object.value(QStringLiteral("domain")).toString();
    if (object.value(QStringLiteral("domainPattern")).isString())
        return object.value(QStringLiteral("domainPattern")).toString();
    return QString();
}

bool readOptionalTime(const QJsonObject &object, const QString &key, QDateTime *value,
                      QString *error)
{
    const QJsonValue raw = object.value(key);
    if (raw.isUndefined() || raw.isNull()) {
        if (value) *value = QDateTime();
        return true;
    }
    if (!raw.isString())
        return fail(error, QStringLiteral("invalid \"%1\"").arg(key));
    const QDateTime parsed = QDateTime::fromString(raw.toString(), Qt::ISODate);
    if (!parsed.isValid())
        return fail(error, QStringLiteral("invalid \"%1\"").arg(key));
    if (value) *value = parsed.toUTC();
    return true;
}

bool readOptionalBool(const QJsonObject &object, const QString &key, bool *present, bool *value,
                      QString *error)
{
    const QJsonValue raw = object.value(key);
    if (raw.isUndefined()) {
        if (present) *present = false;
        return true;
    }
    if (!raw.isBool())
        return fail(error, QStringLiteral("invalid \"%1\"").arg(key));
    if (present) *present = true;
    if (value) *value = raw.toBool();
    return true;
}

bool integerVariant(const QVariant &variant, int *value)
{
    switch (variant.metaType().id()) {
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::LongLong:
    case QMetaType::ULongLong:
    case QMetaType::Short:
    case QMetaType::UShort: {
        bool ok = false;
        const int parsed = variant.toInt(&ok);
        if (ok && value) *value = parsed;
        return ok;
    }
    default:
        return false;
    }
}

int pinSpecificity(const QString &pattern)
{
    if (pattern == QStringLiteral("*")) return 1;
    if (pattern.startsWith(QStringLiteral("*."))) return 1000 + pattern.size();
    return 100000;
}

int sessionSpecificity(const SessionOverride &override)
{
    if (override.scope == SessionScope::Flow) return 200000;
    const QString pattern = RuleResolver::normalizeDomainPattern(override.domainPattern);
    if (pattern == QStringLiteral("*")) return 1;
    if (pattern.startsWith(QStringLiteral("*."))) return 1000 + pattern.size();
    return 100000;
}

bool sameAction(const RuleMatch &match, Action action, bool continueAfterNotify)
{
    return match.action == action && match.continueAfterNotify == continueAfterNotify;
}

} // namespace

bool PinnedRule::isActiveAt(const QDateTime &now) const
{
    if (!expiresAt.isValid()) return true;
    const QDateTime current = now.isValid() ? now.toUTC() : utcNow();
    return current < expiresAt.toUTC();
}

QString sessionScopeToken(SessionScope scope)
{
    return scope == SessionScope::Flow ? QStringLiteral("flow")
                                       : QStringLiteral("executable_domain");
}

bool sessionScopeFromToken(const QString &text, SessionScope *scope)
{
    if (text.compare(QStringLiteral("flow"), Qt::CaseInsensitive) == 0) {
        if (scope) *scope = SessionScope::Flow;
        return true;
    }
    if (text.compare(QStringLiteral("executable_domain"), Qt::CaseInsensitive) == 0
        || text.compare(QStringLiteral("executable"), Qt::CaseInsensitive) == 0) {
        if (scope) *scope = SessionScope::ExecutableDomain;
        return true;
    }
    return false;
}

bool SessionOverride::isActiveAt(const QDateTime &now) const
{
    if (!expiresAt.isValid()) return true;
    const QDateTime current = now.isValid() ? now.toUTC() : utcNow();
    return current < expiresAt.toUTC();
}

QString RuleResolver::normalizeExecutable(const QString &name)
{
    QString base = name.trimmed();
    const int slash = base.lastIndexOf(QLatin1Char('/'));
    const int backslash = base.lastIndexOf(QLatin1Char('\\'));
    const int cut = qMax(slash, backslash);
    if (cut >= 0) base = base.mid(cut + 1);
    base = base.trimmed();
    if (base.isEmpty()) return QString();
    if (base.contains(QLatin1Char('/')) || base.contains(QLatin1Char('\\')))
        return QString();
    return base.toLower();
}

QString RuleResolver::normalizeDomainPattern(const QString &pattern)
{
    QString text = pattern.trimmed().toLower();
    while (text.endsWith(QLatin1Char('.'))) text.chop(1);
    if (text.isEmpty()) return QString();
    if (text == QStringLiteral("*")) return QStringLiteral("*");
    if (text.startsWith(QStringLiteral("*."))) {
        const QString suffix = normalizeFlowDomain(text.mid(2));
        return suffix.isEmpty() ? QString() : QStringLiteral("*.") + suffix;
    }
    return normalizeFlowDomain(text);
}

bool RuleResolver::executableMatches(const QString &ruleExecutable, const QString &exeName)
{
    const QString left = normalizeExecutable(ruleExecutable);
    const QString right = normalizeExecutable(exeName);
    return !left.isEmpty() && !right.isEmpty() && left == right;
}

bool RuleResolver::domainPatternMatches(const QString &pattern, const QString &domain)
{
    const QString normalizedPattern = normalizeDomainPattern(pattern);
    const QString normalizedDomain = normalizeFlowDomain(domain);
    if (normalizedPattern.isEmpty() || normalizedDomain.isEmpty())
        return false;
    if (normalizedPattern == QStringLiteral("*"))
        return true;
    if (normalizedPattern.startsWith(QStringLiteral("*."))) {
        const QString suffix = normalizedPattern.mid(2);
        if (suffix.isEmpty() || normalizedDomain.size() <= suffix.size())
            return false;
        return normalizedDomain.endsWith(suffix)
               && normalizedDomain.at(normalizedDomain.size() - suffix.size() - 1)
                      == QLatin1Char('.');
    }
    return normalizedDomain == normalizedPattern;
}

QJsonObject PinnedRuleStore::toJson(const PinnedRule &rule)
{
    QJsonObject object;
    object.insert(QStringLiteral("id"), rule.id);
    object.insert(QStringLiteral("origin"), QStringLiteral("pinned"));
    object.insert(QStringLiteral("executable"), rule.executable);
    object.insert(QStringLiteral("domain"), rule.domainPattern);
    object.insert(QStringLiteral("action"), actionToken(rule.action, rule.continueAfterNotify));
    object.insert(QStringLiteral("direction"), directionToken(rule.direction));
    object.insert(QStringLiteral("rateBitsPerSecond"),
                  static_cast<qint64>(rule.rateBitsPerSecond));
    object.insert(QStringLiteral("createdAt"),
                  rule.createdAt.toUTC().toString(Qt::ISODate));
    if (rule.expiresAt.isValid())
        object.insert(QStringLiteral("expiresAt"),
                      rule.expiresAt.toUTC().toString(Qt::ISODate));
    if (!rule.description.isEmpty())
        object.insert(QStringLiteral("description"), rule.description);
    return object;
}

bool PinnedRuleStore::fromJson(const QJsonObject &object, PinnedRule *rule, QString *error)
{
    if (!object.value(QStringLiteral("origin")).isString())
        return fail(error, QStringLiteral("pinned rule is missing its origin"));
    const QString origin = object.value(QStringLiteral("origin")).toString().trimmed().toLower();
    if (origin != QStringLiteral("pinned") && origin != QStringLiteral("user"))
        return fail(error, QStringLiteral("pinned rule has a non-user origin"));

    PinnedRule parsed;
    const QJsonValue idValue = object.value(QStringLiteral("id"));
    if (!idValue.isUndefined()) {
        if (!idValue.isString())
            return fail(error, QStringLiteral("invalid pinned rule id"));
        parsed.id = idValue.toString();
        if (!parsed.id.isEmpty() && !validId(parsed.id, QStringLiteral("pin_")))
            return fail(error, QStringLiteral("invalid pinned rule id"));
    }

    if (!object.value(QStringLiteral("executable")).isString())
        return fail(error, QStringLiteral("pinned rule is missing its executable"));
    parsed.executable = object.value(QStringLiteral("executable")).toString();

    parsed.domainPattern = pinnedDomainPattern(object);
    if (parsed.domainPattern.isEmpty())
        return fail(error, QStringLiteral("pinned rule is missing its domain"));

    const QJsonValue actionValue = object.value(QStringLiteral("action"));
    if (!actionValue.isString()
        || !actionFromToken(actionValue.toString(), &parsed.action,
                            &parsed.continueAfterNotify))
        return fail(error, QStringLiteral("invalid pinned action"));
    bool hasContinue = false;
    bool continueValue = false;
    if (!readOptionalBool(object, QStringLiteral("continueAfterNotify"), &hasContinue,
                          &continueValue, error))
        return false;
    if (hasContinue && continueValue != parsed.continueAfterNotify)
        return fail(error, QStringLiteral("continueAfterNotify disagrees with the action"));

    const QJsonValue directionValue = object.value(QStringLiteral("direction"));
    if (!directionValue.isUndefined()) {
        if (!directionValue.isString()
            || !directionFromToken(directionValue.toString(), &parsed.direction))
            return fail(error, QStringLiteral("invalid pinned direction"));
    }

    const QJsonValue rateValue = object.value(QStringLiteral("rateBitsPerSecond"));
    if (!rateValue.isUndefined()) {
        if (!rateValue.isDouble())
            return fail(error, QStringLiteral("invalid pinned rate"));
        const qint64 rate = rateValue.toInteger(-1);
        if (rate < 0)
            return fail(error, QStringLiteral("invalid pinned rate"));
        parsed.rateBitsPerSecond = static_cast<quint64>(rate);
    }

    if (!readOptionalTime(object, QStringLiteral("createdAt"), &parsed.createdAt, error)
        || !readOptionalTime(object, QStringLiteral("expiresAt"), &parsed.expiresAt, error))
        return false;

    if (object.value(QStringLiteral("description")).isString())
        parsed.description = object.value(QStringLiteral("description")).toString();

    if (!validate(&parsed, error))
        return false;
    if (rule) *rule = parsed;
    return true;
}

bool PinnedRuleStore::validate(PinnedRule *rule, QString *error)
{
    if (!rule) return fail(error, QStringLiteral("missing pinned rule"));

    rule->executable = RuleResolver::normalizeExecutable(rule->executable);
    if (rule->executable.isEmpty())
        return fail(error, QStringLiteral("pinned rule needs an executable base name"));

    rule->domainPattern = RuleResolver::normalizeDomainPattern(rule->domainPattern);
    if (rule->domainPattern.isEmpty())
        return fail(error, QStringLiteral("pinned rule needs a valid domain or wildcard"));

    if (!pinnedActionSupported(rule->action, error))
        return false;
    if (!validDirection(rule->direction))
        return fail(error, QStringLiteral("invalid pinned direction"));

    if (rule->action == Action::Throttle) {
        if (rule->rateBitsPerSecond == 0)
            return fail(error, QStringLiteral("a throttling pinned rule needs a positive rate"));
    } else {
        rule->rateBitsPerSecond = 0;
    }

    if (rule->action != Action::Notify)
        rule->continueAfterNotify = false;

    rule->createdAt = normalizedTime(rule->createdAt);
    if (!rule->createdAt.isValid())
        rule->createdAt = utcNow();
    rule->expiresAt = normalizedTime(rule->expiresAt);

    if (rule->id.isEmpty()) {
        rule->id = generatedId(QStringLiteral("pin_"),
                               QStringLiteral("%1|%2|%3|%4")
                                   .arg(rule->executable, rule->domainPattern,
                                        actionToken(rule->action, rule->continueAfterNotify),
                                        QString::number(rule->createdAt.toMSecsSinceEpoch())));
    } else if (!validId(rule->id, QStringLiteral("pin_"))) {
        return fail(error, QStringLiteral("invalid pinned rule id"));
    }
    return true;
}

PinnedRuleLoadResult PinnedRuleStore::load()
{
    PinnedRuleLoadResult result;
    QSettings settings;
    settings.beginGroup(storageGroup());

    const QVariant versionValue = settings.value(QStringLiteral("schemaVersion"), 1);
    int version = 1;
    if (!integerVariant(versionValue, &version) || version < 1) {
        result.diagnostic = QStringLiteral("the pinned rule store has an unreadable schema version");
        settings.endGroup();
        return result;
    }
    if (version > DataSaverRules::kSchemaVersion) {
        result.rejectedNewer = true;
        result.diagnostic = QStringLiteral("the pinned rule store uses newer schema version %1")
                                .arg(version);
        settings.endGroup();
        return result;
    }

    const QString json = settings.value(QStringLiteral("rules")).toString();
    settings.endGroup();
    if (json.trimmed().isEmpty())
        return result;

    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8());
    if (!document.isArray()) {
        result.diagnostic = QStringLiteral("the pinned rule store is not a JSON array");
        return result;
    }

    const QJsonArray array = document.array();
    for (const QJsonValue &value : array) {
        if (!value.isObject()) {
            ++result.skipped;
            continue;
        }
        PinnedRule rule;
        QString error;
        if (!fromJson(value.toObject(), &rule, &error)) {
            ++result.skipped;
            if (!result.diagnostic.isEmpty()) result.diagnostic += QStringLiteral("; ");
            result.diagnostic += error;
            continue;
        }
        result.rules.append(rule);
    }
    return result;
}

bool PinnedRuleStore::loadForWrite(QList<PinnedRule> *rules, QString *error)
{
    const PinnedRuleLoadResult loaded = load();
    if (loaded.rejectedNewer)
        return fail(error, loaded.diagnostic);
    if (rules) *rules = loaded.rules;
    return true;
}

bool PinnedRuleStore::save(const QList<PinnedRule> &rules, QString *error)
{
    // Never replace a store written by a newer build, even through the low-level
    // save path.
    QSettings existing;
    existing.beginGroup(storageGroup());
    const QVariant versionValue = existing.value(QStringLiteral("schemaVersion"));
    int storedVersion = 0;
    const bool versionReadable = integerVariant(versionValue, &storedVersion);
    existing.endGroup();
    if (versionReadable && storedVersion > DataSaverRules::kSchemaVersion) {
        return fail(error, QStringLiteral("the pinned rule store uses a newer schema"));
    }

    QJsonArray array;
    for (const PinnedRule &rule : rules) {
        PinnedRule validated = rule;
        if (!validate(&validated, error))
            return false;
        array.append(toJson(validated));
    }

    QSettings settings;
    settings.beginGroup(storageGroup());
    settings.setValue(QStringLiteral("schemaVersion"), DataSaverRules::kSchemaVersion);
    settings.setValue(QStringLiteral("rules"),
                      QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact)));
    settings.endGroup();
    settings.sync();
    if (settings.status() != QSettings::NoError)
        return fail(error, QStringLiteral("the pinned rule store could not be written"));
    return true;
}

bool PinnedRuleStore::add(PinnedRule &rule, bool alwaysAllowConfirmed, QString *error)
{
    if (rule.action == Action::Allow && !alwaysAllowConfirmed) {
        return fail(error,
                    QStringLiteral("Always Allow requires explicit confirmation before it is pinned"));
    }
    if (!validate(&rule, error))
        return false;

    QList<PinnedRule> rules;
    if (!loadForWrite(&rules, error))
        return false;
    for (const PinnedRule &existing : rules) {
        if (existing.id == rule.id)
            return fail(error, QStringLiteral("a pinned rule with this id already exists"));
    }
    rules.append(rule);
    return save(rules, error);
}

bool PinnedRuleStore::remove(const QString &id, QString *error)
{
    QList<PinnedRule> rules;
    if (!loadForWrite(&rules, error))
        return false;
    const int before = static_cast<int>(rules.size());
    for (int i = rules.size() - 1; i >= 0; --i) {
        if (rules.at(i).id == id)
            rules.removeAt(i);
    }
    if (static_cast<int>(rules.size()) == before)
        return true;
    return save(rules, error);
}

bool SessionOverrideStore::add(SessionOverride &override, QString *error)
{
    if (!sessionActionSupported(override.action, error))
        return false;
    if (!validDirection(override.direction))
        return fail(error, QStringLiteral("invalid session direction"));

    if (override.action == Action::Throttle) {
        if (override.rateBitsPerSecond == 0)
            return fail(error, QStringLiteral("a throttling session override needs a positive rate"));
    } else {
        override.rateBitsPerSecond = 0;
    }
    if (override.action != Action::Notify)
        override.continueAfterNotify = false;

    override.createdAt = normalizedTime(override.createdAt);
    if (!override.createdAt.isValid())
        override.createdAt = utcNow();
    override.expiresAt = normalizedTime(override.expiresAt);

    if (override.scope == SessionScope::Flow) {
        if (!validFlowId(override.flowId))
            return fail(error, QStringLiteral("a flow session override needs a valid flow id"));
    } else {
        override.executable = RuleResolver::normalizeExecutable(override.executable);
        override.domainPattern = RuleResolver::normalizeDomainPattern(override.domainPattern);
        if (override.executable.isEmpty() || override.domainPattern.isEmpty())
            return fail(error, QStringLiteral("a session override needs an executable and domain"));
    }

    if (override.id.isEmpty()) {
        override.id = generatedId(QStringLiteral("ses_"),
                                  QStringLiteral("%1|%2|%3|%4")
                                      .arg(sessionScopeToken(override.scope),
                                           override.flowId, override.executable,
                                           override.domainPattern));
    } else if (!validId(override.id, QStringLiteral("ses_"))) {
        return fail(error, QStringLiteral("invalid session override id"));
    }

    for (const SessionOverride &existing : m_overrides) {
        if (existing.id == override.id)
            return fail(error, QStringLiteral("a session override with this id already exists"));
    }
    m_overrides.append(override);
    return true;
}

bool SessionOverrideStore::remove(const QString &id)
{
    for (int i = m_overrides.size() - 1; i >= 0; --i) {
        if (m_overrides.at(i).id == id) {
            m_overrides.removeAt(i);
            return true;
        }
    }
    return false;
}

QList<SessionOverride> SessionOverrideStore::activeOverrides(const QDateTime &now) const
{
    QList<SessionOverride> active;
    for (const SessionOverride &override : m_overrides) {
        if (override.isActiveAt(now)) active.append(override);
    }
    return active;
}

RuleResolution RuleResolver::resolve(const FlowObservation &observation,
                                     const QList<PinnedRule> &pins,
                                     const QList<SessionOverride> &sessions,
                                     const QDateTime &now,
                                     const QList<LowerTierVote> &lowerTiers)
{
    const QString exeName = normalizeExecutable(observation.process.exeName);
    const QString domain = normalizeFlowDomain(observation.flow.domain);

    const PinnedRule *bestPin = nullptr;
    int bestPinScore = -1;
    for (const PinnedRule &pin : pins) {
        if (!pin.isActiveAt(now)) continue;
        if (!executableMatches(pin.executable, exeName)) continue;
        if (!domainPatternMatches(pin.domainPattern, domain)) continue;
        const int score = pinSpecificity(normalizeDomainPattern(pin.domainPattern));
        if (score > bestPinScore
            || (score == bestPinScore && bestPin && pin.id < bestPin->id)) {
            bestPin = &pin;
            bestPinScore = score;
        }
    }

    auto sessionMatches = [&](const SessionOverride &override) {
        if (!override.isActiveAt(now)) return false;
        if (override.scope == SessionScope::Flow) {
            return !override.flowId.isEmpty() && !observation.flow.flowId.isEmpty()
                   && override.flowId == observation.flow.flowId;
        }
        return executableMatches(override.executable, exeName)
               && domainPatternMatches(override.domainPattern, domain);
    };

    const SessionOverride *bestSession = nullptr;
    int bestSessionScore = -1;
    for (const SessionOverride &override : sessions) {
        if (!sessionMatches(override)) continue;
        const int score = sessionSpecificity(override);
        if (score > bestSessionScore
            || (score == bestSessionScore && bestSession && override.id < bestSession->id)) {
            bestSession = &override;
            bestSessionScore = score;
        }
    }

    RuleResolution resolution;
    if (bestPin) {
        resolution.matched = true;
        resolution.winner.matched = true;
        resolution.winner.tier = 1;
        resolution.winner.ruleId = bestPin->id;
        resolution.winner.origin = QStringLiteral("pinned");
        resolution.winner.action = bestPin->action;
        resolution.winner.continueAfterNotify = bestPin->continueAfterNotify;
        resolution.winner.direction = bestPin->direction;
        resolution.winner.rateBitsPerSecond = bestPin->rateBitsPerSecond;
        resolution.winner.scope = QStringLiteral("executable");
        resolution.winner.executable = bestPin->executable;
        resolution.winner.domain = domain;
        resolution.winner.flowId = observation.flow.flowId;
    } else if (bestSession) {
        resolution.matched = true;
        resolution.winner.matched = true;
        resolution.winner.tier = 2;
        resolution.winner.ruleId = bestSession->id;
        resolution.winner.origin = QStringLiteral("session");
        resolution.winner.action = bestSession->action;
        resolution.winner.continueAfterNotify = bestSession->continueAfterNotify;
        resolution.winner.direction = bestSession->direction;
        resolution.winner.rateBitsPerSecond = bestSession->rateBitsPerSecond;
        resolution.winner.scope = bestSession->scope == SessionScope::Flow
                                      ? QStringLiteral("flow")
                                      : QStringLiteral("executable");
        resolution.winner.executable = bestSession->executable;
        resolution.winner.domain = domain;
        resolution.winner.flowId = observation.flow.flowId;
    }

    if (!resolution.matched)
        return resolution;

    // A matching session is itself a lower tier when a pin wins. Lower-tier
    // votes supplied by the caller are checked the same way. Nothing here
    // writes to `pins` or `sessions`.
    QList<LowerTierVote> votes = lowerTiers;
    if (resolution.winner.tier == 1 && bestSession) {
        LowerTierVote vote;
        vote.tier = 2;
        vote.action = bestSession->action;
        vote.continueAfterNotify = bestSession->continueAfterNotify;
        vote.source = QStringLiteral("session");
        vote.ruleId = bestSession->id;
        votes.append(vote);
    }

    for (const LowerTierVote &vote : votes) {
        if (vote.tier <= resolution.winner.tier) continue;
        if (sameAction(resolution.winner, vote.action, vote.continueAfterNotify)) continue;
        if (!resolution.conflict.hasConflict
            || vote.tier < resolution.conflict.conflictingTier) {
            resolution.conflict.hasConflict = true;
            resolution.conflict.conflictingTier = vote.tier;
            resolution.conflict.conflictingRuleId = vote.ruleId;
            resolution.conflict.resolution = QStringLiteral("higher_tier_won");
            resolution.conflict.detail =
                QStringLiteral("tier %1 (%2) disagrees with %3")
                    .arg(vote.tier)
                    .arg(vote.source.isEmpty() ? QStringLiteral("lower tier") : vote.source,
                         resolution.winner.origin);
        }
    }
    return resolution;
}
