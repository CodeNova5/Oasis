/**
 * @file    datasavercache.cpp
 * @brief   Evidence fingerprint cache for Data Saver decisions (DS-007).
 * @author  Oasis
 */
#include "datasavercache.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonValue>
#include <QMutexLocker>
#include <QVariant>

#include <algorithm>

namespace {

using Action = NetworkPolicy::Action;

const QString kFingerprintPrefix = QStringLiteral("fp_");
const QString kEntriesKey = QStringLiteral("entries");
const QString kVersionKey = QStringLiteral("schemaVersion");

bool fail(QString *error, const QString &message)
{
    if (error) *error = message;
    return false;
}

bool integerVariant(const QVariant &value, int *out)
{
    bool ok = false;
    const int number = value.toInt(&ok);
    if (ok && out) *out = number;
    return ok;
}

QString roleToken(FlowProcessRole role)
{
    switch (role) {
    case FlowProcessRole::Main: return QStringLiteral("main");
    case FlowProcessRole::Child: return QStringLiteral("child");
    case FlowProcessRole::Service: return QStringLiteral("service");
    case FlowProcessRole::Unknown: break;
    }
    return QStringLiteral("unknown");
}

QString foregroundToken(FlowForegroundState state)
{
    switch (state) {
    case FlowForegroundState::ForegroundActive: return QStringLiteral("foreground_active");
    case FlowForegroundState::ForegroundIdle: return QStringLiteral("foreground_idle");
    case FlowForegroundState::Background: return QStringLiteral("background");
    case FlowForegroundState::Unknown: break;
    }
    return QStringLiteral("unknown");
}

/// `ip:port` / `[v6]:port` -> the bare, lower-case address. Ports differ per
/// flow and are never part of the identity.
QString remoteAddressKey(const QString &endpoint)
{
    QString address = endpoint.trimmed();
    const int colon = address.lastIndexOf(QLatin1Char(':'));
    if (colon > 0) address.truncate(colon);
    if (address.startsWith(QLatin1Char('[')) && address.endsWith(QLatin1Char(']')))
        address = address.mid(1, address.size() - 2);
    return address.toLower();
}

QString executableKeyFor(const FlowObservation &observation)
{
    const QString name = RuleResolver::normalizeExecutable(observation.process.exeName);
    if (name.isEmpty()) return QString();
    const QString version = observation.process.exeVersion.trimmed();
    return version.isEmpty() ? name : name + QLatin1Char('@') + version;
}

bool isFingerprint(const QString &value)
{
    if (!value.startsWith(kFingerprintPrefix)) return false;
    const QString hex = value.mid(kFingerprintPrefix.size());
    if (hex.size() != 64) return false;
    for (const QChar character : hex) {
        if (!((character >= QLatin1Char('0') && character <= QLatin1Char('9'))
              || (character >= QLatin1Char('a') && character <= QLatin1Char('f')))) {
            return false;
        }
    }
    return true;
}

QString utcNow(const QDateTime &now)
{
    return (now.isValid() ? now : QDateTime::currentDateTimeUtc()).toUTC().toString(Qt::ISODate);
}

QDateTime utcValue(const QDateTime &value)
{
    return value.toUTC();
}

QString cacheSourceTokenFromTokenSet(CacheSource source)
{
    switch (source) {
    case CacheSource::MeteredHotspot: return QStringLiteral("metered_hotspot");
    case CacheSource::ManualToggle: return QStringLiteral("manual_toggle");
    case CacheSource::BatterySaver: return QStringLiteral("battery_saver");
    }
    return QStringLiteral("manual_toggle");
}

} // namespace

QString cacheSourceToken(CacheSource source)
{
    return cacheSourceTokenFromTokenSet(source);
}

bool cacheSourceFromToken(const QString &text, CacheSource *source)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("metered_hotspot")) {
        if (source) *source = CacheSource::MeteredHotspot;
        return true;
    }
    if (token == QStringLiteral("manual_toggle")) {
        if (source) *source = CacheSource::ManualToggle;
        return true;
    }
    if (token == QStringLiteral("battery_saver")) {
        if (source) *source = CacheSource::BatterySaver;
        return true;
    }
    return false;
}

QString CacheKey::canonical() const
{
    return QStringList{executableKey, domainKey, processRole, foregroundState,
                       receiveBucket, durationBucket, source}
        .join(QStringLiteral("\n"));
}

bool CacheKey::operator==(const CacheKey &other) const
{
    return executableKey == other.executableKey && domainKey == other.domainKey
           && processRole == other.processRole && foregroundState == other.foregroundState
           && receiveBucket == other.receiveBucket && durationBucket == other.durationBucket
           && source == other.source;
}

QString receiveBucket(quint64 rxBytes)
{
    constexpr quint64 mib = 1024ULL * 1024ULL;
    if (rxBytes < 10 * mib) return QStringLiteral("below_10MB");
    if (rxBytes < 25 * mib) return QStringLiteral("10_25MB");
    if (rxBytes < 50 * mib) return QStringLiteral("25_50MB");
    if (rxBytes < 100 * mib) return QStringLiteral("50_100MB");
    return QStringLiteral("100MB_plus");
}

QString durationBucket(qint64 durationMs)
{
    if (durationMs < 10 * 1000) return QStringLiteral("burst_<10s");
    if (durationMs < 60 * 1000) return QStringLiteral("sustained_10_60s");
    return QStringLiteral("long_>60s");
}

QString fingerprintFor(const CacheKey &key)
{
    const QByteArray digest =
        QCryptographicHash::hash(key.canonical().toUtf8(), QCryptographicHash::Sha256);
    return kFingerprintPrefix + QString::fromLatin1(digest.toHex());
}

CacheKey buildCacheKey(const FlowObservation &observation, const CacheContext &context)
{
    CacheKey key;
    key.executableKey = executableKeyFor(observation);

    QString domain = normalizeFlowDomain(observation.flow.domain);
    if (domain.isEmpty()) {
        QString fallback = context.addressFallback.trimmed();
        if (fallback.isEmpty()) {
            const QString address = remoteAddressKey(observation.flow.remoteEndpoint);
            fallback = address.isEmpty() ? QStringLiteral("unknown_remote")
                                         : QStringLiteral("addr:%1").arg(address);
        }
        domain = fallback;
    }
    key.domainKey = domain;

    key.processRole = roleToken(observation.process.role);
    key.foregroundState = foregroundToken(observation.process.foregroundState);
    key.receiveBucket = receiveBucket(observation.metrics.rxBytes);
    key.durationBucket = durationBucket(observation.metrics.durationMs);
    key.source = cacheSourceTokenFromTokenSet(context.source);
    return key;
}

qint64 ttlSeconds(DecisionOrigin origin, double confidence, bool corroborated)
{
    // The confidence-derived AI TTLs below the profile row of the contract
    // table become reachable when DS-012/DS-013 add the `ai` origin. Until then
    // the local profile decision is the only cacheable source.
    Q_UNUSED(confidence)
    Q_UNUSED(corroborated)
    switch (origin) {
    case DecisionOrigin::Profile:
        // Local signatures are the highest-confidence source in the contract
        // table: 30 days, or a catalog-version change, whichever comes first.
        return DataSaverCache::kProfileTtlSeconds;
    case DecisionOrigin::Pinned:
    case DecisionOrigin::Session:
    case DecisionOrigin::Fallback:
    case DecisionOrigin::Cache:
        // User state is never cached; an ephemeral fallback is not evidence.
        return 0;
    }
    return 0;
}

QJsonObject cacheEntryToJson(const CacheEntry &entry)
{
    QJsonObject key;
    key.insert(QStringLiteral("executableKey"), entry.key.executableKey);
    key.insert(QStringLiteral("domainKey"), entry.key.domainKey);
    key.insert(QStringLiteral("processRole"), entry.key.processRole);
    key.insert(QStringLiteral("foregroundState"), entry.key.foregroundState);
    key.insert(QStringLiteral("receiveBucket"), entry.key.receiveBucket);
    key.insert(QStringLiteral("durationBucket"), entry.key.durationBucket);
    key.insert(QStringLiteral("source"), entry.key.source);

    QJsonObject object;
    object.insert(QStringLiteral("schemaVersion"), entry.schemaVersion);
    object.insert(QStringLiteral("fingerprint"), entry.fingerprint);
    object.insert(QStringLiteral("observationId"), entry.observationId);
    object.insert(QStringLiteral("decisionId"), entry.decisionId);
    object.insert(QStringLiteral("decisionSchemaVersion"), entry.decisionSchemaVersion);
    object.insert(QStringLiteral("decision"), entry.decision.toJson());
    object.insert(QStringLiteral("createdAt"), utcNow(entry.createdAt));
    object.insert(QStringLiteral("expiresAt"), utcNow(entry.expiresAt));
    if (!entry.auditId.isEmpty())
        object.insert(QStringLiteral("auditId"), entry.auditId);
    object.insert(QStringLiteral("catalogVersion"), entry.catalogVersion);
    object.insert(QStringLiteral("key"), key);
    return object;
}

bool cacheEntryFromJson(const QJsonObject &object, CacheEntry *entry, QString *error)
{
    if (!entry) return fail(error, QStringLiteral("no cache entry target"));

    const QJsonValue versionValue = object.value(QStringLiteral("schemaVersion"));
    int version = DataSaverCache::kSchemaVersion;
    if (!versionValue.isUndefined()) {
        if (!versionValue.isDouble())
            return fail(error, QStringLiteral("the cache entry has an unreadable schema version"));
        version = versionValue.toInt();
    }
    if (version != DataSaverCache::kSchemaVersion) {
        return fail(error, version > DataSaverCache::kSchemaVersion
                                ? QStringLiteral("the cache entry uses newer schema version %1")
                                      .arg(version)
                                : QStringLiteral("the cache entry has an unsupported schema version %1")
                                      .arg(version));
    }

    CacheEntry parsed;
    parsed.schemaVersion = version;

    const QJsonValue fingerprintValue = object.value(QStringLiteral("fingerprint"));
    if (!fingerprintValue.isString() || !isFingerprint(fingerprintValue.toString()))
        return fail(error, QStringLiteral("the cache entry has an invalid fingerprint"));
    parsed.fingerprint = fingerprintValue.toString();

    const QJsonValue observationValue = object.value(QStringLiteral("observationId"));
    if (!observationValue.isString()
        || !isFlowIdentifier(observationValue.toString(), QStringLiteral("obs_"))) {
        return fail(error, QStringLiteral("the cache entry has an invalid observationId"));
    }
    parsed.observationId = observationValue.toString();

    const QJsonValue decisionIdValue = object.value(QStringLiteral("decisionId"));
    if (!decisionIdValue.isString()
        || !isFlowIdentifier(decisionIdValue.toString(), QStringLiteral("dec_"))) {
        return fail(error, QStringLiteral("the cache entry has an invalid decisionId"));
    }
    parsed.decisionId = decisionIdValue.toString();

    const QJsonValue decisionVersionValue = object.value(QStringLiteral("decisionSchemaVersion"));
    if (!decisionVersionValue.isDouble()
        || decisionVersionValue.toInt() != PolicyDecision::kSchemaVersion) {
        return fail(error, QStringLiteral("the cache entry's decision schema is unsupported"));
    }
    parsed.decisionSchemaVersion = decisionVersionValue.toInt();

    if (!object.value(QStringLiteral("decision")).isObject())
        return fail(error, QStringLiteral("the cache entry has no decision"));
    QString decisionError;
    if (!PolicyDecision::fromJson(object.value(QStringLiteral("decision")).toObject(),
                                  &parsed.decision, &decisionError)) {
        return fail(error, QStringLiteral("the cache entry's decision is invalid: %1")
                               .arg(decisionError));
    }
    if (parsed.decision.origin != DecisionOrigin::Profile) {
        return fail(error, QStringLiteral("the cache entry's decision is not a cacheable origin"));
    }
    if (parsed.decision.decisionId != parsed.decisionId) {
        return fail(error, QStringLiteral("the cache entry decisionId does not match its decision"));
    }

    const QDateTime createdAt =
        QDateTime::fromString(object.value(QStringLiteral("createdAt")).toString(), Qt::ISODate);
    if (!createdAt.isValid())
        return fail(error, QStringLiteral("the cache entry has an invalid createdAt"));
    parsed.createdAt = createdAt.toUTC();

    const QDateTime expiresAt =
        QDateTime::fromString(object.value(QStringLiteral("expiresAt")).toString(), Qt::ISODate);
    if (!expiresAt.isValid() || expiresAt <= parsed.createdAt)
        return fail(error, QStringLiteral("the cache entry has an invalid expiresAt"));
    parsed.expiresAt = expiresAt.toUTC();

    parsed.auditId = object.value(QStringLiteral("auditId")).toString();

    const QJsonValue catalogValue = object.value(QStringLiteral("catalogVersion"));
    if (!catalogValue.isUndefined()) {
        if (!catalogValue.isString())
            return fail(error, QStringLiteral("the cache entry has an invalid catalogVersion"));
        parsed.catalogVersion = catalogValue.toString();
    }

    const QJsonValue keyValue = object.value(QStringLiteral("key"));
    if (!keyValue.isObject())
        return fail(error, QStringLiteral("the cache entry has no key"));
    const QJsonObject keyObject = keyValue.toObject();
    const QStringList keyFields{
        QStringLiteral("executableKey"), QStringLiteral("domainKey"),
        QStringLiteral("processRole"), QStringLiteral("foregroundState"),
        QStringLiteral("receiveBucket"), QStringLiteral("durationBucket"),
        QStringLiteral("source")};
    for (const QString &field : keyFields) {
        if (!keyObject.value(field).isString() || keyObject.value(field).toString().isEmpty())
            return fail(error, QStringLiteral("the cache entry key is missing %1").arg(field));
    }
    parsed.key.executableKey = keyObject.value(QStringLiteral("executableKey")).toString();
    parsed.key.domainKey = keyObject.value(QStringLiteral("domainKey")).toString();
    parsed.key.processRole = keyObject.value(QStringLiteral("processRole")).toString();
    parsed.key.foregroundState = keyObject.value(QStringLiteral("foregroundState")).toString();
    parsed.key.receiveBucket = keyObject.value(QStringLiteral("receiveBucket")).toString();
    parsed.key.durationBucket = keyObject.value(QStringLiteral("durationBucket")).toString();
    parsed.key.source = keyObject.value(QStringLiteral("source")).toString();
    if (fingerprintFor(parsed.key) != parsed.fingerprint) {
        return fail(error, QStringLiteral("the cache entry fingerprint does not match its key"));
    }

    *entry = parsed;
    return true;
}

DecisionCache::DecisionCache(int maxEntries)
    : m_maxEntries(qMax(1, maxEntries))
{
}

void DecisionCache::evictIfNeededLocked()
{
    while (m_entries.size() >= m_maxEntries && !m_entries.isEmpty()) {
        QString victim;
        QDateTime victimExpiry;
        for (auto it = m_entries.constBegin(); it != m_entries.constEnd(); ++it) {
            if (victim.isEmpty() || it.value().expiresAt < victimExpiry
                || (it.value().expiresAt == victimExpiry
                    && it.value().createdAt < m_entries.value(victim).createdAt)) {
                victim = it.key();
                victimExpiry = it.value().expiresAt;
            }
        }
        if (victim.isEmpty()) break;
        m_entries.remove(victim);
    }
}

bool DecisionCache::insert(const FlowObservation &observation, const CacheContext &context,
                           const PolicyDecision &decision, const QString &auditId,
                           const QDateTime &now, QString *error)
{
    if (!decision.validate(error)) return false;
    if (decision.origin != DecisionOrigin::Profile) {
        return fail(error, QStringLiteral("only a local profile decision is cacheable"));
    }
    if (decision.action == Action::Block) {
        return fail(error, QStringLiteral("a cache entry may never carry a hard block"));
    }

    const CacheKey key = buildCacheKey(observation, context);
    if (key.executableKey.isEmpty()) {
        return fail(error, QStringLiteral("the observation has no executable identity"));
    }

    const QString executable = RuleResolver::normalizeExecutable(decision.target.executable);
    if (executable.isEmpty()
        || executable != RuleResolver::normalizeExecutable(observation.process.exeName)) {
        return fail(error, QStringLiteral("the decision targets a different executable"));
    }
    const QString domain = normalizeFlowDomain(decision.target.domain);
    const QString observationDomain = normalizeFlowDomain(observation.flow.domain);
    if (domain != observationDomain) {
        return fail(error, QStringLiteral("the decision targets a different domain"));
    }

    const qint64 ttl =
        ttlSeconds(decision.origin, decision.confidence, !observationDomain.isEmpty());
    if (ttl <= 0) return fail(error, QStringLiteral("the decision origin is not cacheable"));

    const QDateTime reference = utcValue(now.isValid() ? now : QDateTime::currentDateTimeUtc());

    QMutexLocker locker(&m_mutex);
    CacheEntry entry;
    entry.fingerprint = fingerprintFor(key);
    entry.key = key;
    entry.observationId = observation.observationId;
    entry.decisionId = decision.decisionId;
    entry.decisionSchemaVersion = decision.schemaVersion;
    entry.decision = decision;
    entry.createdAt = reference;
    entry.expiresAt = reference.addSecs(ttl);
    entry.auditId = auditId;
    entry.catalogVersion = context.catalogVersion;

    if (m_entries.contains(entry.fingerprint)) m_entries.remove(entry.fingerprint);
    evictIfNeededLocked();
    m_entries.insert(entry.fingerprint, entry);
    return true;
}

bool DecisionCache::lookup(const FlowObservation &observation, const CacheContext &context,
                           PolicyDecision *decision, const QDateTime &now, QString *diagnostic)
{
    if (!decision) {
        if (diagnostic) *diagnostic = QStringLiteral("no decision target");
        return false;
    }

    const CacheKey key = buildCacheKey(observation, context);
    if (key.executableKey.isEmpty()) {
        if (diagnostic) *diagnostic = QStringLiteral("the observation has no executable identity");
        return false;
    }
    const QString fingerprint = fingerprintFor(key);
    QMutexLocker locker(&m_mutex);
    auto it = m_entries.find(fingerprint);
    if (it == m_entries.end()) return false;

    const QDateTime reference = utcValue(now.isValid() ? now : QDateTime::currentDateTimeUtc());
    const CacheEntry entry = it.value();

    // Any change to the seven key inputs produces a different fingerprint, so a
    // hit here already proves executable, domain, role, foreground, bucket, and
    // source are unchanged. The remaining dimensions are checked explicitly.
    if (entry.catalogVersion != context.catalogVersion) {
        m_entries.erase(it);
        if (diagnostic)
            *diagnostic = QStringLiteral("the cache entry was invalidated by a catalog change");
        return false;
    }
    if (!entry.isValidAt(reference)) {
        m_entries.erase(it);
        if (diagnostic) *diagnostic = QStringLiteral("the cache entry has expired");
        return false;
    }
    if (entry.decision.action == Action::Block) {
        m_entries.erase(it);
        if (diagnostic) *diagnostic = QStringLiteral("a cached hard block was discarded");
        return false;
    }

    PolicyDecision candidate = entry.decision;
    QString error;
    if (!candidate.validate(&error)) {
        m_entries.erase(it);
        if (diagnostic) *diagnostic = QStringLiteral("the cache entry was rejected: %1").arg(error);
        return false;
    }

    // Re-check the target against the evidence actually being resolved, not
    // just against the stored key.
    const QString executable =
        RuleResolver::normalizeExecutable(observation.process.exeName);
    if (RuleResolver::normalizeExecutable(candidate.target.executable) != executable) {
        m_entries.erase(it);
        if (diagnostic) *diagnostic = QStringLiteral("the cache entry targets a different executable");
        return false;
    }
    const QString domain = normalizeFlowDomain(observation.flow.domain);
    if (normalizeFlowDomain(candidate.target.domain) != domain) {
        m_entries.erase(it);
        if (diagnostic) *diagnostic = QStringLiteral("the cache entry targets a different domain");
        return false;
    }

    candidate.origin = DecisionOrigin::Cache;
    candidate.tier = decisionOriginTier(DecisionOrigin::Cache);
    candidate.conflict = DecisionConflict(); // a conflict belongs to the winning tier
    if (isFlowIdentifier(observation.observationId, QStringLiteral("obs_")))
        candidate.observationId = observation.observationId;
    if (!candidate.validate(&error)) {
        m_entries.erase(it);
        if (diagnostic)
            *diagnostic = QStringLiteral("the tier-4 candidate was rejected: %1").arg(error);
        return false;
    }
    *decision = candidate;
    return true;
}

bool DecisionCache::contains(const QString &fingerprint) const
{
    QMutexLocker locker(&m_mutex);
    return m_entries.contains(fingerprint);
}

bool DecisionCache::remove(const QString &fingerprint)
{
    QMutexLocker locker(&m_mutex);
    return m_entries.remove(fingerprint) > 0;
}

void DecisionCache::clear()
{
    QMutexLocker locker(&m_mutex);
    m_entries.clear();
}

int DecisionCache::count() const
{
    QMutexLocker locker(&m_mutex);
    return static_cast<int>(m_entries.size());
}

QList<CacheEntry> DecisionCache::entries() const
{
    QMutexLocker locker(&m_mutex);
    QList<CacheEntry> result = m_entries.values();
    std::sort(result.begin(), result.end(), [](const CacheEntry &left, const CacheEntry &right) {
        if (left.createdAt == right.createdAt) return left.fingerprint < right.fingerprint;
        return left.createdAt < right.createdAt;
    });
    return result;
}

QStringList DecisionCache::fingerprints() const
{
    QMutexLocker locker(&m_mutex);
    QStringList result = m_entries.keys();
    result.sort();
    return result;
}

int DecisionCache::pruneExpired(const QDateTime &now)
{
    QMutexLocker locker(&m_mutex);
    const QDateTime reference = utcValue(now.isValid() ? now : QDateTime::currentDateTimeUtc());
    int removed = 0;
    for (auto it = m_entries.begin(); it != m_entries.end();) {
        if (!it.value().isValidAt(reference)) {
            it = m_entries.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

CacheLoadResult DecisionCache::load(QSettings *settings)
{
    CacheLoadResult result;
    QSettings local;
    QSettings &store = settings ? *settings : local;
    store.beginGroup(storageGroup());

    const QVariant versionValue = store.value(kVersionKey, DataSaverCache::kSchemaVersion);
    int version = DataSaverCache::kSchemaVersion;
    if (!integerVariant(versionValue, &version) || version < 1) {
        result.diagnostic = QStringLiteral("the decision cache has an unreadable schema version");
        store.endGroup();
        return result;
    }
    if (version > DataSaverCache::kSchemaVersion) {
        result.rejectedNewer = true;
        result.diagnostic =
            QStringLiteral("the decision cache uses newer schema version %1").arg(version);
        store.endGroup();
        return result;
    }

    const QString json = store.value(kEntriesKey).toString();
    store.endGroup();
    if (json.trimmed().isEmpty()) return result;

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8(), &parseError);
    if (!document.isArray()) {
        result.diagnostic = QStringLiteral("the decision cache is not a JSON array");
        return result;
    }

    for (const QJsonValue &value : document.array()) {
        if (!value.isObject()) {
            ++result.skipped;
            continue;
        }
        CacheEntry entry;
        QString error;
        if (!cacheEntryFromJson(value.toObject(), &entry, &error)) {
            ++result.skipped;
            if (!result.diagnostic.isEmpty()) result.diagnostic += QStringLiteral("; ");
            result.diagnostic += error;
            continue;
        }
        result.entries.append(entry);
    }
    return result;
}

bool DecisionCache::save(const QList<CacheEntry> &entries, QSettings *settings, QString *error)
{
    QSettings local;
    QSettings &store = settings ? *settings : local;

    store.beginGroup(storageGroup());
    const QVariant storedVersionValue = store.value(kVersionKey);
    int storedVersion = 0;
    const bool versionReadable = integerVariant(storedVersionValue, &storedVersion);
    store.endGroup();
    if (versionReadable && storedVersion > DataSaverCache::kSchemaVersion) {
        return fail(error, QStringLiteral("refusing to overwrite a newer decision cache (schema %1)")
                               .arg(storedVersion));
    }

    QJsonArray array;
    for (const CacheEntry &entry : entries) {
        CacheEntry normalized = entry;
        if (normalized.schemaVersion != DataSaverCache::kSchemaVersion)
            return fail(error, QStringLiteral("a cache entry has an unsupported schema version"));
        if (normalized.fingerprint.isEmpty())
            normalized.fingerprint = fingerprintFor(normalized.key);
        array.append(cacheEntryToJson(normalized));
    }

    store.beginGroup(storageGroup());
    store.setValue(kVersionKey, DataSaverCache::kSchemaVersion);
    store.setValue(kEntriesKey,
                   QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact)));
    store.endGroup();
    store.sync();
    if (store.status() != QSettings::NoError)
        return fail(error, QStringLiteral("the decision cache could not be written"));
    return true;
}

bool DecisionCache::loadInto(QSettings *settings, QString *error)
{
    const CacheLoadResult loaded = load(settings);
    QMutexLocker locker(&m_mutex);
    m_entries.clear();
    if (loaded.rejectedNewer) return fail(error, loaded.diagnostic);
    for (const CacheEntry &entry : loaded.entries) {
        if (m_entries.size() >= m_maxEntries) break;
        m_entries.insert(entry.fingerprint, entry);
    }
    if (!loaded.diagnostic.isEmpty() && error) *error = loaded.diagnostic;
    return true;
}

bool DecisionCache::save(QSettings *settings, QString *error) const
{
    QList<CacheEntry> snapshot;
    {
        QMutexLocker locker(&m_mutex);
        snapshot = m_entries.values();
    }
    return save(snapshot, settings, error);
}
