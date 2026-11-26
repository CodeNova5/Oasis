/**
 * @file    datasavercache.h
 * @brief   Evidence fingerprint cache for Data Saver decisions (DS-007).
 *
 * The cache reuses a decision only while the evidence that justified it is
 * still the same evidence. The key is the fingerprint defined in
 * docs/DATA_SAVER_CONTRACT.md §8: executable name + version, domain (or the
 * remote-address fallback), process role, foreground state, receive bucket,
 * duration bucket, and the Data Saver source. Every one of those inputs is
 * metadata; no payload byte, executable path, local address, or credential is
 * stored.
 *
 * A bucket, executable-version, source, or catalog-version change invalidates
 * the entry rather than matching it. Entries also carry their own schema
 * version and expire on a source/confidence TTL. A malformed, newer-version, or
 * expired entry is discarded without affecting the decision path, and a lookup
 * failure is simply a miss: the caller falls back to local resolution, so the
 * cache can never create a hard block. Block decisions are never accepted from
 * the cache at all.
 *
 * Only automatic, cacheable origins are stored. Today that is the DS-006 local
 * profile decision (30 days, or until the catalog version changes); the AI TTLs
 * in the contract table arrive with DS-012/DS-013. Pinned and session decisions
 * are user state, not evidence, and are never cached: they are resolved
 * directly from `PinnedRuleStore`/`SessionOverrideStore`.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QMutex>
#include <QSettings>
#include <QString>
#include <QStringList>

#include "datasaverdecision.h"
#include "flowobservation.h"

namespace DataSaverCache {
constexpr int kSchemaVersion = 1;
constexpr int kDefaultMaxEntries = 512;
constexpr qint64 kProfileTtlSeconds = 30LL * 24 * 60 * 60;
// Reserved for the `ai` origin that DS-012/DS-013 add to `DecisionOrigin`.
constexpr qint64 kAiHighConfidenceTtlSeconds = 7LL * 24 * 60 * 60;
constexpr qint64 kAiDomainOnlyTtlSeconds = 24LL * 60 * 60;
constexpr qint64 kAiLowConfidenceTtlSeconds = 30LL * 60;
} // namespace DataSaverCache

/// What turned Data Saver on for this decision (§8 key input 7). It is not the
/// policy origin: a decision made while on a metered hotspot is cached under
/// `metered_hotspot` and not reused under `battery_saver`.
enum class CacheSource {
    MeteredHotspot,
    ManualToggle,
    BatterySaver
};

QString cacheSourceToken(CacheSource source);
bool cacheSourceFromToken(const QString &text, CacheSource *source);

/// The seven canonical key inputs, in contract order. Keeping them separate
/// from the hash makes invalidations and diagnostics explainable.
struct CacheKey
{
    QString executableKey;    // lower-case base name plus @version when known
    QString domainKey;        // normalized domain, or the address fallback token
    QString processRole;      // main / child / service / unknown
    QString foregroundState;  // foreground_active / foreground_idle / background / unknown
    QString receiveBucket;    // below_10MB / 10_25MB / 25_50MB / 50_100MB / 100MB_plus
    QString durationBucket;   // burst_<10s / sustained_10_60s / long_>60s
    QString source;           // metered_hotspot / manual_toggle / battery_saver

    /// Newline-joined canonical field list, in contract order.
    QString canonical() const;
    bool operator==(const CacheKey &other) const;
};

/// Everything the key needs that is not already on the observation. `now` is a
/// parameter of the cache calls, not part of the key.
struct CacheContext
{
    CacheSource source = CacheSource::ManualToggle;
    /// The local signature catalog version; a change invalidates every entry.
    /// Matches `EndpointCatalog::catalogVersion()`.
    QString catalogVersion;
    /// Optional caller-supplied ASN/address token for flows without a domain.
    /// Empty derives the remote address from the observation.
    QString addressFallback;
};

/// Bucket helpers, exposed because they are part of the contract's key.
QString receiveBucket(quint64 rxBytes);
QString durationBucket(qint64 durationMs);

/// The `fp_` + SHA-256-over-`key.canonical()` fingerprint (§3.2, §8).
QString fingerprintFor(const CacheKey &key);

/// Builds the key from the observation. A flow with neither a domain nor a
/// usable remote address is keyed `unknown_remote`; it is still bounded by the
/// same executable/bucket/source inputs.
CacheKey buildCacheKey(const FlowObservation &observation, const CacheContext &context);

/// TTL in seconds for a cacheable decision. Returns 0 for origins that are
/// never cached (pinned, session, fallback, cache). `corroborated` is false
/// when only a domain is known, with no process/SNI corroboration.
qint64 ttlSeconds(DecisionOrigin origin, double confidence, bool corroborated);

/// One stored decision. It carries the source observation id, the audit link,
/// and the full decision so a hit can be audited and explained.
struct CacheEntry
{
    int schemaVersion = DataSaverCache::kSchemaVersion;
    QString fingerprint;
    CacheKey key;
    QString observationId;
    QString decisionId;
    int decisionSchemaVersion = PolicyDecision::kSchemaVersion;
    PolicyDecision decision;
    QDateTime createdAt;
    QDateTime expiresAt;
    QString auditId;              // may be empty until DS-010 links it
    QString catalogVersion;

    bool isValidAt(const QDateTime &now) const
    {
        return expiresAt.isValid() && createdAt.isValid() && now < expiresAt;
    }
};

QJsonObject cacheEntryToJson(const CacheEntry &entry);
bool cacheEntryFromJson(const QJsonObject &object, CacheEntry *entry,
                        QString *error = nullptr);

struct CacheLoadResult
{
    QList<CacheEntry> entries;
    QString diagnostic;          // empty on a clean read
    bool rejectedNewer = false;  // the whole store was written by a newer build
    int skipped = 0;
};

/// Bounded, in-memory evidence cache with optional versioned persistence.
/// All methods are cheap and never block on the network, the UI, or the
/// capture thread; a lookup is a hash probe plus a fingerprint hash.
class DecisionCache
{
public:
    explicit DecisionCache(int maxEntries = DataSaverCache::kDefaultMaxEntries);

    static QString storageGroup() { return QStringLiteral("Oasis/DataSaver/DecisionCache"); }

    /// Stores `decision` for the evidence in `observation`. Only a validated
    /// automatic profile decision for this exact executable/domain is accepted;
    /// pinned, session, fallback, cache, block, and mismatched decisions are
    /// refused with `error`. Replaces an existing entry for the same key.
    bool insert(const FlowObservation &observation, const CacheContext &context,
                const PolicyDecision &decision, const QString &auditId = QString(),
                const QDateTime &now = QDateTime(), QString *error = nullptr);

    /// Returns the cached decision as a validated tier-4 cache candidate.
    /// Expired, invalidated, malformed, mismatched, and block entries are
    /// removed and treated as a miss. `diagnostic` explains a removal.
    bool lookup(const FlowObservation &observation, const CacheContext &context,
                PolicyDecision *decision, const QDateTime &now = QDateTime(),
                QString *diagnostic = nullptr);

    bool contains(const QString &fingerprint) const;
    bool remove(const QString &fingerprint);
    void clear();
    int count() const;
    int capacity() const { return m_maxEntries; }
    QList<CacheEntry> entries() const;
    QStringList fingerprints() const;

    /// Drops every expired entry. Returns the number removed.
    int pruneExpired(const QDateTime &now = QDateTime());

    /// Reads the persisted store. A newer root schema is rejected whole; a
    /// malformed entry is skipped. Never throws and never fails the caller.
    static CacheLoadResult load(QSettings *settings = nullptr);
    static bool save(const QList<CacheEntry> &entries, QSettings *settings = nullptr,
                     QString *error = nullptr);

    /// Replaces the in-memory entries with the persisted store. Returns false
    /// and leaves the cache empty when the store cannot be read.
    bool loadInto(QSettings *settings = nullptr, QString *error = nullptr);

    /// Persists the current entries. Refuses to overwrite a newer store.
    bool save(QSettings *settings = nullptr, QString *error = nullptr) const;

private:
    void evictIfNeededLocked();

    mutable QMutex m_mutex;
    QHash<QString, CacheEntry> m_entries;
    int m_maxEntries = DataSaverCache::kDefaultMaxEntries;
};
