/**
 * @file    dnscorrelator.h
 * @brief   Connects recently observed DNS answers and visible TLS SNI names to
 *          destination addresses (NG-031/NG-032), with bounded lifetime,
 *          multiple names per address, and explicit attribution sources.
 * @author  Ali Sakkaf
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QMutex>
#include <QString>

#include "dnsobserver.h"
#include "network/policy.h"
#include "tlsobserver.h"

/// Where a destination record came from. Records stay separate per source so a
/// DNS answer and a TLS SNI observation can expire independently; the combined
/// summary reports both when they name the same destination.
enum class AttributionSource
{
    Unknown,
    DnsAnswer,
    TlsSni,
    DnsAndTls
};

QString attributionSourceName(AttributionSource source);

/**
 * One name associated with a destination address.
 *
 * The record keeps the querying process and identity from the DNS response, so
 * a caller can show not just "this address was resolved as example.com" but
 * "the browser resolved it as example.com". Several records can share one
 * address; each has its own first/last-seen times and expiry.
 */
struct DomainAttribution
{
    QString address;
    QString name;
    quint32 pid = 0;
    QString processName;
    QString identityId;
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
    AttributionSource source = AttributionSource::Unknown;
    QDateTime firstSeen;
    QDateTime lastSeen;
    QDateTime expiresAt;
};

/// One resolved view of every name observed for a destination. When DNS and TLS
/// SNI name the same endpoint, `name` is that shared name, `source` is
/// `DnsAndTls`, and `confidence` can be `Confirmed`; a name seen by only one
/// observer remains a strong inference.
struct DestinationNameSummary
{
    QString address;
    QString name;
    QStringList names;
    AttributionSource source = AttributionSource::Unknown;
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
    QDateTime expiresAt;
    QStringList evidence;
};

/// Combine records for one address, preferring a name observed by both DNS and
/// TLS. The input is expected in the correlator's most-recent-first order.
DestinationNameSummary summarizeDestinationNames(
    const QList<DomainAttribution> &records, const QString &address);

/**
 * Thread-safe, bounded address -> domain store.
 *
 * DNS answers expire after the smaller of the DNS TTL and `maximumTtlSeconds`,
 * so a stale mapping cannot live forever; an answer without a usable TTL gets
 * `defaultTtlSeconds`. A visible TLS SNI observation has no TTL of its own and
 * uses `defaultTtlSeconds`. At most eight names are kept per address and the
 * store evicts the least recently seen address when `maxAddresses` is reached.
 */
class DnsCorrelator
{
public:
    explicit DnsCorrelator(int maximumTtlSeconds = 3600,
                           int defaultTtlSeconds = 300,
                           int maxAddresses = 4096);

    /// Record the A/AAAA answers of a DNS response. Queries, empty answers, and
    /// malformed names are ignored. `observedAt` is injectable for tests.
    void observe(const DnsEvent &event,
                 const QDateTime &observedAt = QDateTime::currentDateTimeUtc());

    /// Record a visible TLS SNI observation against its remote address. Only an
    /// available SNI with a non-empty name and address creates a record; the
    /// name is stored alongside, not merged with, any DNS record of the same
    /// name so each source expires independently.
    void observeTls(
        const TlsObservation &observation,
        const QDateTime &observedAt = QDateTime::currentDateTimeUtc());

    /// Names still valid for `address`, most recently seen first. Expired
    /// records are filtered even if pruning has not run yet.
    QList<DomainAttribution> lookup(
        const QString &address,
        const QDateTime &now = QDateTime::currentDateTimeUtc()) const;

    /// NG-036: bound how long a record may live, in seconds. New records are
    /// capped to this window and records last seen outside it are dropped, so
    /// lowering retention immediately shortens what was already stored.
    void setRetentionSeconds(int seconds);
    int retentionSeconds() const;

    /// Drop every name -> address record. Used by "Clear attribution history";
    /// no payload data exists to clear, because none is ever stored.
    void clear();

    /// Records currently held, including any not yet pruned.
    int recordCount() const;

private:
    void recordLocked(const QString &address, const QString &name, quint32 pid,
                      const QString &processName, const QString &identityId,
                      AttributionSource source,
                      ApplicationIdentity::Confidence confidence,
                      const QDateTime &observedAt, int ttlSeconds);
    void pruneLocked(const QDateTime &now);
    void evictAddressLocked();

    int m_maximumTtlSeconds;
    int m_defaultTtlSeconds;
    const int m_maxAddresses;
    mutable int m_retentionSeconds;

    mutable QMutex m_mutex;
    QHash<QString, QList<DomainAttribution>> m_byAddress;
};
