/**
 * @file    dnscorrelator.h
 * @brief   Connects recently observed DNS answers to destination addresses
 *          (NG-031), with bounded lifetime, multiple names per address, and
 *          an explicit attribution source.
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

/// Where a destination record came from. NG-031 only produces DNS answers;
/// other observers (TLS SNI, endpoint catalogs) can add sources later without
/// making a direct-IP connection look resolved.
enum class AttributionSource
{
    Unknown,
    DnsAnswer
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

/**
 * Thread-safe, bounded address -> domain store.
 *
 * Answers expire after the smaller of the DNS TTL and `maximumTtlSeconds`, so a
 * stale mapping cannot live forever; an answer without a usable TTL gets
 * `defaultTtlSeconds`. At most eight names are kept per address and the store
 * evicts the least recently seen address when `maxAddresses` is reached.
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

    /// Names still valid for `address`, most recently seen first. Expired
    /// records are filtered even if pruning has not run yet.
    QList<DomainAttribution> lookup(
        const QString &address,
        const QDateTime &now = QDateTime::currentDateTimeUtc()) const;

private:
    void pruneLocked(const QDateTime &now);
    void evictAddressLocked();

    const int m_maximumTtlSeconds;
    const int m_defaultTtlSeconds;
    const int m_maxAddresses;

    mutable QMutex m_mutex;
    QHash<QString, QList<DomainAttribution>> m_byAddress;
};
