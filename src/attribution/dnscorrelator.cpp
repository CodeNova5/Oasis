/**
 * @file    dnscorrelator.cpp
 * @author  Ali Sakkaf
 */
#include "dnscorrelator.h"
#include "attributionconfidence.h"

#include <algorithm>

namespace {

// A single address rarely needs more than a handful of names; keeping a fixed
// cap prevents a hostile or misconfigured resolver from growing one list
// without bound.
const int kMaxNamesPerAddress = 8;

QString normalizedAddress(const QString &address)
{
    return address.trimmed().toLower();
}

} // namespace

QString attributionSourceName(AttributionSource source)
{
    switch (source) {
    case AttributionSource::DnsAnswer: return QStringLiteral("DNS answer");
    case AttributionSource::TlsSni:    return QStringLiteral("TLS SNI");
    case AttributionSource::DnsAndTls: return QStringLiteral("DNS answer + TLS SNI");
    case AttributionSource::Unknown:   break;
    }
    return QStringLiteral("Unknown");
}

DnsCorrelator::DnsCorrelator(int maximumTtlSeconds, int defaultTtlSeconds,
                             int maxAddresses)
    : m_maximumTtlSeconds(qMax(1, maximumTtlSeconds)),
      m_defaultTtlSeconds(qBound(1, defaultTtlSeconds, qMax(1, maximumTtlSeconds))),
      m_maxAddresses(qMax(1, maxAddresses)),
      m_retentionSeconds(qMax(1, maximumTtlSeconds))
{
}

void DnsCorrelator::observe(const DnsEvent &event, const QDateTime &observedAt)
{
    // Only a response with addresses says anything about a destination. A bare
    // query (or an empty response) must not create a mapping.
    if (!event.response || event.addresses.isEmpty() || event.name.isEmpty()) {
        return;
    }

    QMutexLocker locker(&m_mutex);
    int ttl = event.ttlSeconds > 0 ? static_cast<int>(event.ttlSeconds)
                                   : m_defaultTtlSeconds;
    // NG-036: retention is a hard ceiling on top of the DNS TTL.
    ttl = qBound(1, ttl, qMin(m_maximumTtlSeconds, m_retentionSeconds));
    pruneLocked(observedAt);

    for (const QString &rawAddress : event.addresses) {
        recordLocked(normalizedAddress(rawAddress), event.name, event.pid,
                     event.processName, event.identityId,
                     AttributionSource::DnsAnswer, event.confidence,
                     observedAt, ttl);
    }
}

void DnsCorrelator::observeTls(const TlsObservation &observation,
                               const QDateTime &observedAt)
{
    if (!observation.isAvailable()) return;

    const QString address = normalizedAddress(observation.remoteAddress);
    const QString name = observation.serverName.trimmed().toLower();
    if (address.isEmpty() || name.isEmpty()) return;

    QMutexLocker locker(&m_mutex);
    pruneLocked(observedAt);
    recordLocked(address, name, observation.pid, observation.processName,
                 observation.identityId, AttributionSource::TlsSni,
                 ApplicationIdentity::Confidence::StrongInference,
                 observedAt, qMin(m_defaultTtlSeconds, m_retentionSeconds));
}

void DnsCorrelator::recordLocked(const QString &address, const QString &name,
                                 quint32 pid, const QString &processName,
                                 const QString &identityId,
                                 AttributionSource source,
                                 ApplicationIdentity::Confidence confidence,
                                 const QDateTime &observedAt, int ttlSeconds)
{
    if (address.isEmpty() || name.isEmpty()) return;

    if (!m_byAddress.contains(address) &&
        m_byAddress.size() >= m_maxAddresses) {
        evictAddressLocked();
    }

    QList<DomainAttribution> &records = m_byAddress[address];
    DomainAttribution *existing = nullptr;
    for (DomainAttribution &record : records) {
        if (record.name == name && record.source == source) {
            existing = &record;
            break;
        }
    }

    if (existing) {
        // Refresh lifetime and evidence; firstSeen stays put so the record
        // still shows when the name was first associated with the address.
        existing->lastSeen = observedAt;
        existing->expiresAt = observedAt.addSecs(ttlSeconds);
        existing->confidence = confidence;
        if (pid != 0) {
            existing->pid = pid;
            existing->processName = processName;
        }
        if (!identityId.isEmpty()) {
            existing->identityId = identityId;
        }
        return;
    }

    if (records.size() >= kMaxNamesPerAddress) {
        int oldest = 0;
        for (int i = 1; i < records.size(); ++i) {
            if (records.at(i).lastSeen < records.at(oldest).lastSeen) {
                oldest = i;
            }
        }
        records.removeAt(oldest);
    }

    DomainAttribution record;
    record.address = address;
    record.name = name;
    record.pid = pid;
    record.processName = processName;
    record.identityId = identityId;
    record.confidence = confidence;
    record.source = source;
    record.firstSeen = observedAt;
    record.lastSeen = observedAt;
    record.expiresAt = observedAt.addSecs(ttlSeconds);
    records.append(record);
}

DestinationNameSummary summarizeDestinationNames(
    const QList<DomainAttribution> &records, const QString &address)
{
    DestinationNameSummary result;
    result.address = address;

    for (const DomainAttribution &record : records) {
        if (!record.name.isEmpty() && !result.names.contains(record.name)) {
            result.names.append(record.name);
        }
    }
    if (result.names.isEmpty()) return result;

    auto isDns = [](AttributionSource source) {
        return source == AttributionSource::DnsAnswer ||
               source == AttributionSource::DnsAndTls;
    };
    auto isTls = [](AttributionSource source) {
        return source == AttributionSource::TlsSni ||
               source == AttributionSource::DnsAndTls;
    };
    auto hasSource = [&records, &isDns, &isTls](const QString &name,
                                                bool dns, bool tls) {
        bool foundDns = false;
        bool foundTls = false;
        for (const DomainAttribution &record : records) {
            if (record.name != name) continue;
            foundDns = foundDns || isDns(record.source);
            foundTls = foundTls || isTls(record.source);
        }
        return (!dns || foundDns) && (!tls || foundTls);
    };

    // Prefer a name both observers agree on; otherwise the most recent name in
    // the correlator's ordering is the best available inference.
    for (const QString &name : result.names) {
        if (hasSource(name, true, true)) {
            result.name = name;
            break;
        }
    }
    if (result.name.isEmpty()) result.name = result.names.first();

    bool dns = false;
    bool tls = false;
    for (const DomainAttribution &record : records) {
        if (record.name != result.name) continue;
        dns = dns || isDns(record.source);
        tls = tls || isTls(record.source);
        if (record.expiresAt.isValid() &&
            (!result.expiresAt.isValid() || record.expiresAt > result.expiresAt)) {
            result.expiresAt = record.expiresAt;
        }
    }

    result.source = dns && tls ? AttributionSource::DnsAndTls
                              : (dns ? AttributionSource::DnsAnswer
                                     : AttributionSource::TlsSni);

    AttributionConfidenceModel::DomainEvidence evidence;
    evidence.name = result.name;
    evidence.address = address;
    evidence.dnsAnswer = dns;
    evidence.tlsSni = tls;
    const AttributionConfidenceModel::Assessment assessment =
        AttributionConfidenceModel::forDomain(evidence);
    result.confidence = assessment.confidence;
    result.evidence = assessment.descriptions();
    return result;
}

QList<DomainAttribution> DnsCorrelator::lookup(const QString &address,
                                               const QDateTime &now) const
{
    QList<DomainAttribution> result;
    const QString key = normalizedAddress(address);
    if (key.isEmpty()) return result;

    QMutexLocker locker(&m_mutex);
    const auto it = m_byAddress.constFind(key);
    if (it == m_byAddress.constEnd()) return result;

    // Retention is checked alongside the TTL so lowering it takes effect
    // immediately instead of only for records created afterwards.
    for (const DomainAttribution &record : it.value()) {
        if (record.expiresAt > now &&
            record.lastSeen.addSecs(m_retentionSeconds) > now) {
            result.append(record);
        }
    }

    std::sort(result.begin(), result.end(),
              [](const DomainAttribution &left, const DomainAttribution &right) {
                  if (left.lastSeen != right.lastSeen) {
                      return left.lastSeen > right.lastSeen;
                  }
                  return left.name < right.name;
              });
    return result;
}

void DnsCorrelator::pruneLocked(const QDateTime &now)
{
    for (auto it = m_byAddress.begin(); it != m_byAddress.end();) {
        QList<DomainAttribution> &records = it.value();
        for (int i = records.size() - 1; i >= 0; --i) {
            if (records.at(i).expiresAt <= now ||
                records.at(i).lastSeen.addSecs(m_retentionSeconds) <= now) {
                records.removeAt(i);
            }
        }
        if (records.isEmpty()) {
            it = m_byAddress.erase(it);
        } else {
            ++it;
        }
    }
}

void DnsCorrelator::setRetentionSeconds(int seconds)
{
    const int retention = qMax(1, seconds);
    QMutexLocker locker(&m_mutex);
    m_retentionSeconds = retention;
    if (m_defaultTtlSeconds > retention) m_defaultTtlSeconds = retention;
    pruneLocked(QDateTime::currentDateTimeUtc());
}

int DnsCorrelator::retentionSeconds() const
{
    QMutexLocker locker(&m_mutex);
    return m_retentionSeconds;
}

void DnsCorrelator::clear()
{
    QMutexLocker locker(&m_mutex);
    m_byAddress.clear();
}

int DnsCorrelator::recordCount() const
{
    QMutexLocker locker(&m_mutex);
    int count = 0;
    for (const QList<DomainAttribution> &records : m_byAddress)
        count += records.size();
    return count;
}

void DnsCorrelator::evictAddressLocked()
{
    QString victim;
    QDateTime victimSeen;
    for (auto it = m_byAddress.constBegin(); it != m_byAddress.constEnd(); ++it) {
        QDateTime newest;
        for (const DomainAttribution &record : it.value()) {
            if (!newest.isValid() || record.lastSeen > newest) {
                newest = record.lastSeen;
            }
        }
        if (victim.isEmpty() || newest < victimSeen ||
            (newest == victimSeen && it.key() > victim)) {
            victim = it.key();
            victimSeen = newest;
        }
    }
    if (!victim.isEmpty()) m_byAddress.remove(victim);
}
