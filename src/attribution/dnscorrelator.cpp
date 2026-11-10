/**
 * @file    dnscorrelator.cpp
 * @author  Ali Sakkaf
 */
#include "dnscorrelator.h"

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
    case AttributionSource::Unknown:   break;
    }
    return QStringLiteral("Unknown");
}

DnsCorrelator::DnsCorrelator(int maximumTtlSeconds, int defaultTtlSeconds,
                             int maxAddresses)
    : m_maximumTtlSeconds(qMax(1, maximumTtlSeconds)),
      m_defaultTtlSeconds(qBound(1, defaultTtlSeconds, qMax(1, maximumTtlSeconds))),
      m_maxAddresses(qMax(1, maxAddresses))
{
}

void DnsCorrelator::observe(const DnsEvent &event, const QDateTime &observedAt)
{
    // Only a response with addresses says anything about a destination. A bare
    // query (or an empty response) must not create a mapping.
    if (!event.response || event.addresses.isEmpty() || event.name.isEmpty()) {
        return;
    }

    int ttl = event.ttlSeconds > 0 ? static_cast<int>(event.ttlSeconds)
                                   : m_defaultTtlSeconds;
    ttl = qBound(1, ttl, m_maximumTtlSeconds);

    QMutexLocker locker(&m_mutex);
    pruneLocked(observedAt);

    for (const QString &rawAddress : event.addresses) {
        const QString address = normalizedAddress(rawAddress);
        if (address.isEmpty()) continue;

        if (!m_byAddress.contains(address) &&
            m_byAddress.size() >= m_maxAddresses) {
            evictAddressLocked();
        }

        QList<DomainAttribution> &records = m_byAddress[address];
        DomainAttribution *existing = nullptr;
        for (DomainAttribution &record : records) {
            if (record.name == event.name) {
                existing = &record;
                break;
            }
        }

        if (existing) {
            // Refresh lifetime and evidence; firstSeen stays put so the record
            // still shows when the name was first associated with the address.
            existing->lastSeen = observedAt;
            existing->expiresAt = observedAt.addSecs(ttl);
            existing->confidence = event.confidence;
            existing->source = AttributionSource::DnsAnswer;
            if (event.pid != 0) {
                existing->pid = event.pid;
                existing->processName = event.processName;
            }
            if (!event.identityId.isEmpty()) {
                existing->identityId = event.identityId;
            }
            continue;
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
        record.name = event.name;
        record.pid = event.pid;
        record.processName = event.processName;
        record.identityId = event.identityId;
        record.confidence = event.confidence;
        record.source = AttributionSource::DnsAnswer;
        record.firstSeen = observedAt;
        record.lastSeen = observedAt;
        record.expiresAt = observedAt.addSecs(ttl);
        records.append(record);
    }
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

    for (const DomainAttribution &record : it.value()) {
        if (record.expiresAt > now) result.append(record);
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
            if (records.at(i).expiresAt <= now) records.removeAt(i);
        }
        if (records.isEmpty()) {
            it = m_byAddress.erase(it);
        } else {
            ++it;
        }
    }
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
