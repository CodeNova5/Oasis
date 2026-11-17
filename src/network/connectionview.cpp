/**
 * @file    connectionview.cpp
 * @brief   Widget-free presentation rules for the Connections screen.
 * @author  Oasis
 */
#include "network/connectionsnapshot.h"

#include "attribution/attributionconfidence.h"

namespace Connections {

QString filterLabel(Filter filter)
{
    switch (filter) {
    case Filter::Domains:     return QStringLiteral("Domains");
    case Filter::IpAddresses: return QStringLiteral("IP addresses");
    case Filter::Unknown:     return QStringLiteral("Unknown");
    case Filter::Outbound:    return QStringLiteral("Outbound");
    case Filter::Inbound:     return QStringLiteral("Inbound");
    case Filter::Blocked:     return QStringLiteral("Blocked");
    case Filter::All:         break;
    }
    return QStringLiteral("All");
}

QString filterToken(Filter filter)
{
    switch (filter) {
    case Filter::Domains:     return QStringLiteral("domains");
    case Filter::IpAddresses: return QStringLiteral("ip");
    case Filter::Unknown:     return QStringLiteral("unknown");
    case Filter::Outbound:    return QStringLiteral("outbound");
    case Filter::Inbound:     return QStringLiteral("inbound");
    case Filter::Blocked:     return QStringLiteral("blocked");
    case Filter::All:         break;
    }
    return QStringLiteral("all");
}

bool matchesFilter(const Row &row, Filter filter)
{
    switch (filter) {
    case Filter::All:
        return true;
    case Filter::Domains:
        return row.hasDomain;
    case Filter::IpAddresses:
        return !row.hasDomain;
    case Filter::Unknown:
        // A name probed only by a weak inference is still not a fact.
        return !row.hasDomain
               || row.confidenceRank <= confidenceRank(
                      ApplicationIdentity::Confidence::WeakInference);
    case Filter::Outbound:
        return row.direction == QLatin1String("Outbound");
    case Filter::Inbound:
        return row.direction == QLatin1String("Inbound");
    case Filter::Blocked:
        return row.policyToken == QLatin1String("blocked");
    }
    return true;
}

bool matchesSource(const Row &row, const QString &sourceKey)
{
    return sourceKey == QLatin1String("all") || row.evidenceKey == sourceKey;
}

bool matchesQuery(const Row &row, const QString &query)
{
    const QString needle = query.trimmed().toLower();
    if (needle.isEmpty())
        return true;

    if (row.destination.toLower().contains(needle))
        return true;
    if (row.appName.toLower().contains(needle)
        || row.displayName.toLower().contains(needle)
        || row.publisher.toLower().contains(needle)
        || row.path.toLower().contains(needle)) {
        return true;
    }
    for (const QString &name : row.domainNames) {
        if (name.toLower().contains(needle))
            return true;
    }
    for (const QString &address : row.addresses) {
        if (address.toLower().contains(needle))
            return true;
    }
    if (row.ports.toLower().contains(needle))
        return true;
    for (const Endpoint &endpoint : row.endpoints) {
        if (QString::number(endpoint.port).contains(needle))
            return true;
    }
    return false;
}

QString sourceKey(AttributionSource source)
{
    switch (source) {
    case AttributionSource::DnsAnswer: return QStringLiteral("dns");
    case AttributionSource::TlsSni:    return QStringLiteral("tls");
    case AttributionSource::DnsAndTls: return QStringLiteral("dns+tls");
    case AttributionSource::Unknown:   break;
    }
    return QStringLiteral("none");
}

QString sourceLabel(AttributionSource source)
{
    switch (source) {
    case AttributionSource::DnsAnswer: return QStringLiteral("DNS answer");
    case AttributionSource::TlsSni:    return QStringLiteral("TLS SNI");
    case AttributionSource::DnsAndTls: return QStringLiteral("DNS + TLS");
    case AttributionSource::Unknown:   break;
    }
    return QStringLiteral("No evidence");
}

QString confidenceLabel(ApplicationIdentity::Confidence confidence)
{
    return AttributionConfidenceModel::displayName(confidence);
}

int confidenceRank(ApplicationIdentity::Confidence confidence)
{
    switch (confidence) {
    case ApplicationIdentity::Confidence::Confirmed:       return 3;
    case ApplicationIdentity::Confidence::StrongInference: return 2;
    case ApplicationIdentity::Confidence::WeakInference:   return 1;
    case ApplicationIdentity::Confidence::Unknown:         break;
    }
    return 0;
}

QString directionFor(quint64 rxBytes, quint64 txBytes)
{
    if (rxBytes > 0 && txBytes > 0)
        return QStringLiteral("Both");
    if (rxBytes > 0)
        return QStringLiteral("Inbound");
    if (txBytes > 0)
        return QStringLiteral("Outbound");
    return QStringLiteral("—");
}

QString formatRate(quint64 bytesPerSecond)
{
    if (bytesPerSecond == 0)          return QStringLiteral("0 B/s");
    if (bytesPerSecond < 1024)        return QStringLiteral("%1 B/s").arg(bytesPerSecond);
    if (bytesPerSecond < 1024ULL * 1024ULL)
        return QStringLiteral("%1 KB/s").arg(bytesPerSecond / 1024.0, 0, 'f', 1);
    if (bytesPerSecond < 1024ULL * 1024ULL * 1024ULL)
        return QStringLiteral("%1 MB/s").arg(bytesPerSecond / (1024.0 * 1024.0), 0, 'f', 2);
    return QStringLiteral("%1 GB/s").arg(bytesPerSecond / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
}

QString formatBytes(quint64 bytes)
{
    if (bytes < 1024)        return QStringLiteral("%1 B").arg(bytes);
    if (bytes < 1024ULL * 1024ULL)
        return QStringLiteral("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    if (bytes < 1024ULL * 1024ULL * 1024ULL)
        return QStringLiteral("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 2);
    return QStringLiteral("%1 GB").arg(bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
}

} // namespace Connections
