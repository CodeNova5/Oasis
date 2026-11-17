/**
 * @file    connectionsnapshot.h
 * @brief   Screen 05 — Connections: one display-ready row per application and
 *          destination, assembled from the attribution evidence the capture
 *          layer already produces.
 *
 * The snapshot is deliberately plain: no widget, no policy, no enforcement
 * path. NetworkWidget fills it once per one-second beat, and ConnectionsPage
 * renders it. A row groups every observed socket that shares one application
 * and one destination, so rotating CDN addresses collapse into a single
 * honest entry while the drawer still lists each endpoint.
 *
 * @author  Oasis
 */
#pragma once

#include <QIcon>
#include <QList>
#include <QString>
#include <QStringList>

#include "attribution/dnscorrelator.h"
#include "network/policy.h"

namespace Connections {

/// One observed socket inside a grouped row.
struct Endpoint
{
    QString address;                 // remote address
    quint16 port = 0;                // remote port
    QString protocol;                // "TCP" or "UDP"
    QString domain;                  // name observed for this address, if any
    QStringList domainNames;         // every name currently attached to it
    QStringList evidence;            // human-readable evidence lines
    AttributionSource source = AttributionSource::Unknown;
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
    quint32 packets = 0;
};

/// One table row: an application talking to one destination.
struct Row
{
    QString id;                      // stable identity across beats
    quint32 pid = 0;
    qint64 processStartMs = 0;       // pins the process instance behind the row

    QIcon icon;
    QString appName;                 // executable, e.g. "chrome.exe"
    QString displayName;             // friendly identity, empty when unresolved
    QString path;                    // executable path, empty when unresolved
    QString publisher;               // verified signer, empty when unknown
    QString activity;                // activity classification summary, if known

    QString destination;             // hostname, or the raw address
    bool hasDomain = false;          // true only when a name was observed
    QStringList addresses;           // every remote address in the group
    QStringList domainNames;         // every observed name for the group
    QString ports;                   // "443 / TCP" or "Multiple ports / TCP"
    QString direction;               // "Outbound", "Inbound", "Both"
    QString evidenceKey;             // "dns+tls", "dns", "tls" or "none"
    QString evidenceLabel;           // plain interface wording
    QString confidence;              // Confirmed / Likely / Possible / Unknown
    int confidenceRank = 0;

    QString policy;                  // "None", "Throttle (Active)", "Block (Active)"
    QString policyToken;             // "none", "restricted" or "blocked"

    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
    quint32 packets = 0;
    int endpointCount = 0;
    QList<Endpoint> endpoints;

    quint64 totalBytes() const { return rxBytes + txBytes; }
    quint64 bytesPerSecond() const { return rxBytesPerSecond + txBytesPerSecond; }
    QString label() const
    {
        return displayName.trimmed().isEmpty() ? appName : displayName;
    }
};

/// Filter pills from SCREENS_SPEC.md §Screen 05, without the time-based one.
enum class Filter {
    All = 0,
    Domains,
    IpAddresses,
    Unknown
};

QString filterLabel(Filter filter);
QString filterToken(Filter filter);

/// True when a row belongs in the filter. "Unknown" keeps the mock's meaning:
/// an address with no name, or a name only weakly inferred.
bool matchesFilter(const Row &row, Filter filter);

/// Filters by attribution source key. "all" matches every row.
bool matchesSource(const Row &row, const QString &sourceKey);

/// Case-insensitive search across the destination, every attached name and
/// address, and the application identity behind the row.
bool matchesQuery(const Row &row, const QString &query);

QString sourceKey(AttributionSource source);
QString sourceLabel(AttributionSource source);
QString confidenceLabel(ApplicationIdentity::Confidence confidence);
int confidenceRank(ApplicationIdentity::Confidence confidence);
QString directionFor(quint64 rxBytes, quint64 txBytes);

QString formatRate(quint64 bytesPerSecond);
QString formatBytes(quint64 bytes);

} // namespace Connections
