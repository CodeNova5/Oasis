/**
 * @file    dnsobserver.h
 * @brief   Passive DNS metadata parsing (NG-030): names, types, and answers
 *          from visible UDP DNS messages, without retaining payloads.
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QList>
#include <QMetaType>
#include <QString>
#include <QStringList>
#include <cstdint>

#include "network/policy.h"

/**
 * One DNS question (and, for a response, its answers) seen on the wire.
 *
 * Only metadata survives parsing; the packet payload is never copied into the
 * event, so nothing here can reconstruct the message. Names are lower-cased
 * and stored without the trailing root dot, which makes comparison with
 * connection destinations in NG-031 straightforward.
 */
struct DnsEvent
{
    QDateTime timestamp;             // when the datagram was parsed (UTC)
    bool response = false;           // QR bit
    bool truncated = false;          // TC bit: the answer set is incomplete
    QString transactionId;          // hex DNS id, retained for joining a reply
    QString name;                   // first question name, lower-case, no dot
    quint16 recordType = 0;         // QTYPE of the question (A, AAAA, ...)
    QString recordTypeName;         // printable QTYPE
    QStringList addresses;          // A/AAAA answers in this message
    QStringList aliases;            // CNAME targets in this message
    quint32 ttlSeconds = 0;         // minimum A/AAAA TTL (0 = none seen)

    // Filled by the capture loop when the owning socket can be resolved.
    quint32 pid = 0;
    QString processName;
    QString identityId;

    // Confidence in the name -> address association, not in the process
    // attribution: a response carrying addresses is a strong inference, a
    // response without one is weak, and a bare request is unknown (NG-035
    // refines this once endpoint evidence is joined).
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
};
Q_DECLARE_METATYPE(DnsEvent)

namespace DnsObserver {

/// Parse a raw IPv4/IPv6 datagram captured by the raw socket. Only UDP port 53
/// is considered; DNS over TCP/DoH/DoT is intentionally unavailable. Returns an
/// empty list for anything malformed, unsupported, or not DNS.
QList<DnsEvent> parseDatagram(const uint8_t *data, quint32 length);

/// Parse one DNS message (no IP/UDP header). Malformed input never throws and
/// returns an empty list.
QList<DnsEvent> parseMessage(const uint8_t *payload, int length);

/// Printable record type used in events and UI text.
QString recordTypeName(quint16 type);

} // namespace DnsObserver
