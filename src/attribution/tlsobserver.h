/**
 * @file    tlsobserver.h
 * @brief   Passive TLS ClientHello metadata (NG-032): visible SNI only, never
 *          decrypted payloads.
 * @author  Ali Sakkaf
 */
#pragma once

#include <QDateTime>
#include <QMetaType>
#include <QString>

#include <cstdint>

/**
 * Why a TLS handshake did or did not yield a server name.
 *
 * `Fragmented` is deliberate: if a ClientHello is split across TCP segments or
 * records, this observer does not reassemble it and does not guess. The same
 * applies to encrypted handshakes and ECH, which hides the real name.
 */
enum class TlsSniStatus
{
    NotTls,          // no supported TLS record was found
    NotClientHello,  // a TLS handshake, but not a ClientHello
    NoSni,           // a ClientHello without a server_name extension
    Available,       // SNI was extracted
    Fragmented,      // the handshake extends past the visible data
    Encrypted,       // TLS application data: the handshake is encrypted
    EchHidden,       // encrypted ClientHello (ECH) hides the real name
    Malformed        // inconsistent lengths or an invalid SNI list
};

QString tlsSniStatusName(TlsSniStatus status);

/**
 * One observed ClientHello.
 *
 * `serverName` is lower-case and has no trailing root dot. It is empty unless
 * `status` is `Available`, so callers cannot accidentally treat an unavailable
 * handshake as a resolved domain. The capture loop fills the process fields.
 */
struct TlsObservation
{
    QDateTime timestamp;
    TlsSniStatus status = TlsSniStatus::NotTls;
    QString serverName;

    quint32 pid = 0;
    QString processName;
    QString identityId;

    bool isAvailable() const { return status == TlsSniStatus::Available; }
};
Q_DECLARE_METATYPE(TlsObservation)

namespace TlsObserver {

/// Parse a raw IPv4/IPv6 TCP segment. Returns `NotTls` for anything that is not
/// a supported TLS record, so non-TLS traffic is ignored cheaply.
TlsObservation parseDatagram(const uint8_t *data, quint32 length);

/// Parse one TLS record (no IP/TCP header). Never throws; malformed input
/// yields `Malformed` rather than a partial name.
TlsObservation parseRecord(const uint8_t *payload, int length);

} // namespace TlsObserver
