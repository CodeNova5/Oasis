/**
 * @file    quicobserver.h
 * @brief   Safe QUIC metadata (NG-033): clear long-header facts only. The
 *          Initial payload is encrypted, so no hostname is ever claimed.
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QMetaType>
#include <QString>

#include <cstdint>

/**
 * Why a datagram did or did not yield QUIC hostname metadata.
 *
 * A QUIC Initial carries its TLS ClientHello inside an encrypted payload.
 * `PRD.md` excludes decrypting QUIC traffic, so a valid Initial is reported as
 * `InitialEncrypted` with no hostname instead of exposing a guessed name.
 */
enum class QuicMetadataStatus
{
    NotQuic,             // no supported QUIC long header was found
    UnsupportedVersion,  // a QUIC version this observer does not understand
    VersionNegotiation,  // version 0: the endpoints are choosing a version
    NotInitial,          // a supported version, but not an Initial packet
    InitialEncrypted,    // a valid Initial; its hostname is encrypted
    Malformed            // inconsistent long-header lengths
};

QString quicMetadataStatusName(QuicMetadataStatus status);

/**
 * One observed QUIC long-header packet.
 *
 * Only the version and packet type survive parsing. Connection IDs, tokens,
 * packet numbers, and ciphertext are deliberately not stored, and no field can
 * carry a hostname: the ClientHello is encrypted and is never decrypted here.
 * The capture loop fills the process fields.
 */
struct QuicObservation
{
    QDateTime timestamp;
    QuicMetadataStatus status = QuicMetadataStatus::NotQuic;
    quint32 version = 0;
    QString versionName;
    QString packetType; // "initial", "0-RTT", "handshake", or "retry"

    quint32 pid = 0;
    QString processName;
    QString identityId;

    /// QUIC hostname attribution is always unknown in this release.
    bool hasHostname() const { return false; }
};
Q_DECLARE_METATYPE(QuicObservation)

namespace QuicObserver {

/// Parse a raw IPv4/IPv6 UDP datagram. Returns `NotQuic` for anything that is
/// not a QUIC long-header packet, so ordinary UDP is ignored cheaply.
QuicObservation parseDatagram(const uint8_t *data, quint32 length);

/// Parse one UDP payload (no IP/UDP header). Never throws; malformed input
/// yields `Malformed` rather than a packet type or version guess.
QuicObservation parsePacket(const uint8_t *payload, int length);

/// Printable version, e.g. "QUIC v1" or "version 0xff00001d".
QString versionName(quint32 version);

} // namespace QuicObserver
