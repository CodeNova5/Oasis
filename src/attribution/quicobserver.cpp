/**
 * @file    quicobserver.cpp
 * @author  Oasis
 */
#include "quicobserver.h"

#include <climits>

namespace {

const quint32 QuicVersion1 = 0x00000001;
const quint32 QuicVersion2 = 0x6B3343CF;

// QUIC variable-length integers: the top two bits select a 1, 2, 4, or 8-byte
// encoding. Every read is bounds-checked and leaves the position untouched on
// failure.
bool readVarint(const uint8_t *data, int length, int &pos, quint64 &value)
{
    if (pos < 0 || pos >= length) return false;
    const quint8 first = data[pos];
    const int size = 1 << (first >> 6);
    if (pos + size > length) return false;

    quint64 parsed = first & 0x3F;
    for (int i = 1; i < size; ++i) {
        parsed = (parsed << 8) | data[pos + i];
    }
    pos += size;
    value = parsed;
    return true;
}

bool supportedVersion(quint32 version)
{
    return version == QuicVersion1 || version == QuicVersion2;
}

bool isInitialPacket(quint32 version, quint8 firstByte)
{
    const quint8 typeBits = static_cast<quint8>((firstByte >> 4) & 0x03);
    // Long-header packet types are version-specific: v1 calls type 0 Initial,
    // while v2 renumbers the same bit pattern as Retry and calls type 1 Initial.
    return version == QuicVersion1 ? typeBits == 0 : typeBits == 1;
}

QString packetTypeName(quint32 version, quint8 firstByte)
{
    const quint8 typeBits = static_cast<quint8>((firstByte >> 4) & 0x03);
    if (version == QuicVersion1) {
        switch (typeBits) {
        case 0: return QStringLiteral("initial");
        case 1: return QStringLiteral("0-RTT");
        case 2: return QStringLiteral("handshake");
        default: return QStringLiteral("retry");
        }
    }
    switch (typeBits) {
    case 0: return QStringLiteral("retry");
    case 1: return QStringLiteral("initial");
    case 2: return QStringLiteral("0-RTT");
    default: return QStringLiteral("handshake");
    }
}

QuicObservation malformed(QuicObservation observation)
{
    observation.status = QuicMetadataStatus::Malformed;
    observation.packetType.clear();
    return observation;
}

} // namespace

QString QuicObserver::versionName(quint32 version)
{
    switch (version) {
    case 0:              return QStringLiteral("version negotiation");
    case QuicVersion1:   return QStringLiteral("QUIC v1");
    case QuicVersion2:   return QStringLiteral("QUIC v2");
    default:             return QStringLiteral("version 0x%1")
                                    .arg(version, 8, 16, QLatin1Char('0'));
    }
}

QString quicMetadataStatusName(QuicMetadataStatus status)
{
    switch (status) {
    case QuicMetadataStatus::UnsupportedVersion:
        return QStringLiteral("unsupported QUIC version");
    case QuicMetadataStatus::VersionNegotiation:
        return QStringLiteral("QUIC version negotiation");
    case QuicMetadataStatus::NotInitial:
        return QStringLiteral("not a QUIC Initial");
    case QuicMetadataStatus::InitialEncrypted:
        return QStringLiteral("encrypted QUIC Initial");
    case QuicMetadataStatus::Malformed:
        return QStringLiteral("malformed QUIC packet");
    case QuicMetadataStatus::NotQuic:
        break;
    }
    return QStringLiteral("not QUIC");
}

QuicObservation QuicObserver::parsePacket(const uint8_t *payload, int length)
{
    QuicObservation observation;
    observation.timestamp = QDateTime::currentDateTimeUtc();

    if (!payload || length < 1) return observation;

    // Short-header QUIC (1-RTT) has no version and carries no usable metadata,
    // and arbitrary UDP can start with the long-header bit. Only the explicit
    // long-header/version combination below is treated as QUIC.
    if ((payload[0] & 0x80) == 0) return observation;
    if (length < 5) return malformed(observation);

    observation.version = (static_cast<quint32>(payload[1]) << 24) |
                          (static_cast<quint32>(payload[2]) << 16) |
                          (static_cast<quint32>(payload[3]) << 8) |
                          static_cast<quint32>(payload[4]);
    observation.versionName = versionName(observation.version);

    if (observation.version == 0) {
        // Version negotiation has no packet type and no hostname. Its version
        // list is left unread; the next handshake reports the chosen version.
        observation.status = QuicMetadataStatus::VersionNegotiation;
        return observation;
    }
    if (!supportedVersion(observation.version)) {
        // Draft and future versions have unknown packet layouts. Reporting the
        // version without interpreting the rest keeps attribution unknown.
        observation.status = QuicMetadataStatus::UnsupportedVersion;
        return observation;
    }
    if ((payload[0] & 0x40) == 0) return malformed(observation); // fixed bit

    int pos = 5;

    if (pos >= length) return malformed(observation);
    const int destinationIdLength = payload[pos++];
    if (destinationIdLength > 20 || pos + destinationIdLength > length) {
        return malformed(observation);
    }
    pos += destinationIdLength; // deliberately not retained

    if (pos >= length) return malformed(observation);
    const int sourceIdLength = payload[pos++];
    if (sourceIdLength > 20 || pos + sourceIdLength > length) {
        return malformed(observation);
    }
    pos += sourceIdLength; // deliberately not retained

    observation.packetType = packetTypeName(observation.version, payload[0]);
    if (!isInitialPacket(observation.version, payload[0])) {
        // Retry, 0-RTT, and Handshake packets have no visible ClientHello and
        // their layouts differ, so they are not parsed further.
        observation.status = QuicMetadataStatus::NotInitial;
        return observation;
    }

    quint64 tokenLength = 0;
    if (!readVarint(payload, length, pos, tokenLength) ||
        tokenLength > static_cast<quint64>(length - pos)) {
        return malformed(observation);
    }
    pos += static_cast<int>(tokenLength); // deliberately not retained

    quint64 packetLength = 0;
    if (!readVarint(payload, length, pos, packetLength) ||
        packetLength == 0 ||
        packetLength > static_cast<quint64>(length - pos)) {
        return malformed(observation);
    }

    // The protected payload is a packet number plus ciphertext. No key material
    // is derived from the connection ID: decrypting the Initial would expose
    // the TLS ClientHello, which PRD.md explicitly excludes.
    const int packetNumberLength = (payload[0] & 0x03) + 1;
    if (packetLength <= static_cast<quint64>(packetNumberLength)) {
        return malformed(observation);
    }

    observation.status = QuicMetadataStatus::InitialEncrypted;
    return observation;
}

QuicObservation QuicObserver::parseDatagram(const uint8_t *data, quint32 length)
{
    if (!data || length < 20) return QuicObservation();

    const int version = (data[0] >> 4) & 0x0F;
    int transportOffset = 0;
    if (version == 4) {
        const int headerLength = (data[0] & 0x0F) * 4;
        if (headerLength < 20 || static_cast<quint32>(headerLength) > length) {
            return QuicObservation();
        }
        if (data[9] != 17) return QuicObservation(); // UDP only
        transportOffset = headerLength;
    } else if (version == 6) {
        if (length < 40) return QuicObservation();
        if (data[6] != 17) return QuicObservation(); // extension headers unsupported
        transportOffset = 40;
    } else {
        return QuicObservation();
    }

    if (static_cast<quint32>(transportOffset) + 8 > length) return QuicObservation();

    const quint16 udpLength = static_cast<quint16>((data[transportOffset + 4] << 8) |
                                                   data[transportOffset + 5]);
    int payloadLength = static_cast<int>(length) - transportOffset - 8;
    if (udpLength >= 8) payloadLength = qMin(payloadLength, static_cast<int>(udpLength) - 8);
    if (payloadLength <= 0) return QuicObservation();

    const int payloadOffset = transportOffset + 8;
    return parsePacket(data + payloadOffset, payloadLength);
}
