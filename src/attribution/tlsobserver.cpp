/**
 * @file    tlsobserver.cpp
 * @author  Oasis
 */
#include "tlsobserver.h"

namespace {

// Bounds-checked cursor. Every reader leaves the position untouched on
// failure, so a malformed field aborts without reading past the record.
class Cursor
{
public:
    Cursor(const uint8_t *data, int length) : m_data(data), m_length(length) {}

    bool u8(quint8 &value)
    {
        if (m_pos + 1 > m_length) return false;
        value = m_data[m_pos++];
        return true;
    }

    bool u16(quint16 &value)
    {
        if (m_pos + 2 > m_length) return false;
        value = static_cast<quint16>((m_data[m_pos] << 8) | m_data[m_pos + 1]);
        m_pos += 2;
        return true;
    }

    bool skip(int count)
    {
        if (count < 0 || m_pos + count > m_length) return false;
        m_pos += count;
        return true;
    }

    int remaining() const { return m_length - m_pos; }
    const uint8_t *current() const { return m_data + m_pos; }

private:
    const uint8_t *m_data;
    int m_length;
    int m_pos = 0;
};

enum class SniParse { Found, Absent, Invalid };

bool validHostName(const uint8_t *bytes, int length, QString &name)
{
    // A host_name is ASCII without embedded NULs. Anything else is not a name
    // this observer can claim, so it is rejected instead of rendered.
    if (length <= 0 || length > 255) return false;
    for (int i = 0; i < length; ++i) {
        if (bytes[i] < 0x21 || bytes[i] > 0x7E) return false;
    }

    QString value = QString::fromLatin1(reinterpret_cast<const char *>(bytes), length);
    while (value.endsWith(QLatin1Char('.'))) value.chop(1);
    value = value.toLower();
    if (value.isEmpty() || value.size() > 253) return false;
    name = value;
    return true;
}

SniParse parseSniExtension(const uint8_t *data, int length, QString &name)
{
    if (length < 2) return SniParse::Invalid;

    const int listLength = (data[0] << 8) | data[1];
    if (listLength <= 0 || listLength > length - 2) return SniParse::Invalid;

    const int end = 2 + listLength;
    int pos = 2;
    bool found = false;
    while (pos < end) {
        if (pos + 3 > end) return SniParse::Invalid;
        const quint8 nameType = data[pos];
        const int nameLength = (data[pos + 1] << 8) | data[pos + 2];
        pos += 3;
        if (nameLength <= 0 || pos + nameLength > end) return SniParse::Invalid;
        if (nameType == 0 && !found) {
            if (!validHostName(data + pos, nameLength, name)) {
                return SniParse::Invalid;
            }
            found = true;
        }
        pos += nameLength;
    }
    if (pos != end) return SniParse::Invalid;
    return found ? SniParse::Found : SniParse::Absent;
}

} // namespace

QString tlsSniStatusName(TlsSniStatus status)
{
    switch (status) {
    case TlsSniStatus::Available:      return QStringLiteral("available");
    case TlsSniStatus::NoSni:          return QStringLiteral("no SNI");
    case TlsSniStatus::Fragmented:     return QStringLiteral("fragmented");
    case TlsSniStatus::Encrypted:      return QStringLiteral("encrypted");
    case TlsSniStatus::EchHidden:      return QStringLiteral("ECH hidden");
    case TlsSniStatus::Malformed:      return QStringLiteral("malformed");
    case TlsSniStatus::NotClientHello: return QStringLiteral("not a ClientHello");
    case TlsSniStatus::NotTls:         break;
    }
    return QStringLiteral("not TLS");
}

TlsObservation TlsObserver::parseRecord(const uint8_t *payload, int length)
{
    TlsObservation observation;
    observation.timestamp = QDateTime::currentDateTimeUtc();

    if (!payload || length < 2) return observation;
    if (length < 5) {
        // A short first segment can still be the start of a TLS record. Report
        // it as fragmented rather than pretending there is no handshake there.
        if (payload[0] == 22 && payload[1] == 3) {
            observation.status = TlsSniStatus::Fragmented;
        }
        return observation;
    }

    const quint8 contentType = payload[0];
    const quint8 major = payload[1];
    const quint8 minor = payload[2];

    // Only SSL 3.0 through TLS 1.3 records have a 3.x version here. A TLS 1.3
    // ClientHello still uses 0x0301/0x0303 as its legacy record version.
    if (major != 3 || minor > 3) return observation;

    // TLS 1.3 encrypts handshake messages as application data. Without keys the
    // ClientHello cannot be read, so it is reported as unavailable.
    if (contentType == 23) {
        observation.status = TlsSniStatus::Encrypted;
        return observation;
    }
    if (contentType != 22) return observation; // not a handshake record

    const int recordLength = (payload[3] << 8) | payload[4];
    if (recordLength < 4) {
        observation.status = TlsSniStatus::Malformed;
        return observation;
    }

    if (length >= 6 && payload[5] != 1) {
        observation.status = TlsSniStatus::NotClientHello;
        return observation;
    }
    if (recordLength > length - 5) {
        observation.status = TlsSniStatus::Fragmented;
        return observation;
    }

    const uint8_t *body = payload + 5;
    const quint32 handshakeLength = (static_cast<quint32>(body[1]) << 16) |
                                    (static_cast<quint32>(body[2]) << 8) |
                                    static_cast<quint32>(body[3]);
    if (handshakeLength > static_cast<quint32>(recordLength - 4)) {
        // The rest of the ClientHello is in another record or TCP segment.
        observation.status = TlsSniStatus::Fragmented;
        return observation;
    }

    Cursor cursor(body + 4, static_cast<int>(handshakeLength));

    quint16 legacyVersion = 0;
    quint8 sessionIdLength = 0;
    quint16 cipherSuitesLength = 0;
    quint8 compressionLength = 0;
    quint16 extensionsLength = 0;
    if (!cursor.u16(legacyVersion) || !cursor.skip(32) ||
        !cursor.u8(sessionIdLength) || !cursor.skip(sessionIdLength) ||
        !cursor.u16(cipherSuitesLength) || !cursor.skip(cipherSuitesLength) ||
        !cursor.u8(compressionLength) || !cursor.skip(compressionLength) ||
        !cursor.u16(extensionsLength)) {
        observation.status = TlsSniStatus::Malformed;
        return observation;
    }
    Q_UNUSED(legacyVersion)

    if (extensionsLength == 0) {
        observation.status = TlsSniStatus::NoSni;
        return observation;
    }
    if (extensionsLength > cursor.remaining()) {
        observation.status = TlsSniStatus::Malformed;
        return observation;
    }

    Cursor extensions(cursor.current(), extensionsLength);
    QString serverName;
    bool echPresent = false;
    while (extensions.remaining() > 0) {
        quint16 type = 0;
        quint16 size = 0;
        if (!extensions.u16(type) || !extensions.u16(size)) {
            observation.status = TlsSniStatus::Malformed;
            return observation;
        }
        if (size > extensions.remaining()) {
            observation.status = TlsSniStatus::Malformed;
            return observation;
        }

        if (type == 0xFE0D) {
            // Encrypted ClientHello (RFC 9180 family): the visible name is only
            // the outer public name, not the destination's real identity.
            echPresent = true;
        } else if (type == 0 && serverName.isEmpty()) {
            QString parsed;
            const SniParse result = parseSniExtension(extensions.current(), size, parsed);
            if (result == SniParse::Invalid) {
                observation.status = TlsSniStatus::Malformed;
                return observation;
            }
            if (result == SniParse::Found) serverName = parsed;
        }
        if (!extensions.skip(size)) {
            observation.status = TlsSniStatus::Malformed;
            return observation;
        }
    }

    if (echPresent) {
        observation.status = TlsSniStatus::EchHidden;
    } else if (!serverName.isEmpty()) {
        observation.status = TlsSniStatus::Available;
        observation.serverName = serverName;
    } else {
        observation.status = TlsSniStatus::NoSni;
    }
    return observation;
}

TlsObservation TlsObserver::parseDatagram(const uint8_t *data, quint32 length)
{
    if (!data || length < 20) return TlsObservation();

    const int version = (data[0] >> 4) & 0x0F;
    int transportOffset = 0;
    if (version == 4) {
        const int headerLength = (data[0] & 0x0F) * 4;
        if (headerLength < 20 || static_cast<quint32>(headerLength) > length) {
            return TlsObservation();
        }
        if (data[9] != 6) return TlsObservation(); // TCP only
        transportOffset = headerLength;
    } else if (version == 6) {
        if (length < 40) return TlsObservation();
        if (data[6] != 6) return TlsObservation(); // extension headers unsupported
        transportOffset = 40;
    } else {
        return TlsObservation();
    }

    if (static_cast<quint32>(transportOffset) + 20 > length) return TlsObservation();
    const int tcpHeaderLength = (data[transportOffset + 12] >> 4) * 4;
    if (tcpHeaderLength < 20 ||
        static_cast<quint32>(transportOffset + tcpHeaderLength) > length) {
        return TlsObservation();
    }

    const int payloadOffset = transportOffset + tcpHeaderLength;
    const int payloadLength = static_cast<int>(length) - payloadOffset;
    if (payloadLength <= 0) return TlsObservation();
    return parseRecord(data + payloadOffset, payloadLength);
}
