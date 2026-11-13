/**
 * @file    dnsobserver.cpp
 * @author  Oasis
 */
#include "dnsobserver.h"

namespace {

// Bounds-checked cursor over one message. Every reader leaves the position
// untouched on failure, so a malformed field simply aborts the parse.
class Reader
{
public:
    Reader(const uint8_t *data, int length) : m_data(data), m_length(length) {}

    bool u8(int &pos, quint8 &value) const
    {
        if (pos < 0 || pos + 1 > m_length) return false;
        value = m_data[pos++];
        return true;
    }

    bool u16(int &pos, quint16 &value) const
    {
        if (pos < 0 || pos + 2 > m_length) return false;
        value = static_cast<quint16>((m_data[pos] << 8) | m_data[pos + 1]);
        pos += 2;
        return true;
    }

    bool u32(int &pos, quint32 &value) const
    {
        if (pos < 0 || pos + 4 > m_length) return false;
        value = (static_cast<quint32>(m_data[pos]) << 24) |
                (static_cast<quint32>(m_data[pos + 1]) << 16) |
                (static_cast<quint32>(m_data[pos + 2]) << 8) |
                static_cast<quint32>(m_data[pos + 3]);
        pos += 4;
        return true;
    }

    // DNS names use labels and compression pointers. A pointer must point
    // strictly backwards (so a loop is impossible), labels are capped at 63
    // bytes, and the expanded name at 255 bytes, per RFC 1035.
    bool name(int &pos, QString &out) const
    {
        QStringList labels;
        int cursor = pos;
        int resumeAt = -1;
        int expanded = 0;
        int jumps = 0;

        for (;;) {
            quint8 lengthByte = 0;
            if (!u8(cursor, lengthByte)) return false;

            if ((lengthByte & 0xC0) == 0xC0) {
                quint8 low = 0;
                const int pointerPos = cursor - 1;
                if (!u8(cursor, low)) return false;
                const int target = ((lengthByte & 0x3F) << 8) | low;
                if (target >= pointerPos || target >= m_length) return false;
                if (resumeAt < 0) resumeAt = cursor;
                cursor = target;
                if (++jumps > 16) return false;
                continue;
            }
            if ((lengthByte & 0xC0) != 0) return false; // reserved label type

            if (lengthByte == 0) {
                if (resumeAt < 0) resumeAt = cursor;
                break;
            }

            const int labelLength = lengthByte;
            if (labelLength > 63 || cursor + labelLength > m_length) return false;
            expanded += labelLength + 1;
            if (expanded > 255) return false;
            labels.append(QString::fromLatin1(
                reinterpret_cast<const char *>(m_data + cursor), labelLength));
            cursor += labelLength;
        }

        pos = resumeAt;
        out = labels.join(QLatin1Char('.')).toLower();
        return true;
    }

private:
    const uint8_t *m_data;
    int m_length;
};

QString ipv4Text(const uint8_t *address)
{
    return QStringLiteral("%1.%2.%3.%4")
        .arg(address[0]).arg(address[1]).arg(address[2]).arg(address[3]);
}

QString ipv6Text(const uint8_t *address)
{
    QStringList groups;
    groups.reserve(8);
    for (int i = 0; i < 16; i += 2) {
        const uint group = static_cast<uint>((address[i] << 8) | address[i + 1]);
        groups.append(QStringLiteral("%1").arg(group, 4, 16, QLatin1Char('0')));
    }
    return groups.join(QLatin1Char(':'));
}

} // namespace

QString DnsObserver::recordTypeName(quint16 type)
{
    switch (type) {
    case 1:   return QStringLiteral("A");
    case 2:   return QStringLiteral("NS");
    case 5:   return QStringLiteral("CNAME");
    case 6:   return QStringLiteral("SOA");
    case 12:  return QStringLiteral("PTR");
    case 15:  return QStringLiteral("MX");
    case 16:  return QStringLiteral("TXT");
    case 28:  return QStringLiteral("AAAA");
    case 33:  return QStringLiteral("SRV");
    case 64:  return QStringLiteral("SVCB");
    case 65:  return QStringLiteral("HTTPS");
    case 257: return QStringLiteral("CAA");
    default:  return QStringLiteral("TYPE%1").arg(type);
    }
}

QList<DnsEvent> DnsObserver::parseMessage(const uint8_t *payload, int length)
{
    QList<DnsEvent> events;
    if (!payload || length < 12) return events;

    const Reader reader(payload, length);
    int pos = 0;
    quint16 id = 0;
    quint16 flags = 0;
    quint16 questionCount = 0;
    quint16 answerCount = 0;
    quint16 authorityCount = 0;
    quint16 additionalCount = 0;
    if (!reader.u16(pos, id) || !reader.u16(pos, flags) ||
        !reader.u16(pos, questionCount) || !reader.u16(pos, answerCount) ||
        !reader.u16(pos, authorityCount) || !reader.u16(pos, additionalCount)) {
        return events;
    }

    // Only standard queries. IQUERY, STATUS, NOTIFY, and UPDATE carry different
    // layouts that this observer does not claim to understand.
    if (((flags >> 11) & 0x0F) != 0) return events;
    // Refuse absurd counts instead of looping over a hostile header.
    if (questionCount > 8 || answerCount > 64) return events;

    QString name;
    quint16 questionType = 0;
    for (int i = 0; i < questionCount; ++i) {
        QString questionName;
        if (!reader.name(pos, questionName)) return events;
        quint16 type = 0;
        quint16 klass = 0;
        if (!reader.u16(pos, type) || !reader.u16(pos, klass)) return events;
        if (i == 0) {
            name = questionName;
            questionType = type;
        }
    }

    QStringList addresses;
    QStringList aliases;
    quint16 firstAnswerType = 0;
    quint32 minimumTtl = 0;
    bool haveTtl = false;

    for (int i = 0; i < answerCount; ++i) {
        QString owner;
        if (!reader.name(pos, owner)) return events;
        quint16 type = 0;
        quint16 klass = 0;
        quint32 ttl = 0;
        quint16 dataLength = 0;
        if (!reader.u16(pos, type) || !reader.u16(pos, klass) ||
            !reader.u32(pos, ttl) || !reader.u16(pos, dataLength)) {
            return events;
        }
        if (pos + dataLength > length) return events; // record runs past the message
        const int dataStart = pos;

        if (type == 1 && dataLength == 4) {
            addresses.append(ipv4Text(payload + dataStart));
            if (!haveTtl || ttl < minimumTtl) minimumTtl = ttl;
            haveTtl = true;
        } else if (type == 28 && dataLength == 16) {
            addresses.append(ipv6Text(payload + dataStart));
            if (!haveTtl || ttl < minimumTtl) minimumTtl = ttl;
            haveTtl = true;
        } else if (type == 5 || type == 12) {
            // The target is another DNS name and may itself use compression.
            int aliasPos = dataStart;
            QString target;
            if (!reader.name(aliasPos, target)) return events;
            if (type == 5 && !target.isEmpty()) aliases.append(target);
        }

        if (i == 0) {
            firstAnswerType = type;
            if (name.isEmpty()) name = owner;
        }
        pos += dataLength;
    }

    // Authority/additional counts were read so the header is fully consumed;
    // their records are not needed for a name->address observation.
    Q_UNUSED(authorityCount)
    Q_UNUSED(additionalCount)

    if (name.isEmpty()) return events;

    DnsEvent event;
    event.timestamp = QDateTime::currentDateTimeUtc();
    event.response = (flags & 0x8000) != 0;
    event.truncated = (flags & 0x0200) != 0;
    event.transactionId = QStringLiteral("%1").arg(id, 4, 16, QLatin1Char('0'));
    event.name = name;
    event.recordType = questionType != 0 ? questionType : firstAnswerType;
    event.recordTypeName = recordTypeName(event.recordType);
    event.addresses = addresses;
    event.aliases = aliases;
    event.ttlSeconds = minimumTtl;
    if (!addresses.isEmpty()) {
        event.confidence = ApplicationIdentity::Confidence::StrongInference;
    } else if (event.response) {
        event.confidence = ApplicationIdentity::Confidence::WeakInference;
    } else {
        event.confidence = ApplicationIdentity::Confidence::Unknown;
    }
    events.append(event);
    return events;
}

QList<DnsEvent> DnsObserver::parseDatagram(const uint8_t *data, quint32 length)
{
    if (!data || length < 20 || length > 65535) return QList<DnsEvent>();

    const int version = (data[0] >> 4) & 0x0F;
    int transportOffset = 0;
    if (version == 4) {
        const int headerLength = (data[0] & 0x0F) * 4;
        if (headerLength < 20 || static_cast<quint32>(headerLength) > length) {
            return QList<DnsEvent>();
        }
        if (data[9] != 17) return QList<DnsEvent>(); // UDP only
        transportOffset = headerLength;
    } else if (version == 6) {
        if (length < 40) return QList<DnsEvent>();
        if (data[6] != 17) return QList<DnsEvent>(); // extension headers unsupported
        transportOffset = 40;
    } else {
        return QList<DnsEvent>();
    }

    if (static_cast<quint32>(transportOffset) + 8 > length) return QList<DnsEvent>();
    const quint16 sourcePort = static_cast<quint16>((data[transportOffset] << 8) |
                                                    data[transportOffset + 1]);
    const quint16 destinationPort = static_cast<quint16>((data[transportOffset + 2] << 8) |
                                                         data[transportOffset + 3]);
    if (sourcePort != 53 && destinationPort != 53) return QList<DnsEvent>();

    const quint16 udpLength = static_cast<quint16>((data[transportOffset + 4] << 8) |
                                                   data[transportOffset + 5]);
    int payloadLength = static_cast<int>(length) - transportOffset - 8;
    if (udpLength >= 8) payloadLength = qMin(payloadLength, static_cast<int>(udpLength) - 8);
    if (payloadLength <= 0) return QList<DnsEvent>();

    const int payloadOffset = transportOffset + 8;
    return parseMessage(data + payloadOffset, payloadLength);
}
