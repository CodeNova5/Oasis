/**
 * @file    networkmodel.cpp
 * @brief   Network tree model implementation with silent batch additions and UserRoles.
 * @author  Ali Sakkaf
 */
#include "networkmodel.h"
#include "attribution/attributionconfidence.h"
#include "networkmonitor.h"
#include "identity/processlineage.h"
#include "identity/processgroupmanager.h"
#include <QFont>
#include <QColor>
#include <QBrush>
#include <QStringList>
#include <utility>

namespace {

// NG-011: one short, unambiguous phrase per Authenticode state.
QString signerRowText(const ProcessNode &p)
{
    switch (p.signerStatus) {
    case ApplicationIdentity::SignerStatus::Signed:
        return p.publisher.isEmpty()
            ? QStringLiteral("signed")
            : QStringLiteral("signed: %1").arg(p.publisher);
    case ApplicationIdentity::SignerStatus::Unsigned:
        return QStringLiteral("unsigned");
    case ApplicationIdentity::SignerStatus::Invalid:
        return QStringLiteral("invalid signature");
    case ApplicationIdentity::SignerStatus::Unknown:
        break;
    }
    return QStringLiteral("signature unavailable");
}

} // namespace

NetworkTreeModel::NetworkTreeModel(QObject *parent) : QAbstractItemModel(parent)
{
    m_ticker = new QTimer(this);
    m_ticker->setInterval(1000);
    connect(m_ticker, &QTimer::timeout, this, &NetworkTreeModel::onTick);
    m_ticker->start();
}

QModelIndex NetworkTreeModel::index(int row, int col, const QModelIndex &parent) const
{
    if (!parent.isValid()) {
        if (row < 0 || row >= m_procs.size()) return {};
        return createIndex(row, col, nullptr);
    }
    if (parent.internalPointer() != nullptr) return {};
    int pRow = parent.row();
    if (pRow < 0 || pRow >= m_procs.size()) return {};
    const ProcessNode &p = m_procs[pRow];
    const int serviceRows = p.services.size();
    if (row < 0 || row >= serviceRows + p.conns.size()) return {};
    // NG-012: children are the hosted services first, then connections. The low
    // bit of the internal pointer marks a service row so both kinds can share
    // one child index space without a second model.
    const qintptr tag = qintptr(pRow + 1) * 2 + (row < serviceRows ? 1 : 0);
    return createIndex(row, col, reinterpret_cast<void*>(tag));
}

QModelIndex NetworkTreeModel::parent(const QModelIndex &child) const
{
    if (!child.isValid()) return {};
    if (child.internalPointer() == nullptr) return {};
    const qintptr tag = static_cast<qintptr>(reinterpret_cast<uintptr_t>(child.internalPointer()));
    const int pRow = static_cast<int>(tag / 2) - 1;
    if (pRow < 0 || pRow >= m_procs.size()) return {};
    return createIndex(pRow, 0, nullptr);
}

int NetworkTreeModel::rowCount(const QModelIndex &parent) const
{
    if (!parent.isValid()) return m_procs.size();
    if (parent.internalPointer() != nullptr) return 0;
    int pRow = parent.row();
    if (pRow < 0 || pRow >= m_procs.size()) return 0;
    const ProcessNode &p = m_procs[pRow];
    return p.services.size() + p.conns.size();
}

int NetworkTreeModel::columnCount(const QModelIndex &) const { return COL_COUNT; }

Qt::ItemFlags NetworkTreeModel::flags(const QModelIndex &idx) const
{
    return idx.isValid() ? Qt::ItemIsEnabled | Qt::ItemIsSelectable : Qt::NoItemFlags;
}

QVariant NetworkTreeModel::data(const QModelIndex &idx, int role) const
{
    if (!idx.isValid()) return {};

    const bool isProcess = (idx.internalPointer() == nullptr);
    const int  col       = idx.column();

    if (isProcess)
    {
        if (idx.row() >= m_procs.size()) return {};
        const ProcessNode &p = m_procs[idx.row()];

        // ── Custom Roles for Context Menu (Task Kill/Info) ──
        if (role == Qt::UserRole) return p.pid;
        if (role == Qt::UserRole + 1) return p.name;
        if (role == Qt::UserRole + 2) return true; // isProcess flag
        if (role == Qt::UserRole + 6) return p.identityId;
        // NG-016: which activity group the row belongs to, for the detail UI.
        if (role == Qt::UserRole + 7) return p.groupId;

        // ── FIX: Custom Role for Numeric Sorting ──
        if (role == Qt::UserRole + 5) {
            switch (col) {
            case COL_NAME:   return p.name;
            case COL_RX:     return static_cast<qulonglong>(p.totalRxSpeed);
            case COL_TX:     return static_cast<qulonglong>(p.totalTxSpeed);
            case COL_BYTES:  return static_cast<qulonglong>(p.totalRxBytes + p.totalTxBytes);
            case COL_PKTS:   return static_cast<qulonglong>(p.totalPackets);
            default:         return QVariant();
            }
        }

        if (role == Qt::DecorationRole && col == COL_NAME)
            return p.icon.isNull() ? QVariant() : QVariant(p.icon.pixmap(18, 18));

        if (role == Qt::DisplayRole) {
            switch (col) {
            case COL_NAME: {
                // NG-010: show the resolver's display name when it adds
                // information beyond the process name (service rows already
                // carry their service display name).
                QString label = p.name;
                if (!p.identityName.isEmpty() && !p.name.startsWith("Service:")
                    && p.identityName.compare(p.name, Qt::CaseInsensitive) != 0) {
                    label += " — " + p.identityName;
                }
                // NG-011: keep the Authenticode state visible on the row so
                // signed, unsigned, invalid, and unavailable stay distinct.
                if (!p.identityId.isEmpty())
                    label += "  •  " + signerRowText(p);
                // NG-012: a shared host keeps its services in child rows; the
                // count makes that visible without expanding.
                if (p.services.size() > 1)
                    label += QStringLiteral("  •  %1 services").arg(p.services.size());
                return QString("%1  (PID %2)  •  %3 conn%4").arg(label).arg(p.pid).arg(p.conns.size()).arg(p.conns.size() == 1 ? "" : "s");
            }
            case COL_SRC:    return {};
            case COL_DST:    return {};
            case COL_DOMAIN: return {};
            case COL_SERVICE:return {};
            case COL_RX:     return "↓ " + formatSpeed(p.totalRxSpeed);
            case COL_TX:     return "↑ " + formatSpeed(p.totalTxSpeed);
            case COL_BYTES:  return formatBytes(p.totalRxBytes + p.totalTxBytes);
            case COL_PKTS:   return static_cast<qulonglong>(p.totalPackets);
            }
        }
        if (role == Qt::ToolTipRole && col == COL_NAME) {
            QStringList lines;
            lines << p.name;
            if (!p.identityName.isEmpty() && p.identityName != p.name)
                lines << "Identity: " + p.identityName;
            lines << "Signature: " + signerRowText(p);
            if (!p.publisher.isEmpty())
                lines << "Publisher: " + p.publisher;
            if (!p.identityId.isEmpty())
                lines << "Identity ID: " + p.identityId;
            if (p.services.size() > 1)
                lines << QStringLiteral("%1 services (expand to list)").arg(p.services.size());
            // NG-013: which instance of this PID is talking, and who started it.
            const QString started = NetGuard::ProcessLineage::formatStartTime(p.processStartMs);
            if (!started.isEmpty())
                lines << "Started: " + started;
            if (p.parentPid != 0) {
                lines << (p.parentName.isEmpty()
                              ? QStringLiteral("Parent: PID %1").arg(p.parentPid)
                              : QStringLiteral("Parent: %1 (PID %2)").arg(p.parentName).arg(p.parentPid));
            }
            // NG-014: the activity group this process was grouped into.
            if (!p.groupName.isEmpty()) {
                lines << QStringLiteral("Group: %1 (%2)")
                             .arg(p.groupName,
                                  NetGuard::groupConfidenceName(p.groupConfidence));
            }
            return lines.join('\n');
        }
        if (role == Qt::ForegroundRole) {
            if (col == COL_RX) return QColor("#3B82F6");
            if (col == COL_TX) return QColor("#10B981");
        }
        if (role == Qt::FontRole) { QFont f; f.setBold(true); return f; }
        if (role == Qt::BackgroundRole && (p.totalRxSpeed + p.totalTxSpeed) > 0) return QColor(59, 130, 246, 20);
        return {};
    }

    const qintptr tag = static_cast<qintptr>(reinterpret_cast<uintptr_t>(idx.internalPointer()));
    const int pRow = static_cast<int>(tag / 2) - 1;
    if (pRow < 0 || pRow >= m_procs.size()) return {};
    const ProcessNode &p = m_procs[pRow];
    const int serviceRows = p.services.size();
    if (idx.row() >= serviceRows + p.conns.size()) return {};

    // ── NG-012: service rows ──
    // A shared host shows every service it runs; each row carries the service
    // key, its state, and the SCM image path. No traffic is duplicated here:
    // the packets stay on the hosting process row.
    if ((tag & 1) != 0) {
        const NetGuard::ServiceEntry &s = p.services[idx.row()];
        if (role == Qt::UserRole + 1) return s.displayName;
        if (role == Qt::UserRole + 2) return false; // not a process node
        if (role == Qt::UserRole + 5) {
            switch (col) {
            case COL_NAME:   return QStringLiteral("\x01") + s.displayName; // services sort first
            case COL_RX: case COL_TX: case COL_BYTES: case COL_PKTS:
                return static_cast<qulonglong>(0);
            default:         return QVariant();
            }
        }
        if (role == Qt::ToolTipRole) {
            QStringList lines;
            lines << s.displayName + " (" + s.serviceName + ")";
            lines << "State: " + NetGuard::serviceStateName(s.state);
            if (!s.executablePath.isEmpty())
                lines << "Image: " + s.executablePath;
            if (p.pid) lines << QStringLiteral("Hosted by PID %1").arg(p.pid);
            if (!p.groupName.isEmpty())
                lines << QStringLiteral("Group: %1 (%2)")
                             .arg(p.groupName,
                                  NetGuard::groupConfidenceName(p.groupConfidence));
            lines << (s.acceptsStop ? "Can be stopped from Services"
                                    : "Protected service (not user-stoppable)");
            return lines.join('\n');
        }
        if (role == Qt::DisplayRole) {
            switch (col) {
            case COL_NAME:    return s.displayName;
            case COL_SERVICE: return s.serviceName + "  —  " + NetGuard::serviceStateName(s.state);
            default:          return {};
            }
        }
        if (role == Qt::ForegroundRole && col == COL_NAME
            && s.state != NetGuard::ServiceState::Running)
            return QColor("#8B949E"); // stopped / pending services are dimmed
        return {};
    }

    const ConnectionStat &c = p.conns[idx.row() - serviceRows];

    // ── Custom Roles for Connection child rows ──
    if (role == Qt::UserRole) return p.pid;
    if (role == Qt::UserRole + 1) return c.key.srcIP + ":" + QString::number(c.key.srcPort);
    if (role == Qt::UserRole + 2) return false; // not process node

    // ── FIX: Custom Role for Numeric Sorting ──
    if (role == Qt::UserRole + 5) {
        switch (col) {
        case COL_NAME:   return c.key.protocol;
        case COL_DOMAIN: return c.domain;
        case COL_RX:     return static_cast<qulonglong>(c.rxSpeed);
        case COL_TX:     return static_cast<qulonglong>(c.txSpeed);
        case COL_BYTES:  return static_cast<qulonglong>(c.rxBytes + c.txBytes);
        case COL_PKTS:   return static_cast<qulonglong>(c.packets);
        default:         return QVariant();
        }
    }

    if (role == Qt::DisplayRole) {
        switch (col) {
        case COL_NAME:    return c.key.protocol;
        case COL_SRC:     return QString("%1 : %2").arg(c.key.srcIP).arg(c.key.srcPort);
        case COL_DST:     return QString("%1 : %2").arg(c.key.dstIP).arg(c.key.dstPort);
        case COL_DOMAIN:
            return c.domain.isEmpty()
                ? QString()
                : AttributionConfidenceModel::qualifiedText(c.domain,
                                                            c.domainConfidence);
        case COL_SERVICE: return c.service;
        case COL_RX:      return "↓ " + formatSpeed(c.rxSpeed);
        case COL_TX:      return "↑ " + formatSpeed(c.txSpeed);
        case COL_BYTES:   return formatBytes(c.rxBytes + c.txBytes);
        case COL_PKTS:    return static_cast<qulonglong>(c.packets);
        }
    }

    if (role == Qt::ToolTipRole && col == COL_DOMAIN) {
        if (c.domain.isEmpty()) {
            return QStringLiteral("No DNS answer or TLS SNI has been observed for this endpoint.\n"
                                  "A direct-IP, encrypted-DNS, or ECH-hidden connection stays unattributed.");
        }
        QStringList lines;
        lines << (c.domains.size() > 1
                      ? QStringLiteral("Domain names observed for this endpoint:")
                      : QStringLiteral("Domain name observed for this endpoint:"));
        for (const QString &name : c.domains) lines << "  " + name;
        lines << QStringLiteral("Confidence: %1 (%2)")
                     .arg(AttributionConfidenceModel::displayName(c.domainConfidence),
                          AttributionConfidenceModel::technicalName(c.domainConfidence));
        if (!c.domainEvidence.isEmpty()) {
            lines << QStringLiteral("Evidence:");
            for (const QString &item : c.domainEvidence) lines << "  " + item;
        }
        lines << QStringLiteral("Source: %1").arg(attributionSourceName(c.domainSource));
        if (c.domainExpiresAt.isValid()) {
            lines << QStringLiteral("Valid until: %1")
                         .arg(c.domainExpiresAt.toLocalTime().toString("HH:mm:ss"));
        }
        return lines.join('\n');
    }

    if (role == Qt::ForegroundRole) {
        if (col == COL_NAME) {
            if (c.key.protocol.startsWith("TCP"))  return QColor("#3B82F6");
            if (c.key.protocol.startsWith("UDP"))  return QColor("#10B981");
            if (c.key.protocol.startsWith("ICMP")) return QColor("#F59E0B");
        }
        if (col == COL_RX) return QColor("#3B82F6");
        if (col == COL_TX) return QColor("#10B981");
    }
    return {};
}

QVariant NetworkTreeModel::headerData(int s, Qt::Orientation o, int role) const
{
    if (o != Qt::Horizontal || role != Qt::DisplayRole) return {};
    static const char *H[COL_COUNT] = {
        "Application / Protocol", "Source", "Destination", "Domain",
        "Service", "Download", "Upload", "Total Bytes", "Packets"
    };
    return QLatin1String(H[s]);
}

void NetworkTreeModel::addPackets(const QList<CapturedPacketInfo> &batch)
{
    for (const auto& info : batch) {
        const ParsedPacket &pkt = info.pkt;
        quint32 pid = info.pid;
        QString proc = info.proc;

        const QString name = proc.isEmpty() ? (pid ? QString("PID %1").arg(pid) : "Unknown") : proc;
        const int pRow = findOrAddProcess(name, pid);
        ProcessNode &p = m_procs[pRow];

        // NG-010: identities resolve asynchronously; attach them when they
        // arrive and refresh the label without touching grouping or icons.
        if (!info.identityId.isEmpty()
            && (p.identityId != info.identityId || p.identityName != info.identityName
                || p.publisher != info.identityPublisher
                || p.signerStatus != info.signerStatus)) {
            p.identityId = info.identityId;
            p.identityName = info.identityName;
            p.publisher = info.identityPublisher;
            p.signerStatus = info.signerStatus;
            const QModelIndex nameIdx = index(pRow, COL_NAME);
            emit dataChanged(nameIdx, nameIdx, {Qt::DisplayRole, Qt::ToolTipRole, Qt::UserRole + 6});
        }

        // NG-013: lineage resolves on the cache thread; refresh it when it
        // arrives. A changed start time means the PID was recycled.
        if (info.processStartMs != 0
            && (p.processStartMs != info.processStartMs || p.parentPid != info.parentPid
                || p.parentName != info.parentName)) {
            p.processStartMs = info.processStartMs;
            p.parentPid = info.parentPid;
            p.parentName = info.parentName;
            const QModelIndex nameIdx = index(pRow, COL_NAME);
            emit dataChanged(nameIdx, nameIdx, {Qt::ToolTipRole});
        }

        // NG-014: group membership resolves on the cache thread too.
        if (p.groupName != info.groupName || p.groupId != info.groupId
            || p.groupConfidence != info.groupConfidence) {
            p.groupId = info.groupId;
            p.groupName = info.groupName;
            p.groupConfidence = info.groupConfidence;
            const QModelIndex nameIdx = index(pRow, COL_NAME);
            emit dataChanged(nameIdx, nameIdx, {Qt::ToolTipRole, Qt::UserRole + 7});
        }

        const quint64 bytes  = pkt.wireLen ? pkt.wireLen : pkt.captureLen;
        const bool    isDown = pkt.isDownload;

        ConnectionKey key;
        key.srcIP = pkt.srcIP; key.srcPort = pkt.srcPort;
        key.dstIP = pkt.dstIP; key.dstPort = pkt.dstPort;
        key.protocol = pkt.protocol;

        auto it = p.connIdx.find(key);
        if (it == p.connIdx.end()) {
            const int cRow = p.conns.size();
            const QModelIndex pIdx = createIndex(pRow, 0, nullptr);
            beginInsertRows(pIdx, cRow, cRow);
            ConnectionStat c;
            c.key = key;
            // The remote side is the one DNS can name; for download traffic it
            // is the source address, for upload it is the destination.
            c.remoteAddress = isDown ? pkt.srcIP : pkt.dstIP;
            if (isDown) c.rxBytes = bytes; else c.txBytes = bytes;
            c.packets = 1;
            c.service = pkt.service;
            p.conns.append(c);
            p.connIdx.insert(key, cRow);
            endInsertRows();
        } else {
            const int cRow = it.value();
            if (isDown) p.conns[cRow].rxBytes += bytes;
            else        p.conns[cRow].txBytes += bytes;
            p.conns[cRow].packets += 1;
        }

        if (isDown) p.totalRxBytes += bytes;
        else        p.totalTxBytes += bytes;
        p.totalPackets += 1;
    }
}

void NetworkTreeModel::onTick()
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (int pRow = 0; pRow < m_procs.size(); ++pRow) {
        ProcessNode &p = m_procs[pRow];
        quint64 sumRx = 0, sumTx = 0;

        for (auto &c : p.conns) {
            // NG-031: a connection with no new traffic must still lose a name
            // whose DNS TTL has run out. The refresh below repopulates it if a
            // fresh answer arrived.
            if (!c.domain.isEmpty() && c.domainExpiresAt.isValid()
                && c.domainExpiresAt <= now) {
                c.domain.clear();
                c.domains.clear();
                c.domainSource = AttributionSource::Unknown;
                c.domainConfidence = ApplicationIdentity::Confidence::Unknown;
                c.domainEvidence.clear();
                c.domainExpiresAt = QDateTime();
            }
            quint64 rawRx = (c.rxBytes > c.prevRx) ? (c.rxBytes - c.prevRx) : 0;
            quint64 rawTx = (c.txBytes > c.prevTx) ? (c.txBytes - c.prevTx) : 0;

            c.rxSpeed = static_cast<quint64>(0.7 * rawRx + 0.3 * c.rxSpeed);
            c.txSpeed = static_cast<quint64>(0.7 * rawTx + 0.3 * c.txSpeed);

            c.prevRx  = c.rxBytes;
            c.prevTx  = c.txBytes;
            sumRx    += c.rxSpeed;
            sumTx    += c.txSpeed;
        }
        p.totalRxSpeed = sumRx;
        p.totalTxSpeed = sumTx;

        // ── FIX: Emit dataChanged starting from COL_NAME to update parent UI correctly ──
        // ── FIX: Include Qt::UserRole + 5 to keep sorting updated dynamically ──
        if (!p.conns.isEmpty() || !p.services.isEmpty()) {
            const QModelIndex pIdx = createIndex(pRow, 0, nullptr);
            emit dataChanged(index(0, COL_NAME, pIdx),
                             index(p.services.size() + p.conns.size() - 1, COL_PKTS, pIdx),
                             {Qt::DisplayRole, Qt::UserRole + 5});
        }
        emit dataChanged(createIndex(pRow, COL_NAME, nullptr), createIndex(pRow, COL_PKTS, nullptr), {Qt::DisplayRole, Qt::UserRole + 5});
    }
}

void NetworkTreeModel::setDomainResolver(
    std::function<QList<DomainAttribution>(const QString &)> resolver)
{
    m_domainResolver = std::move(resolver);
}

void NetworkTreeModel::refreshDomains()
{
    if (!m_domainResolver) return;

    for (int pRow = 0; pRow < m_procs.size(); ++pRow) {
        ProcessNode &p = m_procs[pRow];
        if (p.conns.isEmpty()) continue;
        const QModelIndex pIdx = createIndex(pRow, 0, nullptr);
        for (int cRow = 0; cRow < p.conns.size(); ++cRow) {
            ConnectionStat &c = p.conns[cRow];
            const QList<DomainAttribution> records =
                m_domainResolver(c.remoteAddress);

            // NG-031/NG-032/NG-035: DNS answers and visible TLS SNI records
            // share one address index. The summary prefers a name both
            // observers agree on, so a DNS name and a matching SNI are
            // confirmed while either alone stays Likely.
            const DestinationNameSummary summary =
                summarizeDestinationNames(records, c.remoteAddress);
            const QString &domain = summary.name;
            const QStringList &names = summary.names;
            const AttributionSource source = summary.source;
            const ApplicationIdentity::Confidence confidence = summary.confidence;
            const QStringList &evidence = summary.evidence;
            const QDateTime &expiresAt = summary.expiresAt;

            if (c.domain == domain && c.domains == names
                && c.domainSource == source && c.domainConfidence == confidence
                && c.domainEvidence == evidence
                && c.domainExpiresAt == expiresAt) {
                continue;
            }

            c.domain = domain;
            c.domains = names;
            c.domainSource = source;
            c.domainConfidence = confidence;
            c.domainEvidence = evidence;
            c.domainExpiresAt = expiresAt;
            emit dataChanged(index(cRow, COL_DOMAIN, pIdx),
                             index(cRow, COL_DOMAIN, pIdx),
                             {Qt::DisplayRole, Qt::ToolTipRole, Qt::UserRole + 5});
        }
    }
}

void NetworkTreeModel::setProcessIcon(const QString &procName, const QIcon &icon)
{
    auto it = m_procIdx.find(procName);
    if (it == m_procIdx.end()) return;
    const int pRow = it.value();
    m_procs[pRow].icon = icon;
    const QModelIndex idx = createIndex(pRow, COL_NAME, nullptr);
    emit dataChanged(idx, idx, {Qt::DecorationRole});
}

void NetworkTreeModel::clear()
{
    if (m_procs.isEmpty()) return;
    beginResetModel();
    m_procs.clear();
    m_procIdx.clear();
    m_servicesByPid.clear();
    endResetModel();
}

void NetworkTreeModel::applyServiceSnapshot(const NetGuard::ServicePidMap &services)
{
    m_servicesByPid = services;

    for (int pRow = 0; pRow < m_procs.size(); ++pRow) {
        ProcessNode &p = m_procs[pRow];
        if (!p.pid) continue;
        const auto hosted = m_servicesByPid.constFind(p.pid);
        const QVector<NetGuard::ServiceEntry> entries =
            (hosted == m_servicesByPid.constEnd()) ? QVector<NetGuard::ServiceEntry>()
                                                   : hosted.value();
        if (p.services == entries) continue;

        const int oldCount = p.services.size();
        const int newCount = entries.size();
        const QModelIndex pIdx = createIndex(pRow, 0, nullptr);
        if (newCount > oldCount) {
            beginInsertRows(pIdx, oldCount, newCount - 1);
            p.services = entries;
            endInsertRows();
        } else if (newCount < oldCount) {
            beginRemoveRows(pIdx, newCount, oldCount - 1);
            p.services = entries;
            endRemoveRows();
        } else {
            p.services = entries;
        }

        // The host row shows the service count, and service rows carry the
        // fields that changed (state, image path).
        emit dataChanged(index(pRow, COL_NAME), index(pRow, COL_PKTS),
                         {Qt::DisplayRole, Qt::ToolTipRole});
        if (newCount > 0)
            emit dataChanged(index(0, COL_NAME, pIdx), index(newCount - 1, COL_PKTS, pIdx),
                             {Qt::DisplayRole, Qt::ToolTipRole, Qt::ForegroundRole});
    }
}

int NetworkTreeModel::findOrAddProcess(const QString &name, quint32 pid)
{
    auto it = m_procIdx.find(name);
    if (it != m_procIdx.end()) {
        if (pid && !m_procs[it.value()].pid) m_procs[it.value()].pid = pid;
        return it.value();
    }
    const int pRow = m_procs.size();
    beginInsertRows(QModelIndex(), pRow, pRow);
    ProcessNode p; p.name = name; p.pid = pid;
    // NG-012: a service snapshot may have arrived before the first packet of
    // this process; attach what is already known so the rows appear at once.
    const auto hosted = m_servicesByPid.constFind(pid);
    if (hosted != m_servicesByPid.constEnd()) p.services = hosted.value();
    m_procs.append(p);
    m_procIdx.insert(name, pRow);
    endInsertRows();
    return pRow;
}

QString NetworkTreeModel::formatSpeed(quint64 bps)
{
    if (bps == 0)            return "0 B/s";
    if (bps < 1024)          return QString("%1 B/s").arg(bps);
    if (bps < 1024*1024)     return QString("%1 KB/s").arg(bps/1024.0, 0, 'f', 1);
    if (bps < 1024*1024*1024ULL) return QString("%1 MB/s").arg(bps/(1024.0*1024), 0, 'f', 2);
    return                         QString("%1 GB/s").arg(bps/(1024.0*1024*1024), 0, 'f', 2);
}

QString NetworkTreeModel::formatBytes(quint64 bytes)
{
    if (bytes < 1024)             return QString("%1 B").arg(bytes);
    if (bytes < 1024*1024)        return QString("%1 KB").arg(bytes/1024.0, 0, 'f', 1);
    if (bytes < 1024*1024*1024ULL)return QString("%1 MB").arg(bytes/(1024.0*1024), 0, 'f', 2);
    return                               QString("%1 GB").arg(bytes/(1024.0*1024*1024), 0, 'f', 2);
}

