/**
 * @file    networkmodel.cpp
 * @brief   Network tree model implementation with silent batch additions and UserRoles.
 * @author  Oasis
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

// NG-040: the tooltip behind the Activity column. It names the plain category
// with its confidence, every matched rule and the criteria that matched, and the
// manual policy scope the user can still choose. NG-041 adds the advisory
// foreground signal that fed the classification.
QStringList activityTooltip(const ActivityClassification &activity,
                            Oasis::ForegroundAssociation foreground =
                                Oasis::ForegroundAssociation::None)
{
    QStringList lines;
    lines << QStringLiteral("Activity: %1").arg(activity.summary());
    if (foreground == Oasis::ForegroundAssociation::ForegroundApp) {
        lines << QStringLiteral("Foreground: the active application "
                                "(advisory signal, never a policy override).");
    } else if (foreground == Oasis::ForegroundAssociation::ForegroundChild) {
        lines << QStringLiteral("Foreground: a live helper of the active "
                                "application (advisory signal, never a policy "
                                "override).");
    }
    if (!activity.matchedRules.isEmpty()) {
        lines << QStringLiteral("Matched rules:");
        for (const CatalogMatch &rule : activity.matchedRules) {
            lines << QStringLiteral("  • %1 — %2").arg(rule.ruleId, rule.explanation);
            if (!rule.matchedOn.isEmpty())
                lines << QStringLiteral("      %1")
                             .arg(rule.matchedOn.join(QStringLiteral("; ")));
        }
    }
    for (const QString &item : activity.evidence)
        lines << QStringLiteral("Evidence: %1").arg(item);
    if (!activity.manualPolicyTargets.isEmpty()) {
        lines << QStringLiteral("Manual policy scope: %1")
                     .arg(activity.manualPolicyTargets.first().label);
        lines << QStringLiteral("(Create policy... can scope it; nothing is applied "
                                "automatically.)");
    }
    return lines;
}

} // namespace

NetworkTreeModel::NetworkTreeModel(QObject *parent) : QAbstractItemModel(parent)
{
    // NG-040: the Activity column uses the same versioned catalog as the
    // classifier, including any local rule edits the user saved.
    EndpointCatalog catalog;
    catalog.load();
    m_activityClassifier.setCatalog(catalog);

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
            case COL_ACTIVITY: return catalogCategoryToken(p.activity.category);
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
            case COL_ACTIVITY: return p.activity.summary();
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
            const QString started = Oasis::ProcessLineage::formatStartTime(p.processStartMs);
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
                                  Oasis::groupConfidenceName(p.groupConfidence));
            }
            // NG-041: the advisory foreground association behind the Activity
            // column. It never changes or overrides a policy.
            if (p.foreground == Oasis::ForegroundAssociation::ForegroundApp) {
                lines << QStringLiteral("Foreground: active application "
                                        "(advisory, does not override policy)");
            } else if (p.foreground == Oasis::ForegroundAssociation::ForegroundChild) {
                lines << QStringLiteral("Foreground: helper of the active "
                                        "application (advisory, does not override "
                                        "policy)");
            }
            return lines.join('\n');
        }
        if (role == Qt::ToolTipRole && col == COL_ACTIVITY)
            return activityTooltip(p.activity, p.foreground).join('\n');
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
        const Oasis::ServiceEntry &s = p.services[idx.row()];
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
            lines << "State: " + Oasis::serviceStateName(s.state);
            if (!s.executablePath.isEmpty())
                lines << "Image: " + s.executablePath;
            if (p.pid) lines << QStringLiteral("Hosted by PID %1").arg(p.pid);
            if (!p.groupName.isEmpty())
                lines << QStringLiteral("Group: %1 (%2)")
                             .arg(p.groupName,
                                  Oasis::groupConfidenceName(p.groupConfidence));
            lines << (s.acceptsStop ? "Can be stopped from Services"
                                    : "Protected service (not user-stoppable)");
            lines << activityTooltip(p.activity, p.foreground);
            return lines.join('\n');
        }
        if (role == Qt::DisplayRole) {
            switch (col) {
            case COL_NAME:    return s.displayName;
            case COL_ACTIVITY:return p.activity.summary();
            case COL_SERVICE: return s.serviceName + "  —  " + Oasis::serviceStateName(s.state);
            default:          return {};
            }
        }
        if (role == Qt::ForegroundRole && col == COL_NAME
            && s.state != Oasis::ServiceState::Running)
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
        case COL_ACTIVITY: return catalogCategoryToken(p.activity.category);
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
        case COL_ACTIVITY: return p.activity.summary();
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

    if (role == Qt::ToolTipRole && col == COL_ACTIVITY) {
        // A connection row shows the classification of the process that owns
        // it, with the same matched rules and confidence as the process row.
        QStringList lines;
        lines << QStringLiteral("Owning process: %1 (PID %2)").arg(p.name).arg(p.pid);
        lines << activityTooltip(p.activity, p.foreground);
        if (!c.domain.isEmpty()) {
            lines << QStringLiteral("This connection's destination: %1 (%2)")
                         .arg(c.domain,
                              AttributionConfidenceModel::displayName(c.domainConfidence));
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
        "Application / Protocol", "Source", "Destination", "Domain", "Activity",
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

        // NG-041: the foreground sample travels with the packet. refreshActivity
        // below reclassifies when it changes; an old sample is already filtered
        // to None by the monitor, so nothing stale is inherited here.
        if (p.foreground != info.foreground) {
            p.foreground = info.foreground;
            const QModelIndex nameIdx = index(pRow, COL_NAME);
            emit dataChanged(nameIdx, nameIdx, {Qt::ToolTipRole});
        }

        // NG-040: reclassify when identity, publisher, group, service, or
        // foreground evidence changed; refreshActivity() skips unchanged
        // evidence, so this costs a string comparison per packet rather than a
        // catalog match.
        refreshActivity(pRow);

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

        // NG-041: a foreground transfer can cross the classifier's sustained-rate
        // threshold between packets. Re-evaluate only foreground rows; the
        // signature check makes this a no-op when nothing changed.
        if (p.foreground != Oasis::ForegroundAssociation::None)
            refreshActivity(pRow);

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

ActivityQuery NetworkTreeModel::activityQueryForRow(int pRow) const
{
    ActivityQuery query;
    if (pRow < 0 || pRow >= m_procs.size()) return query;

    const ProcessNode &p = m_procs[pRow];
    query.executableName = p.name;
    query.displayName = p.identityName;
    query.publisher = p.publisher;
    query.publisherVerified =
        p.signerStatus == ApplicationIdentity::SignerStatus::Signed;
    query.identityId = p.identityId;
    query.groupId = p.groupId;
    query.groupName = p.groupName;
    query.foreground = p.foreground != Oasis::ForegroundAssociation::None;
    query.bytesPerSecond = p.totalRxSpeed;
    if (!p.services.isEmpty()) {
        query.serviceName = p.services.first().serviceName;
        query.service = true;
    }
    return query;
}

ActivityClassification NetworkTreeModel::activityForRow(int pRow) const
{
    if (pRow < 0 || pRow >= m_procs.size()) return ActivityClassification();
    return m_procs[pRow].activity;
}

// NG-052: a copy of the row, taken while the caller still owns a valid index.
ProcessRowSnapshot NetworkTreeModel::snapshotForRow(int pRow) const
{
    ProcessRowSnapshot snapshot;
    if (pRow < 0 || pRow >= m_procs.size()) return snapshot;

    const ProcessNode &p = m_procs[pRow];
    snapshot.name = p.name;
    snapshot.identityId = p.identityId;
    snapshot.identityName = p.identityName;
    snapshot.publisher = p.publisher;
    snapshot.signerStatus = p.signerStatus;
    snapshot.pid = p.pid;
    snapshot.parentPid = p.parentPid;
    snapshot.processStartMs = p.processStartMs;
    snapshot.parentName = p.parentName;
    snapshot.groupId = p.groupId;
    snapshot.groupName = p.groupName;
    snapshot.groupConfidence = p.groupConfidence;
    for (const Oasis::ServiceEntry &service : p.services)
        snapshot.services << service.serviceName;
    snapshot.foreground = p.foreground;
    snapshot.query = activityQueryForRow(pRow);
    snapshot.activity = p.activity;
    snapshot.rxBytes = p.totalRxBytes;
    snapshot.txBytes = p.totalTxBytes;
    snapshot.rxBytesPerSecond = p.totalRxSpeed;
    snapshot.txBytesPerSecond = p.totalTxSpeed;
    snapshot.packets = p.totalPackets;
    snapshot.connections = p.conns;
    return snapshot;
}

int NetworkTreeModel::rowForPid(quint32 pid) const
{
    if (pid == 0) return -1;
    for (int row = 0; row < m_procs.size(); ++row) {
        if (m_procs[row].pid == pid) return row;
    }
    return -1;
}

void NetworkTreeModel::refreshActivity(int pRow)
{
    if (pRow < 0 || pRow >= m_procs.size()) return;
    ProcessNode &p = m_procs[pRow];

    QStringList signature;
    signature << p.name << p.identityId << p.identityName << p.publisher
              << p.groupId << p.groupName << QString::number(p.services.size());
    if (!p.services.isEmpty()) signature << p.services.first().serviceName;

    // NG-041: a foreground transfer only changes category when it crosses the
    // classifier's sustained-rate threshold, so the boolean is part of the
    // signature rather than the ever-changing rate itself.
    const quint64 foregroundThreshold =
        m_activityClassifier.foregroundDownloadThreshold();
    const bool foregroundDownloadEligible =
        p.foreground != Oasis::ForegroundAssociation::None
        && foregroundThreshold > 0
        && p.totalRxSpeed >= foregroundThreshold;
    signature << QString::number(static_cast<int>(p.foreground))
              << (foregroundDownloadEligible ? QStringLiteral("1")
                                             : QStringLiteral("0"));

    const QString current = signature.join(QChar('\x1f'));
    if (current == p.activitySignature) return;
    p.activitySignature = current;

    p.activity = m_activityClassifier.classify(activityQueryForRow(pRow));

    const QModelIndex idx = index(pRow, COL_ACTIVITY);
    emit dataChanged(idx, idx, {Qt::DisplayRole, Qt::ToolTipRole, Qt::UserRole + 5});

    // Service and connection rows show the owning process's classification, so
    // they refresh with it.
    const int childCount = p.services.size() + p.conns.size();
    if (childCount > 0) {
        const QModelIndex pIdx = index(pRow, 0);
        emit dataChanged(index(0, COL_ACTIVITY, pIdx),
                         index(childCount - 1, COL_ACTIVITY, pIdx),
                         {Qt::DisplayRole, Qt::ToolTipRole, Qt::UserRole + 5});
    }
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

void NetworkTreeModel::applyServiceSnapshot(const Oasis::ServicePidMap &services)
{
    m_servicesByPid = services;

    for (int pRow = 0; pRow < m_procs.size(); ++pRow) {
        ProcessNode &p = m_procs[pRow];
        if (!p.pid) continue;
        const auto hosted = m_servicesByPid.constFind(p.pid);
        const QVector<Oasis::ServiceEntry> entries =
            (hosted == m_servicesByPid.constEnd()) ? QVector<Oasis::ServiceEntry>()
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

        // NG-040: a hosted service can satisfy a catalog service criterion.
        refreshActivity(pRow);
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

