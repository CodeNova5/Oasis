/**
 * @file   diagnostics.cpp
 * @brief  Diagnostics for capture gaps (dropped packets, unresolved PIDs, unknown direction, stale mappings, unavailable adapters) - NG-003.
 * @author Codebuff
 */

#include "diagnostics.h"

#include <QDebug>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace {

QString dropReasonName(PacketDropReason reason)
{
    switch (reason) {
    case PacketDropReason::None:                   return QStringLiteral("None");
    case PacketDropReason::BufferOverflow:         return QStringLiteral("BufferOverflow");
    case PacketDropReason::SocketError:            return QStringLiteral("SocketError");
    case PacketDropReason::InvalidChecksum:        return QStringLiteral("InvalidChecksum");
    case PacketDropReason::TooLarge:               return QStringLiteral("TooLarge");
    case PacketDropReason::PromiscuousModeDisabled:return QStringLiteral("PromiscuousModeDisabled");
    case PacketDropReason::NotPromiscuous:         return QStringLiteral("NotPromiscuous");
    case PacketDropReason::OutOfMemory:            return QStringLiteral("OutOfMemory");
    case PacketDropReason::Other:                  return QStringLiteral("Other");
    }
    return QStringLiteral("Other");
}

QString pidStatusName(PidResolutionStatus status)
{
    switch (status) {
    case PidResolutionStatus::Resolved:        return QStringLiteral("Resolved");
    case PidResolutionStatus::Unresolved:      return QStringLiteral("Unresolved");
    case PidResolutionStatus::ServiceHost:     return QStringLiteral("ServiceHost");
    case PidResolutionStatus::KernelMode:      return QStringLiteral("KernelMode");
    case PidResolutionStatus::PermissionDenied:return QStringLiteral("PermissionDenied");
    case PidResolutionStatus::ProcessNotFound: return QStringLiteral("ProcessNotFound");
    case PidResolutionStatus::PidReuse:        return QStringLiteral("PidReuse");
    case PidResolutionStatus::Other:           return QStringLiteral("Other");
    }
    return QStringLiteral("Other");
}

QString directionStatusName(DirectionStatus status)
{
    switch (status) {
    case DirectionStatus::DirectionKnown:  return QStringLiteral("DirectionKnown");
    case DirectionStatus::UnknownDirection:return QStringLiteral("UnknownDirection");
    case DirectionStatus::LocalOnly:       return QStringLiteral("LocalOnly");
    case DirectionStatus::ExternalOnly:    return QStringLiteral("ExternalOnly");
    case DirectionStatus::Loopback:        return QStringLiteral("Loopback");
    case DirectionStatus::Other:           return QStringLiteral("Other");
    }
    return QStringLiteral("Other");
}

QString adapterStatusName(AdapterStatus status)
{
    switch (status) {
    case AdapterStatus::AdapterAvailable:    return QStringLiteral("AdapterAvailable");
    case AdapterStatus::AdapterUnavailable:  return QStringLiteral("AdapterUnavailable");
    case AdapterStatus::AdapterMissingDriver:return QStringLiteral("AdapterMissingDriver");
    case AdapterStatus::AdministratorRequired:return QStringLiteral("AdministratorRequired");
    case AdapterStatus::NoSuitableAdapter:   return QStringLiteral("NoSuitableAdapter");
    case AdapterStatus::Other:               return QStringLiteral("Other");
    }
    return QStringLiteral("Other");
}

QString mappingStatusName(MappingStatus status)
{
    switch (status) {
    case MappingStatus::Fresh:         return QStringLiteral("Fresh");
    case MappingStatus::StaleMapping:  return QStringLiteral("StaleMapping");
    case MappingStatus::MissingMapping:return QStringLiteral("MissingMapping");
    }
    return QStringLiteral("Fresh");
}

// Short category shown in the support view's Type column.
QString categoryName(const DiagnosticRecord &rec)
{
    if (rec.dropReason != PacketDropReason::None)                     return QStringLiteral("Dropped packets");
    if (rec.pidStatus == PidResolutionStatus::PidReuse)               return QStringLiteral("PID reuse");
    if (rec.pidStatus != PidResolutionStatus::Resolved)               return QStringLiteral("Unresolved PID");
    if (rec.directionStatus != DirectionStatus::DirectionKnown)       return QStringLiteral("Unknown direction");
    if (rec.mappingStatus != MappingStatus::Fresh)                    return QStringLiteral("Stale mapping");
    if (rec.adapterStatus != AdapterStatus::AdapterAvailable)         return QStringLiteral("Adapter");
    return QStringLiteral("Info");
}

} // namespace

DiagnosticsModel::DiagnosticsModel(QObject *parent) : QAbstractListModel(parent)
{
}

int DiagnosticsModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return m_records.size();
}

int DiagnosticsModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return 4; // Time | Type | Details | Context
}

QVariant DiagnosticsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_records.size())
        return QVariant();

    const DiagnosticRecord &rec = m_records[index.row()];
    const int column = index.column();

    if (role == Qt::DisplayRole) {
        switch (column) {
        case 0: return rec.timestamp.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        case 1: return categoryName(rec);
        case 2: return rec.details;
        case 3: return rec.context;
        default: return QVariant();
        }
    }
    if (role == Qt::ToolTipRole && column == 2)
        return rec.context.isEmpty() ? rec.details : rec.details + QStringLiteral("\n") + rec.context;

    switch (role) {
    case RoleTimestamp:       return rec.timestamp;
    case RoleDropReason:      return static_cast<int>(rec.dropReason);
    case RolePidStatus:       return static_cast<int>(rec.pidStatus);
    case RoleDirectionStatus: return static_cast<int>(rec.directionStatus);
    case RoleAdapterStatus:   return static_cast<int>(rec.adapterStatus);
    case RoleMappingStatus:   return static_cast<int>(rec.mappingStatus);
    case RoleDetails:         return rec.details;
    case RoleContext:         return rec.context;
    case RoleAffectedPid:     return rec.affectedPid;
    case RoleAffectedProcess: return rec.affectedProcess;
    default:                  return QVariant();
    }
}

QVariant DiagnosticsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QAbstractListModel::headerData(section, orientation, role);

    switch (section) {
    case 0: return QStringLiteral("Time");
    case 1: return QStringLiteral("Type");
    case 2: return QStringLiteral("Details");
    case 3: return QStringLiteral("Context");
    default: return QVariant();
    }
}

QHash<int, QByteArray> DiagnosticsModel::roleNames() const
{
    QHash<int, QByteArray> roles;
    roles[RoleTimestamp]         = "timestamp";
    roles[RoleDropReason]        = "dropReason";
    roles[RolePidStatus]         = "pidStatus";
    roles[RoleDirectionStatus]   = "directionStatus";
    roles[RoleAdapterStatus]     = "adapterStatus";
    roles[RoleMappingStatus]     = "mappingStatus";
    roles[RoleDetails]           = "details";
    roles[RoleContext]           = "context";
    roles[RoleAffectedPid]       = "affectedPid";
    roles[RoleAffectedProcess]   = "affectedProcess";
    return roles;
}

void DiagnosticsModel::addRecord(const DiagnosticRecord &record)
{
    // Bound memory: evict the oldest record when the cap is reached.
    if (m_records.size() >= MaxRecords) {
        beginRemoveRows(QModelIndex(), 0, 0);
        m_records.removeFirst();
        endRemoveRows();
    }

    const int row = m_records.size();
    beginInsertRows(QModelIndex(), row, row);
    m_records.append(record);
    endInsertRows();
    emit recordAdded(record);
    emit modelUpdated();
}

void DiagnosticsModel::clear()
{
    beginResetModel();
    m_records.clear();
    endResetModel();
    emit modelUpdated();
}

void DiagnosticsModel::reportDroppedPackets(int count, const QString &adapter, const QString &context)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.dropReason = PacketDropReason::BufferOverflow;  // generic, could be enhanced
    rec.details = QStringLiteral("%1 packets dropped from %2").arg(count).arg(adapter);
    rec.context = context;
    addRecord(rec);
}

void DiagnosticsModel::reportUnresolvedPid(quint32 pid, const QString &processName, const QString &context)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.pidStatus = PidResolutionStatus::Unresolved;
    rec.details = QStringLiteral("PID %1 resolution failed").arg(pid);
    rec.context = context;
    rec.affectedPid = pid;
    rec.affectedProcess = processName;
    addRecord(rec);
}

void DiagnosticsModel::reportUnknownDirection(const QString &packetSummary, const QString &context)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.directionStatus = DirectionStatus::UnknownDirection;
    rec.details = packetSummary;
    rec.context = context;
    addRecord(rec);
}

void DiagnosticsModel::reportStaleMapping(quint32 pid, const QString &expected, const QString &actual, const QString &context)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.mappingStatus = MappingStatus::StaleMapping;
    rec.details = QStringLiteral("Stale PID mapping: expected %1, got %2").arg(expected, actual);
    rec.context = context;
    rec.affectedPid = pid;
    addRecord(rec);
}

void DiagnosticsModel::reportServiceLookupFailed(quint32 pid, const QString &serviceName,
                                                 const QString &reason)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.pidStatus = PidResolutionStatus::ServiceHost;
    rec.details = reason;
    rec.context = serviceName.isEmpty()
        ? QStringLiteral("service resolution")
        : QStringLiteral("service: %1").arg(serviceName);
    rec.affectedPid = pid;
    addRecord(rec);
}

void DiagnosticsModel::reportPidReuse(quint32 pid, const QString &previousProcess,
                                      const QString &currentProcess, qint64 previousStartMs,
                                      qint64 currentStartMs)
{
    const auto describe = [](const QString &name, qint64 startMs) {
        const QString label = name.isEmpty() ? QStringLiteral("(unknown)") : name;
        if (startMs <= 0) return label;
        return label + QStringLiteral(" (started ")
            + QDateTime::fromMSecsSinceEpoch(startMs).toString(Qt::ISODate) + QLatin1Char(')');
    };

    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.pidStatus = PidResolutionStatus::PidReuse;
    rec.details = QStringLiteral("PID %1 was reused: %2 replaced by %3; cached attribution discarded")
                      .arg(pid)
                      .arg(describe(previousProcess, previousStartMs),
                           describe(currentProcess, currentStartMs));
    rec.context = QStringLiteral("process lineage");
    rec.affectedPid = pid;
    rec.affectedProcess = currentProcess;
    addRecord(rec);
}

void DiagnosticsModel::reportAdapterUnavailable(const QString &adapterName, const QString &reason)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.adapterStatus = AdapterStatus::AdapterUnavailable;
    rec.details = reason;
    rec.context = QStringLiteral("adapter: %1").arg(adapterName);
    addRecord(rec);
}

int DiagnosticsModel::droppedPacketsCount() const
{
    int count = 0;
    for (const auto &rec : m_records)
        if (rec.dropReason != PacketDropReason::None)
            ++count;
    return count;
}

int DiagnosticsModel::unresolvedPidsCount() const
{
    int count = 0;
    for (const auto &rec : m_records)
        if (rec.pidStatus == PidResolutionStatus::Unresolved)
            ++count;
    return count;
}

int DiagnosticsModel::pidReusesCount() const
{
    int count = 0;
    for (const auto &rec : m_records)
        if (rec.pidStatus == PidResolutionStatus::PidReuse)
            ++count;
    return count;
}

int DiagnosticsModel::unknownDirectionCount() const
{
    int count = 0;
    for (const auto &rec : m_records)
        if (rec.directionStatus == DirectionStatus::UnknownDirection)
            ++count;
    return count;
}

int DiagnosticsModel::staleMappingsCount() const
{
    int count = 0;
    for (const auto &rec : m_records)
        if (rec.mappingStatus != MappingStatus::Fresh)
            ++count;
    return count;
}

int DiagnosticsModel::adapterUnavailableCount() const
{
    int count = 0;
    for (const auto &rec : m_records)
        if (rec.adapterStatus != AdapterStatus::AdapterAvailable)
            ++count;
    return count;
}

QList<DiagnosticRecord> DiagnosticsModel::records() const
{
    return m_records;
}

QString DiagnosticsModel::toJson() const
{
    QJsonObject summary;
    summary[QStringLiteral("records")]            = m_records.size();
    summary[QStringLiteral("droppedPackets")]     = droppedPacketsCount();
    summary[QStringLiteral("unresolvedPids")]      = unresolvedPidsCount();
    summary[QStringLiteral("unknownDirections")]   = unknownDirectionCount();
    summary[QStringLiteral("staleMappings")]       = staleMappingsCount();
    summary[QStringLiteral("pidReuses")]           = pidReusesCount();
    summary[QStringLiteral("adapterUnavailable")]  = adapterUnavailableCount();

    QJsonArray records;
    for (const auto &rec : m_records) {
        QJsonObject obj;
        obj[QStringLiteral("timestamp")]        = rec.timestamp.toString(Qt::ISODateWithMs);
        obj[QStringLiteral("dropReason")]       = dropReasonName(rec.dropReason);
        obj[QStringLiteral("pidStatus")]        = pidStatusName(rec.pidStatus);
        obj[QStringLiteral("directionStatus")]  = directionStatusName(rec.directionStatus);
        obj[QStringLiteral("adapterStatus")]    = adapterStatusName(rec.adapterStatus);
        obj[QStringLiteral("mappingStatus")]    = mappingStatusName(rec.mappingStatus);
        obj[QStringLiteral("details")]          = rec.details;
        obj[QStringLiteral("context")]          = rec.context;
        obj[QStringLiteral("affectedPid")]      = static_cast<qint64>(rec.affectedPid);
        obj[QStringLiteral("affectedProcess")]  = rec.affectedProcess;
        records.append(obj);
    }

    QJsonObject root;
    root[QStringLiteral("schemaVersion")] = 1;
    root[QStringLiteral("exportedAt")]     = QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
    root[QStringLiteral("summary")]        = summary;
    root[QStringLiteral("records")]        = records;

    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}
