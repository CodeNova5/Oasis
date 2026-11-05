/**
 * @file   diagnostics.cpp
 * @brief  Diagnostics for capture gaps (dropped packets, unresolved PIDs, unknown direction, stale mappings, unavailable adapters) - NG-003.
 * @author Codebuff
 */

#include "diagnostics.h"

#include <QDebug>

DiagnosticsModel::DiagnosticsModel(QObject *parent) : QAbstractListModel(parent)
{
}

int DiagnosticsModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return m_records.size();
}

QVariant DiagnosticsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_records.size())
        return QVariant();

    const DiagnosticRecord &rec = m_records[index.row()];

    switch (role) {
    case RoleTimestamp:       return rec.timestamp;
    case RoleDropReason:      return static_cast<int>(rec.dropReason);
    case RolePidStatus:       return static_cast<int>(rec.pidStatus);
    case RoleDirectionStatus: return static_cast<int>(rec.directionStatus);
    case RoleAdapterStatus:   return static_cast<int>(rec.adapterStatus);
    case RoleDetails:         return rec.details;
    case RoleContext:         return rec.context;
    case RoleAffectedPid:     return rec.affectedPid;
    case RoleAffectedProcess: return rec.affectedProcess;
    default:                  return QVariant();
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
    roles[RoleDetails]           = "details";
    roles[RoleContext]           = "context";
    roles[RoleAffectedPid]       = "affectedPid";
    roles[RoleAffectedProcess]   = "affectedProcess";
    return roles;
}

void DiagnosticsModel::addRecord(const DiagnosticRecord &record)
{
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
}

void DiagnosticsModel::reportDroppedPackets(int count, const QString &adapter, const QString &context)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.dropReason = PacketDropReason::BufferOverflow;  // generic, could be enhanced
    rec.details = QString("%1 packets dropped from %2").arg(count).arg(adapter);
    rec.context = context;
    addRecord(rec);
}

void DiagnosticsModel::reportUnresolvedPid(quint32 pid, const QString &processName, const QString &context)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.pidStatus = PidResolutionStatus::Unresolved;
    rec.details = QString("PID %1 resolution failed").arg(pid);
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
    rec.details = QString("Stale PID mapping: expected %1, got %2").arg(expected, actual);
    rec.context = context;
    rec.affectedPid = pid;
    addRecord(rec);
}

void DiagnosticsModel::reportAdapterUnavailable(const QString &adapterName, const QString &reason)
{
    DiagnosticRecord rec;
    rec.timestamp = QDateTime::currentDateTime();
    rec.adapterStatus = AdapterStatus::AdapterUnavailable;
    rec.details = reason;
    rec.context = QString("adapter: %1").arg(adapterName);
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

int DiagnosticsModel::unknownDirectionCount() const
{
    int count = 0;
    for (const auto &rec : m_records)
        if (rec.directionStatus == DirectionStatus::UnknownDirection)
            ++count;
    return count;
}

QList<DiagnosticRecord> DiagnosticsModel::records() const
{
    return m_records;
}
