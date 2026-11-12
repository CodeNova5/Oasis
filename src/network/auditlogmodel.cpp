/**
 * @file   auditlogmodel.cpp
 * @brief  Filterable table model over the NG-050 audit event store.
 * @author Codebuff
 */

#include "auditlogmodel.h"

AuditLogModel::AuditLogModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

void AuditLogModel::setStore(AuditEventStore *store)
{
    if (m_store == store) return;
    if (m_store)
        disconnect(m_store, &AuditEventStore::changed, this, &AuditLogModel::reload);

    m_store = store;
    if (m_store)
        connect(m_store, &AuditEventStore::changed, this, &AuditLogModel::reload);

    reload();
}

void AuditLogModel::setFilters(int eventType, const QString &text, int windowHours)
{
    m_typeFilter = eventType;
    m_textFilter = text.trimmed();
    m_windowHours = windowHours > 0 ? windowHours : 0;
    reload();
}

AuditEvent AuditLogModel::eventAt(int row) const
{
    if (row < 0 || row >= m_events.size()) return AuditEvent();
    return m_events.at(row);
}

void AuditLogModel::reload()
{
    AuditQuery query;
    if (m_typeFilter >= 0)
        query.types << static_cast<AuditEvent::EventType>(m_typeFilter);
    query.text = m_textFilter;
    if (m_windowHours > 0)
        query.from = QDateTime::currentDateTime().addSecs(-m_windowHours * 3600);

    const QList<AuditEvent> events = m_store ? m_store->query(query) : QList<AuditEvent>();

    beginResetModel();
    m_events = events;
    endResetModel();
}

int AuditLogModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return m_events.size();
}

int AuditLogModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return ColumnCount;
}

QVariant AuditLogModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_events.size())
        return QVariant();

    const AuditEvent &event = m_events.at(index.row());

    if (role == TimestampRole) return event.timestamp;
    if (role == TypeRole)      return static_cast<int>(event.type);
    if (role == ScopeRole)     return event.scope;
    if (role == ReasonRole)    return event.reason;
    if (role == ResultRole)    return event.result;
    if (role == ErrorInfoRole) return event.errorInfo;
    if (role == IdentityIdRole)return event.relatedIdentityId;
    if (role == PolicyIdRole)  return event.relatedPolicyId;
    if (role == DetailsRole)   return event.details;

    if (role == Qt::ToolTipRole) {
        QStringList lines;
        lines << event.timestamp.toString(Qt::ISODateWithMs)
              << auditEventTypeName(event.type);
        if (!event.scope.isEmpty())
            lines << QStringLiteral("Scope: %1").arg(event.scope);
        if (!event.reason.isEmpty())
            lines << QStringLiteral("Reason: %1").arg(event.reason);
        if (!event.result.isEmpty())
            lines << QStringLiteral("Result: %1").arg(event.result);
        if (!event.errorInfo.isEmpty())
            lines << QStringLiteral("Error: %1").arg(event.errorInfo);
        if (!event.relatedIdentityId.isEmpty())
            lines << QStringLiteral("Identity: %1").arg(event.relatedIdentityId);
        if (!event.relatedPolicyId.isEmpty())
            lines << QStringLiteral("Policy: %1").arg(event.relatedPolicyId);
        if (!event.details.isEmpty())
            lines << QStringLiteral("Details: %1").arg(event.details);
        return lines.join(QLatin1Char('\n'));
    }

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case TimeColumn:   return event.timestamp.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        case TypeColumn:   return auditEventTypeName(event.type);
        case ScopeColumn:  return event.scope;
        case ReasonColumn: return event.reason;
        case ResultColumn: return event.result;
        case PolicyColumn: return event.relatedPolicyId;
        default: break;
        }
    }
    return QVariant();
}

QVariant AuditLogModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole) return QVariant();
    if (orientation == Qt::Vertical) return section + 1;

    switch (section) {
    case TimeColumn:   return QStringLiteral("Time");
    case TypeColumn:   return QStringLiteral("Type");
    case ScopeColumn:  return QStringLiteral("Scope");
    case ReasonColumn: return QStringLiteral("Reason");
    case ResultColumn: return QStringLiteral("Result");
    case PolicyColumn: return QStringLiteral("Policy");
    default:           return QVariant();
    }
}

QHash<int, QByteArray> AuditLogModel::roleNames() const
{
    return {
        { TimestampRole, "timestamp" },
        { TypeRole,      "type" },
        { ScopeRole,     "scope" },
        { ReasonRole,    "reason" },
        { ResultRole,    "result" },
        { ErrorInfoRole, "errorInfo" },
        { IdentityIdRole,"identityId" },
        { PolicyIdRole,  "policyId" },
        { DetailsRole,   "details" }
    };
}
