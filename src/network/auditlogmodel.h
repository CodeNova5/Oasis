/**
 * @file   auditlogmodel.h
 * @brief  Filterable table model over the NG-050 audit event store, used by
 *         the audit log view and its JSON export.
 * @author Codebuff
 *
 * The model owns no events: it asks the store for a filtered snapshot, so it
 * can never drift from the persisted log or keep a second copy alive. A filter
 * is the event type, a case-insensitive text match (scope, reason, result,
 * error text, or details), and a time window. The store's `changed` signal
 * reloads the model, so a new enforcement outcome appears without polling.
 */

#pragma once

#include <QAbstractTableModel>
#include <QList>
#include <QString>

#include "network/auditeventstore.h"

class AuditLogModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    enum Column {
        TimeColumn = 0,
        TypeColumn,
        ScopeColumn,
        ReasonColumn,
        ResultColumn,
        PolicyColumn,
        ColumnCount
    };

    enum Role {
        TimestampRole = Qt::UserRole,
        TypeRole,
        ScopeRole,
        ReasonRole,
        ResultRole,
        ErrorInfoRole,
        IdentityIdRole,
        PolicyIdRole,
        DetailsRole
    };

    explicit AuditLogModel(QObject *parent = nullptr);

    // The store is not owned. Replaces any previous store and reloads.
    void setStore(AuditEventStore *store);
    AuditEventStore *store() const { return m_store; }

    // -1 = every type, 0 = no time bound, text empty = no text filter. All
    // values are applied in one pass so the view is reset once.
    void setFilters(int eventType, const QString &text, int windowHours);
    int typeFilter() const { return m_typeFilter; }
    QString textFilter() const { return m_textFilter; }
    int windowHours() const { return m_windowHours; }

    // Snapshot currently shown, in chronological order (this is what export copies).
    QList<AuditEvent> visibleEvents() const { return m_events; }
    // The event behind a visible row, or a default event when out of range.
    AuditEvent eventAt(int row) const;

    // Re-runs the query against the store.
    void reload();

    // QAbstractTableModel
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

private:
    AuditEventStore *m_store = nullptr;
    QList<AuditEvent> m_events;
    int m_typeFilter = -1;
    QString m_textFilter;
    int m_windowHours = 0;
};
