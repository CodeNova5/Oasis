/**
 * @file    connectionstable.h
 * @brief   Grouped, expandable Connections table: one row per application and
 *          destination, with the observed sockets revealed underneath.
 *
 * The mock draws multi-line cells, tinted policy badges, direction chips and a
 * hover-only inspect action, so the table paints its rows directly instead of
 * pushing them through item delegates. The widget is presentation-only; it
 * emits the identity of the row the user selected or asked to inspect.
 *
 * @author  Oasis
 */
#pragma once

#include <QHash>
#include <QList>
#include <QSet>
#include <QString>
#include <QWidget>

#include "network/connectionsnapshot.h"

class QScrollArea;

class ConnectionsTable : public QWidget
{
    Q_OBJECT

public:
    explicit ConnectionsTable(QWidget *parent = nullptr);

    /// Replaces the rows. Expansion survives a beat when the group is still
    /// present; selection survives when the same identity is still visible.
    void setRows(const QList<Connections::Row> &rows);

    /// Rows that are no longer in the live capture, with the moment each was
    /// last observed. They stay in the table for the page's time window and are
    /// painted as closed rather than passed off as active.
    void setClosedAt(const QHash<QString, qint64> &closedAt);

    QString selectedId() const { return m_selectedId; }
    void selectId(const QString &id);
    void clearSelection();

signals:
    void selectionChanged(const QString &id);
    void inspectRequested(const QString &id);

protected:
    void paintEvent(QPaintEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    friend class ConnectionsTableHeader;
    friend class ConnectionsTableBody;

    enum class SortKey { Application, Destination, Port, Policy, Traffic };

    struct FlatRow {
        int row = -1;
        int endpoint = -1; // -1 when this is the group row itself
        int y = 0;
        int height = 0;
    };

    void setSortKey(SortKey key);
    void applySort();
    QList<FlatRow> buildFlatRows() const;
    void rebuildBody();
    void toggleExpanded(const QString &id);
    bool isExpanded(const QString &id) const { return m_expanded.contains(id); }

    QScrollArea *m_scroll = nullptr;
    QWidget *m_header = nullptr;
    QWidget *m_body = nullptr;

    QList<Connections::Row> m_rows;
    QHash<QString, qint64> m_closedAt;
    QSet<QString> m_expanded;
    SortKey m_sortKey = SortKey::Traffic;
    Qt::SortOrder m_sortOrder = Qt::DescendingOrder;
    QString m_selectedId;
    bool m_autoExpanded = false;
};
