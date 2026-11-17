/**
 * @file    connectionspage.h
 * @brief   Screen 05 — Connections (SCREENS_SPEC.md).
 *
 * A pure presentation layer over the grouped connection snapshots the network
 * layer produces once per beat. The page renders the KPI row, the filter
 * toolbar, the expandable grouped table and the connection inspector; it never
 * captures packets, resolves names, or applies a policy itself. Actions are
 * routed back to the shell through signals so the existing application/policy
 * flows remain the only enforcement path.
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

class ConnectionsTable;
class EmptyStateWidget;
class FilterPill;
class MetricTile;
class QAction;
class QButtonGroup;
class QFrame;
class QLabel;
class QLineEdit;
class QPushButton;
class QResizeEvent;
class QScrollArea;
class QStackedWidget;
class QVBoxLayout;

class ConnectionsPage : public QWidget
{
    Q_OBJECT

public:
    explicit ConnectionsPage(QWidget *parent = nullptr);

    /// Replaces the table contents. Expansion, selection and scroll position
    /// survive a beat while the same groups are still present.
    void setGroups(const QList<Connections::Row> &groups);

    /// Capture state decides the empty-state wording; it never fakes rows.
    void setMonitoringActive(bool active);

    /// The Export control, hosted by the shell in the page header.
    QWidget *actionsWidget() const { return m_actionsWidget; }

signals:
    /// Ask the host to re-resolve destination evidence and rebuild the beat.
    void refreshRequested();
    /// Every action reuses an existing NetworkWidget entry point.
    void detailsRequested(quint32 pid, const QString &path, const QString &name);
    void trafficRequested(quint32 pid, const QString &path, const QString &name);

protected:
    void resizeEvent(QResizeEvent *event) override;

private:
    enum class TimeRange { Live, OneMinute, FiveMinutes, FifteenMinutes, OneHour };

    struct ObservedRow
    {
        Connections::Row row;
        qint64 lastSeenMs = 0;
    };

    void buildMetrics(QVBoxLayout *root);
    void buildToolbar(QVBoxLayout *root);
    void buildTable(QVBoxLayout *root);
    void buildInspector();

    void setFilter(Connections::Filter filter);
    void clearFilters();
    void setTimeRange(TimeRange range);
    void rebuildVisibleRows();
    static QString timeRangeLabel(TimeRange range);
    static qint64 timeRangeWindowMs(TimeRange range);
    void applyFilters();
    void refreshMetrics();
    void refreshPills();
    void refreshEmptyState();
    void refreshTheme();

    void openInspector(const QString &id);
    void closeInspector();
    void renderInspector();
    void onSelectionChanged(const QString &id);

    void exportVisibleRows();

    const Connections::Row *rowForId(const QString &id) const;

    QWidget     *m_actionsWidget = nullptr;
    QPushButton *m_exportButton = nullptr;

    MetricTile  *m_activeTile = nullptr;
    MetricTile  *m_blockedTile = nullptr;
    MetricTile  *m_outboundTile = nullptr;
    MetricTile  *m_inboundTile = nullptr;
    MetricTile  *m_unknownTile = nullptr;

    QLineEdit    *m_search = nullptr;
    QAction      *m_searchAction = nullptr;
    QFrame       *m_pillHost = nullptr;
    QButtonGroup *m_pillGroup = nullptr;
    FilterPill   *m_pillAll = nullptr;
    FilterPill   *m_pillOutbound = nullptr;
    FilterPill   *m_pillInbound = nullptr;
    FilterPill   *m_pillBlocked = nullptr;
    FilterPill   *m_pillUnknown = nullptr;
    QPushButton  *m_groupButton = nullptr;
    QPushButton  *m_rangeButton = nullptr;

    QStackedWidget *m_stack = nullptr;
    ConnectionsTable *m_table = nullptr;
    EmptyStateWidget *m_empty = nullptr;
    bool m_emptyFiltered = false;

    QFrame      *m_inspector = nullptr;
    QLabel      *m_inspectorTitle = nullptr;
    QLabel      *m_inspectorSubtitle = nullptr;
    QScrollArea *m_inspectorScroll = nullptr;
    QVBoxLayout *m_inspectorBody = nullptr;
    QString      m_inspectorId;

    QList<Connections::Row> m_rows;
    QList<Connections::Row> m_filtered;
    QSet<QString> m_seenEndpoints;
    QHash<QString, ObservedRow> m_history;
    QSet<QString> m_liveIds;

    Connections::Filter m_filter = Connections::Filter::All;
    TimeRange m_timeRange = TimeRange::FiveMinutes;
    QString m_query;
    QString m_selectedId;
    bool m_monitoringActive = false;
};
