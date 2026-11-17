/**
 * @file    connectionspage.h
 * @brief   Screen 05 — Connections (SCREENS_SPEC.md).
 *
 * A pure presentation layer over the grouped connection snapshots the network
 * layer produces once per beat. The page owns search, filtering, sorting and
 * the evidence drawer; it never captures packets, resolves names, or applies a
 * policy itself. Actions are routed back to the shell through signals so the
 * existing application/policy flows remain the only enforcement path.
 *
 * @author  Oasis
 */
#pragma once

#include <QString>
#include <QWidget>

#include "network/connectionsnapshot.h"

class QButtonGroup;
class QComboBox;
class QFrame;
class QGridLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QStackedWidget;
class QTableView;
class QToolButton;
class QVBoxLayout;
class ConnectionsFilterProxy;
class ConnectionsTableModel;
class EmptyStateWidget;

class ConnectionsPage : public QWidget
{
    Q_OBJECT

public:
    explicit ConnectionsPage(QWidget *parent = nullptr);

    /// Replaces the table contents. Selection survives a beat when the selected
    /// application + destination is still present.
    void setGroups(const QList<Connections::Row> &groups);

    /// Capture state decides the empty-state wording; it never fakes rows.
    void setMonitoringActive(bool active);

signals:
    /// Ask the host to re-resolve destination evidence and rebuild the beat.
    void refreshRequested();
    /// Every action reuses an existing NetworkWidget entry point.
    void detailsRequested(quint32 pid, const QString &path, const QString &name);
    void trafficRequested(quint32 pid, const QString &path, const QString &name);
    void policyRequested(quint32 pid, const QString &path, const QString &name);

private:
    void buildToolbar(QVBoxLayout *root);
    void buildTable(QVBoxLayout *root);
    void buildDrawer(QWidget *parent);
    void buildBanner(QVBoxLayout *root);

    void setFilter(Connections::Filter filter);
    void clearFilters();
    void applyFilters();
    void refreshPills();
    void refreshBanner();
    void refreshFooter();
    void refreshEmptyState();

    void showRow(const Connections::Row &row);
    void clearDrawer();
    void refreshDrawerActions();

    QString selectedId() const;
    void selectGroup(const QString &id);

    QFrame      *m_banner = nullptr;
    QLabel      *m_bannerText = nullptr;
    QPushButton *m_bannerAction = nullptr;

    QLineEdit   *m_search = nullptr;
    QButtonGroup *m_pillGroup = nullptr;
    QComboBox   *m_source = nullptr;
    QPushButton *m_refreshButton = nullptr;

    QStackedWidget *m_stack = nullptr;
    QFrame         *m_tableCard = nullptr;
    QTableView     *m_table = nullptr;
    QLabel         *m_footerCount = nullptr;
    QLabel         *m_footerNote = nullptr;
    EmptyStateWidget *m_empty = nullptr;
    bool            m_emptyFiltered = false;

    QFrame      *m_drawer = nullptr;
    QLabel      *m_drawerTitle = nullptr;
    QLabel      *m_drawerBadge = nullptr;
    QLabel      *m_appIcon = nullptr;
    QLabel      *m_appName = nullptr;
    QLabel      *m_appMeta = nullptr;
    QLabel      *m_hostValue = nullptr;
    QLabel      *m_addressesValue = nullptr;
    QLabel      *m_portsValue = nullptr;
    QLabel      *m_directionValue = nullptr;
    QLabel      *m_evidenceTitle = nullptr;
    QLabel      *m_evidenceDetail = nullptr;
    QLabel      *m_rateValue = nullptr;
    QLabel      *m_dataValue = nullptr;
    QLabel      *m_downloadValue = nullptr;
    QLabel      *m_uploadValue = nullptr;
    QLabel      *m_packetsValue = nullptr;
    QLabel      *m_endpointValue = nullptr;
    QVBoxLayout *m_endpointsLayout = nullptr;
    QLabel      *m_policyNote = nullptr;
    QPushButton *m_trafficButton = nullptr;
    QPushButton *m_detailsButton = nullptr;
    QPushButton *m_policyButton = nullptr;

    ConnectionsTableModel *m_model = nullptr;
    ConnectionsFilterProxy *m_proxy = nullptr;

    QList<Connections::Row> m_groups;
    Connections::Filter m_filter = Connections::Filter::All;
    bool m_monitoringActive = false;
    bool m_hasSelection = false;
    Connections::Row m_selected;
};
