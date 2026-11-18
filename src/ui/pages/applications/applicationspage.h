/**
 * @file    applicationspage.h
 * @brief   Screen 03 — Applications (SCREENS_SPEC.md): every application the
 *          shell has seen, with its publisher, live status and per-app rule.
 *
 * The page is pure presentation. MainWindow hands it a list of rows once per
 * one-second beat; it owns search, filtering, sorting and the rule control, and
 * never queries the capture layer or applies enforcement itself.
 *
 * @author  Oasis
 */
#pragma once

#include <QIcon>
#include <QList>
#include <QStringList>
#include <QModelIndex>
#include <QPoint>
#include <QString>
#include <QWidget>

#include "network/applicationsnapshot.h"

class QAction;
class QFrame;
class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;
class QTableView;
class QVBoxLayout;
class EmptyStateWidget;
class ApplicationsPageTableModel;
class ApplicationsPageFilterModel;

namespace Applications {

enum class Filter {
    All = 0,
    Active,
    Idle,
    AllowRule,
    AskRule,
    BlockRule
};

/// A display-ready application row. All formatting decisions stay on this side
/// of the boundary so the page does not need to know how evidence is gathered.
struct Row
{
    quint32 pid = 0;
    QIcon icon;            // executable icon, empty until resolved
    QString name;          // executable, e.g. "chrome.exe"
    QString displayName;   // friendly identity, empty when unresolved
    QString publisher;     // empty when no verified signer is known
    QString path;          // executable path, empty when unresolved

    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
    quint64 totalBytes = 0;

    QString activity;      // "Foreground", "Background" or "System"
    QString policy;        // "None", "Throttle (Active)", "Block (Active)"
    QString policyToken;   // "none", "restricted" or "blocked"
    QString identity;      // "Confirmed", "Likely", "Possible", "Unknown"
    QString rule;          // "allow", "ask" or "block"
};

QString filterLabel(Filter filter);

} // namespace Applications

class ApplicationsPage : public QWidget
{
    Q_OBJECT

public:
    explicit ApplicationsPage(QWidget *parent = nullptr);

    /// Replaces the table contents. Selection and scroll position survive a
    /// beat when the selected application is still present.
    void setRows(const QList<Applications::Row> &rows);

    /// Opens (or refreshes) the right-side details drawer for one application.
    void showDetails(const Applications::Details &details);

    /// Search, filter, sort and overflow controls; the shell hosts these in the
    /// page header so the title and table share the mock's vertical rhythm.
    QWidget *actionsWidget() const { return m_actionsWidget; }

signals:
    /// Every action is performed by the shell through an existing entry point;
    /// the page only says which application the action targets.
    void detailsRequested(quint32 pid, const QString &path, const QString &name);
    void trafficRequested(quint32 pid, const QString &path, const QString &name);
    void policyRequested(quint32 pid, const QString &path, const QString &name);
    void activityRequested(quint32 pid, const QString &path, const QString &name);
    void ruleChangeRequested(quint32 pid, const QString &path, const QString &name,
                             const QString &rule);
    void policiesRequested();

private:
    void applyFilter(Applications::Filter filter);
    void applyQuery(const QString &query);
    void refreshEmptyState();
    void refreshFooter();
    void refreshThemeIcons();
    void showFilterMenu();
    void showSortMenu();
    void showMoreMenu();
    void showRuleMenu(const QModelIndex &index);
    void showRuleMenuFor(quint32 pid, const QString &path, const QString &name,
                         const QString &rule, const QPoint &globalPos);
    void showContextMenu(const QPoint &pos);
    /// Opens the details drawer for the row behind a proxy index.
    void openDetailsAt(const QModelIndex &index);
    void closeDetails();
    void populateDetails();
    void applyDetailsRule(const QString &rule);
    QWidget *buildDrawer();
    QWidget *buildDetailsTab();
    QWidget *buildConnectionsTab();
    QWidget *buildRulesTab();
    /// Copies the row behind a proxy index. False when the index is not a row.
    bool rowForIndex(const QModelIndex &index, Applications::Row *row) const;

    QWidget *m_actionsWidget = nullptr;
    QLineEdit *m_search = nullptr;
    QAction *m_searchAction = nullptr;
    QPushButton *m_filterButton = nullptr;
    QPushButton *m_sortButton = nullptr;
    QPushButton *m_moreButton = nullptr;
    QTableView *m_table = nullptr;

    // Right-side details drawer (Screen 03, "Details drawer").
    QFrame *m_drawer = nullptr;
    QTabWidget *m_drawerTabs = nullptr;
    QLabel *m_drawerIcon = nullptr;
    QLabel *m_drawerName = nullptr;
    QLabel *m_drawerPublisher = nullptr;
    QLabel *m_drawerVersion = nullptr;
    QLabel *m_drawerInstalled = nullptr;
    QLabel *m_drawerPath = nullptr;
    QPushButton *m_drawerRuleButton = nullptr;
    QPushButton *m_rulesRuleButton = nullptr;
    QLabel *m_ruleHint = nullptr;
    QLabel *m_rulesDescription = nullptr;
    QLabel *m_sessionUploaded = nullptr;
    QLabel *m_sessionDownloaded = nullptr;
    QLabel *m_sessionTotal = nullptr;
    QLabel *m_weekUploaded = nullptr;
    QLabel *m_weekDownloaded = nullptr;
    QLabel *m_weekTotal = nullptr;
    QLabel *m_lastActive = nullptr;
    QLabel *m_lastConnections = nullptr;
    QLabel *m_lastRemoteAddresses = nullptr;
    QVBoxLayout *m_connectionsLayout = nullptr;
    QLabel *m_connectionsEmpty = nullptr;
    Applications::Details m_details;
    bool m_detailsOpen = false;
    QWidget *m_emptyHost = nullptr;
    EmptyStateWidget *m_empty = nullptr;
    QWidget *m_footer = nullptr;
    QLabel *m_footerCount = nullptr;
    QLabel *m_legend = nullptr;

    ApplicationsPageTableModel *m_model = nullptr;
    ApplicationsPageFilterModel *m_proxy = nullptr;

    QList<Applications::Row> m_rows;
    Applications::Filter m_filter = Applications::Filter::All;
};
