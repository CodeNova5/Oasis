/**
 * @file    applicationspage.h
 * @brief   Screen 03 — Applications (SCREENS_SPEC.md): every application the
 *          shell has seen, with publisher, live rates, activity class, policy
 *          state and identity confidence.
 *
 * The page is pure presentation. MainWindow hands it a list of rows once per
 * one-second beat; it owns search, filtering and sorting, and never queries the
 * capture layer or applies enforcement.
 *
 * @author  Oasis
 */
#pragma once

#include <QIcon>
#include <QList>
#include <QModelIndex>
#include <QPoint>
#include <QString>
#include <QWidget>

class QLabel;
class QLineEdit;
class QTableView;
class QToolButton;
class QWidget;
class EmptyStateWidget;
class ApplicationsPageTableModel;
class ApplicationsPageFilterModel;

namespace Applications {

enum class Filter {
    All = 0,
    Active,
    Background,
    SystemServices,
    Restricted,
    Unresolved
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
};

struct Counts
{
    int all = 0;
    int active = 0;
    int background = 0;
    int systemServices = 0;
    int restricted = 0;
    int unresolved = 0;
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

    int applicationCount() const;
    int visibleApplicationCount() const;

signals:
    /// Every action is performed by the shell through an existing entry point;
    /// the page only says which application the action targets.
    void detailsRequested(quint32 pid, const QString &path, const QString &name);
    void trafficRequested(quint32 pid, const QString &path, const QString &name);
    void policyRequested(quint32 pid, const QString &path, const QString &name);
    void activityRequested(quint32 pid, const QString &path, const QString &name);

private:
    void applyFilter(Applications::Filter filter);
    void applyQuery(const QString &query);
    void refreshCounts();
    void refreshEmptyState();
    void refreshFooter();
    void showContextMenu(const QPoint &pos);
    /// Copies the row behind a proxy index. False when the index is not a row.
    bool rowForIndex(const QModelIndex &index, Applications::Row *row) const;

    QLineEdit *m_search = nullptr;
    QList<QToolButton *> m_filterButtons;
    QTableView *m_table = nullptr;
    QWidget *m_emptyHost = nullptr;
    EmptyStateWidget *m_empty = nullptr;
    QWidget *m_footer = nullptr;
    QLabel *m_footerCount = nullptr;

    ApplicationsPageTableModel *m_model = nullptr;
    ApplicationsPageFilterModel *m_proxy = nullptr;

    QList<Applications::Row> m_rows;
    Applications::Filter m_filter = Applications::Filter::All;
};
