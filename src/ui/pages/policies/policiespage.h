/**
 * @file    policiespage.h
 * @brief   Screen — Policies (docs/POLICIES_PAGE_PLAN.md, Phases 1-2).
 *
 * The KPI row, the filter bar and a read-only policy table. The shell derives
 * every cell from `PolicyStore`, the activation rules and the scope helpers and
 * hands display-ready rows over; the page itself never reads the store, applies
 * a policy or reconciles anything, so it cannot become a second enforcement
 * path.
 *
 * The status shown per row is deliberately one of six states rather than the
 * raw scheduler state: a scheduled policy reads `Scheduled` whether or not its
 * window is open, and the reason line says which. `Stored only` and
 * `Unsupported` are separate states so neither is silently merged into another
 * bucket.
 *
 * Editing, toggling and verification arrive in a later phase; the toolbar and
 * the actions column are present but inert.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QIcon>
#include <QList>
#include <QString>
#include <QWidget>

class EmptyStateWidget;
class MetricCard;
class QButtonGroup;
class QFrame;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QToolButton;
class QVBoxLayout;

namespace Policies {

/// How a row reads in the table. Derived by the shell, not by the page.
enum class Status {
    Active,       // enforced now, no window
    Scheduled,    // has a recurring window; the reason says if it is open
    Disabled,     // the user's switch is off
    StoredOnly,   // saved, but this build cannot enforce the scope
    Expired,      // its expiration has passed
    Unsupported   // the window cannot be parsed
};

enum class Filter {
    All,
    Active,
    Scheduled,
    Disabled,
    StoredOnly,
    Expired,
    Unsupported
};

QString statusLabel(Status status);
QString filterLabel(Filter filter);
Filter filterFor(Status status);

/// A display-ready policy row. Every string is final; the page only lays out.
struct Row
{
    QString id;
    QIcon icon;            // the executable's own icon, or the generic app icon
    QString name;          // executable name, group, publisher, service or PID
    QString subtitle;      // stored note, or what the target is
    QString tooltip;       // full target and note
    QString effect;        // "Throttle to 0.40 Mbit/s, both directions"
    QString window;        // "Always" or the stored window
    QString expires;       // "No expiration" or the countdown
    Status status = Status::Active;
    QString statusReason;  // why the row reads the way it does
    bool enabled = true;   // the user's switch, independent of the state above
};

} // namespace Policies

class PoliciesPage : public QWidget
{
    Q_OBJECT

public:
    explicit PoliciesPage(QWidget *parent = nullptr);

    /// Replaces every row. KPI counts and pill counts are derived from the
    /// rows here, so the strip and the table can never disagree.
    void setRows(const QList<Policies::Row> &rows);

    /// Shows the outcome of one reconciliation pass. `details` is the report's
    /// per-action lines; the page only lays them out.
    void showVerificationResult(bool ok, const QString &summary,
                                const QString &details);
    /// "Last verified ..." in the toolbar. An invalid time reads "Not verified
    /// yet", so a fresh profile never implies a pass that did not run.
    void setLastVerified(const QDateTime &when);

signals:
    /// Emitted by the page-body toolbar. The buttons are still disabled; the
    /// shell wires these when the actions exist.
    void verifyRequested();
    void createRequested();
    /// A row's switch was flipped, or its edit/delete action was used. The shell
    /// routes all three through NetworkWidget, which owns the store and
    /// enforcement, so a change here takes the same path as any other write.
    void policyEnabledChangeRequested(const QString &policyId, bool enabled);
    void policyEditRequested(const QString &policyId);
    void policyDeleteRequested(const QString &policyId);

private:
    void buildToolbar(QVBoxLayout *root);
    void buildBanner(QVBoxLayout *root);
    void buildMetrics(QVBoxLayout *root);
    void buildFilterBar(QVBoxLayout *root);
    void buildTable(QVBoxLayout *root);
    void buildEmptyStates(QVBoxLayout *root);

    void setFilter(Policies::Filter filter);
    void applyFilters();
    void refreshPills();
    void refreshContent();
    void refreshCounts();
    int countFor(Policies::Filter filter) const;

    void populateTable(const QList<Policies::Row> &rows);
    QWidget *applicationCell(const Policies::Row &row);
    QWidget *statusCell(const Policies::Row &row);
    QWidget *actionsCell(const Policies::Row &row);
    static QWidget *textCell(const QString &primary, const QString &secondary,
                             const QString &tooltip);

    MetricCard *m_activeCard = nullptr;
    MetricCard *m_scheduledCard = nullptr;
    MetricCard *m_storedOnlyCard = nullptr;

    QPushButton *m_verifyButton = nullptr;
    QPushButton *m_createButton = nullptr;
    QLabel *m_verifiedLabel = nullptr;

    QFrame *m_banner = nullptr;
    QLabel *m_bannerTitle = nullptr;
    QLabel *m_bannerDetail = nullptr;
    QPushButton *m_bannerDismiss = nullptr;
    QDateTime m_lastVerified;

    QWidget *m_filterBar = nullptr;
    QLineEdit *m_search = nullptr;
    QButtonGroup *m_pillGroup = nullptr;
    // Indexed by Policies::Filter, so a pill is found from the filter it sets.
    QList<QToolButton *> m_pills;

    QTableWidget *m_table = nullptr;
    QWidget *m_emptyHost = nullptr;
    EmptyStateWidget *m_empty = nullptr;
    QWidget *m_noMatchHost = nullptr;
    EmptyStateWidget *m_noMatch = nullptr;

    QList<Policies::Row> m_rows;
    Policies::Filter m_filter = Policies::Filter::All;
    QString m_query;
};
