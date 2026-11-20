/**
 * @file    policiespage.h
 * @brief   Screen — Policies (docs/POLICIES_PAGE_PLAN.md, Phase 1).
 *
 * The skeleton of the Policies screen: the page-body toolbar, the KPI row and
 * the empty state. The shell derives the counts from `PolicyStore` and the
 * activation rules and hands them over; the page itself never reads the store,
 * applies a policy or reconciles anything, so it cannot become a second
 * enforcement path.
 *
 * Phase 1 deliberately has no table and no working actions. The buttons are
 * disabled until the row actions and Verify wiring land in a later phase; the
 * signals are declared here so that phase only has to enable them.
 *
 * @author  Oasis
 */
#pragma once

#include <QWidget>

class EmptyStateWidget;
class MetricCard;
class QFrame;
class QLabel;
class QPushButton;
class QVBoxLayout;

namespace Policies {

/// What the KPI strip shows. Counted by the shell, which is the only place
/// that knows how a stored policy maps to a live state.
struct Summary
{
    int active = 0;           // enforced right now
    int scheduledPaused = 0;  // in a window, disabled, or expired
    int storedOnly = 0;       // active, but this build cannot enforce the scope
    int total = 0;            // every stored policy
};

} // namespace Policies

class PoliciesPage : public QWidget
{
    Q_OBJECT

public:
    explicit PoliciesPage(QWidget *parent = nullptr);

    /// Replaces the KPI counts and switches between the empty state and the
    /// "list is being rebuilt" card.
    void setSummary(const Policies::Summary &summary);

signals:
    /// Emitted by the page-body toolbar. Unused in Phase 1 because both
    /// buttons are disabled; the shell wires them when the actions exist.
    void verifyRequested();
    void createRequested();

private:
    void buildToolbar(QVBoxLayout *root);
    void buildMetrics(QVBoxLayout *root);
    void buildContent(QVBoxLayout *root);
    void refreshContent();

    MetricCard *m_activeCard = nullptr;
    MetricCard *m_scheduledCard = nullptr;
    MetricCard *m_storedOnlyCard = nullptr;

    QPushButton *m_verifyButton = nullptr;
    QPushButton *m_createButton = nullptr;

    QWidget *m_emptyHost = nullptr;
    EmptyStateWidget *m_empty = nullptr;
    QWidget *m_storedCardHost = nullptr;
    QFrame *m_storedCard = nullptr;
    QLabel *m_storedTitle = nullptr;
    QLabel *m_storedDetail = nullptr;

    Policies::Summary m_summary;
};
