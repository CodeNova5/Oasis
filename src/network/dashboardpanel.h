/**
 * @file   dashboardpanel.h
 * @brief  The first view of the Network tab: top consumers, controls,
 *         unresolved traffic, and suggested actions (NG-054).
 *
 * The panel only renders a `TopConsumers::Summary` and emits the user's intent
 * back to `NetworkWidget`, which owns every action and every manager. That
 * keeps the ranking testable and the panel free of enforcement code: clicking a
 * row opens the NG-052 detail view, **Suggested action...** opens the NG-042
 * recommendation for the selected (or top) consumer, and **Policies...** opens
 * the stored-policy list.
 *
 * @author Codebuff
 */

#pragma once

#include <QGroupBox>

#include "network/topconsumers.h"

class QLabel;
class QPushButton;
class QTableWidget;

class DashboardPanel : public QGroupBox
{
    Q_OBJECT
public:
    explicit DashboardPanel(QWidget *parent = nullptr);

    // Replaces everything on screen; the panel keeps no history.
    void setSummary(const TopConsumers::Summary &summary);

signals:
    void detailsRequested(quint32 pid, const QString &path, const QString &name);
    void recommendationRequested(quint32 pid, const QString &path, const QString &name);
    void policiesRequested();

private:
    // The selected row, or the top consumer when nothing is selected.
    int effectiveRow() const;
    void updateButtons();

    TopConsumers::Summary m_summary;
    QLabel *m_headline = nullptr;
    QLabel *m_topDetail = nullptr;
    QLabel *m_controls = nullptr;
    QLabel *m_unresolved = nullptr;
    QLabel *m_recommendations = nullptr;
    QTableWidget *m_table = nullptr;
    QPushButton *m_detailsButton = nullptr;
    QPushButton *m_recommendButton = nullptr;
};
