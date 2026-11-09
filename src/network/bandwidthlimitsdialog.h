/**
 * @file   bandwidthlimitsdialog.h
 * @brief  Active bandwidth limits and the policy that owns each one.
 *
 * The process menu can only act on one executable at a time, so there was no
 * place to see the whole set of enforced limits or which stored policy asked
 * for them. This dialog lists the manager's active set with its attribution
 * and can remove the selected limit; the confirmation names the owner so a
 * policy-owned limit is not mistaken for a stray one.
 *
 * @author Codebuff
 */
#pragma once

#include <QDialog>

class QLabel;
class QPushButton;
class QTableWidget;
class ThrottlePolicyManager;

class BandwidthLimitsDialog : public QDialog
{
    Q_OBJECT
public:
    explicit BandwidthLimitsDialog(ThrottlePolicyManager *manager,
                                   QWidget *parent = nullptr);

private slots:
    void refresh();
    void removeSelected();
    void updateButtons();

private:
    int selectedRow() const;

    ThrottlePolicyManager *m_manager = nullptr;
    QTableWidget *m_table = nullptr;
    QLabel *m_summary = nullptr;
    QPushButton *m_removeButton = nullptr;
};
