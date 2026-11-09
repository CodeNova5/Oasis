/**
 * @file   policylistdialog.h
 * @brief  Saved policies at a glance, with edit and delete (NG-022 follow-up).
 *
 * The editor can create a policy, but a stored policy is invisible unless
 * something lists it. This dialog reads `PolicyStore` on open and after every
 * change, shows the scope, target, effect, and derived activation state of each
 * policy, and routes edit through the same `PolicyEditorDialog` used for
 * creation. Deletion asks for confirmation because it cannot be undone.
 *
 * Deleting or editing a policy does not withdraw firewall or shaping state that
 * was already applied: this build cannot attribute a rule to the policy that
 * created it. NG-024 owns that reconciliation.
 *
 * @author Codebuff
 */

#pragma once

#include <QDialog>
#include <QList>

#include "network/policy.h"

class QLabel;
class QPushButton;
class QTableWidget;

class PolicyListDialog : public QDialog
{
    Q_OBJECT
public:
    explicit PolicyListDialog(QWidget *parent = nullptr);

    // True when a policy was saved or deleted, so the caller can re-evaluate
    // activation and forget stale re-application bookkeeping.
    bool changed() const { return m_changed; }

private slots:
    void editSelected();
    void deleteSelected();
    void updateButtons();

private:
    void refresh();
    int selectedRow() const;

    QTableWidget *m_table = nullptr;
    QLabel *m_summary = nullptr;
    QPushButton *m_editButton = nullptr;
    QPushButton *m_deleteButton = nullptr;
    QList<NetworkPolicy> m_policies;
    bool m_changed = false;
};
