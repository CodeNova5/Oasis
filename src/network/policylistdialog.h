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
 * Deleting or editing a policy does not withdraw enforcement directly here;
 * the caller schedules NG-024 reconciliation, which removes the rules and
 * bandwidth limits attributed to the policy. Limits applied outside a policy
 * are left in place, and **Limits...** shows who owns each active limit.
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

    // True when a policy was deleted here, so the caller can re-evaluate
    // activation and forget stale re-application bookkeeping. Edits go through
    // editRequested(), so the caller performs and accounts for them.
    bool changed() const { return m_changed; }

    // Re-reads the store. Called by the host after an edit it performed, so the
    // table shows what was actually saved and keeps the selected row.
    void reload();

signals:
    // The dialog is a view over the store: it asks the owner (which holds the
    // policy editor, scheduler and reconciliation) to edit one policy.
    void editRequested(const QString &policyId);
    // NG-024: the caller owns the enforcement managers, so it performs the
    // verification and shows the result while this dialog is open.
    void verifyRequested();

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
    QPushButton *m_verifyButton = nullptr;
    QList<NetworkPolicy> m_policies;
    bool m_changed = false;
};
