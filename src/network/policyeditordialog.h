/**
 * @file   policyeditordialog.h
 * @brief  Policy scope selection and creation (NG-022).
 *
 * The editor exists to make policy scope explicit before anything is applied:
 * every choice names what it covers, how broad it is, and whether processes
 * that appear later inherit it. The risk text is a plain function rather than
 * widget state, so the wording can be checked without constructing a dialog.
 *
 * Scope keys match `NetworkPolicy::scope`: "pid", "path", "publisher",
 * "service", and "group". A group policy stores the activity-group id in
 * `targetId`, which is what NG-025 re-applies to future members.
 *
 * @author Codebuff
 */

#pragma once

#include <QDialog>
#include <QString>

#include "network/policy.h"

class QCheckBox;
class QComboBox;
class QDateTimeEdit;
class QDoubleSpinBox;
class QLabel;
class QLineEdit;

// ─── Scopes the editor offers (PRD 9.3) ─────────────────────────────────────
enum class PolicyScopeKind {
    Pid,              // this process instance only
    ExecutablePath,   // this file at this path
    Publisher,        // every process signed by this publisher
    Service,          // this Windows service and its hosts
    ApplicationGroup  // every current and future member of the group
};

QString policyScopeDisplayName(PolicyScopeKind scope);
QString policyScopeKey(PolicyScopeKind scope);
QString policyScopeBreadth(PolicyScopeKind scope);
QString policyScopeExplanation(PolicyScopeKind scope);
bool policyScopeAffectsFutureProcesses(PolicyScopeKind scope);
// False for scopes this build stores but cannot resolve to running processes
// yet; the dialog says so instead of implying the policy is in force.
bool policyScopeEnforcedByThisBuild(PolicyScopeKind scope);

// Breadth, explanation, future-process note, and enforcement note, as shown in
// the dialog.
QString policyScopeRiskSummary(PolicyScopeKind scope);

// What the selected tree row and its activity group can fill in. Every field
// is optional: a publisher or service the group does not know is left for the
// user to type.
struct PolicyTarget
{
    quint32 pid = 0;
    QString processName;
    QString executablePath;
    QString publisher;
    QString serviceName;
    QString groupId;
    QString groupName;
};

class PolicyEditorDialog : public QDialog
{
    Q_OBJECT
public:
    explicit PolicyEditorDialog(const PolicyTarget &target, QWidget *parent = nullptr);
    // Edit an existing policy: the id and source are kept, so editing a user
    // policy cannot quietly turn it into something emergency restore removes.
    explicit PolicyEditorDialog(const NetworkPolicy &policy, QWidget *parent = nullptr);

    // Valid once the dialog has been accepted.
    NetworkPolicy policy() const { return m_policy; }

    void accept() override;

private:
    void buildUi();
    PolicyScopeKind currentScope() const;
    NetworkPolicy::Action currentAction() const;
    void updateScopeDescription();
    void updateActionControls();
    QString targetForScope() const;

    PolicyTarget m_target;
    NetworkPolicy m_policy;
    bool m_editing = false;
    QString m_policyId;
    QString m_policySource;

    QComboBox *m_scopeCombo = nullptr;
    QLineEdit *m_targetEdit = nullptr;
    QLabel *m_riskLabel = nullptr;
    QComboBox *m_actionCombo = nullptr;
    QComboBox *m_directionCombo = nullptr;
    QDoubleSpinBox *m_rateSpin = nullptr;
    QComboBox *m_scheduleCombo = nullptr;
    QCheckBox *m_expiresCheck = nullptr;
    QDateTimeEdit *m_expirationEdit = nullptr;
    QCheckBox *m_enabledCheck = nullptr;
    QLineEdit *m_descriptionEdit = nullptr;
};
