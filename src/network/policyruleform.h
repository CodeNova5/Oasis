/**
 * @file   policyruleform.h
 * @brief  The editable portion of the policy editor (scope, action, schedule).
 *
 * The rule form owns everything a policy is made of: the target and its scope,
 * the action cards and direction, the bandwidth limit, the schedule /
 * expiration / note accordion, and the live impact preview. The dialog around
 * it owns only the window chrome (frameless card, header, footer, toast) and
 * the accept-time validation, so the form can be hosted by another surface
 * without dragging the dialog's window management along.
 *
 * @author Codebuff
 */

#pragma once

#include <QDateTime>
#include <QList>
#include <QString>
#include <QWidget>

#include "network/policy.h"
#include "network/policyscope.h"

class QButtonGroup;
class QEvent;
class QComboBox;
class QDateTimeEdit;
class QFrame;
class QLabel;
class QLineEdit;
class QPropertyAnimation;
class QPushButton;

namespace PolicyEditorStyle {
class PolicyActionCard;
class PolicyToggleSwitch;
class PolicyCheckBox;
}

using PolicyActionCard = PolicyEditorStyle::PolicyActionCard;
using PolicyToggleSwitch = PolicyEditorStyle::PolicyToggleSwitch;
using PolicyCheckBox = PolicyEditorStyle::PolicyCheckBox;

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

class PolicyRuleForm : public QWidget
{
    Q_OBJECT
public:
    explicit PolicyRuleForm(const PolicyTarget &target, QWidget *parent = nullptr);

    /// Copy the fields of an existing policy into the form (edit mode).
    void loadPolicy(const NetworkPolicy &policy);

    /// Text the dialog shows in the header badge; the PID and group previews
    /// reuse it so they name the thing the user recognises.
    void setTargetLabel(const QString &label) { m_targetLabel = label; }

    /// Re-resolve colours and the painted glyphs for the active theme.
    void applyTheme();

    /// Rebuild the impact preview (after the target label is known).
    void updateImpactPreview();

    PolicyScopeKind currentScope() const;
    NetworkPolicy::Action currentAction() const;
    PolicyImpact currentImpact() const;
    QString targetForScope() const;
    void setAction(NetworkPolicy::Action action);

    QString scheduleValue() const;
    void setScheduleValue(const QString &schedule);

    NetworkDirection direction() const;
    qint64 rateKbps() const;
    quint64 rateBitsPerSecond() const;
    bool expiresChecked() const;
    QDateTime expiration() const;
    QString description() const;
    bool enabled() const;

    /// The control the dialog should focus when it first opens.
    QWidget *initialFocusWidget() const;
    void focusTargetField();
    void focusRateField();
    void focusExpirationField();

signals:
    /// The form's preferred height changed; the host scroll area re-measures.
    void layoutChanged();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    void buildUi();
    void updateScopeTarget();
    void updateServiceBanner();
    void updateActionControls();
    void updateAccordionStatus();
    void toggleAccordion();
    QString previewHtml() const;
    QString enforcementText() const;
    void browseForExecutable();

    PolicyTarget m_target;
    QString m_targetLabel;

    QFrame *m_targetField = nullptr;
    QFrame *m_rateField = nullptr;
    QFrame *m_accordion = nullptr;
    QFrame *m_impactCard = nullptr;
    QWidget *m_rateContainer = nullptr;
    QWidget *m_accordionBody = nullptr;
    QWidget *m_expirationWrap = nullptr;
    QWidget *m_customScheduleWrap = nullptr;

    QLabel *m_scopeLabel = nullptr;
    QLabel *m_targetHint = nullptr;
    QLabel *m_serviceBanner = nullptr;
    QLabel *m_accordionStatus = nullptr;
    QLabel *m_chevron = nullptr;
    QLabel *m_clockIcon = nullptr;
    QLabel *m_eyeIcon = nullptr;
    QLabel *m_enabledLabel = nullptr;
    QLabel *m_impactLabel = nullptr;
    QLabel *m_enforcementLabel = nullptr;

    QLineEdit *m_targetEdit = nullptr;
    QLineEdit *m_rateEdit = nullptr;
    QLineEdit *m_customScheduleEdit = nullptr;
    QLineEdit *m_descriptionEdit = nullptr;
    QComboBox *m_scopeCombo = nullptr;
    QComboBox *m_directionCombo = nullptr;
    QComboBox *m_scheduleCombo = nullptr;
    QDateTimeEdit *m_expirationEdit = nullptr;

    QPushButton *m_browseButton = nullptr;
    QPushButton *m_accordionHeader = nullptr;

    QButtonGroup *m_actionGroup = nullptr;
    QList<PolicyActionCard *> m_actionCards;
    PolicyToggleSwitch *m_enabledSwitch = nullptr;
    PolicyCheckBox *m_expiresCheck = nullptr;

    QPropertyAnimation *m_accordionAnim = nullptr;
    bool m_accordionOpen = false;
};
