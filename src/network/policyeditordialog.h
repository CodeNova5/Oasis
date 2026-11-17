/**
 * @file   policyeditordialog.h
 * @brief  Policy scope selection and creation (NG-022).
 *
 * The editor exists to make policy scope explicit before anything is applied:
 * every choice names what it covers, how broad it is, and whether processes
 * that appear later inherit it. The risk text is a plain function rather than
 * widget state, so the wording can be checked without constructing a dialog.
 *
 * The visual layout follows `create_network_policy_modal_ui.html`: a 520 px
 * rounded card with an icon header, numbered sections, action cards, a
 * collapsible schedule group, and a live impact summary. Inter and JetBrains
 * Mono are bundled in `resources/fonts` and registered by ThemeManager, so the
 * dialog keeps the mockup's type in both themes.
 *
 * Scope keys match `NetworkPolicy::scope`: "pid", "path", "publisher",
 * "service", and "group". A group policy stores the activity-group id in
 * `targetId`, which is what NG-025 re-applies to future members.
 *
 * @author Codebuff
 */

#pragma once

#include <QDialog>
#include <QList>
#include <QString>

#include "network/policy.h"
#include "network/policyscope.h"

class QButtonGroup;
class QComboBox;
class QDateTimeEdit;
class QFrame;
class QGraphicsOpacityEffect;
class QLabel;
class QLineEdit;
class QPropertyAnimation;
class QPushButton;
class QScrollArea;
class QWidget;

// Painted controls: a card, a switch, and a checkbox. Kept out of the header's
// public surface because they are implementation details of this dialog.
class PolicyActionCard;
class PolicyToggleSwitch;
class PolicyCheckBox;

// The scope wording and impact preview live in policyscope.h, so the list
// dialog and the harness use exactly the same text as this editor.

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

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;
    void showEvent(QShowEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    void buildUi();
    void applyTheme();
    void updateScopeTarget();
    void updateServiceBanner();
    void updateActionControls();
    void updateImpactPreview();
    void updateAccordionStatus();
    void toggleAccordion();
    void setScheduleValue(const QString &schedule);
    QString scheduleValue() const;
    QString processBadgeText() const;
    QString previewHtml() const;
    QString enforcementText() const;
    void setAction(NetworkPolicy::Action action);
    void showToast(const QString &message);
    void browseForExecutable();
    static void repolish(QWidget *widget);

    PolicyScopeKind currentScope() const;
    NetworkPolicy::Action currentAction() const;
    PolicyImpact currentImpact() const;
    QString targetForScope() const;

    PolicyTarget m_target;
    NetworkPolicy m_policy;
    bool m_editing = false;
    QString m_policyId;
    QString m_policySource;

    QFrame *m_card = nullptr;
    QWidget *m_header = nullptr;
    QScrollArea *m_scroll = nullptr;
    QLabel *m_headerIcon = nullptr;
    QLabel *m_titleLabel = nullptr;
    QLabel *m_processBadge = nullptr;
    QLabel *m_scopeLabel = nullptr;
    QLabel *m_targetHint = nullptr;
    QLabel *m_serviceBanner = nullptr;
    QLabel *m_rateLabel = nullptr;
    QLabel *m_accordionStatus = nullptr;
    QLabel *m_chevron = nullptr;
    QLabel *m_clockIcon = nullptr;
    QLabel *m_eyeIcon = nullptr;
    QLabel *m_enabledLabel = nullptr;
    QLabel *m_impactLabel = nullptr;
    QLabel *m_enforcementLabel = nullptr;
    QLabel *m_toast = nullptr;

    QFrame *m_targetField = nullptr;
    QFrame *m_rateField = nullptr;
    QFrame *m_accordion = nullptr;
    QFrame *m_impactCard = nullptr;
    QWidget *m_rateContainer = nullptr;
    QWidget *m_accordionBody = nullptr;
    QWidget *m_expirationWrap = nullptr;
    QWidget *m_customScheduleWrap = nullptr;

    QLineEdit *m_targetEdit = nullptr;
    QLineEdit *m_rateEdit = nullptr;
    QLineEdit *m_customScheduleEdit = nullptr;
    QLineEdit *m_descriptionEdit = nullptr;
    QComboBox *m_scopeCombo = nullptr;
    QComboBox *m_directionCombo = nullptr;
    QComboBox *m_scheduleCombo = nullptr;
    QDateTimeEdit *m_expirationEdit = nullptr;

    QPushButton *m_browseButton = nullptr;
    QPushButton *m_closeButton = nullptr;
    QPushButton *m_accordionHeader = nullptr;
    QPushButton *m_cancelButton = nullptr;
    QPushButton *m_saveButton = nullptr;

    QButtonGroup *m_actionGroup = nullptr;
    QList<PolicyActionCard *> m_actionCards;
    PolicyToggleSwitch *m_enabledSwitch = nullptr;
    PolicyCheckBox *m_expiresCheck = nullptr;

    QPropertyAnimation *m_accordionAnim = nullptr;
    QPropertyAnimation *m_toastFade = nullptr;
    QGraphicsOpacityEffect *m_toastEffect = nullptr;

    bool m_accordionOpen = false;
    bool m_sized = false;
    bool m_initialFocusDone = false;
};
