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
 * The editable surface (scope, action, limit, schedule, preview) lives in
 * PolicyRuleForm; this class owns the window chrome and the accept-time
 * validation only.
 *
 * @author Codebuff
 */

#pragma once

#include <QDialog>
#include <QString>

#include "network/policyruleform.h"

class QFrame;
class QGraphicsOpacityEffect;
class QLabel;
class QPropertyAnimation;
class QPushButton;
class QScrollArea;
class QShowEvent;
class QResizeEvent;

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
    QString processBadgeText() const;
    void showToast(const QString &message);

    PolicyTarget m_target;
    NetworkPolicy m_policy;
    bool m_editing = false;
    QString m_policyId;
    QString m_policySource;

    QFrame *m_card = nullptr;
    QWidget *m_header = nullptr;
    QScrollArea *m_scroll = nullptr;
    PolicyRuleForm *m_form = nullptr;

    QLabel *m_headerIcon = nullptr;
    QLabel *m_titleLabel = nullptr;
    QLabel *m_processBadge = nullptr;
    QLabel *m_toast = nullptr;

    QPushButton *m_closeButton = nullptr;
    QPushButton *m_cancelButton = nullptr;
    QPushButton *m_saveButton = nullptr;

    QPropertyAnimation *m_toastFade = nullptr;
    QGraphicsOpacityEffect *m_toastEffect = nullptr;

    bool m_sized = false;
    bool m_initialFocusDone = false;
};
