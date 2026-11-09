/**
 * @file   policyeditordialog.cpp
 * @brief  Policy scope selection and creation (NG-022).
 * @author Codebuff
 */

#include "policyeditordialog.h"

#include "policyschedule.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDateTimeEdit>
#include <QDialogButtonBox>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QUuid>
#include <QVBoxLayout>

// ─── Scope descriptions ─────────────────────────────────────────────────────

QString policyScopeDisplayName(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid: return QStringLiteral("This process only (PID)");
    case PolicyScopeKind::ExecutablePath: return QStringLiteral("This executable path");
    case PolicyScopeKind::Publisher: return QStringLiteral("This publisher");
    case PolicyScopeKind::Service: return QStringLiteral("This Windows service");
    case PolicyScopeKind::ApplicationGroup: return QStringLiteral("This application group");
    }
    return QString();
}

QString policyScopeKey(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid: return QStringLiteral("pid");
    case PolicyScopeKind::ExecutablePath: return QStringLiteral("path");
    case PolicyScopeKind::Publisher: return QStringLiteral("publisher");
    case PolicyScopeKind::Service: return QStringLiteral("service");
    case PolicyScopeKind::ApplicationGroup: return QStringLiteral("group");
    }
    return QString();
}

QString policyScopeBreadth(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid: return QStringLiteral("Narrowest");
    case PolicyScopeKind::ExecutablePath: return QStringLiteral("One file");
    case PolicyScopeKind::Publisher: return QStringLiteral("Broad");
    case PolicyScopeKind::Service: return QStringLiteral("One service");
    case PolicyScopeKind::ApplicationGroup: return QStringLiteral("Broad");
    }
    return QString();
}

QString policyScopeExplanation(PolicyScopeKind scope)
{
    switch (scope) {
    case PolicyScopeKind::Pid:
        return QStringLiteral(
            "Applies only while this process instance is running. A restart, a "
            "respawn, or a reused PID is a different process, so the policy "
            "does not follow it.");
    case PolicyScopeKind::ExecutablePath:
        return QStringLiteral(
            "Applies to the file at this path, now and on later runs. A copy of "
            "the file elsewhere, or an update installed to a new path, is not "
            "covered.");
    case PolicyScopeKind::Publisher:
        return QStringLiteral(
            "Applies to every process signed by this publisher, including "
            "products and updates you have not seen yet. A broad certificate "
            "affects unrelated software too.");
    case PolicyScopeKind::Service:
        return QStringLiteral(
            "Applies to this Windows service and the processes that host it, "
            "including instances started later.");
    case PolicyScopeKind::ApplicationGroup:
        return QStringLiteral(
            "Applies to every current and future member of this activity group, "
            "including helpers and updaters that appear later. Adding a member "
            "to the group widens what the policy affects.");
    }
    return QString();
}

bool policyScopeAffectsFutureProcesses(PolicyScopeKind scope)
{
    return scope != PolicyScopeKind::Pid;
}

bool policyScopeEnforcedByThisBuild(PolicyScopeKind scope)
{
    // Path and group policies are resolved to executables and applied by the
    // enforcement coordinator; the other scopes are stored but not resolved.
    return scope == PolicyScopeKind::ExecutablePath ||
           scope == PolicyScopeKind::ApplicationGroup;
}

QString policyScopeRiskSummary(PolicyScopeKind scope)
{
    QString text = policyScopeBreadth(scope) + QStringLiteral(": ") +
                   policyScopeExplanation(scope);

    if (policyScopeAffectsFutureProcesses(scope))
        text += QStringLiteral("\n\nThis scope also affects processes that appear later.");

    if (!policyScopeEnforcedByThisBuild(scope)) {
        text += QStringLiteral(
            "\n\nNot enforced yet: this build stores the policy but cannot "
            "resolve this scope to running processes, so no firewall or "
            "shaping action is taken.");
    }

    return text;
}

// ─── Dialog ─────────────────────────────────────────────────────────────────

PolicyEditorDialog::PolicyEditorDialog(const PolicyTarget &target, QWidget *parent)
    : QDialog(parent)
    , m_target(target)
{
    setWindowTitle(QStringLiteral("Create policy"));
    setMinimumWidth(560);

    auto *layout = new QVBoxLayout(this);

    auto *intro = new QLabel(
        QStringLiteral("Choose what this policy covers before it is applied."), this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    auto *scopeBox = new QGroupBox(QStringLiteral("Scope"), this);
    auto *scopeLayout = new QFormLayout(scopeBox);

    m_scopeCombo = new QComboBox(scopeBox);
    for (PolicyScopeKind scope : {PolicyScopeKind::Pid, PolicyScopeKind::ExecutablePath,
                                  PolicyScopeKind::Publisher, PolicyScopeKind::Service,
                                  PolicyScopeKind::ApplicationGroup}) {
        m_scopeCombo->addItem(policyScopeDisplayName(scope), static_cast<int>(scope));
    }
    // The executable path is the narrow default: it survives a restart without
    // silently widening to everything the vendor ships.
    m_scopeCombo->setCurrentIndex(1);
    scopeLayout->addRow(QStringLiteral("Applies to:"), m_scopeCombo);

    m_targetEdit = new QLineEdit(scopeBox);
    scopeLayout->addRow(QStringLiteral("Target:"), m_targetEdit);

    m_riskLabel = new QLabel(scopeBox);
    m_riskLabel->setWordWrap(true);
    m_riskLabel->setTextFormat(Qt::PlainText);
    m_riskLabel->setMinimumHeight(110);
    m_riskLabel->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    m_riskLabel->setStyleSheet(QStringLiteral("color: palette(mid);"));
    scopeLayout->addRow(QStringLiteral("Breadth and risk:"), m_riskLabel);

    layout->addWidget(scopeBox);

    auto *effectBox = new QGroupBox(QStringLiteral("Effect"), this);
    auto *effectLayout = new QFormLayout(effectBox);

    m_actionCombo = new QComboBox(effectBox);
    m_actionCombo->addItem(QStringLiteral("Allow"),
                           static_cast<int>(NetworkPolicy::Action::Allow));
    m_actionCombo->addItem(QStringLiteral("Throttle"),
                           static_cast<int>(NetworkPolicy::Action::Throttle));
    m_actionCombo->addItem(QStringLiteral("Block"),
                           static_cast<int>(NetworkPolicy::Action::Block));
    m_actionCombo->addItem(QStringLiteral("Notify"),
                           static_cast<int>(NetworkPolicy::Action::Notify));
    m_actionCombo->addItem(QStringLiteral("Ask"),
                           static_cast<int>(NetworkPolicy::Action::Ask));
    m_actionCombo->addItem(QStringLiteral("No action"),
                           static_cast<int>(NetworkPolicy::Action::NoAction));
    m_actionCombo->setCurrentIndex(1);  // throttle is the cautious default
    effectLayout->addRow(QStringLiteral("Action:"), m_actionCombo);

    m_directionCombo = new QComboBox(effectBox);
    m_directionCombo->addItem(QStringLiteral("Download"),
                              static_cast<int>(NetworkDirection::Download));
    m_directionCombo->addItem(QStringLiteral("Upload"),
                              static_cast<int>(NetworkDirection::Upload));
    m_directionCombo->addItem(QStringLiteral("Both directions"),
                              static_cast<int>(NetworkDirection::Both));
    m_directionCombo->setCurrentIndex(2);
    effectLayout->addRow(QStringLiteral("Direction:"), m_directionCombo);

    m_rateSpin = new QDoubleSpinBox(effectBox);
    m_rateSpin->setRange(0.05, 100000.0);
    m_rateSpin->setDecimals(2);
    m_rateSpin->setValue(0.40);
    m_rateSpin->setSuffix(QStringLiteral(" Mbit/s"));
    // NG-021: the throttle channel currently requests the manager's default
    // limit, so a different stored rate is not what gets enforced.
    m_rateSpin->setToolTip(QStringLiteral(
        "This build requests a fixed 0.4096 Mbit/s limit. A different rate is "
        "stored with the policy but is not applied yet."));
    effectLayout->addRow(QStringLiteral("Rate limit:"), m_rateSpin);

    m_scheduleCombo = new QComboBox(effectBox);
    m_scheduleCombo->setEditable(true);
    m_scheduleCombo->addItem(QString());
    m_scheduleCombo->addItem(QStringLiteral("work-hours"));
    m_scheduleCombo->addItem(QStringLiteral("overnight"));
    m_scheduleCombo->addItem(QStringLiteral("22:00-06:00"));
    m_scheduleCombo->addItem(QStringLiteral("Mon-Fri 09:00-17:00"));
    effectLayout->addRow(QStringLiteral("Recurring window:"), m_scheduleCombo);

    auto *scheduleHint = new QLabel(
        QStringLiteral("Optional, local time. Use work-hours, overnight, "
                       "HH:MM-HH:MM, or \"Mon-Fri 09:00-17:00\"."), effectBox);
    scheduleHint->setWordWrap(true);
    scheduleHint->setStyleSheet(QStringLiteral("color: palette(mid);"));
    effectLayout->addRow(QString(), scheduleHint);

    m_expiresCheck = new QCheckBox(QStringLiteral("Expires"), effectBox);
    m_expirationEdit = new QDateTimeEdit(
        QDateTime::currentDateTime().addSecs(3600), effectBox);
    m_expirationEdit->setCalendarPopup(true);
    m_expirationEdit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm"));
    m_expirationEdit->setEnabled(false);

    auto *expiryRow = new QWidget(effectBox);
    auto *expiryLayout = new QHBoxLayout(expiryRow);
    expiryLayout->setContentsMargins(0, 0, 0, 0);
    expiryLayout->addWidget(m_expiresCheck);
    expiryLayout->addWidget(m_expirationEdit, 1);
    effectLayout->addRow(QStringLiteral("Expiration:"), expiryRow);

    m_descriptionEdit = new QLineEdit(effectBox);
    m_descriptionEdit->setPlaceholderText(
        QStringLiteral("Why this policy exists (optional)"));
    effectLayout->addRow(QStringLiteral("Note:"), m_descriptionEdit);

    layout->addWidget(effectBox);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    layout->addWidget(buttons);

    connect(buttons, &QDialogButtonBox::accepted, this, &PolicyEditorDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &PolicyEditorDialog::reject);
    connect(m_scopeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyEditorDialog::updateScopeDescription);
    connect(m_actionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyEditorDialog::updateActionControls);
    connect(m_expiresCheck, &QCheckBox::toggled, m_expirationEdit, &QWidget::setEnabled);

    updateScopeDescription();
    updateActionControls();
}

PolicyScopeKind PolicyEditorDialog::currentScope() const
{
    return static_cast<PolicyScopeKind>(m_scopeCombo->currentData().toInt());
}

NetworkPolicy::Action PolicyEditorDialog::currentAction() const
{
    return static_cast<NetworkPolicy::Action>(m_actionCombo->currentData().toInt());
}

void PolicyEditorDialog::updateScopeDescription()
{
    const PolicyScopeKind scope = currentScope();
    m_riskLabel->setText(policyScopeRiskSummary(scope));

    // The target follows the scope: switching to publisher must not silently
    // keep a path in the field and save a policy that matches nothing.
    switch (scope) {
    case PolicyScopeKind::Pid:
        m_targetEdit->setReadOnly(true);
        m_targetEdit->setText(m_target.pid
            ? QStringLiteral("PID %1 (%2)").arg(m_target.pid).arg(m_target.processName)
            : QString());
        break;
    case PolicyScopeKind::ExecutablePath:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setText(m_target.executablePath);
        break;
    case PolicyScopeKind::Publisher:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setText(m_target.publisher);
        break;
    case PolicyScopeKind::Service:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setText(m_target.serviceName);
        break;
    case PolicyScopeKind::ApplicationGroup:
        m_targetEdit->setReadOnly(true);
        m_targetEdit->setText(m_target.groupName.isEmpty()
            ? m_target.groupId
            : QStringLiteral("%1 (%2)").arg(m_target.groupName, m_target.groupId));
        break;
    }
}

void PolicyEditorDialog::updateActionControls()
{
    const bool shaping = currentAction() == NetworkPolicy::Action::Throttle;
    m_rateSpin->setEnabled(shaping);
    // Direction is stored either way, but only shaping uses it in this build.
    m_directionCombo->setEnabled(shaping);
}

QString PolicyEditorDialog::targetForScope() const
{
    switch (currentScope()) {
    case PolicyScopeKind::Pid: return QString::number(m_target.pid);
    case PolicyScopeKind::ApplicationGroup: return m_target.groupId;
    default: return m_targetEdit->text().trimmed();
    }
}

void PolicyEditorDialog::accept()
{
    const PolicyScopeKind scope = currentScope();
    const NetworkPolicy::Action action = currentAction();
    const QString target = targetForScope();

    if (scope == PolicyScopeKind::Pid && m_target.pid == 0) {
        QMessageBox::warning(this, QStringLiteral("Create policy"),
                             QStringLiteral("Select a process row before creating a "
                                            "PID-scoped policy."));
        return;
    }
    if (scope == PolicyScopeKind::ApplicationGroup && m_target.groupId.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Create policy"),
                             QStringLiteral("This process does not belong to an activity "
                                            "group, so a group-scoped policy has no target."));
        return;
    }
    if (scope != PolicyScopeKind::Pid && scope != PolicyScopeKind::ApplicationGroup &&
        target.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Create policy"),
                             QStringLiteral("Enter the %1 this policy should cover.")
                                 .arg(scope == PolicyScopeKind::Publisher
                                          ? QStringLiteral("publisher")
                                          : scope == PolicyScopeKind::Service
                                                ? QStringLiteral("service name")
                                                : QStringLiteral("path")));
        m_targetEdit->setFocus();
        return;
    }

    const QString schedule = m_scheduleCombo->currentText().trimmed();
    if (!schedule.isEmpty() && !scheduleIsSupported(schedule)) {
        QMessageBox::warning(
            this, QStringLiteral("Create policy"),
            QStringLiteral("The recurring window \"%1\" is not recognised. Use "
                           "work-hours, overnight, HH:MM-HH:MM, or "
                           "\"Mon-Fri 09:00-17:00\".").arg(schedule));
        m_scheduleCombo->setFocus();
        return;
    }

    if (action == NetworkPolicy::Action::Throttle && m_rateSpin->value() <= 0.0) {
        QMessageBox::warning(this, QStringLiteral("Create policy"),
                             QStringLiteral("A throttle policy needs a rate above zero."));
        m_rateSpin->setFocus();
        return;
    }

    const QDateTime now = QDateTime::currentDateTime();
    if (m_expiresCheck->isChecked() && m_expirationEdit->dateTime() <= now) {
        QMessageBox::warning(this, QStringLiteral("Create policy"),
                             QStringLiteral("The expiration must be in the future."));
        m_expirationEdit->setFocus();
        return;
    }

    m_policy = NetworkPolicy();
    m_policy.id = QStringLiteral("policy-") +
                  QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_policy.scope = policyScopeKey(scope);
    m_policy.targetId = target;
    m_policy.direction = static_cast<NetworkDirection>(
        m_directionCombo->currentData().toInt());
    m_policy.action = action;
    m_policy.rateBitsPerSecond = action == NetworkPolicy::Action::Throttle
        ? static_cast<quint64>(qRound64(m_rateSpin->value() * 1000000.0))
        : 0;

    const bool expires = m_expiresCheck->isChecked();
    m_policy.schedule = schedule;
    m_policy.expiration = expires ? m_expirationEdit->dateTime() : QDateTime();
    if (expires && !schedule.isEmpty()) {
        m_policy.scheduleType = NetworkPolicy::ScheduleType::Both;
    } else if (expires) {
        m_policy.scheduleType = NetworkPolicy::ScheduleType::Expiration;
    } else if (!schedule.isEmpty()) {
        m_policy.scheduleType = NetworkPolicy::ScheduleType::Recurring;
    } else {
        m_policy.scheduleType = NetworkPolicy::ScheduleType::None;
    }

    m_policy.source = QStringLiteral("user");
    m_policy.enabled = true;
    m_policy.description = m_descriptionEdit->text().trimmed();

    QDialog::accept();
}
