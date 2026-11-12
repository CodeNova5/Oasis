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

// ─── Dialog ─────────────────────────────────────────────────────────────────

PolicyEditorDialog::PolicyEditorDialog(const PolicyTarget &target, QWidget *parent)
    : QDialog(parent)
    , m_target(target)
{
    buildUi();
    setWindowTitle(QStringLiteral("Create policy"));
    updateScopeTarget();
    updateActionControls();
    updateImpactPreview();
}

PolicyEditorDialog::PolicyEditorDialog(const NetworkPolicy &policy, QWidget *parent)
    : QDialog(parent)
{
    m_editing = true;
    m_policyId = policy.id;
    m_policySource = policy.source;

    PolicyScopeKind scope = PolicyScopeKind::ExecutablePath;
    policyScopeKindFromKey(policy.scope, &scope);
    switch (scope) {
    case PolicyScopeKind::Pid:
        m_target.pid = policy.targetId.toUInt();
        break;
    case PolicyScopeKind::Publisher:
        m_target.publisher = policy.targetId;
        break;
    case PolicyScopeKind::Service:
        m_target.serviceName = policy.targetId;
        break;
    case PolicyScopeKind::ApplicationGroup:
        m_target.groupId = policy.targetId;
        break;
    case PolicyScopeKind::ExecutablePath:
        m_target.executablePath = policy.targetId;
        break;
    }

    buildUi();
    setWindowTitle(QStringLiteral("Edit policy"));

    const int scopeIndex = m_scopeCombo->findData(static_cast<int>(scope));
    if (scopeIndex >= 0) m_scopeCombo->setCurrentIndex(scopeIndex);
    updateScopeTarget();

    const int actionIndex = m_actionCombo->findData(static_cast<int>(policy.action));
    if (actionIndex >= 0) m_actionCombo->setCurrentIndex(actionIndex);
    const int directionIndex = m_directionCombo->findData(static_cast<int>(policy.direction));
    if (directionIndex >= 0) m_directionCombo->setCurrentIndex(directionIndex);
    if (policy.rateBitsPerSecond > 0)
        m_rateSpin->setValue(static_cast<double>(policy.rateBitsPerSecond) / 1000000.0);
    m_scheduleCombo->setCurrentText(policy.schedule);
    m_expiresCheck->setChecked(policy.expiration.isValid());
    if (policy.expiration.isValid()) m_expirationEdit->setDateTime(policy.expiration);
    m_enabledCheck->setChecked(policy.enabled);
    m_descriptionEdit->setText(policy.description);
    updateActionControls();
    updateImpactPreview();
}

void PolicyEditorDialog::buildUi()
{
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

    m_enabledCheck = new QCheckBox(QStringLiteral("Enabled"), effectBox);
    m_enabledCheck->setChecked(true);
    effectLayout->addRow(QStringLiteral("State:"), m_enabledCheck);

    layout->addWidget(effectBox);

    // NG-053: scope, effect, duration, and enforcement in one place, updated
    // from the controls so the user reviews what will actually be stored.
    auto *impactBox = new QGroupBox(QStringLiteral("Impact"), this);
    auto *impactLayout = new QVBoxLayout(impactBox);
    m_impactLabel = new QLabel(impactBox);
    m_impactLabel->setWordWrap(true);
    m_impactLabel->setTextFormat(Qt::PlainText);
    m_impactLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_impactLabel->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    m_impactLabel->setStyleSheet(QStringLiteral("color: palette(window-text);"));
    impactLayout->addWidget(m_impactLabel);
    layout->addWidget(impactBox);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    layout->addWidget(buttons);

    connect(buttons, &QDialogButtonBox::accepted, this, &PolicyEditorDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &PolicyEditorDialog::reject);
    connect(m_scopeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyEditorDialog::updateScopeTarget);
    connect(m_scopeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_targetEdit, &QLineEdit::textChanged,
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_actionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyEditorDialog::updateActionControls);
    connect(m_actionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_directionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_rateSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_scheduleCombo, &QComboBox::currentTextChanged,
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_enabledCheck, &QCheckBox::toggled,
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_expiresCheck, &QCheckBox::toggled, m_expirationEdit, &QWidget::setEnabled);
    connect(m_expiresCheck, &QCheckBox::toggled,
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_expirationEdit, &QDateTimeEdit::dateTimeChanged,
            this, &PolicyEditorDialog::updateImpactPreview);
}

PolicyScopeKind PolicyEditorDialog::currentScope() const
{
    return static_cast<PolicyScopeKind>(m_scopeCombo->currentData().toInt());
}

NetworkPolicy::Action PolicyEditorDialog::currentAction() const
{
    return static_cast<NetworkPolicy::Action>(m_actionCombo->currentData().toInt());
}

void PolicyEditorDialog::updateScopeTarget()
{
    const PolicyScopeKind scope = currentScope();

    // The target follows the scope: switching to publisher must not silently
    // keep a path in the field and save a policy that matches nothing.
    switch (scope) {
    case PolicyScopeKind::Pid:
        m_targetEdit->setReadOnly(true);
        if (m_target.pid == 0)
            m_targetEdit->clear();
        else if (m_target.processName.isEmpty())
            m_targetEdit->setText(QStringLiteral("PID %1").arg(m_target.pid));
        else
            m_targetEdit->setText(QStringLiteral("PID %1 (%2)")
                                      .arg(m_target.pid)
                                      .arg(m_target.processName));
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

PolicyImpact PolicyEditorDialog::currentImpact() const
{
    PolicyImpact impact;
    impact.scope = currentScope();
    // PID and group policies are saved by id, but the preview and the
    // confirmation should name the thing the user recognises, so they reuse the
    // read-only target field that carries the process name or group name.
    impact.target = (impact.scope == PolicyScopeKind::Pid ||
                     impact.scope == PolicyScopeKind::ApplicationGroup)
        ? m_targetEdit->text().trimmed()
        : targetForScope();
    impact.action = currentAction();
    impact.direction = static_cast<NetworkDirection>(
        m_directionCombo->currentData().toInt());
    impact.rateBitsPerSecond = impact.action == NetworkPolicy::Action::Throttle
        ? static_cast<quint64>(qRound64(m_rateSpin->value() * 1000000.0))
        : 0;
    impact.expiration = m_expiresCheck->isChecked()
        ? m_expirationEdit->dateTime() : QDateTime();
    impact.schedule = m_scheduleCombo->currentText().trimmed();
    impact.enabled = m_enabledCheck->isChecked();
    return impact;
}

void PolicyEditorDialog::updateImpactPreview()
{
    m_impactLabel->setText(
        policyImpactSummary(currentImpact(), QDateTime::currentDateTime()));
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

    // NG-053: a publisher or group policy covers software the user did not pick
    // directly, so it is confirmed with its impact spelled out. Cancel is the
    // default button: an accidental Enter must not widen enforcement.
    const PolicyImpact impact = currentImpact();
    if (policyScopeRequiresConfirmation(impact.scope, impact.enabled)) {
        const QMessageBox::StandardButton answer = QMessageBox::question(
            this, QStringLiteral("Confirm broad policy"),
            policyConfirmationText(impact, now),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer != QMessageBox::Yes) return;
    }

    m_policy = NetworkPolicy();
    m_policy.id = m_editing
        ? m_policyId
        : QStringLiteral("policy-") +
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

    m_policy.source = m_editing ? m_policySource : QStringLiteral("user");
    m_policy.enabled = m_enabledCheck->isChecked();
    m_policy.description = m_descriptionEdit->text().trimmed();

    QDialog::accept();
}
