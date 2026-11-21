/**
 * @file   policyruleform.cpp
 * @brief  Rule-building portion of the network policy editor.
 *
 * Owns the scope/target fields, the action cards and limit, the schedule
 * accordion and the live impact preview. The dialog only hosts this widget and
 * validates the values it exposes.
 *
 * @author Codebuff
 */

#include "policyruleform.h"

#include "policyeditorcontrols.h"
#include "policyeditorstyle.h"
#include "policyschedule.h"
#include "ui/theme/thememanager.h"

#include <QAbstractButton>
#include <QButtonGroup>
#include <QComboBox>
#include <QDateTime>
#include <QDateTimeEdit>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QHBoxLayout>
#include <QIcon>
#include <QIntValidator>
#include <QLabel>
#include <QLineEdit>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QVBoxLayout>

using namespace PolicyEditorStyle;

PolicyRuleForm::PolicyRuleForm(const PolicyTarget &target, QWidget *parent)
    : QWidget(parent)
    , m_target(target)
{
    buildUi();
    updateScopeTarget();
    updateActionControls();
}

void PolicyRuleForm::buildUi()
{
    setObjectName(QStringLiteral("dialogBody"));
    auto *bodyLayout = new QVBoxLayout(this);
    bodyLayout->setContentsMargins(20, 20, 20, 20);
    bodyLayout->setSpacing(16);

    // ── 1. Target & scope ─────────────────────────────────────────────────
    m_sectionTarget = new QWidget(this);
    auto *sectionTarget = m_sectionTarget;
    auto *targetLayout = new QVBoxLayout(sectionTarget);
    targetLayout->setContentsMargins(0, 0, 0, 0);
    targetLayout->setSpacing(12);

    auto *targetHead = new QHBoxLayout();
    targetHead->setContentsMargins(0, 0, 0, 0);
    targetHead->setSpacing(8);
    m_scopeLabel = makeLabel(QStringLiteral("1. TARGET APPLICATION"),
                             QStringLiteral("sectionLabel"), sectionTarget);
    targetHead->addWidget(m_scopeLabel);
    targetHead->addStretch(1);

    m_scopeCombo = new QComboBox(sectionTarget);
    m_scopeCombo->setObjectName(QStringLiteral("scopePill"));
    m_scopeCombo->setCursor(Qt::PointingHandCursor);
    m_scopeCombo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    m_scopeCombo->setFixedHeight(24);
    for (PolicyScopeKind scope : {PolicyScopeKind::Pid, PolicyScopeKind::ExecutablePath,
                                  PolicyScopeKind::Publisher, PolicyScopeKind::Service,
                                  PolicyScopeKind::ApplicationGroup}) {
        m_scopeCombo->addItem(QStringLiteral("Scope: ") + policyScopeDisplayName(scope),
                              static_cast<int>(scope));
    }
    // The executable path is the narrow default: it survives a restart without
    // silently widening to everything the vendor ships.
    m_scopeCombo->setCurrentIndex(1);
    targetHead->addWidget(m_scopeCombo);
    targetLayout->addLayout(targetHead);

    m_targetField = new QFrame(sectionTarget);
    m_targetField->setObjectName(QStringLiteral("targetField"));
    m_targetField->setFixedHeight(38);
    auto *targetFieldLayout = new QHBoxLayout(m_targetField);
    targetFieldLayout->setContentsMargins(12, 0, 6, 0);
    targetFieldLayout->setSpacing(6);

    m_targetEdit = new QLineEdit(m_targetField);
    m_targetEdit->setObjectName(QStringLiteral("targetInput"));
    m_targetEdit->setFrame(false);
    m_targetEdit->installEventFilter(this);
    targetFieldLayout->addWidget(m_targetEdit, 1);

    m_browseButton = new QPushButton(m_targetField);
    m_browseButton->setObjectName(QStringLiteral("iconButton"));
    m_browseButton->setFixedSize(26, 26);
    m_browseButton->setCursor(Qt::PointingHandCursor);
    m_browseButton->setToolTip(QStringLiteral("Browse executable..."));
    m_browseButton->setAccessibleName(QStringLiteral("Browse executable"));
    targetFieldLayout->addWidget(m_browseButton);
    targetLayout->addWidget(m_targetField);

    m_serviceBanner = makeLabel(QString(), QStringLiteral("serviceBanner"), sectionTarget);
    m_serviceBanner->setWordWrap(true);
    m_serviceBanner->setTextFormat(Qt::RichText);
    m_serviceBanner->setVisible(false);
    targetLayout->addWidget(m_serviceBanner);

    m_targetHint = makeLabel(QString(), QStringLiteral("helperText"), sectionTarget);
    m_targetHint->setWordWrap(true);
    targetLayout->addWidget(m_targetHint);
    bodyLayout->addWidget(sectionTarget);

    auto *divider = new QFrame(this);
    divider->setObjectName(QStringLiteral("headerLine"));
    divider->setFixedHeight(1);
    bodyLayout->addWidget(divider);
    m_sectionDivider = divider;

    // ── 2. Traffic action & limit ─────────────────────────────────────────
    m_sectionAction = new QWidget(this);
    auto *sectionAction = m_sectionAction;
    auto *actionLayout = new QVBoxLayout(sectionAction);
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(10);

    auto *actionHead = new QHBoxLayout();
    actionHead->setContentsMargins(0, 0, 0, 0);
    actionHead->setSpacing(8);
    actionHead->addWidget(makeLabel(QStringLiteral("2. TRAFFIC ACTION & LIMIT"),
                                    QStringLiteral("sectionLabel"), sectionAction));
    actionHead->addStretch(1);

    m_directionCombo = new QComboBox(sectionAction);
    m_directionCombo->setObjectName(QStringLiteral("directionPill"));
    m_directionCombo->setCursor(Qt::PointingHandCursor);
    m_directionCombo->setFixedHeight(24);
    m_directionCombo->addItem(QStringLiteral("Direction: Download"),
                              static_cast<int>(NetworkDirection::Download));
    m_directionCombo->addItem(QStringLiteral("Direction: Upload"),
                              static_cast<int>(NetworkDirection::Upload));
    m_directionCombo->addItem(QStringLiteral("Direction: Both"),
                              static_cast<int>(NetworkDirection::Both));
    m_directionCombo->setCurrentIndex(2);
    actionHead->addWidget(m_directionCombo);
    actionLayout->addLayout(actionHead);

    auto *actionRow = new QHBoxLayout();
    actionRow->setContentsMargins(0, 0, 0, 0);
    actionRow->setSpacing(8);

    m_actionGroup = new QButtonGroup(this);
    m_actionGroup->setExclusive(true);

    struct CardSpec
    {
        NetworkPolicy::Action action;
        int glyph;
        const char *label;
        const char *accent;
    };
    const CardSpec cards[] = {
        {NetworkPolicy::Action::Throttle, GlyphBolt, "Throttle", "#3B82F6"},
        {NetworkPolicy::Action::Block, GlyphBan, "Block", "#F43F5E"},
        {NetworkPolicy::Action::Allow, GlyphCheck, "Allow", "#10B981"},
    };
    for (const CardSpec &spec : cards) {
        auto *card = new PolicyActionCard(
            spec.glyph, QString::fromLatin1(spec.label), QColor(spec.accent),
            sectionAction);
        m_actionGroup->addButton(card, static_cast<int>(spec.action));
        m_actionCards.append(card);
        actionRow->addWidget(card, 1);
    }
    actionLayout->addLayout(actionRow);

    // Advisory actions are kept, but secondary: the mockup leads with the three
    // enforcement actions and these three do not create a rule or limit.
    auto *advisoryRow = new QHBoxLayout();
    advisoryRow->setContentsMargins(0, 0, 0, 0);
    advisoryRow->setSpacing(6);
    advisoryRow->addWidget(makeLabel(QStringLiteral("Advisory:"),
                                     QStringLiteral("helperText"), sectionAction));
    const QList<QPair<NetworkPolicy::Action, QString>> advisory = {
        {NetworkPolicy::Action::Notify, QStringLiteral("Notify")},
        {NetworkPolicy::Action::Ask, QStringLiteral("Ask")},
        {NetworkPolicy::Action::NoAction, QStringLiteral("No action")},
    };
    for (const auto &item : advisory) {
        auto *chip = new QPushButton(item.second, sectionAction);
        chip->setObjectName(QStringLiteral("advisoryChip"));
        chip->setCheckable(true);
        chip->setCursor(Qt::PointingHandCursor);
        chip->setFixedHeight(20);
        m_actionGroup->addButton(chip, static_cast<int>(item.first));
        advisoryRow->addWidget(chip);
    }
    advisoryRow->addStretch(1);
    actionLayout->addLayout(advisoryRow);

    // Kept so an existing Schedule policy can round-trip through the editor.
    auto *scheduleAction = new QPushButton(sectionAction);
    scheduleAction->setCheckable(true);
    scheduleAction->setVisible(false);
    m_actionGroup->addButton(scheduleAction, static_cast<int>(NetworkPolicy::Action::Schedule));

    m_rateContainer = new QWidget(sectionAction);
    auto *rateLayout = new QVBoxLayout(m_rateContainer);
    rateLayout->setContentsMargins(0, 0, 0, 0);
    rateLayout->setSpacing(6);

    auto *rateHead = new QHBoxLayout();
    rateHead->setContentsMargins(0, 0, 0, 0);
    rateHead->setSpacing(4);
    rateHead->addWidget(makeLabel(QStringLiteral("Bandwidth Speed Limit"),
                                  QStringLiteral("fieldLabel"), m_rateContainer));
    rateHead->addStretch(1);
    for (int preset : {50, 250, 500, 1024}) {
        auto *chip = new QPushButton(QString::number(preset), m_rateContainer);
        chip->setObjectName(QStringLiteral("presetChip"));
        chip->setCursor(Qt::PointingHandCursor);
        chip->setFixedHeight(20);
        connect(chip, &QPushButton::clicked, this, [this, preset]() {
            m_rateEdit->setText(QString::number(preset));
            m_rateEdit->setFocus();
            m_rateEdit->selectAll();
        });
        rateHead->addWidget(chip);
    }
    rateLayout->addLayout(rateHead);

    m_rateField = new QFrame(m_rateContainer);
    m_rateField->setObjectName(QStringLiteral("rateField"));
    m_rateField->setFixedHeight(38);
    auto *rateFieldLayout = new QHBoxLayout(m_rateField);
    rateFieldLayout->setContentsMargins(14, 0, 6, 0);
    rateFieldLayout->setSpacing(6);
    m_rateEdit = new QLineEdit(m_rateField);
    m_rateEdit->setObjectName(QStringLiteral("rateInput"));
    m_rateEdit->setFrame(false);
    m_rateEdit->setValidator(new QIntValidator(1, 1000000, m_rateEdit));
    m_rateEdit->setText(QStringLiteral("400"));
    m_rateEdit->setToolTip(QStringLiteral(
        "The limit this policy enforces, applied to downloads and uploads "
        "for the target."));
    m_rateEdit->installEventFilter(this);
    rateFieldLayout->addWidget(m_rateEdit, 1);
    auto *unit = makeLabel(QStringLiteral("KB/s"), QStringLiteral("rateUnit"), m_rateField);
    rateFieldLayout->addWidget(unit);
    rateLayout->addWidget(m_rateField);
    actionLayout->addWidget(m_rateContainer);

    bodyLayout->addWidget(sectionAction);

    // ── 3. Schedule, expiration & note ────────────────────────────────────
    m_accordion = new QFrame(this);
    m_accordion->setObjectName(QStringLiteral("accordion"));
    auto *accordionLayout = new QVBoxLayout(m_accordion);
    accordionLayout->setContentsMargins(0, 0, 0, 0);
    accordionLayout->setSpacing(0);

    m_accordionHeader = new QPushButton(m_accordion);
    m_accordionHeader->setObjectName(QStringLiteral("accordionHeader"));
    m_accordionHeader->setCursor(Qt::PointingHandCursor);
    m_accordionHeader->setFixedHeight(40);
    auto *accordionHead = new QHBoxLayout(m_accordionHeader);
    accordionHead->setContentsMargins(14, 0, 14, 0);
    accordionHead->setSpacing(8);
    m_clockIcon = new QLabel(m_accordionHeader);
    m_clockIcon->setFixedSize(16, 16);
    m_clockIcon->setAttribute(Qt::WA_TransparentForMouseEvents);
    accordionHead->addWidget(m_clockIcon);
    auto *accordionTitle = makeLabel(QStringLiteral("Schedule, Expiration & Note"),
                                     QStringLiteral("accordionTitle"),
                                     m_accordionHeader);
    accordionTitle->setAttribute(Qt::WA_TransparentForMouseEvents);
    accordionHead->addWidget(accordionTitle);
    m_accordionStatus = makeLabel(QString(), QStringLiteral("accordionStatus"),
                                  m_accordionHeader);
    m_accordionStatus->setAttribute(Qt::WA_TransparentForMouseEvents);
    accordionHead->addWidget(m_accordionStatus);
    accordionHead->addStretch(1);
    m_chevron = new QLabel(m_accordionHeader);
    m_chevron->setFixedSize(16, 16);
    m_chevron->setAttribute(Qt::WA_TransparentForMouseEvents);
    accordionHead->addWidget(m_chevron);
    accordionLayout->addWidget(m_accordionHeader);

    m_accordionBody = new QWidget(m_accordion);
    m_accordionBody->setObjectName(QStringLiteral("accordionBody"));
    m_accordionBody->setMaximumHeight(0);
    auto *accordionBodyLayout = new QVBoxLayout(m_accordionBody);
    accordionBodyLayout->setContentsMargins(14, 0, 14, 14);
    accordionBodyLayout->setSpacing(10);

    auto *accordionLine = new QFrame(m_accordionBody);
    accordionLine->setObjectName(QStringLiteral("accordionLine"));
    accordionLine->setFixedHeight(1);
    accordionBodyLayout->addWidget(accordionLine);

    accordionBodyLayout->addWidget(makeLabel(QStringLiteral("Recurring Active Window"),
                                             QStringLiteral("fieldLabel"),
                                             m_accordionBody));
    m_scheduleCombo = new QComboBox(m_accordionBody);
    m_scheduleCombo->setObjectName(QStringLiteral("fieldCombo"));
    m_scheduleCombo->setCursor(Qt::PointingHandCursor);
    m_scheduleCombo->setFixedHeight(34);
    m_scheduleCombo->addItem(QStringLiteral("Always in force (24/7)"), QString());
    m_scheduleCombo->addItem(QStringLiteral("Work hours (Mon–Fri, 09:00–17:00)"),
                             QStringLiteral("work-hours"));
    m_scheduleCombo->addItem(QStringLiteral("Overnight (Daily, 22:00–06:00)"),
                             QStringLiteral("overnight"));
    m_scheduleCombo->addItem(QStringLiteral("Custom schedule window..."),
                             QStringLiteral("custom"));
    accordionBodyLayout->addWidget(m_scheduleCombo);

    m_customScheduleWrap = new QWidget(m_accordionBody);
    auto *customLayout = new QVBoxLayout(m_customScheduleWrap);
    customLayout->setContentsMargins(0, 0, 0, 0);
    customLayout->setSpacing(0);
    m_customScheduleEdit = new QLineEdit(m_customScheduleWrap);
    m_customScheduleEdit->setObjectName(QStringLiteral("monoField"));
    m_customScheduleEdit->setFixedHeight(34);
    m_customScheduleEdit->setPlaceholderText(
        QStringLiteral("e.g. Mon,Wed,Fri 18:00-23:00"));
    customLayout->addWidget(m_customScheduleEdit);
    m_customScheduleWrap->setVisible(false);
    accordionBodyLayout->addWidget(m_customScheduleWrap);

    m_expiresCheck = new PolicyCheckBox(
        QStringLiteral("Automatically expire policy"), m_accordionBody);
    accordionBodyLayout->addWidget(m_expiresCheck);

    m_expirationWrap = new QWidget(m_accordionBody);
    auto *expiryLayout = new QVBoxLayout(m_expirationWrap);
    expiryLayout->setContentsMargins(0, 0, 0, 0);
    expiryLayout->setSpacing(0);
    m_expirationEdit = new QDateTimeEdit(
        QDateTime::currentDateTime().addSecs(3600), m_expirationWrap);
    m_expirationEdit->setObjectName(QStringLiteral("expirationEdit"));
    m_expirationEdit->setFixedHeight(34);
    m_expirationEdit->setCalendarPopup(true);
    m_expirationEdit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm"));
    expiryLayout->addWidget(m_expirationEdit);
    m_expirationWrap->setVisible(false);
    accordionBodyLayout->addWidget(m_expirationWrap);

    accordionBodyLayout->addWidget(makeLabel(QStringLiteral("Note / Reason"),
                                             QStringLiteral("fieldLabel"),
                                             m_accordionBody));
    m_descriptionEdit = new QLineEdit(m_accordionBody);
    m_descriptionEdit->setObjectName(QStringLiteral("noteInput"));
    m_descriptionEdit->setFixedHeight(34);
    m_descriptionEdit->setPlaceholderText(
        QStringLiteral("Optional description (e.g. Prevent background sync spikes)"));
    accordionBodyLayout->addWidget(m_descriptionEdit);

    accordionLayout->addWidget(m_accordionBody);
    bodyLayout->addWidget(m_accordion);

    // ── 4. Live impact preview ────────────────────────────────────────────
    m_impactCard = new QFrame(this);
    m_impactCard->setObjectName(QStringLiteral("impactCard"));
    auto *impactLayout = new QVBoxLayout(m_impactCard);
    impactLayout->setContentsMargins(14, 12, 14, 12);
    impactLayout->setSpacing(8);

    auto *impactHead = new QHBoxLayout();
    impactHead->setContentsMargins(0, 0, 0, 0);
    impactHead->setSpacing(6);
    m_eyeIcon = new QLabel(m_impactCard);
    m_eyeIcon->setFixedSize(14, 14);
    impactHead->addWidget(m_eyeIcon);
    impactHead->addWidget(makeLabel(QStringLiteral("LIVE POLICY SUMMARY"),
                                    QStringLiteral("impactCaption"), m_impactCard));
    impactHead->addStretch(1);
    m_enabledLabel = makeLabel(QStringLiteral("Enabled"),
                               QStringLiteral("enabledState"), m_impactCard);
    impactHead->addWidget(m_enabledLabel);
    m_enabledSwitch = new PolicyToggleSwitch(m_impactCard);
    m_enabledSwitch->setChecked(true);
    impactHead->addWidget(m_enabledSwitch);
    impactLayout->addLayout(impactHead);

    m_impactLabel = makeLabel(QString(), QStringLiteral("impactSummary"), m_impactCard);
    m_impactLabel->setWordWrap(true);
    m_impactLabel->setTextFormat(Qt::RichText);
    m_impactLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    impactLayout->addWidget(m_impactLabel);

    m_enforcementLabel = makeLabel(QString(), QStringLiteral("enforcementLabel"),
                                   m_impactCard);
    m_enforcementLabel->setWordWrap(true);
    impactLayout->addWidget(m_enforcementLabel);
    bodyLayout->addWidget(m_impactCard);
    // Anchor the content to the top of the scroll body. Without this the layout
    // spreads any spare height across the labels, which pushed the helper text
    // into the middle of the card on the single-section wizard steps.
    bodyLayout->addStretch(1);

    // ── Connections ───────────────────────────────────────────────────────
    connect(m_browseButton, &QPushButton::clicked,
            this, &PolicyRuleForm::browseForExecutable);

    connect(m_scopeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() {
        updateScopeTarget();
        updateImpactPreview();
    });
    connect(m_targetEdit, &QLineEdit::textChanged, this, [this]() {
        updateServiceBanner();
        updateImpactPreview();
    });

    connect(m_actionGroup, &QButtonGroup::buttonToggled, this,
            [this](QAbstractButton *, bool checked) {
        if (checked) updateActionControls();
    });
    connect(m_directionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyRuleForm::updateImpactPreview);
    connect(m_rateEdit, &QLineEdit::textChanged,
            this, &PolicyRuleForm::updateImpactPreview);

    connect(m_scheduleCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() {
        const bool custom = m_scheduleCombo->currentData().toString() ==
                            QLatin1String("custom");
        m_customScheduleWrap->setVisible(custom);
        if (custom && m_customScheduleEdit->text().trimmed().isEmpty())
            m_customScheduleEdit->setFocus();
        updateImpactPreview();
    });
    connect(m_customScheduleEdit, &QLineEdit::textChanged,
            this, &PolicyRuleForm::updateImpactPreview);
    connect(m_expiresCheck, &QAbstractButton::toggled, this, [this](bool checked) {
        m_expirationWrap->setVisible(checked);
        updateImpactPreview();
    });
    connect(m_expirationEdit, &QDateTimeEdit::dateTimeChanged,
            this, &PolicyRuleForm::updateImpactPreview);

    connect(m_enabledSwitch, &QAbstractButton::toggled, this, [this](bool enabled) {
        m_enabledLabel->setText(enabled ? QStringLiteral("Enabled")
                                        : QStringLiteral("Disabled"));
        updateImpactPreview();
    });
    connect(m_accordionHeader, &QPushButton::clicked,
            this, &PolicyRuleForm::toggleAccordion);

    m_accordionAnim = new QPropertyAnimation(m_accordionBody, "maximumHeight", this);
    m_accordionAnim->setDuration(240);
    m_accordionAnim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_accordionAnim, &QPropertyAnimation::valueChanged, this, [this]() {
        emit layoutChanged();
    });
    connect(m_accordionAnim, &QPropertyAnimation::finished, this, [this]() {
        if (m_accordionOpen)
            m_accordionBody->setMaximumHeight(QWIDGETSIZE_MAX);
    });
}

void PolicyRuleForm::setStep(int step)
{
    m_step = step;
    const bool all = step == 0;
    const bool review = step == 3;

    m_sectionTarget->setVisible(all || step == 1);
    // The divider exists only to separate stacked sections; a single wizard
    // step has nothing to separate from.
    m_sectionDivider->setVisible(all);
    m_sectionAction->setVisible(all || step == 2);
    m_accordion->setVisible(all || review);
    m_impactCard->setVisible(all || review);

    // In the review step the schedule fields are the point of the step, so the
    // collapsible header (and its chevron) is dropped and the body is opened
    // without animating.
    m_accordionHeader->setVisible(!review);
    if (review && !m_accordionOpen) {
        m_accordionAnim->stop();
        m_accordionOpen = true;
        m_accordionBody->setMaximumHeight(QWIDGETSIZE_MAX);
    }
    applyTheme();
    emit layoutChanged();
}

void PolicyRuleForm::loadPolicy(const NetworkPolicy &policy)
{
    PolicyScopeKind scope = PolicyScopeKind::ExecutablePath;
    policyScopeKindFromKey(policy.scope, &scope);
    const int scopeIndex = m_scopeCombo->findData(static_cast<int>(scope));
    if (scopeIndex >= 0) m_scopeCombo->setCurrentIndex(scopeIndex);
    updateScopeTarget();

    setAction(policy.action);
    const int directionIndex = m_directionCombo->findData(static_cast<int>(policy.direction));
    if (directionIndex >= 0) m_directionCombo->setCurrentIndex(directionIndex);
    if (policy.rateBitsPerSecond > 0) {
        const qint64 kbps = qRound64(static_cast<double>(policy.rateBitsPerSecond) / 8000.0);
        m_rateEdit->setText(QString::number(kbps));
    }
    setScheduleValue(policy.schedule);
    m_expiresCheck->setChecked(policy.expiration.isValid());
    m_expirationWrap->setVisible(policy.expiration.isValid());
    if (policy.expiration.isValid()) m_expirationEdit->setDateTime(policy.expiration);
    m_enabledSwitch->setChecked(policy.enabled);
    m_descriptionEdit->setText(policy.description);
    updateActionControls();
    updateImpactPreview();
}

void PolicyRuleForm::applyTheme()
{
    const DialogColors c = dialogColors(ThemeManager::instance().isDark());
    const bool dark = ThemeManager::instance().isDark();

    m_browseButton->setIcon(QIcon(glyphPixmap(GlyphFolder, 16, c.muted, 1.6)));
    m_browseButton->setIconSize(QSize(16, 16));
    m_clockIcon->setPixmap(glyphPixmap(GlyphClock, 16, c.muted, 1.6));
    m_eyeIcon->setPixmap(glyphPixmap(GlyphEye, 14, c.accentText, 1.6));
    m_chevron->setPixmap(glyphPixmap(m_accordionOpen ? GlyphChevronUp : GlyphChevronDown,
                                     16, c.muted, 1.8));

    const QColor actionBg = dark ? QColor("#11151D") : c.field;
    const QColor actionText = dark ? c.muted : QColor("#475569");
    for (PolicyActionCard *card : m_actionCards)
        card->setColors(actionBg, c.fieldBorder, actionText, c.hover, c.accentText);

    m_enabledSwitch->setColors(dark ? QColor("#334155") : QColor("#CBD5E1"),
                               c.accentSolid, QColor("#FFFFFF"));
    m_expiresCheck->setColors(c.text, c.fieldBorder, c.accentSolid, c.field);

    // The mockup tracks its uppercase labels; Qt style sheets cannot set
    // letter spacing, so apply it to the font once the sheet has been styled.
    for (QLabel *label : findChildren<QLabel *>(QStringLiteral("sectionLabel"))) {
        QFont f = label->font();
        f.setLetterSpacing(QFont::AbsoluteSpacing, 0.6);
        label->setFont(f);
    }
    if (QLabel *caption = findChild<QLabel *>(QStringLiteral("impactCaption"))) {
        QFont f = caption->font();
        f.setLetterSpacing(QFont::AbsoluteSpacing, 0.6);
        caption->setFont(f);
    }

    m_impactCard->setProperty("enabled", m_enabledSwitch->isChecked());
    repolish(m_impactCard);

    updateImpactPreview();
}

void PolicyRuleForm::updateScopeTarget()
{
    const PolicyScopeKind scope = currentScope();

    // The target follows the scope: switching to publisher must not silently
    // keep a path in the field and save a policy that matches nothing.
    switch (scope) {
    case PolicyScopeKind::Pid:
        m_targetEdit->setReadOnly(true);
        m_targetEdit->setPlaceholderText(QString());
        m_browseButton->setVisible(false);
        if (m_target.pid == 0)
            m_targetEdit->clear();
        else if (m_target.processName.isEmpty())
            m_targetEdit->setText(QStringLiteral("PID %1").arg(m_target.pid));
        else
            m_targetEdit->setText(QStringLiteral("PID %1 (%2)")
                                      .arg(m_target.pid)
                                      .arg(m_target.processName));
        m_targetHint->setText(
            QStringLiteral("Applies only while this process instance is running."));
        break;
    case PolicyScopeKind::ExecutablePath:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setPlaceholderText(
            QStringLiteral("e.g. C:\\Program Files\\App\\app.exe"));
        m_browseButton->setVisible(true);
        m_targetEdit->setText(m_target.executablePath);
        m_targetHint->setText(
            QStringLiteral("Applies to this executable file now and on future launches."));
        break;
    case PolicyScopeKind::Publisher:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setPlaceholderText(QStringLiteral("e.g. Google LLC"));
        m_browseButton->setVisible(false);
        m_targetEdit->setText(m_target.publisher);
        m_targetHint->setText(
            QStringLiteral("Applies to every process signed by this publisher, including "
                           "software you have not seen yet."));
        break;
    case PolicyScopeKind::Service:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setPlaceholderText(QStringLiteral("e.g. wuauserv"));
        m_browseButton->setVisible(false);
        m_targetEdit->setText(m_target.serviceName);
        m_targetHint->setText(
            QStringLiteral("Applies to this Windows service and the processes that host it."));
        break;
    case PolicyScopeKind::ApplicationGroup:
        m_targetEdit->setReadOnly(true);
        m_targetEdit->setPlaceholderText(QString());
        m_browseButton->setVisible(false);
        m_targetEdit->setText(m_target.groupName.isEmpty()
            ? m_target.groupId
            : QStringLiteral("%1 (%2)").arg(m_target.groupName, m_target.groupId));
        m_targetHint->setText(
            QStringLiteral("Applies to every current and future member of this activity group."));
        break;
    }

    updateServiceBanner();
}

void PolicyRuleForm::updateServiceBanner()
{
    const bool serviceScope = currentScope() == PolicyScopeKind::Service;
    const bool hostProcess =
        m_targetEdit->text().contains(QStringLiteral("svchost.exe"), Qt::CaseInsensitive);
    const bool show = serviceScope || hostProcess;

    m_serviceBanner->setVisible(show);
    m_targetHint->setVisible(!show);
    if (!show) return;

    QString service = serviceScope ? m_targetEdit->text().trimmed()
                                   : m_target.serviceName;
    if (service.isEmpty()) service = QStringLiteral("the selected service");
    m_serviceBanner->setText(
        QStringLiteral("<span style=\"font-weight:600;\">System Host Exception:</span> "
                       "<span style=\"font-family:'JetBrains Mono';\">svchost.exe</span> "
                       "hosts multiple Windows services. Scoped specifically to "
                       "<b>%1</b> so other system services aren't disrupted.")
            .arg(service.toHtmlEscaped()));
}

void PolicyRuleForm::updateActionControls()
{
    const NetworkPolicy::Action action = currentAction();
    const bool shaping = action == NetworkPolicy::Action::Throttle ||
                         action == NetworkPolicy::Action::Schedule;
    m_rateContainer->setVisible(shaping);
    // The scroll area does not hear layout requests from its content widget, so
    // tell its host the preferred height changed.
    emit layoutChanged();
    // Direction is stored either way, but only shaping uses it in this build.
    m_directionCombo->setEnabled(shaping);
    updateImpactPreview();
}

void PolicyRuleForm::updateImpactPreview()
{
    if (!m_impactLabel) return;

    const bool enabled = m_enabledSwitch->isChecked();
    m_impactCard->setProperty("enabled", enabled);
    repolish(m_impactCard);

    m_impactLabel->setText(previewHtml());
    m_enforcementLabel->setText(enforcementText());

    const NetworkPolicy::Action action = currentAction();
    const bool advisory = action == NetworkPolicy::Action::Notify ||
                          action == NetworkPolicy::Action::Ask ||
                          action == NetworkPolicy::Action::NoAction;
    const bool warning = !policyScopeEnforcedByThisBuild(currentScope()) || advisory;
    m_enforcementLabel->setProperty("warning", warning);
    repolish(m_enforcementLabel);

    updateAccordionStatus();
}

void PolicyRuleForm::updateAccordionStatus()
{
    if (!m_accordionStatus) return;
    const bool configured = !scheduleValue().isEmpty() || m_expiresCheck->isChecked();
    m_accordionStatus->setText(configured
        ? QStringLiteral("(Configured)")
        : QStringLiteral("(Optional — Always active)"));
    m_accordionStatus->setProperty("configured", configured);
    repolish(m_accordionStatus);
}

void PolicyRuleForm::toggleAccordion()
{
    if (m_accordionAnim->state() == QPropertyAnimation::Running)
        m_accordionAnim->stop();

    int start = m_accordionBody->maximumHeight();
    if (start == QWIDGETSIZE_MAX) start = m_accordionBody->height();
    int end = 0;

    if (!m_accordionOpen) {
        m_accordionOpen = true;
        m_accordionBody->setMaximumHeight(QWIDGETSIZE_MAX);
        end = m_accordionBody->sizeHint().height();
        m_accordionBody->setMaximumHeight(start);
    } else {
        m_accordionOpen = false;
        start = m_accordionBody->height();
    }

    m_accordionAnim->setStartValue(start);
    m_accordionAnim->setEndValue(end);
    m_accordionAnim->start();

    m_chevron->setPixmap(glyphPixmap(
        m_accordionOpen ? GlyphChevronUp : GlyphChevronDown, 16,
        dialogColors(ThemeManager::instance().isDark()).muted, 1.8));
}

void PolicyRuleForm::setScheduleValue(const QString &schedule)
{
    const QString value = schedule.trimmed();
    int index = m_scheduleCombo->findData(value);
    if (value.isEmpty()) {
        index = 0;
    } else if (index < 0) {
        index = m_scheduleCombo->findData(QStringLiteral("custom"));
        m_customScheduleEdit->setText(value);
        m_customScheduleWrap->setVisible(true);
    }
    if (index >= 0) m_scheduleCombo->setCurrentIndex(index);
}

QString PolicyRuleForm::scheduleValue() const
{
    if (m_scheduleCombo->currentData().toString() == QLatin1String("custom"))
        return m_customScheduleEdit->text().trimmed();
    return m_scheduleCombo->currentData().toString().trimmed();
}

QString PolicyRuleForm::previewHtml() const
{
    const DialogColors c = dialogColors(ThemeManager::instance().isDark());
    const PolicyScopeKind scope = currentScope();
    // PID and group policies store an opaque id; the header badge carries the
    // friendly "name (PID)" form, so reuse it instead of showing the raw id.
    const QString rawTarget = (scope == PolicyScopeKind::Pid ||
                               scope == PolicyScopeKind::ApplicationGroup)
        ? m_targetLabel
        : targetForScope();
    QString targetName;
    if (scope == PolicyScopeKind::ExecutablePath)
        targetName = QFileInfo(rawTarget).fileName();
    else
        targetName = rawTarget.trimmed();
    if (targetName.isEmpty()) targetName = QStringLiteral("the selected target");

    const QString targetSpan = QStringLiteral(
        "<span style=\"font-family:'JetBrains Mono'; font-size:11px;\">%1</span>")
        .arg(targetName.toHtmlEscaped());

    const NetworkPolicy::Action action = currentAction();
    const NetworkDirection direction = static_cast<NetworkDirection>(
        m_directionCombo->currentData().toInt());
    const qint64 kbps = m_rateEdit->text().toLongLong();

    QString directionPhrase;
    switch (direction) {
    case NetworkDirection::Download: directionPhrase = QStringLiteral("for downloads"); break;
    case NetworkDirection::Upload: directionPhrase = QStringLiteral("for uploads"); break;
    case NetworkDirection::Both: directionPhrase = QStringLiteral("in both directions"); break;
    }

    QString actionPhrase;
    switch (action) {
    case NetworkPolicy::Action::Throttle:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Throttle</b> traffic for %2 to "
            "<b>%3 KB/s</b> %4")
            .arg(c.accentText.name(), targetSpan, QString::number(kbps),
                 directionPhrase);
        break;
    case NetworkPolicy::Action::Block:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Block</b> all inbound and outbound traffic for %2")
            .arg(c.dangerText.name(), targetSpan);
        break;
    case NetworkPolicy::Action::Allow:
        actionPhrase = QStringLiteral(
            "Explicitly <b style=\"color:%1;\">Allow</b> all inbound and outbound "
            "traffic for %2")
            .arg(c.successText.name(), targetSpan);
        break;
    case NetworkPolicy::Action::Notify:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Notify</b> you about traffic for %2")
            .arg(c.accentText.name(), targetSpan);
        break;
    case NetworkPolicy::Action::Ask:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Ask</b> before allowing traffic for %2")
            .arg(c.accentText.name(), targetSpan);
        break;
    case NetworkPolicy::Action::NoAction:
        actionPhrase = QStringLiteral("Take no action for %1").arg(targetSpan);
        break;
    case NetworkPolicy::Action::Schedule:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Apply the scheduled limit</b> to %2")
            .arg(c.accentText.name(), targetSpan);
        break;
    }

    const QString schedule = scheduleValue();
    QString schedulePhrase = QStringLiteral("active immediately");
    if (schedule == QLatin1String("work-hours")) {
        schedulePhrase = QStringLiteral(
            "active during <b>work hours (Mon–Fri, 09:00–17:00)</b>");
    } else if (schedule == QLatin1String("overnight")) {
        schedulePhrase = QStringLiteral("active <b>overnight (22:00–06:00)</b>");
    } else if (!schedule.isEmpty()) {
        schedulePhrase = QStringLiteral(
            "active during <span style=\"font-family:'JetBrains Mono'; font-size:11px;\">%1</span>")
            .arg(schedule.toHtmlEscaped());
    }

    QString expirationPhrase = QStringLiteral("with no expiration");
    if (m_expiresCheck->isChecked()) {
        expirationPhrase = QStringLiteral("until <b>%1</b>")
            .arg(m_expirationEdit->dateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm")));
    }

    const bool enabled = m_enabledSwitch->isChecked();
    if (!enabled) {
        return QStringLiteral(
            "<b>Saved inactive</b> — will %1, %2 %3 once enabled.")
            .arg(actionPhrase, schedulePhrase, expirationPhrase);
    }
    return QStringLiteral("This will %1, %2 %3.")
        .arg(actionPhrase, schedulePhrase, expirationPhrase);
}

QString PolicyRuleForm::enforcementText() const
{
    const NetworkPolicy::Action action = currentAction();
    if (action == NetworkPolicy::Action::Notify ||
        action == NetworkPolicy::Action::Ask ||
        action == NetworkPolicy::Action::NoAction) {
        return QStringLiteral("Advisory only: this action does not change firewall "
                              "or bandwidth state in this build.");
    }

    return policyScopeEnforcementNote(currentScope());
}

PolicyScopeKind PolicyRuleForm::currentScope() const
{
    return static_cast<PolicyScopeKind>(m_scopeCombo->currentData().toInt());
}

NetworkPolicy::Action PolicyRuleForm::currentAction() const
{
    if (!m_actionGroup) return NetworkPolicy::Action::Throttle;
    const int id = m_actionGroup->checkedId();
    if (id < 0) return NetworkPolicy::Action::Throttle;
    return static_cast<NetworkPolicy::Action>(id);
}

void PolicyRuleForm::setAction(NetworkPolicy::Action action)
{
    if (QAbstractButton *button = m_actionGroup->button(static_cast<int>(action)))
        button->setChecked(true);
}

PolicyImpact PolicyRuleForm::currentImpact() const
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
    impact.direction = direction();
    impact.rateBitsPerSecond = impact.action == NetworkPolicy::Action::Throttle
        ? rateBitsPerSecond()
        : 0;
    impact.expiration = expiresChecked() ? expiration() : QDateTime();
    impact.schedule = scheduleValue();
    impact.enabled = enabled();
    return impact;
}

QString PolicyRuleForm::targetForScope() const
{
    switch (currentScope()) {
    case PolicyScopeKind::Pid: return QString::number(m_target.pid);
    case PolicyScopeKind::ApplicationGroup: return m_target.groupId;
    default: return m_targetEdit->text().trimmed();
    }
}

NetworkDirection PolicyRuleForm::direction() const
{
    return static_cast<NetworkDirection>(m_directionCombo->currentData().toInt());
}

qint64 PolicyRuleForm::rateKbps() const
{
    return m_rateEdit->text().toLongLong();
}

quint64 PolicyRuleForm::rateBitsPerSecond() const
{
    return static_cast<quint64>(qRound64(m_rateEdit->text().toDouble() * 8000.0));
}

bool PolicyRuleForm::expiresChecked() const
{
    return m_expiresCheck->isChecked();
}

QDateTime PolicyRuleForm::expiration() const
{
    return m_expirationEdit->dateTime();
}

QString PolicyRuleForm::description() const
{
    return m_descriptionEdit->text().trimmed();
}

bool PolicyRuleForm::enabled() const
{
    return m_enabledSwitch->isChecked();
}

QWidget *PolicyRuleForm::initialFocusWidget() const
{
    // Start on the field the dialog is about. When the scope makes the target
    // read-only (PID or activity group), the action choice is the first thing
    // the user can actually change.
    QWidget *initial = m_targetEdit;
    if (m_targetEdit->isReadOnly() && m_actionGroup &&
        m_actionGroup->checkedButton()) {
        initial = m_actionGroup->checkedButton();
    }
    return initial;
}

void PolicyRuleForm::focusTargetField()
{
    m_targetEdit->setFocus();
}

void PolicyRuleForm::focusRateField()
{
    m_rateEdit->setFocus();
}

void PolicyRuleForm::focusExpirationField()
{
    m_expirationEdit->setFocus();
}

void PolicyRuleForm::browseForExecutable()
{
    const QString start = m_targetEdit->text().trimmed().isEmpty()
        ? m_target.executablePath
        : m_targetEdit->text().trimmed();
    const QString file = QFileDialog::getOpenFileName(
        this, QStringLiteral("Select executable"), start,
        QStringLiteral("Executables (*.exe);;All files (*.*)"));
    if (!file.isEmpty()) {
        m_targetEdit->setText(QDir::toNativeSeparators(file));
        m_targetEdit->setFocus();
    }
}

bool PolicyRuleForm::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == m_targetEdit || watched == m_rateEdit) {
        QFrame *frame = watched == m_targetEdit ? m_targetField : m_rateField;
        if (event->type() == QEvent::FocusIn) {
            frame->setProperty("focused", true);
            repolish(frame);
        } else if (event->type() == QEvent::FocusOut) {
            frame->setProperty("focused", false);
            repolish(frame);
        }
    }

    return QWidget::eventFilter(watched, event);
}
