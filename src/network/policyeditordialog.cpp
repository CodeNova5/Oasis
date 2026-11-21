/**
 * @file   policyeditordialog.cpp
 * @brief  Window chrome and validation for the network policy editor.
 *
 * The frameless card, its header, the sticky footer and the toast live here;
 * everything the policy is made of is in PolicyRuleForm. Validation runs on
 * accept and reports through the toast, so the form stays presentation-only.
 *
 * @author Codebuff
 */

#include "policyeditordialog.h"

#include "policyeditorstyle.h"
#include "policyschedule.h"
#include "ui/theme/thememanager.h"

#include <QDateTime>
#include <QEvent>
#include <QFileInfo>
#include <QFontMetrics>
#include <QGraphicsDropShadowEffect>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLayout>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QResizeEvent>
#include <QScreen>
#include <QScrollArea>
#include <QStyle>
#include <QShowEvent>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>
#include <QWindow>

using namespace PolicyEditorStyle;

namespace {
QString dialogStyleSheet(const DialogColors &c)
{
    QString s = QStringLiteral(R"QSS(
QDialog { background: transparent; }
QFrame#policyCard { background: {card}; border: 1px solid {border}; border-radius: 16px; }
QWidget { font-family: "Inter"; font-size: 12px; color: {text}; }
QFrame#headerIconTile { background: {accentSoft}; border: 1px solid {accentBorder}; border-radius: 12px; }
QLabel { background: transparent; color: {text}; }
QLabel#dialogTitle { font-size: 14px; font-weight: 700; color: {title}; }
QLabel#dialogSubtitle { font-size: 11px; color: {muted}; }
QLabel#stepNum { border-radius: 9px; font-size: 10px; font-weight: 700; }
QLabel#stepNum[state="current"] { background: {accentSolid}; color: #FFFFFF; }
QLabel#stepNum[state="done"] { background: #10B981; color: #FFFFFF; }
QLabel#stepNum[state="todo"] { background: {chip}; color: {muted}; }
QLabel#stepTitle { font-size: 11px; font-weight: 600; color: {muted}; }
QLabel#stepTitle[state="current"] { color: {title}; }
QLabel#stepTitle[state="done"] { color: #10B981; }
QPushButton#stepPill { background: transparent; border: 1px solid {border}; border-radius: 8px; padding: 0; text-align: left; }
QPushButton#stepPill:hover { background: {hoverSoft}; }
QPushButton#stepPill[state="current"] { background: {accentSoft}; border-color: {accent}; }
QPushButton#stepPill[state="done"] { background: rgba(16, 185, 129, 22); border-color: rgba(16, 185, 129, 75); }
QLabel#processBadge { font-family: "JetBrains Mono"; font-size: 11px; color: {secondary}; background: {field}; border: 1px solid {border}; border-radius: 4px; padding: 1px 6px; }
QFrame#headerLine { background: {border}; border: none; }
QScrollArea { background: transparent; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }
QWidget#dialogBody { background: transparent; }
QScrollBar:vertical { background: transparent; width: 6px; margin: 0; }
QScrollBar::handle:vertical { background: {scroll}; border-radius: 3px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: {scrollHover}; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QLabel#sectionLabel { font-size: 12px; font-weight: 600; color: {muted}; }
QComboBox#scopePill, QComboBox#directionPill { background: {field}; border: 1px solid {border}; border-radius: 12px; padding: 2px 10px; color: {secondary}; font-size: 11px; }
QComboBox#scopePill::drop-down, QComboBox#directionPill::drop-down { width: 0; border: none; }
QComboBox#scopePill::down-arrow, QComboBox#directionPill::down-arrow { width: 0; height: 0; image: none; }
QComboBox#scopePill:disabled, QComboBox#directionPill:disabled { color: {muted}; }
QComboBox QAbstractItemView { background: {card}; color: {text}; border: 1px solid {border}; padding: 4px; outline: 0; selection-background-color: {accentSolid}; selection-color: #FFFFFF; }
QFrame#targetField, QFrame#rateField { background: {field}; border: 1px solid {fieldBorder}; border-radius: 12px; }
QFrame#targetField[focused="true"], QFrame#rateField[focused="true"] { border: 1px solid {accent}; }
QLineEdit#targetInput { background: transparent; border: none; padding: 0; font-family: "JetBrains Mono"; font-size: 12px; color: {text}; selection-background-color: {accentSolid}; selection-color: #FFFFFF; }
QLineEdit#rateInput { background: transparent; border: none; padding: 0; font-family: "JetBrains Mono"; font-size: 14px; font-weight: 600; color: {title}; selection-background-color: {accentSolid}; selection-color: #FFFFFF; }
QLabel#rateUnit { background: {rateUnitBg}; border-radius: 8px; padding: 3px 8px; font-family: "JetBrains Mono"; font-size: 12px; font-weight: 600; color: {secondary}; }
QLabel#helperText { font-size: 11px; color: {muted}; }
QLabel#serviceBanner { font-size: 11px; color: {warningText}; background: {warningSoft}; border: 1px solid {warningBorder}; border-radius: 12px; padding: 8px 10px; }
QLabel#fieldLabel { font-size: 12px; font-weight: 500; color: {secondary}; }
QPushButton#iconButton { background: transparent; border: none; border-radius: 8px; padding: 0; }
QPushButton#iconButton:hover { background: {hover}; }
QPushButton#presetChip, QPushButton#advisoryChip { background: {chip}; border: 1px solid {border}; border-radius: 6px; padding: 1px 8px; font-family: "JetBrains Mono"; font-size: 11px; color: {muted}; }
QPushButton#presetChip:hover, QPushButton#advisoryChip:hover { background: {accentSoft}; color: {accentText}; }
QPushButton#advisoryChip:checked { background: {accentSoft}; border-color: {accent}; color: {accentText}; }
QFrame#accordion { background: {accordionBg}; border: 1px solid {border}; border-radius: 12px; }
QPushButton#accordionHeader { background: transparent; border: none; text-align: left; }
QPushButton#accordionHeader:hover { background: {hoverSoft}; border-radius: 11px; }
QLabel#accordionTitle { font-size: 12px; font-weight: 500; color: {secondary}; }
QLabel#accordionStatus { font-size: 11px; color: {muted}; }
QLabel#accordionStatus[configured="true"] { color: {accentText}; font-weight: 500; }
QFrame#accordionLine { background: {border}; border: none; }
QComboBox#fieldCombo, QLineEdit#noteInput, QLineEdit#monoField, QDateTimeEdit#expirationEdit { background: {field}; border: 1px solid {fieldBorder}; border-radius: 8px; padding: 5px 8px; color: {text}; font-size: 12px; }
QComboBox#fieldCombo:focus, QLineEdit#noteInput:focus, QLineEdit#monoField:focus, QDateTimeEdit#expirationEdit:focus { border-color: {accent}; }
QComboBox#fieldCombo::drop-down { border: none; width: 18px; }
QComboBox#fieldCombo::down-arrow { width: 0; height: 0; image: none; }
QLineEdit#monoField { font-family: "JetBrains Mono"; font-size: 11px; }
QDateTimeEdit#expirationEdit { font-family: "JetBrains Mono"; font-size: 11px; }
QDateTimeEdit#expirationEdit::drop-down { border: none; width: 20px; }
QFrame#identityCard { background: {field}; border: 1px solid {fieldBorder}; border-radius: 12px; }
QFrame#identityIconTile { background: {accentSoft}; border: 1px solid {accentBorder}; border-radius: 12px; }
QLabel#appName { font-size: 12px; font-weight: 700; color: {title}; }
QLabel#appSubtitle { font-size: 11px; color: {muted}; }
QLabel#exceptionBadge { font-family: "JetBrains Mono"; font-size: 10px; color: {warningText}; background: {warningSoft}; border: 1px solid {warningBorder}; border-radius: 4px; padding: 1px 6px; }
QFrame#identityLine { background: {border}; border: none; }
QPushButton#linkButton { background: transparent; border: none; padding: 0; text-align: left; font-size: 11px; font-weight: 500; color: {muted}; }
QPushButton#linkButton:hover { color: {accentText}; }
QLabel#pathValue { font-family: "JetBrains Mono"; font-size: 11px; color: {secondary}; background: {card}; border: 1px solid {border}; border-radius: 8px; padding: 6px 10px; }
QFrame#expiredBanner { background: rgba(227, 107, 112, 26); border: 1px solid rgba(227, 107, 112, 77); border-radius: 12px; }
QLabel#expiredText { font-size: 11px; color: {dangerText}; }
QPushButton#reactivateButton { background: transparent; border: 1px solid rgba(227, 107, 112, 102); border-radius: 8px; padding: 2px 8px; font-size: 11px; font-weight: 600; color: {dangerText}; }
QPushButton#reactivateButton:hover { background: rgba(227, 107, 112, 38); }
QPushButton#actionPill { background: {field}; border: 1px solid {border}; border-radius: 12px; padding: 7px 12px; font-size: 12px; font-weight: 600; color: {secondary}; }
QPushButton#actionPill:hover { background: {hover}; }
QPushButton#actionPill[tone="throttle"]:checked { background: {accentSoft}; border: 2px solid {accent}; color: {accentText}; padding: 6px 11px; }
QPushButton#actionPill[tone="block"]:checked { background: rgba(244, 63, 94, 22); border: 2px solid #F43F5E; color: {dangerText}; padding: 6px 11px; }
QPushButton#actionPill[tone="allow"]:checked { background: rgba(16, 185, 129, 22); border: 2px solid #10B981; color: {successText}; padding: 6px 11px; }
QFrame#accordion[edit="true"] { background: transparent; border: none; }
QFrame#impactCard { background: {impactBg}; border: 1px solid {impactBorder}; border-radius: 12px; }
QFrame#impactCard[enabled="false"] { background: {inactiveBg}; border: 1px solid {inactiveBorder}; }
QLabel#impactCaption { font-size: 11px; font-weight: 600; color: {accentText}; }
QLabel#impactSummary { font-size: 12px; color: {text}; }
QLabel#enabledState { font-size: 11px; font-weight: 500; color: {secondary}; }
QLabel#enforcementLabel { font-size: 11px; color: {muted}; }
QLabel#enforcementLabel[warning="true"] { color: {warningText}; }
QPushButton#cancelButton { background: transparent; border: 1px solid {border}; border-radius: 12px; padding: 8px 16px; color: {secondary}; font-size: 12px; font-weight: 500; }
QPushButton#cancelButton:hover { background: {hover}; }
QPushButton#saveButton { background: {accentSolid}; border: 1px solid {accentSolid}; border-radius: 12px; padding: 8px 16px; color: #FFFFFF; font-size: 12px; font-weight: 600; }
QPushButton#saveButton:hover { background: {accentSolidHover}; border-color: {accentSolidHover}; }
QPushButton#saveButton:pressed { background: {accentPressed}; }
QPushButton#saveButton:focus { border: 1px solid {title}; }
QLabel#toast { background: {toastBg}; color: #FFFFFF; border: 1px solid {toastBorder}; border-radius: 12px; padding: 10px 14px; font-size: 12px; font-weight: 500; }
)QSS");

    struct Token
    {
        const char *name;
        QColor value;
    };
    const Token tokens[] = {
        {"{card}", c.card},
        {"{title}", c.title},
        {"{text}", c.text},
        {"{secondary}", c.secondary},
        {"{muted}", c.muted},
        {"{border}", c.border},
        {"{field}", c.field},
        {"{fieldBorder}", c.fieldBorder},
        {"{hover}", c.hover},
        {"{hoverSoft}", c.hoverSoft},
        {"{accordionBg}", c.accordionBg},
        {"{accent}", c.accent},
        {"{accentHover}", c.accentHover},
        {"{accentSolid}", c.accentSolid},
        {"{accentSolidHover}", c.accentSolidHover},
        {"{accentPressed}", c.accentPressed},
        {"{accentSoft}", c.accentSoft},
        {"{accentBorder}", c.accentBorder},
        {"{accentText}", c.accentText},
        {"{impactBg}", c.impactBg},
        {"{impactBorder}", c.impactBorder},
        {"{inactiveBg}", c.inactiveBg},
        {"{inactiveBorder}", c.inactiveBorder},
        {"{rateUnitBg}", c.rateUnitBg},
        {"{chip}", c.chip},
        {"{scroll}", c.scroll},
        {"{scrollHover}", c.scrollHover},
        {"{warningText}", c.warningText},
        {"{warningSoft}", c.warningSoft},
        {"{warningBorder}", c.warningBorder},
        {"{dangerText}", c.dangerText},
        {"{successText}", c.successText},
        {"{toastBg}", c.toastBg},
        {"{toastBorder}", c.toastBorder},
    };
    for (const Token &token : tokens)
        s.replace(QLatin1String(token.name), css(token.value));
    return s;
}

} // namespace

PolicyEditorDialog::PolicyEditorDialog(const PolicyTarget &target, QWidget *parent)
    : QDialog(parent)
    , m_target(target)
{
    buildUi();
    setWindowTitle(QStringLiteral("Create Network Policy"));
}

PolicyEditorDialog::PolicyEditorDialog(const NetworkPolicy &policy, QWidget *parent)
    : QDialog(parent)
{
    m_editing = true;
    m_policy = policy;
    m_policyId = policy.id;
    m_policySource = policy.source;
    if (policy.expiration.isValid() && policy.expiration <= QDateTime::currentDateTime())
        m_storedExpiration = policy.expiration;

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
    setWindowTitle(QStringLiteral("Edit Policy"));
    m_titleLabel->setText(QStringLiteral("Edit Policy"));
    m_form->loadPolicy(policy);
    m_form->setExpired(policy.expiration);
}

void PolicyEditorDialog::buildUi()
{
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setSizeGripEnabled(false);
    setModal(true);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(0);
    root->setSizeConstraint(QLayout::SetFixedSize);

    m_card = new QFrame(this);
    m_card->setObjectName(QStringLiteral("policyCard"));
    m_card->setFixedWidth(540);
    root->addWidget(m_card, 0, Qt::AlignHCenter);

    const bool dark = ThemeManager::instance().isDark();
    auto *shadow = new QGraphicsDropShadowEffect(m_card);
    shadow->setBlurRadius(48);
    shadow->setOffset(0, 14);
    shadow->setColor(QColor(0, 0, 0, dark ? 180 : 45));
    m_card->setGraphicsEffect(shadow);

    auto *cardLayout = new QVBoxLayout(m_card);
    cardLayout->setContentsMargins(0, 0, 0, 0);
    cardLayout->setSpacing(0);

    // ── Header ────────────────────────────────────────────────────────────
    // Title and step subtitle, then the three-cell stepper, all inside the
    // tinted header block the mock draws above the step body.
    m_header = new QWidget(m_card);
    auto *headerColumn = new QVBoxLayout(m_header);
    headerColumn->setContentsMargins(20, 16, 20, 16);
    // A little more air than the mock's 14 px so the stepper reads as its own
    // block rather than crowding the title line above it.
    headerColumn->setSpacing(18);

    auto *headerRowWidget = new QWidget(m_header);
    auto *headerRow = new QHBoxLayout(headerRowWidget);
    headerRow->setContentsMargins(0, 0, 0, 0);
    headerRow->setSpacing(10);

    auto *iconTile = new QFrame(headerRowWidget);
    iconTile->setObjectName(QStringLiteral("headerIconTile"));
    iconTile->setFixedSize(32, 32);
    auto *iconLayout = new QVBoxLayout(iconTile);
    iconLayout->setContentsMargins(0, 0, 0, 0);
    m_headerIcon = new QLabel(iconTile);
    m_headerIcon->setAlignment(Qt::AlignCenter);
    m_headerIcon->setFixedSize(16, 16);
    iconLayout->addWidget(m_headerIcon, 0, Qt::AlignCenter);
    // The edit modal's header is title + subtitle only, as the mock draws it;
    // the app identity moves into the locked card at the top of the body.
    iconTile->setVisible(!m_editing);
    headerRow->addWidget(iconTile, 0, Qt::AlignVCenter);

    auto *titleColumn = new QVBoxLayout();
    titleColumn->setContentsMargins(0, 0, 0, 0);
    titleColumn->setSpacing(3);
    m_titleLabel = makeLabel(QStringLiteral("Create Network Policy"),
                             QStringLiteral("dialogTitle"), headerRowWidget);
    titleColumn->addWidget(m_titleLabel);

    m_stepSubtitle = makeLabel(QString(), QStringLiteral("dialogSubtitle"),
                               headerRowWidget);
    titleColumn->addWidget(m_stepSubtitle);

    // The single-view edit layout has no step subtitle, so it keeps the target
    // badge the wizard drops in favour of its step line.
    m_targetRow = new QWidget(headerRowWidget);
    auto *subtitleRow = new QHBoxLayout(m_targetRow);
    subtitleRow->setContentsMargins(0, 0, 0, 0);
    subtitleRow->setSpacing(6);
    auto *subtitlePrefix =
        makeLabel(QStringLiteral("Target process:"), QStringLiteral("dialogSubtitle"),
                  m_targetRow);
    subtitleRow->addWidget(subtitlePrefix);
    m_processBadge = makeLabel(processBadgeText(), QStringLiteral("processBadge"),
                               m_targetRow);
    m_processBadge->setProperty("fullText", processBadgeText());
    m_processBadge->setToolTip(processBadgeText());
    subtitleRow->addWidget(m_processBadge);
    subtitleRow->addStretch(1);
    titleColumn->addWidget(m_targetRow);
    headerRow->addLayout(titleColumn, 1);

    m_closeButton = new QPushButton(headerRowWidget);
    m_closeButton->setObjectName(QStringLiteral("iconButton"));
    m_closeButton->setFixedSize(28, 28);
    m_closeButton->setCursor(Qt::PointingHandCursor);
    m_closeButton->setToolTip(QStringLiteral("Close"));
    m_closeButton->setAccessibleName(QStringLiteral("Close"));
    headerRow->addWidget(m_closeButton, 0, Qt::AlignVCenter);
    headerColumn->addWidget(headerRowWidget);

    // ── Stepper ───────────────────────────────────────────────────────────
    m_stepper = new QWidget(m_header);
    auto *stepperRow = new QHBoxLayout(m_stepper);
    stepperRow->setContentsMargins(0, 0, 0, 0);
    stepperRow->setSpacing(8);
    const char *stepTitles[] = {"Select App", "Traffic Rule", "Schedule & Review"};
    for (int i = 0; i < 3; ++i) {
        auto *pill = new QPushButton(m_stepper);
        pill->setObjectName(QStringLiteral("stepPill"));
        pill->setCursor(Qt::PointingHandCursor);
        pill->setFixedHeight(32);
        pill->setAccessibleName(QStringLiteral("Step %1: %2")
                                    .arg(i + 1)
                                    .arg(QLatin1String(stepTitles[i])));
        auto *cell = new QHBoxLayout(pill);
        cell->setContentsMargins(8, 0, 8, 0);
        cell->setSpacing(8);

        auto *number = new QLabel(QString::number(i + 1), pill);
        number->setObjectName(QStringLiteral("stepNum"));
        number->setAlignment(Qt::AlignCenter);
        number->setFixedSize(18, 18);
        number->setAttribute(Qt::WA_TransparentForMouseEvents);
        cell->addWidget(number, 0, Qt::AlignVCenter);

        auto *title = new QLabel(QLatin1String(stepTitles[i]), pill);
        title->setObjectName(QStringLiteral("stepTitle"));
        title->setAttribute(Qt::WA_TransparentForMouseEvents);
        cell->addWidget(title, 1);

        pill->setProperty("state", QStringLiteral("todo"));
        number->setProperty("state", QStringLiteral("todo"));
        title->setProperty("state", QStringLiteral("todo"));
        stepperRow->addWidget(pill, 1);

        connect(pill, &QPushButton::clicked, this, [this, i]() {
            if (i > 0 && !targetReady()) {
                showToast(QStringLiteral("Choose an application before moving "
                                         "past the first step."));
                return;
            }
            goToStep(i + 1);
        });

        m_stepButtons << pill;
        m_stepNums << number;
        m_stepTitles << title;
    }
    headerColumn->addWidget(m_stepper);

    cardLayout->addWidget(m_header);

    auto *headerLine = new QFrame(m_card);
    headerLine->setObjectName(QStringLiteral("headerLine"));
    headerLine->setFixedHeight(1);
    cardLayout->addWidget(headerLine);

    // ── Scrollable body: the rule form ────────────────────────────────────
    m_scroll = new PolicyScrollArea(m_card);
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scroll->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContents);

    m_form = new PolicyRuleForm(m_target, m_scroll);
    m_form->setTargetLabel(processBadgeText());
    m_scroll->setWidget(m_form);
    cardLayout->addWidget(m_scroll, 1);

    // The form owns the content height; the scroll area has to be told when the
    // preferred height changes (action choice, accordion animation).
    connect(m_form, &PolicyRuleForm::layoutChanged, this, [this]() {
        m_scroll->updateGeometry();
    });

    // ── Footer ────────────────────────────────────────────────────────────
    // Sits outside the scroll area so Cancel / Save stay reachable while the
    // form above scrolls.
    auto *footerLine = new QFrame(m_card);
    footerLine->setObjectName(QStringLiteral("headerLine"));
    footerLine->setFixedHeight(1);
    footerLine->setVisible(!m_editing);
    cardLayout->addWidget(footerLine);

    auto *footer = new QWidget(m_card);
    auto *footerRow = new QHBoxLayout(footer);
    footerRow->setContentsMargins(20, 14, 20, 14);
    footerRow->setSpacing(10);

    // The wizard puts Cancel / Back on the left and its forward action on the
    // right; the edit modal right-aligns Cancel next to Save Changes.
    if (m_editing) footerRow->addStretch(1);

    m_cancelButton = new QPushButton(QStringLiteral("Cancel"), footer);
    m_cancelButton->setObjectName(QStringLiteral("cancelButton"));
    m_cancelButton->setCursor(Qt::PointingHandCursor);
    m_cancelButton->setAutoDefault(false);
    footerRow->addWidget(m_cancelButton);
    if (!m_editing) footerRow->addStretch(1);

    m_saveButton = new QPushButton(m_editing ? QStringLiteral("Save Changes")
                                             : QStringLiteral("Save Policy"), footer);
    m_saveButton->setObjectName(QStringLiteral("saveButton"));
    m_saveButton->setCursor(Qt::PointingHandCursor);
    m_saveButton->setDefault(true);
    footerRow->addWidget(m_saveButton);
    cardLayout->addWidget(footer);

    // Toast for validation and status, positioned over the card.
    m_toast = new QLabel(m_card);
    m_toast->setObjectName(QStringLiteral("toast"));
    m_toast->setWordWrap(true);
    m_toast->setMaximumWidth(360);
    m_toast->setVisible(false);
    m_toastEffect = new QGraphicsOpacityEffect(m_toast);
    m_toastEffect->setOpacity(0.0);
    m_toast->setGraphicsEffect(m_toastEffect);
    m_toastFade = new QPropertyAnimation(m_toastEffect, "opacity", this);
    m_toastFade->setDuration(220);

    // ── Connections ───────────────────────────────────────────────────────
    connect(m_closeButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_saveButton, &QPushButton::clicked, this, &PolicyEditorDialog::advance);

    // Drag the frameless card by its header.
    QWidget *handles[] = {m_header, m_titleLabel, m_processBadge, m_headerIcon};
    for (QWidget *handle : handles)
        handle->installEventFilter(this);

    applyTheme();

    if (m_editing) {
        // Edit keeps the mock's single-view modal: every section at once, no
        // stepper, no target badge, and the form's locked identity card in
        // place of the scope fields.
        m_stepper->setVisible(false);
        m_targetRow->setVisible(false);
        m_stepSubtitle->setVisible(true);
        m_stepSubtitle->setText(
            QStringLiteral("Adjust traffic limits, schedule, or activation state"));
        m_form->setStep(0);
        m_form->setEditMode(true);
    } else {
        m_targetRow->setVisible(false);
        m_step = 1;
        m_form->setStep(1);
        updateStepChrome();
    }

    // Cap the scroll viewport before the fixed-size layout is first applied so
    // the dialog never flashes at its full content height. Measure the chrome
    // (header, sticky footer, dividers and shadow margins) instead of assuming
    // a constant, then leave 8 px so the card always fits on screen.
    layout()->activate();
    const int chrome = cardLayout->sizeHint().height()
        - m_scroll->sizeHint().height() + 2 * 28;
    const QRect available = screen() ? screen()->availableGeometry()
                                     : QRect(0, 0, 1080, 720);
    const int cap = qMax(240, available.height() - chrome - 8);
    m_scroll->setMaximumHeight(cap);
}

QString PolicyEditorDialog::processBadgeText() const
{
    QString name = m_target.processName;
    quint32 pid = m_target.pid;

    if (m_editing) {
        if (m_policy.scope == QLatin1String("pid"))
            pid = m_policy.targetId.toUInt();
        else if (name.isEmpty())
            name = QFileInfo(m_policy.targetId).fileName();
    }
    if (name.isEmpty() && !m_target.executablePath.isEmpty())
        name = QFileInfo(m_target.executablePath).fileName();
    if (name.isEmpty() && !m_target.groupName.isEmpty())
        name = m_target.groupName;
    if (name.isEmpty() && !m_target.serviceName.isEmpty())
        name = m_target.serviceName;
    if (name.isEmpty() && !m_target.publisher.isEmpty())
        name = m_target.publisher;
    if (name.isEmpty()) name = QStringLiteral("policy target");

    if (pid != 0)
        return QStringLiteral("%1 (PID %2)").arg(name).arg(pid);
    return name;
}

void PolicyEditorDialog::applyTheme()
{
    const DialogColors c = dialogColors(ThemeManager::instance().isDark());
    setStyleSheet(dialogStyleSheet(c));

    // A long executable or publisher name must not push the close button out of
    // the fixed-width card; elide it in the middle and keep the full text in the
    // tooltip.
    const QString badgeText = m_processBadge->property("fullText").toString();
    m_processBadge->setMaximumWidth(240);
    m_processBadge->setText(m_processBadge->fontMetrics().elidedText(
        badgeText, Qt::ElideMiddle, 216));

    m_headerIcon->setPixmap(glyphPixmap(GlyphShield, 16, c.accent, 1.8));
    m_closeButton->setIcon(QIcon(glyphPixmap(GlyphClose, 16, c.muted, 1.8)));
    m_closeButton->setIconSize(QSize(16, 16));
    m_saveButton->setIcon(QIcon(glyphPixmap(GlyphCheck, 14, QColor("#FFFFFF"), 2.0)));
    m_saveButton->setIconSize(QSize(14, 14));

    if (!m_toast->isVisible()) m_toast->setGraphicsEffect(m_toastEffect);

    m_form->applyTheme();
}

bool PolicyEditorDialog::targetReady() const
{
    const PolicyScopeKind scope = m_form->currentScope();
    if (scope == PolicyScopeKind::Pid)
        return m_target.pid != 0;
    if (scope == PolicyScopeKind::ApplicationGroup)
        return !m_target.groupId.isEmpty();
    return !m_form->targetForScope().isEmpty();
}

bool PolicyEditorDialog::validateStep(int step, QString *message)
{
    const PolicyScopeKind scope = m_form->currentScope();

    if (step == 1) {
        if (scope == PolicyScopeKind::Pid && m_target.pid == 0) {
            *message = QStringLiteral("Select a process row before creating a "
                                      "PID-scoped policy.");
            return false;
        }
        if (scope == PolicyScopeKind::ApplicationGroup &&
            m_target.groupId.isEmpty()) {
            *message = QStringLiteral("This process does not belong to an activity "
                                      "group, so a group-scoped policy has no "
                                      "target.");
            return false;
        }
        if (!targetReady()) {
            *message = QStringLiteral("Enter the %1 this policy should cover.")
                           .arg(scope == PolicyScopeKind::Publisher
                                    ? QStringLiteral("publisher")
                                    : scope == PolicyScopeKind::Service
                                          ? QStringLiteral("service name")
                                          : QStringLiteral("path"));
            m_form->focusTargetField();
            return false;
        }
        return true;
    }

    if (step == 2) {
        const NetworkPolicy::Action action = m_form->currentAction();
        const bool shaping = action == NetworkPolicy::Action::Throttle ||
                             action == NetworkPolicy::Action::Schedule;
        if (shaping && m_form->rateKbps() <= 0) {
            *message = QStringLiteral("A throttle policy needs a rate above zero.");
            m_form->focusRateField();
            return false;
        }
        return true;
    }

    const QString schedule = m_form->scheduleValue();
    if (!schedule.isEmpty() && !scheduleIsSupported(schedule)) {
        *message = QStringLiteral("The recurring window \"%1\" is not recognised. "
                                  "Use work-hours, overnight, HH:MM-HH:MM, or "
                                  "\"Mon-Fri 09:00-17:00\".")
                       .arg(schedule);
        return false;
    }
    if (m_form->expiresChecked() &&
        m_form->expiration() <= QDateTime::currentDateTime() &&
        !(m_storedExpiration.isValid() &&
          m_form->expiration() == m_storedExpiration)) {
        // Saving an already-expired policy unchanged is allowed; back-dating a
        // new one is not.
        *message = QStringLiteral("The expiration must be in the future.");
        m_form->focusExpirationField();
        return false;
    }
    return true;
}

void PolicyEditorDialog::advance()
{
    if (m_editing || m_step >= 3) {
        accept();
        return;
    }

    QString message;
    if (!validateStep(m_step, &message)) {
        showToast(message);
        return;
    }
    goToStep(m_step + 1);
}

void PolicyEditorDialog::goToStep(int step)
{
    if (m_editing) return;

    step = qBound(1, step, 3);
    if (step > 1 && !targetReady()) {
        showToast(QStringLiteral("Choose an application before moving past the "
                                 "first step."));
        step = 1;
    }

    m_step = step;
    m_form->setStep(step);
    updateStepChrome();
    layout()->activate();
    adjustSize();
}

void PolicyEditorDialog::updateStepChrome()
{
    static const char *subtitles[] = {
        "Step 1 of 3 \xE2\x80\x94 Choose an application to control",
        "Step 2 of 3 \xE2\x80\x94 Set traffic action and bandwidth limit",
        "Step 3 of 3 \xE2\x80\x94 Optional schedule and final review",
    };
    m_stepSubtitle->setText(QString::fromUtf8(subtitles[m_step - 1]));
    m_targetRow->setVisible(false);
    m_stepSubtitle->setVisible(true);

    for (int i = 0; i < m_stepButtons.size(); ++i) {
        const int number = i + 1;
        const char *state = number < m_step ? "done"
                          : number == m_step ? "current"
                                             : "todo";
        QWidget *parts[] = {m_stepButtons[i], m_stepNums[i], m_stepTitles[i]};
        for (QWidget *part : parts) {
            part->setProperty("state", QLatin1String(state));
            part->style()->unpolish(part);
            part->style()->polish(part);
            part->update();
        }
    }

    const bool last = m_step == 3;
    m_cancelButton->setText(m_step == 1 ? QStringLiteral("Cancel")
                                        : QString::fromUtf8("\xE2\x86\x90 Back"));
    m_saveButton->setText(
        last ? QStringLiteral("Create Policy")
             : m_step == 1
                   ? QString::fromUtf8("Next: Traffic Rule \xE2\x86\x92")
                   : QString::fromUtf8("Next: Schedule & Review \xE2\x86\x92"));
    m_saveButton->setIcon(last
                              ? QIcon(glyphPixmap(GlyphCheck, 14, QColor("#FFFFFF"), 2.0))
                              : QIcon());
    m_saveButton->setIconSize(QSize(14, 14));
}

bool PolicyEditorDialog::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress) {
        auto *mouse = static_cast<QMouseEvent *>(event);
        if (mouse->button() == Qt::LeftButton &&
            (watched == m_header || watched == m_titleLabel ||
             watched == m_processBadge || watched == m_headerIcon)) {
            if (windowHandle()) {
                windowHandle()->startSystemMove();
                return true;
            }
        }
    }

    return QDialog::eventFilter(watched, event);
}

void PolicyEditorDialog::showEvent(QShowEvent *event)
{
    QDialog::showEvent(event);
    if (!m_sized) {
        layout()->activate();
        adjustSize();
        m_sized = true;
    }
    if (!m_initialFocusDone) {
        m_initialFocusDone = true;
        if (QWidget *initial = m_form->initialFocusWidget())
            initial->setFocus(Qt::OtherFocusReason);
    }
    const QRect available = screen() ? screen()->availableGeometry()
                                     : QRect();
    if (available.isValid())
        move(available.center() - QPoint(width() / 2, height() / 2));
}

void PolicyEditorDialog::resizeEvent(QResizeEvent *event)
{
    QDialog::resizeEvent(event);
    // The fixed-size layout settles a beat after showEvent, so recentre on the
    // final size (and after any explicit content-height change).
    if (m_sized) {
        const QRect available = screen() ? screen()->availableGeometry()
                                         : QRect();
        if (available.isValid()) {
            const QPoint centered = available.center() -
                QPoint(width() / 2, height() / 2);
            if (pos() != centered) move(centered);
        }
    }
    if (m_toast && m_toast->isVisible()) {
        const int toastBottom = m_scroll->isVisible()
            ? m_scroll->geometry().bottom() - 12
            : m_card->height() - 20;
        m_toast->move(m_card->width() - m_toast->width() - 20,
                      toastBottom - m_toast->height());
    }
}

void PolicyEditorDialog::accept()
{
    const PolicyScopeKind scope = m_form->currentScope();
    const NetworkPolicy::Action action = m_form->currentAction();
    const QString target = m_form->targetForScope();

    // Enter on an unfinished wizard advances instead of saving a half-built
    // policy; accept-time validation still runs as the last line of defence.
    if (!m_editing && m_step < 3) {
        advance();
        return;
    }

    QString message;
    for (int step = 1; step <= 3; ++step) {
        if (!validateStep(step, &message)) {
            showToast(message);
            return;
        }
    }

    const bool shaping = action == NetworkPolicy::Action::Throttle ||
                         action == NetworkPolicy::Action::Schedule;
    const QString schedule = m_form->scheduleValue();
    const QDateTime now = QDateTime::currentDateTime();

    // NG-053: a publisher or group policy covers software the user did not pick
    // directly, so it is confirmed with its impact spelled out. Cancel is the
    // default button: an accidental Enter must not widen enforcement.
    const PolicyImpact impact = m_form->currentImpact();
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
    m_policy.direction = m_form->direction();
    m_policy.action = action;
    m_policy.rateBitsPerSecond = shaping ? m_form->rateBitsPerSecond() : 0;

    const bool expires = m_form->expiresChecked();
    m_policy.schedule = schedule;
    m_policy.expiration = expires ? m_form->expiration() : QDateTime();
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
    m_policy.enabled = m_form->enabled();
    m_policy.description = m_form->description();

    QDialog::accept();
}

void PolicyEditorDialog::showToast(const QString &message)
{
    if (!m_toast) return;

    if (m_toastFade->state() == QPropertyAnimation::Running) m_toastFade->stop();
    m_toast->setText(message);
    const int toastWidth = qMin(360, m_card->width() - 40);
    m_toast->setFixedWidth(toastWidth);
    // QLabel::adjustSize() ignores wrapped height, so measure it explicitly and
    // add the style's 10 px top/bottom padding plus the 1 px border.
    int textHeight = m_toast->heightForWidth(toastWidth);
    if (textHeight <= 0) textHeight = m_toast->fontMetrics().height();
    m_toast->setFixedHeight(textHeight + 24);
    // Keep the toast above the now-sticky footer.
    const int toastBottom = m_scroll->isVisible()
        ? m_scroll->geometry().bottom() - 12
        : m_card->height() - 20;
    const QPoint pos(m_card->width() - m_toast->width() - 20,
                     toastBottom - m_toast->height());
    m_toast->move(pos);
    m_toast->raise();
    m_toast->show();
    m_toastEffect->setOpacity(0.0);
    m_toastFade->setStartValue(0.0);
    m_toastFade->setEndValue(1.0);
    m_toastFade->start();

    QTimer::singleShot(3200, m_toast, [this]() {
        if (!m_toast) return;
        m_toastFade->stop();
        m_toastFade->setStartValue(m_toastEffect->opacity());
        m_toastFade->setEndValue(0.0);
        m_toastFade->start();
        QTimer::singleShot(240, m_toast, [this]() { m_toast->hide(); });
    });
}
