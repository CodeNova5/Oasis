/**
 * @file    aiapprovaldialog.cpp
 * @brief   AI approval flow (NG-046).
 * @author  Oasis
 */
#include "aiapprovaldialog.h"

#include "policyeditordialog.h"
#include "ui/theme/thememanager.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QtConcurrentRun>

namespace {

PolicyScopeKind scopeKindFromKey(const QString &scope)
{
    const QString key = scope.trimmed().toLower();
    if (key == QLatin1String("pid"))       return PolicyScopeKind::Pid;
    if (key == QLatin1String("publisher")) return PolicyScopeKind::Publisher;
    if (key == QLatin1String("service"))   return PolicyScopeKind::Service;
    if (key == QLatin1String("group"))     return PolicyScopeKind::ApplicationGroup;
    return PolicyScopeKind::ExecutablePath;
}

QString actionDescription(const NetworkPolicy &policy)
{
    switch (policy.action) {
    case NetworkPolicy::Action::Throttle: {
        const double mbits = static_cast<double>(policy.rateBitsPerSecond) / 1000000.0;
        return QStringLiteral("Throttle to %1 Mbit/s in both directions")
            .arg(mbits, 0, 'f', 2);
    }
    case NetworkPolicy::Action::Block:
        return QStringLiteral("Block traffic in both directions for the chosen duration");
    case NetworkPolicy::Action::Schedule:
        return policy.schedule.trimmed().isEmpty()
            ? QStringLiteral("Defer traffic to the chosen duration")
            : QStringLiteral("Defer traffic to the \"%1\" window").arg(policy.schedule);
    default:
        return QStringLiteral("No enforceable action");
    }
}

} // namespace

AiApprovalDialog::AiApprovalDialog(const RecommendationContext &context,
                                   const RecommendationEngine &engine,
                                   AiAssistant *assistant,
                                   QWidget *parent)
    : QDialog(parent)
    , m_context(context)
    , m_engine(&engine)
    , m_assistant(assistant)
{
    m_recommendation = m_engine ? m_engine->recommend(m_context) : Recommendation();
    m_scopeOptions = aiApprovalScopeOptions(m_context, m_recommendation);

    setWindowTitle(QStringLiteral("Review and approve policy"));
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    setMinimumWidth(660);
    setMaximumWidth(820);

    buildUi();
    applyProviderSettingsToUi();
    updateScopeDescription();
    updateApprovalState();
}

void AiApprovalDialog::buildUi()
{
    const bool isDark = ThemeManager::instance().isDark();
    const QString bg        = isDark ? "#1F2328" : "#F6F8FA";
    const QString fg        = isDark ? "#E6EDF3" : "#24292E";
    const QString border    = isDark ? "#30363D" : "#D0D7DE";
    const QString btnBg     = isDark ? "#21262D" : "#EBECF0";
    const QString btnHover  = isDark ? "#30363D" : "#F3F4F6";
    const QString textMuted = isDark ? "#8B949E" : "#57606A";
    const QString accent    = isDark ? "#1F6FEB" : "#0969DA";
    const QString fieldBg   = isDark ? "#0D1117" : "#FFFFFF";

    setStyleSheet(QString(
                      "QDialog { background-color: %1; color: %2; }"
                      "QLabel { color: %2; font-size: 10pt; }"
                      "QPushButton { background-color: %4; border: 1px solid %3; border-radius: 6px; padding: 6px 16px; color: %2; font-weight: bold; }"
                      "QPushButton:hover { background-color: %5; }"
                      "QPushButton:default { background-color: %7; border-color: %7; color: #FFFFFF; }"
                      "QPushButton:disabled { color: %6; background-color: %1; }"
                      "QGroupBox { border: 1px solid %3; border-radius: 6px; margin-top: 12px; font-weight: bold; color: %2; }"
                      "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; left: 10px; padding: 0 4px; }"
                      "QLineEdit, QComboBox, QPlainTextEdit { background-color: %8; color: %2; border: 1px solid %3; border-radius: 4px; padding: 4px; }"
                      ).arg(bg, fg, border, btnBg, btnHover, textMuted, accent, fieldBg));

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(10);
    layout->setContentsMargins(20, 20, 20, 20);

    QLabel *intro = new QLabel(
        QStringLiteral("AI can explain the activity, but it cannot choose or apply a "
                       "policy. The action below comes from the local recommendation. "
                       "You choose the scope and duration, and nothing is saved until "
                       "you press Approve policy."),
        this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    // ─── Local recommendation ──────────────────────────────────────────────
    QGroupBox *recommendationBox =
        new QGroupBox(QStringLiteral(" Local recommendation "), this);
    QVBoxLayout *recommendationLayout = new QVBoxLayout(recommendationBox);
    recommendationLayout->setContentsMargins(15, 20, 15, 12);
    recommendationLayout->setSpacing(6);

    m_title = new QLabel(recommendationBox);
    QFont titleFont = m_title->font();
    titleFont.setPointSize(titleFont.pointSize() + 2);
    titleFont.setBold(true);
    m_title->setFont(titleFont);
    m_title->setWordWrap(true);
    recommendationLayout->addWidget(m_title);

    m_meta = new QLabel(recommendationBox);
    m_meta->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    recommendationLayout->addWidget(m_meta);

    m_body = new QLabel(recommendationBox);
    m_body->setWordWrap(true);
    m_body->setTextInteractionFlags(Qt::TextSelectableByMouse);
    recommendationLayout->addWidget(m_body);
    layout->addWidget(recommendationBox);

    // ─── AI explanation ────────────────────────────────────────────────────
    QGroupBox *aiBox = new QGroupBox(QStringLiteral(" Optional AI explanation "), this);
    QVBoxLayout *aiLayout = new QVBoxLayout(aiBox);
    aiLayout->setContentsMargins(15, 20, 15, 12);
    aiLayout->setSpacing(8);

    QLabel *previewLabel = new QLabel(
        QStringLiteral("This exact redacted summary is all that would be sent. It is "
                       "never sent automatically."),
        aiBox);
    previewLabel->setWordWrap(true);
    previewLabel->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    aiLayout->addWidget(previewLabel);

    m_contextPreview = new QPlainTextEdit(aiBox);
    m_contextPreview->setReadOnly(true);
    m_contextPreview->setMaximumHeight(120);
    m_contextPreview->setPlainText(
        AiContext::forRecommendation(m_context, m_recommendation).previewText());
    aiLayout->addWidget(m_contextPreview);

    QHBoxLayout *aiButtonRow = new QHBoxLayout();
    m_askAi = new QPushButton(QStringLiteral("Send summary and explain"), aiBox);
    aiButtonRow->addWidget(m_askAi);
    aiButtonRow->addStretch();
    aiLayout->addLayout(aiButtonRow);

    m_explanationStatus = new QLabel(aiBox);
    m_explanationStatus->setWordWrap(true);
    m_explanationStatus->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    aiLayout->addWidget(m_explanationStatus);

    m_explanation = new QPlainTextEdit(aiBox);
    m_explanation->setReadOnly(true);
    m_explanation->setVisible(false);
    m_explanation->setMinimumHeight(110);
    aiLayout->addWidget(m_explanation);

    QGroupBox *providerBox = new QGroupBox(QStringLiteral(" Provider settings "), aiBox);
    QFormLayout *providerLayout = new QFormLayout(providerBox);
    providerLayout->setContentsMargins(10, 15, 10, 10);

    m_aiEnabled = new QCheckBox(
        QStringLiteral("Allow optional AI explanations (off by default)"), providerBox);
    providerLayout->addRow(m_aiEnabled);

    m_endpoint = new QLineEdit(providerBox);
    m_endpoint->setPlaceholderText(
        QStringLiteral("https://host/v1/chat/completions"));
    providerLayout->addRow(QStringLiteral("Endpoint:"), m_endpoint);

    m_model = new QLineEdit(providerBox);
    m_model->setPlaceholderText(QStringLiteral("model name"));
    providerLayout->addRow(QStringLiteral("Model:"), m_model);

    QPushButton *saveSettings = new QPushButton(QStringLiteral("Save provider settings"),
                                                providerBox);
    providerLayout->addRow(QString(), saveSettings);

    m_providerStatus = new QLabel(providerBox);
    m_providerStatus->setWordWrap(true);
    m_providerStatus->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    m_providerStatus->setText(QStringLiteral(
        "The API key is read from OASIS_AI_API_KEY when you send; it is never stored."));
    providerLayout->addRow(m_providerStatus);

    aiLayout->addWidget(providerBox);
    layout->addWidget(aiBox);

    // ─── Policy approval ───────────────────────────────────────────────────
    QGroupBox *policyBox = new QGroupBox(QStringLiteral(" Policy to approve "), this);
    QFormLayout *policyLayout = new QFormLayout(policyBox);
    policyLayout->setContentsMargins(15, 20, 15, 12);

    m_scopeCombo = new QComboBox(policyBox);
    for (const AiApprovalScopeOption &option : m_scopeOptions)
        m_scopeCombo->addItem(option.label, option.scope);
    policyLayout->addRow(QStringLiteral("Scope:"), m_scopeCombo);

    m_scopeRisk = new QLabel(policyBox);
    m_scopeRisk->setWordWrap(true);
    m_scopeRisk->setTextFormat(Qt::PlainText);
    m_scopeRisk->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    m_scopeRisk->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    policyLayout->addRow(QStringLiteral("Breadth and risk:"), m_scopeRisk);

    m_actionText = new QLabel(policyBox);
    m_actionText->setWordWrap(true);
    policyLayout->addRow(QStringLiteral("Action:"), m_actionText);

    m_durationCombo = new QComboBox(policyBox);
    for (AiApprovalDuration duration : aiApprovalDurations())
        m_durationCombo->addItem(aiApprovalDurationDisplayName(duration),
                                 static_cast<int>(duration));
    policyLayout->addRow(QStringLiteral("Duration:"), m_durationCombo);

    m_durationText = new QLabel(policyBox);
    m_durationText->setWordWrap(true);
    m_durationText->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    policyLayout->addRow(QString(), m_durationText);

    m_note = new QLineEdit(policyBox);
    m_note->setPlaceholderText(QStringLiteral("Why this policy exists (optional)"));
    policyLayout->addRow(QStringLiteral("Note:"), m_note);

    layout->addWidget(policyBox);

    QHBoxLayout *bottomRow = new QHBoxLayout();
    bottomRow->addStretch();
    QPushButton *reject = new QPushButton(QStringLiteral("Reject"), this);
    m_approve = new QPushButton(QStringLiteral("Approve policy"), this);
    m_approve->setDefault(true);
    bottomRow->addWidget(reject);
    bottomRow->addWidget(m_approve);
    layout->addLayout(bottomRow);

    // ─── Recommendation text ───────────────────────────────────────────────
    m_title->setText(m_recommendation.title.trimmed().isEmpty()
                         ? QStringLiteral("No recommendation")
                         : m_recommendation.title);
    m_meta->setText(QStringLiteral("%1  •  %2  •  %3 confidence")
                        .arg(catalogCategoryDisplayName(m_recommendation.category),
                             recommendationActionDisplayName(m_recommendation.action),
                             m_recommendation.confidenceName()));
    QStringList lines = m_recommendation.lines();
    if (!lines.isEmpty()) lines.removeFirst();
    m_body->setText(lines.join(QLatin1Char('\n')));

    m_actionText->setText(m_recommendation.hasSuggestedPolicy()
                              ? actionDescription(m_recommendation.suggestedPolicy)
                              : QStringLiteral(
                                    "None — this recommendation does not propose an "
                                    "enforceable policy."));
    m_note->setText(m_recommendation.suggestedPolicy.description);

    const AiApprovalDuration defaultDuration =
        aiApprovalDefaultDuration(m_recommendation, QDateTime::currentDateTimeUtc());
    const int durationIndex = m_durationCombo->findData(static_cast<int>(defaultDuration));
    if (durationIndex >= 0) m_durationCombo->setCurrentIndex(durationIndex);

    if (m_scopeOptions.isEmpty()) {
        m_scopeCombo->addItem(QStringLiteral("No scope available for this activity"));
        m_scopeCombo->setEnabled(false);
    }

    connect(reject, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_approve, &QPushButton::clicked, this, &AiApprovalDialog::accept);
    connect(m_scopeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AiApprovalDialog::updateScopeDescription);
    connect(m_durationCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AiApprovalDialog::updateApprovalState);
    connect(saveSettings, &QPushButton::clicked,
            this, &AiApprovalDialog::saveProviderSettings);
    connect(m_askAi, &QPushButton::clicked,
            this, &AiApprovalDialog::requestExplanation);
    connect(m_aiEnabled, &QCheckBox::toggled, this, &AiApprovalDialog::updateApprovalState);

    m_watcher = new QFutureWatcher<AiAssistResult>(this);
    connect(m_watcher, &QFutureWatcherBase::finished,
            this, &AiApprovalDialog::onExplanationReady);
}

void AiApprovalDialog::applyProviderSettingsToUi()
{
    if (!m_assistant) {
        m_aiEnabled->setEnabled(false);
        m_endpoint->setEnabled(false);
        m_model->setEnabled(false);
        m_askAi->setEnabled(false);
        m_explanationStatus->setText(
            QStringLiteral("AI assistance is not wired up in this view."));
        return;
    }

    const AiProviderSettings settings = m_assistant->settings();
    m_aiEnabled->setChecked(settings.enabled);
    m_endpoint->setText(settings.endpoint);
    m_model->setText(settings.model);

    if (settings.isUsable()) {
        m_explanationStatus->setText(
            QStringLiteral("AI is configured. Nothing is sent until you press the "
                           "button above."));
    } else if (!settings.enabled) {
        m_explanationStatus->setText(
            QStringLiteral("AI is off. Local recommendations work without it."));
    } else {
        m_explanationStatus->setText(
            QStringLiteral("AI is enabled but not usable: %1")
                .arg(settings.endpointProblem().isEmpty()
                         ? QStringLiteral("set an endpoint and a model")
                         : settings.endpointProblem()));
    }
    m_askAi->setEnabled(settings.isUsable() && !m_watcher->isRunning());
}

void AiApprovalDialog::saveProviderSettings()
{
    if (!m_assistant) return;

    AiProviderSettings settings = m_assistant->settings();
    settings.enabled = m_aiEnabled->isChecked();
    settings.endpoint = m_endpoint->text().trimmed();
    settings.model = m_model->text().trimmed();

    m_assistant->setSettings(settings);
    const bool saved = m_assistant->saveSettings();
    applyProviderSettingsToUi();

    if (!saved) {
        m_providerStatus->setText(
            QStringLiteral("The provider settings could not be saved."));
        return;
    }
    if (settings.enabled && !settings.isUsable()) {
        m_providerStatus->setText(
            QStringLiteral("Settings saved, but they are not usable yet: %1")
                .arg(settings.endpointProblem().isEmpty()
                         ? QStringLiteral("set an endpoint and a model")
                         : settings.endpointProblem()));
        return;
    }
    m_providerStatus->setText(
        QStringLiteral("Settings saved. The API key still comes from "
                       "OASIS_AI_API_KEY."));
}

void AiApprovalDialog::requestExplanation()
{
    if (!m_assistant || m_watcher->isRunning()) return;

    const AiProviderSettings settings = m_assistant->settings();
    if (!settings.isUsable()) {
        m_explanationStatus->setText(
            QStringLiteral("Configure an endpoint and model, and enable AI, before "
                           "sending."));
        return;
    }

    AiAssistant *assistant = m_assistant;
    const AiContext context = AiContext::forRecommendation(m_context, m_recommendation);
    const Recommendation local = m_recommendation;

    m_askAi->setEnabled(false);
    m_explanationStatus->setText(
        QStringLiteral("Asking the provider… the local recommendation is unaffected."));
    m_watcher->setFuture(QtConcurrent::run([assistant, context, local]() {
        return assistant->explain(context, local);
    }));
}

void AiApprovalDialog::onExplanationReady()
{
    const AiAssistResult result = m_watcher->result();
    m_askAi->setEnabled(m_assistant && m_assistant->settings().isUsable());

    if (result.usedProvider()) {
        m_explanationUsed = true;
        m_explanation->setVisible(true);
        m_explanation->setPlainText(result.explanation.text);
        m_explanationStatus->setText(
            QStringLiteral("Explanation from %1 (%2). This text is advice only: the "
                           "approved policy's action, rate, scope, and duration stay "
                           "under your control.")
                .arg(result.explanation.providerName.isEmpty()
                         ? QStringLiteral("the provider")
                         : result.explanation.providerName,
                     result.explanation.model.isEmpty()
                         ? QStringLiteral("unknown model")
                         : result.explanation.model));
        return;
    }

    m_explanationUsed = false;
    m_explanation->setVisible(false);
    m_explanation->clear();
    m_explanationStatus->setText(
        QStringLiteral("No AI explanation: %1 The local recommendation stands and "
                       "nothing was sent to a policy.")
            .arg(result.detail.trimmed().isEmpty()
                     ? QStringLiteral("the provider did not answer.")
                     : result.detail.trimmed()));
}

void AiApprovalDialog::updateScopeDescription()
{
    const int index = m_scopeCombo->currentIndex();
    if (index < 0 || index >= m_scopeOptions.size()) {
        m_scopeRisk->setText(QStringLiteral(
            "No scope is available, so no policy can be approved here."));
        updateApprovalState();
        return;
    }

    const AiApprovalScopeOption &option = m_scopeOptions.at(index);
    m_scopeRisk->setText(policyScopeRiskSummary(scopeKindFromKey(option.scope)));
    updateApprovalState();
}

void AiApprovalDialog::updateApprovalState()
{
    AiApprovalChoices choices;
    const int index = m_scopeCombo->currentIndex();
    if (index >= 0 && index < m_scopeOptions.size()) {
        choices.scope = m_scopeOptions.at(index).scope;
        choices.targetId = m_scopeOptions.at(index).targetId;
    }
    choices.duration = static_cast<AiApprovalDuration>(
        m_durationCombo->currentData().toInt());

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QDateTime expiration = aiApprovalExpiration(choices.duration, now);
    m_durationText->setText(expiration.isValid()
        ? QStringLiteral("The policy stops being active at %1.")
              .arg(expiration.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm")))
        : QStringLiteral("The policy stays until you remove it from Policies…."));

    bool aiBusy = m_watcher && m_watcher->isRunning();
    if (m_askAi) m_askAi->setEnabled(!aiBusy && m_assistant
                                     && m_assistant->settings().isUsable());

    if (m_approve)
        m_approve->setEnabled(aiApprovalProblems(m_recommendation, choices, now).isEmpty());
}

void AiApprovalDialog::accept()
{
    AiApprovalChoices choices;
    const int index = m_scopeCombo->currentIndex();
    if (index >= 0 && index < m_scopeOptions.size()) {
        choices.scope = m_scopeOptions.at(index).scope;
        choices.targetId = m_scopeOptions.at(index).targetId;
    }
    choices.duration = static_cast<AiApprovalDuration>(
        m_durationCombo->currentData().toInt());
    choices.explanationReviewed = m_explanationUsed;

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QStringList problems = aiApprovalProblems(m_recommendation, choices, now);
    if (!problems.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Approve policy"),
                             problems.join(QLatin1Char('\n')));
        return;
    }

    // The note field is the only policy text the user edits here; everything
    // else comes from the deterministic recommendation.
    m_recommendation.suggestedPolicy.description = m_note->text().trimmed();
    m_policy = aiApprovalBuildPolicy(m_recommendation, choices, now);
    m_approved = true;
    QDialog::accept();
}
