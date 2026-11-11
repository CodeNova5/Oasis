/**
 * @file    recommendationdialog.cpp
 * @brief   Recommendation and local feedback view (NG-042/NG-043).
 * @author  Ali Sakkaf
 */
#include "recommendationdialog.h"

#include "stylemanager.h"
#include "apptheme.h"

#include <QButtonGroup>
#include <QFont>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QVBoxLayout>

RecommendationDialog::RecommendationDialog(const RecommendationContext &context,
                                           const RecommendationEngine &engine,
                                           RecommendationFeedbackStore *feedbackStore,
                                           QWidget *parent)
    : QDialog(parent)
    , m_context(context)
    , m_engine(&engine)
    , m_store(feedbackStore)
{
    setWindowTitle(QStringLiteral("Recommendation"));
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    setMinimumWidth(560);
    setMaximumWidth(720);

    const bool isDark = (StyleManager::instance().currentMode() == AppTheme::Dark);
    const QString bg        = isDark ? "#1F2328" : "#F6F8FA";
    const QString fg        = isDark ? "#E6EDF3" : "#24292E";
    const QString border    = isDark ? "#30363D" : "#D0D7DE";
    const QString btnBg     = isDark ? "#21262D" : "#EBECF0";
    const QString btnHover  = isDark ? "#30363D" : "#F3F4F6";
    const QString textMuted = isDark ? "#8B949E" : "#57606A";
    const QString accent    = isDark ? "#1F6FEB" : "#0969DA";

    setStyleSheet(QString(
                      "QDialog { background-color: %1; color: %2; }"
                      "QLabel { color: %2; font-size: 10pt; }"
                      "QPushButton { background-color: %4; border: 1px solid %3; border-radius: 6px; padding: 6px 16px; color: %2; font-weight: bold; }"
                      "QPushButton:hover { background-color: %5; }"
                      "QPushButton:checked { background-color: %7; border-color: %7; color: #FFFFFF; }"
                      "QPushButton:disabled { color: %6; background-color: %1; }"
                      "QGroupBox { border: 1px solid %3; border-radius: 6px; margin-top: 12px; font-weight: bold; color: %2; }"
                      "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; left: 10px; padding: 0 4px; }"
                      ).arg(bg, fg, border, btnBg, btnHover, textMuted, accent));

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(12);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    m_title = new QLabel(this);
    QFont titleFont = m_title->font();
    titleFont.setPointSize(titleFont.pointSize() + 3);
    titleFont.setBold(true);
    m_title->setFont(titleFont);
    m_title->setWordWrap(true);
    mainLayout->addWidget(m_title);

    m_meta = new QLabel(this);
    m_meta->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    mainLayout->addWidget(m_meta);

    QFrame *line = new QFrame(this);
    line->setFrameShape(QFrame::HLine);
    line->setStyleSheet(QStringLiteral("background-color: %1;").arg(border));
    mainLayout->addWidget(line);

    m_body = new QLabel(this);
    m_body->setWordWrap(true);
    m_body->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mainLayout->addWidget(m_body);

    QGroupBox *feedbackGroup = new QGroupBox(
        QStringLiteral(" Was this recommendation useful? "), this);
    QVBoxLayout *feedbackLayout = new QVBoxLayout(feedbackGroup);
    feedbackLayout->setContentsMargins(15, 20, 15, 15);
    feedbackLayout->setSpacing(8);

    QHBoxLayout *buttonRow = new QHBoxLayout();
    m_useful = new QPushButton(QStringLiteral("👍 Useful"), feedbackGroup);
    m_incorrect = new QPushButton(QStringLiteral("✏ Incorrect"), feedbackGroup);
    m_unwanted = new QPushButton(QStringLiteral("🚫 Not wanted"), feedbackGroup);
    m_clear = new QPushButton(QStringLiteral("Clear feedback"), feedbackGroup);
    for (QPushButton *button : {m_useful, m_incorrect, m_unwanted})
        button->setCheckable(true);

    m_group = new QButtonGroup(this);
    m_group->setExclusive(true);
    m_group->addButton(m_useful);
    m_group->addButton(m_incorrect);
    m_group->addButton(m_unwanted);

    buttonRow->addWidget(m_useful);
    buttonRow->addWidget(m_incorrect);
    buttonRow->addWidget(m_unwanted);
    buttonRow->addStretch();
    buttonRow->addWidget(m_clear);
    feedbackLayout->addLayout(buttonRow);

    m_status = new QLabel(feedbackGroup);
    m_status->setWordWrap(true);
    m_status->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    feedbackLayout->addWidget(m_status);
    mainLayout->addWidget(feedbackGroup);

    QLabel *advisory = new QLabel(
        QStringLiteral("Recommendations are advice only: nothing is applied until you "
                       "create and approve a policy. Feedback stays on this device and "
                       "nothing is uploaded."),
        this);
    advisory->setWordWrap(true);
    advisory->setStyleSheet(QStringLiteral("color: %1;").arg(textMuted));
    mainLayout->addWidget(advisory);

    QHBoxLayout *bottomRow = new QHBoxLayout();
    bottomRow->addStretch();
    QPushButton *close = new QPushButton(QStringLiteral("Close"), this);
    bottomRow->addWidget(close);
    mainLayout->addLayout(bottomRow);

    connect(close, &QPushButton::clicked, this, &QDialog::accept);
    connect(m_useful, &QPushButton::clicked, this, [this]() {
        setFeedback(RecommendationFeedback::Useful);
    });
    connect(m_incorrect, &QPushButton::clicked, this, [this]() {
        setFeedback(RecommendationFeedback::Incorrect);
    });
    connect(m_unwanted, &QPushButton::clicked, this, [this]() {
        setFeedback(RecommendationFeedback::Unwanted);
    });
    connect(m_clear, &QPushButton::clicked, this, [this]() {
        setFeedback(RecommendationFeedback::None);
    });

    if (!m_store) {
        feedbackGroup->setEnabled(false);
        m_status->setText(QStringLiteral("Feedback is unavailable."));
    }

    refresh();
}

void RecommendationDialog::refresh()
{
    m_recommendation = m_engine ? m_engine->recommend(m_context) : Recommendation();

    m_title->setText(m_recommendation.title.trimmed().isEmpty()
                         ? QStringLiteral("No recommendation")
                         : m_recommendation.title);
    m_meta->setText(QStringLiteral("%1  •  %2  •  %3 confidence")
                        .arg(catalogCategoryDisplayName(m_recommendation.category),
                             recommendationActionDisplayName(m_recommendation.action),
                             m_recommendation.confidenceName()));

    QStringList lines = m_recommendation.lines();
    if (!lines.isEmpty()) lines.removeFirst(); // title and meta are shown above
    m_body->setText(lines.join(QLatin1Char('\n')));

    const bool canFeedback = m_store && !m_recommendation.feedbackKey.isEmpty();
    const RecommendationFeedback feedback = m_recommendation.feedback;
    {
        const QSignalBlocker blocker(m_group);
        m_useful->setChecked(feedback == RecommendationFeedback::Useful);
        m_incorrect->setChecked(feedback == RecommendationFeedback::Incorrect);
        m_unwanted->setChecked(feedback == RecommendationFeedback::Unwanted);
    }
    for (QPushButton *button : {m_useful, m_incorrect, m_unwanted})
        button->setEnabled(canFeedback);
    m_clear->setEnabled(canFeedback && feedback != RecommendationFeedback::None);

    m_status->setText(canFeedback
                          ? feedbackStatusText()
                          : QStringLiteral("Feedback is unavailable for this recommendation."));
}

void RecommendationDialog::setFeedback(RecommendationFeedback feedback)
{
    if (!m_store || m_recommendation.feedbackKey.isEmpty()) return;

    const bool saved = m_store->setFeedback(m_recommendation.feedbackKey, feedback);
    refresh();
    if (!saved) {
        m_status->setText(m_status->text()
                          + QStringLiteral("\nThe feedback could not be saved."));
    }
}

QString RecommendationDialog::feedbackStatusText() const
{
    QString text;
    switch (m_recommendation.feedback) {
    case RecommendationFeedback::Useful:
        text = QStringLiteral("Marked useful. Future suggestions for this application "
                              "stay enabled.");
        break;
    case RecommendationFeedback::Incorrect:
        text = QStringLiteral("Marked incorrect. Future suggestions for this application "
                              "are downgraded to a review.");
        break;
    case RecommendationFeedback::Unwanted:
        text = QStringLiteral("Marked not wanted. Future suggestions for this application "
                              "are hidden.");
        break;
    case RecommendationFeedback::None:
        text = QStringLiteral("No feedback recorded for this application.");
        break;
    }
    return text + QStringLiteral("\nStored locally only; nothing is uploaded.");
}
