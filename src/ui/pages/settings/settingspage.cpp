/**
 * @file    settingspage.cpp
 * @author  Oasis
 */
#include "settingspage.h"

#include "ui/theme/dimensions.h"

#include <QButtonGroup>
#include <QFrame>
#include <QLabel>
#include <QRadioButton>
#include <QScrollArea>
#include <QVBoxLayout>

SettingsPage::SettingsPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("SettingsPage"));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);

    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    root->addWidget(scroll);

    auto *content = new QWidget;
    content->setObjectName(QStringLiteral("SettingsContent"));
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV,
                                      Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV);
    contentLayout->setSpacing(Theme::Dim::SpaceLg);
    scroll->setWidget(content);

    buildDetectionCard(content);
    contentLayout->addStretch(1);

    // Fill in the status line for the profile the page opened with.
    setDetectionProfile(m_profile);
}

void SettingsPage::buildDetectionCard(QWidget *content)
{
    auto *card = new QFrame(content);
    card->setProperty("uiRole", QStringLiteral("card"));
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(Theme::Dim::SpaceXl, Theme::Dim::SpaceXl,
                               Theme::Dim::SpaceXl, Theme::Dim::SpaceXl);
    layout->setSpacing(Theme::Dim::SpaceSm);

    auto *heading = new QLabel(QStringLiteral("Detection profile"), card);
    heading->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(heading);

    auto *subtitle = new QLabel(
        QStringLiteral("How much traffic the Activity screen calls notable. "
                       "Capture, attribution and enforcement are the same under "
                       "either profile."),
        card);
    subtitle->setProperty("uiRole", QStringLiteral("muted"));
    subtitle->setWordWrap(true);
    layout->addWidget(subtitle);
    layout->addSpacing(Theme::Dim::SpaceSm);

    m_profileGroup = new QButtonGroup(card);
    m_profileGroup->setExclusive(true);

    for (const Activity::DetectionProfileOption &option : Activity::detectionProfiles()) {
        auto *choice = new QWidget(card);
        auto *choiceLayout = new QVBoxLayout(choice);
        choiceLayout->setContentsMargins(0, 0, 0, 0);
        choiceLayout->setSpacing(2);

        auto *button = new QRadioButton(option.label, choice);
        button->setCursor(Qt::PointingHandCursor);
        button->setChecked(option.profile == m_profile);
        m_profileGroup->addButton(button, static_cast<int>(option.profile));
        m_profileButtons.append(button);
        choiceLayout->addWidget(button);

        auto *summary = new QLabel(option.summary, choice);
        summary->setProperty("uiRole", QStringLiteral("muted"));
        summary->setWordWrap(true);
        summary->setContentsMargins(Theme::Dim::SpaceXl, 0, 0, 0);
        choiceLayout->addWidget(summary);

        // The exact numbers are shown so the choice is never a black box.
        auto *detail = new QLabel(option.detail, choice);
        detail->setProperty("uiRole", QStringLiteral("muted"));
        detail->setWordWrap(true);
        detail->setContentsMargins(Theme::Dim::SpaceXl, 0, 0, 0);
        choiceLayout->addWidget(detail);

        layout->addWidget(choice);
        layout->addSpacing(Theme::Dim::SpaceSm);

        connect(button, &QRadioButton::toggled, this, [this, option](bool checked) {
            if (!checked || m_profile == option.profile)
                return;
            m_profile = option.profile;
            if (m_profileStatus) {
                m_profileStatus->setText(
                    QStringLiteral("Active profile: %1. New events follow it "
                                   "immediately; events already in the feed keep "
                                   "their original classification.")
                        .arg(option.label));
            }
            emit detectionProfileChanged(option.profile);
        });
    }

    m_profileStatus = new QLabel(card);
    m_profileStatus->setProperty("uiRole", QStringLiteral("muted"));
    m_profileStatus->setWordWrap(true);
    layout->addWidget(m_profileStatus);

    layout->addSpacing(Theme::Dim::SpaceSm);
    auto *note = new QLabel(
        QStringLiteral("Other settings sections — monitoring, enforcement, "
                       "notifications, privacy, appearance and diagnostics — are "
                       "being rebuilt as dedicated views. Saved values from the "
                       "previous build keep working."),
        card);
    note->setProperty("uiRole", QStringLiteral("muted"));
    note->setWordWrap(true);
    layout->addWidget(note);

    content->layout()->addWidget(card);
}

void SettingsPage::setDetectionProfile(Activity::DetectionProfile profile)
{
    m_profile = profile;
    for (QRadioButton *button : m_profileButtons) {
        if (m_profileGroup
            && m_profileGroup->id(button) == static_cast<int>(profile)) {
            if (!button->isChecked())
                button->setChecked(true);
            break;
        }
    }
    if (m_profileStatus) {
        m_profileStatus->setText(
            QStringLiteral("Active profile: %1. New events follow it immediately; "
                           "events already in the feed keep their original "
                           "classification.")
                .arg(Activity::detectionProfileLabel(profile)));
    }
}
