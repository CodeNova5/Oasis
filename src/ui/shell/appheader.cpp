/**
 * @file    appheader.cpp
 * @author  Oasis
 */
#include "appheader.h"

#include "ui/theme/dimensions.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPushButton>
#include <QStyle>

namespace {

void repolish(QWidget *widget)
{
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
}

} // namespace

AppHeader::AppHeader(QWidget *parent)
    : QFrame(parent)
{
    setObjectName(QStringLiteral("headerFrame"));
    setFixedHeight(Theme::Dim::HeaderHeight);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(Theme::Dim::SpaceXl, 0,
                               Theme::Dim::SpaceXl, 0);
    layout->setSpacing(Theme::Dim::SpaceMd);

    m_title = new QLabel(this);
    m_title->setProperty("uiRole", QStringLiteral("pageTitle"));

    m_subtitle = new QLabel(this);
    m_subtitle->setProperty("uiRole", QStringLiteral("secondary"));
    m_subtitle->hide();

    m_pill = new QLabel(QStringLiteral("● Stopped"), this);
    m_pill->setProperty("uiRole", QStringLiteral("badge"));
    m_pill->setProperty("status", QStringLiteral("inactive"));
    m_pill->setCursor(Qt::PointingHandCursor);
    m_pill->setToolTip(QStringLiteral("Open monitoring diagnostics."));

    m_themeButton = new QPushButton(QStringLiteral("☀"), this);
    m_themeButton->setProperty("variant", QStringLiteral("ghost"));
    m_themeButton->setFixedSize(Theme::Dim::ButtonHeight, Theme::Dim::ButtonHeight);
    m_themeButton->setCursor(Qt::PointingHandCursor);
    m_themeButton->setToolTip(QStringLiteral("Switch between the dark and light theme."));

    m_minimizeButton = new QPushButton(QStringLiteral("⊟"), this);
    m_minimizeButton->setProperty("variant", QStringLiteral("ghost"));
    m_minimizeButton->setFixedSize(Theme::Dim::ButtonHeight, Theme::Dim::ButtonHeight);
    m_minimizeButton->setCursor(Qt::PointingHandCursor);
    m_minimizeButton->setToolTip(QStringLiteral("Minimize to the system tray."));

    layout->addWidget(m_title);
    layout->addWidget(m_subtitle, 0, Qt::AlignBottom);
    layout->addStretch(1);
    layout->addWidget(m_pill);
    layout->addWidget(m_themeButton);
    layout->addWidget(m_minimizeButton);

    connect(m_themeButton, &QPushButton::clicked,
            this, &AppHeader::themeToggleRequested);
    connect(m_minimizeButton, &QPushButton::clicked,
            this, &AppHeader::minimizeToTrayRequested);

    // A label has no clicked() signal; a transparent button over it would add
    // chrome, so the pill is handled through its own mouse release below.
    m_pill->installEventFilter(this);
}

void AppHeader::setPage(const QString &title, const QString &subtitle)
{
    m_title->setText(title);
    m_subtitle->setText(subtitle);
    m_subtitle->setVisible(!subtitle.isEmpty());
}

void AppHeader::setMonitoringState(MonitorState state)
{
    m_state = state;
    switch (state) {
    case MonitorState::Active:
        m_pill->setText(QStringLiteral("● Active"));
        m_pill->setProperty("status", QStringLiteral("active"));
        m_pill->setToolTip(QStringLiteral("Packet capture is running."));
        break;
    case MonitorState::Degraded:
        m_pill->setText(QStringLiteral("● Degraded"));
        m_pill->setProperty("status", QStringLiteral("degraded"));
        m_pill->setToolTip(QStringLiteral(
            "Capture is running with reduced capability. Open diagnostics."));
        break;
    case MonitorState::Stopped:
        m_pill->setText(QStringLiteral("● Stopped"));
        m_pill->setProperty("status", QStringLiteral("inactive"));
        m_pill->setToolTip(QStringLiteral("Packet capture is stopped."));
        break;
    }
    repolish(m_pill);
}

void AppHeader::setDarkMode(bool dark)
{
    m_themeButton->setText(dark ? QStringLiteral("☀") : QStringLiteral("🌙"));
    m_themeButton->setToolTip(dark ? QStringLiteral("Switch to the light theme.")
                                   : QStringLiteral("Switch to the dark theme."));
}

bool AppHeader::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == m_pill && event->type() == QEvent::MouseButtonRelease) {
        const auto *mouse = static_cast<QMouseEvent *>(event);
        if (mouse->button() == Qt::LeftButton) {
            emit monitoringPillActivated();
            return true;
        }
    }
    return QFrame::eventFilter(watched, event);
}
