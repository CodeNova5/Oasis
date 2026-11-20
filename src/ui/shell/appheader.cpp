/**
 * @file    appheader.cpp
 * @author  Oasis
 */
#include "appheader.h"

#include "ui/theme/dimensions.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QVBoxLayout>
#include <QWidget>

AppHeader::AppHeader(QWidget *parent)
    : QFrame(parent)
{
    setObjectName(QStringLiteral("headerFrame"));
    setFixedHeight(Theme::Dim::HeaderHeight);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(Theme::Dim::SpaceXl, 0,
                               Theme::Dim::SpaceXl, 0);
    layout->setSpacing(Theme::Dim::SpaceMd);

    auto *titleBlock = new QWidget(this);
    auto *titleLayout = new QVBoxLayout(titleBlock);
    titleLayout->setContentsMargins(0, 0, 0, 0);
    titleLayout->setSpacing(2);

    m_title = new QLabel(titleBlock);
    m_title->setProperty("uiRole", QStringLiteral("pageTitle"));

    m_subtitle = new QLabel(titleBlock);
    m_subtitle->setProperty("uiRole", QStringLiteral("secondary"));
    m_subtitle->hide();
    titleLayout->addWidget(m_title);
    titleLayout->addWidget(m_subtitle);

    m_actionsHost = new QWidget(this);
    auto *actionsLayout = new QHBoxLayout(m_actionsHost);
    actionsLayout->setContentsMargins(0, 0, 0, 0);
    actionsLayout->setSpacing(0);
    m_actionsHost->hide();

    layout->addWidget(titleBlock);
    layout->addStretch(1);
    layout->addWidget(m_actionsHost, 0, Qt::AlignVCenter);
}

void AppHeader::setPage(const QString &title, const QString &subtitle)
{
    m_title->setText(title);
    m_subtitle->setText(subtitle);
    m_subtitle->setVisible(!subtitle.isEmpty());
}

void AppHeader::setPageActions(QWidget *actions)
{
    if (!actions || actions == m_actions)
        return;

    auto *actionsLayout = qobject_cast<QHBoxLayout *>(m_actionsHost->layout());
    if (m_actions && actionsLayout) {
        actionsLayout->removeWidget(m_actions);
        // The widget now belongs to another screen's page; hide it so it does
        // not keep painting over the controls that replaced it.
        m_actions->hide();
    }

    m_actions = actions;
    m_actions->setParent(m_actionsHost);
    if (actionsLayout)
        actionsLayout->addWidget(m_actions);
    // Reparenting hides a widget; showing it here lets the host's visibility
    // govern the toolbar instead of leaving it explicitly hidden.
    m_actions->show();
}

void AppHeader::setPageActionsVisible(bool visible)
{
    m_actionsHost->setVisible(visible && m_actions);
}
