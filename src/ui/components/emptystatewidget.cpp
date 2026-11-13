/**
 * @file    emptystatewidget.cpp
 * @author  Oasis
 */
#include "emptystatewidget.h"

#include "ui/theme/dimensions.h"

#include <QLabel>
#include <QPushButton>
#include <QStyle>
#include <QVBoxLayout>

EmptyStateWidget::EmptyStateWidget(QWidget *parent)
    : QWidget(parent)
{
    setProperty("uiRole", QStringLiteral("emptyState"));
    setMaximumWidth(420);
    setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(Theme::Dim::Space2Xl, Theme::Dim::Space2Xl,
                               Theme::Dim::Space2Xl, Theme::Dim::Space2Xl);
    layout->setSpacing(Theme::Dim::SpaceSm);

    m_icon = new QLabel(QStringLiteral("◌"), this);
    m_icon->setProperty("uiRole", QStringLiteral("emptyIcon"));
    m_icon->setAlignment(Qt::AlignCenter);

    m_title = new QLabel(this);
    m_title->setProperty("uiRole", QStringLiteral("emptyTitle"));
    m_title->setAlignment(Qt::AlignCenter);

    m_detail = new QLabel(this);
    m_detail->setProperty("uiRole", QStringLiteral("emptyText"));
    m_detail->setAlignment(Qt::AlignCenter);
    m_detail->setWordWrap(true);

    m_action = new QPushButton(this);
    m_action->setProperty("variant", QStringLiteral("secondary"));
    m_action->setCursor(Qt::PointingHandCursor);
    m_action->hide();

    layout->addWidget(m_icon, 0, Qt::AlignHCenter);
    layout->addWidget(m_title);
    layout->addWidget(m_detail);
    layout->addSpacing(Theme::Dim::SpaceXs);
    layout->addWidget(m_action, 0, Qt::AlignHCenter);

    connect(m_action, &QPushButton::clicked, this, &EmptyStateWidget::actionTriggered);
}

void EmptyStateWidget::setTitle(const QString &title)
{
    m_title->setText(title);
    m_title->setVisible(!title.isEmpty());
}

void EmptyStateWidget::setDetail(const QString &detail)
{
    m_detail->setText(detail);
    m_detail->setVisible(!detail.isEmpty());
}

void EmptyStateWidget::setAction(const QString &text)
{
    m_action->setText(text);
    m_action->setVisible(!text.isEmpty());
}

void EmptyStateWidget::setActionVariant(const QString &variant)
{
    m_action->setProperty("variant", variant);
    if (m_action->style()) {
        m_action->style()->unpolish(m_action);
        m_action->style()->polish(m_action);
    }
}
