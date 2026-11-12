/**
 * @file    appsidebar.cpp
 * @author  Ali Sakkaf
 */
#include "appsidebar.h"

#include "ui/theme/dimensions.h"
#include "ui/theme/typography.h"

#include <QButtonGroup>
#include <QLabel>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

QLabel *sectionLabel(const QString &text, QWidget *parent)
{
    auto *label = new QLabel(text.toUpper(), parent);
    label->setProperty("uiRole", QStringLiteral("navSection"));
    return label;
}

} // namespace

AppSidebar::AppSidebar(QWidget *parent)
    : QFrame(parent)
{
    setObjectName(QStringLiteral("AppSidebar"));
    setFixedWidth(Theme::Dim::SidebarExpanded);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, Theme::Dim::SpaceMd);
    root->setSpacing(0);

    // ── Brand ───────────────────────────────────────────────────────────────
    auto *brand = new QWidget(this);
    brand->setContentsMargins(0, 0, 0, 0);
    auto *brandLayout = new QVBoxLayout(brand);
    brandLayout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                                    Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    brandLayout->setSpacing(2);

    auto *title = new QLabel(QStringLiteral("NETGUARD"), brand);
    title->setObjectName(QStringLiteral("appTitle"));
    auto *subtitle = new QLabel(QStringLiteral("Network intelligence"), brand);
    subtitle->setObjectName(QStringLiteral("appSubtitle"));
    brandLayout->addWidget(title);
    brandLayout->addWidget(subtitle);
    root->addWidget(brand);

    // ── Navigation (MONITOR / CONTROL / HISTORY) ────────────────────────────
    m_topLayout = new QVBoxLayout;
    m_topLayout->setContentsMargins(Theme::Dim::SpaceSm, 0,
                                    Theme::Dim::SpaceSm, 0);
    m_topLayout->setSpacing(2);
    root->addLayout(m_topLayout);
    root->addStretch(1);

    // ── Pinned group (SYSTEM) ───────────────────────────────────────────────
    m_bottomLayout = new QVBoxLayout;
    m_bottomLayout->setContentsMargins(Theme::Dim::SpaceSm, Theme::Dim::SpaceXs,
                                       Theme::Dim::SpaceSm, 0);
    m_bottomLayout->setSpacing(2);
    root->addLayout(m_bottomLayout);

    m_group = new QButtonGroup(this);
    m_group->setExclusive(true);
}

void AppSidebar::addSection(const QString &title)
{
    m_topLayout->addWidget(sectionLabel(title, this));
}

void AppSidebar::addPinnedSection(const QString &title)
{
    m_bottomLayout->addWidget(sectionLabel(title, this));
}

QToolButton *AppSidebar::createItem(const QString &label, int index)
{
    auto *button = new QToolButton(this);
    button->setText(label);
    button->setProperty("uiRole", QStringLiteral("navItem"));
    button->setCheckable(true);
    button->setAutoRaise(true);
    button->setCursor(Qt::PointingHandCursor);
    button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    button->setToolButtonStyle(Qt::ToolButtonTextOnly);
    button->setFocusPolicy(Qt::StrongFocus);
    m_group->addButton(button, index);
    m_items.append(button);

    connect(button, &QToolButton::clicked, this, [this, index]() {
        setCurrentIndex(index);
        emit itemActivated(index);
    });
    return button;
}

int AppSidebar::addItem(const QString &label)
{
    const int index = m_items.size();
    m_topLayout->addWidget(createItem(label, index));
    return index;
}

int AppSidebar::addPinnedItem(const QString &label)
{
    const int index = m_items.size();
    m_bottomLayout->addWidget(createItem(label, index));
    return index;
}

void AppSidebar::setCurrentIndex(int index)
{
    if (index < 0 || index >= m_items.size())
        return;
    m_current = index;
    m_items.at(index)->setChecked(true);
}
