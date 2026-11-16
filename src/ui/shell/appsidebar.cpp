/**
 * @file    appsidebar.cpp
 * @author  Oasis
 */
#include "appsidebar.h"

#include "ui/theme/colors.h"
#include "ui/theme/dimensions.h"
#include "ui/theme/thememanager.h"
#include "ui/theme/typography.h"

#include <QButtonGroup>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLinearGradient>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QPushButton>
#include <QVBoxLayout>
#include <QtMath>

namespace {

QLabel *sectionLabel(const QString &text, QWidget *parent)
{
    auto *label = new QLabel(text, parent);
    label->setProperty("uiRole", QStringLiteral("navSection"));
    return label;
}

QIcon brandIcon()
{
    QPixmap pixmap(52, 52);
    pixmap.setDevicePixelRatio(2);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.scale(2, 2);

    QPainterPath shield;
    shield.moveTo(13, 1.5);
    shield.lineTo(23.5, 5);
    shield.lineTo(23.5, 11.5);
    shield.cubicTo(23.5, 18.5, 19, 23, 13, 25);
    shield.cubicTo(7, 23, 2.5, 18.5, 2.5, 11.5);
    shield.lineTo(2.5, 5);
    shield.closeSubpath();

    QLinearGradient gradient(0, 2, 0, 25);
    gradient.setColorAt(0, QColor(QStringLiteral("#55B8FF")));
    gradient.setColorAt(1, QColor(QStringLiteral("#1D5FD1")));
    painter.setPen(Qt::NoPen);
    painter.setBrush(gradient);
    painter.drawPath(shield);

    painter.setBrush(Qt::white);
    painter.drawEllipse(QPointF(13, 9.5), 2.2, 2.2);
    painter.drawRoundedRect(QRectF(11.8, 11.5, 2.4, 5.0), 1.0, 1.0);
    return QIcon(pixmap);
}

QIcon navIcon(const QString &label, const QColor &color)
{
    QPixmap pixmap(36, 36);
    pixmap.setDevicePixelRatio(2);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.scale(2, 2);
    QPen pen(color, 1.5);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    painter.setPen(pen);
    painter.setBrush(Qt::NoBrush);

    const QString key = label.trimmed().toLower();
    if (key == QLatin1String("overview")) {
        QPainterPath roof;
        roof.moveTo(2.2, 8.2);
        roof.lineTo(9, 2.2);
        roof.lineTo(15.8, 8.2);
        painter.drawPath(roof);
        painter.drawRoundedRect(QRectF(4.2, 7.5, 9.6, 8.2), 1.2, 1.2);
    } else if (key == QLatin1String("activity")) {
        QPainterPath pulse;
        pulse.moveTo(1.5, 9);
        pulse.lineTo(4.5, 9);
        pulse.lineTo(6.5, 4);
        pulse.lineTo(9.5, 14);
        pulse.lineTo(11.8, 7.5);
        pulse.lineTo(16.5, 7.5);
        painter.drawPath(pulse);
    } else if (key == QLatin1String("applications")) {
        painter.drawRoundedRect(QRectF(2.2, 2.2, 5.6, 5.6), 1.2, 1.2);
        painter.drawRoundedRect(QRectF(10.2, 2.2, 5.6, 5.6), 1.2, 1.2);
        painter.drawRoundedRect(QRectF(2.2, 10.2, 5.6, 5.6), 1.2, 1.2);
        painter.drawRoundedRect(QRectF(10.2, 10.2, 5.6, 5.6), 1.2, 1.2);
    } else if (key == QLatin1String("connections")) {
        painter.drawEllipse(QPointF(3.8, 9), 2.1, 2.1);
        painter.drawEllipse(QPointF(14.2, 9), 2.1, 2.1);
        painter.drawLine(QPointF(5.9, 9), QPointF(12.1, 9));
        painter.drawLine(QPointF(9, 9), QPointF(9, 3));
        painter.drawEllipse(QPointF(9, 2.2), 1.2, 1.2);
    } else if (key == QLatin1String("policies")) {
        QPainterPath shield;
        shield.moveTo(9, 1.8);
        shield.lineTo(15.5, 4.2);
        shield.lineTo(15.5, 8.5);
        shield.cubicTo(15.5, 13.2, 12.4, 15.6, 9, 16.5);
        shield.cubicTo(5.6, 15.6, 2.5, 13.2, 2.5, 8.5);
        shield.lineTo(2.5, 4.2);
        shield.closeSubpath();
        painter.drawPath(shield);
        painter.drawLine(QPointF(6.3, 9), QPointF(8.3, 11));
        painter.drawLine(QPointF(8.3, 11), QPointF(11.8, 6.8));
    } else if (key == QLatin1String("data saver")) {
        painter.drawLine(QPointF(9, 2), QPointF(9, 10.5));
        painter.drawLine(QPointF(5.8, 7.5), QPointF(9, 10.8));
        painter.drawLine(QPointF(12.2, 7.5), QPointF(9, 10.8));
        painter.drawLine(QPointF(3, 13.5), QPointF(15, 13.5));
    } else if (key == QLatin1String("insights")) {
        painter.drawEllipse(QPointF(9, 7.5), 4.7, 4.7);
        painter.drawLine(QPointF(7, 13), QPointF(11, 13));
        painter.drawLine(QPointF(7.7, 15.5), QPointF(10.3, 15.5));
    } else if (key == QLatin1String("history")) {
        painter.drawEllipse(QPointF(9, 9), 6.8, 6.8);
        painter.drawLine(QPointF(9, 5), QPointF(9, 9));
        painter.drawLine(QPointF(9, 9), QPointF(12.4, 10.8));
    } else if (key == QLatin1String("audit & reports")) {
        painter.drawRoundedRect(QRectF(4, 2.5, 10, 13.2), 1.2, 1.2);
        painter.drawLine(QPointF(7, 6), QPointF(11, 6));
        painter.drawLine(QPointF(7, 9), QPointF(11, 9));
        painter.drawLine(QPointF(7, 12), QPointF(9.5, 12));
    } else if (key == QLatin1String("hardware")) {
        painter.drawRoundedRect(QRectF(4.5, 4.5, 9, 9), 1.2, 1.2);
        painter.drawRect(QRectF(7.2, 7.2, 3.6, 3.6));
        for (qreal offset : {2.5, 7.0, 11.5}) {
            painter.drawLine(QPointF(offset, 1.8), QPointF(offset, 4.2));
            painter.drawLine(QPointF(offset, 13.8), QPointF(offset, 16.2));
            painter.drawLine(QPointF(1.8, offset), QPointF(4.2, offset));
            painter.drawLine(QPointF(13.8, offset), QPointF(16.2, offset));
        }
    } else if (key == QLatin1String("settings")) {
        painter.drawEllipse(QPointF(9, 9), 4.8, 4.8);
        painter.drawEllipse(QPointF(9, 9), 1.8, 1.8);
        for (int i = 0; i < 8; ++i) {
            const qreal angle = i * 3.1415926 / 4.0;
            painter.drawLine(QPointF(9 + qCos(angle) * 6.3, 9 + qSin(angle) * 6.3),
                             QPointF(9 + qCos(angle) * 7.7, 9 + qSin(angle) * 7.7));
        }
    } else {
        painter.drawEllipse(QPointF(9, 9), 3.2, 3.2);
    }

    return QIcon(pixmap);
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
    auto *brandLayout = new QHBoxLayout(brand);
    brandLayout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                                    Theme::Dim::SpaceLg, Theme::Dim::SpaceSm);
    brandLayout->setSpacing(Theme::Dim::SpaceMd);

    auto *logo = new QLabel(brand);
    logo->setPixmap(brandIcon().pixmap(QSize(26, 26), 2.0));
    logo->setFixedSize(26, 26);
    logo->setAttribute(Qt::WA_TransparentForMouseEvents);

    auto *brandText = new QWidget(brand);
    auto *brandTextLayout = new QVBoxLayout(brandText);
    brandTextLayout->setContentsMargins(0, 0, 0, 0);
    brandTextLayout->setSpacing(1);
    auto *title = new QLabel(QStringLiteral("OASIS"), brandText);
    title->setObjectName(QStringLiteral("appTitle"));
    auto *subtitle = new QLabel(QStringLiteral("Network intelligence"), brandText);
    subtitle->setObjectName(QStringLiteral("appSubtitle"));
    brandTextLayout->addWidget(title);
    brandTextLayout->addWidget(subtitle);

    brandLayout->addWidget(logo, 0, Qt::AlignVCenter);
    brandLayout->addWidget(brandText, 1, Qt::AlignVCenter);
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

    connect(&ThemeManager::instance(), &ThemeManager::themeChanged, this,
            [this](ThemeManager::Mode) {
        const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
        for (QPushButton *button : m_items)
            button->setIcon(navIcon(button->text(), Theme::qcolor(palette.textSecondary)));
    });
}

void AppSidebar::addSection(const QString &title)
{
    m_topLayout->addWidget(sectionLabel(title, this));
}

void AppSidebar::addPinnedSection(const QString &title)
{
    m_bottomLayout->addWidget(sectionLabel(title, this));
}

QPushButton *AppSidebar::createItem(const QString &label, int index)
{
    auto *button = new QPushButton(this);
    button->setText(label);
    button->setProperty("uiRole", QStringLiteral("navItem"));
    button->setCheckable(true);
    button->setCursor(Qt::PointingHandCursor);
    button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    button->setIconSize(QSize(Theme::Dim::NavIcon, Theme::Dim::NavIcon));
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    button->setIcon(navIcon(label, Theme::qcolor(palette.textSecondary)));
    button->setFocusPolicy(Qt::StrongFocus);
    m_group->addButton(button, index);
    m_items.append(button);

    connect(button, &QPushButton::clicked, this, [this, index]() {
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
