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
#include <QEvent>
#include <QHash>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QStyle>
#include <QSvgRenderer>
#include <QVBoxLayout>
#include <QtMath>

namespace {

// Row metrics. These are the values the sidebar mock is drawn with, so they are
// named here instead of being spread through the layout code.
constexpr int kRowHeight      = 42;
constexpr int kRowRadius      = 8;
constexpr int kRowPaddingH    = 12;
constexpr int kIconSize       = Theme::Dim::NavIcon;
constexpr int kIconGap        = 12;
constexpr int kIndicatorWidth = 3;
constexpr int kIndicatorInset = 6;

QString navIconResource(const QString &label)
{
    static const QHash<QString, QString> icons{
        {QStringLiteral("overview"),     QStringLiteral(":/icons/sidebar/layout-grid.svg")},
        {QStringLiteral("activity"),     QStringLiteral(":/icons/sidebar/activity.svg")},
        {QStringLiteral("applications"), QStringLiteral(":/icons/sidebar/app-window.svg")},
        {QStringLiteral("connections"),  QStringLiteral(":/icons/sidebar/connections.svg")},
        {QStringLiteral("policies"),     QStringLiteral(":/icons/sidebar/shield.svg")},
        {QStringLiteral("insights"),     QStringLiteral(":/icons/sidebar/insight.svg")},
        {QStringLiteral("reports"),      QStringLiteral(":/icons/sidebar/clipboard.svg")},
        {QStringLiteral("settings"),     QStringLiteral(":/icons/sidebar/settings.svg")}
    };
    return icons.value(label.trimmed().toLower());
}

/// Render a sidebar glyph in `color`, `size` logical pixels square.
QPixmap tintedIcon(const QString &resource, const QColor &color, int size, qreal dpr)
{
    QPixmap pixmap(QSize(qCeil(size * dpr), qCeil(size * dpr)));
    pixmap.setDevicePixelRatio(dpr);
    pixmap.fill(Qt::transparent);

    if (resource.isEmpty())
        return pixmap;

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    QSvgRenderer renderer(resource);
    renderer.render(&painter, QRectF(0, 0, size, size));

    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(QRectF(0, 0, size, size), color);
    return pixmap;
}

/**
 * A sidebar destination. The row is painted here rather than by the stylesheet
 * because QPushButton hard-codes a 4 px gap between icon and label, which cannot
 * express the mock's 12 px gutter / 20 px glyph / 12 px gap rhythm.
 */
class NavItem : public QPushButton
{
public:
    explicit NavItem(const QString &label, QWidget *parent)
        : QPushButton(label, parent)
    {
        setProperty("uiRole", QStringLiteral("navItem"));
        // Re-apply the sheet so the transparent navItem rule (not the generic
        // QPushButton chrome) is what the row is polished against.
        style()->unpolish(this);
        style()->polish(this);
        setCheckable(true);
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::StrongFocus);
        setFixedHeight(kRowHeight);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

protected:
    void enterEvent(QEnterEvent *event) override
    {
        QPushButton::enterEvent(event);
        update();
    }

    void leaveEvent(QEvent *event) override
    {
        QPushButton::leaveEvent(event);
        update();
    }

    void paintEvent(QPaintEvent *) override
    {
        const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
        const bool active = isChecked();
        const int radius = kRowRadius;

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);

        // Only the active and hovered rows carry a surface; the rest sit
        // directly on the sidebar.
        QColor surface;
        if (active)
            surface = Theme::qcolor(palette.accentSubtle);
        else if (isDown())
            surface = Theme::qcolor(palette.surfaceElevated);
        else if (underMouse())
            surface = Theme::qcolor(palette.surfaceHover);

        if (surface.isValid()) {
            painter.setPen(Qt::NoPen);
            painter.setBrush(surface);
            painter.drawRoundedRect(QRectF(rect()), radius, radius);
        }

        // Glyph, vertically centred on the row.
        const QColor iconColor = active ? Theme::qcolor(palette.accentPrimary)
                                        : Theme::qcolor(palette.textSecondary);
        const QPixmap icon = tintedIcon(navIconResource(text()), iconColor,
                                        kIconSize, devicePixelRatioF());
        const int iconY = rect().top() + (rect().height() - kIconSize) / 2;
        painter.drawPixmap(QPointF(kRowPaddingH, iconY), icon);

        // Label.
        QFont labelFont = font();
        labelFont.setPixelSize(Theme::Type::Body);
        labelFont.setWeight(active ? QFont::DemiBold : QFont::Medium);
        painter.setFont(labelFont);
        painter.setPen(active ? Theme::qcolor(palette.textPrimary)
                              : Theme::qcolor(palette.textSecondary));

        const int textX = kRowPaddingH + kIconSize + kIconGap;
        const QRect textRect(textX, rect().top(),
                             qMax(0, rect().right() - textX - kRowPaddingH + 1),
                             rect().height());
        painter.drawText(textRect, Qt::AlignLeft | Qt::AlignVCenter, text());

        // Keyboard focus stays visible without shifting the content.
        if (hasFocus()) {
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(Theme::qcolor(palette.focusRing), 1));
            painter.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5),
                                    radius, radius);
        }
    }
};

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
    brand->setFixedHeight(68);
    brand->setObjectName(QStringLiteral("sidebarBrand"));
    auto *brandLayout = new QHBoxLayout(brand);
    brandLayout->setContentsMargins(20, 0, 20, 0);
    brandLayout->setSpacing(12);

    auto *logo = new QLabel(brand);
    logo->setPixmap(QIcon(QStringLiteral(":/icons/sidebar/app-image.png"))
                        .pixmap(QSize(32, 32), 2.0));
    logo->setFixedSize(32, 32);
    logo->setAttribute(Qt::WA_TransparentForMouseEvents);

    auto *title = new QLabel(QStringLiteral("Oasis"), brand);
    title->setObjectName(QStringLiteral("appTitle"));

    brandLayout->addWidget(logo, 0, Qt::AlignVCenter);
    brandLayout->addWidget(title, 1, Qt::AlignVCenter);
    root->addWidget(brand);

    // ── Destinations ────────────────────────────────────────────────────────
    m_topLayout = new QVBoxLayout;
    m_topLayout->setContentsMargins(12, 4, 12, 0);
    m_topLayout->setSpacing(4);
    root->addLayout(m_topLayout);
    root->addStretch(1);

    // ── Pinned group (Settings) ─────────────────────────────────────────────
    m_bottomLayout = new QVBoxLayout;
    m_bottomLayout->setContentsMargins(12, 4, 12, 0);
    m_bottomLayout->setSpacing(4);
    root->addLayout(m_bottomLayout);

    m_group = new QButtonGroup(this);
    m_group->setExclusive(true);

    connect(&ThemeManager::instance(), &ThemeManager::themeChanged, this,
            [this](ThemeManager::Mode) {
        for (QPushButton *item : m_items)
            item->update();
        update();
    });
}

QPushButton *AppSidebar::createItem(const QString &label, int index)
{
    auto *button = new NavItem(label, this);
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
    for (int i = 0; i < m_items.size(); ++i)
        m_items.at(i)->setChecked(i == index);
    update();
}

void AppSidebar::paintEvent(QPaintEvent *event)
{
    QFrame::paintEvent(event);

    // The active row is echoed by an accent bar on the sidebar's leading edge.
    if (m_current < 0 || m_current >= m_items.size())
        return;

    const QPushButton *item = m_items.at(m_current);
    if (!item)
        return;

    const QRect row(item->mapTo(this, QPoint(0, 0)), item->size());
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setBrush(Theme::qcolor(palette.accentPrimary));
    painter.drawRoundedRect(
        QRectF(0, row.top() + kIndicatorInset,
               kIndicatorWidth, qMax(0, row.height() - 2 * kIndicatorInset)),
        kIndicatorWidth / 2.0, kIndicatorWidth / 2.0);
}
