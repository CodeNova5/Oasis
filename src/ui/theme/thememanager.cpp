/**
 * @file    thememanager.cpp
 * @author  Oasis
 */
#include "thememanager.h"

#include "colors.h"
#include "dimensions.h"
#include "typography.h"

#include <QApplication>
#include <QDebug>
#include <QFile>
#include <QHash>
#include <QRegularExpression>

namespace {

QString px(int value)
{
    return QString::number(value) + QStringLiteral("px");
}

/// All tokens reachable from styles.qss, for one mode.
QHash<QString, QString> buildTokenMap(ThemeManager::Mode mode)
{
    const bool dark = (mode == ThemeManager::Dark);
    const Theme::Palette c = Theme::palette(dark);

    QHash<QString, QString> t;
    t.reserve(64);

    // Colors (token name -> mode value), generated from the X-macro list.
#define OASIS_PALETTE_TOKEN(id, token, darkValue, lightValue)                \
    t.insert(QStringLiteral(token), c.id);
    OASIS_PALETTE(OASIS_PALETTE_TOKEN)
#undef OASIS_PALETTE_TOKEN

    // Spacing.
    t.insert(QStringLiteral("space-xs"), px(Theme::Dim::SpaceXs));
    t.insert(QStringLiteral("space-sm"), px(Theme::Dim::SpaceSm));
    t.insert(QStringLiteral("space-md"), px(Theme::Dim::SpaceMd));
    t.insert(QStringLiteral("space-lg"), px(Theme::Dim::SpaceLg));
    t.insert(QStringLiteral("space-xl"), px(Theme::Dim::SpaceXl));
    t.insert(QStringLiteral("space-2xl"), px(Theme::Dim::Space2Xl));
    t.insert(QStringLiteral("space-3xl"), px(Theme::Dim::Space3Xl));

    // Shell & component dimensions.
    t.insert(QStringLiteral("sidebar-width"), px(Theme::Dim::SidebarExpanded));
    t.insert(QStringLiteral("header-height"), px(Theme::Dim::HeaderHeight));
    t.insert(QStringLiteral("statusbar-height"), px(Theme::Dim::StatusBarHeight));
    t.insert(QStringLiteral("radius-card"), px(Theme::Dim::RadiusCard));
    t.insert(QStringLiteral("radius-modal"), px(Theme::Dim::RadiusModal));
    t.insert(QStringLiteral("radius-control"), px(Theme::Dim::RadiusControl));
    t.insert(QStringLiteral("radius-badge"), px(Theme::Dim::RadiusBadge));
    t.insert(QStringLiteral("control-height"), px(Theme::Dim::ButtonHeight));
    t.insert(QStringLiteral("input-height"), px(Theme::Dim::InputHeight));
    t.insert(QStringLiteral("pill-height"), px(Theme::Dim::FilterPillHeight));
    t.insert(QStringLiteral("badge-height"), px(Theme::Dim::BadgeHeight));
    t.insert(QStringLiteral("inline-icon"), px(Theme::Dim::InlineIcon));
    t.insert(QStringLiteral("row-standard"), px(Theme::Dim::RowStandard));
    t.insert(QStringLiteral("row-compact"), px(Theme::Dim::RowCompact));
    t.insert(QStringLiteral("page-padding"), px(Theme::Dim::PagePaddingH));

    // Typography.
    t.insert(QStringLiteral("font-family"), Theme::Type::familyList());
    t.insert(QStringLiteral("font-size-metric"), px(Theme::Type::MetricLarge));
    t.insert(QStringLiteral("font-size-page-title"), px(Theme::Type::PageTitle));
    t.insert(QStringLiteral("font-size-section"), px(Theme::Type::SectionHeading));
    t.insert(QStringLiteral("font-size-card"), px(Theme::Type::CardHeading));
    t.insert(QStringLiteral("font-size-body"), px(Theme::Type::Body));
    t.insert(QStringLiteral("font-size-secondary"), px(Theme::Type::Secondary));
    t.insert(QStringLiteral("font-size-meta"), px(Theme::Type::Metadata));

    return t;
}

} // namespace

ThemeManager &ThemeManager::instance()
{
    static ThemeManager s;
    return s;
}

ThemeManager::ThemeManager(QObject *parent)
    : QObject(parent)
    , m_template(loadTemplate())
{
}

QString ThemeManager::loadTemplate()
{
    QFile file(QStringLiteral(":/theme/styles.qss"));
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "ThemeManager: cannot open :/theme/styles.qss";
        return QString();
    }
    return QString::fromUtf8(file.readAll());
}

QString ThemeManager::resolveTokens(const QString &templ, Mode mode)
{
    if (templ.isEmpty())
        return QString();

    const QHash<QString, QString> tokens = buildTokenMap(mode);
    static const QRegularExpression tokenRe(QStringLiteral("@([a-z0-9-]+)"));

    QString out;
    out.reserve(templ.size() + 4096);

    int last = 0;
    auto it = tokenRe.globalMatch(templ);
    while (it.hasNext()) {
        const QRegularExpressionMatch match = it.next();
        out += templ.mid(last, match.capturedStart() - last);

        const QString key = match.captured(1);
        if (tokens.contains(key)) {
            out += tokens.value(key);
        } else {
            qWarning() << "ThemeManager: unknown style token @" << key;
            out += match.captured(0); // leave visible so the gap is obvious
        }
        last = match.capturedEnd();
    }
    out += templ.mid(last);
    return out;
}

QString ThemeManager::styleSheetFor(Mode mode) const
{
    QString &cached = m_cache[mode == Dark ? 0 : 1];
    if (cached.isEmpty())
        cached = resolveTokens(m_template, mode);
    return cached;
}

QPalette ThemeManager::buildPalette(Mode mode)
{
    const Theme::Palette c = Theme::palette(mode == Dark);
    auto col = [](const QString &value) { return Theme::qcolor(value); };

    QPalette p;
    p.setColor(QPalette::Window, col(c.surfaceWindow));
    p.setColor(QPalette::WindowText, col(c.textPrimary));
    p.setColor(QPalette::Base, col(c.surfacePrimary));
    p.setColor(QPalette::AlternateBase, col(c.surfaceWindow));
    p.setColor(QPalette::Text, col(c.textPrimary));
    p.setColor(QPalette::Button, col(c.surfaceElevated));
    p.setColor(QPalette::ButtonText, col(c.textPrimary));
    p.setColor(QPalette::BrightText, col(c.semanticDanger));
    p.setColor(QPalette::ToolTipBase, col(c.tooltipBackground));
    p.setColor(QPalette::ToolTipText, col(c.tooltipText));
    p.setColor(QPalette::Highlight, col(c.accentPrimary));
    p.setColor(QPalette::HighlightedText, col(c.textOnAccent));
    p.setColor(QPalette::Link, col(c.accentPrimary));
    p.setColor(QPalette::LinkVisited, col(c.accentPrimary));
    p.setColor(QPalette::PlaceholderText, col(c.textMuted));

    // Disabled states must stay legible, never black-on-dark.
    p.setColor(QPalette::Disabled, QPalette::WindowText, col(c.textMuted));
    p.setColor(QPalette::Disabled, QPalette::Text, col(c.textMuted));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, col(c.textMuted));
    p.setColor(QPalette::Disabled, QPalette::Base, col(c.surfaceWindow));
    p.setColor(QPalette::Disabled, QPalette::Button, col(c.surfacePrimary));
    p.setColor(QPalette::Disabled, QPalette::Highlight, col(c.surfaceHover));
    p.setColor(QPalette::Disabled, QPalette::HighlightedText, col(c.textMuted));
    return p;
}

void ThemeManager::apply(QApplication *app)
{
    QApplication *target = app ? app : qApp;
    if (!target)
        return;

    target->setStyleSheet(styleSheetFor(m_mode));
    target->setPalette(buildPalette(m_mode));
    target->setFont(Theme::Type::baseFont());
}

void ThemeManager::setMode(Mode mode)
{
    if (mode == m_mode)
        return;
    m_mode = mode;
    apply();
    emit themeChanged(m_mode);
}

void ThemeManager::toggleTheme()
{
    setMode(m_mode == Dark ? Light : Dark);
}
