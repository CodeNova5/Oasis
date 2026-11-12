/**
 * @file    colors.h
 * @brief   Color design tokens for the NetGuard Fluent UI.
 *
 * Single source of truth for the palette in docs/Design/DESIGN_SYSTEM.md §2.
 * The X-macro keeps the C++ palette, the QSS token names (styles.qss) and the
 * light-theme counterpart in sync: every color exists in both modes and owns
 * exactly one token name.
 *
 * QSS is authored against the token name, e.g. `background: @surface-primary;`.
 * ThemeManager substitutes the active mode's value at runtime.
 *
 * @author  Ali Sakkaf
 */
#pragma once
#include <QColor>
#include <QString>

/**
 * NETGUARD_PALETTE(X)
 *   X(cppId, qss-token, dark value, light value)
 */
#define NETGUARD_PALETTE(X)                                                     \
    /* ── Surfaces ──────────────────────────────────────────────────────── */ \
    X(surfaceWindow,   "surface-window",   "#111318", "#F3F5F8")                \
    X(surfaceSidebar,  "surface-sidebar",  "#171A21", "#FBFCFD")                \
    X(surfacePrimary,  "surface-primary",  "#1C2029", "#FFFFFF")                \
    X(surfaceElevated, "surface-elevated", "#242A35", "#FFFFFF")                \
    X(surfaceHover,    "surface-hover",    "#2B3240", "#EDF1F6")                \
    X(surfaceSelected, "surface-selected", "rgba(76, 141, 255, 0.15)",          \
                                           "rgba(37, 99, 235, 0.10)")           \
    X(borderDefault,   "border-default",   "#343B48", "#D9DFE8")                \
    /* ── Accent & semantic ─────────────────────────────────────────────── */ \
    X(accentPrimary,   "accent-primary",   "#4C8DFF", "#2563EB")                \
    X(accentHover,     "accent-hover",     "#6BA1FF", "#1D4ED8")                \
    X(accentSubtle,    "accent-subtle",    "rgba(76, 141, 255, 0.15)",          \
                                           "rgba(37, 99, 235, 0.10)")           \
    X(semanticSuccess, "semantic-success", "#3FB982", "#1F9D6B")                \
    X(successSubtle,   "success-subtle",   "rgba(63, 185, 130, 0.12)",          \
                                           "rgba(31, 157, 107, 0.10)")          \
    X(semanticWarning, "semantic-warning", "#E6AD4D", "#B8791A")                \
    X(warningSubtle,   "warning-subtle",   "rgba(230, 173, 77, 0.12)",          \
                                           "rgba(184, 121, 26, 0.10)")          \
    X(semanticDanger,  "semantic-danger",  "#E36B70", "#C8484F")                \
    X(dangerSubtle,    "danger-subtle",    "rgba(227, 107, 112, 0.12)",         \
                                           "rgba(200, 72, 79, 0.10)")           \
    X(semanticInfo,    "semantic-info",    "#62B5E8", "#2A7FB8")                \
    X(infoSubtle,      "info-subtle",      "rgba(98, 181, 232, 0.12)",          \
                                           "rgba(42, 127, 184, 0.10)")          \
    /* ── Text ──────────────────────────────────────────────────────────── */ \
    X(textPrimary,     "text-primary",     "#F3F5F8", "#161A20")                \
    X(textSecondary,   "text-secondary",   "#A1A9B7", "#5B6473")                \
    X(textMuted,       "text-muted",       "#6C7586", "#8A93A3")                \
    X(textOnAccent,    "text-on-accent",   "#FFFFFF", "#FFFFFF")                \
    X(textOnDanger,    "text-on-danger",   "#1A1113", "#FFFFFF")                \
    X(focusRing,       "focus-ring",       "#4C8DFF", "#2563EB")                \
    /* ── Data visualisation ────────────────────────────────────────────── */ \
    X(chartDownload,   "chart-download",   "#4C8DFF", "#2563EB")                \
    X(chartUpload,     "chart-upload",     "#3FB982", "#1F9D6B")                \
    /* ── Chrome details ────────────────────────────────────────────────── */ \
    X(scrollbarHandle,      "scrollbar-handle",       "#52525B", "#C6CCD6")     \
    X(scrollbarHandleHover, "scrollbar-handle-hover", "#71717A", "#A6AEBB")     \
    X(tooltipBackground,    "tooltip-background",     "#242A35", "#161A20")     \
    X(tooltipText,          "tooltip-text",           "#F3F5F8", "#F3F5F8")

namespace Theme {

/// Active-mode-ready palette. Access members by their camelCase id.
struct Palette
{
#define NETGUARD_PALETTE_MEMBER(id, token, darkValue, lightValue) QString id;
    NETGUARD_PALETTE(NETGUARD_PALETTE_MEMBER)
#undef NETGUARD_PALETTE_MEMBER
};

/// Build the palette for a mode. Values are raw QSS fragments (hex or rgba).
inline Palette palette(bool dark)
{
    Palette p;
#define NETGUARD_PALETTE_ASSIGN(id, token, darkValue, lightValue)               \
    p.id = QString::fromLatin1(dark ? darkValue : lightValue);
    NETGUARD_PALETTE(NETGUARD_PALETTE_ASSIGN)
#undef NETGUARD_PALETTE_ASSIGN
    return p;
}

/// Convenience conversion for custom-painted widgets (charts, badges, icons).
/// Understands both hex values and the `rgba(r, g, b, a)` tints used in QSS.
inline QColor qcolor(const QString &value)
{
    const QString trimmed = value.trimmed();
    if (trimmed.startsWith(QLatin1String("rgba"), Qt::CaseInsensitive)) {
        const int open = trimmed.indexOf(QLatin1Char('('));
        const int close = trimmed.lastIndexOf(QLatin1Char(')'));
        if (open > 0 && close > open) {
            const QStringList parts = trimmed.mid(open + 1, close - open - 1)
                                          .split(QLatin1Char(','), Qt::SkipEmptyParts);
            if (parts.size() == 4) {
                QColor c(parts.at(0).trimmed().toInt(),
                         parts.at(1).trimmed().toInt(),
                         parts.at(2).trimmed().toInt());
                c.setAlphaF(parts.at(3).trimmed().toDouble());
                return c;
            }
        }
        return QColor();
    }
    return QColor::fromString(trimmed);
}

/// Resolve a color token by its QSS token name for the given mode.
/// Returns an invalid QColor when the token does not exist.
inline QColor colorForToken(const QString &tokenName, bool dark)
{
    const Palette p = palette(dark);
#define NETGUARD_PALETTE_LOOKUP(id, token, darkValue, lightValue)               \
    if (tokenName == QLatin1String(token))                                      \
        return qcolor(p.id);
    NETGUARD_PALETTE(NETGUARD_PALETTE_LOOKUP)
#undef NETGUARD_PALETTE_LOOKUP
    return QColor();
}

} // namespace Theme
