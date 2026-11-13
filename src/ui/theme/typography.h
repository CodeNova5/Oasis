/**
 * @file    typography.h
 * @brief   Type scale tokens (DESIGN_SYSTEM.md §3).
 *
 * Sizes are CSS pixels, matching the QSS values, so C++-painted text and
 * stylesheet text scale together.
 *
 * @author  Oasis
 */
#pragma once
#include <QFont>
#include <QFontDatabase>
#include <QStringList>

namespace Theme {
namespace Type {

inline constexpr const char *FamilyPrimary  = "Segoe UI Variable";
inline constexpr const char *FamilyFallback = "Segoe UI";

/// Type scale (px).
inline constexpr int MetricLarge   = 30; // KPI numbers
inline constexpr int PageTitle     = 24; // global header screen titles
inline constexpr int SectionHeading = 16;
inline constexpr int CardHeading   = 14;
inline constexpr int Body          = 13;
inline constexpr int Secondary     = 12;
inline constexpr int Metadata      = 11;

/// Font weights.
inline constexpr int WeightRegular  = 400;
inline constexpr int WeightSemibold = 600;
inline constexpr int WeightBold     = 700;

/// Family list for QSS `font-family: ...;` with a native fallback.
inline QString familyList()
{
    return QStringLiteral("\"%1\", \"%2\", sans-serif")
        .arg(QString::fromLatin1(FamilyPrimary),
             QString::fromLatin1(FamilyFallback));
}

/// The app-wide base font, preferring Segoe UI Variable when installed.
inline QFont baseFont()
{
    const QStringList families = QFontDatabase::families();
    const QString family = families.contains(QString::fromLatin1(FamilyPrimary))
                               ? QString::fromLatin1(FamilyPrimary)
                               : QString::fromLatin1(FamilyFallback);
    QFont f(family);
    f.setPixelSize(Body);
    f.setWeight(QFont::Normal);
    f.setHintingPreference(QFont::PreferFullHinting);
    return f;
}

} // namespace Type
} // namespace Theme
