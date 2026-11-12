/**
 * @file    dimensions.h
 * @brief   Spacing, radii and component sizes on the 4 px grid
 *          (DESIGN_SYSTEM.md §4).
 *
 * These are logical pixels. The stylesheet consumes the matching tokens
 * (`@space-lg`, `@radius-card`, ...); C++ layout code uses the constants.
 *
 * @author  Ali Sakkaf
 */
#pragma once

namespace Theme {
namespace Dim {

// ── Spacing (4 px grid) ─────────────────────────────────────────────────────
inline constexpr int SpaceXs = 4;
inline constexpr int SpaceSm = 8;
inline constexpr int SpaceMd = 12;
inline constexpr int SpaceLg = 16;
inline constexpr int SpaceXl = 24;
inline constexpr int Space2Xl = 32;
inline constexpr int Space3Xl = 40;

// ── Shell ───────────────────────────────────────────────────────────────────
inline constexpr int SidebarExpanded = 232;
inline constexpr int SidebarCollapsed = 64;
inline constexpr int HeaderHeight = 60;
inline constexpr int StatusBarHeight = 28;

// ── Content ─────────────────────────────────────────────────────────────────
inline constexpr int PagePaddingH = 24;
inline constexpr int PagePaddingV = 24;

// ── Radii ───────────────────────────────────────────────────────────────────
inline constexpr int RadiusCard = 10;
inline constexpr int RadiusModal = 12;
inline constexpr int RadiusControl = 6;
inline constexpr int RadiusBadge = 6;

// ── Controls ────────────────────────────────────────────────────────────────
inline constexpr int ButtonHeight = 36;
inline constexpr int ButtonPaddingH = 16;
inline constexpr int InputHeight = 38;
inline constexpr int FilterPillHeight = 32;
inline constexpr int BadgeHeight = 22;
inline constexpr int StatusDot = 6;
inline constexpr int NavIcon = 18;
inline constexpr int InlineIcon = 16;

// ── Tables ──────────────────────────────────────────────────────────────────
inline constexpr int RowStandard = 48;
inline constexpr int RowCompact = 40;

} // namespace Dim
} // namespace Theme
