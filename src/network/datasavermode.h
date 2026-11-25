/**
 * @file    datasavermode.h
 * @brief   Data Saver Off/Enforce mode: versioned persistence and the one-time
 *          migration away from the legacy three-state value (DS-002).
 *
 * The automation PRD allows exactly two modes. The control that predates it had
 * three (0 = off, 1 = monitor, 2 = enforce), and monitor was the compiled
 * default. Loading is therefore conservative:
 *
 *  - a legacy 0 stays Off;
 *  - a legacy 1 (monitor) migrates to Off, because monitoring never enforced and
 *    an upgrade must not start enforcement on its own;
 *  - a legacy 2 stays Enforce;
 *  - a missing, malformed, or newer stored value fails closed to Off.
 *
 * The migration is idempotent: once `modeVersion` is stored, the legacy value is
 * never read again. A newer version is left untouched (a newer build may still
 * understand it) and this build keeps running with automation off.
 *
 * The module has no UI and no service dependency, so the migration rules are
 * tested without Qt Widgets, elevation, or a capture thread.
 *
 * @author  Oasis
 */
#pragma once

#include <QSettings>
#include <QString>

namespace DataSaverMode {

/// The only two modes the automation contract permits.
enum class Mode {
    Off = 0,
    Enforce = 1
};

namespace Store {
constexpr int kCurrentVersion = 2;
constexpr const char *kGroup = "Oasis/DataSaver";
constexpr const char *kVersionKey = "modeVersion";
constexpr const char *kModeKey = "mode";
constexpr const char *kLegacyValueKey = "legacyValue";
} // namespace Store

/// Wire token: "off" or "enforce". Never "monitor".
QString token(Mode mode);

/// Parses a stored token. Case-insensitive; returns false for anything unknown.
bool fromToken(const QString &text, Mode *mode);

/// Maps the legacy three-state value. `recognized` is false outside 0..2.
Mode fromLegacyValue(int value, bool *recognized);

struct LoadResult {
    Mode mode = Mode::Off;
    bool migrated = false;        // a legacy value existed and was mapped
    bool invalid = false;         // the stored value was unsupported; mode is Off
    bool legacyValueKnown = false;
    int legacyValue = -1;
    bool writeFailed = false;
    QString diagnostic;           // empty unless migrated or rejected
};

/// Reads the persisted mode, migrating the legacy value on first run. A newer
/// stored version is never overwritten; an unreadable token under the current
/// version is repaired to Off so the rejection is reported once, not every start.
LoadResult load(QSettings &settings);

/// Writes the current version and mode token. Returns false when the settings
/// backend reports an error, so a caller can report a failed write instead of
/// claiming the mode was stored.
bool save(QSettings &settings, Mode mode);

} // namespace DataSaverMode
