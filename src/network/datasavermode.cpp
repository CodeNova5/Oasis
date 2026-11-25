/**
 * @file    datasavermode.cpp
 * @brief   Data Saver Off/Enforce mode persistence and legacy migration.
 * @author  Oasis
 */
#include "datasavermode.h"

#include <QMetaType>
#include <QVariant>

namespace DataSaverMode {
namespace {

// QSettings stores integers as typed registry/INI values, so a string in an
// integer slot is not a number that can be trusted. Anything else (a string, a
// list, a newer enum token) is treated as unsupported and fails closed.
bool integerVariant(const QVariant &variant, int *value)
{
    switch (variant.metaType().id()) {
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::LongLong:
    case QMetaType::ULongLong:
    case QMetaType::Short:
    case QMetaType::UShort: {
        bool ok = false;
        const int parsed = variant.toInt(&ok);
        if (ok && value) *value = parsed;
        return ok;
    }
    default:
        return false;
    }
}

// Diagnostics end up in an audit record, so a malformed stored value must not
// turn into an unbounded string.
QString briefValue(const QVariant &variant)
{
    const QString text = variant.toString().trimmed().left(40);
    return text.isEmpty() ? QStringLiteral("empty") : text;
}

} // namespace

QString token(Mode mode)
{
    return mode == Mode::Enforce ? QStringLiteral("enforce") : QStringLiteral("off");
}

bool fromToken(const QString &text, Mode *mode)
{
    if (text.compare(QStringLiteral("off"), Qt::CaseInsensitive) == 0) {
        if (mode) *mode = Mode::Off;
        return true;
    }
    if (text.compare(QStringLiteral("enforce"), Qt::CaseInsensitive) == 0) {
        if (mode) *mode = Mode::Enforce;
        return true;
    }
    return false;
}

Mode fromLegacyValue(int value, bool *recognized)
{
    if (recognized) *recognized = value >= 0 && value <= 2;
    return value == 2 ? Mode::Enforce : Mode::Off;
}

LoadResult load(QSettings &settings)
{
    LoadResult result;
    settings.beginGroup(QLatin1String(Store::kGroup));

    const QVariant versionValue = settings.value(QLatin1String(Store::kVersionKey));
    if (versionValue.isValid()) {
        int version = -1;
        if (!integerVariant(versionValue, &version) || version != Store::kCurrentVersion) {
            // A newer build owns this value; read it as Off and leave it in
            // place so that build keeps its setting.
            result.invalid = true;
            result.diagnostic = QStringLiteral("unsupported stored Data Saver mode version \"%1\"")
                                    .arg(briefValue(versionValue));
            settings.endGroup();
            return result;
        }

        const QString storedToken = settings.value(QLatin1String(Store::kModeKey)).toString();
        if (!fromToken(storedToken, &result.mode)) {
            // A token this build cannot read is repaired to Off rather than left
            // behind, so the rejection is reported once instead of on every
            // start. A newer version is never rewritten (see above).
            result.invalid = true;
            result.mode = Mode::Off;
            result.diagnostic = QStringLiteral("unsupported stored Data Saver mode \"%1\"")
                                    .arg(storedToken.trimmed().left(40));
            settings.setValue(QLatin1String(Store::kModeKey), token(Mode::Off));
            settings.sync();
            result.writeFailed = settings.status() != QSettings::NoError;
        }
        settings.endGroup();
        return result;
    }

    // No version yet: this is either a clean install or the legacy three-state
    // control. Adopt the versioned form either way, exactly once.
    if (settings.contains(QLatin1String(Store::kModeKey))) {
        const QVariant raw = settings.value(QLatin1String(Store::kModeKey));
        int legacy = -1;
        if (!integerVariant(raw, &legacy)) {
            result.invalid = true;
            result.diagnostic = QStringLiteral("unsupported legacy Data Saver mode value \"%1\"")
                                    .arg(briefValue(raw));
        } else {
            bool recognized = false;
            result.mode = fromLegacyValue(legacy, &recognized);
            result.migrated = true;
            result.legacyValueKnown = true;
            result.legacyValue = legacy;
            if (!recognized) {
                result.invalid = true;
                result.diagnostic = QStringLiteral("legacy Data Saver mode %1 is not supported")
                                        .arg(legacy);
            }
        }
    }

    settings.setValue(QLatin1String(Store::kVersionKey), Store::kCurrentVersion);
    settings.setValue(QLatin1String(Store::kModeKey), token(result.mode));
    if (result.legacyValueKnown)
        settings.setValue(QLatin1String(Store::kLegacyValueKey), result.legacyValue);
    settings.sync();
    result.writeFailed = settings.status() != QSettings::NoError;
    settings.endGroup();
    return result;
}

bool save(QSettings &settings, Mode mode)
{
    settings.beginGroup(QLatin1String(Store::kGroup));
    settings.setValue(QLatin1String(Store::kVersionKey), Store::kCurrentVersion);
    settings.setValue(QLatin1String(Store::kModeKey), token(mode));
    settings.sync();
    const bool ok = settings.status() == QSettings::NoError;
    settings.endGroup();
    return ok;
}

} // namespace DataSaverMode
