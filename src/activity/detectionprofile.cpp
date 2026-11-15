/**
 * @file    detectionprofile.cpp
 * @author  Oasis
 */
#include "detectionprofile.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

namespace Activity {

namespace {

const QString kSettingsKey = QStringLiteral("profile");

} // namespace

QString DetectionProfileStore::settingsGroup()
{
    return QStringLiteral("Oasis/Detection");
}

QList<DetectionProfileOption> detectionProfiles()
{
    // The numbers quoted here are the ones detectionSettings() applies; keep
    // the two in step so the screen never promises something it does not do.
    DetectionProfileOption balanced;
    balanced.profile = DetectionProfile::Balanced;
    balanced.key = QStringLiteral("balanced");
    balanced.label = QStringLiteral("Balanced");
    balanced.summary = QStringLiteral(
        "The tuned default. Reports traffic that is unusual for the application "
        "or large in absolute terms.");
    balanced.detail = QStringLiteral(
        "Spikes at 1 MiB/s or 3x an application's recent rate, sustained for 3 "
        "seconds. Steady heavy use from 5 MiB/s. Background transfers from 32 "
        "MiB. Data use warning at 50 MiB and critical at 100 MiB within 90 "
        "seconds. Unrecognized traffic from 16 MiB.");

    DetectionProfileOption metered;
    metered.profile = DetectionProfile::Metered;
    metered.key = QStringLiteral("metered");
    metered.label = QStringLiteral("Metered connection");
    metered.summary = QStringLiteral(
        "For metered or limited connections: smaller transfers are worth "
        "knowing about, so the feed reports more.");
    metered.detail = QStringLiteral(
        "Spikes at 512 KiB/s or 3x an application's recent rate, sustained for 3 "
        "seconds. Steady heavy use from 2 MiB/s. Background transfers from 16 "
        "MiB. Data use warning at 25 MiB and critical at 50 MiB within 90 "
        "seconds. Unrecognized traffic from 8 MiB.");

    return { balanced, metered };
}

QString detectionProfileKey(DetectionProfile profile)
{
    switch (profile) {
    case DetectionProfile::Balanced: return QStringLiteral("balanced");
    case DetectionProfile::Metered:  return QStringLiteral("metered");
    }
    return QStringLiteral("balanced");
}

QString detectionProfileLabel(DetectionProfile profile)
{
    for (const DetectionProfileOption &option : detectionProfiles()) {
        if (option.profile == profile)
            return option.label;
    }
    return QStringLiteral("Balanced");
}

bool detectionProfileFromKey(const QString &key, DetectionProfile *profile)
{
    if (!profile)
        return false;
    const QString normalized = key.trimmed().toLower();
    for (const DetectionProfileOption &option : detectionProfiles()) {
        if (option.key == normalized) {
            *profile = option.profile;
            return true;
        }
    }
    return false;
}

DetectorSettings detectionSettings(DetectionProfile profile)
{
    DetectorSettings settings;
    if (profile == DetectionProfile::Metered) {
        // Every value here is a floor that decides when traffic becomes worth a
        // card. Sustain, tolerance and the relative multiplier are unchanged:
        // they control false alarms, and a metered user does not want more of
        // those either.
        settings.absoluteFloorBytesPerSecond = 512 * 1024;
        settings.highBandwidthFloorBytesPerSecond = 2 * 1024 * 1024;
        settings.backgroundVolumeThreshold = 16 * 1024 * 1024;
        settings.consumptionWarningBytes = 25 * 1024 * 1024;
        settings.consumptionCriticalBytes = 50 * 1024 * 1024;
        settings.unresolvedBytesThreshold = 8 * 1024 * 1024;
        settings.unresolvedFloorBytesPerSecond = 128 * 1024;
    }
    return settings;
}

QString DetectionProfileStore::toJson(DetectionProfile profile)
{
    QJsonObject root;
    root[QStringLiteral("schemaVersion")] = kSchemaVersion;
    root[QStringLiteral("profile")] = detectionProfileKey(profile);
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
}

DetectionProfile DetectionProfileStore::fromJson(const QString &json, bool *ok)
{
    if (ok) *ok = false;

    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8());
    if (!document.isObject())
        return DetectionProfile::Balanced;
    const QJsonObject root = document.object();
    if (root.value(QStringLiteral("schemaVersion")).toInt(0) > kSchemaVersion)
        return DetectionProfile::Balanced;

    DetectionProfile profile = DetectionProfile::Balanced;
    if (!detectionProfileFromKey(root.value(QStringLiteral("profile")).toString(),
                                 &profile))
        return DetectionProfile::Balanced;

    if (ok) *ok = true;
    return profile;
}

DetectionProfile DetectionProfileStore::load() const
{
    QSettings settings;
    return load(settings);
}

DetectionProfile DetectionProfileStore::load(QSettings &settings) const
{
    settings.beginGroup(settingsGroup());
    const QString stored = settings.value(kSettingsKey).toString();
    settings.endGroup();
    return fromJson(stored);
}

bool DetectionProfileStore::save(DetectionProfile profile) const
{
    QSettings settings;
    return save(profile, settings);
}

bool DetectionProfileStore::save(DetectionProfile profile, QSettings &settings) const
{
    settings.beginGroup(settingsGroup());
    settings.setValue(kSettingsKey, toJson(profile));
    settings.endGroup();
    settings.sync();
    return settings.status() == QSettings::NoError;
}

void DetectionProfileStore::reset() const
{
    QSettings settings;
    settings.beginGroup(settingsGroup());
    settings.remove(QString());
    settings.endGroup();
    settings.sync();
}

} // namespace Activity
