/**
 * @file    detectionprofile.h
 * @brief   User-facing detection sensitivity: Balanced or Metered.
 *
 * The profile only decides how eagerly the Activity screen calls traffic
 * notable. Capture, attribution, retention, exports and enforcement behave
 * identically under both, so switching profile never changes what is collected
 * or blocked -- only which events the feed chooses to show.
 *
 * @author  Oasis
 */
#pragma once

#include <QList>
#include <QString>

#include "activity/activitydetector.h"

class QSettings;

namespace Activity {

/// Balanced is the tuned default. Metered assumes data costs money and lowers
/// the volume and rate at which traffic is worth a card.
enum class DetectionProfile {
    Balanced,
    Metered
};

struct DetectionProfileOption
{
    DetectionProfile profile = DetectionProfile::Balanced;
    QString key;
    QString label;      // "Balanced"
    QString summary;    // one line, shown next to the radio button
    QString detail;     // what actually changes, in plain language
};

/// Both profiles in presentation order (least sensitive first).
QList<DetectionProfileOption> detectionProfiles();

QString detectionProfileKey(DetectionProfile profile);
QString detectionProfileLabel(DetectionProfile profile);
bool detectionProfileFromKey(const QString &key, DetectionProfile *profile);

/**
 * Detector settings for a profile.
 *
 * Both start from the tuned defaults; Metered lowers only absolute floors and
 * volume thresholds. The relative rule (3x an application's own median rate)
 * and the sustain requirements are identical, because loosening those produces
 * false alarms on applications that are naturally bursty.
 */
DetectorSettings detectionSettings(DetectionProfile profile);

/**
 * Persisted profile, stored as one versioned JSON object in QSettings.
 *
 * `load` never fails: an unreadable, malformed or newer-schema payload falls
 * back to Balanced rather than half-applying a config it does not understand.
 */
class DetectionProfileStore
{
public:
    static QString settingsGroup();
    static constexpr int kSchemaVersion = 1;

    DetectionProfile load() const;
    DetectionProfile load(QSettings &settings) const;

    bool save(DetectionProfile profile) const;
    bool save(DetectionProfile profile, QSettings &settings) const;

    /// Remove the stored value so Balanced applies again.
    void reset() const;

    /// Serialised form (a single JSON object), used by tests and diagnostics.
    static QString toJson(DetectionProfile profile);
    static DetectionProfile fromJson(const QString &json, bool *ok = nullptr);
};

} // namespace Activity
