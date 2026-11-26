/**
 * @file    datasaverprofiles.h
 * @brief   Local signatures and profile rules for Data Saver (DS-006).
 *
 * The engine resolves one FlowObservation locally: it reuses the bundled
 * EndpointCatalog and BandwidthGuard classification, maps them to the Data Saver
 * classification vocabulary, and applies an ordered profile rule keyed by
 * detector tag and foreground state. It has no network client and no enforcement
 * channel; the result is a recommendation that DS-008/DS-009 may resolve.
 *
 * Foreground-idle is derived only from the observation's foreground state and
 * interaction state. DS-003 writes `unknown` when its foreground sample is stale
 * or missing, and this engine never guesses a state from a process name, window
 * title, or rate. Protected executables, latency-sensitive signals, interactive
 * package installs, foreground-active traffic, and unknown activity are guarded
 * against throttle/block even when a custom profile rule asks for one.
 *
 * @author  Oasis
 */
#pragma once

#include <QList>
#include <QString>
#include <QStringList>

#include "attribution/activityclassifier.h"
#include "flowobservation.h"
#include "network/bandwidthguard.h"
#include "network/policy.h"

enum class SignatureClassification {
    AppUpdate,
    ExtensionUpdate,
    PackageInstall,
    AiInference,
    MediaStream,
    Telemetry,
    PolicyAction,
    Unknown
};

QString signatureClassificationToken(SignatureClassification classification);
bool signatureClassificationFromToken(const QString &text,
                                      SignatureClassification *classification);

/// Foreground bucket a profile rule applies to. `Foreground` means active or
/// idle; `Unknown` matches only an `Any` rule.
enum class ProfileForeground {
    Any,
    Foreground,
    Active,
    Idle,
    Background,
    Unknown
};

QString profileForegroundToken(ProfileForeground foreground);
bool profileForegroundFromToken(const QString &text, ProfileForeground *foreground);

struct ProfileRule
{
    QString id;
    QString detectorTag;
    ProfileForeground foreground = ProfileForeground::Any;
    SignatureClassification classification = SignatureClassification::Unknown;
    NetworkPolicy::Action action = NetworkPolicy::Action::Notify;
    bool continueAfterNotify = true;
    QString scope = QStringLiteral("executable");
    quint64 rateBitsPerSecond = 0;
    double minimumConfidence = 0.0;
    bool advisoryOnly = false;
};

/// Ordered, deterministic built-in rules. Earlier rules win when several match.
QList<ProfileRule> defaultProfileRules();

struct LocalSignatureInput
{
    FlowObservation observation;
    // Identity/attribution evidence the capture layer already resolved. Empty
    // fields simply do not satisfy a rule; they are never guessed.
    ActivityQuery activity;
    bool protectedExecutable = false;
    bool latencySensitive = false;
    bool interactivePackageInstall = false;
};

struct SignatureResult
{
    bool matched = false;
    SignatureClassification classification = SignatureClassification::Unknown;
    double confidence = 0.0;
    QStringList matchedSignatureIds;
    QStringList evidence;
    QStringList detectorTags;
    QString profileRuleId;
    NetworkPolicy::Action action = NetworkPolicy::Action::Allow;
    bool continueAfterNotify = false;
    QString scope = QStringLiteral("executable");
    quint64 rateBitsPerSecond = 0;
    bool advisoryOnly = false;
    ProfileForeground foreground = ProfileForeground::Unknown;
    QString reason;
};

class LocalSignatureEngine
{
public:
    /// Uses the bundled catalog and the built-in profile.
    LocalSignatureEngine();
    explicit LocalSignatureEngine(const EndpointCatalog &catalog,
                                  const QList<ProfileRule> &profileRules = defaultProfileRules());

    SignatureResult classify(const LocalSignatureInput &input) const;

    /// Replaces the profile. Rules are validated as a set; an invalid rule
    /// rejects the whole change and leaves the current profile untouched.
    bool setProfileRules(const QList<ProfileRule> &profileRules, QString *error = nullptr);
    QList<ProfileRule> profileRules() const { return m_profileRules; }

private:
    ActivityClassifier m_classifier;
    QList<ProfileRule> m_profileRules;
};
