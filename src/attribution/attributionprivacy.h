/**
 * @file    attributionprivacy.h
 * @brief   Attribution privacy controls (NG-036): which metadata is collected,
 *          how long it is kept, and how destinations are redacted on export.
 * @author  Ali Sakkaf
 */
#pragma once

#include <QString>

class QSettings;

/**
 * Attribution collection settings.
 *
 * Only metadata is ever collected: DNS names/addresses/TTLs, visible TLS SNI,
 * and QUIC clear-header fields. Packet payloads are not copied by any observer,
 * so there is no payload setting to turn off — this struct decides which
 * metadata observers run and how long their derived records live.
 */
struct AttributionPrivacySettings
{
    bool collectDns = true;
    bool collectTlsSni = true;
    bool collectQuic = true;
    /// How long derived name -> address records are retained, in seconds. DNS
    /// TTLs are capped by this value, so lowering it also shortens records that
    /// were created under a longer retention.
    int retentionSeconds = 3600;
    /// Redact destination addresses and host names in exported diagnostics by
    /// default; the export can still be produced verbatim on request.
    bool redactDestinationsInExport = true;

    bool collectsAnything() const { return collectDns || collectTlsSni || collectQuic; }
};

namespace AttributionPrivacy {

QString settingsGroup();
constexpr int kSchemaVersion = 1;
constexpr int kMinRetentionSeconds = 60;      // one minute
constexpr int kMaxRetentionSeconds = 86400;   // one day
constexpr int kDefaultRetentionSeconds = 3600;

/// Bound a requested retention to the supported range.
int clampedRetentionSeconds(int seconds);

/// Human-readable retention, for the Settings tab.
QString retentionDescription(int seconds);

/**
 * Persist the collection settings in QSettings.
 *
 * `load` never fails: an unreadable, malformed, or newer-schema payload falls
 * back to the defaults instead of half-applying a config it does not
 * understand. `save` only writes fields this schema knows.
 */
class Store
{
public:
    AttributionPrivacySettings load() const;
    AttributionPrivacySettings load(QSettings &settings) const;

    bool save(const AttributionPrivacySettings &settings) const;
    bool save(const AttributionPrivacySettings &settings, QSettings &settingsStore) const;

    /// Remove the stored settings so the defaults apply again.
    void reset() const;
    void reset(QSettings &settings) const;

    /// The serialised form (a single JSON object) used by tests and diagnostics.
    static QString toJson(const AttributionPrivacySettings &settings);
    static AttributionPrivacySettings fromJson(const QString &json, bool *ok = nullptr);
};

// ─── Destination redaction ──────────────────────────────────────────────────
// Used by the diagnostics export. Address literals keep their network part and
// lose the host part, and a host name keeps only its top-level label: enough to
// correlate a report without disclosing where the user went.

/// True when `text` is an IPv4 or IPv6 address literal rather than a name.
bool isAddressLiteral(const QString &text);

/// Redact one destination token. A non-destination token (process name, file
/// name, free text) is returned unchanged.
QString redactDestination(const QString &text);

/// Redact every address literal and host name inside free text, leaving PIDs,
/// process names, file names, and version numbers alone.
QString redactDestinationText(const QString &text);

} // namespace AttributionPrivacy
