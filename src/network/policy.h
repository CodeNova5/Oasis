/**

  * @file   policy.h
  * @brief  Telemetry contracts and Qt metatypes for observations, identities, attribution, policies, and audit events (NG-002).
  * @author Codebuff
  */

#pragma once

#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QDateTime>
#include <QMetaType>
#include <QSettings>

// ─── Application identity ───────────────────────────────────────────────────
struct ApplicationIdentity
{
    QString id;                         // Unique identifier for this identity
    QString displayName;                // Human-readable display name
    QStringList executablePaths;        // Canonical executable paths
    QString publisher;                  // Authenticode publisher
    enum class SignerStatus { Unsigned, Signed, Invalid, Unknown };
    SignerStatus signerStatus = SignerStatus::Unknown;
    QString productName;                // Product name from metadata
    QString originalFileName;           // OriginalFilename version metadata (NG-010)
    QString fileVersion;                // FileVersion version metadata (NG-010)
    QString companyName;                // CompanyName version metadata (NG-010)
    QString packageFamilyName;          // AppX / UWP package family name
    QStringList services;               // Associated Windows services
    QStringList processNames;           // Process names
    QByteArray fingerprints;            // Hash fingerprints (Authenticode, version)
    enum class Confidence { Confirmed, StrongInference, WeakInference, Unknown };
    Confidence confidence = Confidence::Unknown;
};

Q_DECLARE_METATYPE(ApplicationIdentity)

// ─── Direction enum ─────────────────────────────────────────────────────────
enum class NetworkDirection : int {
    Download,  // Inbound (RX)
    Upload,    // Outbound (TX)
    Both       // Combined
};

// ─── Activity observation ───────────────────────────────────────────────────
struct ActivityObservation
{
    QDateTime timestamp;          // When the observation was captured
    QString identityId;           // Link to ApplicationIdentity
    quint32 pid = 0;              // Process ID
    NetworkDirection direction = NetworkDirection::Download;
    quint64 bytes = 0;            // Bytes transferred in this observation
    QString protocol;             // TCP, UDP, ICMP, etc.
    QString localEndpoint;        // e.g. "192.168.1.100:50000"
    QString remoteEndpoint;       // e.g. "93.184.216.34:443"
    QString domain;               // DNS domain or TLS SNI if available
    enum class AttributionSource { Confirmed, StrongInference, WeakInference, Unknown };
    AttributionSource attributionSource = AttributionSource::Unknown;
    enum class Classification { Confirmed, Likely, Possible, Unknown };
    Classification classification = Classification::Unknown;
    QString details;              // Free-form explanation/evidence
};

Q_DECLARE_METATYPE(ActivityObservation)

// ─── Network policy ─────────────────────────────────────────────────────────
struct NetworkPolicy
{
    QString id;              // Unique policy identifier
    QString scope;           // e.g. "path", "publisher", "service", "package", "group", "executable", "port", "protocol"
    QString targetId;        // The path/publisher/service/target this policy applies to
    NetworkDirection direction = NetworkDirection::Download;
    enum class Action { Allow, Notify, Ask, Throttle, Block, Schedule, NoAction };
    enum class ScheduleType { None, Recurring, Expiration, Both };
    ScheduleType scheduleType = ScheduleType::None;
    Action action = Action::Allow;
    quint64 rateBitsPerSecond = 0;  // Rate limit in bits/sec (0 = unlimited)
    QString schedule;        // e.g. "work-hours", "metered-hours", "overnight", or cron-like
    QDateTime expiration;    // When the policy expires (or null for persistent)
    QString source;          // e.g. "user", "automatic", "AI", "system"
    bool enabled = true;     // Whether the policy is currently active
    QString description;     // Human-readable explanation
};

Q_DECLARE_METATYPE(NetworkPolicy)

// ─── Throttle result ────────────────────────────────────────────────────────
// Returned by enforcement coordinator to describe what happened with a policy.
struct NetworkPolicyThrottleResult
{
    enum class Status { NotApplied, Applied, Removed, Failed };
    Status status = Status::NotApplied;
    QString message;         // Human-readable result description
    QString policyId;        // The policy ID this result refers to
    QString executablePath;  // Path the policy was applied to
    bool  uploadLimited = false;
    bool  downloadLimited = false;
    QString uploadReason;    // Why upload shaping succeeded/fails
    QString downloadReason;  // Why download shaping succeeds/fails
};

Q_DECLARE_METATYPE(NetworkPolicyThrottleResult)

// ─── Audit event ────────────────────────────────────────────────────────────
// Persisted audit record for detection, classification, recommendation, decision, enforcement.
struct AuditEvent
{
    QDateTime timestamp;           // When the event occurred
    enum class EventType { Detection, Classification, Recommendation, UserDecision,
                           AutomaticDecision, EnforcementRequest, EnforcementResult,
                           PolicyChange, ProcessGroupMembershipChange };
    EventType type = EventType::Detection;
    QString scope;               // What the event applies to (path, pid, publisher, etc.)
    QString reason;              // Why this event was generated
    QString result;              // What happened (allowed, blocked, throttled, etc.)
    QString errorInfo;           // Error details if failed
    QString relatedIdentityId;   // Link to ApplicationIdentity if applicable
    QString relatedPolicyId;     // Link to NetworkPolicy if applicable
    QString details;             // Free-form structured details
    // NOTE: Packet payload content must NOT be stored - only metadata.
};

// ─── Scope matching ─────────────────────────────────────────────────────────
// Check if a policy's scope matches the given executable scope identifier.
// Group scope acts as a persistent learned category - once a group has learned
// a category, new members inherit it (read-only inspection, never changes the group).
static bool scopeMatches(const NetworkPolicy &policy, const QString &scopeIdentifier);

Q_DECLARE_METATYPE(AuditEvent)

// ─── Serialization helpers ──────────────────────────────────────────────────
// Convert structs to JSON strings (for persistence, serialization, audit export)
QString toJson(const ApplicationIdentity &id);
ApplicationIdentity fromJsonApplicationIdentity(const QString &json);

QString toJson(const ActivityObservation &obs);
ActivityObservation fromJsonActivityObservation(const QString &json);

QString toJson(const NetworkPolicy &policy);
NetworkPolicy fromJsonNetworkPolicy(const QString &json);

QString toJson(const NetworkPolicyThrottleResult &result);
NetworkPolicyThrottleResult fromJsonNetworkPolicyThrottleResult(const QString &json);

QString toJson(const AuditEvent &event);
AuditEvent fromJsonAuditEvent(const QString &json);

// ─── Policy store ──────────────────────────────────────────────────────────────
// Persistent policy store with versioned persistence, migration, and JSON import/export.
// Policies are stored under QSettings group "NetGuard/Policies".
// Version 1 format: QSettings map with key "policies" containing a QVariantMap per policy.
// Version 2 format: JSON array under "policies" key (introduced for NG-020).
// Malformed entries are rejected with a warning and omitted; the store never throws.
struct PolicyStore
{
    static constexpr int kLegacyStoreVersion = 1; // QSettings map format
    static constexpr int kCurrentStoreVersion = 2; // JSON array format

    // Load all policies from QSettings, migrating old formats gracefully.
    // Returns the list of valid policies; invalid entries are logged and skipped.
    static QList<NetworkPolicy> loadPolicies();

    // Save the given policies back to QSettings, overwriting the stored list.
    static void savePolicies(const QList<NetworkPolicy> &policies);

    // Export all policies as a JSON array string (for backup / external editing).
    // Each policy is serialized with toJson(NetworkPolicy).
    static QString exportPoliciesJson();

    // Import policies from a JSON array string, merging with existing policies.
    // Policies whose "id" already exists replace the old one; new ids are appended.
    // Invalid JSON entries are skipped with a warning; the store never throws.
    static bool importPoliciesJson(const QString &json);

    // Internal: migration entry from old QSettings format to the new versioned format.
    static bool migrateOldFormat(QSettings &settings);
};

Q_DECLARE_METATYPE(PolicyStore)

// ─── Throttle Result serialization ──────────────────────────────────────────
QString toJson(const NetworkPolicyThrottleResult &result);
NetworkPolicyThrottleResult fromJsonNetworkPolicyThrottleResult(const QString &json);

// ─── Audit Event serialization ──────────────────────────────────────────────

QString toJson(const AuditEvent &event);
AuditEvent fromJsonAuditEvent(const QString &json);