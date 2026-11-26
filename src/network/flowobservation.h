/**
 * @file    flowobservation.h
 * @brief   Canonical Data Saver `FlowObservation` v1 (DS-003).
 *
 * `FlowObservation` is the evaluation input defined in
 * docs/DATA_SAVER_CONTRACT.md §3. It is not an enforcement request and is never
 * persisted. This module is pure Qt Core: it does not read the network, the
 * policy store, the audit log, an AI provider, or the capture thread. The
 * caller converts a capture batch into `FlowCaptureSample`s and feeds them in;
 * `FlowObservationBuilder` aggregates them under a bounded, mutex-guarded store.
 *
 * Missing or weak evidence is never promoted. A sample without a usable owning
 * process is dropped (and counted) instead of being assigned a placeholder
 * owner; a domain seen only by DNS or SNI stays a strong or weak inference; a
 * flow shared by two process instances is marked `shared` on both observations
 * and never described as a single owner.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QMutex>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QtGlobal>

/// `process.processRole` (§3.1).
enum class FlowProcessRole {
    Main,
    Child,
    Service,
    Unknown
};

/// `process.foregroundState` (§3.1).
enum class FlowForegroundState {
    ForegroundActive,
    ForegroundIdle,
    Background,
    Unknown
};

/// `process.interactionState` (§3.1).
enum class FlowInteractionState {
    Interactive,
    Idle,
    Unknown
};

/// `flow.domainSource` (§3.1). `None` means no domain evidence.
enum class FlowDomainSource {
    Dns,
    Sni,
    EchOuter,
    None
};

/// `flow.domainConfidence` (§3.1).
enum class FlowDomainConfidence {
    Confirmed,
    StrongInference,
    WeakInference,
    Unknown
};

/// One evaluation input. Field names follow the contract, not the PRD snippets.
struct FlowObservation
{
    static constexpr int kSchemaVersion = 1;

    struct ProcessFields
    {
        QString processInstanceId;              // pid:<pid>:<processStartMs>
        quint32 pid = 0;
        quint32 parentPid = 0;
        QString identityId;
        QString exeName;
        QString exePath;
        QString exeVersion;
        FlowProcessRole role = FlowProcessRole::Unknown;
        FlowForegroundState foregroundState = FlowForegroundState::Unknown;
        quint32 foregroundRootPid = 0;
        FlowInteractionState interactionState = FlowInteractionState::Unknown;
    };

    struct FlowFields
    {
        QString flowId;
        QString protocol;
        QString localEndpoint;
        QString remoteEndpoint;
        QString domain;                          // empty = unknown, omitted on the wire
        FlowDomainSource domainSource = FlowDomainSource::None;
        FlowDomainConfidence domainConfidence = FlowDomainConfidence::Unknown;
        bool multiplexed = false;
        bool shared = false;
    };

    struct MetricFields
    {
        quint64 rxBytes = 0;
        quint64 txBytes = 0;
        qint64 durationMs = 0;
        quint64 rateRxBitsPerSecond = 0;
        quint64 milestoneBytes = 0;
        int milestoneIndex = 0;
    };

    struct UxSignalFields
    {
        bool blockingToUser = false;
        bool latencySensitive = false;
        bool deferrable = false;
        bool avoidable = false;
        QStringList detectorTags;
        // Bounded so a misbehaving detector cannot grow an observation forever.
        static constexpr int kMaxDetectorTags = 16;
        static constexpr int kMaxDetectorTagLength = 64;
    };

    QString observationId;
    QDateTime timestamp;
    ProcessFields process;
    FlowFields flow;
    MetricFields metrics;
    UxSignalFields uxSignals;
};

/// Formats `address:port`, bracketing IPv6 literals so the endpoint is
/// unambiguous. Returns an empty string for an invalid address or port.
QString flowEndpoint(const QString &address, quint16 port);

/// Normalizes a domain key: lower-case, IDNA ASCII, no trailing dot, no port or
/// wildcard. Returns an empty string when the value cannot be a domain.
QString normalizeFlowDomain(const QString &domain);

/// True when `id` matches `prefix` + 8–32 lower-case hex (§3.2).
bool isFlowIdentifier(const QString &id, const QString &prefix);

/// Serializes a complete observation. `schemaVersion` is always written.
QJsonObject toJson(const FlowObservation &observation);

/// Parses and validates an observation. A missing `schemaVersion` is read as 1;
/// a newer version, a missing required field, or an unknown enum token rejects
/// the whole payload, leaving `observation` untouched and `error` set.
bool fromJson(const QJsonObject &object, FlowObservation *observation,
              QString *error = nullptr);

/// One packet as the caller observed it. The caller resolves capture evidence
/// (identity, lineage, foreground) before constructing this; the builder does
/// no platform work.
struct FlowCaptureSample
{
    QDateTime timestamp;
    qint64 monotonicMs = 0;               // capture monotonic time, for duration/rate
    quint32 pid = 0;
    quint32 parentPid = 0;
    qint64 processStartMs = 0;            // 0 when unreadable; kept explicit as :0
    QString processName;                  // normalized base name
    QString executablePath;
    QString identityId;
    QString executableVersion;
    bool service = false;

    enum class Foreground {
        Unknown,        // no usable foreground sample
        None,           // sample exists and this PID is not associated
        App,            // the foreground application itself
        Child           // a live child of the foreground application
    };
    Foreground foreground = Foreground::Unknown;
    quint32 foregroundRootPid = 0;

    QString protocol;
    QString localAddress;
    quint16 localPort = 0;
    QString remoteAddress;
    quint16 remotePort = 0;
    quint32 bytes = 0;
    bool download = true;

    // Evidence the caller already knows. `false` means no positive evidence,
    // which is the honest default; it is not a claim that the flow is single.
    bool multiplexed = false;

    // Filled by DS-004. 0 / 0 means no milestone is set yet.
    quint64 milestoneBytes = 0;
    int milestoneIndex = 0;
};

/**
 * Bounded, thread-safe aggregation of capture samples into observations.
 *
 * Identity rules:
 *  - a flow is keyed by protocol, endpoints, and process instance, so two
 *    processes on one 4-tuple are two observations, both marked `shared`;
 *  - `flowId` is hashed once per flow and is never recycled within a session;
 *  - `processInstanceId` includes the process start time, so PID reuse cannot
 *    inherit an earlier process's counters.
 *
 * The caller must pass a fixed `sessionNonce` only in tests; production uses a
 * random nonce so ids are not reused across boots.
 */
class FlowObservationBuilder
{
public:
    // A flow with no traffic for this long is treated as replaced, so a new
    // connection on the same 4-tuple starts with fresh counters.
    static constexpr qint64 kDefaultIdleExpiryMs = 2 * 60 * 1000;

    explicit FlowObservationBuilder(quint64 sessionNonce = 0, int maxFlows = 512);

    /// Installs or upgrades the name evidence for a destination address.
    /// Weaker evidence never replaces stronger evidence for the same address.
    void setDestinationName(const QString &address, const QString &name,
                            FlowDomainSource source, FlowDomainConfidence confidence,
                            bool multiplexed = false);

    /// Adds one packet. A sample without a pid, process name, protocol, or valid
    /// endpoints is counted as dropped and changes nothing.
    void addSample(const FlowCaptureSample &sample);

    /// Drops flows idle for longer than `maxIdleMs`, so a re-established
    /// connection receives a fresh flow id instead of inheriting old counters.
    void expireIdleFlows(qint64 nowMs, qint64 maxIdleMs);

    /// A snapshot of every live flow, one observation each. Observation ids are
    /// minted per call; the contract mints one per evaluation input.
    QList<FlowObservation> observations() const;

    int flowCount() const;
    int droppedSamples() const;
    int evictedFlows() const;
    void reset();

private:
    struct DestinationEvidence
    {
        QString name;
        FlowDomainSource source = FlowDomainSource::None;
        FlowDomainConfidence confidence = FlowDomainConfidence::Unknown;
        bool multiplexed = false;
    };

    struct FlowState
    {
        QString flowId;
        QString endpointKey;
        QString protocol;
        QString localEndpoint;
        QString remoteEndpoint;
        QString processInstanceId;
        quint32 pid = 0;
        quint32 parentPid = 0;
        quint32 foregroundRootPid = 0;
        QString identityId;
        QString exeName;
        QString exePath;
        QString exeVersion;
        FlowProcessRole role = FlowProcessRole::Unknown;
        FlowForegroundState foregroundState = FlowForegroundState::Unknown;
        FlowInteractionState interactionState = FlowInteractionState::Unknown;
        quint64 rxBytes = 0;
        quint64 txBytes = 0;
        qint64 startMs = 0;
        qint64 lastMs = 0;
        quint64 lastRateRx = 0;
        qint64 lastRateMs = 0;
        quint64 rateRxBitsPerSecond = 0;
        bool multiplexed = false;
        quint64 milestoneBytes = 0;
        int milestoneIndex = 0;
        QDateTime lastTimestamp;
    };

    QString mintObservationId(const QString &flowId) const;
    void evictOldestLocked();
    void removeFlowLocked(const QString &key);

    mutable QMutex m_mutex;
    QHash<QString, FlowState> m_flows;
    QHash<QString, QSet<QString>> m_endpointOwners; // endpoint key -> process instances
    QHash<QString, DestinationEvidence> m_destinations;
    quint64 m_nonce = 0;
    mutable quint64 m_sequence = 0;
    quint64 m_flowSequence = 0;
    int m_maxFlows = 512;
    int m_droppedSamples = 0;
    int m_evictedFlows = 0;
};
