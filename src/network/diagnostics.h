/**
 * @file   diagnostics.h
 * @brief  Diagnostics for capture gaps (dropped packets, unresolved PIDs, unknown direction, stale mappings, unavailable adapters) - NG-003.
 * @author Codebuff
 */

#pragma once

#include <QAbstractListModel>
#include <QObject>
#include <QList>
#include <QVariant>
#include <QDateTime>

// ─── Diagnostic reason enums ────────────────────────────────────────────────

enum class PacketDropReason : int {
    None = 0,
    BufferOverflow,
    SocketError,
    InvalidChecksum,
    TooLarge,
    PromiscuousModeDisabled,
    NotPromiscuous,
    OutOfMemory,
    Other
};

enum class PidResolutionStatus : int {
    Resolved = 0,
    Unresolved,
    ServiceHost,
    KernelMode,
    PermissionDenied,
    ProcessNotFound,
    Other
};

enum class DirectionStatus : int {
    DirectionKnown = 0,
    UnknownDirection,
    LocalOnly,
    ExternalOnly,
    Loopback,
    Other
};

enum class AdapterStatus : int {
    AdapterAvailable = 0,
    AdapterUnavailable,
    AdapterMissingDriver,
    AdministratorRequired,
    NoSuitableAdapter,
    Other
};

enum class MappingStatus : int {
    Fresh = 0,
    StaleMapping,
    MissingMapping
};

// ─── Diagnostic record ──────────────────────────────────────────────────────
struct DiagnosticRecord
{
    QDateTime timestamp;     // When the diagnostic event occurred
    PacketDropReason dropReason = PacketDropReason::None;  // 0 if not a drop
    PidResolutionStatus pidStatus = PidResolutionStatus::Resolved;
    DirectionStatus directionStatus = DirectionStatus::DirectionKnown;
    AdapterStatus adapterStatus = AdapterStatus::AdapterAvailable;
    MappingStatus mappingStatus = MappingStatus::Fresh;
    QString details;         // Human-readable description
    QString context;         // Where/what was happening (e.g. "capture loop", "policy apply")
    quint32 affectedPid = 0; // PID involved, if any
    QString affectedProcess; // Process name, if known
};

// ─── Roles for DiagnosticsModel ────────────────────────────────────────────
enum DiagnosticsRole : int {
    RoleTimestamp = Qt::UserRole,     // QDateTime
    RoleDropReason,                    // PacketDropReason (int)
    RolePidStatus,                     // PidResolutionStatus (int)
    RoleDirectionStatus,               // DirectionStatus (int)
    RoleAdapterStatus,                 // AdapterStatus (int)
    RoleMappingStatus,                 // MappingStatus (int)
    RoleDetails,                       // QString
    RoleContext,                       // QString
    RoleAffectedPid,                   // quint32
    RoleAffectedProcess                // QString
};

// ─── DiagnosticsModel ───────────────────────────────────────────────────────
// A QAbstractListModel that holds DiagnosticRecord objects and reports gap statistics.
// Records are bounded so a persistent capture gap cannot grow memory without limit.
// The UI can subscribe to model signals to show a support/diagnostics view.
class DiagnosticsModel : public QAbstractListModel
{
    Q_OBJECT
public:
    // Upper bound on retained records. The oldest record is evicted first.
    enum { MaxRecords = 500 };

    explicit DiagnosticsModel(QObject *parent = nullptr);
    ~DiagnosticsModel() override = default;

    // QAbstractListModel interface
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    // Public API: add a diagnostic record (bounded, oldest evicted first)
    void addRecord(const DiagnosticRecord &record);

    // Remove every record (reset / export).
    void clear();

    // Convenience reporters
    void reportDroppedPackets(int count, const QString &adapter, const QString &context);
    void reportUnresolvedPid(quint32 pid, const QString &processName, const QString &context);
    void reportUnknownDirection(const QString &packetSummary, const QString &context);
    void reportStaleMapping(quint32 pid, const QString &expected, const QString &actual, const QString &context);
    void reportAdapterUnavailable(const QString &adapterName, const QString &reason);
    // NG-012: service identity could not be resolved; traffic keeps flowing.
    void reportServiceLookupFailed(quint32 pid, const QString &serviceName, const QString &reason);

    // Utilities
    int droppedPacketsCount() const;
    int unresolvedPidsCount() const;
    int unknownDirectionCount() const;
    int staleMappingsCount() const;
    int adapterUnavailableCount() const;
    QList<DiagnosticRecord> records() const;

    // Export the current diagnostics as versioned JSON (no packet payloads).
    QString toJson() const;

signals:
    // Emitted when a new record is added; the UI can react or filter
    void recordAdded(const DiagnosticRecord &record);
    // Emitted when the model changes (e.g. after batch reporting)
    void modelUpdated();

private:
    QList<DiagnosticRecord> m_records;
};
