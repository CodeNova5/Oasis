/**
 * @file    networkmonitor.h
 * @brief   Raw-socket packet capture thread with background caching and true hardware speed.
 * @author  Oasis
 */
#pragma once

#include <QThread>
#include <QStringList>
#include <QMutex>
#include <QTimer>
#include <QList>
#include <QHash>
#include <atomic>
#include <chrono>
#include "packetparser.h"
#include "attribution/attributionprivacy.h"
#include "attribution/dnsobserver.h"
#include "attribution/dnscorrelator.h"
#include "attribution/tlsobserver.h"
#include "attribution/quicobserver.h"
#include "identity/applicationidentity.h"
#include "identity/serviceresolver.h"
#include "identity/processlineage.h"
#include "identity/processgroupmanager.h"
#include "identity/foregroundsignal.h"

struct AdapterInfo {
    QString ip;
    QString ipv6; // IPv6 support
    QString description;
    bool    hasGateway = false;
    quint32 index = 0;
};

struct CapturedPacketInfo {
    ParsedPacket pkt;
    quint32 pid;
    QString proc;
    bool isService;
    // NG-010: durable identity of the owning executable, when resolved.
    QString identityId;
    QString identityName;
    // NG-011: Authenticode evidence carried with the identity.
    QString identityPublisher;
    ApplicationIdentity::SignerStatus signerStatus = ApplicationIdentity::SignerStatus::Unknown;
    // NG-013: lineage of the owning process instance.
    qint64  processStartMs = 0;   // 0 when the start time could not be read
    quint32 parentPid = 0;
    QString parentName;
    // NG-014: durable activity group of the owning process, when grouped.
    QString groupId;
    QString groupName;
    ApplicationIdentity::Confidence groupConfidence = ApplicationIdentity::Confidence::Unknown;
    // NG-041: whether the owning PID is the foreground application or one of its
    // live children. Advisory only: classification and recommendations may read
    // it, but it never applies, withdraws, or overrides a policy.
    Oasis::ForegroundAssociation foreground = Oasis::ForegroundAssociation::None;
};
Q_DECLARE_METATYPE(QList<CapturedPacketInfo>)

class NetworkMonitor : public QThread
{
    Q_OBJECT
public:
    explicit NetworkMonitor(QObject *parent = nullptr);
    ~NetworkMonitor() override;

    static QList<AdapterInfo> enumerateAdapters();
    static int recommendedAdapterIndex(const QList<AdapterInfo> &list);

    void setAdapterIP(const QString &ip);
    void startCapture();
    void stopCapture();

    // ── NG-016 group inspection and editing, called from the GUI thread ──
    // Edits are serialized with the cache thread through m_groupMutex and are
    // persisted by ProcessGroupManager, so a rename or a removal survives a
    // restart without the user touching configuration files.
    QList<Oasis::ProcessGroup> processGroups() const;
    QString createProcessGroup(const QString &name);
    bool renameProcessGroup(const QString &groupId, const QString &name);
    bool addProcessGroupMember(const QString &groupId, Oasis::GroupMemberType type,
                               const QString &value, QString *error = nullptr);
    bool removeProcessGroupMember(const QString &groupId, Oasis::GroupMemberType type,
                                  const QString &value);

    // NG-031/NG-032: names recently resolved by DNS or seen in a visible TLS
    // SNI for a destination address, with the owning process/identity and the
    // attribution source. Expired records are filtered, so a direct-IP
    // connection never inherits a stale name.
    QList<DomainAttribution> attributionsForAddress(const QString &address) const;

    // Every live address as one combined summary, sorted by address. Used by the
    // NG-055 attribution export so support receives the same resolution the
    // tree shows, including each name's confidence and evidence.
    QList<DestinationNameSummary> attributionSummaries() const;

    // NG-036: attribution privacy controls. The collection flags are read by
    // the capture thread on every packet, so they are atomics rather than a
    // mutex-guarded struct; retention is applied to the correlator under its
    // own lock.
    void setAttributionPrivacy(const AttributionPrivacySettings &settings);
    AttributionPrivacySettings attributionPrivacy() const;
    // Drop every name -> address record, keeping the two known destinations
    // already shown in the tree from being applied to new connections.
    void clearAttributionHistory();
    int attributionRecordCount() const;

    // NG-041: the last foreground application sample. The snapshot carries the
    // sample time; `associationFor()` returns None once it is stale, so a caller
    // cannot act on an old answer. The signal is advisory only.
    Oasis::ForegroundSnapshot foregroundSnapshot() const;

    bool    isCapturing()  const { return m_captureRunning.load(); }

signals:
    void packetsCapturedBatch(const QList<CapturedPacketInfo> &batch);
    void speedUpdated(quint64 rxBps, quint64 txBps);
    void captureError(const QString &msg);
    void captureStarted();
    void captureStopped();

    // ── NG-003 diagnostics: aggregated capture gaps, safe to emit often ──
    // Sent at the packet-batch cadence with per-interval counts (0 = none).
    void captureGapDetected(int droppedPackets, int unresolvedPids,
                            int unknownDirections, const QString &adapterName);
    // Sent when a cached connection mapping changes owner between refreshes.
    void staleMappingDetected(quint32 pid, const QString &expected, const QString &actual);
    // Sent when the capture adapter could not be opened or used.
    void adapterDiagnostic(const QString &adapterName, const QString &reason);
    // NG-010: emitted once per PID whose executable identity could not be
    // resolved (typed failure); traffic is still attributed by process name.
    void identityResolutionFailed(quint32 pid, const QString &status, const QString &message);
    // NG-012: services hosted by the PIDs that currently own connections, sent
    // only when the mapping or a service state changes.
    void serviceSnapshotReady(const Oasis::ServicePidMap &services);
    // NG-012: the service manager could not be queried; traffic keeps flowing
    // and is attributed to the process instead of a service.
    void serviceLookupFailed(const QString &reason);
    // NG-013: a PID now belongs to a different process than the one tracked
    // (creation time changed). Cached attributions were discarded before this
    // was emitted, so the new process is resolved from scratch.
    void pidReuseDetected(quint32 pid, const QString &previousExecutable,
                          const QString &currentExecutable,
                          qint64 previousStartMs, qint64 currentStartMs);
    // NG-016: the activity group set changed (membership, name, confidence, or
    // a live PID). Sent only when something visible actually changed.
    void groupSnapshotReady(const QList<Oasis::ProcessGroup> &groups);
    // NG-030: metadata from a visible DNS message. The payload is parsed and
    // discarded; the event carries the question, answers, confidence, and the
    // owning process when the socket could be resolved.
    void dnsObservation(const DnsEvent &event);
    // NG-032: a visible TLS ClientHello. `serverName` is set only when SNI was
    // actually parsed; fragmented, encrypted, ECH-hidden, and malformed
    // handshakes arrive with an unavailable status and no name.
    void tlsObservation(const TlsObservation &observation);
    // NG-033: safe QUIC long-header metadata. A valid Initial is reported as
    // encrypted with no hostname; unsupported versions, version negotiation,
    // and malformed packets are explicit instead of being misclassified.
    void quicObservation(const QuicObservation &observation);
    // NG-041: the foreground application changed (window, PID, helper set, or
    // group). Sent only when the visible state moves, so a static window does
    // not repaint the tree every refresh. The snapshot is advisory and stamped
    // with the time it was sampled.
    void foregroundSnapshotReady(const Oasis::ForegroundSnapshot &snapshot);

protected:
    void run() override;

private:
    void refreshLocalIPs();
    void updateCaches();
    // Re-read the manager and emit groupSnapshotReady when the visible set moved.
    void syncGroupSnapshot();

    QString m_adapterIP;
    QString m_adapterIPv6;
    quint32 m_adapterIndex = 0;

    std::atomic<bool> m_stopFlag{false};
    std::atomic<bool> m_captureRunning{false};

    QTimer *m_speedTimer = nullptr;
    QStringList m_localIPs;

    quint64 m_sysRxLast = 0;
    quint64 m_sysTxLast = 0;
    bool m_firstTick = true;
    std::chrono::steady_clock::time_point m_lastTick;

    mutable QMutex m_cacheMutex;
    QHash<QString, quint32> m_tcpCache;
    QHash<QString, quint32> m_udpCache;
    QHash<quint16, quint32> m_tcpListenCache;
    QHash<quint16, quint32> m_udpAnyCache;
    QHash<quint32, QString> m_procCache;

    // NG-031: bounded DNS answer -> destination cache, kept on the capture
    // thread and queried safely from the GUI thread.
    DnsCorrelator m_dnsCorrelator;

    // NG-036: which attribution observers run, read per packet by the capture
    // thread. Defaults match AttributionPrivacySettings; the application applies
    // the persisted values when it starts.
    std::atomic<bool> m_collectDns{true};
    std::atomic<bool> m_collectTlsSni{true};
    std::atomic<bool> m_collectQuic{true};
    std::atomic<bool> m_redactDestinationsInExport{true};

    // NG-010: identity resolution for PIDs that own live connections. Kept on
    // the cache thread; failures are remembered so protected processes are not
    // re-opened on every refresh.
    Oasis::ApplicationIdentityResolver m_identityResolver;
    QHash<quint32, ApplicationIdentity> m_identityCache;
    QHash<quint32, quint32> m_identityFailurePids; // pid -> IdentityResolutionStatus

    // NG-012: one cached SCM snapshot backs every service lookup, so a machine
    // with dozens of svchost processes costs one enumeration per refresh window.
    Oasis::ServiceResolver m_serviceResolver;
    Oasis::ServicePidMap m_serviceCache; // last snapshot sent to the UI
    QString m_lastServiceError;

    // NG-013: parent/child graph with creation times. Owned by the cache thread;
    // the records for PIDs that own traffic are published for the packet loop.
    Oasis::ProcessLineage m_lineage;
    QHash<quint32, Oasis::ProcessLineageRecord> m_lineageCache;

    // NG-014: activity groups rebuilt from the identity, publisher, service, and
    // lineage evidence of the PIDs that own traffic. Manual edits persist
    // through QSettings; derived groups are rebuilt on every refresh.
    Oasis::ProcessGroupManager m_groupManager;
    QHash<quint32, Oasis::GroupBinding> m_groupCache;
    // Guards m_groupManager for GUI edits and holds the last published set.
    mutable QMutex m_groupMutex;
    QList<Oasis::ProcessGroup> m_publishedGroups;

    // NG-041: the last validated foreground sample, read by the packet loop
    // under m_cacheMutex. m_lastForeground is cache-thread-only and is used to
    // emit foregroundSnapshotReady only when the visible state changes.
    Oasis::ForegroundSnapshot m_foregroundCache;
    Oasis::ForegroundSnapshot m_lastForeground;

    // Throttles stale-mapping diagnostics emitted from the cache thread.
    qint64 m_lastStaleReportMs = 0;
};
