/**
 * @file    networkmonitor.h
 * @brief   Raw-socket packet capture thread with background caching and true hardware speed.
 * @author  Ali Sakkaf
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
#include "identity/applicationidentity.h"
#include "identity/serviceresolver.h"
#include "identity/processlineage.h"
#include "identity/processgroupmanager.h"

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
    QList<NetGuard::ProcessGroup> processGroups() const;
    QString createProcessGroup(const QString &name);
    bool renameProcessGroup(const QString &groupId, const QString &name);
    bool addProcessGroupMember(const QString &groupId, NetGuard::GroupMemberType type,
                               const QString &value, QString *error = nullptr);
    bool removeProcessGroupMember(const QString &groupId, NetGuard::GroupMemberType type,
                                  const QString &value);

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
    void serviceSnapshotReady(const NetGuard::ServicePidMap &services);
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
    void groupSnapshotReady(const QList<NetGuard::ProcessGroup> &groups);

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

    QMutex m_cacheMutex;
    QHash<QString, quint32> m_tcpCache;
    QHash<QString, quint32> m_udpCache;
    QHash<quint16, quint32> m_tcpListenCache;
    QHash<quint16, quint32> m_udpAnyCache;
    QHash<quint32, QString> m_procCache;

    // NG-010: identity resolution for PIDs that own live connections. Kept on
    // the cache thread; failures are remembered so protected processes are not
    // re-opened on every refresh.
    NetGuard::ApplicationIdentityResolver m_identityResolver;
    QHash<quint32, ApplicationIdentity> m_identityCache;
    QHash<quint32, quint32> m_identityFailurePids; // pid -> IdentityResolutionStatus

    // NG-012: one cached SCM snapshot backs every service lookup, so a machine
    // with dozens of svchost processes costs one enumeration per refresh window.
    NetGuard::ServiceResolver m_serviceResolver;
    NetGuard::ServicePidMap m_serviceCache; // last snapshot sent to the UI
    QString m_lastServiceError;

    // NG-013: parent/child graph with creation times. Owned by the cache thread;
    // the records for PIDs that own traffic are published for the packet loop.
    NetGuard::ProcessLineage m_lineage;
    QHash<quint32, NetGuard::ProcessLineageRecord> m_lineageCache;

    // NG-014: activity groups rebuilt from the identity, publisher, service, and
    // lineage evidence of the PIDs that own traffic. Manual edits persist
    // through QSettings; derived groups are rebuilt on every refresh.
    NetGuard::ProcessGroupManager m_groupManager;
    QHash<quint32, NetGuard::GroupBinding> m_groupCache;
    // Guards m_groupManager for GUI edits and holds the last published set.
    mutable QMutex m_groupMutex;
    QList<NetGuard::ProcessGroup> m_publishedGroups;

    // Throttles stale-mapping diagnostics emitted from the cache thread.
    qint64 m_lastStaleReportMs = 0;
};
