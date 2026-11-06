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

protected:
    void run() override;

private:
    void refreshLocalIPs();
    void updateCaches();
    QString getServiceNameFromPid(quint32 pid) const;

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

    // Throttles stale-mapping diagnostics emitted from the cache thread.
    qint64 m_lastStaleReportMs = 0;
};
