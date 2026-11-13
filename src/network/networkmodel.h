/**
 * @file    networkmodel.h
 * @brief   QAbstractItemModel with batch-processing support for UI stability.
 * @author  Oasis
 */
#pragma once

#include <QAbstractItemModel>
#include <QHash>
#include <QVector>
#include <QTimer>
#include <QIcon>
#include <functional>
#include "attribution/activityclassifier.h"
#include "attribution/dnscorrelator.h"
#include "identity/foregroundsignal.h"
#include "packetparser.h"
#include "network/policy.h"
#include "identity/serviceresolver.h"

struct CapturedPacketInfo;

struct ConnectionStat
{
    ConnectionKey key;
    quint64 rxBytes  = 0, txBytes  = 0;
    quint64 rxSpeed  = 0, txSpeed  = 0;
    quint64 prevRx   = 0, prevTx   = 0;
    quint32 packets  = 0;
    QString service;
    // NG-031: the remote endpoint and the DNS name(s) recently attributed to
    // it. `domain` is the most recent name; `domains` backs the tooltip.
    QString remoteAddress;
    QString domain;
    QStringList domains;
    AttributionSource domainSource = AttributionSource::Unknown;
    ApplicationIdentity::Confidence domainConfidence = ApplicationIdentity::Confidence::Unknown;
    // NG-035: the evidence behind the domain confidence, shown in the tooltip.
    QStringList domainEvidence;
    QDateTime domainExpiresAt;
};

struct ProcessNode
{
    QString  name;
    QIcon    icon;
    quint32  pid    = 0;
    QString  identityId;   // NG-010 durable executable identity, when resolved
    QString  identityName; // display name derived from version metadata
    QString  publisher;    // NG-011 Authenticode signer (CN), when signed
    ApplicationIdentity::SignerStatus signerStatus = ApplicationIdentity::SignerStatus::Unknown;
    // NG-012: services this process hosts. Drawn as their own child rows so
    // several services sharing one svchost.exe stay individually visible.
    QVector<Oasis::ServiceEntry> services;
    // NG-013: lineage of this process instance. Start time pins the instance so
    // a recycled PID is visible instead of silently merging two processes.
    qint64   processStartMs = 0;
    quint32  parentPid = 0;
    QString  parentName;
    // NG-014: durable activity group this process belongs to.
    QString  groupId;
    QString  groupName;
    ApplicationIdentity::Confidence groupConfidence = ApplicationIdentity::Confidence::Unknown;
    // NG-040: rule-based activity classification, with the matched rules and
    // evidence the Activity column's tooltip shows. Recomputed only when the
    // evidence behind it changes (see refreshActivity()).
    ActivityClassification activity;
    QString  activitySignature;
    // NG-041: the owning PID is the foreground application or one of its live
    // helpers. Advisory; it feeds classification and never changes a policy.
    Oasis::ForegroundAssociation foreground = Oasis::ForegroundAssociation::None;
    quint64  totalRxSpeed = 0;
    quint64  totalTxSpeed = 0;
    quint64  totalRxBytes = 0;
    quint64  totalTxBytes = 0;
    quint32  totalPackets = 0;

    QVector<ConnectionStat>      conns;
    QHash<ConnectionKey, int>    connIdx;
};

// NG-052: everything one process row can contribute to an application detail
// view, captured before the live model can change under the caller. `query` and
// `activity` are the row's own classification evidence, not a re-run.
struct ProcessRowSnapshot
{
    QString name;
    QString identityId;
    QString identityName;
    QString publisher;
    ApplicationIdentity::SignerStatus signerStatus = ApplicationIdentity::SignerStatus::Unknown;
    quint32 pid = 0;
    quint32 parentPid = 0;
    qint64  processStartMs = 0;
    QString parentName;
    QString groupId;
    QString groupName;
    ApplicationIdentity::Confidence groupConfidence = ApplicationIdentity::Confidence::Unknown;
    QStringList services;
    Oasis::ForegroundAssociation foreground = Oasis::ForegroundAssociation::None;
    ActivityQuery query;
    ActivityClassification activity;
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
    quint32 packets = 0;
    QList<ConnectionStat> connections;

    bool isValid() const { return pid != 0 || !name.isEmpty(); }
};

enum NetCol : int {
    COL_NAME = 0,
    COL_SRC,
    COL_DST,
    COL_DOMAIN,
    COL_ACTIVITY,
    COL_SERVICE,
    COL_RX,
    COL_TX,
    COL_BYTES,
    COL_PKTS,
    COL_COUNT
};

class NetworkTreeModel : public QAbstractItemModel
{
    Q_OBJECT
public:
    explicit NetworkTreeModel(QObject *parent = nullptr);

    QModelIndex   index    (int row, int col, const QModelIndex &parent = {}) const override;
    QModelIndex   parent   (const QModelIndex &child)        const override;
    int           rowCount (const QModelIndex &parent = {})  const override;
    int           columnCount(const QModelIndex &parent = {})const override;
    QVariant      data     (const QModelIndex &idx, int role = Qt::DisplayRole)      const override;
    QVariant      headerData(int section, Qt::Orientation, int role = Qt::DisplayRole)     const override;
    Qt::ItemFlags flags    (const QModelIndex &idx)          const override;

    void addPackets(const QList<CapturedPacketInfo> &batch);
    void setProcessIcon(const QString &procName, const QIcon &icon);
    // NG-031: resolves each connection's remote address through the DNS
    // correlator. Called after a capture batch and safe to call repeatedly;
    // only rows whose name, source, or confidence changed are refreshed.
    void setDomainResolver(std::function<QList<DomainAttribution>(const QString &)> resolver);
    void refreshDomains();
    // NG-040: reclassify one process row when its identity, publisher, group, or
    // service evidence changed. Cheap to call; it skips unchanged evidence.
    void refreshActivity(int pRow);
    // NG-043: the evidence and classification behind a process row, for a
    // recommendation or detail view. The row index is the source-model row.
    ActivityQuery activityQueryForRow(int pRow) const;
    ActivityClassification activityForRow(int pRow) const;
    // NG-052: identity, usage, destinations, and lineage of one process row.
    ProcessRowSnapshot snapshotForRow(int pRow) const;
    // Source-model row of a live PID, or -1 when the process is not shown.
    int rowForPid(quint32 pid) const;
    // NG-012: replace the PID -> services map and refresh the affected rows.
    void applyServiceSnapshot(const Oasis::ServicePidMap &services);
    void clear();

    static QString formatSpeed(quint64 bps);
    static QString formatBytes(quint64 bytes);

public slots:
    void onTick();

private:
    int  findOrAddProcess(const QString &name, quint32 pid);
    bool isProcessIndex  (const QModelIndex &idx) const;

    QVector<ProcessNode> m_procs;
    QHash<QString, int>  m_procIdx;
    Oasis::ServicePidMap m_servicesByPid; // NG-012 services per live PID
    std::function<QList<DomainAttribution>(const QString &)> m_domainResolver;
    ActivityClassifier m_activityClassifier;
    QTimer              *m_ticker = nullptr;
};
