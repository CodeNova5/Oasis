/**
 * @file    networkmodel.h
 * @brief   QAbstractItemModel with batch-processing support for UI stability.
 * @author  Ali Sakkaf
 */
#pragma once

#include <QAbstractItemModel>
#include <QHash>
#include <QVector>
#include <QTimer>
#include <QIcon>
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
    QVector<NetGuard::ServiceEntry> services;
    quint64  totalRxSpeed = 0;
    quint64  totalTxSpeed = 0;
    quint64  totalRxBytes = 0;
    quint64  totalTxBytes = 0;
    quint32  totalPackets = 0;

    QVector<ConnectionStat>      conns;
    QHash<ConnectionKey, int>    connIdx;
};

enum NetCol : int {
    COL_NAME = 0,
    COL_SRC,
    COL_DST,
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
    // NG-012: replace the PID -> services map and refresh the affected rows.
    void applyServiceSnapshot(const NetGuard::ServicePidMap &services);
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
    NetGuard::ServicePidMap m_servicesByPid; // NG-012 services per live PID
    QTimer              *m_ticker = nullptr;
};
