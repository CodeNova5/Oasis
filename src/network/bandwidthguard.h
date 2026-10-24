#pragma once

#include <QObject>
#include <QHash>
#include <QTimer>
#include <QVector>

struct CapturedPacketInfo;

enum class ProcessCategory {
    Protected,
    AskFirst,
    AutoCandidate,
    Unknown
};

struct BandwidthEvent
{
    QString processName;
    quint32 pid = 0;
    quint64 bytesLastMinute = 0;
    quint64 bytesPerSecond = 0;
    ProcessCategory category = ProcessCategory::Unknown;
};

class BandwidthGuard : public QObject
{
    Q_OBJECT
public:
    explicit BandwidthGuard(QObject *parent = nullptr);

    void observe(const QList<CapturedPacketInfo> &batch);
    void reset();

    static ProcessCategory classifyProcess(const QString &processName,
                                           bool isService,
                                           quint32 pid);

signals:
    void sustainedBandwidthExceeded(const BandwidthEvent &event);

private slots:
    void onTick();

private:
    struct ProcessWindow {
        QString name;
        QVector<quint64> buckets;
        quint64 currentBytes = 0;
        bool isService = false;
        bool alerted = false;
        int lowRateSeconds = 0;
    };

    static constexpr quint64 DetectionBytesPerMinute = 5ULL * 1024ULL * 1024ULL;
    static constexpr quint64 ReleaseBytesPerMinute = 1ULL * 1024ULL * 1024ULL;
    static constexpr int WindowSeconds = 60;
    static constexpr int ReleaseSeconds = 300;

    QHash<quint32, ProcessWindow> m_processes;
    QTimer *m_timer = nullptr;
};

Q_DECLARE_METATYPE(BandwidthEvent)