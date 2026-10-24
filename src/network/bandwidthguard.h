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
    QString executablePath;
    quint32 pid = 0;
    quint64 bytesLastMinute = 0;
    quint64 bytesPerSecond = 0;
    ProcessCategory category = ProcessCategory::Unknown;

    // Filled in after the alert has been acted upon, so the user is told
    // what actually happened rather than just that usage was high.
    bool    throttleAttempted = false;
    bool    throttleApplied = false;
    quint64 throttleLimitBitsPerSecond = 0;
    QString throttleMessage;
};

class BandwidthGuard : public QObject
{
    Q_OBJECT
public:
    explicit BandwidthGuard(QObject *parent = nullptr);

    void observe(const QList<CapturedPacketInfo> &batch);
    void reset();
    void exemptProcess(const QString &processName, int durationSeconds);
    void setCategoryOverride(const QString &processName, ProcessCategory category);

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
        QString executablePath;
        QVector<quint64> buckets;
        quint64 currentBytes = 0;
        bool isService = false;
        bool alerted = false;
        int lowRateSeconds = 0;
    };

    static QString normalizeProcessName(const QString &processName);
    static QString resolveExecutablePath(quint32 pid);
    bool isExempt(const QString &processName);
    ProcessCategory categoryFor(const ProcessWindow &window, quint32 pid) const;
    void loadPersistentState();
    void savePersistentState() const;

    static constexpr quint64 DetectionBytesPerMinute = 5ULL * 1024ULL * 1024ULL;
    static constexpr quint64 ReleaseBytesPerMinute = 1ULL * 1024ULL * 1024ULL;
    static constexpr int WindowSeconds = 60;
    static constexpr int ReleaseSeconds = 300;

    QHash<quint32, ProcessWindow> m_processes;
    QHash<QString, qint64> m_exemptions;
    QHash<QString, ProcessCategory> m_categoryOverrides;
    QTimer *m_timer = nullptr;
};

Q_DECLARE_METATYPE(BandwidthEvent)