#pragma once

#include <QObject>
#include <QHash>

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
    quint64 totalBytes = 0;
    ProcessCategory category = ProcessCategory::Unknown;

    // Filled in after the alert has been acted upon, so the user is told
    // what actually happened rather than just that usage was high.
    bool    firewallAttempted = false;
    bool    firewallBlocked = false;
    QString firewallMessage;
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

private:
    struct ProcessWindow {
        QString name;
        QString executablePath;
        quint64 totalBytes = 0;
        bool isService = false;
        bool alerted = false;
    };

    static QString normalizeProcessName(const QString &processName);
    static QString resolveExecutablePath(quint32 pid);
    bool isExempt(const QString &processName);
    ProcessCategory categoryFor(const ProcessWindow &window, quint32 pid) const;
    void loadPersistentState();
    void savePersistentState() const;

    static constexpr quint64 DetectionBytes = 10ULL * 1024ULL * 1024ULL;

    QHash<quint32, ProcessWindow> m_processes;
    QHash<QString, qint64> m_exemptions;
    QHash<QString, ProcessCategory> m_categoryOverrides;
};

Q_DECLARE_METATYPE(BandwidthEvent)