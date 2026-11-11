/**
 * @file    bandwidthguard.h
 * @brief   Data Saver classification and sustained-bandwidth detection.
 *
 * Classification reads the evidence the capture loop already carries with
 * every packet (NG-010 identity, NG-011 publisher, NG-012 service role, NG-014
 * activity group), so a rule matches an application rather than the PID it
 * happens to run as. An updated executable, or a helper that has no rule of its
 * own, classifies like the rest of its activity group.
 */
#pragma once

#include <QObject>
#include <QHash>

#include "network/policy.h"

struct CapturedPacketInfo;

enum class ProcessCategory {
    Protected,
    AskFirst,
    AutoCandidate,
    Unknown
};

// Everything the classifier may look at for one observed process. The name and
// service flag preserve the rules the product shipped with; identity, publisher,
// and group are what let a rule survive an update, a rename, or a respawn under a
// new PID.
struct ClassificationEvidence
{
    quint32 pid = 0;
    QString processName;
    QString executablePath;
    QString identityId;      // NG-010 durable identity
    QString displayName;     // NG-010 display name, version metadata when readable
    QString publisher;       // NG-011 Authenticode publisher, empty when unsigned
    ApplicationIdentity::SignerStatus signerStatus =
        ApplicationIdentity::SignerStatus::Unknown;
    QString groupId;         // NG-014 activity group, empty when ungrouped
    QString groupName;
    bool isService = false;
};

// NG-035: the category plus the confidence and evidence behind it. Callers use
// this to qualify a category as Likely or Possible instead of stating it as a
// fact when the evidence is only a name or a learned group.
struct ProcessClassification
{
    ProcessCategory category = ProcessCategory::Unknown;
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
    QStringList evidence;
};

struct BandwidthEvent
{
    QString processName;
    QString executablePath;
    quint32 pid = 0;
    quint64 totalBytes = 0;
    ProcessCategory category = ProcessCategory::Unknown;
    // NG-035: confidence in the category and the evidence that produced it.
    ApplicationIdentity::Confidence categoryConfidence =
        ApplicationIdentity::Confidence::Unknown;
    QStringList categoryEvidence;
    // NG-015: where the category came from, so the alert can say that it was
    // learned from the process's activity group rather than from a rule.
    QString groupId;
    QString groupName;
    bool    categoryFromGroup = false;

    // Filled in after the alert has been acted upon, so the user is told
    // what actually happened rather than just that usage was high.
    bool    firewallAttempted = false;
    bool    firewallBlocked = false;
    QString firewallMessage;
    bool    throttleAttempted = false;
    bool    throttled = false;
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

    // Name-only form: keeps the historical contract for callers that have no
    // identity evidence (and for NG-001 fixtures).
    static ProcessCategory classifyProcess(const QString &processName,
                                           bool isService,
                                           quint32 pid);
    // Evidence form: executable name first, then publisher and product metadata.
    // Group evidence is applied by the guard itself, because it needs the
    // categories of the group's other members.
    static ProcessCategory classifyProcess(const ClassificationEvidence &evidence);
    // Same decision with the confidence and evidence needed to explain it.
    static ProcessClassification classifyWithEvidence(const ClassificationEvidence &evidence);

    // Text the UI shows for a category. Kept in one place so the bandwidth alert
    // and the activity group view describe the same decision the same way.
    static QString categoryDisplayName(ProcessCategory category);

    // Category an activity group has learned, or Unknown while none of its
    // members has crossed the bandwidth threshold.
    ProcessCategory groupCategory(const QString &groupId) const;

    // Category shown for one group member in the activity group view: an
    // override first, then the member's own name and publisher rules, then what
    // its group has learned. Read-only — inspecting a member never changes the
    // group's category.
    ProcessCategory memberCategory(const ClassificationEvidence &evidence) const;
    ProcessClassification memberClassification(const ClassificationEvidence &evidence) const;

    // NG-043: whether a process is inside an active "ignore alerts" window. The
    // recommendation view reads it so it never suggests something the user has
    // already dismissed. Read-only apart from pruning an expired exemption.
    bool isExempt(const QString &processName);

signals:
    void sustainedBandwidthExceeded(const BandwidthEvent &event);

private:
    struct ProcessWindow {
        QString name;
        QString executablePath;
        quint64 totalBytes = 0;
        bool isService = false;
        bool alerted = false;
        // NG-015: evidence attached to the packets of this PID. Filled lazily,
        // because identity and group resolution can arrive after the first
        // packet of a connection.
        QString identityId;
        QString displayName;
        QString publisher;
        ApplicationIdentity::SignerStatus signerStatus =
            ApplicationIdentity::SignerStatus::Unknown;
        QString groupId;
        QString groupName;
    };

    static QString normalizeProcessName(const QString &processName);
    static QString resolveExecutablePath(quint32 pid);
    static int categoryRank(ProcessCategory category);
    ProcessCategory resolveCategory(const ProcessWindow &window, quint32 pid,
                                   bool *fromGroup = nullptr,
                                   ApplicationIdentity::Confidence *confidence = nullptr,
                                   QStringList *evidenceOut = nullptr);
    void loadPersistentState();
    void savePersistentState() const;

    static constexpr quint64 DetectionBytes = 10ULL * 1024ULL * 1024ULL;

    QHash<quint32, ProcessWindow> m_processes;
    QHash<QString, qint64> m_exemptions;
    QHash<QString, ProcessCategory> m_categoryOverrides;
    // NG-015: category learned from the members of each activity group. Keyed by
    // group id, so it survives the processes it was learned from.
    QHash<QString, ProcessCategory> m_groupCategories;
};

Q_DECLARE_METATYPE(BandwidthEvent)