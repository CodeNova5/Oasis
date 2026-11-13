#pragma once

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include "throttlebackend.h"

class QThread;
class DownloadShaper;

// ── Worker ───────────────────────────────────────────────────────────────────
// Lives on its own thread. Every backend call spawns PowerShell and blocks for
// up to 15 s, so none of it may run on the GUI thread.
class ThrottleWorker : public QObject
{
    Q_OBJECT
public:
    explicit ThrottleWorker(QObject *parent = nullptr);
    ~ThrottleWorker() override;

public slots:
    void applyRequest(const QString &executablePath, const QString &policyId,
                      quint64 limitBitsPerSecond);
    void removeRequest(const QString &executablePath, const QString &policyId);
    void restoreAllRequest(const QVariantMap &policies);
    void verifyRequest(const QVariantMap &policies);

signals:
    void applied(const QString &executablePath, const ThrottleResult &result);
    void removed(const QString &executablePath, const ThrottleResult &result);
    void restored(const ThrottleResult &result, const QStringList &remainingPolicyIds);
    void verified(const QStringList &existingPolicyIds);

private:
    ThrottleBackend *m_backend = nullptr;
};

// ── Manager ──────────────────────────────────────────────────────────────────
class ThrottlePolicyManager : public QObject
{
    Q_OBJECT
public:
    explicit ThrottlePolicyManager(QObject *parent = nullptr);
    ~ThrottlePolicyManager() override;

    static constexpr quint64 DefaultLimitBitsPerSecond = 409600;

    static QString normalizePath(const QString &path);

    // These return immediately; the outcome arrives through the signals below.
    // `automatic` marks a limit applied by Data Saver enforcement, which is the
    // only kind restoreAutoApplied() will take back.
    void apply(const QString &executablePath, bool automatic = false);
    // Applies a limit on behalf of a stored policy. The attribution is kept
    // (and persisted with the active set) so reconciliation can withdraw the
    // limit once that policy stops wanting it; a plain apply() clears it.
    void applyForPolicy(const QString &executablePath, const QString &policyId,
                        bool automatic = false);
    void remove(const QString &executablePath);
    // Changes which policy owns an already-enforced limit, without another QoS
    // call. Used when a different active policy takes over a path; an
    // unattributed (manual) limit is never adopted. Returns false when there is
    // no settled limit to reassign.
    bool reassign(const QString &executablePath, const QString &policyId,
                  bool automatic = false);
    void restoreAutoApplied();

    // Purely a cache lookup, no PowerShell involved.
    bool isThrottled(const QString &executablePath) const;

    // Read-only views for policy reconciliation (NG-024). Paths are normalized
    // the same way as isThrottled(); the auto-applied set is the subset the
    // product may take back without touching a user-requested limit.
    QStringList activePaths() const { return m_activePolicies.keys(); }
    QStringList autoAppliedPaths() const {
        return QStringList(m_autoApplied.cbegin(), m_autoApplied.cend());
    }
    // Normalized path -> Oasis policy id, for limits applied by a policy.
    QHash<QString, QString> policyAttribution() const { return m_policyAttribution; }
    QHash<QString, quint64> downloadLimits() const { return m_downloadLimits; }

    // Empty while download shaping works; otherwise why it cannot start.
    QString downloadLimiterStatus() const { return m_downloadStatus; }


signals:
    void throttleApplied(const QString &executablePath, const ThrottleResult &result);
    void throttleRemoved(const QString &executablePath, const ThrottleResult &result);
    void throttlesRestored(const ThrottleResult &result);
    // The WinDivert download shaper could not start, or stopped working.
    void downloadLimiterError(const QString &message);

    // Internal hand-off to the worker thread.
    void applyRequested(const QString &executablePath, const QString &policyId,
                        quint64 limitBitsPerSecond);
    void removeRequested(const QString &executablePath, const QString &policyId);
    void restoreAllRequested(const QVariantMap &policies);
    void verifyRequested(const QVariantMap &policies);

private slots:
    void onWorkerApplied(const QString &executablePath, const ThrottleResult &result);
    void onWorkerRemoved(const QString &executablePath, const ThrottleResult &result);
    void onWorkerRestored(const ThrottleResult &result, const QStringList &remainingPolicyIds);
    void onWorkerVerified(const QStringList &existingPolicyIds);

private:
    void applyInternal(const QString &path, const QString &policyId, bool automatic);
    static QString policyIdForPath(const QString &path);
    QVariantMap policySnapshot() const;
    void load();
    void save() const;

    // The download shaper mirrors the active policy set; these keep it in sync.
    void rebuildDownloadLimits();
    void pushDownloadLimits();

    QHash<QString, QString> m_activePolicies;
    // Paths whose limit was applied by Data Saver enforcement, not by the user.
    QSet<QString> m_autoApplied;
    // Path -> Oasis policy id for limits a stored policy asked for.
    QHash<QString, QString> m_policyAttribution;
    QHash<QString, bool> m_pendingAutomatic;
    QHash<QString, QString> m_pendingPolicyId;
    // Paths with a QoS call already running. A second request for the same path
    // is dropped so PowerShell is never asked twice in parallel; the running call
    // still reports its own result.
    QSet<QString> m_inFlight;
    bool m_restoreInFlight = false;
    QStringList m_restoringPaths;
    QThread *m_thread = nullptr;
    ThrottleWorker *m_worker = nullptr;

    // Path -> limit (bits/s) currently enforced by the WinDivert download shaper.
    QHash<QString, quint64> m_downloadLimits;
    DownloadShaper *m_download = nullptr;
    QString m_downloadStatus;
};
