#include "throttlepolicymanager.h"

#include "downloadthrottle.h"
#include "windowsqosbackend.h"

#include <QCryptographicHash>
#include <QDir>
#include <QSettings>
#include <QThread>
#include <QVariant>

namespace {
ThrottleResult noPoliciesResult()
{
    ThrottleResult result;
    result.status = ThrottleStatus::NotApplied;
    result.message = "No active bandwidth policies were found.";
    return result;
}

// Windows QoS can only shape egress, so a policy is a pair: QoS for uploads,
// WinDivert for downloads. Say which halves actually took effect.
QString withDownloadChannelNote(const QString &base)
{
    const QString reason = DownloadShaper::unavailableReason();
    const QString note = reason.isEmpty()
        ? QStringLiteral("The limit applies to downloads (WinDivert) and uploads (Windows QoS).")
        : QStringLiteral("Only uploads are limited (Windows QoS). Download shaping is "
                         "unavailable: %1").arg(reason);
    return base.isEmpty() ? note : base + '\n' + note;
}
}

// ── Worker ───────────────────────────────────────────────────────────────────

ThrottleWorker::ThrottleWorker(QObject *parent)
    : QObject(parent)
    , m_backend(new WindowsQosThrottleBackend)
{
}

ThrottleWorker::~ThrottleWorker()
{
    delete m_backend;
}

void ThrottleWorker::applyRequest(const QString &executablePath, const QString &policyId,
                                  quint64 limitBitsPerSecond)
{
    const ThrottleRequest request{executablePath, policyId, limitBitsPerSecond};
    emit applied(executablePath, m_backend->apply(request));
}

void ThrottleWorker::removeRequest(const QString &executablePath, const QString &policyId)
{
    emit removed(executablePath, m_backend->remove(policyId));
}

void ThrottleWorker::restoreAllRequest(const QVariantMap &policies)
{
    QStringList remaining;
    QStringList failures;
    ThrottleResult lastResult = noPoliciesResult();

    for (auto it = policies.constBegin(); it != policies.constEnd(); ++it) {
        const QString policyId = it.value().toString();
        const ThrottleResult result = m_backend->remove(policyId);
        if (result.status == ThrottleStatus::Removed ||
            result.status == ThrottleStatus::NotApplied)
            continue;

        remaining << policyId;
        failures << result.message;
        lastResult = result;
    }

    if (!failures.isEmpty()) {
        lastResult.status = ThrottleStatus::Failed;
        lastResult.message = failures.join('\n');
    }
    emit restored(lastResult, remaining);
}

void ThrottleWorker::verifyRequest(const QVariantMap &policies)
{
    QStringList existing;
    for (auto it = policies.constBegin(); it != policies.constEnd(); ++it) {
        const QString policyId = it.value().toString();
        if (m_backend->isApplied(policyId))
            existing << policyId;
    }
    emit verified(existing);
}

// ── Manager ──────────────────────────────────────────────────────────────────

ThrottlePolicyManager::ThrottlePolicyManager(QObject *parent)
    : QObject(parent)
{
    qRegisterMetaType<ThrottleResult>("ThrottleResult");

    load();

    // Download shaping is in-process, so it is driven straight from the policy
    // cache instead of round-tripping through the QoS worker thread.
    m_download = new DownloadShaper;
    connect(m_download, &DownloadShaper::shaperError,
            this, &ThrottlePolicyManager::downloadLimiterError);
    connect(m_download, &DownloadShaper::availabilityChecked,
            this, [this](bool available, const QString &reason) {
                m_downloadStatus = available ? QString() : reason;
                if (!available && !reason.isEmpty())
                    emit downloadLimiterError(reason);
            });
    m_download->start();
    rebuildDownloadLimits();

    m_thread = new QThread;
    m_thread->setObjectName(QStringLiteral("ThrottleWorker"));
    m_worker = new ThrottleWorker;
    m_worker->moveToThread(m_thread);

    connect(this, &ThrottlePolicyManager::applyRequested,
            m_worker, &ThrottleWorker::applyRequest);
    connect(this, &ThrottlePolicyManager::removeRequested,
            m_worker, &ThrottleWorker::removeRequest);
    connect(this, &ThrottlePolicyManager::restoreAllRequested,
            m_worker, &ThrottleWorker::restoreAllRequest);
    connect(this, &ThrottlePolicyManager::verifyRequested,
            m_worker, &ThrottleWorker::verifyRequest);

    connect(m_worker, &ThrottleWorker::applied,
            this, &ThrottlePolicyManager::onWorkerApplied);
    connect(m_worker, &ThrottleWorker::removed,
            this, &ThrottlePolicyManager::onWorkerRemoved);
    connect(m_worker, &ThrottleWorker::restored,
            this, &ThrottlePolicyManager::onWorkerRestored);
    connect(m_worker, &ThrottleWorker::verified,
            this, &ThrottlePolicyManager::onWorkerVerified);

    m_thread->start();

    // Drop persisted policies that no longer exist in Windows — queried off the
    // GUI thread so a long policy list cannot stall startup.
    if (!m_activePolicies.isEmpty())
        emit verifyRequested(policySnapshot());
}

ThrottlePolicyManager::~ThrottlePolicyManager()
{
    if (m_download) {
        m_download->stop();
        if (m_download->wait(3000)) {
            delete m_download;
        } else {
            // Parked inside a WinDivert call; the OS reclaims it at exit.
            m_download->disconnect(this);
        }
        m_download = nullptr;
    }

    if (!m_thread) return;

    m_thread->quit();
    if (m_thread->wait(5000)) {
        delete m_worker;
        delete m_thread;
    } else {
        // Still inside a blocking PowerShell call: leave it parked instead of
        // destroying a live thread. The OS reclaims it when the process exits.
        m_worker->disconnect(this);
        m_thread->setParent(nullptr);
    }

    m_worker = nullptr;
    m_thread = nullptr;
}

constexpr quint64 ThrottlePolicyManager::DefaultLimitBitsPerSecond;

void ThrottlePolicyManager::apply(const QString &executablePath, bool automatic)
{
    applyInternal(normalizePath(executablePath), QString(), automatic);
}

void ThrottlePolicyManager::applyForPolicy(const QString &executablePath,
                                           const QString &policyId, bool automatic)
{
    applyInternal(normalizePath(executablePath), policyId, automatic);
}

void ThrottlePolicyManager::applyInternal(const QString &path, const QString &policyId,
                                          bool automatic)
{
    if (path.isEmpty() || m_inFlight.contains(path)) return;

    m_inFlight.insert(path);
    m_pendingAutomatic.insert(path, automatic);
    m_pendingPolicyId.insert(path, policyId);

    // The download half starts immediately instead of waiting for the
    // PowerShell round trip that installs the QoS policy.
    if (!m_downloadLimits.contains(path)) {
        m_downloadLimits.insert(path, DefaultLimitBitsPerSecond);
        pushDownloadLimits();
    }

    emit applyRequested(path, policyIdForPath(path), DefaultLimitBitsPerSecond);
}

void ThrottlePolicyManager::remove(const QString &executablePath)
{
    const QString path = normalizePath(executablePath);
    if (path.isEmpty() || m_inFlight.contains(path)) return;

    m_inFlight.insert(path);
    if (m_downloadLimits.remove(path) > 0)
        pushDownloadLimits();

    const QString policyId = m_activePolicies.value(path, policyIdForPath(path));
    emit removeRequested(path, policyId);
}

void ThrottlePolicyManager::restoreAutoApplied()
{
    if (m_restoreInFlight) return;

    QVariantMap policies;
    for (auto it = m_activePolicies.constBegin(); it != m_activePolicies.constEnd(); ++it) {
        if (m_autoApplied.contains(it.key()) && !m_inFlight.contains(it.key()))
            policies.insert(it.key(), it.value());
    }

    if (policies.isEmpty()) {
        // Report on the next event-loop turn, like the applied/removed results,
        // so a caller that is still assembling its own report (emergency
        // restore) finishes before the outcome arrives.
        QMetaObject::invokeMethod(this, [this]() { emit throttlesRestored(noPoliciesResult()); },
                                  Qt::QueuedConnection);
        return;
    }

    m_restoreInFlight = true;
    m_restoringPaths = policies.keys();
    for (const QString &path : m_restoringPaths)
        m_inFlight.insert(path);
    emit restoreAllRequested(policies);
}

bool ThrottlePolicyManager::isThrottled(const QString &executablePath) const
{
    return m_activePolicies.contains(normalizePath(executablePath));
}

QString ThrottlePolicyManager::normalizePath(const QString &path)
{
    return QDir::cleanPath(QDir::toNativeSeparators(path.trimmed())).toLower();
}

QString ThrottlePolicyManager::policyIdForPath(const QString &path)
{
    const QByteArray digest = QCryptographicHash::hash(path.toUtf8(), QCryptographicHash::Sha1);
    return QString("UltimateNetGuard-BW-%1").arg(QString::fromLatin1(digest.toHex().left(12)));
}

QVariantMap ThrottlePolicyManager::policySnapshot() const
{
    QVariantMap policies;
    for (auto it = m_activePolicies.constBegin(); it != m_activePolicies.constEnd(); ++it)
        policies.insert(it.key(), it.value());
    return policies;
}

void ThrottlePolicyManager::onWorkerApplied(const QString &executablePath,
                                            const ThrottleResult &result)
{
    m_inFlight.remove(executablePath);
    const bool automatic = m_pendingAutomatic.take(executablePath);
    const QString policyId = m_pendingPolicyId.take(executablePath);

    ThrottleResult outcome = result;
    if (result.status == ThrottleStatus::Applied) {
        m_activePolicies.insert(executablePath, result.policyId.isEmpty()
                                                    ? policyIdForPath(executablePath)
                                                    : result.policyId);
        // A user-applied limit always wins over an automatic one.
        if (automatic)
            m_autoApplied.insert(executablePath);
        else
            m_autoApplied.remove(executablePath);
        if (policyId.isEmpty())
            m_policyAttribution.remove(executablePath);
        else
            m_policyAttribution.insert(executablePath, policyId);
        save();
        outcome.message = withDownloadChannelNote(result.message);
    } else if (m_downloadLimits.remove(executablePath) > 0) {
        // The QoS policy did not install, so drop the optimistic download limit
        // too rather than leaving a silent half-limit behind.
        pushDownloadLimits();
    }
    emit throttleApplied(executablePath, outcome);
}

void ThrottlePolicyManager::onWorkerRemoved(const QString &executablePath,
                                            const ThrottleResult &result)
{
    m_inFlight.remove(executablePath);

    if (result.status == ThrottleStatus::Removed || result.status == ThrottleStatus::NotApplied) {
        m_activePolicies.remove(executablePath);
        m_autoApplied.remove(executablePath);
        m_policyAttribution.remove(executablePath);
        save();
    }
    emit throttleRemoved(executablePath, result);
}

void ThrottlePolicyManager::onWorkerRestored(const ThrottleResult &result,
                                             const QStringList &remainingPolicyIds)
{
    // Every policy in that restore request has now been attempted.
    m_restoreInFlight = false;
    for (const QString &path : m_restoringPaths)
        m_inFlight.remove(path);
    m_restoringPaths.clear();

    for (auto it = m_activePolicies.begin(); it != m_activePolicies.end();) {
        if (remainingPolicyIds.contains(it.value())) {
            ++it;
        } else {
            m_autoApplied.remove(it.key());
            m_policyAttribution.remove(it.key());
            it = m_activePolicies.erase(it);
        }
    }
    save();
    rebuildDownloadLimits();
    emit throttlesRestored(result);
}

void ThrottlePolicyManager::onWorkerVerified(const QStringList &existingPolicyIds)
{
    bool changed = false;
    for (auto it = m_activePolicies.begin(); it != m_activePolicies.end();) {
        if (existingPolicyIds.contains(it.value())) {
            ++it;
        } else {
            m_policyAttribution.remove(it.key());
            it = m_activePolicies.erase(it);
            changed = true;
        }
    }
    if (changed) save();
    // Whatever survived the check is still limited on the way down.
    rebuildDownloadLimits();
}

void ThrottlePolicyManager::rebuildDownloadLimits()
{
    m_downloadLimits.clear();
    for (auto it = m_activePolicies.constBegin(); it != m_activePolicies.constEnd(); ++it)
        m_downloadLimits.insert(it.key(), DefaultLimitBitsPerSecond);
    pushDownloadLimits();
}

void ThrottlePolicyManager::pushDownloadLimits()
{
    if (m_download)
        m_download->setPolicies(m_downloadLimits);
}

void ThrottlePolicyManager::load()
{
    QSettings settings;
    settings.beginGroup("BandwidthGuard");
    const QVariantMap policies = settings.value("activePolicies").toMap();
    for (auto it = policies.constBegin(); it != policies.constEnd(); ++it)
        m_activePolicies.insert(it.key(), it.value().toString());

    const QStringList autoPolicies = settings.value("autoPolicies").toStringList();
    for (const QString &path : autoPolicies) {
        if (m_activePolicies.contains(path)) m_autoApplied.insert(path);
    }

    // Attribution only matters for a limit that still exists.
    const QVariantMap attributed = settings.value("policyAttribution").toMap();
    for (auto it = attributed.constBegin(); it != attributed.constEnd(); ++it) {
        const QString path = normalizePath(it.key());
        const QString policyId = it.value().toString();
        if (m_activePolicies.contains(path) && !policyId.isEmpty())
            m_policyAttribution.insert(path, policyId);
    }
    settings.endGroup();
}

void ThrottlePolicyManager::save() const
{
    QSettings settings;
    settings.beginGroup("BandwidthGuard");
    QVariantMap policies;
    for (auto it = m_activePolicies.constBegin(); it != m_activePolicies.constEnd(); ++it)
        policies.insert(it.key(), it.value());
    settings.setValue("activePolicies", policies);

    QStringList autoPolicies;
    for (const QString &path : m_autoApplied) {
        if (m_activePolicies.contains(path)) autoPolicies << path;
    }
    settings.setValue("autoPolicies", autoPolicies);

    QVariantMap attributed;
    for (auto it = m_policyAttribution.constBegin(); it != m_policyAttribution.constEnd(); ++it) {
        if (m_activePolicies.contains(it.key()) && !it.value().isEmpty())
            attributed.insert(it.key(), it.value());
    }
    settings.setValue("policyAttribution", attributed);
    settings.endGroup();
}
