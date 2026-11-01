#include "throttlepolicymanager.h"

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
    const QString path = normalizePath(executablePath);
    if (path.isEmpty()) return;

    m_pendingAutomatic.insert(path, automatic);
    emit applyRequested(path, policyIdForPath(path), DefaultLimitBitsPerSecond);
}

void ThrottlePolicyManager::remove(const QString &executablePath)
{
    const QString path = normalizePath(executablePath);
    if (path.isEmpty()) return;

    const QString policyId = m_activePolicies.value(path, policyIdForPath(path));
    emit removeRequested(path, policyId);
}

void ThrottlePolicyManager::restoreAutoApplied()
{
    QVariantMap policies;
    for (auto it = m_activePolicies.constBegin(); it != m_activePolicies.constEnd(); ++it) {
        if (m_autoApplied.contains(it.key()))
            policies.insert(it.key(), it.value());
    }

    if (policies.isEmpty()) {
        emit throttlesRestored(noPoliciesResult());
        return;
    }
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
    const bool automatic = m_pendingAutomatic.take(executablePath);
    if (result.status == ThrottleStatus::Applied) {
        m_activePolicies.insert(executablePath, result.policyId.isEmpty()
                                                    ? policyIdForPath(executablePath)
                                                    : result.policyId);
        // A user-applied limit always wins over an automatic one.
        if (automatic)
            m_autoApplied.insert(executablePath);
        else
            m_autoApplied.remove(executablePath);
        save();
    }
    emit throttleApplied(executablePath, result);
}

void ThrottlePolicyManager::onWorkerRemoved(const QString &executablePath,
                                            const ThrottleResult &result)
{
    if (result.status == ThrottleStatus::Removed || result.status == ThrottleStatus::NotApplied) {
        m_activePolicies.remove(executablePath);
        m_autoApplied.remove(executablePath);
        save();
    }
    emit throttleRemoved(executablePath, result);
}

void ThrottlePolicyManager::onWorkerRestored(const ThrottleResult &result,
                                             const QStringList &remainingPolicyIds)
{
    for (auto it = m_activePolicies.begin(); it != m_activePolicies.end();) {
        if (remainingPolicyIds.contains(it.value())) {
            ++it;
        } else {
            m_autoApplied.remove(it.key());
            it = m_activePolicies.erase(it);
        }
    }
    save();
    emit throttlesRestored(result);
}

void ThrottlePolicyManager::onWorkerVerified(const QStringList &existingPolicyIds)
{
    bool changed = false;
    for (auto it = m_activePolicies.begin(); it != m_activePolicies.end();) {
        if (existingPolicyIds.contains(it.value())) {
            ++it;
        } else {
            it = m_activePolicies.erase(it);
            changed = true;
        }
    }
    if (changed) save();
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
    settings.endGroup();
}
