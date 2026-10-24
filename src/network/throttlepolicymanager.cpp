#include "throttlepolicymanager.h"

#include "windowsqosbackend.h"

#include <QCryptographicHash>
#include <QDir>
#include <QSettings>
#include <QVariantMap>

ThrottlePolicyManager::ThrottlePolicyManager()
    : m_backend(new WindowsQosThrottleBackend)
{
    load();
}

ThrottlePolicyManager::~ThrottlePolicyManager()
{
    delete m_backend;
}

constexpr quint64 ThrottlePolicyManager::DefaultLimitBitsPerSecond;

ThrottleResult ThrottlePolicyManager::apply(const QString &executablePath)
{
    const QString path = normalizePath(executablePath);
    const QString policyId = policyIdForPath(path);
    const ThrottleRequest request{path, policyId, DefaultLimitBitsPerSecond};

    // The backend shells out to PowerShell, which can take seconds. It is
    // intentionally called without the lock so a background auto-throttle
    // never blocks the UI thread reading or writing the policy list.
    ThrottleResult result = m_backend->apply(request);
    if (result.status == ThrottleStatus::Applied) {
        QMutexLocker locker(&m_mutex);
        m_activePolicies.insert(path, result.policyId);
        save();
    }
    return result;
}

ThrottleResult ThrottlePolicyManager::remove(const QString &executablePath)
{
    const QString path = normalizePath(executablePath);
    QString policyId;
    {
        QMutexLocker locker(&m_mutex);
        policyId = m_activePolicies.value(path, policyIdForPath(path));
    }
    ThrottleResult result = m_backend->remove(policyId);
    if (result.status == ThrottleStatus::Removed || result.status == ThrottleStatus::NotApplied) {
        QMutexLocker locker(&m_mutex);
        m_activePolicies.remove(path);
        save();
    }
    return result;
}

ThrottleResult ThrottlePolicyManager::restoreAll()
{
    ThrottleResult lastResult;
    lastResult.status = ThrottleStatus::NotApplied;
    lastResult.message = "No active bandwidth policies were found.";

    QMutexLocker locker(&m_mutex);

    const QHash<QString, QString> policies = m_activePolicies;
    for (auto it = policies.constBegin(); it != policies.constEnd(); ++it) {
        lastResult = m_backend->remove(it.value());
        if (lastResult.status == ThrottleStatus::Removed ||
            lastResult.status == ThrottleStatus::NotApplied)
            m_activePolicies.remove(it.key());
    }
    save();
    return lastResult;
}

bool ThrottlePolicyManager::isThrottled(const QString &executablePath) const
{
    QMutexLocker locker(&m_mutex);
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

void ThrottlePolicyManager::load()
{
    QSettings settings;
    settings.beginGroup("BandwidthGuard");
    const QVariantMap policies = settings.value("activePolicies").toMap();
    for (auto it = policies.constBegin(); it != policies.constEnd(); ++it)
        m_activePolicies.insert(it.key(), it.value().toString());
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
    settings.endGroup();
}