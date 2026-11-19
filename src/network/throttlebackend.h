#pragma once

#include <QCryptographicHash>
#include <QDir>
#include <QMetaType>
#include <QString>
#include <QStringList>

enum class ThrottleStatus {
    Applied,
    Removed,
    NotApplied,
    Unsupported,
    Failed
};

struct ThrottleRequest
{
    QString executablePath;
    QString policyId;
    quint64 limitBitsPerSecond = 409600;
};

struct ThrottleResult
{
    ThrottleStatus status = ThrottleStatus::NotApplied;
    QString policyId;
    QString message;
    bool affectsAllInstances = true;
};

Q_DECLARE_METATYPE(ThrottleResult)

// Every bandwidth policy the app installs is named from the executable path, so
// the name can be recomputed wherever it is needed — apply, verification, and
// the startup sweep — without a second source of truth. Windows matches policy
// names case-insensitively.
namespace ThrottlePolicyNames {
inline const QString &prefix()
{
    static const QString prefix = QStringLiteral("Oasis-BW-");
    return prefix;
}

inline QString forPath(const QString &executablePath)
{
    const QString normalized =
        QDir::cleanPath(QDir::toNativeSeparators(executablePath.trimmed())).toLower();
    const QByteArray digest =
        QCryptographicHash::hash(normalized.toUtf8(), QCryptographicHash::Sha1);
    return prefix() + QString::fromLatin1(digest.toHex().left(12));
}
}

class ThrottleBackend
{
public:
    virtual ~ThrottleBackend() = default;

    virtual ThrottleResult apply(const ThrottleRequest &request) = 0;
    virtual ThrottleResult remove(const QString &policyId) = 0;
    virtual bool isApplied(const QString &policyId) const = 0;

    // Removes the policies this backend owns that `knownPolicyIds` does not
    // account for: a policy outlives the process that created it, so a crash, a
    // settings reset, or an older build can leave limits behind that nothing in
    // the app tracks any more. Ids that were removed are appended to
    // `removedPolicyIds` when it is not null.
    virtual ThrottleResult pruneOrphans(const QStringList &knownPolicyIds,
                                        QStringList *removedPolicyIds = nullptr) = 0;
};