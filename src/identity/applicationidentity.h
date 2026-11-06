/**
 * @file    applicationidentity.h
 * @brief   Canonical application identity resolver (NG-010).
 *
 * Derives a durable identity from the canonical executable path, process name,
 * version metadata, product name, and original filename. Resolution failures
 * are typed so callers can distinguish access-denied from a vanished process.
 * Resolved identities persist across restarts through IdentityStore.
 *
 * Depends on the NG-002 contracts in network/policy.h.
 */
#pragma once

#include <QString>
#include <QStringList>
#include <QList>
#include <QHash>
#include <QMetaType>

#include "network/policy.h"
#include "identity/publisherresolver.h"

namespace NetGuard {

enum class IdentityResolutionStatus : int {
    Resolved = 0,
    AccessDenied,
    ProcessNotFound,
    KernelProcess,
    InvalidPath,
    FileNotFound,
    UnknownError
};

struct FileVersionMetadata
{
    QString companyName;
    QString productName;
    QString originalFileName;
    QString fileDescription;
    QString fileVersion;
    QString internalName;

    bool isEmpty() const
    {
        return productName.isEmpty() && originalFileName.isEmpty()
            && fileDescription.isEmpty() && fileVersion.isEmpty();
    }
};

struct IdentityResolution
{
    IdentityResolutionStatus status = IdentityResolutionStatus::UnknownError;
    ApplicationIdentity identity;
    QString message;
    quint32 errorCode = 0;

    bool ok() const { return status == IdentityResolutionStatus::Resolved; }
};

QString identityResolutionStatusName(IdentityResolutionStatus status);

// Persists resolved identities so they survive restarts and can still be
// matched when version metadata becomes temporarily unreadable.
class IdentityStore
{
public:
    IdentityStore();

    // Equality key: lowercased, separator-normalized, cleaned path.
    static QString pathKey(const QString &path);

    ApplicationIdentity findById(const QString &id) const;
    ApplicationIdentity findByCanonicalPath(const QString &canonicalPath) const;
    void upsert(const ApplicationIdentity &identity);
    QList<ApplicationIdentity> all() const;
    int count() const;
    void clear();

private:
    void ensureLoaded() const;
    void save() const;

    mutable bool m_loaded = false;
    mutable QHash<QString, ApplicationIdentity> m_byId;
    mutable QHash<QString, QString> m_idByPathKey;
};

class ApplicationIdentityResolver
{
public:
    explicit ApplicationIdentityResolver(IdentityStore *store = nullptr);

    IdentityResolution resolvePid(quint32 pid);
    IdentityResolution resolveExecutablePath(const QString &path);

    IdentityStore *store() const { return m_store; }

    // Absolute, symlink/8.3-resolved, separator-normalized path. Case is kept
    // for display; use pathKey() or identityIdForCanonicalPath() for equality.
    static QString canonicalPath(const QString &path);
    static QString identityIdForCanonicalPath(const QString &canonicalPath);
    static FileVersionMetadata readVersionMetadata(const QString &canonicalPath);

private:
    IdentityStore m_ownedStore;
    IdentityStore *m_store = nullptr;
    PublisherResolver m_publisherResolver;
};

} // namespace NetGuard

Q_DECLARE_METATYPE(NetGuard::IdentityResolution)
