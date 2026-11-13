/**
 * @file   rulenames.cpp
 * @brief  Firewall rule naming (NG-024 follow-up: path-unique names).
 * @author Codebuff
 */

#include "rulenames.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>

QString firewallRuleName(const QString &appPath, const QString &suffix)
{
    // Windows paths are case-insensitive and accept either separator, so the
    // identity must be normalized before hashing; otherwise the same file could
    // get two different rules.
    const QString identity =
        QDir::cleanPath(QDir::toNativeSeparators(QFileInfo(appPath).absoluteFilePath())).toLower();
    const QString hash = QString::fromLatin1(
        QCryptographicHash::hash(identity.toUtf8(), QCryptographicHash::Sha1).toHex().left(10));

    // The base name comes from the normalized identity too, so the same file
    // named in a different case maps to one name rather than two. It is only
    // there for readability; the hash is what keeps names unique, so a very
    // long file name can be shortened without losing identity.
    QString base = QFileInfo(identity).completeBaseName();
    if (base.size() > 40) base = base.left(40);

    return QStringLiteral("Oasis_") + base + QLatin1Char('_') + hash +
           QLatin1Char('_') + suffix;
}

QString legacyFirewallRuleName(const QString &appPath, const QString &suffix)
{
    return QStringLiteral("Oasis_") + QFileInfo(appPath).completeBaseName() +
           QLatin1Char('_') + suffix;
}
