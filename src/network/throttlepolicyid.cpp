#include "throttlepolicyid.h"

#include <QCryptographicHash>
#include <QDir>

namespace ThrottlePolicyNames {
QString prefix()
{
    return QStringLiteral("Oasis-BW-");
}

QString forPath(const QString &executablePath)
{
    const QString normalized =
        QDir::cleanPath(QDir::toNativeSeparators(executablePath.trimmed())).toLower();
    const QByteArray digest =
        QCryptographicHash::hash(normalized.toUtf8(), QCryptographicHash::Sha1);
    return prefix() + QString::fromLatin1(digest.toHex().left(12));
}
}
