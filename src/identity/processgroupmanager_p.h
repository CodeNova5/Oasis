/**
 * @file    processgroupmanager_p.h
 * @brief   Internal string/normalisation helpers shared by the
 *          ProcessGroupManager translation units. Not part of the public
 *          interface.
 */
#pragma once

#include "processgroupmanager.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QString>

namespace Oasis {
namespace processgroupdetail {

inline QString normalised(const QString &value)
{
    return value.trimmed().toLower();
}

inline QString leafName(const QString &path)
{
    if (path.trimmed().isEmpty()) return QString();
    const QFileInfo info(path);
    const QString leaf = info.fileName();
    return leaf.isEmpty() ? QDir::toNativeSeparators(info.absolutePath()) : leaf;
}

inline QByteArray shortDigest(const QString &value)
{
    return QCryptographicHash::hash(value.toUtf8(), QCryptographicHash::Sha1).toHex().left(16);
}

inline QString memberTypeKey(GroupMemberType type)
{
    switch (type) {
    case GroupMemberType::Service:   return QStringLiteral("service");
    case GroupMemberType::Publisher: return QStringLiteral("publisher");
    case GroupMemberType::Package:   return QStringLiteral("package");
    case GroupMemberType::ExecutablePath: break;
    }
    return QStringLiteral("path");
}

} // namespace processgroupdetail
} // namespace Oasis
