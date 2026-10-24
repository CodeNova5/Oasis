#pragma once

#include <QHash>
#include <QString>

#include "throttlebackend.h"

class ThrottlePolicyManager
{
public:
    ThrottlePolicyManager();
    ~ThrottlePolicyManager();

    static constexpr quint64 DefaultLimitBitsPerSecond = 409600;

    ThrottleResult apply(const QString &executablePath);
    ThrottleResult remove(const QString &executablePath);
    ThrottleResult restoreAll();
    bool isThrottled(const QString &executablePath) const;

private:
    static QString normalizePath(const QString &path);
    static QString policyIdForPath(const QString &path);
    void load();
    void save() const;

    QHash<QString, QString> m_activePolicies;
    ThrottleBackend *m_backend = nullptr;
};