#pragma once

#include <QMetaType>
#include <QString>

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

class ThrottleBackend
{
public:
    virtual ~ThrottleBackend() = default;

    virtual ThrottleResult apply(const ThrottleRequest &request) = 0;
    virtual ThrottleResult remove(const QString &policyId) = 0;
    virtual bool isApplied(const QString &policyId) const = 0;
};