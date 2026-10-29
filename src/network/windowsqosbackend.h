#pragma once

#include "throttlebackend.h"

class WindowsQosThrottleBackend final : public ThrottleBackend
{
public:
    ThrottleResult apply(const ThrottleRequest &request) override;
    ThrottleResult remove(const QString &policyId) override;
    bool isApplied(const QString &policyId) const override;

private:
    static QString makePolicyName(const ThrottleRequest &request);
    static ThrottleResult runPowerShell(const QString &script,
                                        ThrottleStatus successStatus,
                                        const QString &policyId);
};