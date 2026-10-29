#include "throttlebackend.h"

ThrottleResult MonitorOnlyThrottleBackend::apply(const ThrottleRequest &request)
{
    ThrottleResult result;
    result.status = ThrottleStatus::Unsupported;
    result.policyId = request.policyId;
    result.message = "Bandwidth shaping is not enabled; no policy was applied.";
    return result;
}

ThrottleResult MonitorOnlyThrottleBackend::remove(const QString &policyId)
{
    ThrottleResult result;
    result.status = ThrottleStatus::NotApplied;
    result.policyId = policyId;
    result.message = "No bandwidth policy was present.";
    return result;
}

bool MonitorOnlyThrottleBackend::isApplied(const QString &) const
{
    return false;
}