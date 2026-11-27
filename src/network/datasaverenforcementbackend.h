/**
 * @file    datasaverenforcementbackend.h
 * @brief   Shipped enforcement adapter for Data Saver controls (DS-009).
 *
 * Wraps the managers the application already owns. It does not create them and
 * it never touches a control it did not attribute to a `dsauto_` policy id.
 * The managers are called directly rather than through `EnforcementCoordinator`
 * so a Data Saver outcome is audited once, by the enforcer's caller; the
 * coordinator remains the router for stored policies.
 *  - throttle requests go to `ThrottlePolicyManager` with `automatic = true`,
 *    so emergency restore may take them back;
 *  - withdrawals check that the path is still attributed to this Data Saver
 *    policy before asking the manager to remove anything;
 *  - block requests go to `FirewallManager`, and a withdrawal removes only the
 *    rules whose description names this Data Saver policy, so a user-created
 *    rule for the same executable survives.
 *
 * This file is compiled into the application only; the test harness uses a
 * mock `DataSaverEnforcementBackend` instead.
 *
 * @author  Oasis
 */
#pragma once

#include "datasaverenforcement.h"

class ThrottlePolicyManager;
class FirewallManager;

class ManagerEnforcementBackend final : public DataSaverEnforcementBackend
{
public:
    ManagerEnforcementBackend(ThrottlePolicyManager *throttle,
                              FirewallManager *firewall);

    bool isAvailable() const override;

    EnforcementResult applyThrottle(const QString &executablePath, const QString &policyId,
                                    quint64 rateBitsPerSecond,
                                    NetworkDirection direction) override;
    EnforcementResult withdrawThrottle(const QString &executablePath,
                                       const QString &policyId) override;
    EnforcementResult applyBlock(const QString &executablePath,
                                 const QString &policyId) override;
    EnforcementResult withdrawBlock(const QString &executablePath,
                                    const QString &policyId) override;

private:
    ThrottlePolicyManager *m_throttle = nullptr;
    FirewallManager *m_firewall = nullptr;
};
