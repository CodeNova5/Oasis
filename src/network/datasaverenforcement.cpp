/**
 * @file    datasaverenforcement.cpp
 * @brief   Apply and withdraw automation-owned enforcement for Data Saver
 *          decisions (DS-009).
 * @author  Oasis
 */
#include "datasaverenforcement.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>

#include <algorithm>

namespace {

using Action = NetworkPolicy::Action;
using Status = EnforcementResult::Status;

const QString kAutomaticPolicyPrefix = QStringLiteral("dsauto_");

QString channelsFor(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("WinDivert download");
    case NetworkDirection::Upload:   return QStringLiteral("QoS upload");
    case NetworkDirection::Both:     break;
    }
    return QStringLiteral("QoS upload + WinDivert download");
}

bool isAutomaticOrigin(DecisionOrigin origin)
{
    return origin == DecisionOrigin::Profile || origin == DecisionOrigin::Cache
           || origin == DecisionOrigin::Fallback;
}

bool isActiveStatus(Status status)
{
    return status == Status::Applied || status == Status::Requested || status == Status::Partial;
}

// A partial request is retried on the next decision: the missing channel may be
// available by then. Only a confirmed request is treated as done.
bool isIdempotentStatus(Status status)
{
    return status == Status::Applied || status == Status::Requested;
}

DataSaverControl controlForDecision(const PolicyDecision &decision, const ControlLease &lease,
                                    const QDateTime &now)
{
    DataSaverControl control;
    control.policyId = DataSaverEnforcement::automaticPolicyId(lease.executablePath);
    control.executablePath = DataSaverEnforcement::normalizedPath(lease.executablePath);
    control.observationId = decision.observationId;
    control.decisionId = decision.decisionId;
    control.action = decision.action;
    control.origin = decision.origin;
    control.tier = decision.tier;
    control.rateBitsPerSecond = decision.rateBitsPerSecond;
    control.direction = decision.direction;
    control.until = decision.until;
    control.requestedAt = now;
    control.expiresAt = lease.expiresAt;
    control.reason = lease.reason.isEmpty() ? decision.reasonShort : lease.reason;
    return control;
}

} // namespace

QString DataSaverEnforcement::normalizedPath(const QString &executablePath)
{
    const QString trimmed = executablePath.trimmed();
    if (trimmed.isEmpty()) return QString();
    return QDir::cleanPath(QDir::toNativeSeparators(trimmed)).toLower();
}

QString DataSaverEnforcement::automaticPolicyId(const QString &executablePath)
{
    const QString normalized = normalizedPath(executablePath);
    if (normalized.isEmpty()) return QString();
    const QByteArray digest =
        QCryptographicHash::hash(normalized.toUtf8(), QCryptographicHash::Sha1);
    return kAutomaticPolicyPrefix + QString::fromLatin1(digest.toHex().left(12));
}

bool DataSaverEnforcement::throttleBelongsTo(const QString &attributedPolicyId,
                                             const QString &policyId)
{
    return !policyId.isEmpty() && attributedPolicyId == policyId;
}

bool DataSaverEnforcement::firewallRuleBelongsTo(const QString &ruleDescription,
                                                 const QString &policyId)
{
    if (policyId.isEmpty()) return false;
    return ruleDescription == QStringLiteral("Oasis policy %1").arg(policyId);
}

DataSaverEnforcer::DataSaverEnforcer(DataSaverEnforcementBackend *backend)
    : m_backend(backend)
{
}

bool DataSaverEnforcer::canThrottle() const
{
    return m_backend && m_backend->isAvailable();
}

EnforcementOutcome DataSaverEnforcer::apply(const PolicyDecision &decision,
                                            const ControlLease &lease,
                                            const QDateTime &now)
{
    EnforcementOutcome outcome;
    outcome.evaluated = true;
    outcome.action = decision.action;
    outcome.executablePath = lease.executablePath.trimmed();
    outcome.direction = decision.direction;

    const QString key = DataSaverEnforcement::normalizedPath(lease.executablePath);
    if (key.isEmpty()) {
        outcome.status = Status::Failed;
        outcome.message = QStringLiteral(
            "No executable path was resolved, so no automatic control was applied.");
        return outcome;
    }

    // A user rule outranks automation. Data Saver withdraws its own control so
    // it cannot keep shaping a path the user just decided about.
    if (!isAutomaticOrigin(decision.origin)) {
        const EnforcementOutcome withdrawn =
            withdraw(lease.executablePath, QStringLiteral("a user rule took precedence"));
        if (withdrawn.failed()) {
            // Never claim the user rule took effect while our control is still
            // in place.
            outcome.status = Status::Failed;
            outcome.message = withdrawn.message;
            outcome.policyId = withdrawn.policyId;
            return outcome;
        }
        outcome.status = Status::NotApplied;
        outcome.changed = withdrawn.changed;
        outcome.policyId = withdrawn.policyId;
        outcome.message = QStringLiteral(
            "The decision belongs to a user rule; no automatic control was applied.");
        return outcome;
    }

    if (decision.action == Action::Allow || decision.action == Action::Notify) {
        const EnforcementOutcome withdrawn =
            withdraw(lease.executablePath, QStringLiteral("traffic continues"));
        if (withdrawn.failed()) {
            outcome.status = Status::Failed;
            outcome.message = withdrawn.message;
            outcome.policyId = withdrawn.policyId;
            return outcome;
        }
        outcome.status = Status::NotApplied;
        outcome.changed = withdrawn.changed;
        outcome.policyId = withdrawn.policyId;
        outcome.message = withdrawn.changed
                              ? QStringLiteral("Traffic continues; the automatic control was withdrawn.")
                              : QStringLiteral("Traffic continues; no control was needed.");
        return outcome;
    }

    if (decision.action != Action::Throttle && decision.action != Action::Block) {
        outcome.status = Status::NotApplied;
        outcome.message = QStringLiteral("The decision needs no enforcement channel.");
        return outcome;
    }

    if (!m_backend || !m_backend->isAvailable()) {
        return backendUnavailable(decision, lease);
    }

    // The channels are path-keyed, so a decision for another executable must
    // never be applied to this path. A target that is not a file name (a
    // service display name, for example) is left to the resolver's own scope
    // checks rather than guessed at here.
    const QString targetName = decision.target.executable.trimmed();
    const QString leaseName = QFileInfo(lease.executablePath).fileName();
    const bool targetNamesAFile = targetName.contains(QLatin1Char('.'));
    if (targetNamesAFile && !leaseName.isEmpty()
        && leaseName.compare(targetName, Qt::CaseInsensitive) != 0) {
        outcome.status = Status::Failed;
        outcome.message = QStringLiteral(
            "The resolved executable path does not match the decision target, so "
            "nothing was enforced.");
        return outcome;
    }

    return decision.action == Action::Throttle
               ? applyThrottleControl(decision, lease, now)
               : applyBlockControl(decision, lease, now);
}

EnforcementOutcome DataSaverEnforcer::applyThrottleControl(const PolicyDecision &decision,
                                                           const ControlLease &lease,
                                                           const QDateTime &now)
{
    EnforcementOutcome outcome;
    outcome.evaluated = true;
    outcome.action = Action::Throttle;
    outcome.executablePath = lease.executablePath.trimmed();
    outcome.direction = decision.direction;

    if (decision.scope != DecisionScope::Executable) {
        outcome.status = Status::Failed;
        outcome.message = QStringLiteral(
            "The shipped throttle channel is keyed by executable path, so a "
            "non-executable decision cannot be enforced.");
        return outcome;
    }

    quint64 rate = decision.rateBitsPerSecond;
    QString note;
    if (rate == 0 || rate < DataSaverDecision::kGentleThrottleBitsPerSecond) {
        outcome.status = Status::Failed;
        outcome.message = QStringLiteral(
            "The requested rate is below the 50 KiB/s gentle-throttle floor, so it "
            "was refused rather than treated as a block.");
        return outcome;
    }
    if (rate > DataSaverDecision::kGentleThrottleBitsPerSecond) {
        rate = DataSaverDecision::kGentleThrottleBitsPerSecond;
        note = QStringLiteral(" The request was capped to the canonical 409600 bits/s.");
    }

    const QString key = DataSaverEnforcement::normalizedPath(lease.executablePath);
    const QString policyId = DataSaverEnforcement::automaticPolicyId(lease.executablePath);

    auto existing = m_controls.find(key);
    if (existing != m_controls.end()) {
        const DataSaverControl &control = existing.value();
        if (control.action == Action::Throttle && control.policyId == policyId
            && control.rateBitsPerSecond == rate && control.direction == decision.direction
            && isIdempotentStatus(control.status)) {
            DataSaverControl updated = control;
            updated.observationId = decision.observationId;
            updated.decisionId = decision.decisionId;
            updated.until = decision.until;
            updated.expiresAt = lease.expiresAt;
            updated.reason = lease.reason.isEmpty() ? decision.reasonShort : lease.reason;
            existing.value() = updated;

            EnforcementOutcome repeated;
            repeated.evaluated = true;
            repeated.action = Action::Throttle;
            repeated.executablePath = lease.executablePath.trimmed();
            repeated.policyId = policyId;
            repeated.status = control.status;
            repeated.channels = control.channels;
            repeated.rateBitsPerSecond = control.rateBitsPerSecond;
            repeated.direction = control.direction;
            repeated.message = QStringLiteral("The control is already in place; no duplicate was requested.");
            return repeated;
        }

        if (control.action != Action::Throttle) {
            const EnforcementOutcome withdrawn =
                withdraw(lease.executablePath, QStringLiteral("replaced by a throttle"));
            if (withdrawn.failed()) {
                return withdrawn;
            }
        }
    }

    const EnforcementResult result =
        m_backend->applyThrottle(lease.executablePath, policyId, rate, decision.direction);

    DataSaverControl control = controlForDecision(decision, lease, now);
    control.policyId = policyId;
    control.rateBitsPerSecond = rate;
    control.channels = result.channels.isEmpty() ? channelsFor(decision.direction)
                                                 : result.channels;
    control.status = result.status;

    if (!isActiveStatus(result.status)) {
        outcome.status = result.status;
        outcome.policyId = policyId;
        outcome.changed = m_controls.remove(key) > 0;
        outcome.channels = control.channels;
        outcome.rateBitsPerSecond = rate;
        outcome.message = result.message.isEmpty()
                              ? QStringLiteral("The throttle channel did not accept the request.")
                              : result.message;
        outcome.message += note;
        return outcome;
    }

    m_controls.insert(key, control);
    outcome = outcomeForControl(control, result);
    if (!note.isEmpty()) outcome.message += note;
    return outcome;
}

EnforcementOutcome DataSaverEnforcer::applyBlockControl(const PolicyDecision &decision,
                                                          const ControlLease &lease,
                                                          const QDateTime &now)
{
    EnforcementOutcome outcome;
    outcome.evaluated = true;
    outcome.action = Action::Block;
    outcome.executablePath = lease.executablePath.trimmed();
    outcome.direction = decision.direction;

    if (decision.scope != DecisionScope::Executable) {
        outcome.status = Status::Failed;
        outcome.message = QStringLiteral(
            "The shipped firewall channel is keyed by executable path, so a "
            "non-executable decision cannot be enforced.");
        return outcome;
    }

    const QString key = DataSaverEnforcement::normalizedPath(lease.executablePath);
    const QString policyId = DataSaverEnforcement::automaticPolicyId(lease.executablePath);

    auto existing = m_controls.find(key);
    if (existing != m_controls.end()) {
        const DataSaverControl &control = existing.value();
        if (control.action == Action::Block && control.policyId == policyId
            && isIdempotentStatus(control.status)) {
            DataSaverControl updated = control;
            updated.observationId = decision.observationId;
            updated.decisionId = decision.decisionId;
            updated.until = decision.until;
            updated.expiresAt = lease.expiresAt;
            updated.reason = lease.reason.isEmpty() ? decision.reasonShort : lease.reason;
            existing.value() = updated;

            EnforcementOutcome repeated;
            repeated.evaluated = true;
            repeated.action = Action::Block;
            repeated.executablePath = lease.executablePath.trimmed();
            repeated.policyId = policyId;
            repeated.status = control.status;
            repeated.channels = control.channels;
            repeated.direction = control.direction;
            repeated.message = QStringLiteral("The control is already in place; no duplicate was requested.");
            return repeated;
        }

        if (control.action != Action::Block) {
            const EnforcementOutcome withdrawn =
                withdraw(lease.executablePath, QStringLiteral("replaced by a block"));
            if (withdrawn.failed()) {
                return withdrawn;
            }
        }
    }

    const EnforcementResult result = m_backend->applyBlock(lease.executablePath, policyId);

    DataSaverControl control = controlForDecision(decision, lease, now);
    control.policyId = policyId;
    control.rateBitsPerSecond = 0;
    control.channels = result.channels.isEmpty() ? QStringLiteral("firewall") : result.channels;
    control.status = result.status;

    if (!isActiveStatus(result.status)) {
        outcome.status = result.status;
        outcome.policyId = policyId;
        outcome.changed = m_controls.remove(key) > 0;
        outcome.channels = control.channels;
        outcome.message = result.message.isEmpty()
                              ? QStringLiteral("The firewall channel did not accept the request.")
                              : result.message;
        return outcome;
    }

    m_controls.insert(key, control);
    return outcomeForControl(control, result);
}

EnforcementOutcome DataSaverEnforcer::withdraw(const QString &executablePath,
                                               const QString &reason)
{
    EnforcementOutcome outcome;
    outcome.executablePath = executablePath.trimmed();

    const QString key = DataSaverEnforcement::normalizedPath(executablePath);
    auto it = m_controls.find(key);
    if (it == m_controls.end()) {
        outcome.status = Status::NotApplied;
        outcome.message = QStringLiteral("No Data Saver control exists for this executable.");
        return outcome;
    }

    const DataSaverControl control = it.value();
    outcome.evaluated = true;
    outcome.action = control.action;
    outcome.policyId = control.policyId;
    outcome.rateBitsPerSecond = control.rateBitsPerSecond;
    outcome.direction = control.direction;
    outcome.channels = control.channels;

    if (!m_backend || !m_backend->isAvailable()) {
        outcome.status = Status::Failed;
        outcome.message = QStringLiteral(
            "No enforcement channel is available, so the automatic control "
            "could not be withdrawn.");
        return outcome;
    }

    EnforcementResult result;
    if (control.action == Action::Throttle)
        result = m_backend->withdrawThrottle(executablePath, control.policyId);
    else if (control.action == Action::Block)
        result = m_backend->withdrawBlock(executablePath, control.policyId);
    else
        result = failedResult(QStringLiteral("The control has no channel to withdraw."));

    outcome.status = result.status;
    outcome.message = result.message;
    if (!result.channels.isEmpty())
        outcome.channels = result.channels;

    if (result.status == Status::Failed) {
        // Keep ownership so a later disable/restore can try again.
        outcome.changed = false;
        if (outcome.message.isEmpty())
            outcome.message = QStringLiteral("The automatic control could not be withdrawn.");
        return outcome;
    }

    m_controls.erase(it);
    outcome.changed = true;
    if (outcome.message.isEmpty())
        outcome.message = QStringLiteral("The automatic control was withdrawn (%1).").arg(reason);
    return outcome;
}

QList<EnforcementOutcome> DataSaverEnforcer::withdrawAll(const QString &reason)
{
    QStringList keys = m_controls.keys();
    keys.sort();
    QList<EnforcementOutcome> outcomes;
    for (const QString &key : keys) {
        const DataSaverControl control = m_controls.value(key);
        outcomes.append(withdraw(control.executablePath, reason));
    }
    return outcomes;
}

QList<EnforcementOutcome> DataSaverEnforcer::withdrawUntil(ThrottleUntil until,
                                                           const QString &reason)
{
    QStringList keys;
    for (auto it = m_controls.constBegin(); it != m_controls.constEnd(); ++it) {
        if (it.value().until == until) keys.append(it.key());
    }
    keys.sort();

    QList<EnforcementOutcome> outcomes;
    for (const QString &key : keys)
        outcomes.append(withdraw(m_controls.value(key).executablePath, reason));
    return outcomes;
}

QList<EnforcementOutcome> DataSaverEnforcer::expire(const QDateTime &now)
{
    const QDateTime reference =
        (now.isValid() ? now : QDateTime::currentDateTimeUtc()).toUTC();

    QStringList keys;
    for (auto it = m_controls.constBegin(); it != m_controls.constEnd(); ++it) {
        if (it.value().expiresAt.isValid() && it.value().expiresAt <= reference)
            keys.append(it.key());
    }
    keys.sort();

    QList<EnforcementOutcome> outcomes;
    for (const QString &key : keys)
        outcomes.append(withdraw(m_controls.value(key).executablePath,
                                 QStringLiteral("the lease expired")));
    return outcomes;
}

QList<DataSaverControl> DataSaverEnforcer::controls() const
{
    QList<DataSaverControl> result = m_controls.values();
    std::sort(result.begin(), result.end(),
              [](const DataSaverControl &left, const DataSaverControl &right) {
                  return left.executablePath < right.executablePath;
              });
    return result;
}

DataSaverControl DataSaverEnforcer::controlFor(const QString &executablePath) const
{
    return m_controls.value(DataSaverEnforcement::normalizedPath(executablePath));
}

bool DataSaverEnforcer::owns(const QString &executablePath) const
{
    return m_controls.contains(DataSaverEnforcement::normalizedPath(executablePath));
}

EnforcementOutcome DataSaverEnforcer::backendUnavailable(const PolicyDecision &decision,
                                                          const ControlLease &lease)
{
    EnforcementOutcome outcome;
    outcome.evaluated = true;
    outcome.action = decision.action;
    outcome.executablePath = lease.executablePath.trimmed();
    outcome.direction = decision.direction;
    outcome.status = Status::Failed;
    outcome.message = QStringLiteral(
        "No enforcement channel is available, so the decision was not applied.");
    return outcome;
}

EnforcementOutcome DataSaverEnforcer::outcomeForControl(const DataSaverControl &control,
                                                         const EnforcementResult &result)
{
    EnforcementOutcome outcome;
    outcome.evaluated = true;
    outcome.changed = true;
    outcome.policyId = control.policyId;
    outcome.executablePath = control.executablePath;
    outcome.action = control.action;
    outcome.status = result.status;
    outcome.message = result.message;
    outcome.channels = control.channels;
    outcome.rateBitsPerSecond = control.rateBitsPerSecond;
    outcome.direction = control.direction;
    return outcome;
}

EnforcementResult DataSaverEnforcer::failedResult(const QString &message)
{
    EnforcementResult result;
    result.status = Status::Failed;
    result.message = message;
    return result;
}
