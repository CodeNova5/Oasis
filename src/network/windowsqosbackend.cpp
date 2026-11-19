#include "windowsqosbackend.h"

#include <QFileInfo>
#include <QOperatingSystemVersion>
#include <QProcess>
#include <QSet>

namespace {
QString quotePowerShell(const QString &value)
{
    QString escaped = value;
    escaped.replace("'", "''");
    return "'" + escaped + "'";
}

// One PowerShell invocation. Every QoS operation goes through this, so start
// failures, timeouts, and exit status are reported the same way whether the
// caller is applying, removing, or sweeping.
struct PowerShellOutput
{
    bool started = false;
    bool timedOut = false;
    bool succeeded = false;
    QString text;
};

PowerShellOutput executePowerShell(const QString &script)
{
    QProcess process;
    process.setProgram("powershell.exe");
    process.setArguments({"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                          "-Command", script});
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start();

    PowerShellOutput output;
    if (!process.waitForStarted(3000))
        return output;
    output.started = true;

    if (!process.waitForFinished(15000)) {
        process.kill();
        output.timedOut = true;
        return output;
    }

    output.text = QString::fromLocal8Bit(process.readAll()).trimmed();
    output.succeeded =
        process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
    return output;
}
}

ThrottleResult WindowsQosThrottleBackend::apply(const ThrottleRequest &request)
{
    ThrottleResult result;
    result.policyId = request.policyId;

    if (QOperatingSystemVersion::currentType() != QOperatingSystemVersion::Windows ||
        QOperatingSystemVersion::current().majorVersion() < 10) {
        result.status = ThrottleStatus::Unsupported;
        result.message = "Windows QoS requires Windows 10 or newer.";
        return result;
    }

    const QFileInfo executable(request.executablePath);
    if (!executable.isFile()) {
        result.status = ThrottleStatus::Failed;
        result.message = "The executable path is unavailable or no longer exists.";
        return result;
    }

    const QString policyName = makePolicyName(request);
    // Applying a limit is idempotent: a policy with this name can already exist
    // from an earlier session or a previous apply, and New-NetQosPolicy refuses
    // to create a duplicate. Replace it so the new rate always takes effect.
    const QString script = QString(
        "$ErrorActionPreference = 'Stop'; "
        "$name = %1; "
        "$existing = Get-NetQosPolicy -Name $name -PolicyStore ActiveStore "
        "-ErrorAction SilentlyContinue; "
        "if ($null -ne $existing) { "
        "Remove-NetQosPolicy -Name $name -PolicyStore ActiveStore "
        "-Confirm:$false | Out-Null }; "
        "New-NetQosPolicy -Name $name -AppPathNameMatchCondition %2 "
        "-ThrottleRateActionBitsPerSecond %3 -PolicyStore ActiveStore | Out-Null")
        .arg(quotePowerShell(policyName))
        .arg(quotePowerShell(executable.absoluteFilePath()))
        .arg(request.limitBitsPerSecond);

    result = runPowerShell(script, ThrottleStatus::Applied, policyName);
    result.affectsAllInstances = true;
    return result;
}

ThrottleResult WindowsQosThrottleBackend::remove(const QString &policyId)
{
    if (policyId.isEmpty()) {
        return {ThrottleStatus::NotApplied, policyId, "No policy identifier was supplied.", true};
    }

    const QString script = QString(
        "$ErrorActionPreference = 'Stop'; "
        "Remove-NetQosPolicy -Name %1 -PolicyStore ActiveStore -Confirm:$false")
        .arg(quotePowerShell(policyId));
    return runPowerShell(script, ThrottleStatus::Removed, policyId);
}

bool WindowsQosThrottleBackend::isApplied(const QString &policyId) const
{
    if (policyId.isEmpty()) return false;

    const QString script = QString(
        "$ErrorActionPreference = 'Stop'; "
        "$policy = Get-NetQosPolicy -Name %1 -PolicyStore ActiveStore "
        "-ErrorAction SilentlyContinue; "
        "if ($null -ne $policy) { $policy.Name }")
        .arg(quotePowerShell(policyId));
    const ThrottleResult result = runPowerShell(script, ThrottleStatus::Applied, policyId);
    return result.status == ThrottleStatus::Applied &&
           result.message.trimmed().compare(policyId, Qt::CaseInsensitive) == 0;
}

QString WindowsQosThrottleBackend::makePolicyName(const ThrottleRequest &request)
{
    return request.policyId.isEmpty()
        ? ThrottlePolicyNames::forPath(request.executablePath)
        : request.policyId;
}

ThrottleResult WindowsQosThrottleBackend::pruneOrphans(const QStringList &knownPolicyIds,
                                                       QStringList *removedPolicyIds)
{
    ThrottleResult result;
    if (QOperatingSystemVersion::currentType() != QOperatingSystemVersion::Windows ||
        QOperatingSystemVersion::current().majorVersion() < 10) {
        result.status = ThrottleStatus::Unsupported;
        result.message = "Windows QoS requires Windows 10 or newer.";
        return result;
    }

    const QString script = QString(
        "$ErrorActionPreference = 'Stop'; "
        "Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Name -like %1 } | ForEach-Object { $_.Name }")
        .arg(quotePowerShell(ThrottlePolicyNames::prefix() + '*'));

    const PowerShellOutput listed = executePowerShell(script);
    if (!listed.started) {
        result.status = ThrottleStatus::Failed;
        result.message = "PowerShell could not be started.";
        return result;
    }
    if (listed.timedOut) {
        result.status = ThrottleStatus::Failed;
        result.message = "The QoS policy lookup timed out.";
        return result;
    }
    if (!listed.succeeded) {
        result.status = ThrottleStatus::Failed;
        result.message = listed.text.isEmpty() ? "The QoS policy store could not be read."
                                               : listed.text;
        return result;
    }

    QSet<QString> known;
    for (const QString &policyId : knownPolicyIds)
        known.insert(policyId.toLower());

    QStringList orphans;
    const QStringList installed = listed.text.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString &line : installed) {
        const QString name = line.trimmed();
        if (!name.isEmpty() && !known.contains(name.toLower()))
            orphans.append(name);
    }

    result.status = ThrottleStatus::NotApplied;
    result.message = "No orphaned QoS policies were found.";
    if (orphans.isEmpty())
        return result;

    QStringList removed;
    QStringList failures;
    for (const QString &name : orphans) {
        const ThrottleResult removal = remove(name);
        if (removal.status == ThrottleStatus::Removed)
            removed.append(name);
        else
            failures.append(removal.message);
    }

    if (removedPolicyIds)
        *removedPolicyIds = removed;

    if (!failures.isEmpty()) {
        result.status = ThrottleStatus::Failed;
        result.message = failures.join(QLatin1Char('\n'));
        return result;
    }

    result.status = ThrottleStatus::Removed;
    result.message = QString("Removed %1 orphaned QoS %2.")
                         .arg(removed.size())
                         .arg(removed.size() == 1 ? "policy" : "policies");
    return result;
}

ThrottleResult WindowsQosThrottleBackend::runPowerShell(const QString &script,
                                                        ThrottleStatus successStatus,
                                                        const QString &policyId)
{
    const PowerShellOutput output = executePowerShell(script);
    if (!output.started)
        return {ThrottleStatus::Failed, policyId, "PowerShell could not be started.", true};
    if (output.timedOut)
        return {ThrottleStatus::Failed, policyId, "The QoS operation timed out.", true};
    if (!output.succeeded) {
        return {ThrottleStatus::Failed, policyId,
                output.text.isEmpty() ? "The QoS operation failed." : output.text, true};
    }

    return {successStatus, policyId,
            output.text.isEmpty() ? "QoS policy operation completed." : output.text, true};
}