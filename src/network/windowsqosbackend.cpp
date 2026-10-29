#include "windowsqosbackend.h"

#include <QCryptographicHash>
#include <QFileInfo>
#include <QOperatingSystemVersion>
#include <QProcess>

namespace {
QString quotePowerShell(const QString &value)
{
    QString escaped = value;
    escaped.replace("'", "''");
    return "'" + escaped + "'";
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
    const QString script = QString(
        "$ErrorActionPreference = 'Stop'; "
        "New-NetQosPolicy -Name %1 -AppPathNameMatchCondition %2 "
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
    const QByteArray digest = QCryptographicHash::hash(
        request.executablePath.toLower().toUtf8(), QCryptographicHash::Sha1);
    return request.policyId.isEmpty()
        ? QString("UltimateNetGuard-BW-%1").arg(QString::fromLatin1(digest.toHex().left(12)))
        : request.policyId;
}

ThrottleResult WindowsQosThrottleBackend::runPowerShell(const QString &script,
                                                        ThrottleStatus successStatus,
                                                        const QString &policyId)
{
    QProcess process;
    process.setProgram("powershell.exe");
    process.setArguments({"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                          "-Command", script});
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start();

    if (!process.waitForStarted(3000))
        return {ThrottleStatus::Failed, policyId, "PowerShell could not be started.", true};
    if (!process.waitForFinished(15000)) {
        process.kill();
        return {ThrottleStatus::Failed, policyId, "The QoS operation timed out.", true};
    }

    const QString output = QString::fromLocal8Bit(process.readAll()).trimmed();
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return {ThrottleStatus::Failed, policyId,
                output.isEmpty() ? "The QoS operation failed." : output, true};
    }

    return {successStatus, policyId,
            output.isEmpty() ? "QoS policy operation completed." : output, true};
}